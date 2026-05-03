package main

/*
#include "coraza_types.h"
*/
import "C"
import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/corazawaf/coraza/v3/types"
	"github.com/rs/zerolog/log"
)

// parseHeaders parses null-separated key-value header pairs.
// Format: "Key1\0Value1\0Key2\0Value2\0"
func parseHeaders(data *C.char, dataLen C.int) []headerPair {
	if data == nil || dataLen <= 0 {
		return nil
	}
	raw := C.GoBytes(unsafe.Pointer(data), dataLen)
	parts := strings.Split(string(raw), "\x00")

	var pairs []headerPair
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] != "" {
			pairs = append(pairs, headerPair{key: parts[i], value: parts[i+1]})
		}
	}
	return pairs
}

type headerPair struct {
	key   string
	value string
}

// buildResult creates a coraza_result_t from a transaction's state.
// It checks both Coraza's native interruption mechanism and CRS anomaly
// scoring rules (949110/949111 for inbound, 959100 for outbound).
func buildResult(tx types.Transaction, interrupted bool) C.coraza_result_t {
	result := allowResult()

	matchedRules := tx.MatchedRules()
	result.rules_hit = C.int(len(matchedRules))

	// Compute anomaly score by summing severities of disruptive-category rules.
	// CRS assigns: CRITICAL=5, ERROR=4, WARNING=3, NOTICE=2.
	// CRS severity-to-score: CRITICAL(2)=5, ERROR(3)=4, WARNING(4)=3, NOTICE(5)=2
	anomalyScore := 0
	for _, mr := range matchedRules {
		switch mr.Rule().Severity() {
		case 2:
			anomalyScore += 5
		case 3:
			anomalyScore += 4
		case 4:
			anomalyScore += 3
		case 5:
			anomalyScore += 2
		}
	}
	result.anomaly_score = C.int(anomalyScore)

	// Check native Coraza interruption first
	if interrupted || tx.IsInterrupted() {
		it := tx.Interruption()
		if it != nil {
			result.rule_id = C.int(it.RuleID)
			result.action = actionToCString(it.Action)
			result.status = C.int(it.Status)
			if it.Data != "" {
				result.data = C.CString(it.Data)
			}
			return result
		}
	}

	// CRS anomaly scoring: check if any anomaly threshold rule matched.
	// CRS v4 rules 949110 (inbound) and 959100 (outbound) fire when
	// the anomaly score exceeds the configured threshold. These rules
	// may not generate a Coraza interruption but indicate the request
	// should be blocked.
	for _, mr := range matchedRules {
		ruleID := mr.Rule().ID()
		if ruleID == 949110 || ruleID == 949111 || ruleID == 959100 || ruleID == 959101 {
			result.rule_id = C.int(ruleID)
			result.action = actionDeny
			result.status = 403
			return result
		}
	}

	return result
}

//export coraza_process_request
func coraza_process_request(
	wafHandle C.uint64_t,
	txID *C.char,
	srcIP *C.char,
	srcPort C.int,
	dstIP *C.char,
	dstPort C.int,
	method *C.char,
	path *C.char,
	query *C.char,
	httpVersion *C.char,
	headers *C.char,
	headersLen C.int,
	body *C.char,
	bodyLen C.int,
	cacheTx C.int,
	appName *C.char,
	detectOnly C.int,
) (result C.coraza_result_t) {
	defer recoverPanic("coraza_process_request")

	// Resolve WAF instance
	var handle uint64
	if appName != nil {
		goApp := C.GoString(appName)
		handle = getWAFForApp(goApp)
	} else {
		handle = uint64(wafHandle)
	}
	if handle == 0 {
		handle = defaultWAF
	}

	inst, err := getWAF(handle)
	if err != nil {
		setLastError(err)
		metricsErrors.Add(1)
		// Deny by default on WAF engine error
		return denyResult()
	}

	// Create transaction
	goTxID := C.GoString(txID)
	tx := inst.waf.NewTransactionWithID(goTxID)

	if tx.IsRuleEngineOff() {
		tx.ProcessLogging()
		tx.Close()
		metricsAllowed.Add(1)
		return allowResult()
	}

	interrupted := false

	// Phase 1: Connection
	goSrcIP := C.GoString(srcIP)
	goDstIP := C.GoString(dstIP)
	tx.ProcessConnection(goSrcIP, int(srcPort), goDstIP, int(dstPort))

	// Phase 1: URI
	goMethod := C.GoString(method)
	goPath := C.GoString(path)
	goQuery := C.GoString(query)
	goVersion := C.GoString(httpVersion)

	uri := goPath
	if goQuery != "" {
		uri = goPath + "?" + goQuery
	}
	tx.ProcessURI(uri, goMethod, goVersion)

	// Phase 1: Request headers
	hdrs := parseHeaders(headers, headersLen)
	for _, h := range hdrs {
		tx.AddRequestHeader(h.key, h.value)
	}

	it := tx.ProcessRequestHeaders()
	if it != nil {
		interrupted = true
	}

	// Phase 2: Request body
	// Always call ProcessRequestBody even without body data, because CRS
	// anomaly scoring rules (949110) fire at the end of phase 2.
	if !interrupted {
		if body != nil && bodyLen > 0 {
			goBody := C.GoBytes(unsafe.Pointer(body), bodyLen)
			bodyIt, _, err := tx.WriteRequestBody(goBody)
			if err != nil {
				log.Error().Err(err).Msg("Error writing request body")
			}
			if bodyIt != nil {
				interrupted = true
			}
		}

		if !interrupted {
			procIt, err := tx.ProcessRequestBody()
			if err != nil {
				log.Error().Err(err).Msg("Error processing request body")
			}
			if procIt != nil {
				interrupted = true
			}
		}
	}

	result = buildResult(tx, interrupted)

	// `result.status > 0` is the canonical deny indicator: allowResult()
	// sets status=0; both the interruption branch and the CRS anomaly
	// branch in buildResult set status to the HTTP code (403, etc).
	denied := result.status != 0

	// Per-message detect-only override (specs/002-detect-only-request/).
	// When set, the WAF still evaluated rules and result carries the
	// matched rule_id, anomaly_score, rules_hit, and data — but the
	// verdict is coerced to allow so HAProxy lets the request through.
	// The operator's HAProxy rules can act on the diagnostic fields
	// (e.g., logging, shadow-banning) without blocking.
	if denied && detectOnly != 0 {
		result.action = actionAllow
		result.status = 0
		denied = false
	}

	if denied {
		metricsBlocked.Add(1)
	} else {
		metricsAllowed.Add(1)
	}
	metricsRulesHit.Add(int64(result.rules_hit))

	// Cache transaction for response phase or close it. In detect-only
	// mode the request is allowed through, so we WILL get a response —
	// honour the cacheTx flag accordingly.
	if cacheTx != 0 && !denied {
		cacheTransaction(goTxID, tx)
	} else {
		tx.ProcessLogging()
		tx.Close()
	}

	return result
}

//export coraza_process_response
func coraza_process_response(
	txIDC *C.char,
	statusCode C.int,
	httpVersion *C.char,
	headers *C.char,
	headersLen C.int,
	body *C.char,
	bodyLen C.int,
	detectOnly C.int,
) (result C.coraza_result_t) {
	defer recoverPanic("coraza_process_response")

	goTxID := C.GoString(txIDC)
	tx := getCachedTransaction(goTxID)
	if tx == nil {
		setLastError(fmt.Errorf("transaction %s not found in cache", goTxID))
		metricsErrors.Add(1)
		// Deny by default when transaction not found
		return denyResult()
	}
	removeCachedTransaction(goTxID)

	// Extract response data from C types (shared by both modes)
	goVersion := C.GoString(httpVersion)
	goStatus := int(statusCode)
	hdrs := parseHeaders(headers, headersLen)
	var goBody []byte
	if body != nil && bodyLen > 0 {
		goBody = C.GoBytes(unsafe.Pointer(body), bodyLen)
	}

	// Detect-only mode: spawn goroutine, return immediately
	if detectOnly != 0 {
		cacheWg.Add(1)
		go func() {
			defer cacheWg.Done()
			processResponsePhases(tx, goStatus, goVersion, hdrs, goBody)
			tx.ProcessLogging()
			tx.Close()
		}()

		metricsAllowed.Add(1)
		return allowResult()
	}

	// Blocking mode: evaluate synchronously
	interrupted := processResponsePhases(tx, goStatus, goVersion, hdrs, goBody)
	result = buildResult(tx, interrupted)

	if interrupted {
		metricsBlocked.Add(1)
	} else {
		metricsAllowed.Add(1)
	}

	tx.ProcessLogging()
	tx.Close()

	return result
}

// processResponsePhases runs all response-phase WAF evaluations.
func processResponsePhases(tx types.Transaction, statusCode int, httpVersion string, hdrs []headerPair, body []byte) bool {
	interrupted := false

	// Phase 3: Response headers
	for _, h := range hdrs {
		tx.AddResponseHeader(h.key, h.value)
	}
	it := tx.ProcessResponseHeaders(statusCode, httpVersion)
	if it != nil {
		interrupted = true
	}

	// Phase 4: Response body
	// Always call ProcessResponseBody even without body data, because CRS
	// outbound anomaly scoring rules (959100) fire at the end of phase 4.
	if !interrupted {
		if len(body) > 0 {
			bodyIt, _, err := tx.WriteResponseBody(body)
			if err != nil {
				log.Error().Err(err).Msg("Error writing response body")
			}
			if bodyIt != nil {
				interrupted = true
			}
		}

		if !interrupted {
			procIt, err := tx.ProcessResponseBody()
			if err != nil {
				log.Error().Err(err).Msg("Error processing response body")
			}
			if procIt != nil {
				interrupted = true
			}
		}
	}

	return interrupted
}
