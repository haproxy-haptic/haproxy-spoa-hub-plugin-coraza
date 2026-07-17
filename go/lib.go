package main

/*
#include "coraza_types.h"
*/
import "C"
import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/rs/zerolog/log"
)

// recoverPanic catches Go panics in FFI exports to prevent crashing
// the host process. It logs the panic and sets the last error.
func recoverPanic(name string) {
	if recover() != nil {
		// Panic values from parsers can contain request bytes. Keep both logs and
		// the Rust-visible error generic so a failure cannot exfiltrate payloads.
		err := fmt.Errorf("panic in %s", name)
		log.Error().Str("function", name).Msg("recovered panic in FFI export")
		setLastError(err)
		metricsErrors.Add(1)
	}
}

var (
	lastErrorMu sync.Mutex
	lastError   string
)

func setLastError(err error) {
	if err == nil {
		return
	}
	lastErrorMu.Lock()
	lastError = err.Error()
	lastErrorMu.Unlock()
}

// Pre-allocated action strings to avoid repeated C.CString allocations.
var (
	actionAllow    = C.CString("allow")
	actionDeny     = C.CString("deny")
	actionDrop     = C.CString("drop")
	actionRedirect = C.CString("redirect")
	emptyStr       = C.CString("")
)

func actionToCString(action string) *C.char {
	switch action {
	case "deny":
		return actionDeny
	case "drop":
		return actionDrop
	case "redirect":
		return actionRedirect
	case "allow":
		return actionAllow
	default:
		// This function is called for an actual Coraza interruption. An
		// unfamiliar disruptive action must fail closed rather than silently
		// turning into allow after an engine upgrade or custom action.
		return actionDeny
	}
}

func denyResult() C.coraza_result_t {
	return C.coraza_result_t{
		action: actionDeny,
		status: 403,
		data:   emptyStr,
	}
}

func engineErrorResult(status int) C.coraza_result_t {
	return C.coraza_result_t{
		action: actionDeny,
		status: C.int(status),
		data:   emptyStr,
	}
}

func allowResult() C.coraza_result_t {
	return C.coraza_result_t{
		rule_id:       0,
		action:        actionAllow,
		status:        0,
		data:          emptyStr,
		anomaly_score: 0,
		rules_hit:     0,
	}
}

//export coraza_waf_new
func coraza_waf_new(
	directives *C.char,
	directivesLen C.int,
	directivesFile *C.char,
	rootFSPath *C.char,
	reqBodyLimit C.int,
	reqBodyMemLimit C.int,
	respBodyLimit C.int,
	ruleMatchLog C.int,
	matchedDataLogMode C.int,
	matchedDataMaxBytes C.int,
) (ret C.uint64_t) {
	defer recoverPanic("coraza_waf_new")
	goDirectives := C.GoStringN(directives, directivesLen)

	goDirectivesFile := ""
	if directivesFile != nil {
		goDirectivesFile = C.GoString(directivesFile)
	}

	goRootFS := ""
	if rootFSPath != nil {
		goRootFS = C.GoString(rootFSPath)
	}

	handle, _, err := createWAF(
		goDirectives,
		goDirectivesFile,
		goRootFS,
		int(reqBodyLimit),
		int(reqBodyMemLimit),
		int(respBodyLimit),
		ruleMatchLog != 0,
		int(matchedDataLogMode),
		int(matchedDataMaxBytes),
	)
	if err != nil {
		setLastError(err)
		return 0
	}

	return C.uint64_t(handle)
}

//export coraza_waf_rules_count
func coraza_waf_rules_count(waf C.uint64_t) (ret C.int) {
	defer recoverPanic("coraza_waf_rules_count")
	inst, err := getWAF(uint64(waf))
	if err != nil {
		return 0
	}
	return C.int(inst.rulesCount)
}

//export coraza_waf_free
func coraza_waf_free(waf C.uint64_t) {
	defer recoverPanic("coraza_waf_free")
	destroyWAF(uint64(waf))
}

//export coraza_waf_active_count
func coraza_waf_active_count() (ret C.int) {
	defer recoverPanic("coraza_waf_active_count")
	return C.int(activeWAFCount())
}

//export coraza_free_string
func coraza_free_string(s *C.char) {
	defer recoverPanic("coraza_free_string")
	if s != nil && s != actionAllow && s != actionDeny && s != actionDrop && s != actionRedirect && s != emptyStr {
		C.free(unsafe.Pointer(s))
	}
}

//export coraza_last_error
func coraza_last_error() (ret *C.char) {
	defer recoverPanic("coraza_last_error")
	lastErrorMu.Lock()
	err := lastError
	lastError = ""
	lastErrorMu.Unlock()

	if err == "" {
		return nil
	}
	return C.CString(err)
}

//export coraza_shutdown
func coraza_shutdown() {
	defer recoverPanic("coraza_shutdown")
	drainCache()
	destroyAllWAFs()
}

func main() {}
