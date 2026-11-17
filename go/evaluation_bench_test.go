package main

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/corazawaf/coraza/v3/types"
)

// chartDefaultDirectives is what HAPTIC renders for a default-on detect policy
// with requestBody.mode: none (issue haproxy-haptic/HAPTIC#697).
const chartDefaultDirectives = `Include @coraza.conf-recommended
SecRxPreFilter On
Include @crs-setup.conf.example
Include @owasp_crs/*.conf
SecRuleEngine On
SecRequestBodyAccess Off
`

type benchRequest struct {
	method, path, query string
	headers             [][2]string
}

var benignRequest = benchRequest{
	method:  "GET",
	path:    "/",
	headers: [][2]string{{"Host", "example"}, {"User-Agent", "oha/1.4.5"}},
}

func newChartWAF(tb testing.TB) uint64 {
	tb.Helper()
	handle, _, err := createWAF(chartDefaultDirectives, "", "", 0, 0, 0, false, matchedDataNone, 128)
	if err != nil {
		tb.Fatalf("createWAF: %v", err)
	}
	return handle
}

// evalDirect is the issue's reference program: the engine calls alone.
func evalDirect(tb testing.TB, handle uint64, r benchRequest, id string) {
	inst, err := getWAF(handle)
	if err != nil {
		tb.Fatal(err)
	}
	tx := inst.waf.NewTransactionWithID(id)
	tx.ProcessConnection("127.0.0.1", 40000, "127.0.0.1", 8080)
	uri := r.path
	if r.query != "" {
		uri += "?" + r.query
	}
	tx.ProcessURI(uri, r.method, "HTTP/1.1")
	for _, h := range r.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	if tx.ProcessRequestHeaders() == nil {
		if _, err := tx.ProcessRequestBody(); err != nil {
			tb.Fatal(err)
		}
	}
	_ = tx.MatchedRules()
	tx.ProcessLogging()
	_ = tx.Close()
}

// cRequest holds the NUL-terminated buffers the FFI entry point reads.
type cRequest struct {
	method, path, query, version, srcIP, dstIP []byte
	headers                                    []byte
}

func cstr(s string) []byte { return append([]byte(s), 0) }

func newCRequest(r benchRequest) cRequest {
	var hdrs []byte
	for _, h := range r.headers {
		hdrs = append(hdrs, h[0]...)
		hdrs = append(hdrs, 0)
		hdrs = append(hdrs, h[1]...)
		hdrs = append(hdrs, 0)
	}
	return cRequest{
		method: cstr(r.method), path: cstr(r.path), query: cstr(r.query),
		version: cstr("HTTP/1.1"), srcIP: cstr("127.0.0.1"), dstIP: cstr("127.0.0.1"),
		headers: hdrs,
	}
}

func cptr(b []byte) *_Ctype_char { return (*_Ctype_char)(unsafe.Pointer(&b[0])) }

// evalPlugin calls the exported FFI entry point with the hub's arguments.
func evalPlugin(handle uint64, r cRequest, id string) _Ctype_coraza_result_t {
	idBuf := cstr(id)
	res := coraza_process_request(
		_Ctype_uint64_t(handle), cptr(idBuf),
		cptr(r.srcIP), 40000, cptr(r.dstIP), 8080,
		cptr(r.method), cptr(r.path), cptr(r.query), cptr(r.version),
		cptr(r.headers), _Ctype_int(len(r.headers)),
		nil, 0,
		0, 1024, 0, 0, 128,
	)
	coraza_free_string(res.data)
	coraza_free_string(res.matched_rules)
	coraza_free_string(res.matched_var)
	return res
}

func BenchmarkEvaluationDirect(b *testing.B) {
	handle := newChartWAF(b)
	defer destroyWAF(handle)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		evalDirect(b, handle, benignRequest, strconv.Itoa(i))
	}
}

func BenchmarkEvaluationPlugin(b *testing.B) {
	handle := newChartWAF(b)
	defer destroyWAF(handle)
	r := newCRequest(benignRequest)
	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		evalPlugin(handle, r, strconv.Itoa(i))
	}
}

// threadCPU is the calling OS thread's CPU time. Unlike wall time it does not
// grow when other load on the machine deschedules the thread.
func threadCPU() time.Duration {
	const clockThreadCPUTimeID = 3
	var ts syscall.Timespec
	_, _, _ = syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockThreadCPUTimeID, uintptr(unsafe.Pointer(&ts)), 0)
	return time.Duration(ts.Nano())
}

func processCPU() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

type abSide struct {
	wall, cpu []time.Duration
}

func (s *abSide) measure(eval func()) {
	w, c := time.Now(), threadCPU()
	eval()
	s.cpu = append(s.cpu, threadCPU()-c)
	s.wall = append(s.wall, time.Since(w))
}

// TestEvaluationLatencyAB interleaves direct and plugin evaluations so both
// see the same machine noise. Opt in with CORAZA_AB_ROUNDS=<n>;
// CORAZA_AB_PACE=<duration> sleeps before each evaluation to model low load.
func TestEvaluationLatencyAB(t *testing.T) {
	rounds, _ := strconv.Atoi(os.Getenv("CORAZA_AB_ROUNDS"))
	if rounds <= 0 {
		t.Skip("set CORAZA_AB_ROUNDS to run")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	handle := newChartWAF(t)
	defer destroyWAF(handle)
	r := newCRequest(benignRequest)
	for i := 0; i < 200; i++ {
		evalDirect(t, handle, benignRequest, strconv.Itoa(i))
		evalPlugin(handle, r, strconv.Itoa(i))
	}
	pace, _ := time.ParseDuration(os.Getenv("CORAZA_AB_PACE"))
	var direct, plugin abSide
	start := processCPU()
	for i := 0; i < rounds; i++ {
		time.Sleep(pace)
		direct.measure(func() { evalDirect(t, handle, benignRequest, strconv.Itoa(i)) })
		time.Sleep(pace)
		plugin.measure(func() { evalPlugin(handle, r, strconv.Itoa(i)) })
	}
	t.Logf("process CPU per evaluation, both sides incl. GC: %v", (processCPU()-start)/time.Duration(2*rounds))
	t.Logf("direct wall %s", percentiles(direct.wall))
	t.Logf("plugin wall %s", percentiles(plugin.wall))
	t.Logf("direct cpu  %s", percentiles(direct.cpu))
	t.Logf("plugin cpu  %s", percentiles(plugin.cpu))
}

func percentiles(d []time.Duration) string {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	at := func(q float64) time.Duration { return d[int(q*float64(len(d)-1))] }
	var sum time.Duration
	for _, v := range d {
		sum += v
	}
	return fmt.Sprintf("n=%d mean=%v p50=%v p90=%v p99=%v", len(d),
		sum/time.Duration(len(d)), at(0.5), at(0.9), at(0.99))
}

func benignMatchedRules(b *testing.B) []types.MatchedRule {
	handle := newChartWAF(b)
	b.Cleanup(func() { destroyWAF(handle) })
	inst, err := getWAF(handle)
	if err != nil {
		b.Fatal(err)
	}
	tx := inst.waf.NewTransaction()
	tx.ProcessConnection("127.0.0.1", 40000, "127.0.0.1", 8080)
	tx.ProcessURI("/", "GET", "HTTP/1.1")
	for _, h := range benignRequest.headers {
		tx.AddRequestHeader(h[0], h[1])
	}
	tx.ProcessRequestHeaders()
	if _, err := tx.ProcessRequestBody(); err != nil {
		b.Fatal(err)
	}
	return tx.MatchedRules()
}

func BenchmarkMatchedRulesJSON(b *testing.B) {
	rules := benignMatchedRules(b)
	b.Logf("%d matched rules", len(rules))
	b.Run("encoding-json", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = legacyMatchedRulesJSON(rules)
		}
	})
	b.Run("append", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = appendMatchedRulesJSON(make([]byte, 0, 24*len(rules)+3), rules)
		}
	})
}
