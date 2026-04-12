package main

/*
#include "coraza_types.h"
*/
import "C"
import "sync/atomic"

var (
	metricsAllowed  atomic.Int64
	metricsBlocked  atomic.Int64
	metricsRulesHit atomic.Int64
	metricsErrors   atomic.Int64
)

//export coraza_metrics_allowed
func coraza_metrics_allowed() (ret C.longlong) {
	defer recoverPanic("coraza_metrics_allowed")
	return C.longlong(metricsAllowed.Load())
}

//export coraza_metrics_blocked
func coraza_metrics_blocked() (ret C.longlong) {
	defer recoverPanic("coraza_metrics_blocked")
	return C.longlong(metricsBlocked.Load())
}

//export coraza_metrics_rules_hit
func coraza_metrics_rules_hit() (ret C.longlong) {
	defer recoverPanic("coraza_metrics_rules_hit")
	return C.longlong(metricsRulesHit.Load())
}

//export coraza_metrics_errors
func coraza_metrics_errors() (ret C.longlong) {
	defer recoverPanic("coraza_metrics_errors")
	return C.longlong(metricsErrors.Load())
}

//export coraza_metrics_reset
func coraza_metrics_reset() {
	defer recoverPanic("coraza_metrics_reset")
	metricsAllowed.Store(0)
	metricsBlocked.Store(0)
	metricsRulesHit.Store(0)
	metricsErrors.Store(0)
}
