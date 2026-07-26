#ifndef CORAZA_TYPES_H
#define CORAZA_TYPES_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    int rule_id;
    const char *action;
    int status;
    const char *data;
    int anomaly_score;
    int rules_hit;
    /* Compact JSON array of every matched rule for per-rule metrics:
       [{"i":<rule id>,"s":<severity 0-7>}, ...]. NULL when no rules
       matched. Heap-allocated; the caller frees via coraza_free_string. */
    const char *matched_rules;
    /* Name of the request field a rule matched on, as VARIABLE or
       VARIABLE:KEY (e.g. "ARGS:q", "REQUEST_HEADERS:User-Agent"). The NAME
       only — never the matched value, so this is safe to log where `data` is
       not. Prefers the rule reported in rule_id; falls back to the first
       matched rule that names a target. NULL when nothing matched.
       Heap-allocated; the caller frees via coraza_free_string. */
    const char *matched_var;
} coraza_result_t;

#endif
