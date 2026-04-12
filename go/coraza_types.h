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
} coraza_result_t;

#endif
