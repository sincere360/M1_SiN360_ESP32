#pragma once

#include "m1_protocol.h"

void pktmon_init(void);
void pktmon_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void pktmon_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void pktmon_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void pktmon_set_channel(const m1_cmd_t *cmd, m1_resp_t *resp);
void pktmon_raw_next(const m1_cmd_t *cmd, m1_resp_t *resp);

void sta_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void sta_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void sta_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
