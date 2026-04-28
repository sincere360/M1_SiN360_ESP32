#pragma once

#include "m1_protocol.h"

void ble_ops_init(void);
void ble_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_scan_next_raw(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_adv_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_adv_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_adv_raw(const m1_cmd_t *cmd, m1_resp_t *resp);
