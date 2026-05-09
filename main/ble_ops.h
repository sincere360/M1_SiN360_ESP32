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
void ble_adv_raw_ex(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_write(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_subscribe(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_gatt_notify_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_hid_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_hid_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_hid_report(const m1_cmd_t *cmd, m1_resp_t *resp);
void ble_hid_status(const m1_cmd_t *cmd, m1_resp_t *resp);
