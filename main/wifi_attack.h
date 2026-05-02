#pragma once

#include "m1_protocol.h"

void wifi_attack_init(void);
void deauth_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void deauth_multi_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void deauth_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void beacon_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void beacon_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void beacon_set_flags(const m1_cmd_t *cmd, m1_resp_t *resp);
void probe_flood_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void probe_flood_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void karma_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void karma_portal_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void karma_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void karma_status(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_raw_attack_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_raw_attack_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void ssid_add(const m1_cmd_t *cmd, m1_resp_t *resp);
void ssid_clear(const m1_cmd_t *cmd, m1_resp_t *resp);
void ssid_get_count(const m1_cmd_t *cmd, m1_resp_t *resp);
