#pragma once

#include "m1_protocol.h"

void wifi_scan_init(void);
void wifi_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_join(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_disconnect(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_set_mac(const m1_cmd_t *cmd, m1_resp_t *resp);
void wifi_set_channel(const m1_cmd_t *cmd, m1_resp_t *resp);
void netscan_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void netscan_next(const m1_cmd_t *cmd, m1_resp_t *resp);
void netscan_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
