#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "m1_protocol.h"

void portal_init(void);
bool portal_prepare_ap(const char *ssid, uint8_t channel);
bool portal_services_start(bool reset_creds);
void portal_services_stop(bool restore_sta);
void portal_start(const m1_cmd_t *cmd, m1_resp_t *resp);
void portal_stop(const m1_cmd_t *cmd, m1_resp_t *resp);
void portal_get_creds(const m1_cmd_t *cmd, m1_resp_t *resp);
void portal_html_clear(const m1_cmd_t *cmd, m1_resp_t *resp);
void portal_html_add(const m1_cmd_t *cmd, m1_resp_t *resp);
