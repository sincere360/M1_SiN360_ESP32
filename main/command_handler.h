#pragma once

#include "m1_protocol.h"

/**
 * Process an incoming command and produce a response.
 * Dispatches to the appropriate subsystem based on cmd_id.
 */
void cmd_handle(const m1_cmd_t *cmd, m1_resp_t *resp);
