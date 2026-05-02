#include <string.h>
#include "esp_log.h"
#include "esp_system.h"
#include "command_handler.h"
#include "wifi_scan.h"
#include "wifi_attack.h"
#include "pkt_monitor.h"
#include "evil_portal.h"
#include "ble_ops.h"

static const char *TAG = "cmd_handler";

static void cmd_ping(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    resp->status = RESP_OK;
    resp->payload_len = 4;
    memcpy(resp->payload, "PONG", 4);
}

static void cmd_get_status(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    resp->status = RESP_OK;

    /* Payload: [fw_major, fw_minor, fw_patch, wifi_state, ble_state] */
    resp->payload[0] = 1;  /* FW v1.0.0 */
    resp->payload[1] = 0;
    resp->payload[2] = 0;
    resp->payload[3] = 0;  /* TODO: actual wifi state */
    resp->payload[4] = 0;  /* TODO: actual ble state */
    resp->payload_len = 5;
}

void cmd_handle(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    /* Pre-fill response header */
    memset(resp, 0, sizeof(m1_resp_t));
    resp->magic = M1_RESP_MAGIC;
    resp->cmd_id = cmd->cmd_id;
    resp->status = RESP_ERR;     /* default to error, handlers override on success */
    resp->payload_len = 0;

    switch (cmd->cmd_id) {
    /* System */
    case CMD_PING:            cmd_ping(cmd, resp);              break;
    case CMD_GET_STATUS:      cmd_get_status(cmd, resp);        break;

    /* WiFi scan */
    case CMD_WIFI_SCAN_START: wifi_scan_start(cmd, resp);       break;
    case CMD_WIFI_SCAN_NEXT:  wifi_scan_next(cmd, resp);        break;
    case CMD_WIFI_SCAN_STOP:  wifi_scan_stop(cmd, resp);        break;

    /* BLE */
    case CMD_BLE_SCAN_START:  ble_scan_start(cmd, resp);        break;
    case CMD_BLE_SCAN_NEXT:   ble_scan_next(cmd, resp);         break;
    case CMD_BLE_SCAN_STOP:   ble_scan_stop(cmd, resp);         break;
    case CMD_BLE_ADV_START:   ble_adv_start(cmd, resp);         break;
    case CMD_BLE_ADV_STOP:    ble_adv_stop(cmd, resp);          break;
    case CMD_BLE_ADV_RAW:     ble_adv_raw(cmd, resp);           break;
    case CMD_BLE_SCAN_NEXT_RAW: ble_scan_next_raw(cmd, resp);    break;
    case CMD_BLE_ADV_RAW_EX:  ble_adv_raw_ex(cmd, resp);        break;
    case CMD_BLE_GATT_START:  ble_gatt_start(cmd, resp);        break;
    case CMD_BLE_GATT_NEXT:   ble_gatt_next(cmd, resp);         break;
    case CMD_BLE_GATT_STOP:   ble_gatt_stop(cmd, resp);         break;
    case CMD_BLE_GATT_WRITE:  ble_gatt_write(cmd, resp);        break;
    case CMD_BLE_GATT_SUB:    ble_gatt_subscribe(cmd, resp);    break;
    case CMD_BLE_GATT_NOTIF:  ble_gatt_notify_next(cmd, resp);  break;

    /* WiFi attacks */
    case CMD_DEAUTH_START:    deauth_start(cmd, resp);          break;
    case CMD_DEAUTH_STOP:     deauth_stop(cmd, resp);           break;
    case CMD_BEACON_START:    beacon_start(cmd, resp);          break;
    case CMD_BEACON_STOP:     beacon_stop(cmd, resp);           break;
    case CMD_PROBE_FLOOD_START: probe_flood_start(cmd, resp);  break;
    case CMD_PROBE_FLOOD_STOP:  probe_flood_stop(cmd, resp);   break;
    case CMD_BEACON_SET_FLAGS:  beacon_set_flags(cmd, resp);   break;
    case CMD_KARMA_START:     karma_start(cmd, resp);           break;
    case CMD_KARMA_STOP:      karma_stop(cmd, resp);            break;
    case CMD_DEAUTH_MULTI:    deauth_multi_start(cmd, resp);    break;
    case CMD_KARMA_STATUS:    karma_status(cmd, resp);          break;
    case CMD_KARMA_PORTAL_START: karma_portal_start(cmd, resp); break;
    case CMD_WIFI_RAW_ATTACK_START: wifi_raw_attack_start(cmd, resp); break;
    case CMD_WIFI_RAW_ATTACK_STOP: wifi_raw_attack_stop(cmd, resp);   break;

    /* Station scan */
    case CMD_STA_SCAN_START:  sta_scan_start(cmd, resp);        break;
    case CMD_STA_SCAN_NEXT:   sta_scan_next(cmd, resp);         break;
    case CMD_STA_SCAN_STOP:   sta_scan_stop(cmd, resp);         break;

    /* Packet monitor */
    case CMD_PKTMON_START:    pktmon_start(cmd, resp);          break;
    case CMD_PKTMON_NEXT:     pktmon_next(cmd, resp);           break;
    case CMD_PKTMON_STOP:     pktmon_stop(cmd, resp);           break;
    case CMD_PKTMON_SET_CHAN: pktmon_set_channel(cmd, resp);    break;
    case CMD_PKTMON_RAW_NEXT: pktmon_raw_next(cmd, resp);       break;

    /* SSID management */
    case CMD_SSID_ADD:        ssid_add(cmd, resp);              break;
    case CMD_SSID_CLEAR:      ssid_clear(cmd, resp);            break;
    case CMD_SSID_COUNT:      ssid_get_count(cmd, resp);        break;

    /* WiFi general */
    case CMD_WIFI_JOIN:       wifi_join(cmd, resp);             break;
    case CMD_WIFI_DISCONNECT: wifi_disconnect(cmd, resp);       break;
    case CMD_WIFI_SET_MAC:    wifi_set_mac(cmd, resp);          break;
    case CMD_WIFI_SET_CHANNEL: wifi_set_channel(cmd, resp);     break;
    case CMD_NETSCAN_START:   netscan_start(cmd, resp);         break;
    case CMD_NETSCAN_NEXT:    netscan_next(cmd, resp);          break;
    case CMD_NETSCAN_STOP:    netscan_stop(cmd, resp);          break;

    /* Evil portal */
    case CMD_PORTAL_START:    portal_start(cmd, resp);          break;
    case CMD_PORTAL_STOP:     portal_stop(cmd, resp);           break;
    case CMD_PORTAL_CREDS:    portal_get_creds(cmd, resp);      break;
    case CMD_PORTAL_HTML_CLEAR: portal_html_clear(cmd, resp);   break;
    case CMD_PORTAL_HTML_ADD: portal_html_add(cmd, resp);       break;

    default:
        ESP_LOGW(TAG, "Unknown cmd_id: 0x%02X", cmd->cmd_id);
        resp->status = RESP_ERR;
        break;
    }
}
