#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "wifi_scan.h"

extern bool m1_wifi_is_started(void);

static const char *TAG = "wifi_scan";

#define MAX_SCAN_RESULTS 64

static wifi_ap_record_t ap_records[MAX_SCAN_RESULTS];
static uint16_t ap_count = 0;
static uint16_t ap_index = 0;
static bool scan_active = false;

void wifi_scan_init(void)
{
}

void wifi_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (scan_active) {
        resp->status = RESP_BUSY;
        return;
    }

    if (!m1_wifi_is_started()) {
        resp->status = RESP_ERR;
        return;
    }

    ap_count = 0;
    ap_index = 0;
    memset(ap_records, 0, sizeof(ap_records));

    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 120,
        .scan_time.active.max = 500,
    };

    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "scan_start failed: %s", esp_err_to_name(err));
        resp->status = RESP_ERR;
        return;
    }

    ap_count = MAX_SCAN_RESULTS;
    esp_wifi_scan_get_ap_records(&ap_count, ap_records);
    scan_active = true;

    ESP_LOGI(TAG, "Scan complete: %u APs", ap_count);

    resp->status = RESP_OK;
    resp->payload[0] = (uint8_t)(ap_count & 0xFF);
    resp->payload[1] = (uint8_t)(ap_count >> 8);
    resp->payload_len = 2;
}

void wifi_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (!scan_active || ap_index >= ap_count) {
        resp->status = RESP_ERR;
        resp->payload[0] = 0;
        resp->payload_len = 1;
        return;
    }

    wifi_ap_record_t *ap = &ap_records[ap_index++];

    resp->payload[0] = (uint8_t)ap->rssi;
    resp->payload[1] = ap->primary;
    resp->payload[2] = (uint8_t)ap->authmode;
    memcpy(&resp->payload[3], ap->bssid, 6);
    uint8_t ssid_len = (uint8_t)strnlen((char *)ap->ssid, 32);
    resp->payload[9] = ssid_len;
    memcpy(&resp->payload[10], ap->ssid, ssid_len);

    resp->payload_len = 10 + ssid_len;
    resp->status = RESP_OK;
}

void wifi_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
	(void)cmd;

    esp_wifi_scan_stop();
    scan_active = false;
    ap_count = 0;
    ap_index = 0;

	resp->status = RESP_OK;
	resp->payload_len = 0;
}

void wifi_join(const m1_cmd_t *cmd, m1_resp_t *resp)
{
	if (cmd->payload_len < 2) {
		resp->status = RESP_ERR;
		return;
	}

	uint8_t ssid_len = cmd->payload[0];
	uint8_t pass_len = cmd->payload[1];

	if (ssid_len == 0 || ssid_len > 32 || pass_len > 63 ||
		2 + ssid_len + pass_len > cmd->payload_len) {
		resp->status = RESP_ERR;
		return;
	}

	wifi_config_t cfg;
	memset(&cfg, 0, sizeof(cfg));
	memcpy(cfg.sta.ssid, &cmd->payload[2], ssid_len);
	if (pass_len > 0) {
		memcpy(cfg.sta.password, &cmd->payload[2 + ssid_len], pass_len);
	}

	esp_wifi_scan_stop();
	scan_active = false;
	ap_count = 0;
	ap_index = 0;
	esp_wifi_set_promiscuous(false);
	esp_wifi_set_mode(WIFI_MODE_STA);
	esp_wifi_disconnect();

	esp_err_t err = esp_wifi_set_config(WIFI_IF_STA, &cfg);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "join set_config failed: %s", esp_err_to_name(err));
		resp->status = RESP_ERR;
		return;
	}

	err = esp_wifi_connect();
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "join connect failed: %s", esp_err_to_name(err));
		resp->status = RESP_ERR;
		return;
	}

	wifi_ap_record_t ap;
	for (int i = 0; i < 80; i++) {
		if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
			resp->payload[0] = ap.primary;
			resp->payload[1] = (uint8_t)ap.rssi;
			resp->payload_len = 2;
			resp->status = RESP_OK;
			return;
		}
		vTaskDelay(pdMS_TO_TICKS(100));
	}

	resp->status = RESP_BUSY;
	resp->payload_len = 0;
}

void wifi_disconnect(const m1_cmd_t *cmd, m1_resp_t *resp)
{
	(void)cmd;

    esp_wifi_scan_stop();
    scan_active = false;
    ap_count = 0;
    ap_index = 0;

    esp_wifi_set_promiscuous(false);
    esp_wifi_disconnect();

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "wifi_set_mode STA failed: %s", esp_err_to_name(err));
        resp->status = RESP_ERR;
        return;
    }

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void wifi_set_mac(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (cmd->payload_len < 7) {
        resp->status = RESP_ERR;
        return;
    }

    wifi_interface_t iface = (cmd->payload[0] == 1) ? WIFI_IF_AP : WIFI_IF_STA;
    uint8_t mac[6];
    memcpy(mac, &cmd->payload[1], 6);

    /* Force a locally administered unicast MAC for user-provided values. */
    mac[0] &= 0xFE;
    mac[0] |= 0x02;

    esp_wifi_disconnect();
    esp_wifi_set_promiscuous(false);

    esp_err_t err = esp_wifi_set_mac(iface, mac);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set MAC failed iface=%d: %s", iface, esp_err_to_name(err));
        resp->status = RESP_ERR;
        return;
    }

    resp->payload[0] = cmd->payload[0];
    memcpy(&resp->payload[1], mac, 6);
    resp->payload_len = 7;
    resp->status = RESP_OK;
}

void wifi_set_channel(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (cmd->payload_len < 1) {
        resp->status = RESP_ERR;
        return;
    }

    uint8_t channel = cmd->payload[0];
    if (channel < 1 || channel > 13) {
        resp->status = RESP_ERR;
        return;
    }

    esp_err_t err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "set channel %u failed: %s", channel, esp_err_to_name(err));
        resp->status = RESP_ERR;
        return;
    }

    resp->payload[0] = channel;
    resp->payload_len = 1;
    resp->status = RESP_OK;
}

/* ---- LAN TCP scanners ---- */

#define NETSCAN_MAX_RESULTS 32
#define NETSCAN_MODE_SSH    0
#define NETSCAN_MODE_TELNET 1
#define NETSCAN_MODE_COMMON 2

typedef struct {
    uint8_t ip[4];
    uint16_t port;
} netscan_result_t;

static TaskHandle_t netscan_task_handle = NULL;
static volatile bool netscan_running = false;
static volatile bool netscan_done = false;
static volatile uint8_t netscan_progress = 0;
static uint8_t netscan_mode = NETSCAN_MODE_COMMON;
static uint8_t netscan_timeout_ms = 80;
static uint8_t netscan_base_ip[4];
static netscan_result_t netscan_results[NETSCAN_MAX_RESULTS];
static uint8_t netscan_result_count = 0;
static uint8_t netscan_read_idx = 0;

static bool netscan_tcp_open(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port, uint8_t timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = PP_HTONL(LWIP_MAKEU32(a, b, c, d));

    int rc = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
    if (rc == 0) {
        close(sock);
        return true;
    }

    if (errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv = {
        .tv_sec = 0,
        .tv_usec = timeout_ms * 1000,
    };

    rc = select(sock + 1, NULL, &wfds, NULL, &tv);
    if (rc > 0 && FD_ISSET(sock, &wfds)) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        close(sock);
        return err == 0;
    }

    close(sock);
    return false;
}

static void netscan_add_result(uint8_t d, uint16_t port)
{
    if (netscan_result_count >= NETSCAN_MAX_RESULTS) return;

    netscan_result_t *r = &netscan_results[netscan_result_count++];
    r->ip[0] = netscan_base_ip[0];
    r->ip[1] = netscan_base_ip[1];
    r->ip[2] = netscan_base_ip[2];
    r->ip[3] = d;
    r->port = port;
}

static void netscan_task(void *arg)
{
    (void)arg;
    static const uint16_t common_ports[] = {22, 23, 80, 443};
    uint8_t self = netscan_base_ip[3];

    for (uint16_t host = 1; host <= 254 && netscan_running; host++) {
        if ((uint8_t)host == self) {
            continue;
        }

        netscan_progress = (uint8_t)host;

        if (netscan_mode == NETSCAN_MODE_SSH) {
            if (netscan_tcp_open(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                (uint8_t)host, 22, netscan_timeout_ms)) {
                netscan_add_result((uint8_t)host, 22);
            }
        } else if (netscan_mode == NETSCAN_MODE_TELNET) {
            if (netscan_tcp_open(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                (uint8_t)host, 23, netscan_timeout_ms)) {
                netscan_add_result((uint8_t)host, 23);
            }
        } else {
            for (uint8_t i = 0; i < sizeof(common_ports) / sizeof(common_ports[0]) && netscan_running; i++) {
                if (netscan_tcp_open(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                    (uint8_t)host, common_ports[i], netscan_timeout_ms)) {
                    netscan_add_result((uint8_t)host, common_ports[i]);
                }
            }
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }

    netscan_done = true;
    netscan_running = false;
    netscan_task_handle = NULL;
    vTaskDelete(NULL);
}

void netscan_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (netscan_running) {
        resp->status = RESP_BUSY;
        return;
    }

    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
        resp->status = RESP_ERR;
        return;
    }

    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    if (!netif || esp_netif_get_ip_info(netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0) {
        resp->status = RESP_ERR;
        return;
    }

    netscan_mode = (cmd->payload_len >= 1) ? cmd->payload[0] : NETSCAN_MODE_COMMON;
    if (netscan_mode > NETSCAN_MODE_COMMON) netscan_mode = NETSCAN_MODE_COMMON;
    netscan_timeout_ms = (cmd->payload_len >= 2 && cmd->payload[1] >= 20) ? cmd->payload[1] : 80;

    netscan_base_ip[0] = esp_ip4_addr1_16(&ip_info.ip);
    netscan_base_ip[1] = esp_ip4_addr2_16(&ip_info.ip);
    netscan_base_ip[2] = esp_ip4_addr3_16(&ip_info.ip);
    netscan_base_ip[3] = esp_ip4_addr4_16(&ip_info.ip);
    netscan_result_count = 0;
    netscan_read_idx = 0;
    netscan_progress = 0;
    netscan_done = false;
    memset(netscan_results, 0, sizeof(netscan_results));

    netscan_running = true;
    xTaskCreate(netscan_task, "netscan", 4096, NULL, 4, &netscan_task_handle);

    resp->payload[0] = netscan_base_ip[0];
    resp->payload[1] = netscan_base_ip[1];
    resp->payload[2] = netscan_base_ip[2];
    resp->payload[3] = netscan_base_ip[3];
    resp->payload_len = 4;
    resp->status = RESP_OK;
}

void netscan_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (netscan_read_idx < netscan_result_count) {
        netscan_result_t *r = &netscan_results[netscan_read_idx++];
        resp->payload[0] = 1; /* result */
        resp->payload[1] = r->ip[0];
        resp->payload[2] = r->ip[1];
        resp->payload[3] = r->ip[2];
        resp->payload[4] = r->ip[3];
        resp->payload[5] = (uint8_t)(r->port & 0xFF);
        resp->payload[6] = (uint8_t)(r->port >> 8);
        resp->payload[7] = netscan_result_count;
        resp->payload[8] = netscan_progress;
        resp->payload_len = 9;
        resp->status = RESP_OK;
        return;
    }

    if (netscan_done) {
        resp->payload[0] = 2; /* done */
        resp->payload[1] = netscan_result_count;
        resp->payload[2] = netscan_progress;
        resp->payload_len = 3;
        resp->status = RESP_OK;
        return;
    }

    resp->payload[0] = 0; /* running */
    resp->payload[1] = netscan_result_count;
    resp->payload[2] = netscan_progress;
    resp->payload_len = 3;
    resp->status = RESP_OK;
}

void netscan_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    netscan_running = false;
    netscan_done = true;
    netscan_task_handle = NULL;

    resp->status = RESP_OK;
    resp->payload_len = 0;
}
