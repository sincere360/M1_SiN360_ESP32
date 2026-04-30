#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "esp_log.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/etharp.h"
#include "lwip/ip4_addr.h"
#include "ping/ping_sock.h"
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

/* ---- LAN scanners ---- */

#define NETSCAN_MAX_RESULTS 32
#define NETSCAN_MODE_SSH    0
#define NETSCAN_MODE_TELNET 1
#define NETSCAN_MODE_COMMON 2
#define NETSCAN_MODE_PING   3
#define NETSCAN_MODE_ARP    4

typedef struct {
    uint8_t ip[4];
    uint16_t port;
    uint8_t mac[6];
    bool has_mac;
} netscan_result_t;

typedef struct {
    SemaphoreHandle_t done;
    bool success;
} netscan_ping_ctx_t;

static TaskHandle_t netscan_task_handle = NULL;
static volatile bool netscan_running = false;
static volatile bool netscan_done = false;
static volatile uint8_t netscan_progress = 0;
static uint8_t netscan_mode = NETSCAN_MODE_COMMON;
static uint8_t netscan_timeout_ms = 80;
static uint8_t netscan_base_ip[4];
static uint32_t netscan_interface_idx = 0;
static esp_netif_t *netscan_esp_netif = NULL;
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

static void netscan_ping_success(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    netscan_ping_ctx_t *ctx = (netscan_ping_ctx_t *)args;
    if (ctx) {
        ctx->success = true;
    }
}

static void netscan_ping_end(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    netscan_ping_ctx_t *ctx = (netscan_ping_ctx_t *)args;
    if (ctx && ctx->done) {
        xSemaphoreGive(ctx->done);
    }
}

static bool netscan_ping_host(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t timeout_ms)
{
    netscan_ping_ctx_t ctx = {
        .done = xSemaphoreCreateBinary(),
        .success = false,
    };
    if (!ctx.done) return false;

    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.count = 1;
    cfg.interval_ms = 10;
    cfg.timeout_ms = timeout_ms;
    cfg.data_size = 16;
    cfg.task_stack_size = 2048;
    cfg.task_prio = 2;
    cfg.interface = netscan_interface_idx;
    IP_ADDR4(&cfg.target_addr, a, b, c, d);

    esp_ping_callbacks_t cbs = {
        .cb_args = &ctx,
        .on_ping_success = netscan_ping_success,
        .on_ping_timeout = NULL,
        .on_ping_end = netscan_ping_end,
    };

    esp_ping_handle_t ping = NULL;
    if (esp_ping_new_session(&cfg, &cbs, &ping) != ESP_OK) {
        vSemaphoreDelete(ctx.done);
        return false;
    }

    if (esp_ping_start(ping) == ESP_OK) {
        xSemaphoreTake(ctx.done, pdMS_TO_TICKS(timeout_ms + 500));
    }

    esp_ping_stop(ping);
    esp_ping_delete_session(ping);
    vSemaphoreDelete(ctx.done);
    return ctx.success;
}

static bool netscan_arp_host(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t mac[6])
{
    if (!netscan_esp_netif) return false;

    struct netif *netif = (struct netif *)esp_netif_get_netif_impl(netscan_esp_netif);
    if (!netif) return false;

    ip4_addr_t ip;
    IP4_ADDR(&ip, a, b, c, d);

    etharp_request(netif, &ip);
    vTaskDelay(pdMS_TO_TICKS(netscan_timeout_ms));

    struct eth_addr *eth_ret = NULL;
    const ip4_addr_t *ip_ret = NULL;
    if (etharp_find_addr(netif, &ip, &eth_ret, &ip_ret) >= 0 && eth_ret) {
        memcpy(mac, eth_ret->addr, 6);
        return true;
    }

    return false;
}

static void netscan_add_result(uint8_t d, uint16_t port, const uint8_t mac[6])
{
    if (netscan_result_count >= NETSCAN_MAX_RESULTS) return;

    netscan_result_t *r = &netscan_results[netscan_result_count++];
    r->ip[0] = netscan_base_ip[0];
    r->ip[1] = netscan_base_ip[1];
    r->ip[2] = netscan_base_ip[2];
    r->ip[3] = d;
    r->port = port;
    if (mac) {
        memcpy(r->mac, mac, sizeof(r->mac));
        r->has_mac = true;
    } else {
        memset(r->mac, 0, sizeof(r->mac));
        r->has_mac = false;
    }
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
                netscan_add_result((uint8_t)host, 22, NULL);
            }
        } else if (netscan_mode == NETSCAN_MODE_TELNET) {
            if (netscan_tcp_open(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                (uint8_t)host, 23, netscan_timeout_ms)) {
                netscan_add_result((uint8_t)host, 23, NULL);
            }
        } else if (netscan_mode == NETSCAN_MODE_PING) {
            if (netscan_ping_host(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                (uint8_t)host, netscan_timeout_ms)) {
                netscan_add_result((uint8_t)host, 0, NULL);
            }
        } else if (netscan_mode == NETSCAN_MODE_ARP) {
            uint8_t mac[6];
            if (netscan_arp_host(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                (uint8_t)host, mac)) {
                netscan_add_result((uint8_t)host, 0, mac);
            }
        } else {
            for (uint8_t i = 0; i < sizeof(common_ports) / sizeof(common_ports[0]) && netscan_running; i++) {
                if (netscan_tcp_open(netscan_base_ip[0], netscan_base_ip[1], netscan_base_ip[2],
                    (uint8_t)host, common_ports[i], netscan_timeout_ms)) {
                    netscan_add_result((uint8_t)host, common_ports[i], NULL);
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
    if (netscan_mode > NETSCAN_MODE_ARP) netscan_mode = NETSCAN_MODE_COMMON;
    netscan_timeout_ms = (cmd->payload_len >= 2 && cmd->payload[1] >= 20) ? cmd->payload[1] : 80;

    netscan_esp_netif = netif;
    int netif_idx = esp_netif_get_netif_impl_index(netif);
    netscan_interface_idx = netif_idx > 0 ? (uint32_t)netif_idx : 0;

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
        resp->payload[9] = r->has_mac ? 1 : 0;
        if (r->has_mac) {
            memcpy(&resp->payload[10], r->mac, 6);
            resp->payload_len = 16;
        } else {
            resp->payload_len = 10;
        }
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
