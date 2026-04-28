#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "pkt_monitor.h"

static const char *TAG = "pkt_monitor";

#define PKT_QUEUE_SIZE     32
#define PKT_DATA_LEN       48
#define MAX_STATIONS        64
#define DEFAULT_HOP_MS      500
#define NUM_CHANNELS        13

/* 802.11 frame control field helpers */
#define FC_TYPE(fc0)        (((fc0) >> 2) & 0x03)
#define FC_SUBTYPE(fc0)     (((fc0) >> 4) & 0x0F)
#define TYPE_MGMT           0
#define TYPE_DATA           2
#define SUB_PROBE_REQ       4
#define SUB_PROBE_RESP      5
#define SUB_BEACON          8
#define SUB_DISASSOC        10
#define SUB_AUTH            11
#define SUB_DEAUTH          12

#define HDR_ADDR1           4
#define HDR_ADDR2           10
#define HDR_ADDR3           16
#define BEACON_IE_OFF       36  /* 24 hdr + 8 timestamp + 2 interval + 2 capability */
#define PROBE_REQ_IE_OFF    24

/* ---- Parsed packet entry ---- */
typedef struct {
    uint8_t  type;
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  data_len;
    uint8_t  data[PKT_DATA_LEN];
} pkt_entry_t;

/* ---- Station table entry ---- */
typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint8_t  bssid[6];
    char     ssid[33];
} sta_entry_t;

/* ---- Per-channel stats for signal monitor ---- */
typedef struct {
    uint32_t pkt_count;
    int32_t  rssi_sum;
} chan_stats_t;

/* ---- State ---- */
static QueueHandle_t      pkt_queue = NULL;
static volatile bool      pktmon_active = false;
static uint8_t            sniff_type = SNIFF_ALL;

static esp_timer_handle_t hop_timer = NULL;
static uint8_t            hop_channel = 1;
static int                hop_users = 0;

static sta_entry_t        sta_table[MAX_STATIONS];
static uint16_t           sta_count = 0;
static uint16_t           sta_index = 0;
static volatile bool      sta_scan_active = false;

static chan_stats_t        chan_stats[NUM_CHANNELS + 1]; /* index 1..13 */

/* ---- Forward declarations ---- */
static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type);

/* ---- IE parsing helpers ---- */

static const uint8_t *find_ie(const uint8_t *ies, uint16_t ies_len,
                              uint8_t tag, uint8_t *out_len)
{
    uint16_t pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t t = ies[pos];
        uint8_t l = ies[pos + 1];
        if (pos + 2 + l > ies_len) break;
        if (t == tag) {
            *out_len = l;
            return &ies[pos + 2];
        }
        pos += 2 + l;
    }
    *out_len = 0;
    return NULL;
}

static uint8_t parse_auth_from_ies(const uint8_t *ies, uint16_t ies_len)
{
    uint8_t len;
    if (find_ie(ies, ies_len, 0x30, &len)) return 3; /* RSN = WPA2+ */
    uint16_t pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t t = ies[pos], l = ies[pos + 1];
        if (pos + 2 + l > ies_len) break;
        if (t == 0xDD && l >= 4) {
            const uint8_t *d = &ies[pos + 2];
            if (d[0] == 0x00 && d[1] == 0x50 && d[2] == 0xF2 && d[3] == 0x01)
                return 2; /* WPA */
        }
        pos += 2 + l;
    }
    return 0; /* Open */
}

static bool check_pwnagotchi(const uint8_t *ies, uint16_t ies_len)
{
    uint16_t pos = 0;
    while (pos + 2 <= ies_len) {
        uint8_t t = ies[pos], l = ies[pos + 1];
        if (pos + 2 + l > ies_len) break;
        if (t == 0xDD && l > 10) {
            const uint8_t *d = &ies[pos + 2];
            for (int i = 0; i + 3 < l; i++) {
                if (d[i] == 'p' && d[i+1] == 'w' && d[i+2] == 'n' && d[i+3] == 'd')
                    return true;
            }
        }
        pos += 2 + l;
    }
    return false;
}

/* ---- Channel hopping ---- */

static void hop_timer_cb(void *arg)
{
    (void)arg;
    hop_channel++;
    if (hop_channel > NUM_CHANNELS) hop_channel = 1;
    esp_wifi_set_channel(hop_channel, WIFI_SECOND_CHAN_NONE);
}

static void start_hop(uint16_t interval_ms)
{
    hop_users++;
    if (hop_timer) return;
    if (!interval_ms) interval_ms = DEFAULT_HOP_MS;

    const esp_timer_create_args_t args = {
        .callback = hop_timer_cb,
        .name = "ch_hop",
    };
    esp_timer_create(&args, &hop_timer);
    esp_timer_start_periodic(hop_timer, (uint64_t)interval_ms * 1000);
    hop_channel = 1;
    ESP_LOGI(TAG, "Channel hop started (%dms)", interval_ms);
}

static void stop_hop(void)
{
    if (hop_users > 0) hop_users--;
    if (hop_users == 0 && hop_timer) {
        esp_timer_stop(hop_timer);
        esp_timer_delete(hop_timer);
        hop_timer = NULL;
    }
}

/* ---- Promiscuous mode management ---- */

static void enable_promiscuous(void)
{
    esp_wifi_set_promiscuous_rx_cb(promiscuous_rx_cb);
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL,
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
}

static void disable_promiscuous_if_idle(void)
{
    if (!pktmon_active && !sta_scan_active) {
        esp_wifi_set_promiscuous(false);
    }
}

/* ---- Station table ---- */

static void sta_add(const uint8_t *mac, int8_t rssi, uint8_t ch,
                    const uint8_t *bssid, const char *ssid, uint8_t ssid_len)
{
    if (mac[0] & 0x01) return; /* skip broadcast/multicast */

    for (uint16_t i = 0; i < sta_count; i++) {
        if (memcmp(sta_table[i].mac, mac, 6) == 0) {
            sta_table[i].rssi = rssi;
            sta_table[i].channel = ch;
            if (bssid) memcpy(sta_table[i].bssid, bssid, 6);
            if (ssid && ssid_len > 0) {
                if (ssid_len > 32) ssid_len = 32;
                memcpy(sta_table[i].ssid, ssid, ssid_len);
                sta_table[i].ssid[ssid_len] = '\0';
            }
            return;
        }
    }

    if (sta_count >= MAX_STATIONS) return;

    memset(&sta_table[sta_count], 0, sizeof(sta_entry_t));
    memcpy(sta_table[sta_count].mac, mac, 6);
    sta_table[sta_count].rssi = rssi;
    sta_table[sta_count].channel = ch;
    if (bssid) memcpy(sta_table[sta_count].bssid, bssid, 6);
    if (ssid && ssid_len > 0) {
        if (ssid_len > 32) ssid_len = 32;
        memcpy(sta_table[sta_count].ssid, ssid, ssid_len);
        sta_table[sta_count].ssid[ssid_len] = '\0';
    }
    sta_count++;
}

/* ---- Promiscuous RX callback ---- */

static void IRAM_ATTR promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t wifi_type)
{
    if (!pktmon_active && !sta_scan_active) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    uint16_t flen = pkt->rx_ctrl.sig_len;
    int8_t rssi = pkt->rx_ctrl.rssi;
    uint8_t ch = pkt->rx_ctrl.channel;

    if (flen < 24) return;

    uint8_t fc0 = f[0];
    uint8_t ftype = FC_TYPE(fc0);
    uint8_t fsub = FC_SUBTYPE(fc0);

    /* Signal monitor: count packets per channel, don't queue */
    if (pktmon_active && sniff_type == SNIFF_SIGNAL) {
        if (ch >= 1 && ch <= NUM_CHANNELS) {
            chan_stats[ch].pkt_count++;
            chan_stats[ch].rssi_sum += rssi;
        }
        if (!sta_scan_active) return;
    }

    /* Station collection from probe requests and data frames */
    if (sta_scan_active) {
        const uint8_t *src = &f[HDR_ADDR2];
        if (ftype == TYPE_MGMT && fsub == SUB_PROBE_REQ) {
            const uint8_t *ies = &f[PROBE_REQ_IE_OFF];
            uint16_t ies_len = (flen > PROBE_REQ_IE_OFF) ? flen - PROBE_REQ_IE_OFF : 0;
            uint8_t sl = 0;
            const uint8_t *ss = find_ie(ies, ies_len, 0, &sl);
            sta_add(src, rssi, ch, NULL, ss ? (const char *)ss : NULL, sl);
        } else if (ftype == TYPE_DATA) {
            sta_add(src, rssi, ch, &f[HDR_ADDR3], NULL, 0);
        }
        if (!pktmon_active) return;
    }

    if (sniff_type == SNIFF_SIGNAL) return;

    /* Build parsed packet entry */
    pkt_entry_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.rssi = rssi;
    entry.channel = ch;
    bool enqueue = false;

    if (ftype == TYPE_MGMT) {
        if (fsub == SUB_BEACON || fsub == SUB_PROBE_RESP) {
            if (sniff_type == SNIFF_ALL || sniff_type == SNIFF_BEACON ||
                sniff_type == SNIFF_PWNAGOTCHI) {
                const uint8_t *ies = &f[BEACON_IE_OFF];
                uint16_t ies_len = (flen > BEACON_IE_OFF) ? flen - BEACON_IE_OFF : 0;

                if (sniff_type == SNIFF_PWNAGOTCHI && !check_pwnagotchi(ies, ies_len)) {
                    /* Not a Pwnagotchi — skip without falling through to raw */
                } else {
                    entry.type = (sniff_type == SNIFF_PWNAGOTCHI) ?
                                  SNIFF_PWNAGOTCHI : SNIFF_BEACON;
                    /* BSSID(6) + auth(1) + ssid_len(1) + SSID(N) */
                    memcpy(entry.data, &f[HDR_ADDR3], 6);
                    entry.data[6] = parse_auth_from_ies(ies, ies_len);
                    uint8_t sl = 0;
                    const uint8_t *ss = find_ie(ies, ies_len, 0, &sl);
                    if (sl > 32) sl = 32;
                    entry.data[7] = sl;
                    if (ss && sl) memcpy(&entry.data[8], ss, sl);
                    entry.data_len = 8 + sl;
                    enqueue = true;
                }
            }

        } else if (fsub == SUB_PROBE_REQ) {
            if (sniff_type == SNIFF_ALL || sniff_type == SNIFF_PROBE_REQ) {
                entry.type = SNIFF_PROBE_REQ;
                /* client_mac(6) + ssid_len(1) + SSID(N) */
                memcpy(entry.data, &f[HDR_ADDR2], 6);
                const uint8_t *ies = &f[PROBE_REQ_IE_OFF];
                uint16_t ies_len = (flen > PROBE_REQ_IE_OFF) ? flen - PROBE_REQ_IE_OFF : 0;
                uint8_t sl = 0;
                const uint8_t *ss = find_ie(ies, ies_len, 0, &sl);
                if (sl > 32) sl = 32;
                entry.data[6] = sl;
                if (ss && sl) memcpy(&entry.data[7], ss, sl);
                entry.data_len = 7 + sl;
                enqueue = true;
            }

        } else if (fsub == SUB_DEAUTH || fsub == SUB_DISASSOC) {
            if (sniff_type == SNIFF_ALL || sniff_type == SNIFF_DEAUTH) {
                entry.type = SNIFF_DEAUTH;
                /* src(6) + dst(6) + reason(2) */
                memcpy(&entry.data[0], &f[HDR_ADDR2], 6);
                memcpy(&entry.data[6], &f[HDR_ADDR1], 6);
                if (flen >= 26) {
                    entry.data[12] = f[24];
                    entry.data[13] = f[25];
                }
                entry.data_len = 14;
                enqueue = true;
            }

        } else if (fsub == SUB_AUTH) {
            if (sniff_type == SNIFF_SAE || sniff_type == SNIFF_ALL) {
                if (flen >= 28) {
                    uint16_t auth_alg = f[24] | (f[25] << 8);
                    if (sniff_type == SNIFF_ALL || auth_alg == 3) {
                        entry.type = SNIFF_SAE;
                        /* src(6) + dst(6) + BSSID(6) + auth_alg(2) + seq(2) */
                        memcpy(&entry.data[0], &f[HDR_ADDR2], 6);
                        memcpy(&entry.data[6], &f[HDR_ADDR1], 6);
                        memcpy(&entry.data[12], &f[HDR_ADDR3], 6);
                        entry.data[18] = f[24];
                        entry.data[19] = f[25];
                        entry.data[20] = f[26];
                        entry.data[21] = f[27];
                        entry.data_len = 22;
                        enqueue = true;
                    }
                }
            }
        }

    } else if (ftype == TYPE_DATA) {
        if (sniff_type == SNIFF_ALL || sniff_type == SNIFF_EAPOL) {
            uint16_t hdr_len = 24;
            if (fc0 & 0x80) hdr_len = 26; /* QoS data: +2 bytes */

            if (flen >= hdr_len + 8) {
                const uint8_t *llc = &f[hdr_len];
                /* LLC/SNAP: AA AA 03 00 00 00 + EtherType 88 8E = EAPOL */
                if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
                    llc[6] == 0x88 && llc[7] == 0x8E) {
                    entry.type = SNIFF_EAPOL;
                    /* src(6) + dst(6) + BSSID(6) + key_info(2) + has_pmkid(1) + pmkid(16) */
                    memcpy(&entry.data[0], &f[HDR_ADDR2], 6);
                    memcpy(&entry.data[6], &f[HDR_ADDR1], 6);
                    memcpy(&entry.data[12], &f[HDR_ADDR3], 6);

                    /* EAPOL-Key body starts after LLC/SNAP(8) + EAPOL header(4) */
                    uint16_t ek = hdr_len + 8 + 4;
                    if (flen >= ek + 3) {
                        entry.data[18] = f[ek + 1]; /* key info lo */
                        entry.data[19] = f[ek + 2]; /* key info hi */
                    }

                    /* PMKID in Message 1: Key Data at EAPOL-Key + 95 */
                    entry.data[20] = 0;
                    uint16_t kd = ek + 95;
                    if (flen >= kd + 22 &&
                        f[kd] == 0xDD && f[kd+1] == 0x14 &&
                        f[kd+2] == 0x00 && f[kd+3] == 0x0F &&
                        f[kd+4] == 0xAC && f[kd+5] == 0x04) {
                        entry.data[20] = 1;
                        memcpy(&entry.data[21], &f[kd + 6], 16);
                    }
                    entry.data_len = entry.data[20] ? 37 : 21;
                    enqueue = true;
                }
            }
        }
    }

    /* SNIFF_ALL fallback: capture unmatched frames as raw summary */
    if (!enqueue && sniff_type == SNIFF_ALL) {
        entry.type = SNIFF_ALL;
        /* fc(1) + src(6) + dst(6) + orig_len(2) */
        entry.data[0] = fc0;
        memcpy(&entry.data[1], &f[HDR_ADDR2], 6);
        memcpy(&entry.data[7], &f[HDR_ADDR1], 6);
        entry.data[13] = flen & 0xFF;
        entry.data[14] = (flen >> 8) & 0xFF;
        entry.data_len = 15;
        enqueue = true;
    }

    if (enqueue && pkt_queue) {
        xQueueSend(pkt_queue, &entry, 0);
    }
}

/* ---- Public API ---- */

void pktmon_init(void)
{
    if (!pkt_queue) {
        pkt_queue = xQueueCreate(PKT_QUEUE_SIZE, sizeof(pkt_entry_t));
    }
}

/*
 * START payload: [0] sniff type, [1] channel (0=hop), [2] hop interval (x100ms, 0=default)
 */
void pktmon_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (pktmon_active) {
        resp->status = RESP_BUSY;
        return;
    }

    sniff_type = SNIFF_ALL;
    uint8_t channel = 0;
    uint16_t hop_ms = DEFAULT_HOP_MS;

    if (cmd->payload_len >= 1) sniff_type = cmd->payload[0];
    if (cmd->payload_len >= 2) channel   = cmd->payload[1];
    if (cmd->payload_len >= 3 && cmd->payload[2] > 0)
        hop_ms = (uint16_t)cmd->payload[2] * 100;

    if (!pkt_queue) pkt_queue = xQueueCreate(PKT_QUEUE_SIZE, sizeof(pkt_entry_t));
    xQueueReset(pkt_queue);

    if (sniff_type == SNIFF_SIGNAL)
        memset(chan_stats, 0, sizeof(chan_stats));

    enable_promiscuous();

    if (channel > 0 && channel <= 14) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    } else {
        start_hop(hop_ms);
    }

    pktmon_active = true;

    ESP_LOGI(TAG, "Started: type=%d ch=%d hop=%dms", sniff_type, channel,
             channel ? 0 : hop_ms);
    resp->status = RESP_OK;
    resp->payload[0] = sniff_type;
    resp->payload_len = 1;
}

/*
 * NEXT response for signal mode: ch_count(1) + [ch(1) + count_lo(1) + count_hi(1) + avg_rssi(1)] * N
 * NEXT response for other modes: type(1) + rssi(1) + channel(1) + data_len(1) + data(N)
 * Empty (no packet available): payload_len = 0
 */
void pktmon_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (pktmon_active && sniff_type == SNIFF_SIGNAL) {
        resp->payload[0] = NUM_CHANNELS;
        uint8_t pos = 1;
        for (int i = 1; i <= NUM_CHANNELS && pos + 4 <= M1_MAX_PAYLOAD; i++) {
            resp->payload[pos++] = i;
            resp->payload[pos++] = chan_stats[i].pkt_count & 0xFF;
            resp->payload[pos++] = (chan_stats[i].pkt_count >> 8) & 0xFF;
            int8_t avg = chan_stats[i].pkt_count ?
                (int8_t)(chan_stats[i].rssi_sum / (int32_t)chan_stats[i].pkt_count) : 0;
            resp->payload[pos++] = (uint8_t)avg;
        }
        memset(chan_stats, 0, sizeof(chan_stats));
        resp->payload_len = pos;
        resp->status = RESP_OK;
        return;
    }

    if (!pkt_queue) {
        resp->status = RESP_ERR;
        return;
    }

    pkt_entry_t entry;
    if (xQueueReceive(pkt_queue, &entry, 0) != pdTRUE) {
        resp->status = RESP_OK;
        resp->payload_len = 0;
        return;
    }

    resp->payload[0] = entry.type;
    resp->payload[1] = (uint8_t)entry.rssi;
    resp->payload[2] = entry.channel;
    uint8_t copy = entry.data_len;
    if (copy > M1_MAX_PAYLOAD - 4) copy = M1_MAX_PAYLOAD - 4;
    resp->payload[3] = copy;
    memcpy(&resp->payload[4], entry.data, copy);

    resp->payload_len = 4 + copy;
    resp->status = RESP_OK;
}

void pktmon_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    pktmon_active = false;
    stop_hop();
    disable_promiscuous_if_idle();

    ESP_LOGI(TAG, "Stopped");
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void pktmon_set_channel(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (cmd->payload_len < 1 || cmd->payload[0] < 1 || cmd->payload[0] > 14) {
        resp->status = RESP_ERR;
        return;
    }

    uint8_t ch = cmd->payload[0];

    /* Stop hopping and lock to this channel */
    if (hop_users > 0 && pktmon_active) stop_hop();
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Channel locked to %d", ch);
    resp->status = RESP_OK;
    resp->payload[0] = ch;
    resp->payload_len = 1;
}

/* ---- Station scan ---- */

void sta_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (sta_scan_active) {
        resp->status = RESP_BUSY;
        return;
    }

    sta_count = 0;
    sta_index = 0;
    memset(sta_table, 0, sizeof(sta_table));

    enable_promiscuous();

    uint8_t ch = 0;
    if (cmd->payload_len >= 1) ch = cmd->payload[0];
    if (ch > 0 && ch <= 14) {
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    } else if (!hop_timer) {
        start_hop(DEFAULT_HOP_MS);
    }

    sta_scan_active = true;

    ESP_LOGI(TAG, "Station scan started");
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/*
 * Returns one station per call:
 *   mac(6) + rssi(1) + channel(1) + bssid(6) + ssid_len(1) + ssid(N) + remaining(2)
 * When no more stations: payload[0..1] = total, payload[2] = 0
 */
void sta_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (sta_index >= sta_count) {
        resp->status = RESP_OK;
        resp->payload[0] = sta_count & 0xFF;
        resp->payload[1] = (sta_count >> 8) & 0xFF;
        resp->payload[2] = 0;
        resp->payload_len = 3;
        return;
    }

    sta_entry_t *s = &sta_table[sta_index++];

    memcpy(&resp->payload[0], s->mac, 6);
    resp->payload[6] = (uint8_t)s->rssi;
    resp->payload[7] = s->channel;
    memcpy(&resp->payload[8], s->bssid, 6);
    uint8_t sl = (uint8_t)strnlen(s->ssid, 32);
    resp->payload[14] = sl;
    if (sl) memcpy(&resp->payload[15], s->ssid, sl);
    uint8_t pos = 15 + sl;
    uint16_t remaining = sta_count - sta_index;
    resp->payload[pos++] = remaining & 0xFF;
    resp->payload[pos++] = (remaining >> 8) & 0xFF;

    resp->payload_len = pos;
    resp->status = RESP_OK;
}

void sta_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;
    sta_scan_active = false;
    sta_index = 0;
    stop_hop();
    disable_promiscuous_if_idle();

    resp->payload[0] = sta_count & 0xFF;
    resp->payload[1] = (sta_count >> 8) & 0xFF;
    resp->payload_len = 2;
    resp->status = RESP_OK;

    ESP_LOGI(TAG, "Station scan stopped: %d stations", sta_count);
}
