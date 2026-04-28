#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "ble_ops.h"

static const char *TAG = "ble_ops";

/* ---- BLE Scan ---- */
#define MAX_BLE_RESULTS 32

typedef struct {
    uint8_t  addr[6];
    uint8_t  addr_type;
    int8_t   rssi;
    uint8_t  adv_len;
    uint8_t  adv_data[31];
    uint8_t  name_len;
    char     name[29]; /* BLE short name max ~29 bytes to fit payload */
} ble_scan_entry_t;

static ble_scan_entry_t ble_results[MAX_BLE_RESULTS];
static uint16_t ble_result_count = 0;
static uint16_t ble_result_index = 0;
static volatile bool ble_scanning = false;
static volatile bool ble_host_synced = false;
static SemaphoreHandle_t ble_scan_done_sem = NULL;

static int ble_scan_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC: {
        if (ble_result_count >= MAX_BLE_RESULTS) break;

        struct ble_hs_adv_fields fields;
        ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);

        ble_scan_entry_t *e = &ble_results[ble_result_count];
        memcpy(e->addr, event->disc.addr.val, 6);
        e->addr_type = event->disc.addr.type;
        e->rssi = event->disc.rssi;
        e->adv_len = event->disc.length_data > sizeof(e->adv_data) ?
            sizeof(e->adv_data) : event->disc.length_data;
        if (e->adv_len > 0) {
            memcpy(e->adv_data, event->disc.data, e->adv_len);
        }

        if (fields.name != NULL && fields.name_len > 0) {
            e->name_len = (fields.name_len > sizeof(e->name) - 1) ? sizeof(e->name) - 1 : fields.name_len;
            memcpy(e->name, fields.name, e->name_len);
            e->name[e->name_len] = '\0';
        } else {
            e->name_len = 0;
            e->name[0] = '\0';
        }

        ble_result_count++;
        break;
    }
    case BLE_GAP_EVENT_DISC_COMPLETE:
        if (ble_scan_done_sem) {
            xSemaphoreGive(ble_scan_done_sem);
        }
        ble_scanning = false;
        break;
    default:
        break;
    }
    return 0;
}

void ble_scan_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (!ble_host_synced) {
        ESP_LOGE(TAG, "BLE host not synced yet");
        resp->status = RESP_ERR;
        return;
    }

    if (ble_scanning) {
        resp->status = RESP_BUSY;
        return;
    }

    ble_result_count = 0;
    ble_result_index = 0;

    if (!ble_scan_done_sem) {
        ble_scan_done_sem = xSemaphoreCreateBinary();
    }

    struct ble_gap_disc_params disc_params = {
        .filter_duplicates = 1,
        .passive = 0,
        .itvl = 0,    /* use defaults */
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, 5000 /* 5s */, &disc_params,
                          ble_scan_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE scan start failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    ble_scanning = true;

    /* Block until scan completes */
    xSemaphoreTake(ble_scan_done_sem, pdMS_TO_TICKS(6000));

    ESP_LOGI(TAG, "BLE scan complete: %u devices", ble_result_count);
    resp->status = RESP_OK;
    resp->payload[0] = ble_result_count & 0xFF;
    resp->payload[1] = (ble_result_count >> 8) & 0xFF;
    resp->payload_len = 2;
}

void ble_scan_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (ble_result_index >= ble_result_count) {
        resp->status = RESP_OK;
        resp->payload[0] = 0;
        resp->payload_len = 1;
        return;
    }

    ble_scan_entry_t *e = &ble_results[ble_result_index++];

    /* Pack: [0] rssi, [1] addr_type, [2..7] addr, [8] name_len, [9..] name */
    resp->payload[0] = (uint8_t)e->rssi;
    resp->payload[1] = e->addr_type;
    memcpy(&resp->payload[2], e->addr, 6);
    resp->payload[8] = e->name_len;
    if (e->name_len > 0) {
        memcpy(&resp->payload[9], e->name, e->name_len);
    }

    resp->payload_len = 9 + e->name_len;
    resp->status = RESP_OK;
}

void ble_scan_next_raw(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (ble_result_index >= ble_result_count) {
        resp->status = RESP_OK;
        resp->payload[0] = 0;
        resp->payload_len = 1;
        return;
    }

    ble_scan_entry_t *e = &ble_results[ble_result_index++];

    /* Pack: [0] rssi, [1] addr_type, [2..7] addr, [8] adv_len, [9..] adv data */
    resp->payload[0] = (uint8_t)e->rssi;
    resp->payload[1] = e->addr_type;
    memcpy(&resp->payload[2], e->addr, 6);
    resp->payload[8] = e->adv_len;
    if (e->adv_len > 0) {
        memcpy(&resp->payload[9], e->adv_data, e->adv_len);
    }

    resp->payload_len = 9 + e->adv_len;
    resp->status = RESP_OK;
}

void ble_scan_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    ble_gap_disc_cancel();
    ble_scanning = false;

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- BLE Advertise ---- */

static volatile bool ble_advertising = false;

void ble_adv_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced) {
        ESP_LOGE(TAG, "BLE host not synced yet");
        resp->status = RESP_ERR;
        return;
    }

    if (ble_advertising) {
        resp->status = RESP_BUSY;
        return;
    }

    /* Optional name in payload, default "M1" */
    const char *name = "M1";
    uint8_t name_len = 2;
    if (cmd->payload_len > 0 && cmd->payload_len <= 29) {
        name = (const char *)cmd->payload;
        name_len = cmd->payload_len;
    }

    /* Set device name */
    ble_svc_gap_device_name_set(name);

    struct ble_hs_adv_fields adv_fields = {0};
    adv_fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    adv_fields.name = (uint8_t *)name;
    adv_fields.name_len = name_len;
    adv_fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&adv_fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE adv set fields failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
    };

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE adv start failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    ble_advertising = true;
    ESP_LOGI(TAG, "BLE advertising started: '%s'", name);
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void ble_adv_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    ble_gap_adv_stop();
    ble_advertising = false;

    ESP_LOGI(TAG, "BLE advertising stopped");
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- Raw advertising (arbitrary adv data from STM32) ---- */

void ble_adv_raw(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced) {
        resp->status = RESP_ERR;
        return;
    }

    if (cmd->payload_len < 1 || cmd->payload_len > 31) {
        resp->status = RESP_ERR;
        return;
    }

    ble_gap_adv_stop();
    ble_advertising = false;

    int rc = ble_gap_adv_set_data(cmd->payload, cmd->payload_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE raw adv set data failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0x0020,
        .itvl_max = 0x0040,
    };

    rc = ble_gap_adv_start(BLE_OWN_ADDR_PUBLIC, NULL, BLE_HS_FOREVER,
                           &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE raw adv start failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    ble_advertising = true;
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- Init ---- */

static void ble_host_task(void *arg)
{
    (void)arg;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

static void ble_on_sync(void)
{
    ble_hs_util_ensure_addr(0);
    ble_host_synced = true;
    ESP_LOGI(TAG, "BLE host synced");
}

void ble_ops_init(void)
{
    int rc = nimble_port_init();
    if (rc != 0) {
        ESP_LOGE(TAG, "NimBLE init failed: %d", rc);
        return;
    }

    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);

    ESP_LOGI(TAG, "BLE initialized (NimBLE)");
}
