#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "ble_ops.h"

static const char *TAG = "ble_ops";

/* ---- BLE Scan ---- */
#define MAX_BLE_RESULTS 32
#define MAX_GATT_ENTRIES 64
#define MAX_GATT_SERVICES 12
#define MAX_GATT_NOTIFS 8
#define MAX_GATT_NOTIFY_VALUE 48

#define BLE_ADV_EX_FLAG_RANDOM_ADDR 0x01
#define BLE_GATT_ENTRY_SVC 1
#define BLE_GATT_ENTRY_CHR 2
#define BLE_GATT_ENTRY_DSC 3
#define BLE_GATT_WRITE_FLAG_NO_RSP 0x01

typedef struct {
    uint8_t  addr[6];
    uint8_t  addr_type;
    int8_t   rssi;
    uint8_t  adv_len;
    uint8_t  adv_data[31];
    uint8_t  name_len;
    char     name[29]; /* BLE short name max ~29 bytes to fit payload */
} ble_scan_entry_t;

typedef struct {
    uint8_t  type;       /* 1=service, 2=characteristic */
    uint16_t handle1;    /* service start or characteristic def handle */
    uint16_t handle2;    /* service end or characteristic value handle */
    uint8_t  props;
    uint8_t  uuid_len;
    uint8_t  uuid[16];
    uint8_t  value_len;
    uint8_t  value[16];
} ble_gatt_entry_t;

typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
} ble_gatt_service_range_t;

typedef struct {
    uint16_t handle;
    uint8_t  indication;
    uint8_t  value_len;
    uint8_t  value[MAX_GATT_NOTIFY_VALUE];
} ble_gatt_notify_entry_t;

static ble_scan_entry_t ble_results[MAX_BLE_RESULTS];
static uint16_t ble_result_count = 0;
static uint16_t ble_result_index = 0;
static volatile bool ble_scanning = false;
static volatile bool ble_host_synced = false;
static SemaphoreHandle_t ble_scan_done_sem = NULL;
static SemaphoreHandle_t ble_gatt_sem = NULL;
static ble_gatt_entry_t ble_gatt_entries[MAX_GATT_ENTRIES];
static ble_gatt_service_range_t ble_gatt_services[MAX_GATT_SERVICES];
static uint16_t ble_gatt_entry_count = 0;
static uint16_t ble_gatt_entry_index = 0;
static uint8_t ble_gatt_service_count = 0;
static uint16_t ble_gatt_conn_handle = 0xFFFF;
static volatile int ble_gatt_status = 0;
static ble_gatt_entry_t *ble_gatt_read_target = NULL;
static ble_gatt_notify_entry_t ble_gatt_notifs[MAX_GATT_NOTIFS];
static uint8_t ble_gatt_notif_count = 0;
static uint8_t ble_gatt_notif_read = 0;

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

static int ble_set_random_static_addr(void)
{
    uint8_t addr[6];

    esp_fill_random(addr, sizeof(addr));

    /* BLE static random addresses require the two MSBs of the most significant
     * octet to be set. This gives spam payloads a fresh identity each cycle so
     * phones are less likely to cache/suppress repeated advertisements.
     */
    addr[5] = (addr[5] & 0x3F) | 0xC0;

    return ble_hs_id_set_rnd(addr);
}

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

    int rc = ble_set_random_static_addr();
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE random addr set failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    rc = ble_gap_adv_set_data(cmd->payload, cmd->payload_len);
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

    rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, BLE_HS_FOREVER,
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

void ble_adv_raw_ex(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced) {
        resp->status = RESP_ERR;
        return;
    }

    if (cmd->payload_len < 6) {
        resp->status = RESP_ERR;
        return;
    }

    uint8_t flags = cmd->payload[0];
    uint16_t itvl_min = cmd->payload[1] | ((uint16_t)cmd->payload[2] << 8);
    uint16_t itvl_max = cmd->payload[3] | ((uint16_t)cmd->payload[4] << 8);
    uint8_t adv_len = cmd->payload[5];
    const uint8_t *adv = &cmd->payload[6];

    if (adv_len < 1 || adv_len > 31 || cmd->payload_len < 6 + adv_len) {
        resp->status = RESP_ERR;
        return;
    }

    if (itvl_min < 0x0020) itvl_min = 0x0020;
    if (itvl_max < itvl_min) itvl_max = itvl_min;

    ble_gap_adv_stop();
    ble_advertising = false;

    int rc;
    uint8_t own_addr_type = BLE_OWN_ADDR_PUBLIC;
    if (flags & BLE_ADV_EX_FLAG_RANDOM_ADDR) {
        rc = ble_set_random_static_addr();
        if (rc != 0) {
            ESP_LOGE(TAG, "BLE random addr set failed: %d", rc);
            resp->status = RESP_ERR;
            return;
        }
        own_addr_type = BLE_OWN_ADDR_RANDOM;
    }

    rc = ble_gap_adv_set_data(adv, adv_len);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE raw ex adv set data failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_NON,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = itvl_min,
        .itvl_max = itvl_max,
    };

    rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER,
                           &adv_params, NULL, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE raw ex adv start failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    ble_advertising = true;
    resp->status = RESP_OK;
    resp->payload_len = 0;
}

/* ---- GATT discovery ---- */

static void ble_uuid_store(const ble_uuid_any_t *uuid, ble_gatt_entry_t *entry)
{
    memset(entry->uuid, 0, sizeof(entry->uuid));
    if (uuid->u.type == BLE_UUID_TYPE_16) {
        uint16_t v = BLE_UUID16(uuid)->value;
        entry->uuid_len = 2;
        entry->uuid[0] = v & 0xFF;
        entry->uuid[1] = (v >> 8) & 0xFF;
    } else if (uuid->u.type == BLE_UUID_TYPE_32) {
        uint32_t v = BLE_UUID32(uuid)->value;
        entry->uuid_len = 4;
        entry->uuid[0] = v & 0xFF;
        entry->uuid[1] = (v >> 8) & 0xFF;
        entry->uuid[2] = (v >> 16) & 0xFF;
        entry->uuid[3] = (v >> 24) & 0xFF;
    } else {
        entry->uuid_len = 16;
        memcpy(entry->uuid, BLE_UUID128(uuid)->value, 16);
    }
}

static void ble_gatt_notify_reset(void)
{
    ble_gatt_notif_count = 0;
    ble_gatt_notif_read = 0;
    memset(ble_gatt_notifs, 0, sizeof(ble_gatt_notifs));
}

static int ble_gatt_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
        ble_gatt_status = event->connect.status;
        if (event->connect.status == 0) {
            ble_gatt_conn_handle = event->connect.conn_handle;
        }
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        ble_gatt_conn_handle = 0xFFFF;
        break;
    case BLE_GAP_EVENT_NOTIFY_RX: {
        uint8_t slot;
        ble_gatt_notify_entry_t *n;

        if (ble_gatt_notif_count < MAX_GATT_NOTIFS) {
            slot = ble_gatt_notif_count++;
        } else {
            memmove(&ble_gatt_notifs[0], &ble_gatt_notifs[1],
                    sizeof(ble_gatt_notifs[0]) * (MAX_GATT_NOTIFS - 1));
            slot = MAX_GATT_NOTIFS - 1;
            if (ble_gatt_notif_read > 0) {
                ble_gatt_notif_read--;
            }
        }

        n = &ble_gatt_notifs[slot];
        memset(n, 0, sizeof(*n));
        n->handle = event->notify_rx.attr_handle;
        n->indication = event->notify_rx.indication ? 1 : 0;
        if (event->notify_rx.om) {
            uint16_t len = OS_MBUF_PKTLEN(event->notify_rx.om);
            if (len > sizeof(n->value)) {
                len = sizeof(n->value);
            }
            if (len > 0 &&
                os_mbuf_copydata(event->notify_rx.om, 0, len, n->value) == 0) {
                n->value_len = len;
            }
        }
        break;
    }
    default:
        break;
    }

    return 0;
}

static int ble_gatt_svc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
    const struct ble_gatt_svc *service, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == BLE_HS_EDONE) {
        ble_gatt_status = 0;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (error->status != 0) {
        ble_gatt_status = error->status;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (ble_gatt_entry_count < MAX_GATT_ENTRIES) {
        ble_gatt_entry_t *e = &ble_gatt_entries[ble_gatt_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = BLE_GATT_ENTRY_SVC;
        e->handle1 = service->start_handle;
        e->handle2 = service->end_handle;
        ble_uuid_store(&service->uuid, e);
    }

    if (ble_gatt_service_count < MAX_GATT_SERVICES) {
        ble_gatt_services[ble_gatt_service_count].start_handle = service->start_handle;
        ble_gatt_services[ble_gatt_service_count].end_handle = service->end_handle;
        ble_gatt_service_count++;
    }

    return 0;
}

static int ble_gatt_chr_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
    const struct ble_gatt_chr *chr, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == BLE_HS_EDONE) {
        ble_gatt_status = 0;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (error->status != 0) {
        ble_gatt_status = error->status;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (ble_gatt_entry_count < MAX_GATT_ENTRIES) {
        ble_gatt_entry_t *e = &ble_gatt_entries[ble_gatt_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = BLE_GATT_ENTRY_CHR;
        e->handle1 = chr->def_handle;
        e->handle2 = chr->val_handle;
        e->props = chr->properties;
        ble_uuid_store(&chr->uuid, e);
    }

    return 0;
}

static int ble_gatt_dsc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
    uint16_t chr_val_handle, const struct ble_gatt_dsc *dsc, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == BLE_HS_EDONE) {
        ble_gatt_status = 0;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (error->status != 0) {
        ble_gatt_status = error->status;
        if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
        return 0;
    }

    if (ble_gatt_entry_count < MAX_GATT_ENTRIES) {
        ble_gatt_entry_t *e = &ble_gatt_entries[ble_gatt_entry_count++];
        memset(e, 0, sizeof(*e));
        e->type = BLE_GATT_ENTRY_DSC;
        e->handle1 = dsc->handle;
        e->handle2 = chr_val_handle;
        ble_uuid_store(&dsc->uuid, e);
    }

    return 0;
}

static int ble_gatt_read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
    struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == 0 && attr && attr->om && ble_gatt_read_target) {
        uint16_t len = OS_MBUF_PKTLEN(attr->om);
        if (len > sizeof(ble_gatt_read_target->value)) {
            len = sizeof(ble_gatt_read_target->value);
        }
        if (len > 0 &&
            os_mbuf_copydata(attr->om, 0, len, ble_gatt_read_target->value) == 0) {
            ble_gatt_read_target->value_len = len;
        }
    }

    ble_gatt_status = error->status;
    if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
    return 0;
}

static int ble_gatt_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
    struct ble_gatt_attr *attr, void *arg)
{
    (void)conn_handle;
    (void)attr;
    (void)arg;

    ble_gatt_status = error->status;
    if (ble_gatt_sem) xSemaphoreGive(ble_gatt_sem);
    return 0;
}

void ble_gatt_start(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced || cmd->payload_len < 7) {
        resp->status = RESP_ERR;
        return;
    }

    if (!ble_gatt_sem) {
        ble_gatt_sem = xSemaphoreCreateBinary();
    }
    if (!ble_gatt_sem) {
        resp->status = RESP_ERR;
        return;
    }

    ble_gap_disc_cancel();
    ble_gap_adv_stop();
    ble_advertising = false;
    if (ble_gatt_conn_handle != 0xFFFF) {
        ble_gap_terminate(ble_gatt_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        ble_gatt_conn_handle = 0xFFFF;
    }

    memset(ble_gatt_entries, 0, sizeof(ble_gatt_entries));
    memset(ble_gatt_services, 0, sizeof(ble_gatt_services));
    ble_gatt_notify_reset();
    ble_gatt_entry_count = 0;
    ble_gatt_entry_index = 0;
    ble_gatt_service_count = 0;
    ble_gatt_conn_handle = 0xFFFF;
    ble_gatt_status = 0;

    ble_addr_t peer = {0};
    peer.type = cmd->payload[0];
    memcpy(peer.val, &cmd->payload[1], 6);

    int rc = ble_gap_connect(BLE_OWN_ADDR_PUBLIC, &peer, 7000, NULL,
                             ble_gatt_gap_event, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "BLE GATT connect failed: %d", rc);
        resp->status = RESP_ERR;
        return;
    }

    if (xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(8000)) != pdTRUE ||
        ble_gatt_status != 0 || ble_gatt_conn_handle == 0xFFFF) {
        ESP_LOGE(TAG, "BLE GATT connect timeout/status=%d", ble_gatt_status);
        ble_gap_conn_cancel();
        resp->status = RESP_ERR;
        return;
    }

    ble_gatt_status = 0;
    rc = ble_gattc_disc_all_svcs(ble_gatt_conn_handle, ble_gatt_svc_cb, NULL);
    if (rc != 0 ||
        xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(7000)) != pdTRUE ||
        ble_gatt_status != 0) {
        ESP_LOGE(TAG, "BLE GATT service discovery failed: rc=%d status=%d", rc, ble_gatt_status);
        ble_gap_terminate(ble_gatt_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        resp->status = RESP_ERR;
        return;
    }

    for (uint8_t i = 0; i < ble_gatt_service_count; i++) {
        uint16_t chr_first_idx = ble_gatt_entry_count;
        ble_gatt_status = 0;
        rc = ble_gattc_disc_all_chrs(ble_gatt_conn_handle,
                                     ble_gatt_services[i].start_handle,
                                     ble_gatt_services[i].end_handle,
                                     ble_gatt_chr_cb, NULL);
        if (rc == 0) {
            xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(5000));
        }

        uint16_t chr_last_idx = ble_gatt_entry_count;
        for (uint16_t j = chr_first_idx; j < chr_last_idx; j++) {
            ble_gatt_entry_t *chr = &ble_gatt_entries[j];
            if (chr->type != BLE_GATT_ENTRY_CHR) continue;

            if (chr->props & BLE_GATT_CHR_F_READ) {
                ble_gatt_read_target = chr;
                ble_gatt_status = 0;
                rc = ble_gattc_read(ble_gatt_conn_handle, chr->handle2,
                                    ble_gatt_read_cb, NULL);
                if (rc == 0) {
                    xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(2500));
                }
                ble_gatt_read_target = NULL;
            }

            uint16_t desc_start = chr->handle2 + 1;
            uint16_t desc_end = ble_gatt_services[i].end_handle;
            for (uint16_t k = j + 1; k < chr_last_idx; k++) {
                if (ble_gatt_entries[k].type == BLE_GATT_ENTRY_CHR) {
                    desc_end = ble_gatt_entries[k].handle1 - 1;
                    break;
                }
            }

            if (desc_start <= desc_end && ble_gatt_entry_count < MAX_GATT_ENTRIES) {
                ble_gatt_status = 0;
                rc = ble_gattc_disc_all_dscs(ble_gatt_conn_handle, desc_start,
                                             desc_end, ble_gatt_dsc_cb, NULL);
                if (rc == 0) {
                    xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(3000));
                }
            }
        }
    }

    resp->status = RESP_OK;
    resp->payload[0] = ble_gatt_entry_count & 0xFF;
    resp->payload[1] = (ble_gatt_entry_count >> 8) & 0xFF;
    resp->payload[2] = ble_gatt_service_count;
    resp->payload_len = 3;
}

void ble_gatt_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (ble_gatt_entry_index >= ble_gatt_entry_count) {
        resp->status = RESP_OK;
        resp->payload[0] = 0;
        resp->payload_len = 1;
        return;
    }

    ble_gatt_entry_t *e = &ble_gatt_entries[ble_gatt_entry_index++];
    resp->payload[0] = e->type;
    resp->payload[1] = e->handle1 & 0xFF;
    resp->payload[2] = (e->handle1 >> 8) & 0xFF;
    resp->payload[3] = e->handle2 & 0xFF;
    resp->payload[4] = (e->handle2 >> 8) & 0xFF;
    resp->payload[5] = e->props;
    resp->payload[6] = e->uuid_len;
    memcpy(&resp->payload[7], e->uuid, e->uuid_len);
    uint8_t pos = 7 + e->uuid_len;
    resp->payload[pos++] = e->value_len;
    if (e->value_len > 0) {
        memcpy(&resp->payload[pos], e->value, e->value_len);
        pos += e->value_len;
    }
    resp->payload_len = pos;
    resp->status = RESP_OK;
}

void ble_gatt_write(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced || ble_gatt_conn_handle == 0xFFFF ||
        cmd->payload_len < 4 || !ble_gatt_sem) {
        resp->status = RESP_ERR;
        return;
    }

    uint16_t handle = cmd->payload[0] | ((uint16_t)cmd->payload[1] << 8);
    uint8_t flags = cmd->payload[2];
    uint8_t value_len = cmd->payload[3];
    const uint8_t *value = &cmd->payload[4];

    if (handle == 0 || value_len == 0 || cmd->payload_len < 4 + value_len) {
        resp->status = RESP_ERR;
        return;
    }

    int rc;
    if (flags & BLE_GATT_WRITE_FLAG_NO_RSP) {
        rc = ble_gattc_write_no_rsp_flat(ble_gatt_conn_handle, handle,
                                         value, value_len);
        if (rc != 0) {
            ESP_LOGE(TAG, "GATT write no-rsp failed: %d", rc);
            resp->status = RESP_ERR;
            return;
        }
    } else {
        ble_gatt_status = 0;
        rc = ble_gattc_write_flat(ble_gatt_conn_handle, handle, value, value_len,
                                  ble_gatt_write_cb, NULL);
        if (rc != 0 ||
            xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(4000)) != pdTRUE ||
            ble_gatt_status != 0) {
            ESP_LOGE(TAG, "GATT write failed: rc=%d status=%d", rc, ble_gatt_status);
            resp->status = RESP_ERR;
            return;
        }
    }

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void ble_gatt_subscribe(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    if (!ble_host_synced || ble_gatt_conn_handle == 0xFFFF ||
        cmd->payload_len < 3) {
        resp->status = RESP_ERR;
        return;
    }

    uint16_t handle = cmd->payload[0] | ((uint16_t)cmd->payload[1] << 8);
    uint8_t enable = cmd->payload[2];
    uint8_t mode = (cmd->payload_len >= 4) ? cmd->payload[3] : 1;
    uint16_t cccd_handle = 0;
    uint8_t cccd_value[2] = {0, 0};
    int rc;

    if (handle == 0) {
        resp->status = RESP_ERR;
        return;
    }

    for (uint16_t i = 0; i < ble_gatt_entry_count; i++) {
        ble_gatt_entry_t *e = &ble_gatt_entries[i];
        if (e->type == BLE_GATT_ENTRY_DSC && e->handle2 == handle &&
            e->uuid_len == 2 && e->uuid[0] == 0x02 && e->uuid[1] == 0x29) {
            cccd_handle = e->handle1;
            break;
        }
    }

    if (cccd_handle == 0 && mode == 1) {
        rc = enable ? ble_gattc_register_for_notification(ble_gatt_conn_handle, handle) :
                      ble_gattc_unregister_for_notification(ble_gatt_conn_handle, handle);
        if (rc != 0) {
            ESP_LOGE(TAG, "GATT notify %s failed: %d", enable ? "enable" : "disable", rc);
            resp->status = RESP_ERR;
            return;
        }

        if (enable) {
            ble_gatt_notify_reset();
        }
        resp->status = RESP_OK;
        resp->payload_len = 0;
        return;
    }

    if (cccd_handle == 0 || !ble_gatt_sem) {
        resp->status = RESP_ERR;
        return;
    }

    if (enable) {
        cccd_value[0] = (mode == 2) ? 0x02 : 0x01;
    }

    ble_gatt_status = 0;
    rc = ble_gattc_write_flat(ble_gatt_conn_handle, cccd_handle,
                              cccd_value, sizeof(cccd_value),
                              ble_gatt_write_cb, NULL);
    if (rc != 0 ||
        xSemaphoreTake(ble_gatt_sem, pdMS_TO_TICKS(4000)) != pdTRUE ||
        ble_gatt_status != 0) {
        ESP_LOGE(TAG, "GATT CCCD write failed: rc=%d status=%d", rc, ble_gatt_status);
        resp->status = RESP_ERR;
        return;
    }

    if (enable) {
        ble_gatt_notify_reset();
    }

    resp->status = RESP_OK;
    resp->payload_len = 0;
}

void ble_gatt_notify_next(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (ble_gatt_notif_read >= ble_gatt_notif_count) {
        resp->status = RESP_OK;
        resp->payload[0] = 0;
        resp->payload_len = 1;
        return;
    }

    ble_gatt_notify_entry_t *n = &ble_gatt_notifs[ble_gatt_notif_read++];
    uint8_t value_len = n->value_len;
    if (value_len > M1_MAX_PAYLOAD - 5) {
        value_len = M1_MAX_PAYLOAD - 5;
    }

    resp->payload[0] = 1;
    resp->payload[1] = n->handle & 0xFF;
    resp->payload[2] = (n->handle >> 8) & 0xFF;
    resp->payload[3] = n->indication;
    resp->payload[4] = value_len;
    if (value_len > 0) {
        memcpy(&resp->payload[5], n->value, value_len);
    }
    resp->payload_len = 5 + value_len;
    resp->status = RESP_OK;
}

void ble_gatt_stop(const m1_cmd_t *cmd, m1_resp_t *resp)
{
    (void)cmd;

    if (ble_gatt_conn_handle != 0xFFFF) {
        ble_gap_terminate(ble_gatt_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        ble_gatt_conn_handle = 0xFFFF;
    } else {
        ble_gap_conn_cancel();
    }
    ble_gatt_notify_reset();

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
