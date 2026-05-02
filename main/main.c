#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"
#include "m1_protocol.h"
#include "spi_slave.h"
#include "command_handler.h"
#include "wifi_scan.h"
#include "wifi_attack.h"
#include "pkt_monitor.h"
#include "evil_portal.h"
#include "ble_ops.h"

static const char *TAG = "m1_esp32";

static volatile bool s_wifi_started = false;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        s_wifi_started = true;
        ESP_LOGI(TAG, "WIFI_EVENT_STA_START — radio ready");
    }
}

bool m1_wifi_is_started(void)
{
    return s_wifi_started;
}

static void wifi_init(void)
{
    esp_err_t ret;

    ret = esp_netif_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "netif init failed: %s", esp_err_to_name(ret));
        return;
    }

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "event loop failed: %s", esp_err_to_name(ret));
        return;
    }

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "wifi init failed: %s", esp_err_to_name(ret));
        return;
    }

    esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                        &wifi_event_handler, NULL, NULL);

    esp_wifi_set_mode(WIFI_MODE_STA);
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "wifi start failed: %s", esp_err_to_name(ret));
        return;
    }

    /* Wait for STA_START event — WiFi radio not ready until this fires */
    for (int i = 0; i < 50 && !s_wifi_started; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (s_wifi_started) {
        ESP_LOGI(TAG, "WiFi initialized (STA mode, radio confirmed)");
    } else {
        ESP_LOGW(TAG, "WiFi started but STA_START not received after 5s");
    }
}

static void spi_command_loop(void *arg)
{
    (void)arg;
    m1_cmd_t cmd;
    m1_resp_t resp;

    ESP_LOGI(TAG, "SPI command loop started, waiting for master...");

    while (1) {
        int rc = spi_slave_receive_cmd(&cmd);
        if (rc == 0) {
            ESP_LOGI(TAG, "CMD: 0x%02X magic=0x%02X len=%d",
                     cmd.cmd_id, cmd.magic, cmd.payload_len);
            cmd_handle(&cmd, &resp);
            spi_slave_send_resp(&resp);
            ESP_LOGI(TAG, "RESP sent: status=%d", resp.status);
        } else {
            ESP_LOGW(TAG, "SPI RX error: %d", rc);
        }
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "M1 SiN360 ESP32-C6 FW v0.9.0.8");

    /* NVS init with erase fallback — required before WiFi */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase, erasing...");
        nvs_flash_erase();
        ret = nvs_flash_init();
    }
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NVS init failed: %s", esp_err_to_name(ret));
    }

    /* WiFi init before SPI so scan commands work immediately */
    wifi_init();

    /* BLE init — NimBLE host syncs asynchronously after this returns */
    ble_ops_init();

    spi_slave_init();
    xTaskCreate(spi_command_loop, "spi_cmd", 8192, NULL, 5, NULL);

    ESP_LOGI(TAG, "M1 ESP32 ready");
}
