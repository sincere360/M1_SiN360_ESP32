#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/spi_slave.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "spi_slave.h"

static const char *TAG = "spi_slave";

/* DMA-capable buffers must be word-aligned.
 * Separate buffers for cmd receive vs resp send to allow pre-queuing. */
WORD_ALIGNED_ATTR static uint8_t rx_buf[64];
WORD_ALIGNED_ATTR static uint8_t tx_buf[64];
WORD_ALIGNED_ATTR static uint8_t rx_buf2[64];
WORD_ALIGNED_ATTR static uint8_t tx_dummy2[64];

static bool s_rx_prequeued = false;

static void IRAM_ATTR spi_post_trans_cb(spi_slave_transaction_t *trans)
{
    (void)trans;
}

void spi_slave_init(void)
{
    /* Configure handshake GPIO as output (ESP32 -> STM32) */
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << SPI_SLAVE_HANDSHAKE_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);
    gpio_set_level(SPI_SLAVE_HANDSHAKE_PIN, 0);

    /* SPI slave bus config */
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SPI_SLAVE_MOSI_PIN,
        .miso_io_num = SPI_SLAVE_MISO_PIN,
        .sclk_io_num = SPI_SLAVE_SCLK_PIN,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };

    /* SPI mode 1 matches STM32 SPI master (CPOL=0, CPHA=2EDGE).
     * Confirmed by working AT firmware: CONFIG_SPI_MODE=1 on same hardware. */
    spi_slave_interface_config_t slave_cfg = {
        .spics_io_num = SPI_SLAVE_CS_PIN,
        .flags = 0,
        .queue_size = 3,
        .mode = 1,
        .post_trans_cb = spi_post_trans_cb,
    };

    esp_err_t ret = spi_slave_initialize(SPI2_HOST, &bus_cfg, &slave_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPI slave init failed: %s", esp_err_to_name(ret));
        return;
    }

    ESP_LOGI(TAG, "SPI slave initialized (mode 1, DMA)");
}

int spi_slave_receive_cmd(m1_cmd_t *cmd)
{
    if (s_rx_prequeued) {
        /* A receive transaction was already queued by send_resp — just wait */
        spi_slave_transaction_t *rtrans;
        esp_err_t ret = spi_slave_get_trans_result(SPI2_HOST, &rtrans, portMAX_DELAY);
        s_rx_prequeued = false;
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SPI prequeued rx failed: %s", esp_err_to_name(ret));
            return -1;
        }
        memcpy(cmd, rx_buf2, sizeof(m1_cmd_t));
    } else {
        /* First call after boot — no pre-queued transaction */
        memset(rx_buf, 0, sizeof(rx_buf));
        memset(tx_buf, 0, sizeof(tx_buf));

        spi_slave_transaction_t trans = {
            .length = 64 * 8,
            .rx_buffer = rx_buf,
            .tx_buffer = tx_buf,
        };

        esp_err_t ret = spi_slave_transmit(SPI2_HOST, &trans, portMAX_DELAY);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "SPI rx failed: %s", esp_err_to_name(ret));
            return -1;
        }
        memcpy(cmd, rx_buf, sizeof(m1_cmd_t));
    }

    /* Validate magic byte */
    if (cmd->magic != M1_CMD_MAGIC) {
        ESP_LOGW(TAG, "Bad magic: 0x%02X (expected 0x%02X)", cmd->magic, M1_CMD_MAGIC);
        return -1;
    }

    return 0;
}

int spi_slave_send_resp(const m1_resp_t *resp)
{
    memcpy(tx_buf, resp, sizeof(m1_resp_t));
    memset(rx_buf, 0, sizeof(rx_buf));

    spi_slave_transaction_t trans = {
        .length = 64 * 8,
        .tx_buffer = tx_buf,
        .rx_buffer = rx_buf,
    };

    /* Queue transaction BEFORE asserting handshake to avoid race condition:
     * if handshake fires first, master may clock before slave is ready. */
    esp_err_t ret = spi_slave_queue_trans(SPI2_HOST, &trans, pdMS_TO_TICKS(5000));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPI queue failed: %s", esp_err_to_name(ret));
        return -1;
    }

    gpio_set_level(SPI_SLAVE_HANDSHAKE_PIN, 1);

    spi_slave_transaction_t *rtrans;
    ret = spi_slave_get_trans_result(SPI2_HOST, &rtrans, pdMS_TO_TICKS(5000));

    gpio_set_level(SPI_SLAVE_HANDSHAKE_PIN, 0);

    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPI tx failed: %s", esp_err_to_name(ret));
        return -1;
    }

    /* Pre-queue next receive so the slave is immediately ready for the
     * next command.  Eliminates the race where the master sends a
     * back-to-back command before we loop back to receive_cmd(). */
    memset(rx_buf2, 0, sizeof(rx_buf2));
    memset(tx_dummy2, 0, sizeof(tx_dummy2));
    spi_slave_transaction_t rx_next = {
        .length = 64 * 8,
        .rx_buffer = rx_buf2,
        .tx_buffer = tx_dummy2,
    };
    ret = spi_slave_queue_trans(SPI2_HOST, &rx_next, pdMS_TO_TICKS(100));
    if (ret == ESP_OK) {
        s_rx_prequeued = true;
    } else {
        ESP_LOGW(TAG, "Pre-queue rx failed: %s", esp_err_to_name(ret));
        s_rx_prequeued = false;
    }

    return 0;
}
