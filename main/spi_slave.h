#pragma once

#include "m1_protocol.h"

/* ESP32-C6-MINI-1 SPI slave pin assignments
 * Matches working AT firmware (bedge117/esp32-at-monstatek-m1) sdkconfig. */
#define SPI_SLAVE_SCLK_PIN   7
#define SPI_SLAVE_MOSI_PIN   12
#define SPI_SLAVE_MISO_PIN   13
#define SPI_SLAVE_CS_PIN     15

#define SPI_SLAVE_HANDSHAKE_PIN  14

/**
 * Initialize SPI slave peripheral and handshake GPIOs.
 * Must be called before any SPI transactions.
 */
void spi_slave_init(void);

/**
 * Block until a command is received from the STM32 master.
 * Returns 0 on success, -1 on error.
 */
int spi_slave_receive_cmd(m1_cmd_t *cmd);

/**
 * Send a response to the STM32 master.
 * Asserts handshake GPIO, waits for master to clock out the data.
 * Returns 0 on success, -1 on error.
 */
int spi_slave_send_resp(const m1_resp_t *resp);
