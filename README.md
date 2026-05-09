> **WARNING:** This is custom third-party firmware. Use at your own risk. The developer assumes no responsibility for bricked devices, hardware damage, fires, data loss, or any other issues that may result from flashing this firmware. By flashing this firmware, you accept full responsibility for any outcome.

---

# M1 SiN360 ESP32-C6 Firmware

ESP32-C6 wireless coprocessor firmware for the M1 SiN360 STM32 firmware.

This firmware runs on the M1's ESP32-C6 and provides the WiFi/BLE backend used by SiN360. The STM32 handles the UI, SD card, and user interaction; the ESP32 handles wireless operations over the device's SPI link.

## Compatibility

This release pairs with **M1 SiN360 STM32 firmware v0.9.1.0** and later STM32 releases that do not change the WiFi/BLE SPI command protocol.

STM32 releases:

<https://github.com/sincere360/M1_SiN360/releases>

## Features

- Binary SPI slave command protocol
- WiFi AP scan and station scan support
- Packet monitor/sniffer support for beacon, probe, deauth, EAPOL, SAE, Pwnagotchi, and raw packet counts
- Deauth, multi-target deauth, beacon spam, AP clone, Rickroll beacon, and probe request flood
- ESP32-C6 deauth support with patched WiFi library helper
- Karma and Karma Portal support
- Evil Portal captive DNS/HTTP service with credential capture
- Custom Evil Portal HTML upload from STM32/SD card with a 32KB limit
- Custom Evil Portal form/JSON capture helper for JavaScript-driven pages
- WiFi station join, MAC setting, channel setting, and radio shutdown commands
- TCP network scanners for SSH, Telnet, and common ports on the joined network
- Ping Scan and ARP Scan support on the joined network
- Wardrive and Station Wardrive support for STM32 SD-card CSV exports
- MAC Track support for selected devices
- BLE scan and raw advertisement scan support
- Named BLE advertising
- Raw BLE advertising payload command for BLE spam payloads
- Extended raw BLE advertising controls for random address and spam speed
- BLE GATT discovery, characteristic write, notification, and indication support
- BLE HID keyboard backend for BadBLE scripts
- BLE HID advertising uses a generic `Keyboard` name and rotates the BLE address when started

## Build Requirements

- ESP-IDF v5.5
- ESP32-C6 target support
- Python and the standard ESP-IDF toolchain dependencies

## Build

Run this once after installing or updating ESP-IDF:

```bash
cd /path/to/m1_esp32
. /path/to/esp-idf/export.sh
tools/patch-libnet80211.sh
```

Release binaries are already built with this deauth support. This patch step is only needed when compiling the ESP32 firmware from source.

```bash
cd /path/to/m1_esp32
. /path/to/esp-idf/export.sh
idf.py set-target esp32c6
idf.py build
```

The app binary is produced at:

```text
build/m1_esp32.bin
```

## Flash Directly

Use this when the ESP32-C6 is connected through USB-UART:

```bash
idf.py -p /dev/ttyUSB0 flash
```

Adjust the serial port for your machine.

## Build SD-Update Artifacts

The STM32 ESP32 updater expects a merged binary and matching MD5 sidecar.

```bash
idf.py merge-bin -o m1_esp32_merged.bin
HASH=$(md5sum build/m1_esp32_merged.bin | awk '{print toupper($1)}')
printf '%s' "$HASH" > build/m1_esp32_merged.md5
```

Copy both files to the M1 SD card:

```text
build/m1_esp32_merged.bin
build/m1_esp32_merged.md5
```

The `.md5` file must match the format expected by the STM32 updater.

## Notes

Deauth patch credit: neddy299

WiFi promiscuous mode and BLE advertising share the ESP32-C6 radio. The firmware stops conflicting modes before starting new WiFi/BLE operations, but user-facing flows should still avoid running WiFi sniffers and BLE advertising at the same time.

User workflows are documented in the main STM32 firmware repo.
