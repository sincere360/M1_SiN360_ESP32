# M1 SiN360 ESP32-C6 Firmware

ESP32-C6 wireless coprocessor firmware for the M1 SiN360 STM32 firmware.

This firmware runs on the M1's ESP32-C6 and provides the WiFi/BLE backend used by SiN360. The STM32 handles the UI, SD card, and user interaction; the ESP32 handles wireless operations over the device's SPI link.

## Compatibility

This release is intended to pair with **M1 SiN360 STM32 firmware v0.9.0.6**.

STM32 release page:

<https://github.com/sincere360/M1_SiN360/releases/tag/v0.9.0.6>

## Features

- Binary SPI slave command protocol
- WiFi AP scan and station scan support
- Packet monitor/sniffer support for beacon, probe, deauth, EAPOL, SAE, Pwnagotchi, and raw packet counts
- Deauth, multi-target deauth, beacon spam, AP clone, Rickroll beacon, and probe request flood
- Karma and Karma Portal support
- Evil Portal captive DNS/HTTP service with credential capture
- Custom Evil Portal HTML upload from STM32/SD card
- WiFi station join, MAC setting, channel setting, and radio shutdown commands
- TCP network scanners for SSH, Telnet, and common ports on the joined network
- BLE scan and raw advertisement scan support
- Named BLE advertising
- Raw BLE advertising payload command for BLE spam payloads

## Build Requirements

- ESP-IDF v5.5
- ESP32-C6 target support
- Python and the standard ESP-IDF toolchain dependencies

## Build

```bash
cd ~/Documents/m1_esp32
. ~/Documents/esp-idf/export.sh
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

The STM32 ESP32 updater expects a merged binary and a strict uppercase MD5 sidecar.

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

The `.md5` file must be exactly 32 uppercase hex characters with no newline.

## Notes

WiFi promiscuous mode and BLE advertising share the ESP32-C6 radio. The firmware stops conflicting modes before starting new WiFi/BLE operations, but user-facing flows should still avoid running WiFi sniffers and BLE advertising at the same time.

Detailed user how-tos are coming later.
