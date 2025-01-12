# esp_patcher
Tool for patching strings in ESP8266/ESP32 firmware.

This tool was written to patch [Tasmota](https://github.com/arendst/Tasmota)
firmware builds in order to change the default module template and other
assorted string settings.

It handles updating the firmware checksum byte and the sha256 hash (if present).
For ESP32 firmware, it will automatically handle both “OTA” and “factory”
images. Compression is dealt with transparently.

# Usage

(TODO: write this)

For now, read the source.

# Author
Ryan Castellucci @ryancdotorg
