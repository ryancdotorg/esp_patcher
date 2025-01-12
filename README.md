# esp_patcher
Tool for patching strings in ESP8266/ESP32 firmware.

This tool was written to patch [Tasmota](https://github.com/arendst/Tasmota)
firmware builds in order to change the default module template and other
assorted string settings.

Nothing should be specific to Tasmota, as far as I’m aware. It’s useful for
injecting your WiFi SSID and passphrase into firmware as a post-compile step.

It handles updating the firmware checksum byte and the sha256 hash (if present).
For ESP32 firmware, it will automatically handle both “OTA” and “factory”
images. Compression is dealt with transparently.

# Usage

`patcher.py SOURCE TARGET KEY1=VALUE1 KEY2=VALUE2`

This tool expects placeholder strings to have been used in the firmware in the
form of:

`PLACEHOLDER_FOR_[KEY][spaces for padding]`

# Author
Ryan Castellucci @ryancdotorg
