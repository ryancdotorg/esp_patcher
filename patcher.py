#!/usr/bin/env python3

from sys import argv, exit, stdin, stdout, stderr
from functools import partial
eprint = partial(print, file=stderr)

import re
import io
import sys
import struct

from pathlib import Path
from hashlib import sha256
from struct import unpack, unpack_from

SEEK_SET = 0
SEEK_CUR = 1
SEEK_END = 2

ESP_IMAGE_MAGIC = 0xE9
ESP_IMAGE_V2_MAGIC = 0xEA

PART_TYPE = {0x00: 'app', 0x01: 'data'}
PART_APP_SUBTYPE = {0x00: 'factory', 0x20: 'test'}
for i in range(0x10, 0x20): PART_APP_SUBTYPE[i] = f'ota_{i-16}'
PART_DATA_SUBTYPE = {
    0: 'ota', 1: 'phy', 2: 'nvs', 3: 'coredump', 4: 'nvs_keys', 5: 'efuse',
    6: 'undefined', 0x81: 'fat', 0x82: 'spiffs', 0x83: 'littlefs',
}

class ESPImage:
    def __init__(self, data):
        self._data = data
        self._checksum = 0xEF
        self._code_begin = None
        self._code_end = None
        self._parse_header()

    # wrappers
    def seek(self, *a, **kw): return self._data.seek(*a, **kw)
    def tell(self, *a, **kw): return self._data.tell(*a, **kw)
    def read(self, *a, **kw): return self._data.read(*a, **kw)

    def write(self, b, update_checksum=False, /):
        if update_checksum:
            n = len(b)
            a = self.read(n)
            self.seek(-n, SEEK_CUR)
            for x, y in zip(a, b):
                self._checksum ^= x ^ y

        return self._data.write(b)

    def unpack(self, fmt):
        n = struct.calcsize(fmt)
        return struct.unpack(fmt, self.read(n))

    # parsers
    def _parse_header(self):
        magic = self.read(1)[0]

        if magic in (ESP_IMAGE_MAGIC, ESP_IMAGE_V2_MAGIC):
            self.seek(-1, SEEK_CUR)
            return self._parse_ota()

        elif magic == 0xFF:
            return self._parse_factory()

        else:
            print(f'[!] Could not parse firmware image!')
            return None

    def _parse_factory(self):
        # look for a partition table
        self.seek(0x8000, SEEK_SET)
        ptable = self.read(0x0C00)
        for entry in map(lambda p: ptable[p:p+32], range(0, len(ptable), 32)):
            # parse entry
            pmagic, ptype, psubtype, poff, psz, pname = unpack('<HBBII16s4x', entry)
            if pmagic == 0x50AA:
                pname = pname.split(b'\0', 1)[0].decode()
                ptype = PART_TYPE.get(ptype, f'{ptype}')
                if ptype == 'app':
                    psubtype = PART_APP_SUBTYPE.get(psubtype, f'{psubtype}')
                elif ptype == 'data':
                    psubtype = PART_DATA_SUBTYPE.get(psubtype, f'{psubtype}')
                else:
                    psubtype = f'{psubtype}'

                if ptype == 'app' and psubtype == 'ota_0':
                    self.seek(poff)
                    return self._parse_ota()
            else:
                print(f'[!] Could not find application!')
                return None

    def _parse_ota(self):
        self._code_begin = self.tell()

        # magic, n_segments, spi_mode, flash_size, entry_point = unpack('<BBBBI', common_header)
        # https://docs.espressif.com/projects/esptool/en/latest/esp8266/advanced-topics/firmware-image-format.html
        common_header = self.read(8)
        magic, n_segments, spi_mode, flash_size, entry_point = unpack('<BBBBI', common_header)

        # ESP32 firmware images have a larger header, which we detect with heurstics
        # https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/firmware-image-format.html
        extended_header = self.read(16)
        if extended_header[0] == 0:
            self.seek(-16, SEEK_CUR)

        # walk through the segments
        for n in range(n_segments):
            self._parse_segment(n)

    def _parse_segment(self, n):
        segment_header = self.read(8)
        mem_offset, segment_size = unpack('<II', segment_header)
        print(f'[*] segment {n:2} 0x{segment_size:06X}:0x{self.tell():06X} @ 0x{mem_offset:08X}')
        self.seek(segment_size, SEEK_CUR)
        #segment = data.read(segment_size)
        #for x in segment: self._checksum ^= x

def _read_as_bytesio(path):
    if path.suffix == '.gz':
        import gzip
        with gzip.open(path, 'rb') as f:
            return io.BytesIO(f.read())
    else:
        with open(path, 'rb') as f:
            return io.BytesIO(f.read())

def patch_string(f, key, string, offset, size):
    b = string.encode()
    length = len(b)
    if length > size:
        raise ValueError(f'Cannot fit string with encoded size {length} in {size} bytes!')

    print(f'[*] Writing {length} bytes to {key}[{size}] @ {offset}...')
    b += b'\0' * (size - len(b) + 1)
    f.seek(offset)
    f.write(b)

def patch_binary(source, target, to_patch):
    if len(to_patch) == 0:
        return

    target_path = Path(target).absolute()
    source_path = Path(source).absolute()

    print(f'Patching `{source}` -> `{target}`...')
    with open(source_path, 'rb') as f:
        raw = f.read()
        if source_path.suffix == '.gz':
            data = io.BytesIO(gzip.decompress(raw))
        else:
            data = io.BytesIO(raw)

    data.seek(-33, SEEK_END)
    checksum = data.read(1)[0]
    print(f'[*] Initial checksum 0x{checksum:02X}')

    for m in re.finditer(rb'PLACEHOLDER_FOR_(\w+)\s+\0', data.getvalue()):
        key = m.group(1).decode()
        offset, end = m.span()
        size = (end - offset) - 1
        if (value := to_patch.get(key, None)) is not None:
            b = value.encode()
            length = len(b)
            if length > size:
                raise ValueError(f'Cannot fit string with encoded size {length} in {size} bytes!')

            print(f'[*] Writing to {key}[{size}] @ {offset}...')
            b += b'\0' * (size - len(b))
            data.seek(offset)
            replaced = data.read(size)
            data.seek(offset)
            for x, y in zip(b, replaced):
                checksum ^= x ^ y
            data.write(b)

    data.flush()
    if '.factory.' not in str(target_path):
        data.seek(0)

        chip_name = 'esp8266'
        common_header = data.getvalue()[0:8]
        magic = common_header[0]
        if magic in (ESPLoader.ESP_IMAGE_MAGIC, ESP8266V2FirmwareImage.IMAGE_V2_MAGIC):
            extended_header = data.getvalue()[8:24]
            #print(extended_header)
            chip_id = int.from_bytes(extended_header[4:5], "little")
            for rom in [n for n in ROM_LIST if n.CHIP_NAME != "ESP8266"]:
                if chip_id == rom.IMAGE_CHIP_ID:
                    chip_name = rom.CHIP_NAME
                    break

        print(f'[*] Adjusting checksum to 0x{checksum:02X}...')
        data.seek(-33, SEEK_END)
        data.write(bytes([checksum]))

        sha = sha256(data.getvalue()[:-32]).digest()
        # 32 bytes to the end
        data.seek(-32, SEEK_END)
        data.write(sha)
        data.flush()

    if target_path.suffix == '.gz':
        print('[*] Compressing...')
        uncompressed = data.getvalue()
        # "Depending on the file, either first or last gives the best compression."
        buf = compress(uncompressed, blocksplittinglast=False)
        if zopfli is not None:
            maybe = compress(uncompressed, blocksplittinglast=True)
            if len(maybe) < len(buf):
                print('[+] Block splitting last was better')
                buf = maybe
    else:
        buf = data.getbuffer()

    with open(target_path, 'wb') as f:
        f.write(buf)

if __name__ == '__main__':
    for source in argv[1:]:
        print(f'Source: {source}')
        source_path = Path(source).absolute()
        data = _read_as_bytesio(source_path)
        x = ESPImage(data)
'''
    if len(argv) > 2:
        source, target = argv[1], argv[2]
        to_patch = {}
        for patch in argv[3:]:
            key, _, value = patch.partition('=')
            to_patch[key] = value

        #print(source, target, to_patch)
        patch_binary(source, target, to_patch)
    elif len(argv) == 2:
        with open(argv[1]) as f:
            for base, module, template in map(lambda l: l.rstrip().split('\t'), f):
                for x in BUILD_OUTPUT.glob(f'{base}-*ryanc-custom*'):
                    source_name = x.name
                    target_name = source_name.replace('-ryanc-custom', f'-{module}')
                    source = Path(BUILD_OUTPUT, source_name)
                    target = Path(BUILD_OUTPUT, target_name)

                    if target.is_file() or not source.is_file():
                        continue

                    to_patch = {
                        'CODE_IMAGE_STR': module,
                        'USER_TEMPLATE': template,
                    }
                    #print(source, target, to_patch)
                    patch_binary(source, target, to_patch)
'''
