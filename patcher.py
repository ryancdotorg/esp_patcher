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
from binascii import hexlify

# local
from compress import compress

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

        self._checksum = None
        self._checksum_offset = None
        self._hash_offset = None

        self._code_begin = None
        self._code_end = None

        self._segments_begin = None

        self._dirty = False

        self._parse_header()

    # wrappers
    def seek(self, *a, **kw): return self._data.seek(*a, **kw)
    def tell(self, *a, **kw): return self._data.tell(*a, **kw)
    def read(self, *a, **kw): return self._data.read(*a, **kw)

    def getvalue(self): return self._data.getvalue()
    def getbuffer(self): return self._data.getbuffer()

    # write, but it updates the checksum
    def write(self, b, /):
        pos = self.tell()
        if self._checksum is not None and self._code_begin <= pos < self._checksum_offset:
            # we just compute the checksum difference
            n = len(b)
            a = self.read(n)
            self.seek(-n, SEEK_CUR)
            for x, y in zip(a, b):
                self._checksum ^= x ^ y

        self._dirty = True
        return self._data.write(b)

    def flush(self):
        pos = self.tell()
        self.seek(self._checksum_offset)
        self.write(bytes([self._checksum]))
        self.seek(pos)
        print(f'[+] Updated Checksum:  0x{self._checksum:02X}')

        self._update_hash()

        self._dirty = False
        return self._data.flush()

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

        # https://docs.espressif.com/projects/esptool/en/latest/esp8266/advanced-topics/firmware-image-format.html
        magic, n_segments, spi_mode, flash_size, entry_point = self.unpack('<BBBBI')

        # ESP32 firmware images have a larger header, which we detect with heurstics
        # https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/firmware-image-format.html
        extended_header = self.read(16)
        if extended_header[0] == 0:
            self.seek(-16, SEEK_CUR)

        # walk through the segments
        self._segments_begin = self.tell()
        for n in range(n_segments):
            self._parse_segment(n)

        self.seek(15 - (self.tell() % 16), SEEK_CUR)
        self._checksum_offset = self.tell()
        self._checksum = self.read(1)[0]
        print(f'[*] Original Checksum: 0x{self._checksum:02X}')
        self._code_end = self.tell()
        maybe_hash = self.read(32)
        if len(maybe_hash) == 32:
            self.seek(self._code_begin)
            check_hash = sha256(self.read(self._code_end - self._code_begin)).digest()
            if check_hash == maybe_hash:
                self._hash_offset = self.tell() - 32
                print(f'[*] Original Hash:     {hexlify(maybe_hash).decode()}')

    def _parse_segment(self, n):
        mem_offset, segment_size = self.unpack('<II')
        #print(f'[*] Segment {n:2} 0x{segment_size:06X}:0x{self.tell():06X} @ 0x{mem_offset:08X}')
        self.seek(segment_size, SEEK_CUR)
        #segment = data.read(segment_size)
        #for x in segment: self._checksum ^= x

    def _update_hash(self):
        if self._hash_offset is not None:
            pos = self.tell()
            self.seek(self._code_begin)
            sha = sha256(self.read(self._code_end - self._code_begin)).digest()
            self.write(sha)
            self.seek(pos)
            print(f'[+] Updated Hash:      {hexlify(sha).decode()}')

    def patch_string_at(self, key, string, offset, size):
        b = string.encode()
        length = len(b)
        if length > size:
            raise ValueError(f'Cannot fit string with encoded size {length} in {size} bytes!')

        print(f'[+] Writing {length} bytes to {key}[{size}] @ {offset}...')
        # zero pad to size
        b += b'\0' * (size - len(b) + 1)
        self.seek(offset)
        self.write(b)

def _read_as_bytesio(path):
    if path.suffix == '.gz':
        import gzip
        with gzip.open(path, 'rb') as f:
            return io.BytesIO(f.read())
    else:
        with open(path, 'rb') as f:
            return io.BytesIO(f.read())

def patch_binary(source, target, to_patch):
    if len(to_patch) == 0:
        return

    target_path = Path(target).absolute()
    source_path = Path(source).absolute()

    print(f'[+] Patching `{source_path.name}` -> `{target_path.name}`...')

    data = ESPImage(_read_as_bytesio(source_path))

    for m in re.finditer(rb'PLACEHOLDER_FOR_(\w+)\s+\0', data.getvalue()):
        key = m.group(1).decode()
        offset, end = m.span()
        size = (end - offset) - 1
        if (value := to_patch.get(key, None)) is not None:
            data.patch_string_at(key, value, offset, size)

    data.flush()

    if target_path.suffix == '.gz':
        print(f'[*] Compressing...')
        uncompressed = data.getvalue()
        # "Depending on the file, either first or last gives the best compression."
        buf = compress(uncompressed, blocksplittinglast=False)
        if zopfli is not None:
            maybe = compress(uncompressed, blocksplittinglast=True)
            if len(maybe) < len(buf):
                print(f'[+] Block splitting last was better')
                buf = maybe
    else:
        buf = data.getbuffer()

    with open(target_path, 'wb') as f:
        f.write(buf)

if __name__ == '__main__':
    if len(argv) == 2:
        source = argv[1]
        print(f'Source: {source}')
        source_path = Path(source).absolute()
        data = _read_as_bytesio(source_path)
        x = ESPImage(data)
    elif len(argv) > 2:
        source, target = argv[1], argv[2]
        to_patch = {}
        for patch in argv[3:]:
            key, _, value = patch.partition('=')
            to_patch[key] = value

        #print(source, target, to_patch)
        patch_binary(source, target, to_patch)
'''
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
