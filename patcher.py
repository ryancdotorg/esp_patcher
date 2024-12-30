#!/usr/bin/env python3

from sys import argv, exit, stdin, stdout, stderr
from functools import partial
eprint = partial(print, file=stderr)

import re
import io
import sys

import gzip
import zlib

from pathlib import Path
from hashlib import sha256

esptool_dir = Path(Path.home(), 'code', 'esptool')
if esptool_dir.is_dir():
    sys.path.append(str(esptool_dir.resolve()))

import esptool
from esptool.loader import ESPLoader
from esptool.bin_image import ESP8266V2FirmwareImage, LoadFirmwareImage, ImageSegment
from esptool.targets import CHIP_DEFS, CHIP_LIST, ROM_LIST

BUILD_OUTPUT = Path('.', 'build_output', 'firmware')

def compress_with_gzip(data, level=9, **kw):
    if level > 9:
        level = 9
    if level < 1:
        level = 1

    compressor = zlib.compressobj(level=level, wbits=16 + zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()

# zopfli support is optional.
try:
    import zopfli.gzip
    def compress(data, level=100, **kw):
        if level < 10:
            return compress_with_gzip(data, level)

        return zopfli.gzip.compress(data, numiterations=level, blocksplittingmax=100, **kw)

except ModuleNotFoundError:
    eprint('zopfli is not installed.')
    eprint('Note: only zopfli is supported, not zopflipy.')
    def compress(data, level=9):
        return compress_with_gzip(data, level)

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

    data.seek(-33, 2)
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
        data.seek(-33, 2)
        data.write(bytes([checksum]))

        sha = sha256(data.getvalue()[:-32]).digest()
        # 32 bytes to the end
        data.seek(-32, 2)
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
