from __future__ import print_function
from builtins import bytes, chr, open

#!/usr/bin/env python
# Written by James Habben
# Updated 2017-04-04

import argparse
from collections import namedtuple
from datetime import datetime, timedelta
import decimal
import mmap
import os.path
import re
import struct
import sys
import time


if sys.version_info[0] > 2:
    import csv
else:
    from backports import csv


# Below two functions are updated versions of timestamp parsing from Python-Registry package,
# which has not been updated on PyPi.
# Copyright 2011 Will Ballenthin
# Licensed under the Apache License, Version 2.0


def parse_timestamp(ticks, resolution, epoch, mode=decimal.ROUND_HALF_EVEN):
    """
    Generalized function for parsing timestamps

    :param ticks: number of time units since the epoch
    :param resolution: number of time units per second
    :param epoch: the datetime of this timestamp's epoch
    :param mode: decimal rounding mode
    :return: datetime.datetime
    """
    # python's datetime.datetime supports microsecond precision
    datetime_resolution = int(1e6)

    # convert ticks since epoch to microseconds since epoch
    us = int((decimal.Decimal(ticks * datetime_resolution) / decimal.Decimal(resolution)).quantize(1, mode))

    # convert to datetime
    return epoch + timedelta(microseconds=us)


def parse_windows_timestamp(qword):
    """
    :param qword: number of 100-nanoseconds since 1601-01-01
    :return: datetime.datetime
    """
    # see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724290(v=vs.85).aspx
    return parse_timestamp(qword, int(1e7), datetime(1601, 1, 1))


def datetime_from_windows_filetime(count):
    if count == 0:
        return None
    try:
        return parse_windows_timestamp(count)
    except (OverflowError, TypeError, ValueError):
        return None


class NamedStruct(struct.Struct):
    def __init__(self, struct_name='NamedStruct', endianness='<', pairs=None):
        if pairs is None:
            pairs = []
        struct_args = [x[1] for x in pairs]
        super(NamedStruct, self).__init__(endianness + ' '.join(struct_args))
        self.structured_data = namedtuple(struct_name, [x[0] for x in pairs if 'x' not in x[1]])

    def parse(self, buf, offset):
        return self.structured_data._make(self.unpack(buf[offset:self.size + offset]))

    def parse_as_dict(self, buf, offset):
        return dict(self.parse(buf, offset)._asdict())


RECENTLY_USED_APPS_TYPES = {
    128: 'Vista',
    64: 'XP'
}


# Begins after Class ID
RUA_RECORD_HEADER = NamedStruct('CIMRUA_Header', '<', [
    ('last_updated', 'Q'),
    ('last_joined_sccm', 'Q'),
    ('record_size', 'I'),  # size of record, starting from the record_size field offset
    ('_classname_offset', '4x'),
    ('_unknown_byte_0x98', '1x'),
    ('_property_states', '5x'),
])


RUA_PROPERTY_OFFSETS_VALUES = NamedStruct('CIMRUA_Offsets', '<', [
    ('folder_path', 'I'),
    ('explorer_filename', 'I'),
    ('last_username', 'I'),
    ('original_filename', 'I'),
    ('file_version', 'I'),
    ('file_size', 'I'),
    ('product_name', 'I'),
    ('product_version', 'I'),
    ('company_name', 'I'),
    ('product_language', 'I'),
    ('file_description', 'I'),
    ('launch_count', 'I'),
    ('last_used_time', 'I'),
    ('product_code', 'I'),
    ('additional_product_codes', 'I'),
    ('msi_display_name', 'I'),
    ('msi_publisher', 'I'),
    ('msi_version', 'I'),
    ('software_properties_hash', 'I'),
    ('file_properties_hash', 'I'),
    ('_qualifiers_list', '4x'),
    ('_dynamic_properties', '1x'),
    ('properties_size', 'h'),  # property strings section size, starting at the \x00 preceding CCM_RecentlyUsedApps
    ('_unknown_short_0xF5', '2x'),
])


RUA_PROPERTY_VALUE_FIELDS = [
    'file_size',
    'launch_count',
    'product_language'
]


RUA_RECORD_STRINGS = [
    'additional_product_codes',
    'company_name',
    'explorer_filename',
    'file_description',
    'file_properties_hash',
    'file_version',
    'folder_path',
    'last_used_time',
    'last_username',
    'msi_display_name',
    'msi_publisher',
    'msi_version',
    'original_filename',
    'product_code',
    'product_name',
    'product_version',
    'software_properties_hash'
]


CSV_FIELDNAMES = [
    'input_file_path',
    'offset',
    'record_type',
    'full_path',
    'file_extension',
    'last_updated',
    'last_joined_sccm',
    'file_size',
    'launch_count',
    'product_language'
] + RUA_RECORD_STRINGS


# This is an arbitrary safety limit for the parser
RUA_MAX_RECORD_SIZE = 65536


def decode_cim_encoded_string(buf, offset, uncompressed, fullpath=None, file_offset=None):
    if uncompressed:
        try:
            return buf.decode('utf-16le', errors='replace').rstrip('\x00')
        except Exception:
            pass
    else:
        try:
            buf = buf.rstrip(b'\x00')
            range_end = len(buf)
            return ''.join([chr(buf[i]) for i in range(offset, range_end)])
        except Exception:
            pass
    print("Could not decode CIM Encoded String ({}) at offset {} in file {}.".format(
        buf, file_offset, fullpath))
    return None


def read_cim_encoded_string(buf, start, end, fullpath=None, file_offset=None):
    """
    WMI Encoding 2.2.78 Encoded-String
    https://msdn.microsoft.com/en-us/library/cc250923.aspx

    The Encoded-String string data type is encoded using an encoding flag that consists of one
    octet followed by a sequence of character items using one of two formats followed by a null
    terminator.

    The Encoded-String-Flag is set to 0x01 if the sequence of characters that follows consists of
    UTF-16 characters (as specified in [UNICODE]) followed by a UTF-16 null terminator.

    For optimization reasons, the implementation MUST compress the UTF-16 encoding. If all the
    characters in the string have values (as specified in [UNICODE]) that are from 0 to 255, the
    string MUST be compressed. The compression is done by representing each character as a single
    OCTET with its Unicode value. That is, for each Unicode character, only the lower-order byte
    is included in the output. A terminating null character MUST be represented by a single OCTET.
    When the string is compressed, Encoded-String-Flag is set to 0x00. This is distinct from UTF-8,
    which might contain multiple-byte encodings for single characters.
    """
    # Record length 2 only happens when you have a flag and null byte, no point in processing
    if end - start == 2:
        return None
    if start > len(buf):
        return None
    uncompressed_raw = buf[start:start + 1]
    if uncompressed_raw not in [b'\x00', b'\x01']:
        print("Unexpected Encoded-String-Flag value ({}) - should have been 0x00 or 0x01 at offset {} in file {}.".format(
            uncompressed_raw, file_offset, fullpath))
        return None
    uncompressed = uncompressed_raw == b'\x01'
    next_byte = buf[start + 1:start + 2]
    if next_byte == b'':
        return None
    return decode_cim_encoded_string(buf[start + 1:end], 0, uncompressed, fullpath, file_offset)


def get_prop_offsets(fileobj, record, fullpath, hash_start):
    try:
        offsets = RUA_PROPERTY_OFFSETS_VALUES.parse_as_dict(
            fileobj.read(RUA_PROPERTY_OFFSETS_VALUES.size), 0)
    except struct.error:
        print('Could not decode RUA record property offsets/values at offset {} in file {}'.format(
            hash_start, fullpath))
        return None
    # Grab the value fields
    record.update((prop_name, offsets.pop(prop_name, None)) for prop_name in RUA_PROPERTY_VALUE_FIELDS)
    return offsets


def parse_fields(record):
    record['last_updated'] = datetime_from_windows_filetime(record['last_updated'])
    record['last_joined_sccm'] = datetime_from_windows_filetime(record['last_joined_sccm'])
    folder_path = record.get('folder_path', '') or ''
    file_name = record.get('explorer_filename', '') or ''
    record['full_path'] = ''.join([folder_path, '' if folder_path.endswith('\\') else '\\', file_name]) or None
    record['file_extension'] = os.path.splitext(file_name)[1].replace('.', '').lower() or None
    return record


def process_hit(fileobj, match, fullpath):
    hash_start = match.start()
    hash_end = match.end()
    match_len = hash_end - hash_start

    record = {
        'input_file_path': fullpath,
        'offset': hash_start,
        'record_type': RECENTLY_USED_APPS_TYPES[match_len]
    }
    fileobj.seek(hash_end)
    try:
        record.update(
            RUA_RECORD_HEADER.parse_as_dict(fileobj.read(RUA_RECORD_HEADER.size), 0))
    except struct.error:
        print('Could not decode RUA record header at offset {} in file {}'.format(hash_start, fullpath))
        return record
    record_size = record.pop('record_size')
    if record_size > RUA_MAX_RECORD_SIZE:
        print('Decoded record size ({}) larger than allowed max record size ({}) at offset {} in file {}.'.format(
            record_size, RUA_MAX_RECORD_SIZE, hash_start, fullpath))

    offsets = get_prop_offsets(fileobj, record, fullpath, hash_start)
    if offsets is None:
        return record
    properties_size = offsets.pop('properties_size')
    # future bytes() for Python 2.7 compatibility
    properties_data = bytes(fileobj.read(min(properties_size, RUA_MAX_RECORD_SIZE)))

    sorted_offsets = sorted(offsets.items(), key=lambda kv: kv[1])
    s_o_len = len(sorted_offsets)
    for idx, (prop_name, field_offset) in enumerate(sorted_offsets):
        field_end = sorted_offsets[idx + 1][1] if (idx + 1 < s_o_len) else properties_size
        record[prop_name] = read_cim_encoded_string(properties_data, field_offset, field_end, fullpath, hash_start)

    record = parse_fields(record)
    return record


def parse(fileobj, fullpath=None):
    pattern = '7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8|6FA62F462BEF740F820D72D9250D743C'.encode('utf-16le')
    data = mmap.mmap(fileobj.fileno(), 0, access=mmap.ACCESS_READ)
    for match in re.finditer(pattern, data):
        yield process_hit(fileobj, match, fullpath)


def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(description='Carve any data blob file for CCM_RecentlyUsedApps records')
    parser.add_argument('input', help='path to an OBJECTS.DATA/INDEX.BTR file')
    parser.add_argument('--csv', required=True, help='path to tab delimited output file')
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)
    args = parser.parse_args()
    hitcount = 0

    with open(args.input, 'rb') as in_file, open(args.csv, 'w', encoding='utf_8_sig', newline='') as csv_file:
        csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_FIELDNAMES)
        csv_writer.writeheader()
        for record in parse(in_file, args.input):
            hitcount += 1
            csv_writer.writerow(record)

        print('Hits: {}'.format(hitcount))
        print('Time elapsed: {:.2f}s'.format(time.time() - start_time))


if __name__ == "__main__":
    main()
