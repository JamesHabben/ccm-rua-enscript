#!/usr/bin/env python
# Written by James Habben
# Updated 2017-04-04

import sys
import re
import time
import struct
import argparse
import codecs

from datetime import datetime, timedelta

class CcmRua:
    def __init__(self):
        self.FilePath = ''
        self.FileOffset = ''
        self.RecordType = ''
        self.Filetime1 = ''
        self.Filetime2 = ''
        self.RecordSize = 0
        self.Filesize = 0
        self.ProductLanguage = 0
        self.LaunchCount = 0
        self.AdditionalProductCodes = ''
        self.CompanyName = ''
        self.ExplorerFilename = ''
        self.FileDescription = ''
        self.FilePropertiesHash = ''
        self.FileVersion = ''
        self.FolderPath = ''
        self.LastUsedTime = ''
        self.LastUsername = ''
        self.MsiDisplayName = ''
        self.MsiPublisher = ''
        self.MsiVersion = ''
        self.OriginalFilename = ''
        self.ProductCode = ''
        self.ProductName = ''
        self.ProductVersion = ''
        self.SoftwarePropertiesHash = ''



    def ReadWinDate(self, file, offset=-1):
        if offset != -1:
            file.seek(offset)
        bytes = struct.unpack_from('<Q', file.read(8))[0]
        microseconds = bytes / 10 #int(bytes, 16) / 10
        seconds, microseconds = divmod(microseconds, 1000000)
        days, seconds = divmod(seconds, 86400)
        return format(datetime(1601, 1, 1) + timedelta(days, seconds, microseconds), '%Y-%m-%d %H:%M:%S -0')

    def ReadString(self, file, offset=-1):
        if offset != -1:
            file.seek(offset)
        codepage = struct.unpack_from('b', file.read(1))[0]
        ch = -1
        prop = u''
        while ch != 0:
            if codepage == 0:
                ch = struct.unpack_from('B', file.read(1))[0]
                if ch == 0: break
                prop += unichr(ch)
            else:
                ch = struct.unpack_from('H', file.read(2))[0]
                if ch == 0: break
                prop += unichr(ch)
        return prop

    def ParseRecord(self, file, offset, filepath):
        file.seek(offset)
        self.FileOffset = file.tell()
        self.FilePath = filepath
        if file.read(1) == '7':
            self.RecordType = 'W7'
            file.seek(offset + 128)
        else:
            self.RecordType = 'XP'
            file.seek(offset + 32)
        self.Filetime1 = self.ReadWinDate(file)
        self.Filetime2 = self.ReadWinDate(file)
        self.RecordSize = struct.unpack_from('<Q', file.read(8))[0]
        file.seek(file.tell() + 26)
        self.Filesize = struct.unpack_from('<I', file.read(4))[0]
        file.seek(file.tell() + 12)
        self.ProductLanguage = struct.unpack_from('<I', file.read(4))[0]
        file.seek(file.tell() + 4)
        self.LaunchCount = struct.unpack_from('<I', file.read(4))[0]
        file.seek(file.tell() + 42)
        file.seek(file.tell() + 21) # CCM_RecentlyUsedApps
        self.AdditionalProductCodes = self.ReadString(file)
        self.CompanyName = self.ReadString(file)
        self.ExplorerFilename = self.ReadString(file)
        self.FileDescription = self.ReadString(file)
        self.FilePropertiesHash = self.ReadString(file)
        self.FileVersion = self.ReadString(file)
        self.FolderPath = self.ReadString(file)
        self.LastUsedTime = self.ReadString(file)
        self.LastUsername = self.ReadString(file)
        self.MsiDisplayName = self.ReadString(file)
        self.MsiPublisher = self.ReadString(file)
        self.MsiVersion = self.ReadString(file)
        self.OriginalFilename = self.ReadString(file)
        self.ProductCode = self.ReadString(file)
        self.ProductName = self.ReadString(file)
        self.ProductVersion = self.ReadString(file)
        self.SoftwarePropertiesHash = self.ReadString(file)


    ccmrua_w7_hash = '7C261551B264D35E30A7FA29C75283DAE04BBA71DBE8F5E553F7AD381B406DD8'.encode('utf-16le')
    ccmrua_xp_hash = '6FA62F462BEF740F820D72D9250D743C'.encode('utf-16le')

def csvOutput(list, outpath):
    with codecs.open(outpath, 'w', 'utf-8-sig') as outfile:
        outfile.write('sep=\t\nFilePath\tFileOffset\tRecordType\tFiletime1\tFiletime2\tFilesize\tProductLanguage\t'
            'LaunchCount\tAdditionalProductCodes\tCompanyName\tExplorerFilename\tFileDescription\tFilePropertiesHash\t'
            'FileVersion\tFolderPath\tLastUsedTime\tLastUsername\tMsiDisplayName\tMsiPublisher\tMsiVersion\t'
            'OriginalFilename\tProductCode\tProductName\tProductVersion\tSoftwarePropertiesHash\n')

        for rec in list:
            outfile.write(u'{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t'
            '{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n'.format(
                rec.FilePath, rec.FileOffset, rec.RecordType, rec.Filetime1,
                rec.Filetime2, rec.Filesize, rec.ProductLanguage, rec.LaunchCount,
                rec.AdditionalProductCodes, rec.CompanyName, rec.ExplorerFilename,
                rec.FileDescription, rec.FilePropertiesHash, rec.FileVersion,
                rec.FolderPath, rec.LastUsedTime, rec.LastUsername, rec.MsiDisplayName,
                rec.MsiPublisher, rec.MsiVersion, rec.OriginalFilename, rec.ProductCode,
                rec.ProductName, rec.ProductVersion, rec.SoftwarePropertiesHash
            ))

def main():
    start_time = time.time()

    parser = argparse.ArgumentParser(
        description = 'Carve any data blob file for CCM_RecentlyUsedApps records')
    parser.add_argument('input', help='path to an OBJECTS.DATA file')
    parser.add_argument('--csv', help='path to tab delimited output file')
    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(1)
    args = parser.parse_args()

    #searchfilepath = '/Users/jameshabben/Documents/VzCases/Jefferies/cim/OBJECTS.DATA'

    with open(args.input, 'rb') as file:
        text = file.read()
        hitcount = 0
        #hits = re.findall('RecentlyUsedApps', text)
        #hits = re.findall(CCM_RUA_GUID_VISTA_UTF16, text)
        hits = re.finditer(CcmRua.ccmrua_w7_hash, text)
        #hits += re.finditer(CcmRua.ccmrua_xp_hash, text)
        recordlist = []
        for hit in hits:
            record = CcmRua()
            record.ParseRecord(file, hit.start(), args.input)
            recordlist.append(record)
            hitcount += 1
        #print 'hits: {}'.format(len(hits))

        csvOutput(recordlist, args.csv)

        print 'hits: {}'.format(hitcount)
        print 'time elapsed: {:.2f}s'.format(time.time() - start_time)

if __name__ == "__main__":
    main()
