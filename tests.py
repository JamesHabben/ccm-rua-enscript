# -*- coding: utf-8 -*-
from __future__ import print_function


from datetime import datetime
import os.path
import unittest


from carve_for_ccm_recentlyusedapps import parse as parse_wmi_cim


class TestParser(unittest.TestCase):
    def setUp(self):
        self.test_dir = os.path.join(os.path.dirname(os.path.normpath(__file__)), 'test')

    def test_parse(self):
        # This test runs in Python 3 only
        tests = [
            ('CCM_RecentlyUsedApps_0.bin', 1,
             [{'additional_product_codes': None,
               'company_name': 'Adobe Systems Incorporated',
               'explorer_filename': 'FlashUtil32_29_0_0_140_Plugin.exe',
               'file_description': 'Adobe® Flash® Player Installer/Uninstaller 29.0 r0',
               'file_extension': 'exe',
               'file_properties_hash': None,
               'file_size': 1366528,
               'file_version': '29,0,0,140',
               'folder_path': 'C:\\Windows\\SysWOW64\\Macromed\\Flash\\',
               'full_path': 'C:\\Windows\\SysWOW64\\Macromed\\Flash\\FlashUtil32_29_0_0_140_Plugin.exe',
               'input_file_path': 'fullpath',
               'last_joined_sccm': datetime(2018, 1, 9, 15, 3, 41, 178641),
               'last_updated': datetime(2018, 6, 1, 14, 11, 46, 102794),
               'last_used_time': '20180603003600.000000+000',
               'last_username': 'ABCDEFGHIJKLMN\\geofff',
               'launch_count': 64,
               'msi_display_name': None,
               'msi_publisher': None,
               'msi_version': None,
               'offset': 0,
               'original_filename': 'FlashUtil.exe',
               'product_code': None,
               'product_language': 1033,
               'product_name': 'Adobe® Flash® Player Installer/Uninstaller',
               'product_version': '29,0,0,140',
               'record_type': 'Vista',
               'software_properties_hash': None}])
        ]
        for file_name, expected_count, expected_records in tests:
            with open(os.path.join(self.test_dir, file_name), 'rb') as test_file:
                records = list(parse_wmi_cim(test_file, 'fullpath'))
                self.assertEqual(expected_count, len(records))
                self.assertEqual(expected_records, records)

if __name__ == '__main__':
    unittest.main()
