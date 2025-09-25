#!/usr/bin/env python3
# coding:utf-8

"""
this module to write channel info to apk which signing with scheme v2
"""

__author__ = 'Jiasheng Lee'

import os
import unittest
import logging
import getopt
import sys


logging.basicConfig(level=logging.INFO, format='%(levelname)s\t\t%(asctime)s'
                    + '\t\tApkV2ChannelsTools\t%(message)s')

_UNIT16_MAX_VALUE = 0xffff
# the minimum size of the eocd section
_ZIP_EOCD_REC_MIN_SIZE = 22
# the start mark of the eocd section
_ZIP_EOCD_REC_SIGN = bytearray(b'\x06\x05\x4b\x50')
# the offset of the field eocd comment length in the EOCD section
_ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20
# the start mark of the eocd locator
_ZIP64_EOCD_LOCATOR_SIGN_REVERSE_BYTE_ORDER = 0x07064b50
# the offset of the field central directory offset in the EOCD section
_ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
# the offset of the central directory size in the EOCD section
_ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
# the length of sign block id
_SIGN_EXTRA_ID_LENGTH = 4
# sign block magic
_APK_SIGN_BLOCK_MAGIC = bytearray(b'\x32\x34\x20\x6b\x63\x6f\x6c\x42'
                                  b'\x20\x67\x69\x53\x20\x4b\x50\x41')
# signature scheme v2 block id
_APK_SIGNATURE_SCHEME_V2_BLOCK_ID = bytearray(b'\x71\x09\x87\x1a')
# signature scheme v2 channel id
_APK_SIGNATURE_SCHEME_V2_CHANNEL_ID = bytearray(b'\x71\x09\x87\x19')


class SignatureNotFoundError(BaseException):
    pass


class FileTools(object):

    @staticmethod
    def get_file_size(file):
        """
        get the size of the file
        :param file: file path
        :return:
        """
        original_pos = file.tell()
        try:
            file.seek(0, os.SEEK_END)
            return file.tell()
        finally:
            file.seek(original_pos, os.SEEK_SET)

    @staticmethod
    def read_int(file, size):
        tmp = bytearray(file.read(size))
        return int.from_bytes(tmp, byteorder='little', signed=False)

    @staticmethod
    def read_little_endian_data(file, size):
        data = bytearray(file.read(size))
        data.reverse()
        return data

    @staticmethod
    def read_config_file(file_name):
        try:
            with open(file_name, 'rt', encoding='UTF-8') as f:
                lines = f.readlines()
                return [x.strip() for x in lines if
                        not x.strip().startswith("#")]
        except BaseException as e:
            logging.error("read %s error: %s" % (file_name, e))
            raise e


def _get_eocd_offset_in_file(file):
    """
    get the offset of the EOCD section in the zip file
    :param file: the path of the zip file
    :return:
    """
    file_size = FileTools.get_file_size(file)
    if file_size < _ZIP_EOCD_REC_MIN_SIZE:
        return -1

    max_comment_size = min(file_size - _ZIP_EOCD_REC_MIN_SIZE,
                           _UNIT16_MAX_VALUE)
    empty_comment_start_pos = file_size - _ZIP_EOCD_REC_MIN_SIZE

    comment_length = 0
    while comment_length < max_comment_size:
        eocd_start_pos = empty_comment_start_pos - comment_length

        file.seek(eocd_start_pos, os.SEEK_SET)
        tmp_data = FileTools.read_little_endian_data(file, 4)

        if tmp_data == _ZIP_EOCD_REC_SIGN:
            file.seek(_ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET - 4,
                      os.SEEK_CUR)
            actual_comment_length = FileTools.read_int(file, 2)

            if actual_comment_length == comment_length:
                file.seek(0, os.SEEK_SET)
                return eocd_start_pos
            file.seek(eocd_start_pos, os.SEEK_SET)

        comment_length += 1
    return -1


def _get_central_directory_offset_in_file(file, eocd_offset):
    """
    get the start position of the central directory secion in the zip file
    :param file: file path of the zip file
    :param eocd_offset: start position of the EOCD section in the file
    :return:
    """
    file.seek(eocd_offset + _ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET,
              os.SEEK_SET)
    central_dir_offset = FileTools.read_int(file, 4)

    file.seek(eocd_offset + _ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET,
              os.SEEK_SET)
    central_dir_size = FileTools.read_int(file, 4)

    if central_dir_offset + central_dir_size != eocd_offset:
        raise SignatureNotFoundError('ZIP Central Directory is not'
                                     + 'immediately followed by End of' +
                                     ' Central Directory')
    return central_dir_offset


def _is_zip64_end_of_central_directory_locator_present(file,
                                                       ecod_offset):
    """
    chech if the file is zip64 format
    :param file: file path
    :param ecod_offset: the start position of the EOCD section in the file
    :return:
    """
    locator_pos = ecod_offset - _ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET

    if locator_pos < 0:
        return False

    file.seek(locator_pos, os.SEEK_SET)

    return FileTools.read_int(file, 4) \
           == _ZIP64_EOCD_LOCATOR_SIGN_REVERSE_BYTE_ORDER


def _create_channel_data(channel_id, channel_str):
    """
    create the meta data that can be inserted into the signing block
    :param channel_id: the id of the meta data 
    :param channel_str: the meta data
    :return: generated data
    """
    if len(channel_id) != _SIGN_EXTRA_ID_LENGTH:
        raise SignatureNotFoundError("channel id length should = %s"
                                     % _SIGN_EXTRA_ID_LENGTH)

    # length   (8 bytes)
    # id       (4 bytes)
    # content  (length bytes)

    channel_id_data = bytearray(channel_id)
    channel_id_data.reverse()
    channel_content = bytearray(channel_str.encode('utf-8'))
    channel_len = (len(channel_content) + 4).to_bytes(8,
                                                      'little', signed=False)

    data = bytearray()
    data.extend(channel_len)
    data.extend(channel_id_data)
    data.extend(channel_content)
    return data


def _get_sign_block_of_apk(file, central_dir_offset):
    """
    extract the data of the signing block
    :param file: file path of the apk file
    :param central_dir_offset: the start position of the Central Directory section in the file
    :return:
    """
    file_size = FileTools.get_file_size(file)

    if central_dir_offset < 0:
        raise SignatureNotFoundError('Central Directory offset invalid:'
                                     + central_dir_offset)
    if central_dir_offset > file_size - _ZIP_EOCD_REC_MIN_SIZE:
        raise SignatureNotFoundError('central directory offset should not > ' +
                                     file_size - _ZIP_EOCD_REC_MIN_SIZE)

    # verify the signing block magic
    file.seek(central_dir_offset - 16)
    apk_magic = FileTools.read_little_endian_data(file, 16)

    if apk_magic != _APK_SIGN_BLOCK_MAGIC:
        raise SignatureNotFoundError('apk signing block magic is invalid:'
                                     + apk_magic.hex())

    file.seek(central_dir_offset - 24)
    block_size = FileTools.read_int(file, 8)

    file.seek(central_dir_offset - block_size - 8)
    return file.read(block_size + 8)


def _combine_sign_block_and_channel(sign_block, channel_data):
    """
    merge the old signing block and the generated meta data
    :param sign_block: sign block
    :param channel_data: the generated meta data
    :return: the merged data and its length
    """
    old_size = len(sign_block)
    new_size = len(sign_block) + len(channel_data)

    new_sign_block = bytearray()

    # new data length
    new_size_data = (new_size - 8).to_bytes(8, byteorder='little', signed=False)
    # new size of block
    new_sign_block.extend(new_size_data)

    # append the signing block
    key_value = sign_block[8: old_size - 24]
    key_value_size = len(key_value)

    entry_count = 0
    start_pos = 0

    while start_pos < key_value_size:
        entry_count += 1

        # length   (8 bytes)
        # id       (4 bytes)
        # content  (length bytes)
        values_len = int.from_bytes(key_value[start_pos: start_pos + 8],
                                    'little', signed=False)

        key_id = bytearray(key_value[start_pos + 8: start_pos + 12])
        data = key_value[start_pos + 12: start_pos + 12 + values_len]

        new_sign_block.extend(values_len.to_bytes(8, 'little', signed=False))
        new_sign_block.extend(key_id)
        new_sign_block.extend(data)

        start_pos = start_pos + 8 + values_len

    # append the meta info
    new_sign_block.extend(channel_data)

    # append the size of block
    new_sign_block.extend(new_size_data)
    # append the magic number
    new_sign_block.extend(sign_block[old_size - 16: old_size])
    return new_sign_block, new_size - old_size


class ApkChannelTool(object):

    def __init__(self, file):
        self._apk = open(file, 'rb')
        self._file_size = FileTools.get_file_size(self._apk)

        self._eocd_offset = _get_eocd_offset_in_file(self._apk)
        if self._eocd_offset < 0 or self._eocd_offset > self._file_size \
                or _is_zip64_end_of_central_directory_locator_present(
            self._apk, self._eocd_offset):
            self._central_dir_offset = -1
        else:
            try:
                self._central_dir_offset = \
                    _get_central_directory_offset_in_file(self._apk,
                                                          self._eocd_offset)
            except SignatureNotFoundError:
                self._central_dir_offset = -1

        if 0 <= self._central_dir_offset < self._eocd_offset:
            try:
                self._sign_block = _get_sign_block_of_apk(
                    self._apk, self._central_dir_offset)
            except SignatureNotFoundError:
                self._sign_block = None
        else:
            self._sign_block = None

    def has_extra_info_in_signing_block(self, key_id):
        """
        check if the signing block contains the key_id
        :param key_id:
        :return:
        """
        if self._sign_block:
            sign_block = self._sign_block
            key_value = sign_block[8:len(sign_block) - 24]
            key_value_size = len(key_value)
            entry_count = 0

            start_pos = 0

            while start_pos < key_value_size:
                entry_count += 1

                # length   (8 bytes)
                # id       (4 bytes)
                # content  (length bytes)
                values_len = key_value[start_pos: start_pos + 8]
                tmp_key_id = bytearray(key_value[start_pos + 8: start_pos + 12])
                tmp_key_id.reverse()

                next_entry_pos = start_pos + 8 + int.from_bytes(values_len,
                                                                'little',
                                                                signed=False)

                if tmp_key_id == key_id:
                    return True

                start_pos = next_entry_pos

            return False
        return False

    def has_v2_signature(self):
        """
        check if the apk is signed with Scheme v2
        判断apk是否使用v2进行签名
        :return:
        """
        return self.has_extra_info_in_signing_block(
            _APK_SIGNATURE_SCHEME_V2_BLOCK_ID)

    def save_as_channel_file(self, target_file, channel_id, channel_str):
        if self._sign_block:
            channel_block = _create_channel_data(channel_id, channel_str)
            new_sign_block, add_size = _combine_sign_block_and_channel(
                self._sign_block, channel_block)
            with open(target_file, 'w+b'):
                pass

            with open(target_file, 'r+b') as new_apk:
                self._apk.seek(0, os.SEEK_SET)
                pre_data = self._apk.read(self._central_dir_offset
                                          - len(self._sign_block))
                # the data before the signing block
                new_apk.write(pre_data)

                # new signing block
                new_apk.write(new_sign_block)

                # Central Directory and the data after that
                self._apk.seek(self._central_dir_offset, os.SEEK_SET)
                tmp = self._apk.read(self._file_size - self._central_dir_offset)
                new_apk.write(tmp)

                # modify the offset of the Central Directory in EOCD section
                new_apk.seek(self._eocd_offset + add_size
                             + _ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET)
                new_apk.write((self._central_dir_offset + add_size).to_bytes(
                    4, 'little', signed=False))
                return True
        raise SignatureNotFoundError('this file not sign by v2')

    def release(self):
        """
        :return:
        """
        self._apk.close()


class ChannelToolsTest(unittest.TestCase):

    def test_has_v2_sign(self):
        current_dir = os.path.dirname(os.path.realpath(__file__))
        apk_file_path = os.path.join(current_dir, 'app-release_v2.apk')
        channel_apk_file = os.path.join(current_dir, "app-official.apk")

        apk_channel_tools = ApkChannelTool(apk_file_path)

        if apk_channel_tools.has_v2_signature():
            apk_channel_tools.save_as_channel_file(
                channel_apk_file, _APK_SIGNATURE_SCHEME_V2_CHANNEL_ID,
                'official')
            apk_channel_tools.release()

            new_apk_channel_tool = ApkChannelTool(channel_apk_file)

            self.assertTrue(new_apk_channel_tool.has_extra_info_in_signing_block(
                    _APK_SIGNATURE_SCHEME_V2_CHANNEL_ID))
            new_apk_channel_tool.release()

        v1_apk_file = os.path.join(current_dir, 'app-release_v1.apk')
        v1_apk_tools = ApkChannelTool(v1_apk_file)

        self.assertFalse(v1_apk_tools.has_extra_info_in_signing_block(
            _APK_SIGNATURE_SCHEME_V2_CHANNEL_ID))
        v1_apk_tools.release()


if __name__ == '__main__':

    _channels_file = None
    _format = 'app-%s.apk'
    _target_dir = None
    _source_apk = None

    _channels_list = []

    try:
        opts, args = getopt.getopt(sys.argv[1:], "",
                                   ["channels=", "source-apk=", "target-dir=",
                                    "format="])
    except getopt.GetoptError:
        print("apkv2channeltools.py --source-apk=<sourceApk>"
              + " --channels=<channelsFile> [--target-dir=<targetDir>]"
              + " --format=[targetApkFileNameFormat]")
        sys.exit(1)

    for opt, arg in opts:
        if opt == '--source-apk':
            _source_apk = arg
        elif opt == '--channels':
            _channels_file = arg
        elif opt == '--target-dir':
            _target_dir = arg
        elif opt == '--format':
            _format = arg

    try:
        _channels_list = FileTools.read_config_file(_channels_file)
    except BaseException as e:
        print('read channels file error %s' % e)
        sys.exit(1)

    try:
        _format % '23'
    except TypeError as e:
        print("format must like this:[<pre>]%s[<next>]")
        sys.exit(1)

    if not _target_dir:
        _target_dir = os.getcwd()

    if not os.path.isdir(_target_dir):
        print("target directory invalid")
        sys.exit(1)

    apk_tools = ApkChannelTool(_source_apk)

    if apk_tools.has_v2_signature():
        for channel in _channels_list:
            target_name = _format % channel
            target_file = os.path.join(_target_dir, target_name)

            if apk_tools.save_as_channel_file(
                    target_file, _APK_SIGNATURE_SCHEME_V2_CHANNEL_ID, channel):
                target_tools = ApkChannelTool(target_file)
                if target_tools.has_extra_info_in_signing_block(
                        _APK_SIGNATURE_SCHEME_V2_CHANNEL_ID):
                    logging.info("generate %s apk success" % channel)
                    continue
            logging.error("generate %s apk fail" % channel)
    else:
        print("%s is not a apk signed by scheme v2" % _source_apk)
        apk_tools.release()
        sys.exit(2)
    sys.exit(0)
