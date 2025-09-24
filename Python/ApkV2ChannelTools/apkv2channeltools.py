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
# eocd 部最小大小
_ZIP_EOCD_REC_MIN_SIZE = 22
# eocd 部起始标示
_ZIP_EOCD_REC_SIGN = bytearray(b'\x06\x05\x4b\x50')
# eocd comment length 字段在eocd中的偏移量
_ZIP_EOCD_COMMENT_LENGTH_FIELD_OFFSET = 20
# eocd locator 偏移量
_ZIP64_EOCD_LOCATOR_SIZE = 20
# eocd locator 起始标示
_ZIP64_EOCD_LOCATOR_SIGN_REVERSE_BYTE_ORDER = 0x07064b50
# central directory 偏移量字段在eocd段中的偏移量
_ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET = 16
# central directory 大小字段在eocd端中的偏移量
_ZIP_EOCD_CENTRAL_DIR_SIZE_FIELD_OFFSET = 12
# sign block id 长度
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
        获取文件大小
        :param file: 对应文件
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
    获取eocd部在zip文件中的偏移量
    :param file: zip文件
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
    返回Central Directory部在zip文件中的起始位置
    :param file: zip文件
    :param eocd_offset: eocd在文件中的起始位置
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
    判断文件是否zip64格式
    :param file: 对应文件
    :param ecod_offset: eocd部在文件中的偏移量
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
    构建channel在signing block的数据
    :param channel_id: 渠道标示id, 字节数组
    :param channel_str: 渠道信息字符串
    :return: 返回构建好的byte数组
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
    提取apk的signing block部分数据
    :param file: apk 文件
    :param central_dir_offset: apk Central Directory在文件中的偏移量
    :return:
    """
    file_size = FileTools.get_file_size(file)

    if central_dir_offset < 0:
        raise SignatureNotFoundError('Central Directory offset invalid:'
                                     + central_dir_offset)
    if central_dir_offset > file_size - _ZIP_EOCD_REC_MIN_SIZE:
        raise SignatureNotFoundError('central directory offset should not > ' +
                                     file_size - _ZIP_EOCD_REC_MIN_SIZE)

    # 校验signing block magic
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
    合并旧apk的sign block 和渠道信息
    :param sign_block: sign block
    :param channel_data: 渠道信息
    :return: 返回合并后的数据和增长长度
    """
    old_size = len(sign_block)
    new_size = len(sign_block) + len(channel_data)

    new_sign_block = bytearray()

    # 生成新的长度
    new_size_data = (new_size - 8).to_bytes(8, byteorder='little', signed=False)
    # 新的 size of block
    new_sign_block.extend(new_size_data)

    # 拼接signing block
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

    # 拼接 channel info
    new_sign_block.extend(channel_data)

    # 拼接 size of block
    new_sign_block.extend(new_size_data)
    # 拼接magic
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
        判断apk的signing block是否含有key_id
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
                # 写signing block前置数据
                new_apk.write(pre_data)

                # 写new signing block
                new_apk.write(new_sign_block)

                # 写 Central Directory 及后置数据
                self._apk.seek(self._central_dir_offset, os.SEEK_SET)
                tmp = self._apk.read(self._file_size - self._central_dir_offset)
                new_apk.write(tmp)

                # 修改Central Directory在eocd中的偏移量
                new_apk.seek(self._eocd_offset + add_size
                             + _ZIP_EOCD_CENTRAL_DIR_OFFSET_FIELD_OFFSET)
                new_apk.write((self._central_dir_offset + add_size).to_bytes(
                    4, 'little', signed=False))
                return True
        raise SignatureNotFoundError('this file not sign by v2')

    def release(self):
        """
        释放资源
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
