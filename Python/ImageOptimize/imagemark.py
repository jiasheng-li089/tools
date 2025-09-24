#!/usr/bin/env python3
# coding:utf-8

"""this module provide class to mark image with tag and check it"""

__author__ = 'Jiasheng Lee'

import logging
import binascii
import struct
import os
import shutil
import unittest
import imghdr
import piexif


# default suffix of the PNG files
_png_end = bytes(b'\x00\x00\x00\x00\x49\x45\x4E\x44\xAE\x42\x60\x82')

# flag of the mark
_const_mark = b'mark&tiny'

class ImageFormatError(BaseException):
    """
    error when check image format or check mark sign
    """

    def __init__(self, message, marker):
        super(ImageFormatError, self).__init__()
        self._message = message
        self._marker = marker

    @property
    def message(self):
        return self._message

    def marker(self):
        return self._marker


class MarkChecker(object):

    def has_mark(self):
        pass


class Marker(object):

    def mark(self):
        pass


class MarkCheckFactory(object):

    @staticmethod
    def _generate_png_mark(mark_sign):
        content = bytearray(b'tEXt')
        content.extend(mark_sign)
        content_bytes = bytearray(struct.pack('>L', len(mark_sign)))
        content_bytes.extend(content)
        content_bytes.extend((binascii.crc32(content)).to_bytes(
            4, byteorder='big'))
        return content_bytes

    @staticmethod
    def get_checker(filename, marksign):
        """
        check file type and return corresponding MarkChecker
        :param filename: the file
        :return: corresponding MarkChecker and Marker, raise ImageFormatError
        when no MarkChecker and Marker not fount
        """
        try:
            img_format = imghdr.what(filename)
            logging.debug("%s format is %s" % (filename, img_format))
            if 'png' == img_format:
                png_mark = MarkCheckFactory._generate_png_mark(marksign)
                return PNGMarkChecker(filename, png_mark)
            elif 'jpg' == img_format or 'jpeg' == img_format:
                return JPGMarkChecker(filename, marksign)
            else:
                raise ImageFormatError("unsupport image type: %s -> %s"
                                       % (filename, img_format), marksign)
        except BaseException as e:
            logging.info("read file error : %s" % e)
            raise ImageFormatError(e, marksign)

    @staticmethod
    def get_marker(filename, marksign):
        """

        :param filename:
        :param marksign:
        :return:
        """
        try:
            image_format = imghdr.what(filename)
            if image_format == 'png':
                png_mark = MarkCheckFactory._generate_png_mark(marksign)
                return PNGMarker(filename, png_mark)
            elif image_format == 'jpg' or image_format == 'jpeg':
                return JPGMarker(filename, marksign)
            else:
                raise ImageFormatError("unsupport image type: %s -> %s"
                                       % (filename, image_format), marksign)
        except BaseException as e:
            logging.error("read file error : %s" % e)
            raise ImageFormatError(e, marksign)


class JPGMarkChecker(MarkChecker):

    def __init__(self, filename, marker):
        self._fileName = filename
        self._marker = marker

    @property
    def file_name(self):
        return self._fileName

    @property
    def marker(self):
        return self._marker

    def has_mark(self):
        """
        check if the image is marked
        :return: marked for True, otherwise for False, raise
         ImageFormatError if this file is not normal image
        """
        exif_dict = piexif.load(self._fileName)
        if exif_dict is not 0 and '0th' in exif_dict and \
                piexif.ImageIFD.Copyright in exif_dict['0th']:
            return self._marker == exif_dict['0th'][piexif.ImageIFD.Copyright]
        return False


class JPGMarker(Marker):

    def __init__(self, filename, marker):
        self._fileName = filename
        self._marker = marker

    @property
    def file_name(self):
        return self._fileName

    @property
    def marker(self):
        return self._marker

    def mark(self):
        """
        open image and add mark to it
        :return: True if success, False if fail, and raise ImageFormatError if
        the file is not normal image
        """
        exif_dict = piexif.load(self._fileName)
        if exif_dict != 0 and '0th' in exif_dict:
            exif_dict['0th'][piexif.ImageIFD.Copyright] = self._marker
            exif_bytes = piexif.dump(exif_dict)
            piexif.insert(exif_bytes, self._fileName)
            return True
        return False


class PNGMarkChecker(MarkChecker):

    def __init__(self, filename, marker):
        self._fileName = filename
        self._marker = marker

    @property
    def marker(self):
        return self._marker

    @property
    def file_name(self):
        return self._fileName

    def has_mark(self):
        """
        check if the image is marked
        :return:marked for True, otherwise for False, raise ImageFormatError if
        this file is not normal image
        """
        with open(self._fileName, 'rb') as f:
            f.seek(- len(_png_end) - len(self._marker), os.SEEK_END)
            str = f.read(len(self._marker))
            return str == self._marker


class PNGMarker(Marker):

    def __init__(self, filename, marker):
        self._fileName = filename
        self._marker = marker

    @property
    def file_name(self):
        return self._fileName

    @property
    def marker(self):
        return self._marker

    def mark(self):
        """
        open image and add mark to it
        :return: True if success, False if fail, and raise ImageFormatError if
        the file is not normal image
        """
        with open(self._fileName, 'r+b') as f:
            f.seek(-len(_png_end), os.SEEK_END)
            end_sign = f.read()
            f.seek(-len(_png_end), os.SEEK_END)
            f.write(self._marker)
            f.write(end_sign)
            return True


class TestImageMark(unittest.TestCase):

    def test_png(self):
        self._origin_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'startup.jpg')
        self._test_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), 'startup_1.jpg')

        shutil.copyfile(self._origin_file, self._test_file)

        const_marker = _const_mark

        checker = MarkCheckFactory.get_checker(self._test_file, const_marker)

        if checker.has_mark():
            self.assertTrue(True)
        else:
            marker = MarkCheckFactory.get_marker(self._test_file,
                                                 const_marker)
            if marker.mark() and checker.has_mark():
                self.assertTrue(True)
            else:
                self.assertTrue(False)

        if os.path.isfile(self._test_file):
            os.remove(self._test_file)

    def test_jpg(self):
        self._origin_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_optimize_origin.png')
        self._test_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_optimize_origin_1.png')

        shutil.copyfile(self._origin_file, self._test_file)

        const_marker = _const_mark

        checker = MarkCheckFactory.get_checker(self._test_file, const_marker)

        if checker.has_mark():
            self.assertTrue(True)
        else:
            marker = MarkCheckFactory.get_marker(self._test_file,
                                                 const_marker)
            if marker.mark() and checker.has_mark():
                self.assertTrue(True)
            else:
                self.assertTrue(False)

        if os.path.isfile(self._test_file):
            os.remove(self._test_file)

    def test_error(self):
        self._origin_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'ignore.txt')
        self._test_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'ignore_1.txt')

        shutil.copyfile(self._origin_file, self._test_file)

        const_marker = _const_mark

        with self.assertRaises(ImageFormatError):
            MarkCheckFactory.get_checker(self._test_file, const_marker)

        if os.path.isfile(self._test_file):
            os.remove(self._test_file)


if '__main__' == __name__:
    unittest.main()
