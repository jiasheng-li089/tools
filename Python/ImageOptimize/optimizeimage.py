#!/usr/bin/env python3
# coding:utf-8

"""upload image to tiny server to optimize image"""

__author__ = 'Jiasheng Lee'


import logging
import requests
import json
import unittest
import os


class AuthTokenError (BaseException):
    def __init__(self, message):
        self._message = message

    @property
    def message(self):
        return self._message


class NetworkError (BaseException):
    def __init__(self, message):
        self._message = message

    @property
    def message(self):
        return self._message


class ImageOptimizer(object):

    def __init__(self, filePath, authToken):
        self._filePath = filePath
        self._authToken = authToken
        self._header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X'
                        + '10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chr'
                        + 'ome/64.0.3282.140 Safari/537.36"'}
        self._proxy = {}

    def add_proxy(self, key, value):
        self._proxy[key] = value

    @property
    def authToken(self):
        return self._authToken

    @authToken.setter
    def authToken(self, authToken):
        self._authToken = authToken

    def optimizeImage(self):
        '''
            upload image to tiny server and download it to current folder,
            return upload success or fail.
        '''
        logging.debug(self._header['User-Agent'])
        urlStr = 'https://api.tinify.com/shrink'
        with open(self._filePath, 'rb') as f:
            logging.debug('open file name %s' % f.name)
            body = f.read()

        authDic = ('api', self._authToken)
        req = requests.request('POST', urlStr, data=body, headers=self._header,
                               auth=authDic, proxies=self._proxy)
        logging.debug('request for %s, the response code is %d'
                      % (self._filePath, req.status_code))

        if req.ok:
            self._optimzeUrl = req.headers['Location']
            jsonObject = json.loads(req.text)
            self._optimzeFileSize = jsonObject['input']['size']
            self._optimzeFileType = jsonObject['input']['type']
            return True
        else:
            logging.debug("update image fail, result %d" % req.status_code)
            raise NetworkError(req.reason)

    def downloadFile(self):
        '''
            download the optimzed image from server, return the downloaded file
            name
        '''
        authDic = ('api', self._authToken)
        req = requests.request('GET', self._optimzeUrl, headers=self._header,
                               auth=authDic, proxies=self._proxy)

        if req.ok:
            with open(self._filePath + '.opt', 'wb') as f:
                f.write(req.content)
                return f.name
        else:
            raise NetworkError('download image fail, result %d'
                               % req.status_code)


class TestImageOptimizer(unittest.TestCase):

    def test_success(self):
        self._origin_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_optimize_origin.png')
        if os.path.isfile(self._origin_file + '.opt'):
            os.remove(self._origin_file + '.opt')
        self._optimizer_success = ImageOptimizer(
            self._origin_file, 'd7q_GnylgjNEg6BtyWcsrHcsNQqP8eiU')
        self._optimizer_success.optimizeImage()
        opt_file = self._optimizer_success.downloadFile()
        self.assertTrue(self._origin_file + '.opt' == opt_file
                        and os.path.isfile(opt_file)
                        and os.path.getsize(self._origin_file)
                        > os.path.getsize(opt_file))

    def test_fail(self):
        self._origin_file = os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            'test_optimize_origin.png')
        if os.path.isfile(self._origin_file + '.opt'):
            os.remove(self._origin_file + '.opt')
        self._optimizer_fail = ImageOptimizer(self._origin_file, 'error_token')
        with self.assertRaises(NetworkError):
            self._optimizer_fail.optimizeImage()
