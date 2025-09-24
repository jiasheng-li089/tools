#!/usr/bin/env python3
# coding:utf-8

"""
iterate all files in the directory and optimize the image(format png & jpg)
"""

__author__ = 'Jiasheng Lee'


import logging
import sys
import os
import getopt
import threadpool
import threading
import re
from collections import Iterator
from optimizeimage import NetworkError, ImageOptimizer
from imagemark import MarkCheckFactory, ImageFormatError

logging.basicConfig(level=logging.INFO, format='%(levelname)s\t\t%(asctime)s'
                    + '\t\tOptimzeMain\t%(message)s')

local_reader = threading.local()

_const_mark = b'mark&tiny'

class PathFilter(object):

    def __init__(self, regular_list):
        self._regularList = []
        self._validRegularList = []
        if regular_list:
            for x in regular_list:
                try:
                    self._regularList.append(re.compile(x))
                    self._validRegularList.append(x)
                except BaseException as e:
                    logging.error("invalid regular rule: %s --> %s" % (x, e))

    @property
    def valid_regular_list(self):
        return self._validRegularList

    def filter(self, file_name):
        if not self._regularList:
            return False
        for x in self._regularList:
            if x.match(file_name):
                return True
        return False


class TokenReader(Iterator):

    def __init__(self, token_list):
        self._iter = iter(token_list)

    def __next__(self):
        return next(self._iter)


def scan_all_file(start_directory):
    """
    scan all file in the directory
    :param start_directory: the directory
    :return:
    """
    verifier = PathFilter(_ignore_list)

    file_list = []
    file_list.extend([os.path.join(start_directory, x) for x in os.listdir(start_directory)
                      if os.path.isfile(os.path.join(start_directory, x))
                      and not verifier.filter(x)])
    [file_list.extend(scan_all_file(os.path.join(start_directory, x))) for x in os.listdir(start_directory)
     if os.path.isdir(os.path.join(start_directory, x))
     and not verifier.filter(x)]

    return file_list


def optimize_files(list):
    """
    optimze file in directory path
    :param directory: the directory
    :return: NoneType
    """

    local_reader.reader = TokenReader(_token_list)

    token = next(local_reader.reader)
    index = 0
    while index < len(list):
        try:
            origin_file = list[index]
            mark_sign = _const_mark

            checker = MarkCheckFactory.get_checker(origin_file, mark_sign)

            if not checker.has_mark():
                uploader = ImageOptimizer(origin_file, token)
                uploader.optimizeImage()
                opt_file = uploader.downloadFile()
                marker = MarkCheckFactory.get_marker(opt_file, mark_sign)
                if marker.mark():
                    os.remove(origin_file)
                    os.rename(opt_file, origin_file)
                else:
                    logging.error("mark file error: %s" % opt_file)
            index = index + 1
        except NetworkError as e:
            logging.debug("current token invalid %s" % e)
            token = next(local_reader.reader)
        except ImageFormatError as e:
            logging.debug("file type unknown: %s" % e)
            index = index + 1
        except StopIteration:
            logging.error("not any valid tokens")
            return None


def create_task_to_pool(pool, dir):
    """
    Traverse all directory to create task and add to thread pool
    :param pool: thread pool
    :param dir: start directory
    :return: NoneType
    """
    all_files = scan_all_file(dir)

    file_params = []
    step = int(len(all_files) / len(pool.workers))
    if step < 1:
        step = 1

    start = 0
    end = start + step

    try:
        while end <= len(all_files):
            file_params.append(all_files[start:end])
            start = end
            end = start + step
    except:
        pass

    if start < len(all_files) - 1:
        file_params.append(all_files[start:len(all_files)])

    logging.debug("create task and add to pool, in dir : %s" % dir)
    task = threadpool.makeRequests(optimize_files, file_params)
    [pool.putRequest(x) for x in task]


def read_config_file(file_name):
    try:
        with open(file_name, 'rt', encoding='UTF-8') as f:
            lines = f.readlines()
            return [x.strip() for x in lines if not x.strip().startswith("#")]
    except BaseException as e:
        logging.error("read %s error: %s" % (file_name, e))
        raise e


if __name__ == '__main__':

    _token_file = None
    _ignore_file = None
    _start_dir = None

    _token_list = []
    _ignore_list = []

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", ["token=", "ignore=",
                                                      "path="])
    except getopt.GetoptError as e:
        print("optimizemain.py --token=<tokenfile> [--path=<path>]" +
              " [--ignore=<ignorefile>]")
        sys.exit(1)

    for opt, arg in opts:
        if opt == '--token':
            _token_file = arg
        elif opt == '--ignore':
            _ignore_file = arg
        elif opt == '--path':
            _start_dir = arg

    try:
        _token_list = read_config_file(_token_file)
    except BaseException as e:
        sys.exit(1)

    try:
        _ignore_list = read_config_file(_ignore_file)
    except BaseException as e:
        logging.info("read ignore file error %s" % e)

    if not _token_list:
        logging.error("token config file is empty")
        sys.exit(1)

    if not _start_dir:
        _start_dir = os.getcwd()
    if not os.path.isdir(_start_dir):
        logging.error("path should be a valid directory")
        sys.exit(1)

    pool = threadpool.ThreadPool(os.cpu_count())

    create_task_to_pool(pool, _start_dir)

    pool.wait()

    logging.info('done')

    sys.exit(0)

