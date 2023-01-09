# -*- coding: utf-8 -*-

import os
import sys
import requests
from configparser import ConfigParser
from utils.constants import *
from utils.request_result import RequestResult
from difflib import SequenceMatcher
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
disable_warnings(InsecureRequestWarning)


def errmsg(token):
    """
    错误消息
    """
    msg = {
        'url_is_invalid': '[*] URL does not appear to be dynamic',
        'file_is_invalid': '[*] the specified HTTP request file does not exist or unable to read',
        'read_file_occur_wrong': '[*] something went wrong while trying to read the content of file \'{}\' (\'{}\')',
        'data_is_empty': '[*] HTTP post data is empty'
    }

    return msg.get(token, "[*] oops")

def check_file(filename):
    """
    检查文件是否存在和可读
    """

    valid = False

    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        valid = True

    return valid

def send_request(request):
    """
    发送 HTTP 请求
    """

    try:
        if request['method'] == 'GET':
            rsp = requests.get(request['url'], headers=request['headers'], cookies=request['cookies'], proxies=request['proxies'], timeout=request['timeout'], verify=False)
        if request['method'] == 'POST':
            rsp = requests.post(request['url'], data=request['data'], headers=request['headers'], cookies=request['cookies'], proxies=request['proxies'], timeout=request['timeout'], verify=False)

        response = rsp.text
        length = len(response)
        status = rsp.status_code

    except requests.exceptions.RequestException as e:
        response = length = status = None

    return RequestResult(request, response, length, status)

def parse_conf(section, option):
    """
    获取配置文件中的配置项
    """

    conf_path = os.path.join(os.path.dirname(sys.argv[0]), 'yawf.conf')

    value = None
    if check_file(conf_path):
        conf = ConfigParser()
        conf.read(conf_path, encoding='utf-8')

        try:
            value = conf.get(section, option)
        except Exception as e:
            pass

    return value

def parse_dict(file):
    """
    解析 payload 字典文件
    """

    payloads = []
    with open(file) as f:
        for payload in f:
            if not payload.startswith('#') and payload != '\n':
                payloads.append(payload.strip())
    
    return payloads

def similar(str1, str2):
    """
    比较字符串 str1 和 str2 的相似度
    """

    return SequenceMatcher(None, str1, str2).ratio()