# -*- coding: utf-8 -*-

import os
import random
import requests
import json
import base64
from configparser import ConfigParser
from utils.constants import *
from utils.shared import Shared
from difflib import SequenceMatcher
from xml.etree import ElementTree as ET

# 忽略 SSL 告警信息
try:
    from requests.packages import urllib3
    urllib3.disable_warnings()
except Exception:
    pass


def errmsg(token):
    """
    错误消息
    """
    msg = {
        'url_is_invalid': '[*] URL does not appear to be dynamic',
        'file_is_invalid': '[*] the specified HTTP request file does not exist or unable to read',
        'data_is_empty': '[*] HTTP post data is empty',
        'config_is_invalid': '[*] parse config file error: {}',
        'base_request_failed': '[*] base request failed, status code is: {}',
        'data_is_invalid': '[*] post data is invalid, maybe need escaping'
    }

    return msg.get(token, '')

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

    response = headers = status = None
    try:
        if request['method'] == 'GET':
            rsp = requests.get(request['url'], headers=request['headers'], cookies=request['cookies'], proxies=request['proxies'], timeout=request['timeout'], verify=False)
        if request['method'] == 'POST':
            rsp = requests.post(request['url'], data=request['data'], headers=request['headers'], cookies=request['cookies'], proxies=request['proxies'], timeout=request['timeout'], verify=False)

        response = rsp.text
        headers = rsp.headers
        status = rsp.status_code

    except requests.exceptions.RequestException as e:
        print('[*] WARN : request error : {}'.format(str(e)))

    return {
        'request': request,
        'response': response,
        'headers': headers,
        'status': status
    }

def parse_conf(file):
    """
    解析配置文件，将配置数据存储在内存中
    通过 Shared.conf[section_option] 获取配置项的值
    """

    status = None

    if check_file(file):
        try:
            conf = ConfigParser()
            conf.read(file, encoding='utf-8')
            for section in conf.sections():
                for option in conf.options(section):
                    Shared.conf['{}_{}'.format(section, option)] = conf.get(section, option)
        except Exception as e:
            status = str(e)
    else:
        status = 'file not exist or unable to read'

    return status

def parse_payload(file):
    """
    解析 payload 文件
    """

    payloads = []

    if check_file(file):
        with open(file) as f:
            payloads = [payload.strip() for payload in f if not payload.startswith('#') and payload != '\n']
    
    return payloads

def similar(str1, str2):
    """
    比较字符串 str1 和 str2 的相似度
    """

    return SequenceMatcher(None, str1, str2).quick_ratio()

def get_random_str(length):
    """
    生成指定长度的随机字符串
    """

    return ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(length))

def get_content_type(content):
    """
    获取字符串内容类型，支持 x-www-form-urlencoded、json 和 xml 三种类型
    """

    type = None
    
    if not content.replace('.','',1).isdigit():
        try:
            json.loads(content)
            type = 'json'
        except ValueError:
            try:
                ET.fromstring(content)
                type = 'xml'
            except ET.ParseError:
                type = 'form'
    else:
        type = 'form'

    return type

def is_base64(string):
    """
    校验字符串是否为 Base64 编码
    """

    is_b64 = False

    try:
        is_b64 = (base64.b64encode(base64.b64decode(string)) == string)
    except Exception:
        is_b64 = False

    return is_b64