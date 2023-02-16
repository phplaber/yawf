# -*- coding: utf-8 -*-

import os
import random
import requests
import json
import re
from configparser import ConfigParser
from utils.constants import *
from utils.shared import Shared
from difflib import SequenceMatcher
from xml.etree import ElementTree as ET
from requests.auth import HTTPDigestAuth
from requests_ntlm2 import HttpNtlmAuth

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
        'data_is_invalid': '[*] post data is invalid, support form/json/xml data type',
        'method_is_invalid': '[*] Only support GET and POST method',
        'cred_is_invalid': '[*] HTTP NTLM authentication credentials value must be in format "DOMAIN\\username:password"',
        'scheme_is_invalid': '[*] Only support http(s) scheme',
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

def send_request(request, require_response_header=False):
    """
    发送 HTTP 请求
    """

    response = headers = status = None
    
    json_data = None
    data_data = None
    auth = None
    if request['method'] == 'POST':
        if 'json' in request['headers']['content-type']:
            json_data = request['data']
        else:
            data_data = request['data']
    if request['auth']:
        cred = request['auth']['auth_cred'].split(':', 1)
        if request['auth']['auth_type'] == 'Basic':
            auth = (cred[0], cred[1])
        elif request['auth']['auth_type'] == 'Digest':
            auth = HTTPDigestAuth(cred[0], cred[1])
        elif request['auth']['auth_type'] == 'NTLM':
            auth = HttpNtlmAuth(cred[0], cred[1])
    try:    
        rsp = requests.request(request['method'], request['url'], 
            params=request['params'],
            headers=request['headers'], 
            cookies=request['cookies'], 
            proxies=request['proxies'], 
            data=data_data,
            json=json_data, 
            auth=auth,
            timeout=request['timeout'], 
            verify=False)

        response = rsp.text
        headers = rsp.headers if require_response_header else None
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
                if re.search(r"^[A-Za-z0-9_]+=[^=]+", content):
                    type = 'form'

    return type

def is_base64(string):
    """
    【废弃】校验字符串是否为 Base64 编码
    不可能真正校验字符串是否为 Base64 编码，只能判断字符串是否符合 Base64 数据格式
    """

    is_b64 = False

    if re.search("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$", string):
        is_b64 = True

    return is_b64

def detect_waf(req_rsp):
    """
    检测目标对象前是否部署 WAF，以及是哪种 WAF
    检测原理：在 url 中传递 xss 和 sqli payload，检测 response 对象是否包含 Waf 特征。
    参考：https://github.com/Ekultek/WhatWaf
    """
    response = req_rsp.get('response')
    headers = req_rsp.get('headers')
    status = req_rsp.get('status')

    # 请求失败，直接返回
    if status is None:
        return 

    # 阿里云盾
    if status == 405:
        # 阻断
        detection_schema = (
            re.compile(r"error(s)?.aliyun(dun)?.(com|net)", re.I),
            re.compile(r"http(s)?://(www.)?aliyun.(com|net)", re.I)
        )
        for detection in detection_schema:
            if detection.search(response):
                return 'AliYunDun'
        
    elif status == 200:
        # 非阻断，如滑块验证
        detection = re.compile(r"TraceID: [0-9a-z]{30}", re.I)
        if detection.search(response):
            return 'AliYunDun'

    # 云加速
    detection_schema = (
        re.compile(r"fh(l)?", re.I),
        re.compile(r"yunjiasu.nginx", re.I)
    )
    for detection in detection_schema:
        if detection.search(headers.get('x-server', '')) or detection.search(headers.get('server', '')):
            return 'Yunjiasu'

    # 安全狗
    detection_schema = (
        re.compile(r"(http(s)?)?(://)?(www|404|bbs|\w+)?.safedog.\w", re.I),
        re.compile(r"waf(.?\d+.?\d+)", re.I),
    )
    for detection in detection_schema:
        if detection.search(response) or detection.search(headers.get('x-powered-by', '')):
            return 'SafeDog'

    # 加速乐
    detection_schema = (
        re.compile(r"^jsl(_)?tracking", re.I),
        re.compile(r"(__)?jsluid(=)?", re.I),
        re.compile(r"notice.jiasule", re.I),
        re.compile(r"(static|www|dynamic).jiasule.(com|net)", re.I)
    )
    for detection in detection_schema:
        set_cookie = headers.get('set-cookie', '')
        server = headers.get('server', '')
        if any(detection.search(item) for item in [set_cookie, server]) or detection.search(response):
            return 'Jiasule'
            
    # CloudFlare
    detection_schemas = (
        re.compile(r"cloudflare.ray.id.|var.cloudflare.", re.I),
        re.compile(r"cloudflare.nginx", re.I),
        re.compile(r"..cfduid=([a-z0-9]{43})?", re.I),
        re.compile(r"cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?", re.I),
        re.compile(r".>attention.required!.\|.cloudflare<.+", re.I),
        re.compile(r"http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?", re.I),
        re.compile(r"ray.id", re.I)
    )
    server = headers.get('server', '')
    cookie = headers.get('cookie', '')
    set_cookie = headers.get('set-cookie', '')
    cf_ray = headers.get('cf-ray', '')
    expect_ct = headers.get('expect-ct', '')
    if cf_ray or "__cfduid" in set_cookie or "cloudflare" in expect_ct:
        return 'CloudFlare'
    for detection in detection_schemas:
        if detection.search(response) \
                or detection.search(server) \
                or detection.search(cookie) \
                or detection.search(set_cookie) \
                or detection.search(expect_ct):
            return 'CloudFlare'
        
    return 

