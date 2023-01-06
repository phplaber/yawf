# -*- coding: utf-8 -*-

import os
import re
import sys
import requests
from configparser import ConfigParser
from utils.constants import *
from utils.request_result import RequestResult
from utils.shared import Shared


def errmsg(token):
    """
    错误消息
    """
    msg = {
        'url_is_invalid': 'URL does not appear to be dynamic',
        'file_is_invalid': 'the specified HTTP request file does not exist or unable to read',
        'read_file_occur_wrong': 'something went wrong while trying to read the content of file \'{}\' (\'{}\')'
    }

    return msg.get(token, "")


def clear_param(param):
    """
    移除 param 中具体的参数值，
    如：xxx.php?x=3[fuzz] ---> xxx.php?x=[fuzz]
    """
    return re.sub(r'=[^&]+\[fuzz\]', '=[fuzz]', param)


def check_file(filename):
    """
    检查文件是否存在和可读
    """

    valid = True

    if filename is None or not os.path.isfile(filename):
        valid = False

    if valid:
        try:
            with open(filename, "rb") as f:
                pass
        except:
            valid = False

    return valid


def parse_request(content):
    """
    解析 Request 文本文件中包含的各种输入
    """

    request = re.sub(r"\A[^\w]+", "", content)
    lines = request.split('\n')

    scheme = None
    host = None
    port = None
    url = None
    method = None
    headers = {}
    cookies = {}
    data = None
    params = False
    for index in range(len(lines)):
        line = lines[index]
        newline = "\r\n" if line.endswith('\r') else '\n'
        line = filter(None, line.strip('\r'))

        # 主机
        host_match = re.search(r"\Ahost:\s+(.*)", line, re.I) if not host else None
        if host_match:
            value = host_match.group(1)
            if '://' in value:
                scheme, value = value.split('://')[:2]
            splitValue = value.split(":")
            host = splitValue[0]

            if len(splitValue) > 1:
                port = re.sub("[^0-9]", "", splitValue[1])

        # URL 和 方法
        url_method_match = re.search(
            r"\A(%s) (.+) HTTP/[\d.]+\Z" % "|".join(HTTP_METHOD.values()), line, re.I) if not method else None

        if len(line) == 0 and method and method != HTTP_METHOD['GET'] and data is None:
            data = ""
            params = True

        elif url_method_match:
            method = url_method_match.group(1)
            url = url_method_match.group(2)

        # 头部
        elif re.search(r"\A\S+:", line):
            k, v = line.split(":", 1)
            v = v.strip()

            if k.upper() == HTTP_HEADER['COOKIE'].upper():
                for cookie in v.split(";"):
                    for item in cookie.split("=", 1):
                        cookies[item[0]] = item[1]

            if k not in (HTTP_HEADER['COOKIE'], HTTP_HEADER['PROXY_CONNECTION'], HTTP_HEADER['CONNECTION']):
                headers[k] = v

        # 表单数据
        elif data is not None and params:
            data += "{}{}".format(line, newline)

    data = data.strip() if data else data

    if not port and scheme.lower() == "https":
        port = "443"
    elif not scheme and port == "443":
        scheme = "https"

    if not host:
        print("invalid format of a request file")
        exit(1)

    if not url.startswith("http"):
        url = "{}://{}:{}{}".format(scheme or "http", host, port or "80", url)

    return {
        'url': url,
        'method': method,
        'cookies': cookies,
        'headers': headers,
        'data': data
    }


def send_request(request):
    """
    发送 HTTP 请求
    """

    try:
        if request['method'] == 'GET':
            rsp = requests.get(request['url'], headers=request['headers'], cookies=request['cookies'], proxies=Shared.proxy)
        if request['method'] == 'POST':
            rsp = requests.post(request['url'], data=request['data'], headers=request['headers'], cookies=request['cookies'], proxies=Shared.proxy)

        response = rsp.text
        length = len(response)
        status = rsp.status_code

    except requests.exceptions.RequestException as e:
        raise SystemExit(e)

    return RequestResult(request, response, length, status)


def get_conf(section, option):
    """
    获取配置文件中的配置项
    """

    conf_path = os.path.dirname(os.path.realpath(sys.argv[0])) + os.sep + 'yawf.conf'

    value = None
    if check_file(conf_path):
        conf = ConfigParser()
        conf.read(conf_path)

        try:
            value = conf.get(section, option)
        except Exception as e:
            pass

    return value