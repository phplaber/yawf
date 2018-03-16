# -*- coding: utf-8 -*-

import os
import re
import sys
import urllib
import urllib2
from ConfigParser import ConfigParser
from core.constants import *
from core.utils.request_result import RequestResult
from core.utils.shared import Shared


def errmsg_dict():
    """
    错误消息字典
    """
    return {
        'url_is_invalid': 'URL does not appear to be dynamic',
        'file_is_invalid': 'the specified HTTP request file does not exist or unable to read',
        'read_file_occur_wrong': 'something went wrong while trying to read the content of file \'%s\' (\'%s\')'
    }


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

    request = re.sub(r"\A[^\w]+", "", content)
    lines = request.split('\n')

    scheme = None
    host = None
    port = None
    url = None
    method = None
    headers = []
    cookie = None
    data = None
    params = False
    for index in xrange(len(lines)):
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
                cookie = v

            if k not in (HTTP_HEADER['COOKIE'], HTTP_HEADER['PROXY_CONNECTION'], HTTP_HEADER['CONNECTION']):
                headers.append((unicode(k, "utf-8"), unicode(v, "utf-8")))

        # 表单数据
        elif data is not None and params:
            data += "%s%s" % (line, newline)

    data = data.strip() if data else data

    if not port and isinstance(scheme, basestring) and scheme.lower() == "https":
        port = "443"
    elif not scheme and port == "443":
        scheme = "https"

    if not host:
        print "invalid format of a request file"
        sys.exit(1)

    if not url.startswith("http"):
        url = "%s://%s:%s%s" % (scheme or "http", host, port or "80", url)

    return {
        'url': url,
        'method': method,
        'cookie': cookie,
        'headers': tuple(headers),
        'data': data
    }


def send_request(request):
    try:
        proxy = urllib2.ProxyHandler(Shared.proxy)
        opener = urllib2.build_opener(proxy)
        opener.addheaders = []
        if 'headers' in request and request['headers'] is not None:
            for header in request['headers']:
                opener.addheaders.append(header)
        if 'cookie' in request and request['cookie'] is not None:
            opener.addheaders.append(('Cookie', request['cookie']))
        data = None
        if 'data' in request and 'method' in request and request['method'] != HTTP_METHOD['GET'] and request['data'] is not None:
            data = request['data']

        req = opener.open(
            request['url'],
            urllib.quote_plus(data) if data is not None else None
        )

        response = req.read()
        length = len(response)
        status = req.getcode()

    except urllib2.HTTPError, e:
        response = "Request failed: %d %s" % (e.code, e.msg)
        length = len(response)
        status = e.code

    return RequestResult(request, response, length, status)


def get_proxy(proxy_str):

    proxy = {}

    if 'http://' in proxy_str:
        proxy['http'] = proxy_str.split('http://')[1]
    else:
        proxy['https'] = proxy_str.split('https://')[1]

    return proxy


def get_conf(section, option):

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