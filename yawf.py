#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
import copy
import optparse
import email
from io import StringIO
from urllib.parse import urlparse, parse_qsl
from core.fuzzer import Fuzzer
from utils.utils import *
from utils.constants import *
from utils.shared import Shared

banner = "\
_____.___.  _____  __      _____________\n\
\__  |   | /  _  \/  \    /  \_   _____/\n\
 /   |   |/  /_\  \   \/\/   /|    __)  \n\
 \____   /    |    \        / |     \   \n\
 / ______\____|__  /\__/\  /  \___  /   \n\
 \/              \/      \/       \/    \n\
                                        \n\
Automated Web Vulnerability Fuzzer      \n\
{version}                               \n\
Created by yns0ng (@phplaber)           \n\
\
".format(version=VERSION)

if __name__ == '__main__':

    print(banner)

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-m", dest="method", help="HTTP method (e.g. PUT)")
    parser.add_option("-d", dest="data", help="Data string to be sent through POST (e.g. \"id=1\")")
    parser.add_option("-c", dest="cookies", help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")
    parser.add_option("--headers", dest="headers", help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("-r", dest="requestfile", help="Load HTTP request from a file")
    options, _ = parser.parse_args()

    # -u 和 -r 选项二选一
    if not options.url and not options.requestfile:
        parser.print_help()
        exit(1)

    # 网络代理
    proxies = {}
    proxy_conf = parse_conf('request', 'proxy')
    if proxy_conf:
        if 'http://' in proxy_conf or 'https://' in proxy_conf:
            proxies['https'] = proxy_conf
            proxies['http'] = proxy_conf
    
    # 请求超时时间（秒）
    timeout = REQ_TIMEOUT
    timeout_conf = parse_conf('request', 'timeout')
    if timeout_conf:
        timeout = float(timeout_conf)

    requests = []
    request = {
        'url': None,
        'method': None,
        'proxies': proxies,
        'cookies': {},
        'headers': {},
        'data': {},
        'timeout': timeout,
    }
    # 手动标记状态位
    is_mark = False
    if options.url:
        # url、data 和 cookie 处支持手动标记和自动标记
        # url
        request['url'] = options.url
        if MARK_POINT in request['url']:
            is_mark = True

        # data, method
        if (options.method and options.method.upper() == 'POST') or options.data:
            if not options.data:
                print(errmsg('data_is_empty'))
                exit(1)
            
            request['method'] = 'POST'
            for item in options.data.split('&'):
                kv = item.split('=', 1)
                request['data'][kv[0]] = kv[1]
                if MARK_POINT in kv[1]:
                    is_mark = True
        else:
            request['method'] = 'GET'
        
        # cookie
        if options.cookies:
            for item in options.cookies.split(";"):
                kv = item.split("=", 1)
                request['cookies'][kv[0].strip()] = kv[1]
                if MARK_POINT in kv[1]:
                    is_mark = True

        # header
        if options.headers:
            for item in options.headers.split("\\n"):
                kv = item.split(":", 1)
                request['headers'][kv[0].strip().lower()] = kv[1].strip()
        # 使用特定 ua
        request['headers']['user-agent'] = UA
    else:
        if not check_file(options.requestfile):
            print(errmsg('file_is_invalid'))
            exit(1)
        
        scheme = REQ_SCHEME
        scheme_conf = parse_conf('request', 'scheme')
        if scheme_conf:
            scheme = scheme_conf
        
        with open(options.requestfile, "r") as f:
            contents = f.read()
        misc, headers = contents.split('\n', 1)
        misc_list = misc.split(' ')
        message = email.message_from_file(StringIO(headers))
        headers = {}
        for k, v in dict(message.items()).items():
            headers[k.lower()] = v
        
        request['url'] = scheme + '://' + headers['host'] + misc_list[1]
        if MARK_POINT in request['url']:
            is_mark = True
        del headers['host']
        request['method'] = misc_list[0].upper()

        # data
        if request['method'] == 'POST':
            data_raw = contents.split('\n\n')[1]
            for item in data_raw.split('&'):
                kv = item.split('=', 1)
                request['data'][kv[0]] = kv[1]
                if MARK_POINT in kv[1]:
                    is_mark = True

        # cookie
        if headers.get('cookie', False):
            for item in headers['cookie'].split(";"):
                kv = item.split("=", 1)
                request['cookies'][kv[0].strip()] = kv[1]
                if MARK_POINT in kv[1]:
                    is_mark = True
            
            del headers['cookie']
        
        # header
        request['headers'] = headers
        # 使用特定 ua
        request['headers']['user-agent'] = UA

    # 未手动标记且不具备自动标记的条件
    if not is_mark and not '=' in request['url'] and not request['data'] and not request['cookies']:
        print(errmsg('url_is_invalid'))
        exit(1)

    base_request = {}
    if is_mark:
        # 手动标记
        # 获取原始请求对象（不包含标记点）
        base_request['url'] = request['url'] if MARK_POINT not in request['url'] else request['url'].replace(MARK_POINT, '')
        base_request['method'] = request['method']
        base_request['proxies'] = request['proxies']
        base_request['headers'] = request['headers']
        base_request['data'] = {}
        if request['data']:
            for k, v in request['data'].items():
                base_request['data'][k] = v if MARK_POINT not in v else v.replace(MARK_POINT, '')
        base_request['cookies'] = {}
        if request['cookies']:
            for k, v in request['cookies'].items():
                base_request['cookies'][k] = v if MARK_POINT not in v else v.replace(MARK_POINT, '')

        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)
        if MARK_POINT in request['url']:
            point_position = [m.start() for m in re.finditer(MARK_POINT.replace('[', '\['), request['url'])]
            for idx in point_position:
                mark_request['url'] = base_request['url'][:idx] + MARK_POINT + base_request['url'][idx:]
                requests.append(copy.deepcopy(mark_request))
            mark_request['url'] = base_request['url']
            
        if request['data']:
            for k, v in request['data'].items():
                if MARK_POINT in v:
                    mark_request['data'][k] = v
                    requests.append(copy.deepcopy(mark_request))
                    mark_request['data'][k] = base_request['data'][k]
            
        if request['cookies']:
            for k, v in request['cookies'].items():
                if MARK_POINT in v:
                    mark_request['cookies'][k] = v
                    requests.append(copy.deepcopy(mark_request))
                    mark_request['cookies'][k] = base_request['cookies'][k]
    else:
        # 自动标记
        base_request = request

        # 在 url query string、form data 和 cookie 处自动标记
        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)

        # url query string
        if '=' in base_request['url']:
            o = urlparse(base_request['url'])
            qs = parse_qsl(o.query)
            # 提取无参数 url
            #url = o._replace(query=None).geturl()
            for par, val in qs:
                mark_request['url'] = base_request['url'].replace(par + '=' + val.replace(' ', '+'), par + '=' + val.replace(' ', '+') + MARK_POINT)
                requests.append(copy.deepcopy(mark_request))
            mark_request['url'] = base_request['url']

        # form data
        if base_request['data']:
            for k, v in base_request['data'].items():
                mark_request['data'][k] = v + MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                mark_request['data'][k] = v
            
        # cookie
        if base_request['cookies']:
            for k, v in base_request['cookies'].items():
                mark_request['cookies'][k] = v + MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                mark_request['cookies'][k] = v
        
    # request 对象列表
    Shared.requests = requests
    # 基准请求
    Shared.base_response = send_request(base_request)

    # 线程数
    threads_num = THREADS_NUM
    threads_num_conf = parse_conf('misc', 'threads_num')
    if len(Shared.requests) == 1:
        threads_num = 1
    elif threads_num_conf:
        threads_num = int(threads_num_conf)

    Fuzzer(threads_num)

