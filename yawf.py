#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import json
import copy
import optparse
import email
from io import StringIO
from urllib.parse import urlparse, parse_qsl
from xml.etree import ElementTree as ET
from core.fuzzer import Fuzzer
from utils.utils import errmsg, check_file, send_request, parse_conf, parse_payload
from utils.constants import *
from utils.shared import Shared
from probe.probe import Dnslog, Webdriver, DetectWaf

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
    parser.add_option("-m", dest="method", help="HTTP method, default: GET (e.g. POST)")
    parser.add_option("-d", dest="data", help="Data string to be sent through POST (e.g. \"id=1\")")
    parser.add_option("-c", dest="cookies", help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")
    parser.add_option("--headers", dest="headers", help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("-f", dest="requestfile", help="Load HTTP request from a file")
    options, _ = parser.parse_args()

    # -u 和 -r 选项二选一
    if not options.url and not options.requestfile:
        parser.print_help()
        print('\n\n[*] option -u or -f must be set')
        exit(1)

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 解析配置文件
    status = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if status is not None:
        print(errmsg('config_is_invalid').format(status))
        exit(1)

    # 自动标记忽略的参数列表
    ignore_params = [ip.strip() for ip in Shared.conf['misc_ignore_params'].split(',')]
    
    # 网络代理
    proxies = None
    proxy_conf = Shared.conf['request_proxy']
    if proxy_conf:
        if 'http://' in proxy_conf or 'https://' in proxy_conf:
            proxies = {'http': proxy_conf, 'https': proxy_conf}
    
    # 请求超时时间（秒）
    timeout = REQ_TIMEOUT
    timeout_conf = Shared.conf['request_timeout']
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
    # 动态 url 状态位
    is_dynamic_url = False
    if options.url:
        # 动态 url query string、data 和 cookie 处支持手动标记和自动标记
        # url
        request['url'] = options.url
        is_dynamic_url = bool(re.search(r"\?[^#]*=[^#]*", request['url']))
        if is_dynamic_url and MARK_POINT in request['url']:
            is_mark = True

        # data, method
        if (options.method and options.method.upper() == 'POST') or options.data:
            if not options.data:
                print(errmsg('data_is_empty'))
                exit(1)
            
            request['method'] = 'POST'
            if options.data.startswith('<?xml '):
                # xml data
                request['data'] = options.data
                if MARK_POINT in options.data:
                    is_mark = True
            else:
                # form data
                request['data'] = {}
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
        scheme_conf = Shared.conf['request_scheme']
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
        is_dynamic_url = bool(re.search(r"\?[^#]*=[^#]*", request['url']))
        if is_dynamic_url and MARK_POINT in request['url']:
            is_mark = True
        del headers['host']
        request['method'] = misc_list[0].upper()

        # data
        if request['method'] == 'POST':
            data_raw = contents.split('\n\n')[1]
            if data_raw.startswith('<?xml '):
                # xml data
                request['data'] = data_raw
                if MARK_POINT in data_raw:
                    is_mark = True
            else:
                # form data
                request['data'] = {}
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
    if not is_mark and not is_dynamic_url and not request['data'] and not request['cookies']:
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
        base_request['timeout'] = request['timeout']
        base_request['data'] = {}
        if request['data']:
            if type(request['data']) is str:
                base_request['data'] = request['data'] if MARK_POINT not in request['data'] else request['data'].replace(MARK_POINT, '')
            else:
                for k, v in request['data'].items():
                    base_request['data'][k] = v if MARK_POINT not in v else v.replace(MARK_POINT, '')
        base_request['cookies'] = {}
        if request['cookies']:
            for k, v in request['cookies'].items():
                base_request['cookies'][k] = v if MARK_POINT not in v else v.replace(MARK_POINT, '')

        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)
        if is_dynamic_url and MARK_POINT in request['url']:
            o = urlparse(request['url'])
            qs = parse_qsl(o.query)
            for par, val in qs:
                if MARK_POINT in val:
                    # xxx.php?foo=bar[fuzz] ---> xxx.php?foo=[fuzz]
                    mark_request['url'] = base_request['url'].replace(par + '=' + val.replace(MARK_POINT, ''), par + '=' + MARK_POINT)
                    requests.append(copy.deepcopy(mark_request))
            mark_request['url'] = base_request['url']
            
        if request['data']:
            if type(request['data']) is str:
                if MARK_POINT in request['data']:
                    temp_data = request['data']
                    while True:
                        if MARK_POINT not in temp_data:
                            break
                        m = re.search(r'>[0-9a-zA-Z_\-]*{}<'.format(MARK_POINT.replace('[', '\[')), temp_data)
                        first_match = m.group()
                        first_index = m.start()
                        mark_request['data'] = base_request['data'][:first_index+1] + MARK_POINT + base_request['data'][first_index+len(first_match)-len(MARK_POINT)-1:]
                        requests.append(copy.deepcopy(mark_request))
                        temp_data = temp_data[:first_index+len(first_match)-len(MARK_POINT)-1] + temp_data[first_index+len(first_match)-1:]
                    mark_request['data'] = base_request['data']
            else:
                for k, v in request['data'].items():
                    if MARK_POINT in v:
                        mark_request['data'][k] = MARK_POINT
                        requests.append(copy.deepcopy(mark_request))
                        mark_request['data'][k] = base_request['data'][k]
            
        if request['cookies']:
            for k, v in request['cookies'].items():
                if MARK_POINT in v:
                    mark_request['cookies'][k] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request['cookies'][k] = base_request['cookies'][k]
    else:
        # 自动标记
        base_request = request

        # 在 url query string、data 和 cookie 处自动标记
        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)

        # url query string
        if is_dynamic_url:
            o = urlparse(base_request['url'])
            qs = parse_qsl(o.query)
            for par, val in qs:
                if par in ignore_params:
                    continue
                mark_request['url'] = base_request['url'].replace(par + '=' + val, par + '=' + MARK_POINT)
                requests.append(copy.deepcopy(mark_request))
            mark_request['url'] = base_request['url']

        # data
        if base_request['data']:
            if type(base_request['data']) is str:
                # xml data
                tagList = []
                xmlTree = ET.ElementTree(ET.fromstring(base_request['data']))

                for elem in xmlTree.iter():
                    tag = elem.tag
                    if re.search(r'<{}>[0-9a-zA-Z_\-]*</{}>'.format(tag, tag), base_request['data']):
                        tagList.append(tag)

                # 移除重复元素 tag
                # 【优化点】也会移除不同父节点下具有相同 tag 名称的子节点，可能漏掉一些检测点
                tagList = list(set(tagList))

                for tag in tagList:
                    m = re.search(r'<{}>[0-9a-zA-Z_\-]*</{}>'.format(tag, tag), base_request['data'])
                    first_match = m.group()
                    first_index = m.start()
                    mark_request['data'] = base_request['data'][:first_index] + '<{}>{}</{}>'.format(tag, MARK_POINT, tag) + base_request['data'][first_index+len(first_match):]
                    requests.append(copy.deepcopy(mark_request))

                mark_request['data'] = base_request['data']
            else:
                # form data
                for k, v in base_request['data'].items():
                    if k in ignore_params:
                        continue
                    mark_request['data'][k] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request['data'][k] = v
            
        # cookie
        if base_request['cookies']:
            for k, v in base_request['cookies'].items():
                if k in ignore_params:
                    continue
                mark_request['cookies'][k] = MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                mark_request['cookies'][k] = v
    
    # request 对象列表
    Shared.requests = requests

    # 基准请求
    Shared.base_response = send_request(base_request)
    if Shared.base_response.get('status') != 200:
        print(errmsg('base_request_failed').format(Shared.base_response.get('status')))
        exit(1)

    """
    如果配置开启 Waf 检测，在真正开始检测漏洞前，先判断测试目标前面是否部署了 Waf。如果部署了 Waf，则中断检测。
    检测原理：在 url 中传递 xss 和 sqli payload，检测 response 对象是否包含 Waf 特征。
    参考：https://github.com/Ekultek/WhatWaf
    """
    if Shared.conf['misc_enable_waf_detecter'].strip() == 'on':
        dw = DetectWaf()
        detect_request = base_request.copy()
        detect_payloads = [
            '<img/src=1 onerror=alert(1)>',
            '\' and \'a\'=\'a'
        ]

        for payload in detect_payloads:
            detect_request['url'] += '&ispayload={}'.format(payload) if is_dynamic_url else '?ispayload={}'.format(payload)
                
            what_waf = dw.detect(send_request(detect_request))
            if what_waf:
                print("[+] Found Waf: {}, Exit.".format(what_waf))
                exit(0)

    # 获取探针配置
    if Shared.conf['probe_customize']:
        Shared.probes = [probe.strip() for probe in Shared.conf['probe_customize'].split(',')]
    elif Shared.conf['probe_default']:
        Shared.probes = [probe.strip() for probe in Shared.conf['probe_default'].split(',')]
    else:
        Shared.probes.append(PROBE)

    # 获取探针 payload
    payload_path = os.path.join(script_rel_dir, 'probe', 'payload')
    for probe in Shared.probes:
        Shared.probes_payload[probe] = parse_payload(os.path.join(payload_path, '{}.txt'.format(probe)))

    # 获取线程数
    if len(Shared.requests) == 1:
        threads_num = 1
    elif int(Shared.conf['misc_threads_num']) > 0:
        threads_num = int(Shared.conf['misc_threads_num'])
    else:
        threads_num = THREADS_NUM

    # 初始化 dnslog 实例
    if any(p in 'xxe:rce_fastjson:rce_log4j' for p in Shared.probes):
        Shared.dnslog = Dnslog()

    # 初始化 webdriver（headless Chrome）实例
    if any(p in 'xss' for p in Shared.probes):
        Shared.web_driver = Webdriver().driver

    # 开始检测
    Fuzzer(threads_num)

    # 关闭 webdriver
    if Shared.web_driver:
        Shared.web_driver.close()

    # 记录漏洞
    if Shared.fuzz_results:
        outputdir = os.path.join(script_rel_dir, 'output')
        if not os.path.exists(outputdir):
            os.makedirs(outputdir)
        outputfile = os.path.join(outputdir, 'vuls_{}.txt'.format(time.strftime("%Y%m%d%H%M%S")))
        with open(outputfile, 'w') as f:
            for result in Shared.fuzz_results:
                f.write(json.dumps(result))
                f.write('\n')

        print('[+] Fuzz results saved in: {}'.format(outputfile))