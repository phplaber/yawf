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
from urllib.parse import urlparse, parse_qsl, unquote
from xml.etree import ElementTree as ET
from core.fuzzer import Fuzzer
from utils.utils import errmsg, check_file, send_request, parse_conf, parse_payload, get_content_type
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

    # dt 探针自动标记检测的参数列表（包含匹配）
    dt_detect_params = [dp.strip() for dp in Shared.conf['probe_dt_detect_params'].split(',')]
    
    # 网络代理
    proxy_conf = Shared.conf['request_proxy']
    proxies = {'http': proxy_conf, 'https': proxy_conf} if proxy_conf else {}
    
    # 请求超时时间（秒）
    timeout_conf = Shared.conf['request_timeout']
    timeout = float(timeout_conf) if timeout_conf else REQ_TIMEOUT

    requests = []
    # 基础请求对象
    request = {
        'url': None,
        'method': 'GET',
        'params': {},
        'proxies': proxies,
        'cookies': {},
        'headers': {},
        'data': {},
        'timeout': timeout
    }
    # 手动标记状态位
    is_mark = False
    # 动态 url 状态位
    is_dynamic_url = False
    # POST Body 内容类型
    content_type = None
    
    o = None
    data = None
    cookies = None
    if options.url:
        # URL
        o = urlparse(unquote(options.url))
        request['url'] = o._replace(fragment="")._replace(query="").geturl()

        if options.method:
            request['method'] = options.method.upper()

        if options.data:
            request['method'] = 'POST'
            data = options.data

        if options.cookies:
            cookies = options.cookies

        if options.headers:
            for item in options.headers.split("\\n"):
                kv = item.split(":", 1)
                if len(kv) < 2:
                    continue
                request['headers'][kv[0].strip().lower()] = kv[1].strip()
    else:
        # HTTP 请求文件
        if not check_file(options.requestfile):
            print(errmsg('file_is_invalid'))
            exit(1)
        
        scheme_conf = Shared.conf['request_scheme']
        scheme = scheme_conf if scheme_conf else REQ_SCHEME
        
        with open(options.requestfile, "r") as f:
            contents = f.read()
        misc, str_headers = contents.split('\n', 1)
        misc_list = misc.split(' ')
        message = email.message_from_file(StringIO(str_headers))
        headers = {}
        for k, v in dict(message.items()).items():
            headers[k.lower()] = v

        o = urlparse(unquote(misc_list[1]))
        request['url'] = scheme + '://' + headers['host'] + o._replace(fragment="")._replace(query="").geturl()
        del headers['host']

        request['method'] = misc_list[0].upper()
        data = contents.split('\n\n')[1]
        cookies = headers.get('cookie')
        if cookies is not None:
            del headers['cookie']

        request['headers'] = headers

    # 查询字符串
    qs = parse_qsl(o.query)
    if qs:
        is_dynamic_url = True
        for par, val in qs:
            request['params'][par]=val
            if not is_mark and MARK_POINT in val:
                is_mark = True

    if request['method'] not in ['GET', 'POST']:
        print(errmsg('method_is_invalid'))
        exit(1)

    if request['method'] == 'POST' and data is None:
        print(errmsg('data_is_empty'))
        exit(1)

    # post data
    if data is not None:
        content_type = get_content_type(data)

        if content_type == 'json':
            # json data
            request['data'] = json.loads(data)
            for k, v in request['data'].items():
                if not is_mark and type(v) is str and MARK_POINT in v:
                    is_mark = True
        elif content_type == 'xml':
            # xml data
            request['data'] = data
            if not is_mark and MARK_POINT in data:
                is_mark = True
        elif content_type == 'form':
            # form data
            for item in data.split('&'):
                kv = item.split('=', 1)
                if len(kv) < 2:
                    continue
                request['data'][kv[0].strip()] = kv[1]
                if not is_mark and MARK_POINT in kv[1]:
                    is_mark = True
        else:
            print(errmsg('data_is_invalid'))
            exit(1)

    # cookies
    if cookies is not None:
        for item in cookies.split(";"):
            kv = item.split("=", 1)
            if len(kv) < 2:
                continue
            request['cookies'][kv[0].strip()] = kv[1]
            if not is_mark and MARK_POINT in kv[1]:
                is_mark = True

    # 使用特定 ua
    request['headers']['user-agent'] = UA
    # 指定 Content-Type
    if request['method'] == 'POST':
        if content_type == 'json':
            request['headers']['content-type'] = 'application/json; charset=utf-8'
        elif content_type == 'xml':
            request['headers']['content-type'] = 'application/xml; charset=utf-8'
        elif content_type == 'form':
            request['headers']['content-type'] = 'application/x-www-form-urlencoded; charset=utf-8'
        else:
            request['headers']['content-type'] = 'text/plain; charset=utf-8'

    # 共享 content_type 变量
    Shared.content_type = content_type
    
    # 未手动标记且不具备自动标记的条件
    if not is_mark and not is_dynamic_url and not request['data'] and not request['cookies']:
        print(errmsg('url_is_invalid'))
        exit(1)

    base_request = {}
    if is_mark:
        # 手动标记
        # 获取原始请求对象（不包含标记点）
        base_request['url'] = request['url']
        base_request['method'] = request['method']
        base_request['proxies'] = request['proxies']
        base_request['headers'] = request['headers']
        base_request['timeout'] = request['timeout']
        for item in ['params', 'data', 'cookies']:
            base_request[item] = {}
            if not request[item]:
                continue
            if type(request[item]) is not str:
                for k, v in request[item].items():
                    if type(v) is str and MARK_POINT in v:
                        base_request[item][k] = v.replace(MARK_POINT, '')
                    else:
                        base_request[item][k] = v
            else:
                base_request[item] = request[item] if MARK_POINT not in request[item] else request[item].replace(MARK_POINT, '')

        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)
        mark_request['url_json_flag'] = False
        mark_request['dt_detect_flag'] = True

        if is_dynamic_url:
            for par, val in request['params'].items():
                if MARK_POINT not in val:
                    continue
                if get_content_type(val) == 'json':
                    # xxx.php?foo={"a":"b[fuzz]","c":"d[fuzz]"}&bar={"aa":"bb"}
                    mark_request['url_json_flag'] = True
                    val_dict = json.loads(val)
                    base_val_dict = json.loads(val.replace(MARK_POINT, ''))
                    for k, v in val_dict.items():
                        # 忽略 json 里的 list 和 dict 等数据结构
                        if type(v) is str and MARK_POINT in v:
                            base_val_dict[k] = MARK_POINT
                            mark_request['params'][par] = json.dumps(base_val_dict)
                            requests.append(copy.deepcopy(mark_request))
                            base_val_dict[k] = v.replace(MARK_POINT, '')
                    mark_request['url_json_flag'] = False
                else:
                    mark_request['params'][par] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                mark_request['params'][par] = base_request['params'][par]
            
        for item in ['data', 'cookies']:
            if not request[item]:
                continue
            if item == 'data' and content_type == 'xml':
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
                for k, v in request[item].items():
                    condition = type(v) is str and MARK_POINT in v
                    if item == 'data' and content_type == 'form':
                        # form 数据类型只支持常规形式标记
                        # TODO 支持对 form 数据类型形如 foo={"id":100} 中 json 的标记
                        condition = condition and get_content_type(v) is None
                    if condition:
                        mark_request[item][k] = MARK_POINT
                        requests.append(copy.deepcopy(mark_request))
                        mark_request[item][k] = v.replace(MARK_POINT, '')
    else:
        # 自动标记
        base_request = request

        # 在查询字符串、data 和 cookie 处自动标记
        # 构造全部 request 对象（每个标记点对应一个对象）
        mark_request = copy.deepcopy(base_request)
        mark_request['url_json_flag'] = False
        mark_request['dt_detect_flag'] = False

        if is_dynamic_url:
            for par, val in base_request['params'].items():
                if par in ignore_params:
                    continue
                if get_content_type(val) == 'json':
                    # xxx.php?foo={"a":"b","c":"d"}&bar={"aa":"bb"}
                    mark_request['url_json_flag'] = True
                    val_dict = json.loads(val)
                    base_val_dict = copy.deepcopy(val_dict)
                    for k, v in val_dict.items():
                        # 1、忽略白名单参数；2、忽略 json 里的 list 和 dict 数据结构
                        if k in ignore_params or (type(v) is list or type(v) is dict):
                            continue
                        for detect_param in dt_detect_params:
                            if detect_param in k:
                                mark_request['dt_detect_flag'] = True
                                break
                        base_val_dict[k] = MARK_POINT
                        mark_request['params'][par] = json.dumps(base_val_dict)
                        requests.append(copy.deepcopy(mark_request))
                        base_val_dict[k] = v
                        mark_request['dt_detect_flag'] = False
                    mark_request['url_json_flag'] = False
                else:
                    for detect_param in dt_detect_params:
                        if detect_param in par:
                            mark_request['dt_detect_flag'] = True
                            break
                    mark_request['params'][par] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request['dt_detect_flag'] = False
                mark_request['params'][par] = base_request['params'][par]

        for item in ['data', 'cookies']:
            if not base_request[item]:
                continue
            if item == 'data' and content_type == 'xml':
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
                for k, v in base_request[item].items():
                    skip_condition = k in ignore_params
                    if item == 'data':
                        if content_type == 'json':
                            skip_condition = skip_condition or (type(v) is list or type(v) is dict)
                        elif content_type == 'form':
                            # TODO 支持对 form 数据类型形如 foo={"id":100} 中 json 的标记
                            skip_condition = skip_condition or get_content_type(v) is not None
                
                    if skip_condition:
                        continue
                    for detect_param in dt_detect_params:
                        if detect_param in k:
                            mark_request['dt_detect_flag'] = True
                            break
                    mark_request[item][k] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request[item][k] = v
                    mark_request['dt_detect_flag'] = False
    
    # request 对象列表
    if not requests:
        print("[+] Not valid request object to fuzzing, Exit.")
        exit(0)
    
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
        detect_request = copy.deepcopy(base_request)
        detect_payloads = [
            '<img/src=1 onerror=alert(1)>',
            '\' and \'a\'=\'a'
        ]

        for payload in detect_payloads:
            detect_request['params']['ispayload'] = payload
            what_waf = dw.detect(send_request(detect_request, True))
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
    if len(Shared.requests) <= THREADS_NUM:
        threads_num = len(Shared.requests)
    elif Shared.conf['misc_threads_num'] and int(Shared.conf['misc_threads_num']) > 0:
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