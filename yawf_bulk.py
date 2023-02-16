#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import json
import copy
import optparse
from urllib.parse import urlparse, parse_qsl, unquote
from core.fuzzer import Fuzzer
from utils.utils import errmsg, check_file, send_request, parse_conf, parse_payload, get_content_type
from utils.constants import REQ_TIMEOUT, MARK_POINT, UA, PROBE, THREADS_NUM
from utils.shared import Shared
from probe.probe import Dnslog, Webdriver

if __name__ == '__main__':

    # 记录启动时间
    start_time = int(time.time())

    parser = optparse.OptionParser()
    parser.add_option("-l", dest="urls", help="List of target urls")
    parser.add_option("-c", dest="cookies", help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")
    parser.add_option("--headers", dest="headers", help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("--auth-type", dest="auth_type", help="HTTP authentication type (Basic, Digest, NTLM)")
    parser.add_option("--auth-cred", dest="auth_cred", help="HTTP authentication credentials (user:pass)")
    parser.add_option("--output-dir", dest="output_dir", help="Custom output directory path")
    options, _ = parser.parse_args()

    # 必需 -l 选项
    if not options.urls or not check_file(options.urls):
        parser.print_help()
        print('\n\n[*] option -l must be set and readable')
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

    # dt 和 ssrf 探针自动标记检测的参数列表（包含匹配）
    dt_and_ssrf_detect_params = [dp.strip() for dp in Shared.conf['probe_dt_and_ssrf_detect_flag'].split(',')]
    
    # 网络代理
    proxy_conf = Shared.conf['request_proxy']
    proxies = {'http': proxy_conf, 'https': proxy_conf} if proxy_conf else {}
    
    # 请求超时时间（秒）
    timeout_conf = Shared.conf['request_timeout']
    timeout = float(timeout_conf) if timeout_conf else REQ_TIMEOUT

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

    # 初始化 webdriver（headless Chrome）实例
    if any(p in 'xss' for p in Shared.probes):
        Shared.web_driver = Webdriver().driver

    num = 0
    with open(options.urls, 'r', encoding='utf-8') as f:
        for url in f:
            num += 1
            url = url.rstrip()
            print('[+] Start scanning url: {}'.format(url))

            # 初始化
            Shared.request_index = 0
            Shared.fuzz_results = []

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
                'auth': {},
                'timeout': timeout
            }
            # 动态 url 状态位
            is_dynamic_url = False
            # POST Body 内容类型
            content_type = None
            
            # URL
            o = urlparse(unquote(url))
            request['url'] = o._replace(fragment="")._replace(query="").geturl()

            # 查询字符串
            qs = parse_qsl(o.query)
            if qs:
                is_dynamic_url = True
                for par, val in qs:
                    request['params'][par]=val

            # cookies
            if options.cookies:
                for item in options.cookies.split(";"):
                    kv = item.split("=", 1)
                    if len(kv) < 2:
                        continue
                    request['cookies'][kv[0].strip()] = kv[1]

            # 请求头
            if options.headers:
                for item in options.headers.split("\\n"):
                    kv = item.split(":", 1)
                    if len(kv) < 2:
                        continue
                    request['headers'][kv[0].strip().lower()] = kv[1].strip()

            # HTTP 认证
            if options.auth_type and options.auth_cred:
                if options.auth_type in ['Basic', 'Digest', 'NTLM'] and ':' in options.auth_cred:
                    if options.auth_type == 'NTLM' and re.search(r'^(.*\\\\.*):(.*?)$', options.auth_cred) is None:
                        print(errmsg('cred_is_invalid'))
                        continue
                    request['auth']['auth_type'] = options.auth_type
                    request['auth']['auth_cred'] = options.auth_cred
                    # 删除认证请求头 Authorization
                    if 'authorization' in request['headers']:
                        del request['headers']['authorization']

            # 指定 User-Agent
            custom_ua = Shared.conf['request_user_agent']
            request['headers']['user-agent'] = custom_ua if custom_ua else UA

            # 共享 content_type 变量
            Shared.content_type = content_type

            base_request = request

            # 在查询字符串处自动标记
            # 构造全部 request 对象（每个标记点对应一个对象）
            mark_request = copy.deepcopy(base_request)
            mark_request['url_json_flag'] = False
            mark_request['dt_and_ssrf_detect_flag'] = False

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
                            for detect_param in dt_and_ssrf_detect_params:
                                if detect_param in k.lower():
                                    mark_request['dt_and_ssrf_detect_flag'] = True
                                    break
                            base_val_dict[k] = MARK_POINT
                            mark_request['params'][par] = json.dumps(base_val_dict)
                            requests.append(copy.deepcopy(mark_request))
                            base_val_dict[k] = v
                            mark_request['dt_and_ssrf_detect_flag'] = False
                        mark_request['url_json_flag'] = False
                    else:
                        for detect_param in dt_and_ssrf_detect_params:
                            if detect_param in par.lower():
                                mark_request['dt_and_ssrf_detect_flag'] = True
                                break
                        mark_request['params'][par] = MARK_POINT
                        requests.append(copy.deepcopy(mark_request))
                        mark_request['dt_and_ssrf_detect_flag'] = False
                    mark_request['params'][par] = base_request['params'][par]
            
            # request 对象列表
            if not requests:
                print("[+] Not valid request object to fuzzing, Exit.")
                continue
            
            Shared.requests = requests

            # 基准请求
            Shared.base_response = send_request(base_request, True)
            if Shared.base_response.get('status') != 200:
                print(errmsg('base_request_failed').format(Shared.base_response.get('status')))
                continue

            # 初始化 dnslog 实例
            if any(p in 'xxe:fastjson:log4shell:ssrf' for p in Shared.probes):
                Shared.dnslog = Dnslog()

            # 获取线程数
            if len(Shared.requests) <= THREADS_NUM:
                threads_num = len(Shared.requests)
            elif Shared.conf['misc_threads_num'] and int(Shared.conf['misc_threads_num']) > 0:
                threads_num = int(Shared.conf['misc_threads_num'])
            else:
                threads_num = THREADS_NUM

            # 开始检测
            Fuzzer(threads_num)

            # 记录漏洞
            if Shared.fuzz_results:
                outputdir = options.output_dir if options.output_dir else os.path.join(script_rel_dir, 'output')
                if not os.path.exists(outputdir):
                    os.makedirs(outputdir)
                outputfile = os.path.join(outputdir, 'vuls_{}.txt'.format(time.strftime("%Y%m%d%H%M%S")))
                with open(outputfile, 'w') as f:
                    for result in Shared.fuzz_results:
                        f.write(json.dumps(result))
                        f.write('\n')
                print('[+] Fuzz results saved in: {}'.format(outputfile))

            print('\n -------------------------------------------- \n')

            time.sleep(0.2)

    # 关闭 webdriver
    if Shared.web_driver:
        Shared.web_driver.quit()

    print("\n\n[+] Fuzz finished, {} urls scanned in {} seconds.".format(num, int(time.time()) - start_time))
