#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import re
import time
import json
import copy
import base64
import optparse
from urllib.parse import urlparse, parse_qsl, unquote
from xml.etree import ElementTree as ET
from core.fuzzer import Fuzzer
from utils.utils import errmsg, check_file, send_request, parse_conf, read_file, get_content_type, detect_waf, init_requests_pool, get_default_headers, get_jsonp_keys
from utils.constants import REQ_TIMEOUT, MARK_POINT, UA, PROBE, THREADS_NUM, PLATFORM
from utils.shared import Shared
from probe.probe import Dnslog, Ceye, Webdriver

if __name__ == '__main__':

    # 记录启动时间
    start_time = int(time.time())

    parser = optparse.OptionParser()
    parser.add_option("-f", dest="requests_file", help="Full requests dump, generated by browser crawler")
    parser.add_option("--output-dir", dest="output_dir", help="Custom output directory path")
    parser.add_option("--dnslog-provider", dest="dnslog_provider", default="dnslog", help="Dnslog service provider, default: dnslog (e.g. ceye)")
    options, _ = parser.parse_args()

    # 必需 -f 选项
    if not options.requests_file or not check_file(options.requests_file):
        parser.print_help()
        print('\n\n[*] option -f must be set and readable')
        exit(1)

    # 校验 dnslog 服务
    dnslog_provider = options.dnslog_provider.lower()
    if dnslog_provider not in ['dnslog', 'ceye']:
        print(errmsg('dnslog_is_invalid'))
        exit(1)

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 解析配置文件
    conf_dict = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if not conf_dict:
        print(errmsg('config_is_invalid'))
        exit(1)

    # 自动标记忽略的参数列表
    ignore_params = read_file(os.path.join(script_rel_dir, 'data', 'ignore_params.txt'))

    # dt 和 ssrf 探针自动标记检测的参数列表（包含匹配）
    dt_and_ssrf_detect_params = read_file(os.path.join(script_rel_dir, 'data', 'dt_and_ssrf_detect_params.txt'))
    
    # 网络代理
    proxy_conf = conf_dict['request_proxy']
    proxies = {'http': proxy_conf, 'https': proxy_conf} if proxy_conf else {}
    
    # 请求超时时间（秒）
    timeout_conf = conf_dict['request_timeout']
    timeout = float(timeout_conf) if timeout_conf else REQ_TIMEOUT

    # 获取探针配置
    if conf_dict['probe_customize']:
        Shared.probes = [probe.strip() for probe in conf_dict['probe_customize'].split(',')]
    elif conf_dict['probe_default']:
        Shared.probes = [probe.strip() for probe in conf_dict['probe_default'].split(',')]
    else:
        Shared.probes.append(PROBE)

    # 获取探针 payload
    payload_path = os.path.join(script_rel_dir, 'probe', 'payload')
    for probe in Shared.probes:
        payload_file = os.path.join(payload_path, '{}.txt'.format(probe))
        if check_file(payload_file):
            Shared.probes_payload[probe] = read_file(payload_file)

    # 初始化 dnslog 实例
    if any(p in 'xxe:fastjson:log4shell:ssrf' for p in Shared.probes):
        Shared.dnslog = Dnslog(proxies, timeout) if dnslog_provider == 'dnslog' else Ceye(proxies, timeout, conf_dict['ceye_id'], conf_dict['ceye_token'])
        
    # 获取配置线程数
    conf_threads_num = int(conf_dict['misc_threads_num']) if conf_dict['misc_threads_num'] and int(conf_dict['misc_threads_num']) > 0 else THREADS_NUM
    
    # 创建存储漏洞文件目录
    outputdir = options.output_dir if options.output_dir else os.path.join(script_rel_dir, 'output')
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)

    # 全局共享变量
    Shared.platform = conf_dict['misc_platform'].lower() if conf_dict['misc_platform'] else PLATFORM

    # 获取 requests 默认请求头
    default_headers = get_default_headers()

    # 初始请求对象
    init_request = {
        'url': None,
        'method': None,
        'params': {},
        'proxies': proxies,
        'cookies': {},
        'headers': default_headers,
        'data': {},
        'auth': {},
        'timeout': timeout
    }

    # 遍历检测 request
    num = 0
    # 存储域名是否部署 waf 的字典
    # key 为域名，value 为 True（有 waf）、False（无 waf）
    domain_has_waf = {}
    with open(options.requests_file, 'r', encoding='utf-8') as f:
        orig_requests = json.load(f)
        for orig_request in orig_requests:
            num += 1
            method = orig_request.get('Method')
            url = orig_request.get('URL')
            print('[+] Start scanning url: {} {}'.format(method, url))

            o = urlparse(unquote(url))
            hostname = o.hostname
            if domain_has_waf.get(hostname):
                print("[+] Has waf")
                continue

            # 初始化
            Shared.request_index = 0
            Shared.fuzz_results = []

            requests = []
            request = copy.deepcopy(init_request)
            
            # 动态 url 状态位
            is_dynamic_url = False
            # JSONP 标记位
            is_jsonp = False

            # 方法
            request['method'] = method
            
            # URL
            request['url'] = o._replace(fragment="")._replace(query="").geturl()

            # 查询字符串
            qs = parse_qsl(o.query)
            if qs:
                is_dynamic_url = True
                for par, val in qs:
                    # 初步判断是否是 JSONP
                    if request['method'] == 'GET' and not is_jsonp and re.search(r'(?i)callback|jsonp|success|complete|done|function|^cb$|^fn$', par):
                        is_jsonp = True
                    request['params'][par]=val

            # 请求头
            if orig_request.get('Header'):
                for name, value in orig_request.get('Header').items():
                    if name not in ['Cookie']:
                        request['headers'][name.lower()] = value

            # Cookie
            if orig_request.get('Header').get('Cookie'):
                for item in orig_request.get('Header').get('Cookie').split(';'):
                    name, value = item.split('=', 1)
                    request['cookies'][name] = value

            # Data
            content_type = None
            if request['method'] == 'POST' and orig_request.get('b64_body'):
                data = base64.b64decode(orig_request.get('b64_body')).decode('utf-8')
                content_type = request['headers']['content-type']

                if 'json' in content_type:
                    # json data
                    request['data'] = json.loads(data)
                elif 'xml' in content_type:
                    # xml data
                    request['data'] = data
                elif 'form' in content_type:
                    # form data
                    for item in data.split('&'):
                        name, value = item.split('=', 1)
                        request['data'][name.strip()] = unquote(value)
                else:
                    print(errmsg('data_is_invalid'))
                    continue

            # 指定 User-Agent
            custom_ua = conf_dict['request_user_agent']
            request['headers']['user-agent'] = custom_ua if custom_ua else UA

            # 初始化请求连接池
            scheme = o.scheme.lower()
            init_requests_pool(scheme)

            # 如果配置开启 Waf 检测，先判断测试目标前面是否部署了 Waf。
            # 如果部署了 Waf，则中断检测。
            if conf_dict['misc_enable_waf_detecter'].strip() == 'on' and domain_has_waf.get(hostname) is None:
                domain_has_waf[hostname] = False
                detect_request = copy.deepcopy(request)
                detect_payloads = [
                    '<img/src=1 onerror=alert(1)>',
                    '\' and \'a\'=\'a'
                ]

                for payload in detect_payloads:
                    detect_request['params']['ispayload'] = payload
                    what_waf = detect_waf(send_request(detect_request, True))
                    if what_waf:
                        print("[+] Found waf: {}, continue.".format(what_waf))
                        domain_has_waf[hostname] = True
                        break

                if domain_has_waf.get(hostname):
                    continue

            # 基准请求
            Shared.base_http = send_request(request, True)
            if Shared.base_http.get('status') != 200:
                print(errmsg('base_request_failed').format(Shared.base_http.get('status')))
                continue

            # 最终判断是否是 JSONP，如果是则检测是否包含敏感信息
            if is_jsonp and any(ct in Shared.base_http.get('headers').get('content-type') for ct in ['json', 'javascript']):
                sens_info_keywords = read_file(os.path.join(script_rel_dir, 'data', 'sens_info_keywords.txt'))
                
                # 空 referer 测试
                if not request.get('headers').get('referer'):
                    jsonp = Shared.base_http.get('response')
                else:
                    empty_referer_request = copy.deepcopy(request)
                    del empty_referer_request['headers']['referer']
                    empty_referer_response = send_request(empty_referer_request)
                    jsonp = empty_referer_response.get('response')
                
                # 语义分析，获取 jsonp 中所有的 Literal 和 Identifier key
                jsonp_keys = get_jsonp_keys(jsonp)
                if any(key in sens_info_keywords for key in jsonp_keys):
                    print("[+] Found JSONP information leakage!")
                    Shared.fuzz_results.append({
                        'request': request,
                        'payload': '',
                        'poc': '',
                        'type': 'JSONP'
                    })
                else:
                    print("[-] Not Found JSONP information leakage.")
            else:
                print("[-] Not Found JSONP.")

            # 构造全部 request 对象（每个标记点对应一个对象）
            mark_request = copy.deepcopy(request)
            mark_request['url_json_flag'] = False
            mark_request['dt_and_ssrf_detect_flag'] = False

            if is_dynamic_url:
                for par, val in request['params'].items():
                    if par in ignore_params:
                        continue
                    if get_content_type(val) == 'json':
                        # xxx.php?foo={"a":"b","c":"d"}&bar={"aa":"bb"}
                        val_dict = json.loads(val)
                        if type(val_dict) is dict:
                            mark_request['url_json_flag'] = True
                            base_val_dict = copy.deepcopy(val_dict)
                            for k, v in val_dict.items():
                                # 1、忽略白名单参数；2、忽略 json 里的 list 和 dict 数据结构
                                if k in ignore_params or (type(v) is list or type(v) is dict):
                                    continue

                                if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                                    mark_request['dt_and_ssrf_detect_flag'] = True

                                base_val_dict[k] = MARK_POINT
                                mark_request['params'][par] = json.dumps(base_val_dict)
                                requests.append(copy.deepcopy(mark_request))
                                base_val_dict[k] = v
                                mark_request['dt_and_ssrf_detect_flag'] = False
                            mark_request['url_json_flag'] = False
                    else:
                        if any(detect_param in par.lower() for detect_param in dt_and_ssrf_detect_params):
                            mark_request['dt_and_ssrf_detect_flag'] = True
                        
                        mark_request['params'][par] = MARK_POINT
                        requests.append(copy.deepcopy(mark_request))
                        mark_request['dt_and_ssrf_detect_flag'] = False
                    mark_request['params'][par] = request['params'][par]

            for item in ['data', 'cookies']:
                if not request[item]:
                    continue
                if item == 'data' and content_type == 'xml':
                    # xml data
                    xmlTree = ET.ElementTree(ET.fromstring(request['data']))

                    tagList = [elem.tag \
                        if re.search(r'<{}>[^<>]*</{}>'.format(elem.tag, elem.tag), request['data']) \
                        else None \
                        for elem in xmlTree.iter()]
                    # 移除重复元素 tag 和 None 值
                    # 【优化点】也会移除不同父节点下具有相同 tag 名称的子节点，可能漏掉一些检测点
                    tagList = list(set(list(filter(None, tagList))))
                    tagList.sort()

                    for elem_tag in tagList:
                        mark_request['data'] = re.sub(r'<{}>[^<>]*</{}>'.format(elem_tag, elem_tag), \
                            '<{}>{}</{}>'.format(elem_tag, MARK_POINT, elem_tag), request['data'])
                        requests.append(copy.deepcopy(mark_request))
                    mark_request['data'] = request['data']
                else:
                    for k, v in request[item].items():
                        condition = k not in ignore_params
                        if item == 'data' and content_type == 'json':
                            condition = condition and (type(v) is not list and type(v) is not dict)
                        if item == 'data' and content_type == 'form':
                            # form 数据类型只支持常规形式标记
                            # TODO 支持对 form 数据类型形如 foo={"id":100} 中 json 的标记
                            condition = condition and get_content_type(v) is None
                        if condition:
                            if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                                mark_request['dt_and_ssrf_detect_flag'] = True
                            mark_request[item][k] = MARK_POINT
                            requests.append(copy.deepcopy(mark_request))
                            mark_request[item][k] = v.replace(MARK_POINT, '')
                            mark_request['dt_and_ssrf_detect_flag'] = False
            
            # request 对象列表
            if not requests:
                print("[+] Not valid request object to fuzzing, Exit.")
                continue
            
            Shared.requests = requests

            # 获取实际线程数
            threads_num = len(Shared.requests) if len(Shared.requests) < conf_threads_num else conf_threads_num

            # 初始化 webdriver（headless Chrome）实例
            if 'xss' in Shared.probes:
                Shared.web_driver = Webdriver().driver

            # 开始检测
            Fuzzer(threads_num)

            # 关闭 webdriver
            if Shared.web_driver:
                Shared.web_driver.quit()

            # 记录漏洞
            if Shared.fuzz_results:
                outputfile = os.path.join(outputdir, 'vuls_{}.txt'.format(time.strftime("%Y%m%d%H%M%S")))
                with open(outputfile, 'w') as f:
                    for result in Shared.fuzz_results:
                        f.write(json.dumps(result))
                        f.write('\n')
                print('[+] Fuzz results saved in: {}'.format(outputfile))

            print('\n -------------------------------------------- \n')

            time.sleep(1)

    print("\n\n[+] Fuzz finished, {} urls scanned in {} seconds.".format(num, int(time.time()) - start_time))
