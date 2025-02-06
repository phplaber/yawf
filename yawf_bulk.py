#!/usr/bin/env python3

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
from core.probe import Dnslog, Ceye, Browser
from utils.utils import check_file, send_request, parse_conf, read_file, get_content_type, get_default_headers, get_jsonp_keys, is_base64
from utils.constants import REQ_TIMEOUT, MARK_POINT, UA, PROBE, PLATFORM

if __name__ == '__main__':

    # 记录启动时间
    start_time = int(time.time())

    parser = optparse.OptionParser()
    parser.add_option("-f", dest="requests_file", help="Full requests dump, generated by browser crawler")
    parser.add_option("--output-dir", dest="output_dir", help="Custom output directory path")
    parser.add_option("--dnslog-provider", dest="dnslog_provider", default="ceye", help="Dnslog service provider, default: ceye (e.g. dnslog)")
    options, _ = parser.parse_args()

    # 必需 -f 选项
    if not options.requests_file or not check_file(options.requests_file):
        parser.error('option -f must be set and readable')

    # 校验 dnslog 服务
    dnslog_provider = options.dnslog_provider.lower()
    if dnslog_provider not in ['dnslog', 'ceye']:
        sys.exit('[*] Only support dnslog and ceye provider')

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 解析配置文件
    conf_dict = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if not conf_dict:
        sys.exit('[*] parse config file error')

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

    user_agent = conf_dict['request_user_agent'] if conf_dict['request_user_agent'] else UA

    # 获取探针
    probes = []
    if conf_dict['probe_customize']:
        probes = [probe.strip() for probe in conf_dict['probe_customize'].split(',')]
    elif conf_dict['probe_default']:
        probes = [probe.strip() for probe in conf_dict['probe_default'].split(',')]
    else:
        probes.append(PROBE)

    # 获取探针 payload
    probes_payload = {}
    payload_path = os.path.join(script_rel_dir, 'data', 'payload')
    for probe in probes:
        payload_file = os.path.join(payload_path, f'{probe}.txt')
        if check_file(payload_file):
            probes_payload[probe] = read_file(payload_file)
        elif probe not in ['jsonp']:
            print(f'[*] invalid probe: {probe}')

    # 初始化 dnslog 实例
    dnslog = None
    if any(p in 'xxe:fastjson:log4shell:ssrf' for p in probes):
        if dnslog_provider == 'ceye':
            if not conf_dict['ceye_id'] or not conf_dict['ceye_token']:
                sys.exit("[*] When using the ceye out-of-band service, you must configure the id and token")
            dnslog = Ceye(proxies, timeout, conf_dict['ceye_id'], conf_dict['ceye_token'])
        else:
            dnslog = Dnslog(proxies, timeout)
        
    # 设置 Chrome 参数
    browser = Browser(proxies, user_agent) if 'xss' in probes else None

    # 创建存储漏洞文件目录
    outputdir = options.output_dir if options.output_dir else os.path.join(script_rel_dir, 'output')
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)

    # 将测试目标平台存储在环境变量
    os.environ['platform'] = conf_dict['misc_platform'].lower() if conf_dict['misc_platform'] else PLATFORM

    # 获取 requests 默认请求头
    default_headers = get_default_headers()

    # 初始请求对象
    init_request = {
        'url': '',
        'method': '',
        'params': {},
        'proxies': proxies,
        'cookies': {},
        'headers': default_headers,
        'data': {},
        'auth': {},
        'timeout': timeout
    }

    # 遍历检测 request
    # 计数
    req_total = 0
    with open(options.requests_file, 'r', encoding='utf-8') as f:
        orig_requests = json.load(f)
        for orig_request in orig_requests:
            req_total += 1
            method = orig_request.get('method')
            url = orig_request.get('url')
            print(f'[+] Start scanning url: {method} {url}')

            request = copy.deepcopy(init_request)
            
            # 动态 url 状态位、JSONP 标记位
            is_dynamic_url, is_jsonp = (False,)*2

            # 方法
            request['method'] = method
            
            # URL
            o = urlparse(unquote(url))
            request['url'] = o._replace(fragment="")._replace(query="").geturl()

            # 查询字符串
            qs = parse_qsl(o.query)
            if qs:
                is_dynamic_url = True
                for par, val in qs:
                    # 初步判断是否是 JSONP
                    if not is_jsonp and request['method'] == 'GET' and re.search(r'(?i)callback|jsonp|success|complete|done|function|^cb$|^fn$', par):
                        is_jsonp = True
                    request['params'][par]=val

            # 请求头
            if orig_request.get('headers'):
                for name, value in orig_request.get('headers').items():
                    if name not in ['Cookie', 'User-Agent']:
                        request['headers'][name.lower()] = value

            # Cookie
            if orig_request.get('headers').get('Cookie'):
                for item in orig_request.get('headers').get('Cookie').split(';'):
                    name, value = item.split('=', 1)
                    request['cookies'][name.strip()] = unquote(value)

            # Data
            content_type = ''
            if request['method'] == 'POST' and orig_request.get('data'):
                data = base64.b64decode(orig_request.get('data')).decode('utf-8')
                full_content_type = request['headers']['content-type']

                if 'json' in full_content_type:
                    # json data
                    content_type = 'json'
                    request['data'] = json.loads(data)
                elif 'xml' in full_content_type:
                    # xml data
                    content_type = 'xml'
                    request['data'] = data
                elif 'form' in full_content_type:
                    # form data
                    content_type = 'form'
                    for item in data.split('&'):
                        name, value = item.split('=', 1)
                        request['data'][name.strip()] = unquote(value)
                else:
                    print('[*] post data is invalid, support form/json/xml data type')
                    continue

            # 指定 User-Agent
            request['headers']['user-agent'] = user_agent

            # 基准请求
            base_http = send_request(request, True)
            if base_http.get('status') != 200:
                print(f"[*] base request failed, status code is: {base_http.get('status')}")
                continue

            # 构造全部 request 对象（每个标记点对应一个对象）
            requests = []
            mark_request = copy.deepcopy(request)
            mark_request['fastjson_detect_flag'] = False
            mark_request['dt_and_ssrf_detect_flag'] = False

            if is_dynamic_url:
                for par, val in request['params'].items():
                    if par in ignore_params:
                        continue
                    if get_content_type(val) == 'json':
                        # xxx.php?foo={"a":"b","c":"d"}&bar={"aa":"bb"}
                        val_dict = json.loads(val)
                        mark_request['fastjson_detect_flag'] = True
                        base_val_dict = copy.deepcopy(val_dict)
                        for k, v in val_dict.items():
                            # 1、忽略白名单参数；2、忽略 json 里的非字符串数据结构；3、忽略 Base64 编码字符串
                            if type(v) is not str or k in ignore_params or is_base64(v):
                                continue

                            if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                                mark_request['dt_and_ssrf_detect_flag'] = True

                            base_val_dict[k] = v + MARK_POINT
                            mark_request['params'][par] = json.dumps(base_val_dict)
                            requests.append(copy.deepcopy(mark_request))
                            base_val_dict[k] = v
                            mark_request['dt_and_ssrf_detect_flag'] = False
                        mark_request['fastjson_detect_flag'] = False
                    else:
                        if not is_base64(val):
                            if any(detect_param in par.lower() for detect_param in dt_and_ssrf_detect_params):
                                mark_request['dt_and_ssrf_detect_flag'] = True
                            
                            mark_request['params'][par] = val + MARK_POINT
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
                        if re.search(fr'<{elem.tag}>[^<>]*</{elem.tag}>', request['data']) \
                        else None \
                        for elem in xmlTree.iter()]
                    # 移除重复元素 tag 和 None 值
                    tagList = list(set(list(filter(None, tagList))))
                    tagList.sort()

                    for elem_tag in tagList:
                        mark_request['data'] = re.sub(fr'<{elem_tag}>[^<>]*</{elem_tag}>', f'<{elem_tag}>{MARK_POINT}</{elem_tag}>', request['data'])
                        requests.append(copy.deepcopy(mark_request))
                    mark_request['data'] = request['data']
                else:
                    for k, v in request[item].items():
                        if type(v) is str and (k not in ignore_params) and (not is_base64(v)):
                            if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                                mark_request['dt_and_ssrf_detect_flag'] = True
                            mark_request[item][k] = v + MARK_POINT
                            requests.append(copy.deepcopy(mark_request))
                            mark_request[item][k] = v
                            mark_request['dt_and_ssrf_detect_flag'] = False
            
            # 支持检测 referer 处的 log4shell
            if 'log4shell' in probes:
                mark_request['headers']['referer'] = MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                mark_request['headers'] = request['headers']

            # request 对象列表
            if not requests:
                print("[+] Not valid request object to fuzzing, Exit.")
                continue

            # 开始检测
            fuzz_results = []
            # 内置 jsonp 探针检测
            if is_jsonp and any(ct in base_http.get('headers').get('content-type') for ct in ['json', 'javascript']):
                sens_info_keywords = read_file(os.path.join(script_rel_dir, 'data', 'sens_info_keywords.txt'))
                
                # 空 referer 测试
                if not request.get('headers').get('referer'):
                    jsonp = base_http.get('response')
                else:
                    empty_referer_request = copy.deepcopy(request)
                    del empty_referer_request['headers']['referer']
                    empty_referer_response = send_request(empty_referer_request)
                    jsonp = empty_referer_response.get('response')
                
                # 语义分析，获取 jsonp 中所有的 Literal 和 Identifier key
                jsonp_keys = get_jsonp_keys(jsonp)
                if any(key.lower() in sens_info_keywords for key in jsonp_keys):
                    print("[+] Found JSONP information leakage!")
                    fuzz_results.append({
                        'request': request,
                        'payload': '',
                        'poc': '',
                        'type': 'JSONP'
                    })
                else:
                    print("[-] Not Found JSONP information leakage.")
            else:
                print("[*] JSONP detection skipped")

            # 其它探针检测
            fuzz_results.extend(Fuzzer(requests, base_http, probes, probes_payload, dnslog, browser).run())

            # 记录漏洞
            if fuzz_results:
                outputfile = os.path.join(outputdir, f'vuls_{time.strftime("%Y%m%d%H%M%S")}.txt')
                with open(outputfile, 'w') as f:
                    for result in fuzz_results:
                        f.write(json.dumps(result)+'\n')
                print(f'[+] Fuzz results saved in: {outputfile}')

            print('\n -------------------------------------------- \n')

            time.sleep(1)

    print(f"\n\n[+] Fuzz finished, {req_total} urls scanned in {int(time.time()) - start_time} seconds.")
