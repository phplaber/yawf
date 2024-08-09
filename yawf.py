#!/usr/bin/env python3

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
from utils.utils import check_file, send_request, parse_conf, read_file, get_content_type, get_default_headers, get_jsonp_keys
from utils.constants import VERSION, REQ_TIMEOUT, REQ_SCHEME, MARK_POINT, UA, PROBE, PLATFORM
from core.probe import Dnslog, Ceye, Browser

banner = fr"""
_____.___.  _____  __      _____________
\__  |   | /  _  \/  \    /  \_   _____/
 /   |   |/  /_\  \   \/\/   /|    __)  
 \____   /    |    \        / |     \   
 / ______\____|__  /\__/\  /  \___  /   
 \/              \/      \/       \/    
                                        
Automated Web Vulnerability Fuzzer      
{VERSION}                               
Created by yns0ng (@phplaber)           
"""

if __name__ == '__main__':

    # 记录启动时间
    start_time = int(time.time())

    # 标准输出指向终端（非重定向和管道）
    if sys.stdout.isatty():
        print(banner)

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-m", dest="method", default="GET", help="HTTP method, default: GET (e.g. POST)")
    parser.add_option("-d", dest="data", help="Data string to be sent through POST (e.g. \"id=1\")")
    parser.add_option("-c", dest="cookies", help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")
    parser.add_option("--headers", dest="headers", help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("--auth-type", dest="auth_type", help="HTTP authentication type (Basic, Digest, NTLM)")
    parser.add_option("--auth-cred", dest="auth_cred", help="HTTP authentication credentials (user:pass)")
    parser.add_option("-f", dest="requestfile", help="Load HTTP request from a file")
    parser.add_option("--output-dir", dest="output_dir", help="Custom output directory path")
    parser.add_option("--probe-list", action="store_true", dest="probe_list", help="List of available probes")
    parser.add_option("--dnslog-provider", dest="dnslog_provider", default="ceye", help="Dnslog service provider, default: ceye (e.g. dnslog)")
    options, _ = parser.parse_args()

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 显示可用的探针列表
    if options.probe_list:
        files = next(os.walk(os.path.join(script_rel_dir, 'data', 'payload')), (None, None, []))[2]
        s = 'List of available probes: \n'
        for f in files:
            s += f' - {os.path.splitext(f)[0]}\n'
        # 内置 jsonp 探针
        s += ' - jsonp\n'
        print(s.rstrip())
        sys.exit()

    # -u 和 -f 选项二选一
    if not options.url and not options.requestfile:
        parser.error('option -u or -f must be set')

    # 校验 dnslog 服务
    dnslog_provider = options.dnslog_provider.lower()
    if dnslog_provider not in ['dnslog', 'ceye']:
        sys.exit('[*] Only support dnslog and ceye provider')

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

    # 获取 requests 默认请求头
    default_headers = get_default_headers()

    requests = []
    # 基础请求对象
    request = {
        'url': None,
        'method': 'GET',
        'params': {},
        'proxies': proxies,
        'cookies': {},
        'headers': default_headers,
        'data': {},
        'auth': {},
        'timeout': timeout
    }
    # 手动标记状态位、动态 url 状态位、JSONP 标记位
    is_mark, is_dynamic_url, is_jsonp = (False,)*3
    content_type, data, cookies = (None,)*3
    if options.url:
        # URL
        o = urlparse(unquote(options.url))
        scheme = o.scheme.lower()
        request['url'] = o._replace(fragment="")._replace(query="").geturl()
        request['method'] = options.method.upper()

        if options.data:
            request['method'] = 'POST'
            data = options.data

        if options.cookies:
            cookies = options.cookies

        if options.headers:
            for item in options.headers.split("\\n"):
                try:
                    name, value = item.split(":", 1)
                    request['headers'][name.strip().lower()] = value.strip()
                except ValueError:
                    pass
    else:
        # HTTP 请求文件
        if not check_file(options.requestfile):
            sys.exit('[*] the specified HTTP request file does not exist or unable to read')
        
        with open(options.requestfile, 'r', encoding='utf-8') as f:
            contents = f.read()
        misc, str_headers = contents.split('\n', 1)
        misc_list = misc.split(' ')
        message = email.message_from_file(StringIO(str_headers))
        host_and_cookie = {}
        for k, v in dict(message.items()).items():
            kl = k.lower()
            if kl not in ['host', 'cookie', 'authorization']:
                request['headers'][kl] = v
            else:
                host_and_cookie[kl] = v

        scheme_conf = conf_dict['request_scheme']
        scheme = scheme_conf.lower() if scheme_conf else REQ_SCHEME
        
        o = urlparse(unquote(misc_list[1]))
        request['url'] = f"{scheme}://{host_and_cookie['host']}{o._replace(fragment='')._replace(query='').geturl()}"
        request['method'] = misc_list[0].upper()
        if request['method'] == 'POST':
            data = contents.split('\n\n')[1]
        cookies = host_and_cookie.get('cookie')

    # 只支持检测 HTTP 服务
    if scheme not in ['http', 'https']:
        sys.exit('[*] Only support http(s) scheme')

    # 只支持 GET 和 POST 方法
    if request['method'] not in ['GET', 'POST']:
        sys.exit('[*] Only support GET and POST method')

    # POST 数据不能为空
    if request['method'] == 'POST' and data is None:
        sys.exit('[*] HTTP post data is empty')
    
    # 查询字符串
    qs = parse_qsl(o.query)
    if qs:
        is_dynamic_url = True
        for par, val in qs:
            # 初步判断是否是 JSONP
            if not is_jsonp and request['method'] == 'GET' and re.search(r'(?i)callback|jsonp|success|complete|done|function|^cb$|^fn$', par):
                is_jsonp = True
            request['params'][par]=val
            if not is_mark and MARK_POINT in val:
                is_mark = True

    # post data
    if data:
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
                name, value = item.split('=', 1)
                request['data'][name.strip()] = unquote(value)
                if not is_mark and MARK_POINT in value:
                    is_mark = True
        else:
            sys.exit('[*] post data is invalid, support form/json/xml data type')

    # cookies
    if cookies:
        for item in cookies.split(";"):
            name, value = item.split("=", 1)
            request['cookies'][name.strip()] = unquote(value)
            if not is_mark and MARK_POINT in value:
                is_mark = True

    # HTTP 认证
    if options.auth_type and options.auth_cred:
        if options.auth_type in ['Basic', 'Digest', 'NTLM'] and ':' in options.auth_cred:
            if options.auth_type == 'NTLM' and re.search(r'^(.*\\\\.*):(.*?)$', options.auth_cred) is None:
                sys.exit('[*] HTTP NTLM authentication credentials value must be in format "DOMAIN\\username:password"')
            request['auth']['auth_type'] = options.auth_type
            request['auth']['auth_cred'] = options.auth_cred

    # 指定 User-Agent
    user_agent = conf_dict['request_user_agent'] if conf_dict['request_user_agent'] else UA
    request['headers']['user-agent'] = user_agent
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

    # 将测试目标平台存储在环境变量
    os.environ['platform'] = conf_dict['misc_platform'].lower() if conf_dict['misc_platform'] else PLATFORM

    # 获取原始请求
    base_request = copy.deepcopy(request)
    if is_mark:
        # 获取原始请求对象（不包含标记点）
        base_str = json.dumps(base_request)
        base_str = base_str.replace(MARK_POINT, '')
        base_request = json.loads(base_str)

    # 基准请求
    base_http = send_request(base_request, True)
    if base_http.get('status') != 200:
        sys.exit(f"[*] base request failed, status code is: {base_http.get('status')}")

    # 构造全部 request 对象（每个标记点对应一个对象）
    mark_request = copy.deepcopy(base_request)
    mark_request['url_json_flag'] = False
    mark_request['dt_and_ssrf_detect_flag'] = False

    if is_dynamic_url:
        for par, val in request['params'].items():
            if (is_mark and MARK_POINT not in val) or (not is_mark and par in ignore_params):
                continue
            if get_content_type(val) == 'json':
                # xxx.php?foo={"a":"b","c":"d[fuzz]"}&bar={"aa":"bb"}
                val_dict = json.loads(val)
                if type(val_dict) is dict:
                    mark_request['url_json_flag'] = True
                    base_val_dict = json.loads(val.replace(MARK_POINT, '')) if is_mark else copy.deepcopy(val_dict)
                    for k, v in val_dict.items():
                        # 1、自动标记忽略白名单参数；2、忽略 json 里的非字符串数据结构
                        if type(v) is not str \
                            or (is_mark and MARK_POINT not in v) \
                            or (not is_mark and k in ignore_params):
                            continue

                        if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                            mark_request['dt_and_ssrf_detect_flag'] = True
                        
                        base_val_dict[k] = MARK_POINT
                        mark_request['params'][par] = json.dumps(base_val_dict)
                        requests.append(copy.deepcopy(mark_request))
                        base_val_dict[k] = v.replace(MARK_POINT, '')
                        # 重置 dt_and_ssrf_detect_flag
                        mark_request['dt_and_ssrf_detect_flag'] = False
                    # 重置 url_json_flag
                    mark_request['url_json_flag'] = False
            else:
                if any(detect_param in par.lower() for detect_param in dt_and_ssrf_detect_params):
                    mark_request['dt_and_ssrf_detect_flag'] = True
                
                mark_request['params'][par] = MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                # 重置 dt_and_ssrf_detect_flag
                mark_request['dt_and_ssrf_detect_flag'] = False
            # 重置查询参数
            mark_request['params'][par] = base_request['params'][par]

    for item in ['data', 'cookies']:
        if not base_request[item]:
            continue
        if item == 'data' and content_type == 'xml':
            if is_mark and MARK_POINT in request['data']:
                # 全部标记点的位置
                all_mark_point_index = [mp.start() \
                    for mp in re.finditer(MARK_POINT.replace('[', '\\['), request['data'])]
                cursor_idx = 0
                for idx in all_mark_point_index:
                    mark_xml = base_request['data'][:(idx-cursor_idx)] \
                        + MARK_POINT \
                        + base_request['data'][(idx-cursor_idx):]
                    # 删除原始元素值 ">foo[fuzz]<" ---> ">[fuzz]<"
                    # f-string 表达式不能包含反斜线，故此处使用 format 函数格式化字符串
                    mark_request['data'] = re.sub(r">[^<>]*{}<".format(MARK_POINT.replace('[', '\\[')), f'>{MARK_POINT}<', mark_xml)
                    requests.append(copy.deepcopy(mark_request))
                    cursor_idx += len(MARK_POINT)
                mark_request['data'] = base_request['data']
            elif not is_mark:
                # xml data
                xmlTree = ET.ElementTree(ET.fromstring(base_request['data']))

                tagList = [elem.tag \
                    if re.search(fr'<{elem.tag}>[^<>]*</{elem.tag}>', base_request['data']) \
                    else None \
                    for elem in xmlTree.iter()]
                # 移除重复元素 tag 和 None 值
                tagList = list(set(list(filter(None, tagList))))
                tagList.sort()

                for elem_tag in tagList:
                    mark_request['data'] = re.sub(fr'<{elem_tag}>[^<>]*</{elem_tag}>', f'<{elem_tag}>{MARK_POINT}</{elem_tag}>', base_request['data'])
                    requests.append(copy.deepcopy(mark_request))
                mark_request['data'] = base_request['data']
        else:
            for k, v in request[item].items():
                condition = type(v) is str
                if is_mark:
                    condition = condition and (MARK_POINT in v)
                else:
                    condition = condition and (k not in ignore_params)
                if condition:
                    if any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                        mark_request['dt_and_ssrf_detect_flag'] = True
                    mark_request[item][k] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request[item][k] = v.replace(MARK_POINT, '')
                    mark_request['dt_and_ssrf_detect_flag'] = False
    
    # 获取探针
    probes = []
    if conf_dict['probe_customize']:
        probes = [probe.strip() for probe in conf_dict['probe_customize'].split(',')]
    elif conf_dict['probe_default']:
        probes = [probe.strip() for probe in conf_dict['probe_default'].split(',')]
    else:
        probes.append(PROBE)

    # 支持检测 referer 处的 log4shell
    if 'log4shell' in probes:
        referer_request = copy.deepcopy(base_request)
        referer_request['url_json_flag'] = False
        referer_request['dt_and_ssrf_detect_flag'] = False

        referer_request['headers']['referer'] = MARK_POINT
        requests.append(referer_request)

    # request 对象列表
    if not requests:
        sys.exit("[*] Not valid request object to fuzzing, Exit.")

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

    """
    
    子进程使用 pickle 转储参数，因为 Chrome 实例（类selenium.webdriver.chrome.webdriver.WebDriver）包含本地对象 _createenviron.<locals>.encodekey，
    在 pickle.dump 时报错，所以只能在子进程中创建 Chrome 实例。

    在批量检测中，多个子进程频繁的打开和关闭 Chrome，势必带来系统资源和时间消耗。
    最好是能在子进程中复用 Chrome，但目前只能先这样了。
        
    """

    # 设置 Chrome 参数
    browser = Browser(proxies, user_agent) if 'xss' in probes else None

    # 开始检测
    fuzz_results = []
    # 内置 jsonp 探针检测
    if is_jsonp and any(ct in base_http.get('headers').get('content-type') for ct in ['json', 'javascript']):
        sens_info_keywords = read_file(os.path.join(script_rel_dir, 'data', 'sens_info_keywords.txt'))

        # 空 referer 测试
        if not base_request.get('headers').get('referer'):
            jsonp = base_http.get('response')
        else:
            empty_referer_request = copy.deepcopy(base_request)
            del empty_referer_request['headers']['referer']
            empty_referer_response = send_request(empty_referer_request)
            jsonp = empty_referer_response.get('response')
        
        # 语义分析，获取 jsonp 中所有的 Literal 和 Identifier key
        jsonp_keys = get_jsonp_keys(jsonp)
        if any(key.lower() in sens_info_keywords for key in jsonp_keys):
            print("[+] Found JSONP information leakage!")
            fuzz_results.extend({
                'request': base_request,
                'payload': '',
                'poc': '',
                'type': 'JSONP'
            })
        else:
            print("[-] Not Found JSONP information leakage.")
    else:
        print("[*] JSONP detection skipped")
    
    # 其它探针检测
    fuzz_results.extend(Fuzzer(requests, content_type, base_http, probes, probes_payload, dnslog, browser).run())

    # 记录漏洞
    if fuzz_results:
        outputdir = options.output_dir if options.output_dir else os.path.join(script_rel_dir, 'output')
        if not os.path.exists(outputdir):
            os.makedirs(outputdir)
        outputfile = os.path.join(outputdir, f'vuls_{time.strftime("%Y%m%d%H%M%S")}.txt')
        with open(outputfile, 'w') as f:
            for result in fuzz_results:
                f.write(json.dumps(result)+'\n')

        print(f'[+] Fuzz results saved in: {outputfile}')

    print(f"\n\n[+] Fuzz finished, {len(requests)} request(s) scanned in {int(time.time()) - start_time} seconds.")
