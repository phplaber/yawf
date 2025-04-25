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
from utils.utils import (
    check_file,
    send_request,
    parse_conf,
    read_file,
    get_content_type,
    get_default_headers,
    is_base64,
    Browser,
    OOBDetector
)
from utils.constants import VERSION, REQ_TIMEOUT, REQ_SCHEME, MARK_POINT, UA, PROBE, PLATFORM, EFFICIENCY_CONF

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
    parser.add_option("--oob-provider", dest="oob_provider", default="ceye", help="Out-of-Band service provider, default: ceye (e.g. dnslog)")
    options, _ = parser.parse_args()

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 全部探针
    files = next(os.walk(os.path.join(script_rel_dir, 'core', 'probes')), (None, None, []))[2]
    all_probes = [os.path.splitext(f)[0] for f in files if not f.startswith('__init__')]

    # 显示可用的探针列表
    if options.probe_list:
        print('List of available probes: \n' + '\n'.join(f' - {probe}' for probe in all_probes))
        sys.exit()

    # -u 和 -f 选项二选一
    if not options.url and not options.requestfile:
        parser.error('option -u or -f must be set')

    # 校验带外（Out-of-Band）服务
    oob_provider = options.oob_provider.lower()
    if oob_provider not in ['dnslog', 'ceye']:
        sys.exit('[*] Only support dnslog and ceye provider')

    # 自动标记忽略的参数集合
    ignore_params = EFFICIENCY_CONF.get('ignore_params')

    # 解析配置文件
    conf_dict = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if not conf_dict:
        sys.exit('[*] parse config file error')
    
    # 网络代理
    proxy_conf = conf_dict['request_proxy']
    proxies = {'http': proxy_conf, 'https': proxy_conf} if proxy_conf else {}
    
    # 请求超时时间（秒）
    timeout_conf = conf_dict['request_timeout']
    timeout = float(timeout_conf) if timeout_conf else REQ_TIMEOUT

    # 获取 requests 默认请求头
    default_headers = get_default_headers()

    # 基础请求对象
    request = {
        'url': '',
        'method': 'GET',
        'params': {},
        'proxies': proxies,
        'cookies': {},
        'headers': default_headers,
        'data': {},
        'auth': {},
        'timeout': timeout
    }
    # 手动标记状态位
    is_mark = False
    content_type, data, cookies = ('',)*3
    if options.url:
        # URL
        o = urlparse(unquote(options.url))
        scheme = o.scheme.lower()
        if not scheme:
            sys.exit('[*] The full target URL is required')
        request['url'] = o._replace(fragment="")._replace(query="").geturl()
        request['method'] = options.method.upper()

        if options.data:
            request['method'] = 'POST'
            data = options.data

        if options.cookies:
            cookies = options.cookies

        if options.headers:
            for item in options.headers.split("\\n"):
                name, value = item.split(":", 1)
                request['headers'][name.strip().lower()] = value.strip()
    else:
        # HTTP 请求文件
        if not check_file(options.requestfile):
            sys.exit('[*] the specified HTTP request file does not exist or unable to read')
        
        with open(options.requestfile, 'r', encoding='utf-8') as f:
            contents = f.read()
        misc, str_headers = contents.split('\n', 1)
        method, uri, _ = misc.split(' ', 2)
        message = email.message_from_file(StringIO(str_headers))
        for k, v in dict(message.items()).items():
            request['headers'][k.lower()] = v

        scheme_conf = conf_dict['request_scheme']
        scheme = scheme_conf.lower() if scheme_conf else REQ_SCHEME
        
        o = urlparse(unquote(uri))
        request['url'] = f"{scheme}://{request['headers']['host']}{o._replace(fragment='')._replace(query='').geturl()}"
        request['method'] = method.upper()
        if request['method'] == 'POST':
            data = contents.split('\n\n')[1]
        cookies = request['headers'].get('cookie', '')

    # 删除请求头中的 Host、Cookie 和 Authorization 字段
    for header in ['host', 'cookie', 'authorization']:
        request['headers'].pop(header, None)

    # 只支持检测 HTTP 服务
    if scheme not in ['http', 'https']:
        sys.exit('[*] Only support http(s) scheme')

    # 只支持 GET 和 POST 方法
    if request['method'] not in ['GET', 'POST']:
        sys.exit('[*] Only support GET and POST method')

    # POST 数据不能为空
    if request['method'] == 'POST' and not data:
        sys.exit('[*] HTTP post data is empty')
    
    # 查询字符串
    qs = parse_qsl(o.query)
    for par, val in qs:
        request['params'][par]=val

    # post data
    if data:
        content_type = get_content_type(data)

        if content_type == 'json':
            # json data
            request['data'] = json.loads(data)
        elif content_type == 'xml':
            # xml data
            request['data'] = data
        elif content_type == 'form':
            # form data
            for item in data.split('&'):
                name, value = item.split('=', 1)
                request['data'][name.strip()] = unquote(value)
        else:
            sys.exit('[*] post data is invalid, support form/json/xml data type')

    # cookies
    if cookies:
        for item in cookies.split(";"):
            name, value = item.split("=", 1)
            request['cookies'][name.strip()] = unquote(value)

    # HTTP 认证
    if options.auth_type and options.auth_cred:
        if options.auth_type in ['Basic', 'Digest', 'NTLM'] and ':' in options.auth_cred:
            if options.auth_type == 'NTLM' and not re.search(r'^(.*\\\\.*):(.*?)$', options.auth_cred):
                sys.exit('[*] HTTP NTLM authentication credentials value must be in format "DOMAIN\\username:password"')
            request['auth']['auth_type'] = options.auth_type
            request['auth']['auth_cred'] = options.auth_cred

    # 指定 User-Agent
    user_agent = conf_dict['request_user_agent'] if conf_dict['request_user_agent'] else UA
    request['headers']['user-agent'] = user_agent

    # 指定 Content-Type
    if request['method'] == 'POST':
        request['headers']['content-type'] = {
            'json': 'application/json; charset=utf-8',
            'xml': 'application/xml; charset=utf-8',
            'form': 'application/x-www-form-urlencoded; charset=utf-8'
        }.get(content_type, 'text/plain; charset=utf-8')

    # 将测试目标平台存储在环境变量
    os.environ['platform'] = conf_dict['misc_platform'].lower() if conf_dict['misc_platform'] else PLATFORM

    request_str = json.dumps(request)
    # 判断是否手动标记
    is_mark = MARK_POINT in request_str

    # 获取原始请求对象（不包含标记点）
    base_str = request_str.replace(MARK_POINT, '') if is_mark else request_str
    base_request = json.loads(base_str)

    # 基准请求
    base_http = send_request(base_request, True)
    if base_http.get('status') not in [200, 301, 302, 307, 308]:
        sys.exit(f"[*] base request failed, status code is: {base_http.get('status')}")

    # 构造全部 request 对象（每个标记点对应一个对象）
    requests = []
    mark_request = copy.deepcopy(base_request)

    """
    以下情况不处理：
    1. 值为 Base64 字符串
    2. 手动标记场景，值未被标记
    3. 自动标记场景，名称被忽略
    """

    # 处理查询字符串
    for par, val in request['params'].items():
        if is_base64(val) or (MARK_POINT not in val if is_mark else par in ignore_params):
            continue
        if get_content_type(val) == 'json':
            # xxx.php?foo={"a":"b","c":"d[fuzz]"}&bar={"aa":"bb"}
            val_dict = json.loads(val)
            base_val_dict = json.loads(val.replace(MARK_POINT, '')) if is_mark else copy.deepcopy(val_dict)
            for k, v in val_dict.items():
                # 非字符串标记后变为字符串，改变了数据类型，故暂不处理
                if type(v) is not str \
                    or is_base64(v) \
                    or (MARK_POINT not in v if is_mark else k in ignore_params):
                    continue

                base_val_dict[k] = v if MARK_POINT in v else (v + MARK_POINT)
                mark_request['params'][par] = json.dumps(base_val_dict)
                requests.append(copy.deepcopy(mark_request))
                base_val_dict[k] = v.replace(MARK_POINT, '')
        else:
            mark_request['params'][par] = val if MARK_POINT in val else (val + MARK_POINT)
            requests.append(copy.deepcopy(mark_request))
        # 重置查询参数
        mark_request['params'][par] = base_request['params'][par]

    # 处理 Cookie
    for name, value in request['cookies'].items():
        if is_base64(value) or (MARK_POINT not in value if is_mark else name in ignore_params):
            continue
        mark_request['cookies'][name] = value if MARK_POINT in value else (value + MARK_POINT)
        requests.append(copy.deepcopy(mark_request))
        mark_request['cookies'][name] = value.replace(MARK_POINT, '')

    # 处理 POST Body
    if content_type == 'xml':
        # 数据格式为 xml
        if is_mark and MARK_POINT in request['data']:
            escaped_mark = MARK_POINT.replace('[', '\\[')
            # 全部标记点的位置
            all_mark_point_index = [mp.start() \
                for mp in re.finditer(escaped_mark, request['data'])]
            cursor_idx = 0
            for idx in all_mark_point_index:
                mark_xml = base_request['data'][:(idx-cursor_idx)] \
                    + MARK_POINT \
                    + base_request['data'][(idx-cursor_idx):]
                # 删除原始元素值 ">foo[fuzz]<" ---> ">[fuzz]<"
                mark_request['data'] = re.sub(f">[^<>]*{escaped_mark}<", f'>{MARK_POINT}<', mark_xml)
                requests.append(copy.deepcopy(mark_request))
                cursor_idx += len(MARK_POINT)
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
        # 数据格式为 form 或 json
        for field, value in request['data'].items():
            # 非字符串标记后变为字符串，改变了数据类型，故暂不处理
            if type(value) is not str \
                or is_base64(value) \
                or (MARK_POINT not in value if is_mark else field in ignore_params):
                continue

            mark_request['data'][field] = value if MARK_POINT in value else (value + MARK_POINT)
            requests.append(copy.deepcopy(mark_request))
            mark_request['data'][field] = value.replace(MARK_POINT, '')

    # 处理请求头
    for name, value in request['headers'].items():
        # 目前只处理 Referer 和 User-Agent
        if name not in {'referer', 'user-agent'} or (is_mark and MARK_POINT not in value):
            continue
        mark_request['headers'][name] = value if MARK_POINT in value else (value + MARK_POINT)
        requests.append(copy.deepcopy(mark_request))
        mark_request['headers'][name] = value.replace(MARK_POINT, '')

    # 获取探针
    probes = []
    if conf_dict['probe_customize']:
        if 'all' in conf_dict['probe_customize']:
            probes = all_probes
        else:
            probes = [probe.strip() for probe in conf_dict['probe_customize'].split(',')]
    elif conf_dict['probe_default']:
        probes = [probe.strip() for probe in conf_dict['probe_default'].split(',')]
    else:
        probes.append(PROBE)

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

    # 初始化 OOB 检测器实例
    if oob_provider == 'ceye' and not (conf_dict['ceye_id'] and conf_dict['ceye_token']):
        print("[*] When using the ceye out-of-band service, you must configure the id and token. Now use dnslog as a backup.")
        oob_provider = 'dnslog'
    oob_detector = OOBDetector(oob_provider, proxies, timeout, conf_dict['ceye_id'], conf_dict['ceye_token'])

    # 设置 Chrome 参数
    browser = Browser(proxies, user_agent) if 'xss' in probes else None

    # 开始检测
    fuzz_results = []
    fuzz_results.extend(Fuzzer(requests, base_http, probes, probes_payload, oob_detector, browser).run())

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
