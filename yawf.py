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
from utils.utils import errmsg, check_file, send_request, parse_conf, read_file, get_content_type, detect_waf, get_default_headers, get_jsonp_keys, chat_with_ai
from utils.constants import VERSION, REQ_TIMEOUT, REQ_SCHEME, MARK_POINT, UA, PROBE, PLATFORM
from core.probe import Dnslog, Ceye, Browser

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
    parser.add_option("--dnslog-provider", dest="dnslog_provider", default="dnslog", help="Dnslog service provider, default: dnslog (e.g. ceye)")
    options, _ = parser.parse_args()

    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 显示可用的探针列表
    if options.probe_list:
        files = next(os.walk(os.path.join(script_rel_dir, 'data', 'payload')), (None, None, []))[2]
        s = 'List of available probes: \n'
        for f in files:
            s += ' - {}\n'.format(os.path.splitext(f)[0])
        s += ' - jsonp\n'
        print(s.rstrip())
        exit(0)

    # -u 和 -f 选项二选一
    if not options.url and not options.requestfile:
        parser.print_help()
        print('\n\n[*] option -u or -f must be set')
        exit(1)

    # 校验 dnslog 服务
    dnslog_provider = options.dnslog_provider.lower()
    if dnslog_provider not in ['dnslog', 'ceye']:
        print(errmsg('dnslog_is_invalid'))
        exit(1)

    # 解析配置文件
    conf_dict = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if not conf_dict:
        print(errmsg('config_is_invalid'))
        exit(1)

    # Azure openai
    azure_openai_config = {
        'deployment_name': conf_dict.get('azure_deployment_name'),
        'api_base': conf_dict.get('azure_api_base'),
        'api_version': conf_dict.get('azure_api_version'),
        'api_key': conf_dict.get('azure_api_key')
    }

    # 自动标记忽略的参数列表
    ignore_params = []
    if conf_dict.get('azure_enabled') == 'on':
        # 使用 GPT 模型动态获取忽略参数
        prompt = """
            In the HTTP session, some authentication parameters (such as: sessionid, auth_key, PHPSESSID, etc.) will not cause vulnerabilities in most cases, and can be selected when using vulnerability scanning tools to detect Ignore them to balance efficiency and coverage of the security testing process. Please output 100 real parameter names in the following specific format(concatenate with commas), without a dot at the end, without any additional information.
            
            Respond with only valid strings conforming to the following schema:
            sessionid, auth_key, PHPSESSID
        """
        content = chat_with_ai(azure_openai_config, prompt)
        if content != '':
            ignore_params = content.split(', ')
    if not ignore_params:
        # 不使用 azure openai 或接口调用失败，使用默认的参数列表（使用 ChatGPT 获取）
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
    # 手动标记状态位
    is_mark = False
    # 动态 url 状态位
    is_dynamic_url = False
    # JSONP 标记位
    is_jsonp = False
    # POST Body 内容类型
    content_type = None
    
    data = None
    cookies = None
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
                name, value = item.split(":", 1)
                request['headers'][name.strip().lower()] = value.strip()
    else:
        # HTTP 请求文件
        if not check_file(options.requestfile):
            print(errmsg('file_is_invalid'))
            exit(1)
        
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
        request['url'] = scheme + '://' + host_and_cookie['host'] + o._replace(fragment="")._replace(query="").geturl()
        request['method'] = misc_list[0].upper()
        if request['method'] == 'POST':
            data = contents.split('\n\n')[1]
        cookies = host_and_cookie.get('cookie')

    # 只支持检测 HTTP 服务
    if scheme not in ['http', 'https']:
        print(errmsg('scheme_is_invalid'))
        exit(1)

    # 只支持 GET 和 POST 方法
    if request['method'] not in ['GET', 'POST']:
        print(errmsg('method_is_invalid'))
        exit(1)

    # POST 数据不能为空
    if request['method'] == 'POST' and data is None:
        print(errmsg('data_is_empty'))
        exit(1)
    
    # 查询字符串
    qs = parse_qsl(o.query)
    if qs:
        is_dynamic_url = True
        for par, val in qs:
            # 初步判断是否是 JSONP
            if request['method'] == 'GET' and not is_jsonp and re.search(r'(?i)callback|jsonp|success|complete|done|function|^cb$|^fn$', par):
                is_jsonp = True
            request['params'][par]=val
            if not is_mark and MARK_POINT in val:
                is_mark = True

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
                name, value = item.split('=', 1)
                request['data'][name.strip()] = unquote(value)
                if not is_mark and MARK_POINT in value:
                    is_mark = True
        else:
            print(errmsg('data_is_invalid'))
            exit(1)

    # cookies
    if cookies is not None:
        for item in cookies.split(";"):
            name, value = item.split("=", 1)
            request['cookies'][name.strip()] = unquote(value)
            if not is_mark and MARK_POINT in value:
                is_mark = True

    # HTTP 认证
    if options.auth_type and options.auth_cred:
        if options.auth_type in ['Basic', 'Digest', 'NTLM'] and ':' in options.auth_cred:
            if options.auth_type == 'NTLM' and re.search(r'^(.*\\\\.*):(.*?)$', options.auth_cred) is None:
                print(errmsg('cred_is_invalid'))
                exit(1)
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

    # 测试目标平台
    platform = conf_dict['misc_platform'].lower() if conf_dict['misc_platform'] else PLATFORM
    
    # 未手动标记且不具备自动标记的条件
    if not is_mark and not is_dynamic_url and not request['data'] and not request['cookies']:
        print(errmsg('url_is_invalid'))
        exit(1)

    # 获取原始请求
    base_request = copy.deepcopy(request)
    if is_mark:
        # 获取原始请求对象（不包含标记点）
        for item in ['params', 'data', 'cookies']:
            base_request[item] = {}
            if not request[item]:
                continue
            if type(request[item]) is not str:
                for k, v in request[item].items():
                    base_request[item][k] = v.replace(MARK_POINT, '') if type(v) is str and MARK_POINT in v else v
            else:
                base_request[item] = request[item].replace(MARK_POINT, '') if MARK_POINT in request[item] else request[item]

    # 如果配置开启 Waf 检测，先判断测试目标前面是否部署了 Waf。
    # 如果部署了 Waf，则中断检测。
    if conf_dict['misc_enable_waf_detecter'].strip() == 'on':
        detect_request = copy.deepcopy(base_request)
        detect_payloads = [
            '<img/src=1 onerror=alert(1)>',
            '\' and \'a\'=\'a'
        ]

        for payload in detect_payloads:
            detect_request['params']['ispayload'] = payload
            what_waf = detect_waf(send_request(detect_request, True))
            if what_waf:
                print("[+] Found Waf: {}, Exit.".format(what_waf))
                exit(0)

    # 基准请求
    base_http = send_request(base_request, True)
    if base_http.get('status') != 200:
        print(errmsg('base_request_failed').format(base_http.get('status')))
        exit(1)

    fuzz_results = []
    # 最终判断是否是 JSONP，如果是则检测是否包含敏感信息
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
        if any(key in sens_info_keywords for key in jsonp_keys):
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

    # 构造全部 request 对象（每个标记点对应一个对象）
    mark_request = copy.deepcopy(base_request)
    mark_request['url_json_flag'] = False
    mark_request['dt_and_ssrf_detect_flag'] = True if is_mark else False

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
                        # 1、自动标记忽略白名单参数；2、忽略 json 里的 list 和 dict 数据结构
                        if (is_mark and not (type(v) is str and MARK_POINT in v)) \
                            or (not is_mark and (k in ignore_params or (type(v) is list or type(v) is dict))):
                            continue

                        if not is_mark and any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                            mark_request['dt_and_ssrf_detect_flag'] = True
                        
                        base_val_dict[k] = MARK_POINT
                        mark_request['params'][par] = json.dumps(base_val_dict)
                        requests.append(copy.deepcopy(mark_request))
                        base_val_dict[k] = str(v).replace(MARK_POINT, '')
                        if not is_mark:
                            mark_request['dt_and_ssrf_detect_flag'] = False
                    mark_request['url_json_flag'] = False
            else:
                if not is_mark and any(detect_param in par.lower() for detect_param in dt_and_ssrf_detect_params):
                    mark_request['dt_and_ssrf_detect_flag'] = True
                
                mark_request['params'][par] = MARK_POINT
                requests.append(copy.deepcopy(mark_request))
                if not is_mark:
                    mark_request['dt_and_ssrf_detect_flag'] = False
            mark_request['params'][par] = base_request['params'][par]

    for item in ['data', 'cookies']:
        if not base_request[item]:
            continue
        if item == 'data' and content_type == 'xml':
            if is_mark and MARK_POINT in request['data']:
                # 全部标记点的位置
                all_mark_point_index = [mp.start() \
                    for mp in re.finditer(MARK_POINT.replace('[', '\['), request['data'])]
                cursor_idx = 0
                for idx in all_mark_point_index:
                    mark_xml = base_request['data'][:(idx-cursor_idx)] \
                        + MARK_POINT \
                        + base_request['data'][(idx-cursor_idx):]
                    # 删除原始元素值 ">foo[fuzz]<" ---> ">[fuzz]<"
                    mark_request['data'] = re.sub(r'>[^<>]*{}<'.format(MARK_POINT.replace('[', '\[')), \
                        '>{}<'.format(MARK_POINT), mark_xml)
                    requests.append(copy.deepcopy(mark_request))
                    cursor_idx += len(MARK_POINT)
                mark_request['data'] = base_request['data']
            elif not is_mark:
                # xml data
                xmlTree = ET.ElementTree(ET.fromstring(base_request['data']))

                tagList = [elem.tag \
                    if re.search(r'<{}>[^<>]*</{}>'.format(elem.tag, elem.tag), base_request['data']) \
                    else None \
                    for elem in xmlTree.iter()]
                # 移除重复元素 tag 和 None 值
                # 【优化点】也会移除不同父节点下具有相同 tag 名称的子节点，可能漏掉一些检测点
                tagList = list(set(list(filter(None, tagList))))
                tagList.sort()

                for elem_tag in tagList:
                    mark_request['data'] = re.sub(r'<{}>[^<>]*</{}>'.format(elem_tag, elem_tag), \
                        '<{}>{}</{}>'.format(elem_tag, MARK_POINT, elem_tag), base_request['data'])
                    requests.append(copy.deepcopy(mark_request))
                mark_request['data'] = base_request['data']
        else:
            for k, v in request[item].items():
                if is_mark:
                    condition = type(v) is str and MARK_POINT in v
                else:
                    condition = k not in ignore_params
                    if item == 'data' and content_type == 'json':
                        condition = condition and (type(v) is not list and type(v) is not dict)
                if item == 'data' and content_type == 'form':
                    # form 数据类型只支持常规形式标记
                    # TODO 支持对 form 数据类型形如 foo={"id":100} 中 json 的标记
                    condition = condition and get_content_type(v) is None
                if condition:
                    if not is_mark and any(detect_param in k.lower() for detect_param in dt_and_ssrf_detect_params):
                        mark_request['dt_and_ssrf_detect_flag'] = True
                    mark_request[item][k] = MARK_POINT
                    requests.append(copy.deepcopy(mark_request))
                    mark_request[item][k] = str(v).replace(MARK_POINT, '')
                    if not is_mark:
                        mark_request['dt_and_ssrf_detect_flag'] = False
    
    # request 对象列表
    if not requests:
        print("[+] Not valid request object to fuzzing, Exit.")
        exit(0)
    
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
        payload_file = os.path.join(payload_path, '{}.txt'.format(probe))
        if check_file(payload_file):
            probes_payload[probe] = read_file(payload_file)

    # 初始化 dnslog 实例
    dnslog = None
    if any(p in 'xxe:fastjson:log4shell:ssrf' for p in probes):
        dnslog = Dnslog(proxies, timeout) if dnslog_provider == 'dnslog' else Ceye(proxies, timeout, conf_dict['ceye_id'], conf_dict['ceye_token'])

    """
    
    子进程使用 pickle 转储参数，因为 Chrome 实例（类selenium.webdriver.chrome.webdriver.WebDriver）包含本地对象 _createenviron.<locals>.encodekey，在 pickle.dump 时报错，所以只能在子进程中创建 Chrome 实例。

    在批量检测中，多个子进程频繁的打开和关闭 Chrome，势必带来系统资源和时间消耗。最好是能在子进程中复用 Chrome，但目前只能先这样了。
        
    """

    # 设置 Chrome 参数
    browser = Browser(proxies, user_agent) if 'xss' in probes else None

    # 开始检测
    fuzz_results.extend(Fuzzer(requests, content_type, platform, base_http, probes, probes_payload, dnslog, browser).run())

    # 记录漏洞
    if fuzz_results:
        outputdir = options.output_dir if options.output_dir else os.path.join(script_rel_dir, 'output')
        if not os.path.exists(outputdir):
            os.makedirs(outputdir)
        current_timestamp = time.strftime("%Y%m%d%H%M%S")
        outputfile = os.path.join(outputdir, 'vuls_{}.txt'.format(current_timestamp))
        fuzz_results_str = ''
        with open(outputfile, 'w') as f:
            for result in fuzz_results:
                result_str = json.dumps(result)
                f.write(result_str)
                f.write('\n')

                fuzz_results_str += result_str + '\n'

        # 使用 GPT 模型生成可读性更高的报告
        if conf_dict.get('azure_enabled') == 'on':
            outputfile = os.path.join(outputdir, 'vuls_{}.html'.format(current_timestamp))

            prompt = '"""{}"""\nInside the triple quotes is the scan result of the vulnerability scanner in JSON format. Make full use of this scan result to generate a detailed Chinese report in AWVS style, including: complete URL, parameters that generate the vulnerability, PoC payload, vulnerability introduction and repair suggestions, etc. And display it in HTML format. Give the content of the report directly, without any additional information.'.format(fuzz_results_str)
            content = chat_with_ai(azure_openai_config, prompt)

            with open(outputfile, 'w') as f:
                f.write(content)

        print('[+] Fuzz results saved in: {}'.format(outputfile))

    print("\n\n[+] Fuzz finished, {} request(s) scanned in {} seconds.".format(len(requests), int(time.time()) - start_time))
