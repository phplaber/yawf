#!/usr/bin/env python3

import re
import os
import ssl
import time
import sys
import signal
import socket
import optparse
from urllib.parse import urlparse, unquote

import requests
import nmap
import dns.resolver
from tabulate import tabulate
from openai import OpenAI, OpenAIError
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup

from utils.constants import REQ_SCHEME
from utils.utils import Spinner, parse_conf

# 忽略 SSL 告警信息
try:
    from requests.packages import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

if os.name == 'posix':
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
else:
    HEADER, OKBLUE, OKCYAN, OKGREEN, WARNING, FAIL, ENDC, BOLD, UNDERLINE = ('',)*9

def detect_waf(req_rsp):
    """
    检测目标对象前是否部署 WAF，以及是哪种 WAF
    检测原理：在 url 中传递 xss 和 sqli payload，检测 response 对象是否包含 Waf 特征。
    参考：https://github.com/Ekultek/WhatWaf
    """
    response = req_rsp.get('response')
    headers = req_rsp.get('headers')
    status = req_rsp.get('status')

    # 阿里云盾
    if status == 405:
        # 阻断
        detection_schemas = (
            re.compile(r"error(s)?.aliyun(dun)?.(com|net)", re.I),
            re.compile(r"http(s)?://(www.)?aliyun.(com|net)", re.I)
        )
        for detection in detection_schemas:
            if detection.search(response):
                return 'AliYunDun'
        
    elif status == 200:
        # 非阻断，如滑块验证
        detection = re.compile(r"TraceID: [0-9a-z]{30}", re.I)
        if detection.search(response):
            return 'AliYunDun'

    # 腾讯云 waf
    elif status == 202 or status == 403:
        detection = re.compile(r"[0-9a-z]{32}-[0-9a-z]{32}", re.I)
        if 'waf' in headers.get('Set-Cookie', '') or detection.search(response):
            return 'T-Sec-Waf'
    
    # CloudFlare
    detection_schemas = (
        re.compile(r"cloudflare.ray.id.|var.cloudflare.", re.I),
        re.compile(r"cloudflare.nginx", re.I),
        re.compile(r"..cfduid=([a-z0-9]{43})?", re.I),
        re.compile(r"cf[-|_]ray(..)?([0-9a-f]{16})?[-|_]?(dfw|iad)?", re.I),
        re.compile(r".>attention.required!.\|.cloudflare<.+", re.I),
        re.compile(r"http(s)?.//report.(uri.)?cloudflare.com(/cdn.cgi(.beacon/expect.ct)?)?", re.I),
        re.compile(r"ray.id", re.I)
    )
    server = headers.get('server', '')
    cookie = headers.get('cookie', '')
    set_cookie = headers.get('set-cookie', '')
    cf_ray = headers.get('cf-ray', '')
    expect_ct = headers.get('expect-ct', '')
    if cf_ray or "__cfduid" in set_cookie or "cloudflare" in expect_ct:
        return 'CloudFlare'
    for detection in detection_schemas:
        if detection.search(response) \
                or detection.search(server) \
                or detection.search(cookie) \
                or detection.search(set_cookie) \
                or detection.search(expect_ct):
            return 'CloudFlare'
        
    return 'unknown'

def resolve_dns(domain, rtype):
    try:
        answers = my_resolver.resolve(domain, rtype)
        return [(rtype, rdata.to_text()) for rdata in answers]
    except dns.exception.DNSException:
        return []
    
def signal_handler(sig, frame):
    print(f'{WARNING}终止程序 Byebye{ENDC}')
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


if __name__ == '__main__':

    # 记录启动时间
    start_time = time.time()

    parser = optparse.OptionParser(description='+ Get infomation of target +')
    parser.add_option("-u", "--url", dest="url", help='Target URL(e.g. "http://www.target.com")')
    parser.add_option("-t", "--timeout", dest="timeout", type="float", default=60.0, help="Port scan timeout (s)")
    parser.add_option("--req-timeout", dest="req_timeout", type="float", default=3.0, help="HTTP request timeout (s)")
    options, _ = parser.parse_args()

    if not options.url:
        parser.error('url not given')

    # URL 解析
    o = urlparse(unquote(options.url))
    scheme = o.scheme.lower() if o.scheme else REQ_SCHEME
    domain = o.hostname
    port = o.port if o.port else (443 if scheme == 'https' else 80)

    """
    信息收集

    1、基本信息
    2、SSL 证书
    3、DNS 记录
    4、端口信息
    5、杂项
    """

    # 基本信息
    # 服务状态、Web Server 和框架/脚本语言等
    print(f'\n{"-"*10} 基本信息 {"-"*10}\n')
    is_server_up = True
    web_server, framework, waf = ('unknown',)*3
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((domain, port))
    if result:
        is_server_up = False
    sock.close()

    if is_server_up:
        # 判断是否部署了 Waf
        payload = "xss=<img/src=1 onerror=alert(1)>&sqli=' and 'a'='a"
        url = f"{options.url}&{payload}" if '?' in options.url else f"{options.url}?{payload}"
        r = requests.get(url, timeout=options.req_timeout, verify=False)
        waf = detect_waf({'status': r.status_code, 'headers': r.headers, 'response': r.text})
        
        # Web Server 和框架/脚本语言
        r = requests.get(options.url, timeout=options.req_timeout, verify=False)
        web_server = r.headers.get('Server', 'unknown')
        framework = r.headers.get('X-Powered-By', 'unknown')

        # 获取页面标题、关键词和描述
        # 解决中文乱码问题
        r.encoding = r.apparent_encoding
        html = BeautifulSoup(r.text, 'html.parser')
        title = html.title.string if html.title else 'unknown'
        keywords = html.find('meta', attrs={'name': 'keywords'})
        keywords = keywords['content'] if keywords else 'unknown'
        description = html.find('meta', attrs={'name': 'description'})
        description = description['content'] if description else 'unknown'

    basic_info = f"""
服务状态：{OKGREEN + "running" if is_server_up else FAIL + "down"}{ENDC}
WAF：{OKGREEN + waf + ENDC}
Web 服务软件：{OKGREEN + web_server + ENDC}
框架/脚本语言：{OKGREEN + framework + ENDC}
标题：{OKGREEN + title + ENDC}
关键词：{OKGREEN + keywords + ENDC}
描述：{OKGREEN + description + ENDC}
    """
    print(basic_info)

    # SSL 证书信息
    print(f'\n{"-"*10} SSL 证书信息 {"-"*10}\n')
    tls_versions_info = ''
    if scheme == 'https':
        # SSL/TLS 版本
        tls_versions = []
        try:
            nm = nmap.PortScanner()
            nm.scan(domain, arguments=f'--script ssl-enum-ciphers -p {port}', timeout=options.timeout)
            for host in nm.all_hosts():
                if 'tcp' in nm[host] and port in nm[host]['tcp']:
                    if 'script' in nm[host]['tcp'][port]:
                        script_output = nm[host]['tcp'][port]['script']
                        if 'ssl-enum-ciphers' in script_output:
                            lines = script_output['ssl-enum-ciphers'].split('\n')
                            tls_versions = [line.replace(' ', '').replace(':', '') for line in lines if 'TLSv' in line or 'SSLv' in line]
        except Exception as e:
            tls_versions.append(str(e).strip("'"))
        tls_versions_info = f'SSL/TLS 版本：{", ".join(tls_versions)}'
        print(tls_versions_info)

        # 证书信息
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.connect((domain, port))
                cert = s.getpeercert()
                sign_algorithm = x509.load_der_x509_certificate(s.getpeercert(True), default_backend()).signature_algorithm_oid._name

            subject = dict(x[0] for x in cert.get('subject'))
            issuer = dict(x[0] for x in cert.get('issuer'))
            valid_period = {
                'start': cert.get('notBefore'),
                'end': cert.get('notAfter')
            }
            subject_altname = ', '.join([x[1] for x in cert.get('subjectAltName')])

            ssl_info = f"""
颁发对象：
    通用名称：{subject.get('commonName')}
    国家/地区：{subject.get('countryName', '未知')}
    组织：{subject.get('organizationName', '未知')}
颁发者：
    通用名称：{issuer.get('commonName')}
    国家/地区：{issuer.get('countryName')}
    组织：{issuer.get('organizationName')}
有效期：
    颁发日期：{valid_period.get('start')}
    截止日期：{valid_period.get('end')}
颁发对象替代名称：
    DNS：{subject_altname}
证书签名算法：
    {sign_algorithm}"""
        except ssl.SSLError as e:
            ssl_info = f'{WARNING}SSL 连接错误: {str(e)}{ENDC}'
        except socket.error as e:
            ssl_info = f'{WARNING}套接字连接错误: {str(e)}{ENDC}'
        except Exception as e:
            ssl_info = f'{WARNING}获取 SSL 证书时发生错误: {str(e)}{ENDC}'
    else:
        ssl_info = f'{WARNING}目标站点为 HTTP 协议，跳过证书检测{ENDC}'
    print(ssl_info)

    # DNS 记录
    print(f'\n{"-"*10} DNS 记录信息 {"-"*10}\n')
    dns_records = []
    my_resolver = dns.resolver.Resolver()
    my_resolver.nameservers = ['114.114.114.114', '8.8.8.8']
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(resolve_dns, domain, rtype) for rtype in ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'SRV', 'PTR']]
        for future in futures:
            dns_records.extend(future.result())
    
    dns_records_info = tabulate(dns_records, headers=['类型', '记录值'], tablefmt='simple_grid')
    print(dns_records_info)

    # 端口信息
    print(f'\n{"-"*10} 端口信息 {"-"*10}\n')
    ports_info = ''
    spinner = Spinner('正在扫描，请稍候...')
    spinner.start()
    try:
        nm = nmap.PortScanner()
        nm.scan(domain, timeout=options.timeout)
        ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                if proto not in ["tcp", "udp"]:
                    continue

                lport = list(nm[host][proto].keys())
                lport.sort()
                for pt in lport:
                    ports.append([host, f'{pt}/{proto}', nm[host][proto][pt]["state"], nm[host][proto][pt]["name"], f'{nm[host][proto][pt]["product"]} {nm[host][proto][pt]["version"]}'])
        ports_info = tabulate(ports, headers=['主机', '端口', '状态', '服务', '版本'], tablefmt='simple_grid')
    except nmap.nmap.PortScannerTimeout:
        ports_info = f'{WARNING}端口扫描{options.timeout}秒超时，请适当延长超时时间{ENDC}'
    spinner.stop()
    print(ports_info)

    # 杂项
    print(f'\n{"-"*10} robots.txt {"-"*10}\n')
    robots_info = ''
    try:
        robots_response = requests.get(f"{scheme}://{domain}/robots.txt", timeout=options.req_timeout, verify=False)
        if robots_response.status_code == 200:
            robots_info = robots_response.text
        else:
            robots_info = "robots.txt 文件不存在"
    except requests.exceptions.RequestException as e:
        robots_info = f"获取 robots.txt 失败：{str(e)}"
    print(robots_info)

    print(f"\n[+] 信息收集完成，总耗时：{time.time() - start_time:.2f}秒")

    # 大模型智能分析
    # 脚本相对目录
    script_rel_dir = os.path.dirname(sys.argv[0])

    # 解析配置文件
    conf_dict = parse_conf(os.path.join(script_rel_dir, 'yawf.conf'))
    if not conf_dict:
        sys.exit('[*] parse config file error')

    if conf_dict['llm_status'] == 'enable':
        try:
            client = OpenAI(api_key = conf_dict['llm_api_key'], base_url = conf_dict['llm_base_url'])
            info = f'<基本信息>{basic_info}</基本信息><SSL证书信息>{tls_versions_info}{ssl_info}</SSL证书信息><DNS记录信息>{dns_records_info}</DNS记录信息><端口信息>{ports_info}</端口信息><杂项><robots文件内容>{robots_info}</robots文件内容></杂项>'

            response = client.chat.completions.create(
                model = conf_dict['llm_model'],
                messages = [
                    {"role": "system", "content": "你是一位安全测试专家，你将收到和测试对象相关的XML结构化信息。请先分析这些信息，运用透过现象（此处的现象就是收集到的信息）看本质的思维和方法，然后制定下一步的安全测试计划。"},
                    {"role": "user", "content": info},
                ],
                stream = True
            )
            print(f"[+] 使用大模型进行智能分析：\n\n")
            for chunk in response:
                print(chunk.choices[0].delta.content or "", end="", flush=True)
        except OpenAIError as e:
            print(f"[+] 智能分析失败，原因如下：\n\n{e}")
    else:
        print("[+] 未开启大模型，无法进行智能分析")
