import os
import random
import json
import re
import sys
import time
import threading
import itertools
from configparser import ConfigParser
from difflib import SequenceMatcher
from xml.etree import ElementTree as ET
from typing import Dict, Any

import requests
import esprima
from requests.auth import HTTPDigestAuth
from requests_ntlm2 import HttpNtlmAuth
from selenium import webdriver

# 忽略 SSL 告警信息
try:
    from requests.packages import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

class Spinner:
    def __init__(self, msg):
        self.msg = msg
        self.spinner = itertools.cycle(['-', '\\', '|', '/'])
        self.running = False
        self.spinner_thread = None

    def spin(self):
        while self.running:
            sys.stdout.write('\r' + self.msg + ' ' + next(self.spinner))
            sys.stdout.flush()
            time.sleep(0.1)

    def start(self):
        self.running = True
        self.spinner_thread = threading.Thread(target=self.spin)
        self.spinner_thread.daemon = True
        self.spinner_thread.start()

    def stop(self):
        self.running = False
        self.spinner_thread.join()
        sys.stdout.write('\r')
        sys.stdout.flush()

class Browser:
    def __init__(self, proxies, user_agent):
        options = webdriver.ChromeOptions()
        # 以 headless 模式运行 Chrome
        options.add_argument('--headless')
        # 仅 Windows 上运行有效
        options.add_argument('--disable-gpu')
        # 仅 Docker 上运行有效
        options.add_argument('--no-sandbox')
        # 在内存资源有限的环境中运行需要
        options.add_argument('--disable-dev-shm-usage')
        # 禁用扩展程序
        options.add_argument('--disable-extensions')
        # 设置 user-agent
        options.add_argument(f'user-agent={user_agent}')
        # 设置网络代理
        if proxies:
            options.add_argument(f"--proxy-server={proxies['http']}")
        # 忽略证书错误
        options.add_argument('--ignore-ssl-errors=yes')
        options.add_argument('--ignore-certificate-errors')
        # 禁用 xss auditor
        options.add_argument('--disable-xss-auditor')
        # 忽略 DevTools 监听 ws 信息
        options.add_experimental_option('excludeSwitches', ['enable-logging'])

        self.options = options

    def run(self):
        return webdriver.Chrome(options=self.options)

class Dnslog:
    def __init__(self, proxies, timeout):
        self.proxies = proxies
        self.timeout = timeout
        self.req_session = requests.Session()
        req = self.req_session.get("http://www.dnslog.cn/getdomain.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )
        self.domain = req.text

    def pull_logs(self, _):
        req = self.req_session.get("http://www.dnslog.cn/getrecords.php", 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json()

class Ceye:
    def __init__(self, proxies, timeout, id, token):
        self.proxies = proxies
        self.timeout = timeout
        
        self.domain = id
        self.token  = token

    def pull_logs(self, filter):
        req = requests.get(f"http://api.ceye.io/v1/records?token={self.token}&type=dns&filter={filter}", 
            proxies=self.proxies, 
            timeout=self.timeout
        )

        return req.json().get('data')

def check_file(filename):
    """
    检查文件是否存在和可读
    """

    valid = False

    if os.path.isfile(filename) and os.access(filename, os.R_OK):
        valid = True

    return valid

def get_default_headers():
    """
    获取默认请求头
    返回区分大小写的常规 dict 类型，且请求头名称为小写
    """

    case_sensitive_dict = requests.utils.default_headers()
    normal_plain_dict = dict((k.lower(), v) for k, v in case_sensitive_dict.items())

    return normal_plain_dict

def send_request(
    request: Dict[str, Any], 
    require_response_header: bool = False
) -> Dict[str, Any]:
    """
    发送 HTTP 请求

    参数:
        request: 请求配置字典
        require_response_header: 是否返回响应头
        
    返回:
        包含请求、响应、状态码等信息的字典
    """

    response, headers, status, json_data, data_data, auth = (None,)*6
    # 处理 POST 请求数据
    if request['method'] == 'POST':
        content_type = request['headers'].get('content-type', '')
        if 'json' in content_type:
            json_data = request['data'] if not isinstance(request['data'], str) else json.loads(request['data'])
        else:
            data_data = request['data']
    
    # 处理认证信息
    if request['auth']:
        username, password = request['auth']['auth_cred'].split(':', 1)
        auth_type = request['auth']['auth_type']
        
        auth_methods = {
            'Basic': lambda: (username, password),
            'Digest': lambda: HTTPDigestAuth(username, password),
            'NTLM': lambda: HttpNtlmAuth(username, password)
        }
        
        auth = auth_methods.get(auth_type, lambda: None)()
    
    try:
        rsp = requests.request(request['method'], request['url'], 
            params=request['params'],
            headers=request['headers'], 
            cookies=request['cookies'], 
            proxies=request['proxies'], 
            data=data_data,
            json=json_data, 
            auth=auth,
            timeout=request['timeout'], 
            verify=False)
        response = rsp.text
        headers = rsp.headers if require_response_header else None
        status = rsp.status_code
    except requests.exceptions.Timeout as e:
        print(f'[*] WARN : request timeout : {str(e)}')
    except requests.exceptions.ConnectionError as e:
        print(f'[*] WARN : connection error : {str(e)}')
    except requests.exceptions.TooManyRedirects as e:
        print(f'[*] WARN : too many redirects : {str(e)}')
    except requests.exceptions.HTTPError as e:
        print(f'[*] WARN : HTTP error : {str(e)}')
    except requests.exceptions.RequestException as e:
        print(f'[*] WARN : request error : {str(e)}')
    except Exception as e:
        print(f'[*] ERROR : unexpected error : {str(e)}')

    return {
        'request': request,
        'response': response,
        'headers': headers,
        'status': status
    }

def parse_conf(file):
    """
    解析配置文件，将配置数据存储在内存中
    通过 conf_dict[section_option] 获取配置项的值
    """

    conf_dict = {}

    try:
        conf = ConfigParser()
        conf.read(file, encoding='utf-8')
        for section in conf.sections():
            for option in conf.options(section):
                conf_dict[f'{section}_{option}'] = conf.get(section, option)
    except Exception:
        pass

    return conf_dict

def read_file(file):
    """
    逐行读取文件内容到 list，忽略 # 开头行和空白行
    """

    lines = []

    with open(file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if not line.startswith('#') and line != '\n']
    
    return lines

def similar(str1, str2):
    """
    比较字符串 str1 和 str2 的相似度
    """

    return SequenceMatcher(None, str1, str2).quick_ratio()

def get_random_str(length):
    """
    生成指定长度的随机字符串
    """

    return ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for _ in range(length))

def get_content_type(content):
    """
    获取字符串内容类型，支持 x-www-form-urlencoded、json 和 xml 三种类型
    """

    ct = ''
    
    try:
        # 整数、浮点数和布尔值都是有效 json 格式，这里只处理由键值对组成的 json
        d = json.loads(content)
        if type(d) is dict:
            ct = 'json'
    except ValueError:
        try:
            ET.fromstring(content)
            ct = 'xml'
        except ET.ParseError:
            if re.search(r"^[A-Za-z0-9_]+=[^=]+", content):
                ct = 'form'

    return ct

def is_base64(string):
    """
    校验字符串是否为 Base64 编码
    不可能真正校验字符串是否为 Base64 编码，只能根据字符串是否符合 Base64 数据格式和长度大致猜测
    """

    is_b64 = False

    regex = r"^([A-Za-z0-9\-_]{4})*([A-Za-z0-9\-_]{3}=|[A-Za-z0-9\-_]{2}==)?$"
    if re.search(regex, string) and len(string) > 20:
        is_b64 = True

    return is_b64

def get_jsonp_keys(jsonp):
    """
    递归获取 jsonp 参数中所有的键名，用于敏感数据检测。
    如：
    callback({"username":"admin"}); // username
    callback({"data": {username:"admin"}}); // data, username
    """

    def get_keys(node):
        result = []
        if isinstance(node, esprima.nodes.ObjectExpression):
            for property in node.properties:
                if isinstance(property.key, esprima.nodes.Identifier):
                    result.append(property.key.name)
                elif isinstance(property.key, esprima.nodes.Literal):
                    result.append(property.key.value)
                result += get_keys(property.value)
        elif isinstance(node, esprima.nodes.Node):
            for _, value in node.items():
                result += get_keys(value)
        elif isinstance(node, list):
            for item in node:
                result += get_keys(item)
        return result

    ast_obj = esprima.parse(jsonp)

    return list(get_keys(ast_obj))
