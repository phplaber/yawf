#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from core.request import Request
from core.fuzzer import Fuzzer
from utils.utils import *
from utils.constants import *
from utils.shared import Shared

banner = "\
_____.___.  _____  __      _____________\n\
\__  |   | /  _  \/  \    /  \_   _____/\n\
 /   |   |/  /_\  \   \/\/   /|    __)  \n\
 \____   /    |    \        / |     \   \n\
 / ______\____|__  /\__/\  /  \___  /   \n\
 \/              \/      \/       \/    \n\
                                        \n\
Automated Web Vulnerability Fuzz Tester \n\
{version}                               \n\
Created by yns0ng (@phplaber)           \n\
\
".format(version=VERSION)

if __name__ == '__main__':

    print(banner)

    parser = optparse.OptionParser()
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-m", dest="method", help="HTTP method (e.g. PUT)")
    parser.add_option("-d", dest="data", help="Data string to be sent through POST (e.g. \"id=1\")")
    parser.add_option("-c", dest="cookies", help="HTTP Cookie header value (e.g. \"PHPSESSID=a8d127e..\")")
    parser.add_option("--headers", dest="headers", help="Extra headers (e.g. \"Accept-Language: fr\\nETag: 123\")")
    parser.add_option("-r", dest="requestfile", help="Load HTTP request from a file")
    parser.add_option("-n", dest="threads", help="Number of parallel threads (default: 3)")
    parser.add_option("-p", dest="proxy", help="Use a proxy to connect to the target URL")
    options, _ = parser.parse_args()

    # -u 和 -r 选项二选一
    if not options.url and not options.requestfile:
        parser.print_help()
        exit(1)

    # 网络代理
    if options.proxy:
        if 'https://' in options.proxy:
            Shared.proxy['https'] = options.proxy
        elif 'http://' in options.proxy:
            Shared.proxy['http'] = options.proxy

    requests = []
    base_request = RequestResult()
    if options.url:
        request = dict()
        request['url'] = options.url if PAYLOAD not in options.url else options.url.replace(PAYLOAD, '')

        # 手动标记 fuzz 变量
        if PAYLOAD in options.url:
            base_request = send_request(request)
            requests = [{"url": options.url}]
        # 自动标记 fuzz 变量
        elif '=' in options.url:
            base_request = send_request(request)
            requests = Request().gene_url_list(options.url)
        else:
            print(errmsg('url_is_invalid'))
            exit(1)
    else:
        if not check_file(options.requestfile):
            print(errmsg('file_is_invalid'))
            exit(1)

        try:
            with open(options.requestfile, "rb") as f:
                content = f.read()
        except (IOError, OSError, MemoryError) as ex:
            print(errmsg('read_file_occur_wrong').format(options.requestfile, str(ex)))
            exit(1)

        base_request_elements = parse_request(content if PAYLOAD not in content else content.replace(PAYLOAD, ''))
        base_request = send_request(base_request_elements)
        if PAYLOAD in content:
            # 手动标记
            requests = [parse_request(content)]
        else:
            # 自动标记
            requests = Request().gene_requestfile_list(base_request_elements)

    Shared.requests = requests
    Shared.base_request = base_request

    # 线程数
    threads_num = THREADS_NUM
    if len(Shared.requests) == 1:
        threads_num = 1
    elif options.threads:
        threads_num = int(options.threads)

    Fuzzer(threads_num)

