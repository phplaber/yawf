#!/usr/bin/python
# -*- coding: utf-8 -*-

import optparse
from core.request.request import Request
from core.fuzz.fuzzer import Fuzzer
from core.utils.utils import *
from core.utils.shared import Shared

if __name__ == '__main__':

    print "%s #v%s\n by: %s\n" % (NAME, VERSION, AUTHOR)
    parser = optparse.OptionParser(version=VERSION)
    parser.add_option("-u", "--url", dest="url", help="Target URL (e.g. \"http://www.target.com/page.php?id=1\")")
    parser.add_option("-r", dest="requestfile", help="Load HTTP request from a file")
    parser.add_option("-n", dest="threads", help="Number of parallel threads (default: 10)")
    options, _ = parser.parse_args()
    if options.url or options.requestfile:
        error = errmsg_dict()
        if options.url:
            request = dict()
            request['url'] = options.url.strip() if PAYLOAD not in options.url else options.url.replace(PAYLOAD, '').strip()

            # 支持手动标记 fuzz 变量
            if PAYLOAD in options.url:
                base_request = send_request(request)
                requests = [{"url": options.url.strip()}]
            # 目前只支持动态 URL 的模糊测试
            # 自动标记所有 fuzz 变量
            elif '=' in options.url:
                base_request = send_request(request)
                requests = Request().gene_url_list(options.url.strip())
            else:
                print error['url_is_invalid']
                sys.exit(1)
        else:
            if not check_file(options.requestfile):
                print error['file_is_invalid']
                sys.exit(1)

            try:
                with open(options.requestfile, "rb") as f:
                    content = f.read()
            except (IOError, OSError, MemoryError), ex:
                print error['read_file_occur_wrong'] % (options.requestfile, ex)
                sys.exit(1)

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
        threads_num = 0
        if len(Shared.requests) == 1:
            threads_num = 1
        elif options.threads:
            threads_num = int(options.threads)
        else:
            threads_num = THREADS_NUM

        Fuzzer(threads_num)
    else:
        parser.print_help()
