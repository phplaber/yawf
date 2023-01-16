# -*- coding: utf-8 -*-

import os
import sys
import time
import json
from threading import Condition
from core.fuzz_thread import FuzzThread
from utils.shared import Shared
from probe.probe import Dnslog, Webdriver
from utils.utils import parse_payload


class Fuzzer:
    """
    模糊测试调度器
    """

    def __init__(self, threads_num):
        self.start_time = int(time.time())
        self.end_time = 0
        self.threads_num = threads_num
        self.main()

    def loop(self, threads):
        """
        同步线程，等待全部线程结束
        """

        for thread in threads:
            thread.join()

    def main(self):
        """
        启动多个线程去检测漏洞
        """

        # 初始化 dnslog 实例
        if any(p in 'xxe:rce_fastjson:rce_log4j' for p in Shared.probes):
            Shared.dnslog = Dnslog(Shared.base_response.request['proxies'])

        # 初始化 webdriver（headless Chrome）实例
        if any(p in 'xss' for p in Shared.probes):
            Shared.web_driver = Webdriver().driver

        # 读取探针 payload
        payload_path = os.path.join(os.path.dirname(sys.argv[0]), 'probe', 'payload')
        for probe in Shared.probes:
            Shared.probes_payload[probe] = parse_payload(os.path.join(payload_path, '{}.txt'.format(probe)))
        
        Shared.condition = Condition()
        fuzz_threads = []
        for _ in range(self.threads_num):
            fuzz_thread = FuzzThread()
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        self.loop(fuzz_threads)

        # 关闭 webdriver
        if Shared.web_driver:
            Shared.web_driver.close()

        # 本地文件存储发现漏洞
        if Shared.fuzz_results:
            outputdir = os.path.join(os.path.dirname(sys.argv[0]), 'output')
            if not os.path.exists(outputdir):
                os.makedirs(outputdir)
            outputfile = os.path.join(outputdir, 'output_{}.txt'.format(time.strftime("%Y%m%d%H%M%S")))
            with open(outputfile, 'w') as f:
                for result in Shared.fuzz_results:
                    f.write(json.dumps(result))
                    f.write('\n')

        self.end_time = int(time.time())

        print("\n\nFuzz finished, {} request(s) scanned in {} seconds.".format(Shared.request_index, self.end_time - self.start_time))