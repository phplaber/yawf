# -*- coding: utf-8 -*-

import os
import sys
import time
import json
from threading import Condition
from core.fuzz_thread import FuzzThread
from utils.shared import Shared
from probe.prober import Dnslog


class Fuzzer:
    """
    模糊测试调度器
    """

    def __init__(self, threads_num, proxies):
        self.start_time = int(time.time())
        self.end_time = 0
        self.threads_num = threads_num
        # 某些探针需要 dnslog 辅助
        self.dnslog = None
        if any(p in 'xxe:rce_fastjson:rce_log4j' for p in Shared.probes):
            self.dnslog = Dnslog(proxies)
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
        
        Shared.condition = Condition()
        fuzz_threads = []
        for _ in range(self.threads_num):
            fuzz_thread = FuzzThread(self.dnslog)
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        self.loop(fuzz_threads)

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