# -*- coding: utf-8 -*-

import time
from threading import Condition
from core.fuzz_thread import FuzzThread
from utils.shared import Shared

class Fuzzer:
    """
    模糊测试调度器
    """

    def __init__(self, threads_num):
        self.start_time = int(time.time())
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
        启动多线程检测漏洞
        """
        
        Shared.condition = Condition()
        fuzz_threads = []
        for _ in range(self.threads_num):
            fuzz_thread = FuzzThread()
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        self.loop(fuzz_threads)

        print("\n\n[+] Fuzz finished, {} request(s) scanned in {} seconds.".format(Shared.request_index, int(time.time()) - self.start_time))