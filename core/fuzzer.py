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
        Shared.condition = Condition()
        fuzz_threads = []
        for n in range(self.threads_num):
            fuzz_thread = FuzzThread()
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        self.loop(fuzz_threads)

        if len(Shared.fuzz_results):
            for result in Shared.fuzz_results:
                print(result)

        self.end_time = int(time.time())

        print("\n\nFuzz finished, {} request scanned in {} seconds.".format(Shared.requests_index, self.end_time - self.start_time))