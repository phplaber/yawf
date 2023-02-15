# -*- coding: utf-8 -*-

from threading import Condition
from core.fuzz_thread import FuzzThread
from utils.shared import Shared

class Fuzzer:
    """
    模糊测试调度器
    """

    def __init__(self, threads_num):
        self.main(threads_num)

    def main(self, threads_num):
        """
        启动多线程检测漏洞
        """
        
        Shared.condition = Condition()
        fuzz_threads = []
        for _ in range(threads_num):
            fuzz_thread = FuzzThread()
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        # 等待全部线程结束
        for thread in fuzz_threads:
            thread.join()

