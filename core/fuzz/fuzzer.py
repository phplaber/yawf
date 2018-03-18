# -*- coding: utf-8 -*-

import time
import threading
from core.fuzz.fuzz_thread import FuzzThread
from core.utils.shared import Shared
from core.utils.db import Db


class Fuzzer:
    """
    模糊测试调度器
    """

    def __init__(self, threads_num):
        self.start_time = int(time.time())
        self.end_time = 0
        self.threads_num = threads_num
        self.db = Db()
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
        Shared.condition = threading.Condition()
        fuzz_threads = []
        for n in xrange(self.threads_num):
            fuzz_thread = FuzzThread()
            fuzz_threads.append(fuzz_thread)
            fuzz_thread.start()

        self.loop(fuzz_threads)

        if len(Shared.fuzz_results) and self.db.conn is not None:
            self.db.create()
            for result in Shared.fuzz_results:
                self.db.save(result)

        self.end_time = int(time.time())

        print "\n\nFuzz finished, %d request scanned in %d seconds." % (Shared.requests_index, self.end_time - self.start_time)