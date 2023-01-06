# -*- coding: utf-8 -*- 


class Shared:
    """
    多线程共享数据
    """

    base_request = None
    requests = []
    requests_index = 0

    condition = None

    proxy = {}

    fuzz_results = []

