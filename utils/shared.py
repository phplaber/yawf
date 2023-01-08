# -*- coding: utf-8 -*- 


class Shared:
    """
    多线程共享数据
    """

    base_response = None
    requests = []
    request_index = 0

    condition = None

    fuzz_results = []

