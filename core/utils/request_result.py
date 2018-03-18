# -*- coding: utf-8 -*-


class RequestResult:
    """
    结构化请求结果
    """

    def __init__(self, request=None, response=None, length=None, status=None):
        self.request = request
        self.response = response
        self.length = length
        self.status = status
