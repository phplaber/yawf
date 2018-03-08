# -*- coding: utf-8 -*-


class RequestResult:
    def __init__(self, request=None, response=None, length=None, status=None):
        self.request = request
        self.response = response
        self.length = length
        self.status = status
