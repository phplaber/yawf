## Yawf - Yet Another Web Fuzz

**Yawf** 是一个开源的 Web 漏洞模糊测试工具，能够帮助发现 OWASP 披露的一些常见漏洞，包括：XSS，SQL injection，LFI，RFI 和 Directory traversal等。

## 特性

1.  支持动态 URL 和 Request 文件的模糊测试；
2.  支持自动搜索所有测试锚点并标注，目前搜索范围包括 URL 中查询字符串，Cookie 和表单数据。同时，支持手动标注测试锚点；
3.  支持多线程对测试目标进行模糊测试，默认 10 个线程；
4.  基于 OWASP 进行 Web 漏洞挖掘，目前支持：XSS，SQL injection，LFI，RFI 和 Directory traversal；
5.  容易扩展，漏洞测试器和 Payload 字典分离；
6.  支持配置 HTTP 网络代理；
7.  通过调用 shodan api，检测目标为蜜罐的概率。

## 安装

### 环境

Python 2.7

### 运行

```console
$ git clone https://github.com/phplaber/yawf.git yawf
$ python yawf/yawf.py -h
```

## 使用

```
$ python yawf/yawf.py -h
_____.___.  _____  __      _____________
\__  |   | /  _  \/  \    /  \_   _____/
 /   |   |/  /_\  \   \/\/   /|    __)  
 \____   /    |    \        / |     \   
 / ______\____|__  /\__/\  /  \___  /   
 \/              \/      \/       \/    

Automated Web Vulnerability Fuzz Tester
version 1.0.0                           
Created by Yns0ng (@phplaber)           

Usage: yawf.py [options]

Options:
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  -r REQUESTFILE     Load HTTP request from a file
  -n THREADS         Number of parallel threads (default: 10)
  -p PROXY           Specify a proxy in the request http|s://[IP]:[PORT]
  -t TARGET          Check if the target is a honeypot
```

支持动态 URL 和 Request 文件的模糊测试，当需要测试某个单独的输入点时，仅需在参数值后手动标注上 **[fuzz]**，Yawf 就只会对该位置进行模糊测试。如：

```
http://test.sqlilab.local/Less-1/?id=3[fuzz]
```

Request 文件可以通过 Live HTTP Headers 或 Burp Suite 获取得到。
