## Yawf - Yet Another Web Fuzzer

**Yawf** 是一个开源的 Web 漏洞检测工具，能够帮助发现一些常见 Web 漏洞，包括：XSS、SQL injection、XXE、Fastjson RCE 和 Log4j RCE 等。

### 功能

1.  支持检测动态 URL 和 HTTP Request 文件目标对象；
2.  支持手动和自动标记测试点，标记范围覆盖查询字符串、Cookie 和 POST Body；
3.  支持多线程对测试目标进行检测，默认 3 个线程；
4.  容易扩展，探针和 Payload 字典分离；
5.  支持设置 HTTP 网络代理；
6.  高度可配置化，简单配置实现定制需求。

#### 探针

1.  **xss** - 跨站脚本探针
2.  **sqli** - SQL 注入探针
3.  **dt** - 目录遍历探针
4.  **rce_fastjson** - Fastjson RCE 探针
5.  **rce_log4j** - Log4j RCE 探针
6.  **xxe** - XXE 探针

### 安装

#### 依赖

1.  Python 3+
2.  requests

#### 运行

```console
$ git clone https://github.com/phplaber/yawf.git
$ cd yawf
$ python yawf.py -h

_____.___.  _____  __      _____________
\__  |   | /  _  \/  \    /  \_   _____/
 /   |   |/  /_\  \   \/\/   /|    __)  
 \____   /    |    \        / |     \   
 / ______\____|__  /\__/\  /  \___  /   
 \/              \/      \/       \/    

Automated Web Vulnerability Fuzzer      
v2.0                               
Created by yns0ng (@phplaber)           

Usage: yawf.py [options]

Options:
  -h, --help         show this help message and exit
  -u URL, --url=URL  Target URL (e.g. "http://www.target.com/page.php?id=1")
  -m METHOD          HTTP method (e.g. PUT)
  -d DATA            Data string to be sent through POST (e.g. "id=1")
  -c COOKIES         HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
  --headers=HEADERS  Extra headers (e.g. "Accept-Language: fr\nETag: 123")
  -r REQUESTFILE     Load HTTP request from a file
```

### 使用

#### 配置

根据自身需求，修改 **yawf.conf** 配置文件中配置项，如：网络代理、scheme 和探针等。

scheme 需和 **-r** 选项配合使用，默认是 https。

在 **customize** 项中配置自定义探针，多个探针需使用英文逗号分隔，探针名称见上述列表。如果 **customize** 项为空，则使用 **default** 项中配置的探针。如果 **default** 项也为空，最终兜底的为 xss 探针。

#### 标记

Yawf 支持手动和自动标记测试点，支持查询字符串、Cookie 和 POST Body 等处。

当需要测试某个单独的输入点时，仅需在参数值后手动标记 **[fuzz]**，Yawf 就只会对该位置进行检测。注意，手动标记需保留原始参数。在真正进行 PoC 测试时，Yawf 会根据探针类型灵活的选择是否保留原始参数。

```
http://test.sqlilab.local/Less-1/?id=3[fuzz]
```

也可以手动标记 HTTP Request 文件中的输入点，该文件内容可以通过 Live HTTP Headers 或 Burp Suite 获取到。

```
GET /Less-1/?id=3[fuzz] HTTP/1.1
Host: test.sqlilab.local
User-Agent: Yawf v2.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```
如果想要尽可能全面的检测输入点，则不要手动标记，Yawf 会智能的在所有满足条件的地方自动标记。

#### 运行脚本

设置必要的参数，运行 **yawf.py** 脚本，等待脚本运行结束。如果 Yawf 发现疑似漏洞，会将详情写入 output 目录下按时间戳命名的文件中，如果 output 目录不存在，Yawf 会安全的创建，所以无需担心。

详情包括标记过的 request 对象、payload、触发漏洞的 request 对象以及漏洞类型。

至此，Yawf 的使用就结束了。后续就是人工介入，确认漏洞是否存在、等级，然后进入漏洞处置流程。

