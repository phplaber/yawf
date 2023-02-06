## Yawf - Yet Another Web Fuzzer

**Yawf** 是一个开源的 Web 漏洞自动化检测工具，能够帮助发现一些常见 Web 漏洞，包括：XSS、SQL injection、XXE、Fastjson RCE 和 Log4j RCE 等。

### 功能

1.  支持检测动态 URL 和 HTTP Request 文件目标对象；
2.  支持手动和自动标记测试点，标记范围覆盖查询字符串、Cookie 和 POST Body；
3.  支持 GET 和 POST 请求，以及 form、json 和 xml 数据类型；
4.  支持 Basic 和 Digest HTTP 认证；
5.  支持多线程对测试目标进行检测，默认 3 个线程；
6.  容易扩展，探针和 Payload 文件分离；
7.  支持检测目标对象前是否部署 WAF，以及是哪种 WAF；
8.  支持设置 HTTP 网络代理；
9.  高度可配置化，简单配置实现定制需求。

#### 探针

1.  **xss** - 跨站脚本探针
2.  **sqli** - SQL 注入探针
3.  **dt** - 目录遍历探针
4.  **rce_fastjson** - Fastjson RCE 探针
5.  **rce_log4j** - Log4j RCE 探针
6.  **xxe** - XXE 探针

#### 性能优化

假设一次测试活动共有10个测试点，使用全部6个探针。

1.  多线程同时检测测试点，一个测试点对应一个请求对象，每个请求对象间互不依赖，充分利用多核 CPU 提高检测效率；
2.  在多线程执行探针前，提前获取已选择探针载荷内容，后续检测每个测试点时直接获取，文件 IO 从 **60** 次减少到 **6** 次；
3.  读取一次配置文件后，将配置数据写入内存，后续使用直接从内存中读取，文件 IO 从 **9** 次减少到 **1** 次；
4.  一次测试活动只获取一次 dnslog domain，通过随机字符串子域名加以区分每个探针使用的 payload，网络请求从 **10** 次减少到 **1** 次；
5.  查询字符串和 POST Body 中 json 多值标记只执行一次 rce_fastjson 探针，避免不必要的重复测试，减少网络请求；
6.  根据测试目标运行平台操作系统，选择性的使用特定该操作系统的 payload，减少无效网络请求；
7.  根据内容类型，有选择的执行或跳过某个探针。如：当内容类型为 xml 且测试点在 post body 中时，只执行 xxe 探针，跳过其它探针；只有当查询字符串中包含 json 或 post body 为 json 类型且测试点在 post body 中时，才执行 rce_fastjson 探针等；
8.  通过配置检测和忽略的 HTTP 参数名称，跳过某些参数检测和只针对特定参数执行某类探针，减少大量网络请求（其中大多数为无效请求），最大程度的加快测试进程。

### 安装

需使用 Python 3 运行。

由于 Yawf 在检测 XSS 漏洞时，使用了 headless Chrome，所以需预先安装 Chrome 环境。在 Windows 和 Mac 平台上运行，如果已安装 Chrome 应用，则可以直接运行 Yawf；在 Linux 平台上运行，则需安装 [ChromeDriver](https://sites.google.com/chromium.org/driver/) 和 [google-chrome](https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm) ，并将可执行文件放置在 PATH 目录下。

```console
$ git clone https://github.com/phplaber/yawf.git
$ cd yawf
$ pip3 install -r requirements.txt
$ python3 yawf.py -h

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
  -h, --help            show this help message and exit
  -u URL, --url=URL     Target URL (e.g.
                        "http://www.target.com/page.php?id=1")
  -m METHOD             HTTP method, default: GET (e.g. POST)
  -d DATA               Data string to be sent through POST (e.g. "id=1")
  -c COOKIES            HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..")
  --headers=HEADERS     Extra headers (e.g. "Accept-Language: fr\nETag: 123")
  --auth-type=AUTH_TYPE
                        HTTP authentication type (Basic, Digest)
  --auth-cred=AUTH_CRED
                        HTTP authentication credentials (user:pass)
  -f REQUESTFILE        Load HTTP request from a file
```

### 使用

#### 配置

根据自身需求，修改 **yawf.conf** 配置文件中配置项，如：网络代理、scheme 和探针等。

- 在 **proxy** 项中配置网络代理服务器，如：127.0.0.1:8080，在调试 payload 的时候很有用；

- **scheme** 需和 **-f** 选项配合使用，默认是 https；

- 在 **timeout** 项中配置请求超时时间，支持小数，单位为秒，默认是 30 秒；

- 在 **customize** 项中配置自定义探针，多个探针需使用英文逗号分隔，探针名称见上述列表。如果 **customize** 项为空，则使用 **default** 项中配置的探针。如果 **default** 项也为空，最终兜底的为 xss 探针；

- 在 **dt_detect_params** 项中配置名称包含这些关键词的参数，在自动标记模式下，才会去执行 dt 探针；

- 在 **ignore_params** 项中配置自动标记忽略的参数名称，这些参数往往和会话相关，被修改可能影响正常请求，而且这些地方一般不太可能出现漏洞。当然，如果需要测试这些参数，可以手动标记或将其从配置项里移除；

- 在 **platform** 项中配置测试目标运行平台操作系统，默认是 Linux。在遇到特定平台的 payload 时，Yawf 会依据该配置进行针对性的测试，减少无效网络请求；

- 在 **enable_waf_detecter** 项中配置执行漏洞检测前是否开启 WAF 检测，默认是 on，表示开启。Yawf 支持检测的 WAF 有：阿里云盾、云加速、安全狗、加速乐和 CloudFlare，检测代码主要从 [WhatWaf](https://github.com/Ekultek/WhatWaf) 项目移植而来，做了略微修改。需要检测其它 WAF，可以参考使用 [WhatWaf](https://github.com/Ekultek/WhatWaf)。一旦 Yawf 检测到 WAF，将中断执行。

#### 标记

Yawf 支持手动和自动标记测试点，支持查询字符串、Cookie 和 POST Body 处标记。

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

支持标记的位置如下：

1.  **查询字符串**
    -  `?par1=val1&par2=val2[fuzz]`，常规查询字符串数据格式
    -  `?par1={"foo":"bar[fuzz]"}`，参数值为 json 编码数据格式，支持对 json 中的各值（不包含对象和数组）标记
    -  `?par1={"foo":"bar[fuzz]"}&par2=val2[fuzz]`，组合形式
2.  **Cookie**
    -  `k1=v1[fuzz]; k2=v2[fuzz]`，常规键值对数据格式
3.  **POST Body**
    -  `par1=val1&par2=val2[fuzz]`，常规 form 编码数据格式
    -  `{"par1":"val1","par2":"val2[fuzz]"}`，json 编码数据格式，支持对 json 中的各值（不包含对象和数组）标记
    -  `<par1>val1[fuzz]</par1>`，xml 编码数据格式

同时需注意，在自动标记模式下，参数是否被标记还受配置项 **ignore_params** 影响。

#### 运行脚本

设置必要的参数，运行 **yawf.py** 脚本，等待脚本运行结束。如果 Yawf 发现疑似漏洞，会将详情写入 output 目录下按时间戳命名的文件中，如果 output 目录不存在，Yawf 会安全的创建，所以无需担心。

详情包括标记过的 request 对象、payload、触发漏洞的 request 对象以及漏洞类型。

至此，Yawf 的使用就结束了。后续就是人工介入，确认漏洞是否存在、等级，然后进入漏洞处置流程。

### 声明

此工具仅用于企业安全人员评估自身企业资产的安全风险，或有合法授权的安全测试，请勿用于其他用途，如有，后果自负。

