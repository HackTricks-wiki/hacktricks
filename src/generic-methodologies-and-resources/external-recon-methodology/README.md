# 外部侦察方法论

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 你被告知某家公司的所有资产都在范围内，现在想弄清楚这家公司实际拥有些什么。

此阶段的目标是找出**母公司旗下的所有公司**，然后找出这些公司的所有**资产**。为此，我们将：<sup>[[1]](#references)</sup>

1. 找出母公司的收购对象，这样就能确定范围内的公司。
2. 找出每家公司的 ASN（如果有），这样就能得到每家公司拥有的 IP 地址范围。
3. 使用 reverse whois 查询，搜索与第一个条目相关的其他条目（组织名称、域名……）（可以递归进行）。
4. 使用其他技术，例如 Shodan 的 `org`和`ssl`过滤器，搜索其他资产（`ssl`技巧也可以递归进行）。

### **收购**

首先，我们需要了解**母公司旗下还有哪些公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**这家**母公司**，然后**点击**“**acquisitions**”。在那里，你会看到母公司收购的其他公司。\
另一种方法是访问母公司的**Wikipedia**页面，并搜索**收购**信息。\
对于上市公司，请查看 **SEC/EDGAR 文件**、**投资者关系**页面或当地的公司注册机构（例如英国的 **Companies House**）。\
要了解全球企业架构和子公司，可以尝试使用 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好，到这里你应该已经知道范围内有哪些公司。接下来看看如何找到它们的资产。

### **ASN**

自治系统号码（**ASN**）是由**互联网号码分配局（IANA）**分配给**自治系统**（AS）的**唯一号码**。\
一个 **AS** 由一些**网段**组成，这些网段包含**IP 地址**，并且拥有明确定义的外部网络访问策略，由单个组织管理，但可能由多个运营商组成。

找出公司是否**分配了 ASN**，以便找到其**IP 地址范围**，很有意义。对**范围内**的所有**主机**执行**漏洞测试**，并查找这些 IP 中的**域名**也很有意义。\
你可以通过公司**名称**、**IP** 或**域名**在 [**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 上进行**搜索**。\
**根据公司所在地区，这些链接可能有助于收集更多数据：**[**AFRINIC**](https://www.afrinic.net) **（非洲）、**[**Arin**](https://www.arin.net/about/welcome/region/)**（北美）、**[**APNIC**](https://www.apnic.net) **（亚洲）、**[**LACNIC**](https://www.lacnic.net) **（拉丁美洲）、**[**RIPE NCC**](https://www.ripe.net) **（欧洲）。不过，可能所有**有用信息**（IP 地址范围和 Whois）**都已经包含在第一个链接中。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

另外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**的** 枚举会在扫描结束时自动聚合并汇总 ASN。

```bash
bbot -t tesla.com -f subdomain-enum
...
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.244.131.0/24      | 5            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS16509  | 54.148.0.0/15       | 4            | AMAZON-02      | Amazon.com, Inc.           | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS394161 | 8.45.124.0/24       | 3            | TESLA          | Tesla Motors, Inc.         | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.32.0.0/12         | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+
[INFO] bbot.modules.asn: | AS3356   | 8.0.0.0/9           | 1            | LEVEL3         | Level 3 Parent, LLC        | US        |
[INFO] bbot.modules.asn: +----------+---------------------+--------------+----------------+----------------------------+-----------+

```

你也可以使用 [http://asnlookup.com/](http://asnlookup.com) 查找组织的 IP 范围（它提供免费 API）。\
你可以使用 [http://ipv4info.com/](http://ipv4info.com) 查找域名的 IP 和 ASN。

### **寻找漏洞**

此时我们已经知道**范围内的所有资产**，因此如果获得许可，你可以对所有主机运行一些**漏洞扫描器**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
此外，你还可以运行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，**或者使用 Shodan、Censys 或 ZoomEye 等服务来查找**开放端口，**并根据发现的情况**查看本书中有关如何对可能运行的各种服务进行 pentest 的内容。\
**此外，值得一提的是，你还可以准备一些**默认用户名**和**密码**列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行**暴力破解**。

## 域名

> 我们已经知道范围内的所有公司及其资产，现在该找出范围内的域名了。

_请注意，以下建议的技术也可以找到子域名，不应低估这些信息的价值。_

首先，你应该查找每家公司的**主域名**。例如，_Tesla Inc._ 的主域名是 _tesla.com_。

### **反向 DNS**

既然你已经找到了这些域名的所有 IP 范围，就可以尝试对这些 **IP 执行反向 DNS 查询，以发现范围内更多的域名**。尝试使用受害者的 DNS 服务器，或一些知名的 DNS 服务器（1.1.1.1、8.8.8.8）。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

要使其生效，管理员必须手动启用 PTR。\
你也可以使用在线工具查询此信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于较大的范围，可以使用 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 等工具，自动执行反向查询并补充信息。

### **Reverse Whois (loop)**

在 **whois** 信息中，你可以找到许多有趣的信息，例如**组织名称**、**地址**、**电子邮件**、电话号码……但更有意思的是，如果你根据其中任一字段执行 **reverse whois 查询**（例如，查找其他出现相同电子邮件的 whois 记录），就能发现**与该公司相关的更多资产**。\
你可以使用以下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **免费**（Web 和 API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web 端**免费**，API 不免费。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅提供 **100 次免费**搜索）
- [https://www.domainiq.com/](https://www.domainiq.com) - 不免费
- [https://securitytrails.com/](https://securitytrails.com/) - 不免费（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 不免费（API）

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink)自动执行此任务（需要 whoxy API key）。\
你也可以使用 [amass](https://github.com/OWASP/Amass) 自动发现一些 reverse whois 信息：`amass intel -d tesla.com -whois`

**请注意，每当发现一个新域名时，都可以使用此技术发现更多域名。**

### **Trackers**

如果在两个不同的页面中发现**相同 tracker 的相同 ID**，就可以推断**这两个页面**由**同一团队管理**。\
例如，如果你在多个页面中看到相同的 **Google Analytics ID** 或 **Adsense ID**。

以下页面和工具可以让你按这些 tracker 等信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（根据共享的 analytics/trackers 查找相关站点）
- [**StackScan**](https://www.stackscan.com) - **免费层级**（Web 和 API）。可以根据任意已提供的资产进行关联查询，而不只是 tracker ID：例如脚本路径、自托管 bundle 名称，或资产加载所在的主机，并返回包含该资产的所有站点。

API 会返回单个域名的技术栈，这有助于确认候选资产是否属于同一资产范围：

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

返回每种检测到的技术及其类别。目前，资产 pivoting 仅支持 Web，API 则支持按域名查询。

### **Favicon**

你知道吗？我们可以通过查找具有相同 favicon 图标哈希的域名和子域名，来发现与目标相关的域名和子域名。[favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 是由 [@m4ll0k2](https://twitter.com/m4ll0k2) 编写的工具，正是用来做这件事的。下面介绍如何使用它：

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![用于发现共享相同 favicon 哈希的域名的 Favihash 结果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 哈希的域名。

![用于发现具有相同 favicon 哈希的域名的 favihash 输出](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

将已知的 favicon 哈希作为 Shodan 或 FOFA 的 pivot，以查找其他暴露的同类技术实例。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

以下是**计算网站 favicon hash**的方法（对 **base64 编码**后的 favicon 字节执行 MMH3）：

```python
import mmh3
import requests
import codecs

def fav_hash(url):
    response = requests.get(url, timeout=10)
    favicon = codecs.encode(response.content, "base64")
    fhash = mmh3.hash(favicon)
    print(f"{url} : {fhash}")
    return fhash
```

你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) 批量获取 favicon hashes，然后在 Shodan/Censys 中进行 pivot。

将 favicon fingerprints 视为线索，并结合周边信号进行验证。<sup>[[3]](#references)[[4]](#references)</sup>

- **将 hash 视为指示器，而非证据**：MMH3 简洁高效；但可能出现碰撞、图标复用和故意伪造。
- **不要只探测** `/favicon.ico`：检查 framework/build 路径、manifest 文件、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、内嵌 data URL，以及 HTML `<link rel="icon">` 标签。
- **静态资源可能在 WAF/SSO/IdP 控制后仍可访问**：直接请求图标，并查看 `ETag`、`Last-Modified`、重定向和缓存 headers。
- **结合周边信号验证匹配结果**：比较标题、HTML/body hash、headers、TLS 证书的 subjects/SANs、产品组件和开放端口。
- **按 HTML/body hash 聚类**：模板一致会增强指纹可信度；模板混杂则可能表明图标通用或被多个站点共享。
- **如果某个 hash 出现在互不相关的 signatures、端口和产品中，应将其视为潜在的 honeypot 或占位图标。**
- **对于存在歧义的目标，将真实页面与不存在的路径进行比较**，例如 `/_favicon_probe_<8-hex>`；相同的托管或停放页面响应可能解释图标为何相同。
- **通过 Nuclei detection rules 或将 favicon hashes 映射到产品和 CPE 的公开数据集来启动初步分类。**
- **注意以 IP 为中心的覆盖盲区**：CDN 前置、SNI 路由、anycast 和仅限域名的攻击面可能不会出现在 Shodan 类数据集中。

### **版权 / 独特字符串**

在网页中搜索**可能被同一组织下不同网站共享的字符串**。**版权字符串**就是一个很好的例子。然后在 **Google**、其他**浏览器**甚至 **Shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT 时间**

常见做法是设置一个 cron job，例如

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

以便同时续期服务器上的所有证书。关联证书时间戳或 certificate transparency 日志位置，可以发现相关域名。<sup>[[6]](#references)</sup>

也可以直接使用 **certificate transparency** 日志：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 邮件 DMARC 信息

你可以使用 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这类网站，或使用 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这类工具，查找**共享相同 DMARC 信息的域名和子域名**。\
其他实用工具包括 [**spoofcheck**](https://github.com/BishopFox/spoofcheck) 和 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

废弃的 A 记录可能会在云服务提供商重新分配 IP 后变得可访问。文中引用的研究展示了一种机会式工作流程：创建一个实例，并将其地址与被动 DNS 数据关联起来；仅在授权范围内测试接管场景。<sup>[[7]](#references)</sup>

### **其他方法**

每当发现新域名时，都应重复适用的发现路径：每个结果都可能揭示更多证书名称、被动 DNS 关系、favicon 匹配项，以及从初始种子中无法看到的组织标识符。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

你已经知道拥有该 IP 地址段的组织名称。可以在 Shodan 中使用以下数据进行搜索：`org:"Tesla, Inc."` 检查发现的主机，查看其 TLS 证书中是否有新的、意料之外的域名。

你可以访问主网页的 **TLS 证书**，获取**组织名称**，然后使用过滤器 `ssl:"Tesla Motors"`，在 **Shodan** 已知的所有网页的 **TLS 证书**中搜索该名称；也可以使用 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 之类的工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一款用于查找与主域名**相关的域名**及其**子域名**的工具，非常出色。

**被动 DNS / 历史 DNS**

被动 DNS 数据非常适合查找**仍可解析或可被接管的旧记录和遗忘的记录**。可以查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **寻找漏洞**

检查是否存在 [域名接管](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)的可能。可能有公司**正在使用某个域名**，但**已经失去该域名的所有权**。如果价格足够便宜，就注册它，并通知该公司。

如果发现任何 **IP 与资产发现过程中已找到的 IP 不同的域名**，就应该执行**基本漏洞扫描**（使用 Nessus 或 OpenVAS），并进行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，使用 **nmap/masscan/shodan**。根据正在运行的服务，你可以在**本书中找到一些“攻击”它们的方法**。\
_注意，有时域名托管在客户不控制的 IP 上，因此不在范围内，请谨慎操作。_

## Subdomains

> 我们已经了解范围内的所有公司、每家公司的所有资产，以及与这些公司相关的所有域名。

现在该找出每个已发现域名的所有可能子域名了。

> [!TIP]
> 请注意，一些用于查找域名的工具和技术也能帮助查找子域名

### **DNS**

让我们尝试从 **DNS** 记录中获取**子域名**。还应该尝试 **Zone Transfer**（如果存在漏洞，应报告）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

如需了解涵盖基础设施、信誉、泄露记录以及子域名发现之外的信息补充的 API 和平台，请参阅[侦察与威胁情报 API 目录](reconnaissance-and-threat-intelligence-apis.md)。

从外部来源获取大量子域名是最快的方法。最常用的**工具**如下（配置 API keys 可获得更好的结果）：

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/OWASP/Amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Edu4rdSHL/findomain/)

```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```

- [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)

```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```

- [**assetfinder**](https://github.com/tomnomnom/assetfinder)

```bash
assetfinder --subs-only <domain>
```

- [**Sudomy**](https://github.com/Screetsec/Sudomy)

```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```

- [**vita**](https://github.com/junnlikestea/vita)

```
vita -d tesla.com
```

- [**theHarvester**](https://github.com/laramies/theHarvester)

```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```

还有一些**有趣的工具/API**，虽然并非专门用于查找子域名，但也可能有助于查找子域名，例如：

- [**IP.THC.ORG**](https://ip.thc.org) 免费 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**：**使用 API [https://sonar.omnisint.io](https://sonar.omnisint.io) 获取子域名

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**JLDC 免费 API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) 免费 API

```bash
# Get Domains from rapiddns free API
rapiddns(){
 curl -s "https://rapiddns.io/subdomain/$1?full=1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
rapiddns tesla.com
```

- [**https://crt.sh/**](https://crt.sh)

```bash
# Get Domains from crt free API
crt(){
 curl -s "https://crt.sh/?q=%25.$1" \
  | grep -oE "[\.a-zA-Z0-9-]+\.$1" \
  | sort -u
}
crt tesla.com
```

- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault's Open Threat Exchange、Wayback Machine 和 Common Crawl 获取指定域名的已知 URL。

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们会抓取网络上的 JS 文件，并从中提取子域名。

```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```

- [**Shodan**](https://www.shodan.io/)

```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```

- [**Censys 子域名查找器**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**securitytrails.com**](https://securitytrails.com/) 提供免费 API，可用于搜索子域名和 IP 历史记录
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

这个项目免费提供与 **bug-bounty programs 相关的所有子域名**。你也可以通过 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或者查看该项目使用的 scope：[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在此处查看许多此类工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试使用可能的子域名，对 DNS 服务器进行 brute-force，以发现新的**子域名**。

为此，你需要一些**常见的子域名字典，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

你还需要一些优质 DNS resolver 的 IP。要生成一份可信 DNS resolver 列表，可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载 resolver 列表，再使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 进行筛选。或者，你也可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具有：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是首个能有效执行 DNS brute-force 的工具。它速度很快，但容易产生误报。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster)：我认为这个工具只使用 1 个 resolver。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个用 go 编写的 `massdns` wrapper，可通过主动 bruteforce 枚举有效子域名，也可在处理通配符的同时解析子域名，并提供简便的输入输出支持。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns)：它也使用 `massdns`。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步暴力破解域名。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 第二轮 DNS Brute-Force

通过开放来源和暴力破解找到子域名后，可以生成这些子域名的变体，尝试发现更多子域名。以下工具可用于此目的：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**：**根据域名和子域名生成排列组合。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns)：根据域名和子域名生成排列组合。
  - 你可以在[**此处**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的 permutations **wordlist**。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**：**根据给定的域名和子域名生成排列组合。如果未指定 permutations 文件，gotator 将使用自带的文件。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名排列组合外，它还可以尝试解析这些子域名（但最好使用前面提到的工具）。
  - 你可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns 的排列组合 **wordlist**。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut)：另一个用于对子域名进行排列、变异和修改的工具。此工具会对结果进行 brute force（不支持 DNS 泛解析）。
  - 你可以[**在此处**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut permutations wordlist。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**：**根据域名和指定模式生成可能的新子域名，以尝试发现更多子域名。

#### 智能排列生成

- [**regulator**](https://github.com/cramppet/regulator)：从已发现的子域名中学习类似 regex 的模式，并生成待解析的候选名称。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一款子域名暴力破解模糊测试工具，结合了极其简单但有效的 DNS 响应引导算法。它利用提供的输入数据集（例如定制词表或历史 DNS/TLS 记录），准确地生成更多相关域名，并根据 DNS 扫描期间收集的信息不断循环扩展。

```
echo www | subzuf facebook.com
```

### **子域名发现工作流**

Trickest 工作流示例结合了 OSINT、DNS 暴力破解和排列组合阶段，实现可重复的子域名枚举。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / 虚拟主机**

如果你发现某个 IP 地址上有**一个或多个属于子域名的网页**，可以尝试通过在 **OSINT 来源**中查找指向该 IP 的域名，或在该 IP 上**暴力破解 VHost 域名**，来**发现该 IP 上其他带有网站的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 API** 查找 IP 上的 **VHosts**。

**Brute Force**

如果你怀疑某些子域名可能隐藏在 Web 服务器中，可以尝试对其进行暴力破解：

对于基于名称的虚拟主机，可以对 `Host` header 进行 fuzz，并使用 ffuf 的自动校准来过滤默认响应。<sup>[[2]](#references)</sup>

```bash
ffuf -u http://10.10.10.10 -H "Host: FUZZ.example.com" \
  -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -ac
```

```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```

> [!TIP]
> 使用此技术，你甚至可能能够访问内部/隐藏的 endpoints。

### **CORS Brute Force**

有时你会发现，只有在 _**Origin**_ header 中设置了有效的域名/子域名时，页面才会返回 _**Access-Control-Allow-Origin**_ header。在这些情况下，你可以滥用此行为来**发现**新的**子域名**。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

寻找 **subdomains** 时，留意它们是否 **指向**任何类型的 **bucket**；如果是，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，此时你已经知道 scope 内的所有域名，可以尝试[**对可能的 bucket 名称进行 brute force 并检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **监控**

你可以通过监控 **Certificate Transparency** 日志来监测域名是否创建了**新的 subdomains**，[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) 就能做到这一点。

### **寻找漏洞**

检查是否存在可能的 [**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何 **IP 与资产发现阶段已找到的 IP 不同的 subdomain**，应执行**基础漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时 subdomain 托管在不受客户控制的 IP 上，因此不在 scope 内，请务必小心。_

## IPs

在初始阶段，你可能已经**发现了一些 IP 范围、域名和 subdomains**。\
现在该**收集这些范围内的所有 IP**，以及**域名/subdomains 对应的 IP（通过 DNS 查询）**。

使用以下**免费 API** 服务，你还可以找到域名和 subdomains 曾经使用过的 **IP**。这些 IP 可能仍归客户所有（并可能帮助你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP 地址的域名。

### **寻找漏洞**

对**所有不属于 CDN 的 IP 执行 port scan**（因为你很可能在那里找不到任何有趣的东西）。在发现的运行服务中，你或许**能够找到漏洞**。

查找关于如何扫描主机的[**指南**](../pentesting-network/index.html)。

## Web 服务器搜寻

> 我们已经找到了所有公司及其资产，也掌握了 scope 内的 IP 范围、域名和 subdomains。现在该搜索 Web 服务器了。

在前面的步骤中，你可能已经对**发现的 IP 和域名进行了 recon**，因此或许**已经找到了所有可能的 Web 服务器**。不过，如果还没有，下面将介绍一些在 scope 内**快速搜索 Web 服务器的技巧**。

请注意，这些方法将**侧重于发现 Web 应用**，因此你还应执行**漏洞扫描**和 **port scan**（**如果 scope 允许**）。

使用 [**masscan 的快速方法**可在此处找到](../pentesting-network/index.html#http-port-discovery)，用于发现与 **Web** 服务器相关的**开放端口**。\
另一个用于查找 Web 服务器的便捷工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。只需传入域名列表，它们就会尝试连接 80 端口（http）和 443 端口（https）。此外，你还可以指定尝试其他端口：

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

现在，你已经发现了范围内的**所有 Web 服务器**（包括公司的 **IP**，以及所有**域名**和**子域名**），但你可能**不知道从哪里开始**。那么，我们就把事情简单化，先给它们全部截图。只要**查看**一下**主页**，你就能发现一些**奇怪**的端点，它们更**容易**存在**漏洞**。

要实现这个想法，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 扫描所有**截图**，判断哪些**可能包含漏洞**，哪些不太可能。

## Public Cloud Assets

要寻找属于某家公司的潜在云资产，你应该**先列出能够识别该公司的关键词**。例如，对于一家加密货币公司，你可以使用这些词：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

你还需要一些**bucket 中常用词**的词表：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，用这些词生成**排列组合**（更多信息请参见 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

有了生成的词表后，你可以使用 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，寻找 Cloud Assets 时，不应只关注 **AWS 中的 buckets**。

### **寻找漏洞**

如果你发现**开放的 bucket 或暴露的 cloud function**，应该**访问它们**，看看它们能提供什么，以及你是否能滥用它们。

## Emails

有了范围内的**域名**和**子域名**，你基本就具备了**开始查找电子邮件地址**所需的信息。以下是我认为最适合查找公司电子邮件地址的 **API** 和工具：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 配合 API 使用
- [**https://hunter.io/**](https://hunter.io/) 的 API（免费版）
- [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版）
- [**https://minelead.io/**](https://minelead.io/) 的 API（免费版）

### **寻找漏洞**

之后，电子邮件地址可以用来对 **Web 登录和认证服务**（例如 SSH）进行 **brute-force**。它们也可用于 **phishing**。此外，这些 API 还能提供更多关于电子邮件地址背后**个人的信息**，这对 phishing campaign 很有帮助。

## Credential Leaks

有了**域名**、**子域名**和**电子邮件地址**，你就可以开始查找过去泄露的、与这些电子邮件地址相关的凭据：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果你发现**有效的泄露凭据**，这会是一个很容易拿下的目标。

## Secrets Leaks

Credential leaks 通常与公司被黑有关，**敏感信息遭到泄露并被出售**。不过，公司也可能受到**其他泄露事件**的影响，而相关信息并未出现在这些数据库中：

### Github Leaks

凭据和 API 可能会泄露在**公司**的**公共仓库**中，也可能出现在为该公司工作的**员工**的公共仓库中。\
你可以使用工具 [**Leakos**](https://github.com/carlospolop/Leakos) **下载**某个**组织**及其**开发者**的所有**公共仓库**，并自动对其运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 还可以对传入的所有**文本**和 **URL** 运行 **gitleaks**，因为有时**网页中也包含 secrets**。

#### Github Dorks

查看 [GitHub dorks and leaks page](github-leaked-secrets.md)，了解可用于搜索该组织的潜在 **GitHub dorks**。

### Pastes Leaks

有时，攻击者或员工会在 paste 网站上**发布公司内容**。这些内容可能包含，也可能不包含**敏感信息**，但很值得搜索。\
你可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时搜索 80 多个 paste 网站。

### Google Dorks

虽然老套，但 Google dorks 一直很好用，可以查找**不应该暴露的信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数千条可能的查询，无法手动逐条运行。因此，你可以挑选最喜欢的 10 条，也可以使用 [**Gorks**](https://github.com/carlospolop/Gorks) **等工具一次性运行所有查询**。

_请注意，如果工具通过常规 Google 浏览器尝试运行整个数据库，最终也无法完成，因为 Google 很快就会封锁你。_

### **寻找漏洞**

如果你发现**有效泄露的**凭据或 API tokens，这会是一个很容易拿下的目标。

## Public Code Vulnerabilities

如果你发现该公司拥有**开源代码**，就可以对其进行**分析**并查找**漏洞**。

**根据语言不同**，可使用的**工具**也不同；请参见 [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) 列表。

还有一些免费的服务可以**扫描公共仓库**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters 发现的**大多数漏洞**都存在于 **Web 应用程序**中，因此我想在这里介绍一种 **Web 应用程序测试方法**。你可以[**在此处查看相关信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提一下 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节。虽然你不应指望它们能发现非常敏感的漏洞，但将它们集成到 **workflow** 中，获取一些初步的 Web 信息会很方便。

## Recapitulation

> 恭喜！到这里，你已经完成了**所有基础枚举**。没错，这只是基础，因为还可以进行更多枚举（稍后会介绍更多技巧）。

到目前为止，你已经：

1. 找到了范围内的所有**公司**
2. 找到了属于这些公司的所有**资产**（如果在范围内，还进行了漏洞扫描）
3. 找到了属于这些公司的所有**域名**
4. 找到了这些域名的所有**子域名**（是否存在 subdomain takeover？）
5. 找到了范围内的所有 **IP**（包括**来自 CDN 和非 CDN 的 IP**）。
6. 找到了所有 **Web 服务器**并为它们截了**图**（有没有值得深入调查的异常情况？）
7. 找到了可能属于该公司的所有**公共云资产**。
8. 找到了可能让你**轻松取得重大突破**的**电子邮件地址**、**凭据泄露**和 **secret 泄露**。
9. **对找到的所有网站进行 pentesting**

## **Full Recon Automatic Tools**

目前有不少工具可以针对给定范围执行上述部分操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有些旧了，也没有更新

## References

- [1] [Jason Haddix – Bug Hunter 方法论 v4.0：Recon 版](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB：Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – 关于 Favicons：从浏览器图标到攻击面情报](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – 将 favicon.ico 用于 BugBounties、OSINT 等](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – 通过针对 Certificate Transparency 的时间相关性攻击发现域名](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – 被动接管：揭示（并模拟）一场代价高昂的 Subdomain Takeover campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：一种独特的子域名枚举方法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 完整子域名发现工作流，第 1 部分](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 使用自动化 Trickest 工作流进行完整子域名 brute force 发现，第 2 部分](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash 输出截图](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
