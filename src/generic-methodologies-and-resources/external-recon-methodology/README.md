# 外部侦察方法论

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

如需查看其他 OSINT 和 Web 发现项目的分类列表，请参阅 [第三方工具和资源](../third-party-tools-and-resources.md#osint)。

> 有人告诉你，某家公司的所有资产都在范围内，你想弄清楚这家公司实际拥有哪些资产。

此阶段的目标是找出**母公司拥有的所有公司**，然后找出这些公司的所有**资产**。为此，我们将：<sup>[[1]](#references)</sup>

1. 查找母公司的收购记录，从而确定范围内的公司。
2. 查找每家公司的 ASN（如果有），从而确定各公司拥有的 IP 地址段。
3. 使用反向 whois 查询，查找与首个条目相关的其他条目（组织名称、域名等……），此过程可以递归进行。
4. 使用其他技术，例如通过 shodan 的 `org`和`ssl`筛选器搜索其他资产（`ssl`技巧也可以递归使用）。

如需了解从已解析子域名到 HTTP 爬取和端口发现的分阶段交接流程，请参阅 [渗透测试方法论](../pentesting-methodology.md#11-modern-recon-pipeline)。

### **收购**

首先，我们需要了解**母公司还拥有其他哪些公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**母公司，然后**点击**“**acquisitions**”。你会在那里看到被母公司收购的其他公司。\
另一种方法是访问母公司的 **Wikipedia** 页面并搜索 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR 文件**、**投资者关系**页面或当地公司注册机构（例如英国的 **Companies House**）。\
如需查询全球企业架构和子公司，可尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好，到这里你应该已经知道范围内的所有公司。接下来我们来看看如何查找它们的资产。

### **ASN**

自治系统编号（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给**自治系统**（AS）的**唯一编号**。\
**AS** 由一组 **IP 地址块**组成，这些地址块具有明确定义的外部网络访问策略，由单个组织管理，但也可能由多个运营商组成。

查明公司是否**分配了 ASN**，从而找出其**IP 地址段**，很有意义。对**范围**内的所有**主机**进行**漏洞测试**并**查找**这些 IP 中的**域名**也很有价值。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 中按公司**名称**、**IP** 或**域名**进行**搜索**。\
**根据公司所在地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（非洲）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北美）、** [**APNIC**](https://www.apnic.net) **（亚洲）、** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲）、** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。不过，可能所有**有用信息**（IP 地址段和 Whois）**都已经出现在第一个链接中。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)** 的** 枚举会在扫描结束时自动聚合并汇总 ASN。

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

你也可以使用 [ASNLookup](https://asnlookup.com/) 查找某个组织的 IP 范围，该服务提供有限的免费 API 额度。

### **查找漏洞**

此时我们已经知道**范围内的所有资产**，因此如果获得授权，你可以对所有主机运行一些**vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
此外，你也可以运行一些[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，**或者使用** Shodan、Censys 或 ZoomEye 等服务**查找**开放端口；**根据发现的情况，你应该**在本书中查找如何对可能运行的各种服务进行 pentest。\
**另外，值得一提的是，你还可以准备一些**默认的 username **和** password **列表，并尝试对服务进行** bruteforce，使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)。

## 域名

> 我们已经知道范围内的所有公司及其资产，现在是时候查找范围内的域名了。

_请注意，使用以下建议的技术也可以找到子域名，不应低估这些信息的价值。_

首先，你应该查找每家公司的**主域名**。例如，_Tesla Inc._ 的主域名是 _tesla.com_。

### **Reverse DNS**

既然你已经找到了这些域名的所有 IP 范围，就可以尝试对这些 **IP 执行 reverse dns lookups，以查找范围内的更多域名**。尝试使用受害者的 DNS 服务器，或一些知名的 DNS 服务器（1.1.1.1、8.8.8.8）。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

要使其生效，管理员必须手动启用 PTR。\
你也可以使用 [SecurityTrails](https://securitytrails.com/) 获取这些信息，不过历史 DNS 数据需要付费套餐。\
对于较大的范围，可以使用 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 等工具自动执行反向查询并丰富数据。

### **Reverse Whois (loop)**

在 **whois** 信息中，你可以找到许多有趣的**信息**，例如**组织名称**、**地址**、**电子邮件**、电话号码……但更有意思的是，如果使用其中任意字段进行**反向 whois 查询**，还可以发现**与该公司相关的更多资产**（例如其他出现相同电子邮件的 whois 注册记录）。\
你可以使用以下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **免费**（Web 和 API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com) - **免费** Web 界面；API 付费。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 付费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 非免费（仅提供 **100 次免费**查询）
- [https://www.domainiq.com/](https://www.domainiq.com) - 非免费
- [https://securitytrails.com/](https://securitytrails.com/) - 当前 DNS/子域名数据提供有限的免费 API 访问；历史查询和反向查询需要付费套餐。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 注册时赠送 500 个免费 API 额度；之后需付费。

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink)自动执行此任务（需要 whoxy API 密钥）。\
你也可以使用 [amass](https://github.com/owasp-amass/amass) 自动发现反向 whois 信息：`amass intel -d tesla.com -whois`

**请注意，每当发现一个新域名时，都可以使用此技术发现更多域名。**

### **Trackers**

如果在两个不同页面中发现**相同追踪器的相同 ID**，就可以推测这**两个页面**由**同一团队管理**。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或 **Adsense ID**。

有一些页面和工具可以让你按这些追踪器等信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **付费** Web 和 API 服务（[价格](https://www.stackscan.com/pricing)）；目前未提供免费套餐。可以从任何已提供的资产入手进行关联查询，而不只是追踪器 ID：例如脚本路径、自托管 bundle 名称，或加载资产的主机，并找出所有包含该资产的网站。

API 会返回单个域名的技术栈，这有助于确认候选资产是否属于同一资产范围：

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

返回每项检测到的技术及其类别。目前 Asset pivoting 仅支持 Web，API 支持按域名查询。

### **Favicon**

你知道吗？通过查找使用相同 favicon 图标哈希的站点，我们可以发现与目标相关的域名和子域名。[favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) 正是由 [@m4ll0k2](https://twitter.com/m4ll0k2) 编写的、用于实现这一功能的工具。下面介绍如何使用它：

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![用于发现共享相同 favicon 哈希的域名的 Favihash 结果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 图标哈希的域名。

![用于发现具有相同 favicon 哈希的域名的 favihash 输出](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

使用已知的 favicon 哈希作为 Shodan 或 FOFA 的 pivot，查找同一技术的其他暴露实例。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

这是计算网站 **favicon hash** 的方法（对 **base64 编码**后的 favicon 字节计算 MMH3）：

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

你还可以使用 [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）批量获取 favicon hashes，然后在 Shodan/Censys 中进行关联查询。

将 favicon 指纹视为线索，并结合周边信号进行验证。<sup>[[3]](#references)[[4]](#references)</sup>

- **将 hash 视为指示信息，而非证据**：MMH3 简洁高效，但可能发生碰撞、图标复用或蓄意伪造。
- **探测的路径不应局限于** `/favicon.ico`：检查框架/构建路径、manifest 文件、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、内联 data URL，以及 HTML `<link rel="icon">` 标签。
- **静态资源在 WAF/SSO/IdP 控制下仍可能可访问**：直接请求图标，并检查 `ETag`、`Last-Modified`、重定向和缓存头。
- **结合周边信号验证匹配结果**：比较标题、HTML/body hash、响应头、TLS 证书主题名/SAN、产品组件和开放端口。
- **按 HTML/body hash 进行聚类**：模板一致会增强指纹可信度；模板混杂则可能说明图标通用或被多个站点共用。
- **如果某个 hash 出现在互不相关的签名、端口和产品中，应考虑它可能是蜜罐或占位图标。**
- **对于难以判断的目标，将实际页面与不存在的路径进行比较**，例如 `/_favicon_probe_<8-hex>`；托管或停放页面的响应相同，可能说明它们共用了图标。
- **利用映射 favicon hashes 与产品及 CPE 的 Nuclei 检测规则或公开数据集进行初步筛查。**
- **注意以 IP 为中心的覆盖缺口**：CDN 前置、基于 SNI 路由、anycast 和仅限域名的攻击面可能不会出现在 Shodan 等数据集中。

### **版权 / 唯一字符串**

在网页中搜索**可能在同一组织的不同网站之间共用的字符串**。**版权字符串**就是一个很好的例子。然后在 **Google**、其他**浏览器**，甚至 **Shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT 时间**

常见做法是设置一个 cron job，例如

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

在服务器上同时续签所有证书。关联证书时间戳或 certificate-transparency 日志位置，可以发现相关域名。<sup>[[6]](#references)</sup>

也可以直接使用 **certificate transparency** 日志：

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 邮件 DMARC 信息

你可以使用 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这类网站，或使用 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这类工具，查找**共享相同 DMARC 信息的域名和子域名**。\
另一个有用的服务是 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

当云服务提供商重新分配 IP 时，废弃的 A 记录可能会变得可访问。引用的研究展示了一种机会式工作流：创建一个实例，并将其地址与 passive DNS 数据关联起来；仅在授权范围内测试 takeover 场景。<sup>[[7]](#references)</sup>

### **其他方法**

每当发现新域名时，都重复适用的发现路径：每个结果都可能揭示其他证书名称、passive-DNS 关系、favicon 匹配项和组织标识符，而这些信息可能无法从最初的种子中发现。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

如你所知，可以通过拥有该 IP 地址空间的组织名称在 Shodan 中搜索，例如：`org:"Tesla, Inc."`。检查找到的主机，看看 TLS 证书中是否出现了新的意外域名。

你可以查看主网页的 **TLS certificate**，获取 **Organisation name**，然后使用过滤器 `ssl:"Tesla Motors"` 在 **shodan** 已知的所有网页的 **TLS certificates** 中搜索该名称；或者使用 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 之类的工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一个用于查找与主域名**相关的域名**及其**子域名**的工具，非常强大。

**Passive DNS / 历史 DNS**

Passive DNS 数据非常适合查找**仍能解析或可能被 takeover 的旧记录和遗忘记录**。请查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **查找漏洞**

检查是否存在 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) 情况。某家公司可能**正在使用某个域名**，但**已失去其所有权**。只需注册该域名（如果价格足够低），然后通知该公司。

如果你发现任何**IP 与资产发现中已找到的 IP 不同的域名**，就应该进行**基础漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_请注意，有时域名托管在客户并不控制的 IP 上，因此不在范围内，请务必小心。_

## 子域名

> 我们知道范围内的所有公司、每家公司的所有资产，以及与这些公司相关的所有域名。

现在该找出每个已发现域名所有可能的子域名了。

> [!TIP]
> 请注意，一些用于查找域名的工具和技术也能帮助发现子域名

### **DNS**

让我们尝试从 **DNS** 记录中获取**子域名**。我们也应该尝试 **Zone Transfer**（如果存在漏洞，应报告）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

如需查找涵盖基础设施、声誉、泄露记录以及子域名发现以外的信息 enrichment 的 API 和平台，请参阅[侦察与威胁情报 API 目录](reconnaissance-and-threat-intelligence-apis.md)。

从外部来源搜索，是快速获取大量子域名的最佳方式。最常用的 **工具** 如下（配置 API keys 可获得更好的结果）：

- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

还有一些**其他有趣的工具/API**，虽然并非专门用于查找子域名，但也可能有所帮助，例如：

- [**IP.THC.ORG**](https://ip.thc.org) 免费 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 免费 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 获取给定域名的已知 URL。

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们会爬取网页以查找 JS 文件，并从中提取子域名。

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

- [**Censys 子域名查找工具**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) 提供有限的免费 API 访问权限，可查询当前 DNS 和子域名数据；历史 DNS/IP 数据需要付费方案。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

该项目**免费提供所有与漏洞赏金计划相关的子域名**。你也可以通过 [chaospy](https://github.com/Moaaz-0x/chaospy) 访问这些数据，或者访问该项目使用的范围：[https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

你可以在这里找到许多这类工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS 暴力破解**

尝试使用可能的子域名，对 DNS 服务器进行暴力破解，以发现新的**子域名**。

此操作需要一些**常见的子域名词表，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

此外，还需要可靠的 DNS 解析器 IP。要生成可信 DNS 解析器列表，可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载解析器，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 对其进行筛选。你也可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS 暴力破解的工具是：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够有效执行 DNS 暴力破解的工具。它速度很快，但容易产生误报。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster)：我认为这个工具只使用 1 个 resolver。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个用 Go 编写的 `massdns` 封装工具，可通过主动暴力破解枚举有效子域名，也可在处理通配符的同时解析子域名，并提供便捷的输入输出支持。

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

### 第二轮 DNS 暴力破解

通过开放来源和暴力破解找到子域名后，你可以生成已发现子域名的变体，尝试找到更多子域名。以下工具可用于此目的：

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**：**给定域名和子域名，生成排列组合。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns)：根据域名和子域名生成排列组合。
  - 你可以[**在这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的 **wordlist**。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**：**给定域名和子域名后生成排列。如果未指定排列文件，gotator 将使用自带的排列文件。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名排列组合外，它还可以尝试解析这些域名（但最好使用前面提到的工具）。
  - 可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns 的排列组合 **wordlist**。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut)：另一个用于对子域名进行排列、变异和修改的工具。此工具会对结果进行暴力枚举（不支持 DNS wildcard）。
  - 你可以[**在此处**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut 的排列词表。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**：**根据域名和指定模式**生成新的潜在子域名**，以尝试发现更多子域名。

#### 智能排列生成

- [**regulator**](https://github.com/cramppet/regulator)：从已发现的子域名中学习类似正则表达式的模式，并生成待解析的候选名称。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一款子域名暴力破解模糊测试工具，采用极其简单但有效的 DNS 响应引导算法。它利用提供的输入数据（如定制词表或历史 DNS/TLS 记录），准确生成更多相关域名，并根据 DNS 扫描过程中收集的信息，通过循环进一步扩展域名。

```
echo www | subzuf facebook.com
```

### **子域名发现工作流**

Trickest 工作流示例结合了 OSINT、DNS brute force 和排列组合阶段，以便可重复地进行子域名枚举。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / 虚拟主机**

如果你发现某个 IP 地址上有**一个或多个属于子域名的网页**，可以通过在 **OSINT 来源**中查找该 IP 上的域名，或对该 IP 上的 **VHost 域名进行 brute force**，尝试**发现该 IP 上其他带网站的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 API 查找 IP 中的一些 VHosts**。

**Brute Force**

如果你怀疑某个子域名可能隐藏在 Web 服务器中，可以尝试对其进行 brute force：

对于基于名称的 vhost，可以对 `Host` header 进行 fuzz，并使用 ffuf 的自动校准来过滤默认响应。<sup>[[2]](#references)</sup>

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
> 使用此技术，你甚至可能能够访问内部/隐藏端点。

### **CORS Brute Force**

有时，你会发现某些页面只有在 _**Origin**_ header 中设置了有效域名/子域名时，才会返回 _**Access-Control-Allow-Origin**_ header。在这些情况下，你可以利用这一行为来**发现**新的**子域名**。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

在查找**子域名**时，留意它们是否**指向**某种 **bucket**；如果是，请[**检查权限**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**。**\
另外，此时你已经知道范围内的所有域名，可以尝试[**暴力枚举可能的 bucket 名称并检查权限**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

### **监控**

你可以通过监控**Certificate Transparency** 日志，来监控某个域名是否创建了**新的子域名**。[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)就是这样做的。

### **查找漏洞**

检查是否存在可能的[**子域名接管**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果**子域名**指向某个 **S3 bucket**，请[**检查权限**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

如果你发现某个**子域名的 IP 与资产发现阶段已找到的 IP 不同**，应执行**基础漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_注意，有时子域名托管在不受客户控制的 IP 上，因此不在范围内，请谨慎操作。_

## IPs

在初始步骤中，你可能已经**找到了一些 IP 范围、域名和子域名**。\
现在该**收集这些范围内的所有 IP，以及域名/子域名对应的 IP（通过 DNS 查询）**了。

使用以下服务，你还可以找到**域名和子域名曾使用过的 IP**。这些 IP 可能仍归客户所有（也可能让你找到 [**CloudFlare 绕过方法**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**SecurityTrails**](https://securitytrails.com/)（历史 DNS/IP 数据需要付费套餐）

你还可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP 地址的域名。

### **查找漏洞**

**对所有不属于 CDN 的 IP 执行端口扫描**（因为你很可能在 CDN 上找不到有意思的东西）。你或许能在发现的运行中服务里**找到漏洞**。

**查找一份**[**关于如何扫描主机的指南**](../pentesting-network/index.html)。

## Web 服务器搜寻

> 我们已经找到了所有公司及其资产，也知道范围内的 IP 范围、域名和子域名。现在该搜索 Web 服务器了。

在前面的步骤中，你可能已经对发现的 **IP 和域名进行了侦察**，因此或许**已经找到了所有可能的 Web 服务器**。不过，如果还没有找到，下面将介绍一些**在范围内快速搜索 Web 服务器的技巧**。

请注意，这些方法主要面向 **Web 应用发现**，因此你也应执行**漏洞扫描**和**端口扫描**（**如果范围允许**）。

使用 [**masscan** 快速发现与 **Web** 服务器相关的**开放端口的方法见此处](../pentesting-network/index.html#http-port-discovery)。\
另一个适合查找 Web 服务器的工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。只需传入域名列表，它就会尝试连接 80 端口（http）和 443 端口（https）。此外，你还可以指定尝试其他端口：

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **截图**

现在你已经发现了范围内的**所有 Web 服务器**（包括公司所有 **IP**、**域名**和**子域名**），但你可能**不知道从哪里开始**。所以，我们把事情简单化，先给它们全部截图。只要**看一眼** **主页**，你就可能发现一些**奇怪**的端点，它们更**容易**存在**漏洞**。

要实现这个想法，可以使用 [**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 扫描所有**截图**，让它告诉你**哪些可能包含漏洞**，哪些不太可能。

## 公有云资产

要查找可能属于某公司的云资产，应该先准备一份**用于识别该公司的关键词列表**。例如，对于一家加密货币公司，可以使用 `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 等词。

你还需要一些**存储桶常用词**词表：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，用这些词生成**排列组合**（更多信息请参阅[**第二轮 DNS 暴力破解**](#second-dns-bruteforce-round)）。

生成词表后，可以使用 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，查找 Cloud Assets 时，不要只关注 AWS 中的存储桶。

### **查找漏洞**

如果发现**开放的存储桶或暴露的云函数**，应该**访问它们**，看看能获取到什么，以及是否可以滥用它们。

## 电子邮件

有了范围内的**域名**和**子域名**，基本上就具备了**开始查找电子邮件地址**所需的一切。以下是我用于查找公司电子邮件地址时效果最好的 **API** 和**工具**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 使用 API
- [**https://hunter.io/**](https://hunter.io/) 的 API（免费版）
- [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版）
- [**https://minelead.io/**](https://minelead.io/) 的 API（免费版）

### **查找漏洞**

之后可以用电子邮件地址对**Web 登录和身份验证服务**（例如 SSH）进行**暴力破解**。它们也可用于**钓鱼**。此外，这些 API 还能提供更多关于电子邮件地址背后**个人的信息**，这对钓鱼活动很有帮助。

## 凭据泄露

有了**域名**、**子域名**和**电子邮件地址**，就可以开始查找过去泄露的、属于这些电子邮件地址的凭据：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **查找漏洞**

如果发现**有效的泄露**凭据，这是一个很容易拿下的目标。

## Secrets 泄露

凭据泄露通常与公司遭到入侵有关，当时**敏感信息被泄露并出售**。不过，公司也可能受到**其他泄露事件**的影响，而相关信息并未出现在那些数据库中：

### Github 泄露

公司的**公开仓库**或该公司员工的**公开仓库**可能泄露凭据和 API。\
你可以使用 **[**Leakos**](https://github.com/carlospolop/Leakos)** 工具，**下载**某个**组织**及其**开发者**的所有**公开仓库**，并自动对其运行 [**gitleaks**](https://github.com/gitleaks/gitleaks)。

**Leakos** 还可以对传入的所有**文本**和**URL**运行 **gitleaks**，因为有时**网页也会包含 Secrets**。

#### Github Dorks

查看 [GitHub dorks 和泄露页面](github-leaked-secrets.md)，了解可用于搜索组织信息的潜在 **GitHub dorks**。

### Pastes 泄露

有时攻击者或员工会**将公司内容发布到 paste 站点**。这些内容可能包含也可能不包含**敏感信息**，但很值得搜索。\
你可以使用 [**Pastos**](https://github.com/carlospolop/Pastos) 工具，同时搜索 80 多个 paste 站点。

### Google Dorks

虽然老旧，但经典的 Google dorks 始终有助于查找**不该暴露的信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数千条可能的查询，无法手动逐条运行。因此，你可以挑选自己最喜欢的 10 条，也可以使用 [**Gorks**](https://github.com/carlospolop/Gorks) **之类的工具将它们全部运行一遍**。

_请注意，依赖常规 Google 浏览器运行整个数据库的工具永远也跑不完，因为 Google 很快就会封锁你。_

### **查找漏洞**

如果发现**有效的泄露**凭据或 API token，这是一个很容易拿下的目标。

## 公共代码漏洞

如果发现公司有**开源代码**，可以对其进行**分析**并查找**漏洞**。

**根据使用的语言**，可用的**工具**也不同；请参阅 [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) 列表。

还有一些免费服务可以**扫描公开仓库**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Web 渗透测试方法论**](../../network-services-pentesting/pentesting-web/index.html)

**大多数漏洞**都出现在**Web 应用程序**中，因此此时我想介绍一种 **Web 应用程序测试方法论**。你可以[**在此查看相关信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提一下 [**Web 自动化扫描器开源工具**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 一节。虽然不应指望它们能发现非常严重的漏洞，但将它们纳入**工作流以获取一些初步的 Web 信息**会很方便。

## 总结

> 恭喜！到这里，你已经完成了**所有基础枚举**。没错，这只是基础，因为还能进行更多枚举（后面会介绍更多技巧）。

你已经完成了：

1. 找出范围内的所有**公司**
2. 找出属于这些公司的所有**资产**（如果在范围内，还进行了漏洞扫描）
3. 找出属于这些公司的所有**域名**
4. 找出这些域名的所有**子域名**（是否存在子域名接管？）
5. 找出范围内所有的 **IP**（包括**来自 CDN** 和 **不来自 CDN** 的 IP）。
6. 找出所有 **Web 服务器**并为它们**截图**（有没有值得深入调查的异常情况？）
7. 找出可能属于该公司的所有**公有云资产**。
8. 找出可能让你**轻松拿下目标**的**电子邮件地址**、**凭据泄露**和 **Secrets 泄露**。
9. **对找到的所有 Web 站点进行渗透测试**

## **完整的自动化 Recon 工具**

目前有许多工具能够针对给定范围执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点旧，且未更新



## References

- [1] [Jason Haddix – Bug Hunter 方法论 v4.0：Recon 篇](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB：Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – 关于 Favicons：从浏览器图标到攻击面情报](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – 将 favicon.ico 武器化，用于 Bug Bounty、OSINT 及其他用途](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – 通过对 Certificate Transparency 进行时间关联攻击来发现域名](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – 被动接管：揭示（并模拟）一场高成本的子域名接管活动](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：一种独特的子域名枚举方法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 完整子域名发现工作流，第 1 部分](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 使用自动化 Trickest 工作流进行完整子域名暴力破解发现，第 2 部分](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash 输出截图](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
