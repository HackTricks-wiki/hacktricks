# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 所以，你得知某家公司所属的一切都在范围内，并且想弄清楚这家公司实际拥有的资产。

此阶段的目标是获取**主公司拥有的所有公司**，然后获取这些公司的所有**资产**。为此，我们将：<sup>[[1]](#references)</sup>

1. 找出主公司的收购对象，这将为我们提供范围内的公司。
2. 找出每家公司的 ASN（如果有），从而获得每家公司拥有的 IP 范围
3. 使用 reverse whois lookups 搜索与第一个条目相关的其他条目（组织名称、域名……）（此过程可以递归执行）
4. 使用其他技术，例如 shodan 的 `org` 和 `ssl` filters，搜索其他资产（`ssl` 技巧可以递归执行）。

### **Acquisitions**

首先，我们需要知道**主公司拥有的其他公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索** **主公司**，然后点击 "**acquisitions**"。在那里，你会看到被该公司收购的其他公司。\
另一种方法是访问主公司的 **Wikipedia** 页面，并搜索 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面或当地的企业注册机构（例如英国的 **Companies House**）。\
如需查看全球企业架构和子公司，可以尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好了，到这里你应该已经知道范围内的所有公司。接下来让我们弄清楚如何找到它们的资产。

### **ASNs**

自治系统编号（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给**自治系统**（AS）的**唯一编号**。\
一个 **AS** 由多个 **IP 地址块**组成，这些地址块具有明确定义的访问外部网络策略，并由单个组织管理，但可能由多个运营商组成。

查找**公司是否分配了 ASN** 很有意义，这样可以找到其 **IP ranges**。对**范围**内的所有**主机**执行**漏洞测试**，并**查找**这些 IP 中的**域名**也很有价值。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)**、** [**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 中按公司**名称**、**IP** 或**域名**进行**搜索**。\
**根据公司的所在地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（非洲）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北美）、** [**APNIC**](https://www.apnic.net) **（亚洲）、** [**LACNIC**](https://www.lacnic.net) **（拉丁美洲）、** [**RIPE NCC**](https://www.ripe.net) **（欧洲）。无论如何，可能所有**有用的信息**（IP ranges 和 Whois）都已经出现在第一个链接中。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**的**枚举会在扫描结束时自动汇总并总结 ASNs。
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
你还可以使用 [http://asnlookup.com/](http://asnlookup.com) 查找组织的 IP 范围（它提供免费 API）。\
你可以使用 [http://ipv4info.com/](http://ipv4info.com) 查找域名的 IP 和 ASN。

### **查找漏洞**

此时我们已经知道**范围内的所有资产**，因此，如果获得授权，你可以对所有主机运行一些**漏洞扫描器**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
此外，你还可以运行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，**或者使用 Shodan、Censys 或 ZoomEye 等服务来查找**开放端口，**并根据发现的结果**查看本书中有关如何对其中运行的各种可能服务执行 pentest 的内容。\
**另外，值得一提的是，你还可以准备一些**默认用户名**和**密码**列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行 **bruteforce**。

## 域名

> 我们已经知道范围内的所有公司及其资产，现在是时候查找范围内的域名了。

_请注意，在下面介绍的技术中，你也可以找到子域名，不应低估这些信息的价值。_

首先，你应该查找每家公司的**主域名**。例如，_Tesla Inc._ 的主域名是 _tesla.com_。

### **Reverse DNS**

由于你已经找到这些域名的所有 IP 范围，因此可以尝试对这些 **IP 执行 reverse dns lookups，以查找范围内的更多域名**。尝试使用受害者的某个 dns server，或某个知名的 dns server（1.1.1.1、8.8.8.8）。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
要使其生效，管理员必须手动启用 PTR。\
你也可以使用在线工具获取此信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于大型范围，使用 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 等工具，可以自动执行反向查询和信息 enriquecement。

### **Reverse Whois（循环）**

在 **whois** 中，你可以找到许多有趣的 **信息**，例如 **组织名称**、**地址**、**电子邮件**、电话号码等。但更有趣的是，如果你根据这些字段中的任意一个执行 **reverse whois lookups**，就可以找到**与该公司相关的更多资产**（例如其他包含相同电子邮件的 whois registries）。\
你可以使用以下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **免费**（Web 和 API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **免费**，API 不免费。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅提供 **100 次免费**搜索）
- [https://www.domainiq.com/](https://www.domainiq.com) - 不免费
- [https://securitytrails.com/](https://securitytrails.com/) - 不免费（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 不免费（API）

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 自动执行此任务（需要 whoxy API key）。\
你也可以使用 [amass](https://github.com/OWASP/Amass) 执行部分自动化的 reverse whois discovery：`amass intel -d tesla.com -whois`

**请注意，每当你发现一个新 domain 时，都可以使用此技术发现更多 domain names。**

### **Trackers**

如果在 2 个不同页面中发现**同一个 tracker 的相同 ID**，可以推断这**两个页面**由**同一个团队**管理。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些页面和工具可以让你根据这些 trackers 及其他信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（通过共享的 analytics/trackers 查找相关网站）
- [**StackScan**](https://www.stackscan.com) - **免费 tier**（Web 和 API）。可根据任意 served asset 进行 pivot，而不仅限于 tracker IDs：例如 script path、self-hosted bundle name，或 asset 加载来源的 host，并返回所有包含该 asset 的网站

该 API 返回单个 domain 的 stack，这对于确认某个候选 asset 是否属于同一 estate 很有用：
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
返回每个检测到的技术及其类别。目前 Asset pivoting 仅支持 Web，API 提供按域名查询的功能。

### **Favicon**

你知道吗？通过查找使用相同 favicon 图标哈希的目标，我们可以找到与目标相关的域名和子域名。这正是由 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作的 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具所实现的功能。使用方法如下：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![用于发现共享 favicon hash 的域名的 Favihash 结果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 图标 hash 的域名。

![用于发现具有相同 favicon hash 的域名的 favihash 输出](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

使用已知的 favicon hash 作为 Shodan 或 FOFA pivot，以查找同一技术的其他暴露实例。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
以下是计算网站 **favicon hash** 的方法（对 **base64-encoded** 的 favicon 字节执行 **MMH3**）：
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
你还可以使用 [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）批量获取 favicon hashes，然后在 Shodan/Censys 中进行 pivot。

将 favicon 指纹视为线索，并通过周边信号进行验证。<sup>[[3]](#references)[[4]](#references)</sup>

- **将 hash 视为指标，而非证据**：MMH3 很紧凑；可能存在碰撞、重复使用的图标以及蓄意 spoofing。
- **不要只探测** `/favicon.ico`：检查 framework/build 路径、manifest 文件、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、内联 data URLs，以及 HTML `<link rel="icon">` 标签。
- **Static assets 可能在 WAF/SSO/IdP 控制之后仍可访问**：直接请求图标，并检查 `ETag`、`Last-Modified`、重定向和缓存 headers。
- **使用周边信号验证匹配结果**：比较标题、HTML/body hash、headers、TLS 证书的 subjects/SANs、product components 和开放端口。
- **根据 HTML/body hash 进行聚类**：一致的 template 会增强指纹可信度；混合 template 则可能表明这是通用或共享图标。
- **将一个 hash 出现在无关的 signatures、ports 和 products 中视为潜在的 honeypot 或 placeholder。**
- **对于存在歧义的 targets，将真实页面与不存在的路径进行比较**，例如 `/_favicon_probe_<8-hex>`；匹配的 hosting 或 parking 响应可能解释共享图标的原因。
- **从 Nuclei detection rules 或 public datasets 开始 triage**，这些资源会将 favicon hashes 映射到 products 和 CPEs。
- **记住以 IP 为中心的 coverage gap**：由 CDN 前置、SNI 路由、anycast 以及仅基于 domain 的 surfaces 可能不会出现在类似 Shodan 的 datasets 中。

### **Copyright / Uniq string**

在网页中搜索**可能在同一组织的不同 webs 之间共享的 strings**。**copyright string** 就是一个很好的例子。然后在 **google**、其他**浏览器**，甚至 **shodan** 中搜索该 string：`shodan search http.html:"Copyright string"`

### **CRT Time**

常见的情况是存在一个 cron job，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
以便同时续订服务器上的所有证书。关联证书时间戳或 certificate-transparency 日志位置可以发现相关域名。<sup>[[6]](#references)</sup>

也可以直接使用 **certificate transparency** 日志：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### 邮件 DMARC 信息

你可以使用 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 之类的网站，或使用 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 之类的工具，查找**共享相同 dmarc 信息的域名和子域名**。\
其他有用的工具包括 [**spoofcheck**](https://github.com/BishopFox/spoofcheck) 和 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

当 cloud provider 重新分配 IP 时，一个被遗弃的 A 记录可能重新变得可访问。相关研究展示了一种机会式工作流：配置一个实例，并将其地址与 passive DNS 数据进行关联；仅在获得授权的范围内测试 takeover 场景。<sup>[[7]](#references)</sup>

### **其他方式**

每当发现新域名时，重复适用的发现 pivot：每个结果都可能暴露其他 certificate names、passive-DNS 关系、favicon matches 以及从原始 seed 中无法看到的组织标识符。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

由于你已经知道拥有该 IP 空间的组织名称，因此可以在 shodan 中使用以下数据进行搜索：`org:"Tesla, Inc."`。检查找到的主机，查看其 TLS certificate 中是否存在新的意外域名。

你可以访问主网页的 **TLS certificate**，获取 **Organisation name**，然后使用筛选器 `ssl:"Tesla Motors"`，在 **shodan** 已知的所有网页的 **TLS certificates** 中搜索该名称；也可以使用 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 等工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一个用于查找与主域名相关的**域名**及其**子域名**的工具，非常强大。

**Passive DNS / Historical DNS**

Passive DNS 数据非常适合查找仍能解析或可能被 takeover 的**旧记录和被遗忘的记录**。可以查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **查找漏洞**

检查是否存在 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。某些公司可能**正在使用某个域名**，但已经**失去其所有权**。只需注册该域名（如果价格足够低），然后通知该公司。

如果发现某个**域名的 IP 与资产发现阶段已找到的 IP 不同**，则应执行**基本漏洞扫描**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**端口扫描**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的服务，你可以在**本书中找到一些“攻击”这些服务的技巧**。\
_请注意，有时域名托管在客户不控制的 IP 中，因此不在范围内，请务必小心。_

## 子域名

> 我们知道范围内的所有公司、每家公司拥有的所有资产，以及与这些公司相关的所有域名。

现在是时候查找每个已发现域名的所有可能子域名了。

> [!TIP]
> 请注意，用于查找域名的某些工具和技术也可以帮助查找子域名

### **DNS**

让我们尝试从 **DNS** 记录中获取**子域名**。我们还应尝试 **Zone Transfer**（如果存在漏洞，应报告该问题）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名最快的方法是搜索外部来源。最常用的 **工具** 如下（配置 API 密钥可获得更好的结果）：

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
还有一些**其他有趣的工具/API**，即使它们并不直接专门用于查找 subdomains，也可能有助于查找 subdomains，例如：

- [**IP.THC.ORG**](https://ip.thc.org) free API
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
- [**gau**](https://github.com/lc/gau)**：**从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 中获取指定域名的已知 URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们会抓取 Web，查找 JS 文件，并从中提取子域名。
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
- [**securitytrails.com**](https://securitytrails.com/) 提供免费的 API，用于搜索子域名和 IP 历史记录
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目**免费提供所有与 bug-bounty programs 相关的子域名**。你也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或者直接访问该项目使用的 scope：[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到许多此类工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试使用可能的子域名名称对 DNS servers 执行 brute-force，以发现新的**子域名**。

执行此操作需要一些**常见的子域名 wordlists，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要优质 DNS resolvers 的 IP。要生成可信 DNS resolvers 列表，可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载 resolvers，然后使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 对其进行筛选。或者也可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具包括：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够有效执行 DNS brute-force 的工具。它速度非常快，但容易产生 false positives。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster)：我认为这个只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个围绕 `massdns` 的 wrapper，使用 go 编写，可通过 active bruteforce 枚举有效子域名，并支持处理 wildcard 的子域名解析以及便捷的输入输出。
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

在通过 open sources 和 brute-forcing 找到 subdomains 后，你可以生成已发现 subdomains 的变体，以尝试找到更多 subdomains。以下工具对此很有用：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**：**根据 domains 和 subdomains 生成 permutations。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns)：根据域名和子域名生成排列组合。
- 你可以在[**此处**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的排列组合 **wordlist**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**：**给定域名和子域名后生成排列组合。如果未指定 permutations 文件，gotator 将使用其自带的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名 permutations 外，还可以尝试解析它们（但最好使用前面注释掉的工具）。
- 你可以在[**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns permutations **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut)：另一个用于对 subdomains 执行 permutations、mutations 和 alteration 的工具。此工具会对结果进行 brute force（不支持 dns wildcard）。
- 你可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut permutations wordlist。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**：**根据域名，基于指定的模式**生成新的潜在子域名**，以尝试发现更多子域名。

#### 智能排列组合生成

- [**regulator**](https://github.com/cramppet/regulator)：从已发现的子域名中学习类似正则表达式的模式，并生成用于解析的候选名称。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**：**_subzuf_ 是一款子域名 brute-force 模糊测试工具，结合了极其简单但有效的 DNS 响应引导算法。它利用提供的输入数据集（例如定制 wordlist 或历史 DNS/TLS 记录），准确合成更多相关域名，并根据 DNS 扫描期间收集的信息，在循环中进一步扩展这些域名。
```
echo www | subzuf facebook.com
```
### **子域名发现工作流**

Trickest workflow 示例结合了 OSINT、DNS brute force 和 permutation 阶段，用于可重复的子域名枚举。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

如果你发现某个 IP 地址包含属于子域名的**一个或多个网页**，可以通过在 **OSINT sources** 中查找指向某个 IP 的域名，或对该 IP 上的 **VHost domain names** 进行 **brute-forcing**，来尝试**发现该 IP 上其他包含网页的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 APIs 来发现 IP 中的一些 VHosts**。

**Brute Force**

如果你怀疑某个子域名隐藏在 web server 中，可以尝试对其进行 brute force：

对于基于名称的 vhosts，可以 fuzz `Host` header，并使用 ffuf 的 auto-calibration 来过滤默认响应。<sup>[[2]](#references)</sup>
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
> 使用此技术，你甚至可能能够访问 internal/hidden endpoints。

### **CORS Brute Force**

有时你会发现，只有在 _**Origin**_ header 中设置有效的 domain/subdomain 时，页面才会返回 _**Access-Control-Allow-Origin**_ header。在这些场景中，你可以滥用此行为来**发现**新的 **subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在查找 **subdomains** 时，注意检查它是否 **pointing** 到某种类型的 **bucket**；如果是这种情况，请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，由于此时你已经知道 scope 内的所有 domains，可以尝试[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **Monitorization**

你可以通过监控 **Certificate Transparency** Logs，来监控某个 domain 是否创建了**新的 subdomains**，[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)就是这样做的。

### **Looking for vulnerabilities**

检查可能存在的[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果该 **subdomain** 指向某个 **S3 bucket**，请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何**与 assets discovery 中已发现 IP 不同的 subdomain**，应执行**basic vulnerability scan**（使用 Nessus 或 OpenVAS），并使用 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) 配合 **nmap/masscan/shodan** 进行扫描。根据正在运行的服务，你可以在**本书中找到一些“attack”这些服务的技巧**。\
_注意，有时 subdomain 托管在不受 client 控制的 IP 中，因此不属于 scope，请务必小心。_

## IPs

在初始步骤中，你可能已经**找到了一些 IP ranges、domains 和 subdomains**。\
现在是时候**收集这些 ranges 中的所有 IP**，以及 **domains/subdomains 的 IP（DNS queries）**。

使用以下**free apis**提供的服务，你还可以找到 **domains 和 subdomains 之前使用过的 IP**。这些 IP 可能仍归 client 所有（并且可能帮助你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**https://securitytrails.com/**](https://securitytrails.com/)

你还可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host)，检查指向某个特定 IP address 的 domains。

### **Looking for vulnerabilities**

**对所有不属于 CDN 的 IP 执行 port scan**（因为你很可能不会在那里发现任何有价值的内容）。在发现的运行中服务里，你可能**能够找到 vulnerabilities**。

**查找一份**关于如何扫描 hosts 的 [**guide**](../pentesting-network/index.html)**。**

## Web servers hunting

> 我们已经找到所有公司及其 assets，并且知道 scope 内的 IP ranges、domains 和 subdomains。现在是时候搜索 web servers 了。

在前面的步骤中，你可能已经对发现的 IPs 和 domains 执行了一些 **recon**，因此可能已经**找到了所有可能的 web servers**。但是，如果还没有找到，我们现在将介绍一些在 scope 内搜索 web servers 的**快速技巧**。

请注意，这些内容将**面向 web apps discovery**，因此你还应该执行 **vulnerability** 和 **port scanning**（前提是 scope **允许**）。

使用 [**masscan** 可以在这里找到](../pentesting-network/index.html#http-port-discovery)一种快速发现与 **web** servers 相关的**开放 ports**的方法。\
另一个用于查找 web servers 的友好工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入一个 domains 列表，它就会尝试连接 80（http）和 443（https）端口。此外，你还可以指定尝试其他 ports：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **截图**

现在你已经发现了范围内的**所有 Web 服务器**（包括公司 **IP** 以及所有**域名**和**子域名**），你可能**不知道从哪里开始**。所以，让我们把事情简单化，先对它们全部进行截图。只需**查看**一下**主页**，你就可能发现一些**奇怪**的端点，它们更可能**存在漏洞**。

要执行这个想法，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 遍历所有**截图**，判断其中**可能包含漏洞**的内容，以及不太可能包含漏洞的内容。

## Public Cloud Assets

为了发现属于某公司的潜在 cloud assets，你应该**先准备一个能够识别该公司的关键词列表**。例如，对于一家 crypto 公司，你可以使用以下词语：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

你还需要包含 **buckets 中常用词**的 wordlists：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词生成**排列组合**（有关更多信息，请查看 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

使用生成的 wordlists，你可以使用 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

记住，在寻找 Cloud Assets 时，不应**只寻找 AWS 中的 buckets**。

### **寻找漏洞**

如果你发现**开放的 buckets 或暴露的 cloud functions**，应该**访问它们**，尝试了解它们能提供什么，以及你是否可以滥用它们。

## Emails

有了范围内的**域名**和**子域名**，你基本上已经拥有了**开始搜索 emails 所需的一切**。以下是对我而言寻找公司 emails 最有效的 **APIs** 和**工具**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 使用 APIs
- [**https://hunter.io/**](https://hunter.io/) 的 API（免费版本）
- [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版本）
- [**https://minelead.io/**](https://minelead.io/) 的 API（免费版本）

### **寻找漏洞**

之后，Emails 会派上用场，可用于对 **web logins 和 auth services**（例如 SSH）进行 **brute-force**。此外，它们也是进行 **phishings** 所必需的。而且，这些 APIs 还会提供更多**有关 email 背后人员的信息**，这对 phishing campaign 很有用。

## Credential Leaks

利用这些**域名、****子域名**和**emails**，你可以开始寻找过去泄露的、属于这些 emails 的 credentials：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果你找到**有效的 leaked** credentials，这将是一次非常容易的胜利。

## Secrets Leaks

Credential leaks 通常与公司遭到 hack、**敏感信息被泄露并出售**有关。然而，公司也可能受到**其他 leaks** 的影响，而这些信息不在上述数据库中：

### Github Leaks

Credentials 和 APIs 可能会泄露在**公司的 public repositories** 中，也可能泄露在该 github 公司员工的 **users** 的 public repositories 中。\
你可以使用 [**Leakos**](https://github.com/carlospolop/Leakos) 这个**工具**，**下载**某个 **organization** 及其 **developers** 的所有 **public repos**，并自动对它们运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 还可以对传递给它的 **URLs** 所提供的全部 **text** 运行 **gitleaks**，因为有时 **web pages 中也包含 secrets**。

#### Github Dorks

查看 [GitHub dorks and leaks page](github-leaked-secrets.md)，了解可用于在该 organization 中搜索的潜在 **GitHub dorks**。

### Pastes Leaks

有时攻击者，或者普通员工，会将**公司内容发布到 paste site**。其中可能包含也可能不包含**敏感信息**，但搜索这些内容非常值得。\
你可以使用 [**Pastos**](https://github.com/carlospolop/Pastos) 工具，同时搜索 80 多个 paste sites。

### Google Dorks

老牌但非常有效的 google dorks 总是有助于发现**本不应暴露的信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数**千**条可能的查询，你无法手动逐一运行。因此，你可以选出自己最喜欢的 10 条，或者使用 [**Gorks**](https://github.com/carlospolop/Gorks) 之类的**工具**将它们**全部运行**。

_请注意，那些使用常规 Google 浏览器、试图运行整个数据库的工具永远不会结束，因为 google 很快就会将你拦截。_

### **寻找漏洞**

如果你找到**有效的 leaked** credentials 或 API tokens，这将是一次非常容易的胜利。

## Public Code Vulnerabilities

如果你发现公司拥有**开源代码**，就可以对其进行**分析**并搜索其中的**漏洞**。

**根据所使用的语言**，你可以使用不同的**工具**；请查看 [source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) 列表。

此外，还有一些免费服务可以**扫描 public repositories**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters 发现的**大多数漏洞**都存在于 **web applications** 中，因此在这一阶段，我想介绍一种 **web application testing methodology**，你可以[**在这里找到相关信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提到 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节，因为虽然你不应期待它们发现非常敏感的漏洞，但它们很适合部署到 **workflows** 中，以获得一些初始的 web 信息。

## Recapitulation

> 恭喜！到目前为止，你已经完成了**所有基本的 enumeration**。之所以说是基本的，是因为还可以进行更多 enumeration（稍后会介绍更多技巧）。

你已经完成了：

1. 找到了范围内的所有**公司**
2. 找到了属于这些公司的所有 **assets**（如果在范围内，还执行了一些 vuln scan）
3. 找到了属于这些公司的所有**域名**
4. 找到了这些域名的所有**子域名**（是否存在 subdomain takeover？）
5. 找到了范围内的所有 **IP**（来自 **CDNs** 和**不来自 CDNs** 的 IP）。
6. 找到了所有 **web servers** 并对它们进行了**截图**（是否存在值得深入查看的奇怪内容？）
7. 找到了属于该公司的所有潜在 **public cloud assets**。
8. 找到了可能让你**轻松取得重大成果**的 **emails**、**credentials leaks** 和 **secret leaks**。
9. 对你发现的所有 web 执行了 **Pentesting**

## **Full Recon Automatic Tools**

目前有许多工具可以针对给定范围执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 版本较旧且未更新

## References

- [1] [Jason Haddix – Bug Hunter's Methodology v4.0：Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB：Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – 关于 Favicons：从浏览器图标到 Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties、OSINT 及其他用途](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – 通过 Certificate Transparency 上的时间相关攻击发现域名](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：发现（并模拟）一次高成本的 Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：一种独特的 Subdomain Enumeration 方法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 完整的 Subdomain Discovery Workflow，第 1 部分](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 使用 Automated Trickest Workflow 进行完整的 Subdomain Brute Force Discovery，第 2 部分](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
