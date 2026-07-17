# External Recon 方法论

{{#include ../../banners/hacktricks-training.md}}

## Assets 发现

> 所以，你得知某家公司所有相关内容都在 scope 内，现在想弄清楚这家公司实际拥有哪些资产。

此阶段的目标是获取**主公司的所有子公司**，然后获取这些公司的所有 **assets**。为此，我们将：

1. 查找主公司的收购情况，这将为我们提供 scope 内的公司。
2. 查找每家公司是否有 ASN，这将为我们提供每家公司拥有的 IP ranges。
3. 使用 reverse whois 查询来搜索与第一个条目相关的其他条目（组织名称、域名……）（此过程可以递归执行）。
4. 使用其他技术，例如 Shodan 的 `org` 和 `ssl` filters，来搜索其他 assets（`ssl` 技巧可以递归执行）。

### **收购情况**

首先，我们需要了解**主公司拥有的其他公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**主公司，然后点击 "**acquisitions**"。在那里，你会看到被主公司收购的其他公司。\
另一种方法是访问主公司的 **Wikipedia** 页面并搜索 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面或当地的公司注册机构（例如英国的 **Companies House**）。\
对于全球企业架构和子公司，可以尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好了，到这里你应该已经知道 scope 内的所有公司。接下来让我们了解如何查找它们的 assets。

### **ASNs**

自治系统编号（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给**自治系统**（AS）的**唯一编号**。\
一个 **AS** 由多个 **IP addresses blocks** 组成，这些地址块具有明确定义的访问外部网络策略，并由单个组织管理，但可能由多个运营方组成。

了解**公司是否分配了 ASN**，以便找到其 **IP ranges**，是很有意义的。针对 **scope** 内的所有 **hosts** 执行**漏洞测试**，并在这些 IP 中**查找 domains**，也很有价值。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 中按公司**名称**、**IP** 或**域名**进行**搜索**。\
**根据公司的所在地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、**[**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、**[**APNIC**](https://www.apnic.net) **（Asia）、**[**LACNIC**](https://www.lacnic.net) **（Latin America）、**[**RIPE NCC**](https://www.ripe.net) **（Europe）。不过，可能所有**有用信息**（IP ranges 和 Whois）在第一个链接中已经可以找到。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
此外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**的** enumeration 会在扫描结束时自动聚合并汇总 ASNs。
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
你还可以使用 [http://asnlookup.com/](http://asnlookup.com) 查找某个组织的 IP 范围（它提供免费 API）。\
你可以使用 [http://ipv4info.com/](http://ipv4info.com) 查找某个域名的 IP 和 ASN。

### **查找漏洞**

此时我们已经知道**范围内的所有资产**，因此如果获得授权，你可以对所有主机运行一些 **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
此外，你还可以运行一些 [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，**或者使用** Shodan、Censys 或 ZoomEye 等服务，**查找**开放端口；**根据发现的内容，你应该**查看本书中关于如何对多个可能运行的服务进行 pentest 的章节。\
**另外，值得一提的是，你还可以准备一些**默认用户名**和**密码**列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行 **bruteforce**。

## 域名

> 我们已经知道范围内的所有公司及其资产，现在是时候查找范围内的域名了。

_请注意，在以下提出的技术中，你还可以找到子域名，因此不应低估这些信息的价值。_

首先，你应该查找每家公司**主要域名**。例如，对于 _Tesla Inc._，其域名是 _tesla.com_。

### **Reverse DNS**

由于你已经找到了这些域名的所有 IP 范围，因此可以尝试对这些 **IPs 执行 reverse dns lookups**，以**查找范围内的更多域名**。尝试使用受害者的某个 dns server，或者使用某个知名的 dns server（1.1.1.1、8.8.8.8）。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
要使其正常工作，administrator 必须手动启用 PTR。\
你也可以使用在线工具获取此信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于大型范围，可以使用 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 等工具，自动执行 reverse lookups 和 enrichment。

### **Reverse Whois (loop)**

在 **whois** 中，你可以找到许多有趣的 **information**，例如 **organisation name**、**address**、**emails**、phone numbers 等。但更有趣的是，如果你通过这些字段中的任意一个执行 **reverse whois lookups**，就可以找到**与该公司相关的更多资产**（例如其他出现相同 email 的 whois registries）。\
你可以使用以下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **Free**（Web 和 API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web **Free**，API 不免费。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅提供 **100 free** searches）
- [https://www.domainiq.com/](https://www.domainiq.com) - 不免费
- [https://securitytrails.com/](https://securitytrails.com/) - 不免费（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 不免费（API）

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 自动化此任务（需要 whoxy API key）。\
你还可以使用 [amass](https://github.com/OWASP/Amass) 执行一些自动化的 reverse whois discovery：`amass intel -d tesla.com -whois`

**请注意，每次发现新 domain 时，都可以使用此技术发现更多 domain names。**

### **Trackers**

如果在两个不同的页面中发现**同一 tracker 的相同 ID**，则可以推测这**两个页面**由**同一个团队管理**。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些页面和工具可以让你通过这些 trackers 及其他信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（通过共享的 analytics/trackers 查找相关网站）

### **Favicon**

你是否知道，通过查找具有相同 favicon icon hash 的 domain 和 subdomain，我们可以发现与目标相关的 domain 和 subdomain？这正是由 [@m4ll0k2](https://twitter.com/m4ll0k2) 编写的 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具所实现的功能。以下是使用方法：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 发现具有相同 favicon 图标哈希的域名](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 图标哈希的域名。

此外，你还可以使用 favicon 哈希搜索技术，具体方法如[**这篇博客文章**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)中所述。这意味着，如果你知道**某个存在漏洞的 web 技术版本的 favicon 哈希**，就可以在 shodan 中搜索，从而**找到更多存在漏洞的目标**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
这就是如何**计算网站的 favicon hash**（对 favicon 字节进行**base64-encoded**后计算 MMH3）：
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

使用 favicon fingerprints 时，以下事项值得牢记：

- **将 hash 视为 indicator，而非 proof**：MMH3 很紧凑，可能发生 collisions；operators 也可以替换 favicons，或故意复用具有误导性的图标。
- **探测范围不要局限于** `/favicon.ico`：许多产品会通过 framework/build 路径或 `manifest.json`、`site.webmanifest`、`browserconfig.xml`、`apple-touch-icon*`、内联 `data:` URLs 或 HTML `<link rel="icon">` tags 暴露图标。路径本身也可以用于识别 product family。
- **应用不可访问时，静态文件通常仍可访问**：WAF/SSO/IdP controls 可能保护 dynamic routes，但仍会暴露静态图标。始终直接请求 favicon，并检查 `ETag`、`Last-Modified`、redirects 和 cache headers，以寻找较弱的版本/build hints。
- **使用周边 signals 验证 matches**：在认定某个 favicon 能识别某个产品之前，对比 title、HTML/body hash、headers、TLS certificate subjects/SANs、Shodan/Censys components 和开放端口。
- **大规模 pivot 时按 HTML/body hash 进行 clustering**：如果共享某个 favicon 的大多数 hosts 最终归为同一个 page template，则该 fingerprint 更可靠；如果相同 hash 分裂为许多互不相关的 templates，应优先标记为 "generic/shared/honeypot"，而不是某个产品。
- **Honeypot heuristic**：如果同一个 favicon hash 出现在许多互不相关的 HTML signatures、随机端口和相互冲突的产品中，应将其视为可能的 honeypot 或 generic placeholder，而不是实际的产品 fingerprint。
- **对有歧义的 targets 使用 404 probe**：在 browser 中获取一个真实页面和一个不存在的路径，例如 `/_favicon_probe_<8-hex>`。匹配的 hosting-provider/parking responses 通常比真实的产品重叠更能解释共享 favicons。
- **从 detection rules 中建立 bootstrap mappings**：Nuclei templates 和公开的 favicon datasets 可以提供已知的 `favicon` ↔ `product` ↔ `CPE` mappings，在 CVE disclosures 后用于快速 triage。
- **Coverage caveat**：Shodan-style datasets 以 IP 为中心。CDN-fronted、SNI-routed、anycast 和仅基于 domain 的 surfaces 可能被低估，因此较低的 hit count **并不**意味着现实中的部署规模较小。

### **Copyright / Uniq string**

在网页中搜索**可能在同一组织的不同 webs 之间共享的 strings**。**copyright string** 就是一个很好的例子。然后在 **google**、其他 **browsers**，甚至 **shodan** 中搜索该 string：`shodan search http.html:"Copyright string"`

### **CRT Time**

通常会有一个 cron job，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
以续订服务器上的所有 domain certificates。这意味着，即使所使用的 CA 没有在 Validity time 中设置生成时间，也可以**在 certificate transparency logs 中找到属于同一公司的 domains**。\
查看此[**writeup 以获取更多信息**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)。

也可以直接使用 **certificate transparency** logs：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC 信息

你可以使用 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这样的网站，或使用 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这样的工具，来查找**共享相同 dmarc 信息的 domains 和 subdomain**。\
其他有用的工具包括 [**spoofcheck**](https://github.com/BishopFox/spoofcheck) 和 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

显然，人们经常会将 subdomains 分配给属于 cloud providers 的 IP，并在某个时候**失去该 IP 地址，却忘记删除 DNS record**。因此，只需在 cloud 中**spawning 一个 VM**（例如 Digital Ocean），实际上就能**接管某些 subdomains**。

[**这篇文章**](https://kmsec.uk/blog/passive-takeover/)介绍了相关案例，并提出了一个 script，该 script 会**在 DigitalOcean 中 spawning 一个 VM**，**获取**新机器的 **IPv4**，然后**在 Virustotal 中搜索**指向该地址的 subdomain records。

### **其他方式**

**注意，每次发现一个新 domain 时，都可以使用此技术发现更多 domain names。**

**Shodan**

如你所知，拥有该 IP space 的 organisation 名称。你可以在 shodan 中使用以下数据进行搜索：`org:"Tesla, Inc."`。检查找到的 hosts，查看 TLS certificate 中是否存在新的、意外的 domains。

你可以访问主页的 **TLS certificate**，获取 **Organisation name**，然后使用过滤器 `ssl:"Tesla Motors"` 在 **shodan** 已知的所有网页的 **TLS certificates** 中搜索该名称；也可以使用类似 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 的工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)是一个用于查找与主 domain **相关的 domains** 及其 **subdomains** 的工具，非常强大。

**Passive DNS / Historical DNS**

Passive DNS data 非常适合查找仍能解析或可能被接管的**旧的、被遗忘的 records**。可以查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **查找漏洞**

检查是否存在 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。可能某家公司**正在使用某个 domain**，但他们已经**失去了所有权**。只需注册它（如果价格足够低），然后通知该公司。

如果发现任何 **IP 不同于**资产发现阶段已找到的 IP 的 **domain**，应执行**基本的 vulnerability scan**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的 services，你可以在**本书中找到一些“攻击”它们的技巧**。\
_注意，有时该 domain 托管在不受 client 控制的 IP 中，因此不在 scope 内，请务必小心。_

## Subdomains

> 我们知道 scope 内的所有公司、每家公司拥有的所有 assets，以及与这些公司相关的所有 domains。

现在是时候查找每个已发现 domain 的所有可能的 subdomains 了。

> [!TIP]
> 注意，一些用于查找 domains 的 tools 和 techniques 也可以帮助查找 subdomains

### **DNS**

让我们尝试从 **DNS** records 中获取 **subdomains**。我们还应该尝试 **Zone Transfer**（如果存在漏洞，应报告该问题）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名最快的方法是从外部来源中搜索。以下是最常用的 **工具**（为了获得更好的结果，请配置 API keys）：

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
还有一些**其他有趣的工具/API**，即使它们并不直接专门用于查找子域名，也可能对查找子域名有所帮助，例如：

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
- [**gau**](https://github.com/lc/gau)**：从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 获取指定域名的已知 URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：它们爬取 Web，查找 JS 文件，并从中提取子域名。
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
- [**securitytrails.com**](https://securitytrails.com/) 提供免费的 API，可用于搜索子域名和 IP 历史记录
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目**免费提供与 bug-bounty programs 相关的所有子域名**。你也可以通过 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，甚至可以访问该项目使用的 scope：[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到许多此类工具的**比较**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试使用可能的子域名名称，对 DNS servers 执行 brute-force，以发现新的**子域名**。

执行此操作需要一些**常见的子域名 wordlists，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要优质 DNS resolvers 的 IP。要生成可信 DNS resolvers 列表，可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载 resolvers，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 对其进行筛选。或者也可以使用：[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具有：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够有效执行 DNS brute-force 的工具。它的速度非常快，但容易产生 false positives。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster)：我认为这个只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个基于 go 编写的 `massdns` wrapper，支持通过 active bruteforce 枚举有效的 subdomains，并在处理 wildcard 的同时解析 subdomains，还提供便捷的输入输出支持。
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

在通过 open sources 和 Brute-Force 找到 subdomains 后，你可以生成已发现 subdomains 的变体，以尝试找到更多 subdomains。以下工具对此很有用：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**：**根据 domains 和 subdomains 生成排列组合。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns)：根据域名和子域名生成排列组合。
- 你可以在[**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的排列组合 **wordlist**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**：**给定域名和子域名后生成排列组合。如果未指定 permutations 文件，gotator 将使用自带的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns)：除了生成子域名排列组合外，还可以尝试解析它们（但最好使用前面注释掉的工具）。
- 你可以在[**此处**](https://github.com/infosec-au/altdns/blob/master/words.txt)获取 altdns 排列组合**字典**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut)：另一个用于对子域名执行排列、变异和修改的工具。此工具会对结果进行 brute force（不支持 DNS wildcard）。
- 你可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut permutations wordlist。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**：基于一个域名，根据指定的模式**生成新的潜在子域名**，以尝试发现更多子域名。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator)：更多信息请阅读这篇[**文章**](https://cramppet.github.io/regulator/index.html)，但它基本上会从**已发现的子域名**中提取**主要部分**并将其混合，以发现更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**：**_subzuf_ 是一个结合了极其简单但高效的 DNS 响应引导算法的 subdomain brute-force fuzzer。它利用提供的输入数据集（例如定制的 wordlist 或历史 DNS/TLS 记录），准确合成更多对应的域名，并根据 DNS 扫描期间收集的信息，在循环中进一步扩展这些域名。
```
echo www | subzuf facebook.com
```
### **子域名发现工作流**

查看我写的这篇博客，了解如何使用 **Trickest workflows 自动化进行子域名发现**，这样我就不需要在电脑上手动启动一堆工具了：


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

如果你发现某个 IP 地址包含属于子域名的**一个或多个网页**，可以尝试通过在 **OSINT sources** 中查找指向某个 IP 的域名，或者对该 IP 上的 **VHost domain names 进行 brute-forcing**，来**发现该 IP 上其他包含网页的子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 APIs 来发现 IP 中的 VHosts**。

**Brute Force**

如果你怀疑某个子域名隐藏在 web server 中，可以尝试对其进行 brute force：

当 **IP 重定向到 hostname**（基于名称的 vhosts）时，直接对 `Host` header 进行 fuzz，并让 ffuf **auto-calibrate**，从而突出显示与默认 vhost 不同的响应：
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
> 使用此技术，你甚至可能能够访问内部/隐藏 endpoints。

### **CORS Brute Force**

有时你会发现，只有在 _**Origin**_ header 中设置了有效的 domain/subdomain 时，页面才会返回 _**Access-Control-Allow-Origin**_ header。在这些场景中，你可以滥用此行为来**发现**新的 **subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在查找 **subdomains** 时，注意查看它是否 **pointing** 到某种 **bucket**；如果是，请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，由于此时你已经知道 scope 内的所有 domains，可以尝试[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **Monitorization**

可以通过监控 **Certificate Transparency** Logs，来 **monitor** 某个 domain 是否创建了 **new subdomains**，正如 [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)所做的那样。

### **Looking for vulnerabilities**

检查可能存在的 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果发现任何 **subdomain with an IP different** 于在 assets discovery 中已经找到的 IP，应执行 **basic vulnerability scan**（使用 Nessus 或 OpenVAS），并使用 **nmap/masscan/shodan** 进行一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据正在运行的 services，你可以在**本书中找到一些用于“attack”它们的技巧**。\
_注意，有时 subdomain 托管在不受 client 控制的 IP 中，因此不属于 scope，请务必小心。_

## IPs

在初始步骤中，你可能已经**找到了一些 IP ranges、domains 和 subdomains**。\
现在是时候**收集这些 ranges 中的所有 IP**，以及 **domains/subdomains（DNS queries）** 的 IP。

使用以下 **free apis** 提供的 services，你还可以找到 **domains 和 subdomains 过去使用过的 IPs**。这些 IP 可能仍归 client 所有（并且可能帮助你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP address 的 domains。

### **Looking for vulnerabilities**

对所有不属于 CDNs 的 IPs 执行 **port scan**（因为你很可能不会在那里发现任何有价值的内容）。在发现的 running services 中，你可能**能够找到 vulnerabilities**。

查找一份关于如何扫描 hosts 的[**guide**](../pentesting-network/index.html)。

## Web servers hunting

> 我们已经找到所有 companies 及其 assets，并且知道 scope 内的 IP ranges、domains 和 subdomains。现在是时候搜索 web servers 了。

在前面的步骤中，你可能已经对发现的 IPs 和 domains 执行了一些 **recon**，因此可能已经**找到所有可能的 web servers**。不过，如果还没有找到，我们现在将介绍一些在 scope 内搜索 web servers 的**快速技巧**。

请注意，这些内容将**面向 web apps discovery**，因此你也应执行 **vulnerability** 和 **port scanning**（如果 scope **允许**）。

使用 [**masscan** 可在此处找到发现与 **web** servers 相关的 **ports open** 的[**快速方法**](../pentesting-network/index.html#http-port-discovery)。另一个用于查找 web servers 的友好工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**，**[**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入一个 domains 列表，它就会尝试连接 port 80（http）和 443（https）。此外，你还可以指定尝试其他 ports：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **截图**

现在你已经发现了范围内**所有 Web 服务器**（公司 **IPs** 以及所有**域名**和**子域名**），但你可能**不知道从哪里开始**。因此，让我们把事情简单化，先对所有目标进行截图。只需**查看**它们的**主页**，你就可能发现一些**奇怪**的端点，这些端点更**容易**存在**漏洞**。

要执行上述操作，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 扫描所有**截图**，判断其中**哪些可能包含漏洞**，哪些不太可能。

## 公有云资产

为了寻找属于某家公司的潜在云资产，你应该**先准备一份能够识别该公司的关键词列表**。例如，对于一家 crypto 公司，你可以使用以下词语：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

你还需要包含**bucket 中常用词语**的字典：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些词语生成**排列组合**（更多信息请查看 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

有了生成的字典后，你可以使用 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

请记住，在寻找 Cloud Assets 时，不应只**寻找 AWS 中的 bucket**。

### **寻找漏洞**

如果你发现**开放的 bucket 或暴露的 cloud functions**，应该**访问它们**，尝试了解它们能提供什么，以及你是否能够滥用它们。

## 电子邮件

有了范围内的**域名**和**子域名**，基本上你已经具备了**开始搜索电子邮件地址**所需的一切。以下是对我来说寻找公司电子邮件地址效果最好的 **APIs** 和**工具**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 使用 APIs
- [**https://hunter.io/**](https://hunter.io/) 的 API（免费版本）
- [**https://app.snov.io/**](https://app.snov.io/) 的 API（免费版本）
- [**https://minelead.io/**](https://minelead.io/) 的 API（免费版本）

### **寻找漏洞**

之后，你可以使用这些电子邮件地址对 **web 登录和 auth services**（例如 SSH）进行**暴力破解**。此外，进行 **phishing** 时也需要它们。而且，这些 APIs 还会提供更多**关于电子邮件背后人员的信息**，这对 phishing 活动很有用。

## 凭据泄露

有了**域名、** **子域名**和**电子邮件地址**，你就可以开始寻找过去泄露的、属于这些电子邮件地址的凭据：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **寻找漏洞**

如果你找到**有效的泄露凭据**，这将是一个非常容易获得的成果。

## Secrets 泄露

Credential leaks 通常与公司遭到攻击、**敏感信息被泄露并出售**有关。然而，公司也可能受到**其他泄露事件**的影响，而这些信息并不在上述数据库中：

### Github 泄露

公司的**公开 repositories**，或者在该 github 公司工作的**用户**的公开 repositories 中，可能会泄露凭据和 APIs。\
你可以使用 [**Leakos**](https://github.com/carlospolop/Leakos) **工具**，下载某个**组织**及其**开发人员**的所有**公开 repos**，并自动对它们运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 还可以对传递给它的所有 **URLs** 中的**文本**运行 **gitleaks**，因为有时**网页也会包含 secrets**。

#### Github Dorks

你还应查看此**页面**，了解潜在的 **github dorks**，并在你正在攻击的组织中搜索它们：


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes 泄露

有时攻击者或普通员工会将**公司内容发布到 paste 网站**。其中可能包含也可能不包含**敏感信息**，但搜索这些内容非常有价值。\
你可以使用 [**Pastos**](https://github.com/carlospolop/Pastos) 工具，同时在 80 多个 paste 网站中进行搜索。

### Google Dorks

古老但有效的 Google dorks 始终有助于查找**不应暴露的信息**。唯一的问题是，[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数千条可能的查询，你无法手动逐一执行。因此，你可以选出自己最喜欢的 10 条，或者使用[**Gorks**](https://github.com/carlospolop/Gorks) **等工具一次性全部执行**。

_请注意，如果工具试图通过常规 Google 浏览器运行整个数据库，最终将永远无法完成，因为 Google 很快就会封锁你。_

### **寻找漏洞**

如果你找到**有效的泄露凭据**或 API tokens，这将是一个非常容易获得的成果。

## 公开代码漏洞

如果你发现该公司拥有**开源代码**，可以对其进行**分析**并寻找**漏洞**。

**根据所使用的语言**，你可以使用不同的**工具**：


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

此外，还有一些免费服务可以**扫描公开 repositories**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**bug hunters** 发现的**大多数漏洞**都存在于**Web 应用程序**中，因此此时我想介绍一种**Web 应用测试方法**，你可以[**在这里查看相关信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提到 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节。虽然不应期待它们发现非常敏感的漏洞，但它们非常适合加入 **workflows**，以获取一些初步的 Web 信息。

## 总结

> 恭喜！到这里，你已经完成了**所有基础枚举**。是的，这只是基础，因为还可以进行更多枚举（稍后会介绍更多技巧）。

你已经完成了以下工作：

1. 找到了范围内的所有**公司**
2. 找到了属于这些公司的所有**资产**（如果在范围内，还执行了一些 vuln scan）
3. 找到了属于这些公司的所有**域名**
4. 找到了这些域名的所有**子域名**（是否存在 subdomain takeover？）
5. 找到了范围内的所有 **IPs**（来自 **CDNs** 和**不来自 CDNs**）。
6. 找到了所有 **Web 服务器**并对其进行了**截图**（是否存在值得深入查看的奇怪内容？）
7. 找到了属于该公司的所有**潜在公有云资产**。
8. 找到了可能让你**轻松获得重大成果**的**电子邮件**、**credential leaks** 和 **secret leaks**。
9. **对找到的所有 Web 目标进行 Pentesting**

## **完整 Recon 自动化工具**

目前有许多工具可以针对给定范围执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有些老旧且未更新

## **参考资料**

- [**@Jhaddix**](https://twitter.com/Jhaddix) 的所有免费课程，例如 [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
