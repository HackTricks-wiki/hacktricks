# 外部 Recon 方法论

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 所以有人跟你说某公司的所有东西都在 scope 内，你想弄清楚这家公司到底拥有些什么。

此阶段的目标是获取所有被 **主公司拥有的公司**，然后收集这些公司的所有 **assets**。为此，我们将：

1. 找出主公司的收购记录，这会告诉我们 scope 内包含哪些公司。
2. 查找每家公司是否有 ASN（如果有），这会告诉我们每家公司拥有的 IP ranges。
3. 使用 reverse whois 查询来搜索与第一个实体相关的其他条目（组织名、域名等），这可以递归进行。
4. 使用其他技术，比如 shodan `org` 和 `ssl` 过滤器来搜索其他资产（`ssl` 技巧也可以递归进行）。

### **收购**

首先，我们需要知道 **主公司还拥有哪些其他公司**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**主公司，然后**点击**“acquisitions”。在那里你会看到主公司收购的其他公司。\
另一种方法是访问主公司的 **Wikipedia** 页面并查找 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面或本地公司注册处（例如英国的 **Companies House**）。\
对于全球的公司结构和子公司，请尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好的，到这一步你应该知道 scope 内的所有公司。接下来我们来找出它们的资产。

### **ASNs**

一个 autonomous system number（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给一个 autonomous system（**AS**）的 **唯一编号**。\
一个 **AS** 由一组 **IP addresses** 的 **blocks** 组成，这些地址对外网访问有明确的策略，由单一组织管理，但可能由多个运营者构成。

查明公司是否分配了任何 **ASN** 很有价值，这可以帮助找到其 **IP ranges**。对 scope 内的所有 **hosts** 执行 **vulnerability test** 并在这些 IP 中 **查找 domains** 通常很有意义。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) **中按公司名称、IP 或域名进行搜索。**\
**根据公司所在地区，下面这些链接也可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). 无论如何，很可能所有有用的信息（IP ranges 和 Whois）已经出现在第一个链接中。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration 会在 scan 结束时自动聚合并汇总 ASNs。
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **寻找漏洞**

At this point we know **所有在范围内的资产**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## 域名

> 我们知道范围内的所有公司及其资产，是时候找到范围内的域名了。

_请注意，在下面提出的技术中你也可以发现子域名，这些信息不应被低估。_

首先你应该查找每个公司的 **main domain**(s)。例如，对于 _Tesla Inc._ 来说，将是 _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs 来发现更多范围内的域名**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
你也可以使用在线工具获取此信息: [http://ptrarchive.com/](http://ptrarchive.com).\
对于大范围查询，像 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 这样的工具可用于自动化反向查找和信息丰富。

### **Reverse Whois (loop)**

在 **whois** 中可以找到很多有趣的 **信息**，例如 **organisation name**、**address**、**emails**、电话号码等……更有趣的是，如果你对这些字段中的任意字段执行 **reverse whois lookups**，就能发现 **更多与该公司相关的资产**（例如在其他 whois 注册记录中出现相同电子邮件的域名）。\
你可以使用如下在线工具：

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **免费** 网页，不是免费的 API。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 付费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 付费（仅**100 次免费**搜索）
- [https://www.domainiq.com/](https://www.domainiq.com) - 付费
- [https://securitytrails.com/](https://securitytrails.com/) - 付费（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 付费（API）

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 来自动化此任务（需要 whoxy API key）。\
你也可以使用 [amass](https://github.com/OWASP/Amass) 执行一些自动的 reverse whois 发现：`amass intel -d tesla.com -whois`

**注意：每次发现新域名时，你都可以使用该技术来发现更多域名。**

### **Trackers**

如果在两个不同页面中发现了相同追踪器的 **相同 ID**，可以推测这两个页面是由 **同一个团队** 管理的。\
例如，如果在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些网站和工具允许你按这些追踪器等进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (通过共享 analytics/trackers 查找相关站点)

### **Favicon**

你知道吗，我们可以通过查找相同的 favicon 图标 hash 来发现与目标相关的域名和子域名？这正是 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 作者 [@m4ll0k2](https://twitter.com/m4ll0k2) 所做的工具。下面是使用方法：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 将允许我们发现与目标具有相同 favicon icon hash 的域名。

此外，你也可以按照 [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) 中的说明，使用 favicon hash 来搜索技术。这意味着如果你知道某个 web 技术易受攻击版本的 **favicon 的 hash**，你可以在 shodan 中搜索并 **找到更多易受攻击的地方**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
下面展示如何计算网站的 **favicon hash**：
```python
import mmh3
import requests
import codecs

def fav_hash(url):
response = requests.get(url)
favicon = codecs.encode(response.content,"base64")
fhash = mmh3.hash(favicon)
print(f"{url} : {fhash}")
return fhash
```
你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx) 大规模获取 favicon hashes（`httpx -l targets.txt -favicon`），然后在 Shodan/Censys 中进行 pivot。

### **版权 / 唯一字符串**

在网页中搜索那些**可能在同一组织的不同网站之间共享的字符串**。**copyright string** 就是一个好例子。然后在 **google**、其他 **browsers** 或甚至在 **shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT Time**

通常会有一个像这样的 cron job：
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
以更新服务器上所有域名的证书。这意味着即使用于此操作的 CA 在 Validity time 中没有设置生成时间，仍然有可能在 certificate transparency 日志中**找到属于同一公司的域名**。\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

你可以使用像 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这样的网页或像 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这样的工具来查找**共享相同 dmarc 信息 的域名和子域**。\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

### **Passive Takeover**

显然，人们常把子域名指向属于云提供商的 IP，但有时会**丢失该 IP 地址却忘记删除 DNS 记录**。因此，只要在云（例如 Digital Ocean）**spawning a VM**，你实际上就会**接管一些子域名**。

[**This post**](https://kmsec.uk/blog/passive-takeover/) 解释了一个关于它的故事并提供了一个脚本，该脚本**spawns a VM in DigitalOcean**，**gets** 新机器的 **IPv4**，并**searches in Virustotal for subdomain records** 指向它。

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

如果你已经知道拥有该 IP 空间的组织名称，可以在 shodan 中按该信息搜索： `org:"Tesla, Inc."`。检查找到的主机的 TLS certificate 以发现新的意外域名。

你可以访问主网页的 **TLS certificate**，获取 **Organisation name**，然后使用过滤器 `ssl:"Tesla Motors"` 在 **shodan** 已知的所有网页的 **TLS certificates** 中搜索该名称，或使用像 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 这样的工具。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) 是一个查找与主域相关的**域名**及其**子域**的工具，非常棒。

**Passive DNS / Historical DNS**

Passive DNS 数据非常适合查找仍然解析或可被接管的**旧的和被遗忘的记录**。查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

检查一些 [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。也许某公司正在**使用某个域名**，但他们**丢失了所有权**。如果该域名价格合适，直接注册它并通知公司。

如果你发现任何**与资产发现中已找到的 IP 不同的域名**，你应该执行一个**基本漏洞扫描**（使用 Nessus 或 OpenVAS）以及一些 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) ，使用 **nmap/masscan/shodan**。根据运行的服务，你可以在**本书**中找到一些“攻击”它们的技巧。\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> 我们知道范围内所有公司、每个公司的所有资产以及与公司相关的所有域名。

现在是时候为每个已发现的域名找出所有可能的子域名。

> [!TIP]
> 注意：用于发现域名的一些工具和技术也可以用来发现子域名

### **DNS**

我们尝试从 **DNS** 记录中获取**子域名**。我们还应该尝试 **Zone Transfer**（如果存在漏洞，应予以报告）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量 subdomains 的最快方法是搜索外部来源。最常用的 **工具** 如下（为获得更好结果，请配置 API keys）：

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
还有 **其他有趣的工具/API**，即使它们并非专门用于发现子域，也可能有助于发现子域，例如：

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用 API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域名
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
- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault's Open Threat Exchange、Wayback Machine 和 Common Crawl 获取任意给定域名的已知 URL。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 他们抓取网页，查找 JS files 并从中提取 subdomains。
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
- [**Censys subdomain finder**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) 提供一个免费 API 用于搜索子域名和 IP 历史记录
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目免费提供与 bug-bounty programs 相关的所有子域名。你也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或直接查看该项目使用的 scope：[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到这些工具的比较： [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

我们尝试通过对 DNS 服务器进行暴力破解，使用可能的子域名来发现新的子域名。

为此操作你需要一些常用的子域名 wordlists，例如：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

以及一些可靠的 DNS resolver IP。要生成受信任的 DNS resolver 列表，你可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载 resolver 并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 进行过滤。或者直接使用： [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS 暴力破解 的工具包括：

- [**massdns**](https://github.com/blechschmidt/massdns): 这是第一个能有效进行 DNS 暴力破解 的工具。它非常快，但容易产生误报。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 我认为这个只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个基于 `massdns` 的包装器，使用 go 编写，允许你通过主动 bruteforce 枚举有效子域名，并解析子域名，具备通配符处理与简便的输入/输出支持。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步地对域名进行 brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮 DNS Brute-Force

在使用公开来源和 brute-forcing 找到子域名之后，你可以生成已发现子域名的变体以尝试发现更多。为此目的，有几个工具很有用：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 给定域名和子域名，生成变体。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 根据域名和子域名生成排列。
- 你可以在 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) 获取 goaltdns permutations **wordlist**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 对给定的 domains 和 subdomains 生成 permutations。如果未指定 permutations 文件，gotator 将使用其自带的一个。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名排列外，它也可以尝试解析它们（但最好使用之前提到的工具）。
- 你可以在 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) 获取 altdns 排列的 **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 另一个用于对 subdomains 执行 permutations、mutations 和 alteration 的工具。该工具会对结果进行 brute force（它不支持 dns wild card）。
- 你可以在 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) 获取 dmut permutations wordlist。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于 domain，它会根据指定的模式 **生成新的潜在 subdomains 名称**，以尝试发现更多 subdomains。

#### 智能排列生成

- [**regulator**](https://github.com/cramppet/regulator): 欲了解更多信息，请阅读此 [**post**](https://cramppet.github.io/regulator/index.html)，但它基本上会从 **discovered subdomains** 中提取 **主要部分** 并将它们混合以找到更多 subdomains。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个 subdomain brute-force fuzzer，结合了一个极其简单但有效的 DNS reponse-guided algorithm。它利用提供的输入数据集，比如定制的 wordlist 或历史的 DNS/TLS records，来准确合成更多对应的域名，并基于在 DNS scan 中收集到的信息循环地进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

查看我写的这篇博客文章，介绍如何使用 **Trickest workflows** 来 **automate the subdomain discovery**（从一个域），这样我就不需要在本地手动启动一堆工具：

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

如果你发现某个 IP 地址上包含属于子域的 **one or several web pages**，你可以尝试通过在 **OSINT sources** 中查找该 IP 上的域名，或者通过 **brute-forcing VHost domain names in that IP** 来 **find other subdomains with webs in that IP**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 APIs** 来发现一些 **VHosts in IPs using**。

**Brute Force**

如果你怀疑某个 subdomain 被隐藏在某个 web server 上，你可以尝试对其进行 brute force：
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

有时你会发现某些页面只有在 _**Origin**_ header 设置了有效的 domain/subdomain 时才返回 _**Access-Control-Allow-Origin**_ header。在这种情况下，你可以滥用这种行为来 **发现** 新的 **subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在寻找 **subdomains** 时，注意它是否**指向**任何类型的 **bucket**，如果是的话请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，既然此时你已经知道了范围内的所有域名，可以尝试[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **监控**

你可以通过监控 **Certificate Transparency** Logs 来**monitor** 某个域是否创建了 **new subdomains**，这正是 [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) 所做的。

### **寻找漏洞**

检查可能的 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，请[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何 **subdomain with an IP different** 于在资产发现中已找到的那些 IP，应对其执行 **basic vulnerability scan**（使用 Nessus 或 OpenVAS）以及使用 **nmap/masscan/shodan** 进行一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据运行的服务，你可以在**本书**中找到一些“攻击”它们的技巧。\
_注意：有时 subdomain 托管在客户不控制的 IP 上，因此不在范围内，需谨慎。_

## IPs

在初始阶段你可能已经**找到了若干 IP ranges、domains 和 subdomains**。\
现在是时候**从那些网段收集所有 IP**，以及为**domains/subdomains（DNS 查询）**收集 IP 了。

使用下面这些**free apis** 的服务，你还可以找到**域名和子域名之前使用过的 IP**。这些 IP 可能仍然属于客户（并可能允许你找到[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 来检查指向特定 IP 的域名。

### **寻找漏洞**

对所有不属于 CDNs 的 IP 执行 **Port scan**（因为你很可能在 CDN 上找不到有价值的信息）。在发现的运行服务中，你可能**能够找到漏洞**。

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web 服务器搜索

> 我们已经找到了所有公司及其资产，并且知道范围内的 IP ranges、domains 和 subdomains。现在是时候去搜索 web servers 了。

在之前的步骤中，你可能已经对发现的 IP 和域名进行了部分 **recon**，因此可能已经发现了所有可能的 web servers。然而，如果还没有，我们现在将看到一些在范围内快速搜索 web servers 的技巧。

请注意，这些方法将**面向 web apps discovery**，所以你也应当对这些目标执行**vulnerability** 和 **port scanning**（**如果范围允许**）。

一个使用 [**masscan** can be found here](../pentesting-network/index.html#http-port-discovery) 的**快速方法**，用于发现与 **web** 服务器相关的**开放端口**。\
另一个用于查找 web servers 的友好工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入一个域名列表，它会尝试连接端口 80 (http) 和 443 (https)。此外，你还可以指定尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

现在你已经发现了范围内存在的**所有 web servers**（在公司的 **IPs** 以及所有 **domains** 和 **subdomains** 中），你可能**不知道从哪里开始**。所以，简单起见，先对所有这些目标进行截图。仅仅通过**查看**首页就可能发现一些更**奇怪**的端点，这些端点更**容易**存在**vulnerabilities**。

要实现这个想法，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 或者 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 对所有的**screenshots**进行自动化筛查，告诉你哪些**很可能包含漏洞**，哪些不是。

## Public Cloud Assets

为了查找可能属于某公司的云资产，你应该**从识别该公司的关键词列表开始**。例如，对于一家 crypto 公司，你可能会使用诸如："crypto", "wallet", "dao", "<domain_name>", <"subdomain_names"> 这样的词。

你还需要包含**常见 bucket 用词**的 wordlists：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，用这些词生成**permutations**（更多信息请查看 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

用生成的 wordlists，你可以使用诸如 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**

记住，在寻找 Cloud Assets 时，你应该 l**ook for more than just buckets in AWS**。

### **Looking for vulnerabilities**

如果你发现了比如 **open buckets 或 cloud functions exposed**，你应该**访问它们**并尝试查看它们能给你提供什么，以及你是否可以滥用它们。

## Emails

有了范围内的 **domains** 和 **subdomains**，基本上就拥有了**开始搜索 emails 所需的一切**。以下是对我来说最有效的一些 **APIs** 和 **tools**，用于寻找公司邮箱：

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails 在后续用于**brute-force web logins and auth services**（例如 SSH）会很有用。此外，它们对于 **phishings** 也很必要。再者，这些 APIs 还会提供更多关于邮箱背后**人的信息**，这对于钓鱼活动很有帮助。

## Credential Leaks

有了 **domains,** **subdomains**, 和 **emails**，你可以开始查找过去与这些邮箱相关的被 leaked 的凭证：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

如果你发现 **valid leaked** 凭证，这是一个非常容易得到的胜利。

## Secrets Leaks

Credential leaks 与公司被攻破并且**sensitive information was leaked and sold** 的情况有关。然而，公司也可能受到其他类型的 leaks 的影响，这些信息并未出现在上述数据库中：

### Github Leaks

Credentials 和 APIs 可能会出现在该 **company** 或在该 github 公司工作的 **users** 的 **public repositories** 中。\
你可以使用 **tool** [**Leakos**](https://github.com/carlospolop/Leakos) 来**下载**某个 **organization** 及其 **developers** 的所有 **public repos**，并自动对其运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 也可用于对传入的所有 **text provided URLs** 运行 **gitleaks**，因为有时 **web pages** 也会包含 secrets。

#### Github Dorks

也请查看这个**页面**，寻找可能在你正在攻击的组织中搜索的潜在 **github dorks**：


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

有时攻击者或员工会在 paste 站点上**发布公司内容**。这些内容可能包含也可能不包含 **sensitive information**，但值得去检索。\
你可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时在超过 80 个 paste 站点中搜索。

### Google Dorks

老但实用的 google dorks 总能帮你找到一些**不该公开的信息**。问题在于 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 含有数**千**条可能的查询，你无法手动全部执行。所以，你可以选你最喜欢的 10 条，或者使用像 [**Gorks**](https://github.com/carlospolop/Gorks) 这样的**工具来运行它们全部**。

注意：那些试图通过普通 Google 浏览器运行整个数据库的工具几乎不会成功，因为 Google 很快就会阻止你。

### **Looking for vulnerabilities**

如果你发现 **valid leaked** 凭证或 API tokens，这也是一个非常容易的胜利。

## Public Code Vulnerabilities

如果你发现公司有 **open-source code**，你可以**分析**它并搜索其中的 **vulnerabilities**。

**根据不同的语言**，可以使用不同的 **tools**：


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

也有一些免费服务允许你扫描 public repositories，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

大多数漏洞（the **majority of the vulnerabilities**）被 bug hunters 发现于 **web applications**，所以此处我想介绍一个 **web application testing methodology**，你可以在[**这里找到这些信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提到章节 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)，虽然你不应该期望它们能发现非常敏感的漏洞，但将它们纳入 **workflows 以获取一些初步的 web 信息** 是很有用的。

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

所以你已经：

1. 找到范围内的所有 **companies**
2. 找到这些公司所属的所有 **assets**（并在在范围内的情况下对其进行一些 vuln scan）
3. 找到这些公司的所有 **domains**
4. 找到这些 domains 的所有 **subdomains**（是否存在 subdomain takeover？）
5. 找到范围内的所有 **IPs**（来自 CDN 的以及 **not from CDNs** 的）
6. 找到所有 **web servers** 并对它们进行了 **screenshot**（有没有值得深入查看的异常？）
7. 找到可能属于该公司的所有 **potential public cloud assets**
8. **Emails**, **credentials leaks**, 和 **secret leaks**，这些可能会让你非常容易取得大胜利
9. **Pentesting** 你发现的所有 webs

## **Full Recon Automatic Tools**

有若干工具可以对给定范围执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
