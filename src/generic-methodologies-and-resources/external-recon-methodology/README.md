# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 所以你被告知某个公司名下的一切都在 scope 里，而你想弄清楚这家公司实际拥有哪些东西。

这个阶段的目标是获取主公司拥有的所有**companies**，然后获取这些公司的所有**assets**。为此，我们要：

1. 找到主公司的 acquisitions，这会给我们 scope 内的 companies。
2. 找到每个公司的 ASN（如果有），这会给我们每个公司拥有的 IP ranges
3. 使用 reverse whois lookups 搜索与第一个条目相关的其他记录（organisation names、domains...）（这可以递归进行）
4. 使用其他技术，比如 shodan `org` 和 `ssl` filters 来搜索其他 assets（`ssl` trick 也可以递归进行）。

### **Acquisitions**

首先，我们需要知道主公司还拥有哪些**other companies**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**search** 主公司，然后点击 "**acquisitions**"。在那里你会看到被主公司收购的其他 companies。\
另一种方法是访问主公司的 **Wikipedia** 页面并搜索 **acquisitions**。\
对于 public companies，查看 **SEC/EDGAR filings**、**investor relations** 页面，或当地公司注册机构（例如英国的 **Companies House**）。\
对于全球 corporate trees 和 subsidiaries，可以试试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/))。

> 好的，到这里你应该已经知道 scope 内所有的 companies 了。接下来我们来看看如何找到它们的 assets。

### **ASNs**

autonomous system number（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给 **autonomous system**（AS）的一个**unique number**。\
一个 **AS** 由若干 **IP addresses** 的 **blocks** 组成，这些地址块对外部网络的访问策略有明确的定义，并由单一组织管理，但也可能由多个 operator 构成。

找到公司是否分配了任何 **ASN** 来获取它的 **IP ranges** 很有意思。最好对 scope 内所有 **hosts** 执行 **vulnerability test**，并在这些 IP 里 **look for domains**。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) 中按公司 **name**、**IP** 或 **domain** 进行 **search**。\
**根据公司的所在地区，这些链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** 已经出现在第一个链接里了。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
另外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration 会在扫描结束时自动聚合并总结 ASNs。
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
你也可以使用 [http://asnlookup.com/](http://asnlookup.com) 找到一个组织的 IP 范围（它有免费 API）。\
你可以使用 [http://ipv4info.com/](http://ipv4info.com) 找到一个域名的 IP 和 ASN。

### **Looking for vulnerabilities**

此时我们已经知道**范围内的所有资产**，所以如果被允许，你可以对所有主机运行一些**漏洞扫描器**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
另外，你也可以发起一些[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **或者使用** Shodan、Censys 或 ZoomEye **之类的服务来查找**开放端口**，并且根据你发现的内容，你应该**查看本书中关于如何对运行着这些服务的多种可能服务进行 pentest 的内容。\
**另外，值得一提的是，你还可以准备一些**默认用户名 **和** 密码 **列表，并尝试使用** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行 bruteforce。

## Domains

> 我们已经知道范围内的所有公司及其资产，现在是时候寻找范围内的域名了。

_请注意，在下面这些有目的的方法中，你也可以发现子域名，而这些信息不应被低估。_

首先，你应该寻找每家公司对应的**主域名**。例如，_Tesla Inc._ 的主域名是 _tesla.com_。

### **Reverse DNS**

既然你已经找到了这些域名的所有 IP 范围，你可以尝试对这些 **IPs** 执行 **reverse dns lookups**，以**找到范围内更多的域名**。尝试使用目标的一些 dns server，或者一些知名的 dns server（1.1.1.1、8.8.8.8）
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
对于这个方法能够生效，管理员必须手动启用 PTR。\
你也可以使用一个在线工具获取这些信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于大范围，像 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 这样的工具很适合自动化 reverse lookups 和 enrichment。

### **Reverse Whois (loop)**

在 **whois** 中，你可以找到很多有趣的 **信息**，比如 **组织名称**、**地址**、**emails**、电话号码... 但更有意思的是，如果你对这些字段中的任意一个执行 **reverse whois lookups**，你就能找到与该公司相关的 **更多资产**（例如，其他 whois 注册记录中出现了相同的 email）。\
你可以使用如下在线工具：

- [https://ip.thc.org/](https://ip.thc.org/) - **Free** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web, not free API.
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - Not free
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - Not Free (only **100 free** searches)
- [https://www.domainiq.com/](https://www.domainiq.com) - Not Free
- [https://securitytrails.com/](https://securitytrails.com/) - Not free (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - Not free (API)

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 来自动化这个任务（需要 whoxy API key）。\
你也可以使用 [amass](https://github.com/OWASP/Amass) 进行一些自动化 reverse whois discovery：`amass intel -d tesla.com -whois`

**请注意，每当你找到一个新域名时，都可以使用这个技术去发现更多 domain names。**

### **Trackers**

如果你在 2 个不同页面中找到 **同一个 tracker 的相同 ID**，你可以推断这 **两个页面** 是由 **同一团队** 管理的。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些页面和工具可以让你通过这些 trackers 以及更多信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

你知道吗，我们可以通过查看相同的 favicon 图标 hash，找到与目标相关的 domain names 和 subdomains？这正是 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具（由 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作）所做的事情。下面是使用方法：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以帮助我们发现与目标具有相同 favicon 图标 hash 的域名。

此外，你还可以像 [**这篇博客文章**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) 中解释的那样，使用 favicon hash 来搜索技术。这意味着，如果你知道某个 web tech 的 vulnerable version 的 favicon 的 **hash**，你就可以在 shodan 中搜索，并 **找到更多 vulnerable places**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是你可以**计算一个网站的 favicon hash**的方法：
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
你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）大规模获取 favicon hashes，然后在 Shodan/Censys 中继续 pivot。

### **Copyright / Uniq string**

在网页内容中搜索那些**可能会在同一组织的不同 web 中共享的字符串**。**copyright string** 就是一个很好的例子。然后在 **google**、其他 **browsers** 甚至 **shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT Time**

通常会有一个 cron job，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. This means that even if the CA used for this doesn't set the time it was generated in the Validity time, it's possible to **find domains belonging to the same company in the certificate transparency logs**.\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

你可以使用像 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这样的 web，或者像 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这样的工具，来查找**共享相同 dmarc 信息的 domains 和 subdomain**。\
其他有用的工具还有 [**spoofcheck**](https://github.com/BishopFox/spoofcheck) 和 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

Apparently is common for people to assign subdomains to IPs that belongs to cloud providers and at some point **lose that IP address but forget about removing the DNS record**. Therefore, just **spawning a VM** in a cloud (like Digital Ocean) you will be actually **taking over some subdomains(s)**.

[**This post**](https://kmsec.uk/blog/passive-takeover/) explains a store about it and propose a script that **spawns a VM in DigitalOcean**, **gets** the **IPv4** of the new machine, and **searches in Virustotal for subdomain records** pointing to it.

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

As you already know the name of the organisation owning the IP space. You can search by that data in shodan using: `org:"Tesla, Inc."` Check the found hosts for new unexpected domains in the TLS certificate.

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)is a tool that looks for **domains related** with a main domain and **subdomains** of them, pretty amazing.

**Passive DNS / Historical DNS**

Passive DNS data is great to find **old and forgotten records** that still resolve or that can be taken over. Look at:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

It's time to find all the possible subdomains of each found domain.

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

Let's try to get **subdomains** from the **DNS** records. We should also try for **Zone Transfer** (If vulnerable, you should report it).
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名最快的方法是在外部来源中搜索。最常用的 **tools** 如下（为获得更好的结果，请配置 API keys）：

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
还有一些**其他有趣的工具/API**，即使它们不是专门用于查找子域名，也可能有助于发现子域名，例如：

- [**IP.THC.ORG**](https://ip.thc.org) 免费 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用 API [https://sonar.omnisint.io](https://sonar.omnisint.io) 来获取子域名
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 获取任意给定域名的已知 URLs。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 它们会爬取 Web 寻找 JS 文件，并从中提取子域名。
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
- [**securitytrails.com**](https://securitytrails.com/) 有一个免费的 API 可用于搜索 subdomains 和 IP 历史记录
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

这个项目**免费**提供与 bug-bounty programs 相关的所有 subdomains。你也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，甚至可以访问该项目使用的 scope [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到许多这些工具的**比较**： [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试通过使用可能的 subdomain 名称来 brute-forcing DNS servers，从而找到新的 **subdomains**。

为此你将需要一些**常见的 subdomains wordlists，如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

以及一些优秀 DNS resolvers 的 IP。为了生成一个受信任的 DNS resolvers 列表，你可以从 [https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) 下载 resolvers，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 来过滤它们。或者你也可以使用： [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具有：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够进行有效 DNS brute-force 的工具。它非常快，但容易出现 false positives。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 这个我觉得只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是 `massdns` 的一个封装，用 go 编写，允许你使用主动 bruteforce 枚举有效子域名，同时支持带 wildcard 处理的子域名解析以及便捷的输入输出支持。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步暴力破解域名。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮 DNS 破译

在通过开源情报和暴力破解找到子域名后，你可以对已发现的子域名进行变体生成，以尝试找到更多子域名。为此有几个有用的工具：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 给定域名和子域名，生成排列组合。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名，生成排列组合。
- 你可以在 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) 获取 goaltdns permutations **wordlist**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 给定域名和子域名生成排列组合。如果没有指定 permutations 文件，gotator 将使用其自带的。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名排列外，它还可以尝试解析它们（但最好使用前面注释的工具）。
- 你可以在 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) 获取 altdns permutations **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 另一个用于对子域名进行排列、变异和修改的工具。这个工具会对结果进行暴力破解（它不支持 dns wild card）。
- 你可以在 [**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) 获取 dmut 的 permutations 词表。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于一个域名，它会根据指定的模式**生成新的潜在子域名**，以尝试发现更多子域名。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 更多信息请阅读这篇 [**post**](https://cramppet.github.io/regulator/index.html)，但它基本上会从**已发现的子域名**中提取**主要部分**并将它们混合，以查找更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力破解 fuzz 工具，配合一种极其简单但有效的 DNS 响应引导算法。它利用提供的一组输入数据，例如定制的 wordlist 或历史 DNS/TLS 记录，基于 DNS 扫描过程中收集到的信息，准确地合成更多对应的 domain names，并在循环中进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

查看我写的这篇博客，了解如何使用 **Trickest workflows** 从一个域名中**自动化子域名发现**，这样我就不需要在电脑上手动启动一堆工具：


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

如果你找到了一个包含属于子域名的**一个或多个 web pages** 的 IP address，你可以尝试通过查看 **OSINT sources** 中该 IP 里的 domains，或者通过在该 IP 上**brute-forcing VHost domain names**，来**找到该 IP 上其他带有 webs 的 subdomains**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 APIs** 在 IP 中找到一些 **VHosts**。

**Brute Force**

如果你怀疑某个 subdomain 可能隐藏在 web server 中，你可以尝试对它进行 brute force：

当 **IP redirects to a hostname**（name-based vhosts）时，直接 fuzz `Host` header，并让 ffuf **auto-calibrate**，以突出显示与默认 vhost 不同的 responses:
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
> 使用这种技术，你甚至可能能够访问内部/隐藏的 endpoints。

### **CORS Brute Force**

有时你会发现，只有当在 _**Origin**_ header 中设置了有效的 domain/subdomain 时，页面才会返回 _**Access-Control-Allow-Origin**_ header。在这种情况下，你可以滥用这种行为来**发现**新的**subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在查找 **subdomains** 时，要留意它是否 **pointing** 到任何类型的 **bucket**，如果是，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
另外，既然这时你已经知道了作用范围内的所有 domains，可以尝试[**暴力破解可能的 bucket 名称并检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **Monitorization**

你可以通过监控 **Certificate Transparency** Logs 来 **monitor** 某个 domain 是否创建了新的 **subdomains**，[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)就是做这个的。

### **Looking for vulnerabilities**

检查是否存在可能的[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，请[**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何 **subdomain with an IP different** 于你在资产发现阶段已经找到的那些 IP，你应该执行一次 **basic vulnerability scan**（使用 Nessus 或 OpenVAS）以及一些[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，工具可用 **nmap/masscan/shodan**。根据运行的服务，你可以在**本书中找到一些“攻击”它们的技巧**。\
_注意，有时 subdomain 托管在一个不受客户端控制的 IP 上，因此不在作用范围内，请小心。_

## IPs

在最初的步骤中，你可能已经 **found some IP ranges, domains and subdomains**。\
现在是时候把这些范围内的所有 IP **recollect** 出来，以及针对 **domains/subdomains（DNS queries）** 进行整理。

使用下面这些 **free apis** 提供的服务，你也可以找到 domains 和 subdomains **previous IPs used by**。这些 IP 可能仍然归客户端所有（并且可能让你找到[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP 地址的 domains

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs**（因为你大概率不会在那里找到任何有意思的东西）。在发现的运行服务中，你可能会**找到漏洞**。

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> 我们已经找到了所有公司及其资产，并知道作用范围内的 IP ranges、domains 和 subdomains。现在是时候搜索 web servers 了。

在前面的步骤中，你可能已经对发现的 IP 和 domains 做过一些 **recon**，所以你可能已经**找到了所有可能的 web servers**。不过，如果还没有，我们现在就来看看一些在作用范围内**快速搜索 web servers** 的技巧。

请注意，这会更偏向于 **web apps discovery**，所以你也应该进行 **vulnerability** 和 **port scanning**（如果作用范围允许）。

使用 [**masscan** 可找到这里的**快速方法**来发现与 web servers 相关的 **ports open**](../pentesting-network/index.html#http-port-discovery)。\
另一个用于寻找 web servers 的友好工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入一个 domains 列表，它就会尝试连接 80（http）和 443（https）端口。此外，你还可以指定尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

现在你已经发现了作用域内存在的**所有 web servers**（公司所有 **IPs** 以及所有 **domains** 和 **subdomains**），你可能**不知道从哪里开始**。所以，我们先简化一下，先对它们全部做截图。只要**看一眼** **main page**，你就能发现一些**奇怪**的 endpoint，而这些通常**更容易**存在**漏洞**。

要实现这个想法，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 去批量分析所有 **screenshots**，帮你判断**哪些更可能包含漏洞**，哪些不是。

## Public Cloud Assets

为了找到可能属于某个公司的 cloud assets，你应该**先准备一组能识别该公司的关键词**。例如，对于一家 crypto 公司，你可以使用这些词：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

你还需要一些**bucket 中常见词**的 wordlists：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，你应该用这些词生成 **permutations**（更多信息见 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

使用生成的 wordlists，你可以用这些工具：[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

记住，在寻找 Cloud Assets 时，你应该**不只是找 AWS 里的 buckets**。

### **Looking for vulnerabilities**

如果你发现了**open buckets 或暴露的 cloud functions**，你应该**访问它们**，看看它们提供了什么，以及你能否滥用它们。

## Emails

有了作用域内的 **domains** 和 **subdomains**，你基本上就具备了开始搜索 emails 所需的一切。以下是对我来说最有效的用来寻找公司 emails 的 **APIs** 和 **tools**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails 之后会很有用，比如用于**爆破 web logins 和 auth services**（例如 SSH）。另外，它们也是 **phishings** 所必需的。此外，这些 APIs 还会给你更多关于该 email 背后**人的信息**，这对 phishing campaign 很有帮助。

## Credential Leaks

有了 **domains、** **subdomains** 和 **emails**，你就可以开始寻找这些 email 过去是否有对应的 credentials 被泄漏：

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

如果你找到了**有效泄漏**的 credentials，这就是一个非常容易的收获。

## Secrets Leaks

Credential leaks 通常与公司被入侵有关，其中**敏感信息被泄漏并出售**。不过，公司也可能受到其他 leaks 的影响，而这些信息并不在那些数据库里：

### Github Leaks

Credentials 和 APIs 可能泄漏在**公司**的公共 repositories 中，或者泄漏在为这家公司工作的用户的 repositories 中。\
你可以使用 **tool** [**Leakos**](https://github.com/carlospolop/Leakos) 来自动**下载**一个 **organization** 及其开发者的所有 **public repos**，并自动对它们运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 也可以用来对传给它的所有 **text** **URLs passed** 运行 **gitleaks**，因为有时 **web pages also contains secrets**。

#### Github Dorks

也请查看这个 **page**，获取你在攻击目标组织时可能也会搜索的潜在 **github dorks**：


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

有时攻击者或普通员工会在 paste site 上**发布公司内容**。这可能包含也可能不包含**敏感信息**，但搜索它们非常值得。\
你可以使用 [**Pastos**](https://github.com/carlospolop/Pastos) 这个工具同时搜索 80 多个 paste sites。

### Google Dorks

经典的 google dorks 永远有用，可以找到那些**本不该暴露**的信息。唯一的问题是 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 里有**几千**条可能的查询，你不可能手动逐个执行。所以，你可以挑你最喜欢的 10 条，或者使用像 [**Gorks**](https://github.com/carlospolop/Gorks) 这样的 **tool** 来全部运行。

_注意，那些期望通过普通 Google browser 跑完整个数据库的 tools 永远不会结束，因为 google 很快就会封你。_

### **Looking for vulnerabilities**

如果你找到了**有效泄漏**的 credentials 或 API tokens，这就是一个非常容易的收获。

## Public Code Vulnerabilities

如果你发现公司有**open-source code**，你可以**分析**它并搜索其中的**漏洞**。

**根据语言不同**，你可以使用不同的 **tools**：


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

也有一些免费的服务可以让你**扫描 public repositories**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**大多数** bug hunters 找到的漏洞都在 **web applications** 里，所以在这一点上我想谈一套 **web application testing methodology**，你可以在[**这里**](../../network-services-pentesting/pentesting-web/index.html)找到这部分信息。

我还想特别提一下 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节，因为虽然你不应该指望它们帮你找到非常敏感的漏洞，但把它们整合进 **workflows** 来获取一些初步的 web 信息还是很有用的。

## Recapitulation

> 恭喜！到目前为止，你已经完成了**所有基本枚举**。是的，它只是基本，因为还可以做更多枚举（后面会看到更多技巧）。

所以你已经：

1. 找到了作用域内所有的 **companies**
2. 找到了属于这些公司的所有 **assets**（如果在 scope 内，还可以顺手做一些 vuln scan）
3. 找到了属于这些公司的所有 **domains**
4. 找到了这些 domains 的所有 **subdomains**（有没有 subdomain takeover？）
5. 找到了作用域内所有的 **IPs**（包括来自 **CDNs** 和**不来自 CDNs** 的）。
6. 找到了所有 **web servers** 并对它们做了 **screenshot**（有没有什么奇怪的东西值得深入查看？）
7. 找到了所有可能属于该公司的 **potential public cloud assets**。
8. 找到了可能让你**轻松大赚一笔**的 **Emails**、**credentials leaks** 和 **secret leaks**。
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

有一些工具可以针对给定的 scope 执行部分上述操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点旧，而且没有更新

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
