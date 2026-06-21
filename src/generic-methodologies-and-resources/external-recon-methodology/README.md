# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> 所以你被告知某公司的所有内容都在 scope 内，而你想弄清楚这家公司实际上拥有哪些资产。

这个阶段的目标是获取主公司拥有的所有**companies**，然后获取这些公司的所有**assets**。为此，我们将：

1. 查找主公司的收购情况，这会给我们 scope 内的公司。
2. 查找每个公司的 ASN（如果有），这会给我们每个公司拥有的 IP ranges
3. 使用 reverse whois 查询搜索与第一个条目相关的其他记录（organisation names、domains...）（这可以递归执行）
4. 使用其他技术，如 shodan `org`和`ssl`filters 来搜索其他资产（`ssl` 技巧也可以递归执行）。

### **Acquisitions**

首先，我们需要知道主公司拥有哪些**other companies**。\
一种方法是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**search** 主公司，并点击 "**acquisitions**"。在那里你会看到被主公司收购的其他公司。\
另一种方法是访问主公司的 **Wikipedia** 页面并搜索 **acquisitions**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面，或当地公司注册处（例如英国的 **Companies House**）。\
对于全球公司架构和子公司，试试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好了，到这里你应该已经知道 scope 内的所有公司了。接下来我们来看看如何找到它们的 assets。

### **ASNs**

autonomous system number（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给 **autonomous system**（AS）的一个**unique number**。\
**AS** 由若干 **IP addresses** **blocks** 组成，这些地址块对外部网络访问有明确的策略，并由单一组织管理，但也可能由多个运营者组成。

寻找公司是否分配了任何 ASN 来找到它的 **IP ranges** 很有意思。对 scope 内的所有 **hosts** 执行 **vulnerability test**，并在这些 IP 中 **look for domains** 会很有价值。\
你可以按公司**name**、**IP** 或 **domain** 在 [**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **or** [**https://ipinfo.io/**](https://ipinfo.io/) 上进行**search**。\
**Depending on the region of the company this links could be useful to gather more data:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). Anyway, probably all the** useful information **(IP ranges and Whois)** already appears in the first link.
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
另外，[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** 枚举会在扫描结束时自动汇总并总结 ASNs。
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
你也可以使用 [http://asnlookup.com/](http://asnlookup.com) 找到一个组织的 IP ranges（它有免费 API）。\
你可以使用 [http://ipv4info.com/](http://ipv4info.com) 找到一个 domain 的 IP 和 ASN。

### **寻找漏洞**

到这里我们已经知道**范围内的所有资产**，所以如果被允许，你可以对所有主机运行一些**vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）。\
另外，你也可以运行一些[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **或者使用** Shodan、Censys 或 ZoomEye **这类服务来发现** open ports **，并且根据你找到的结果，你应该**查看本书中如何 pentest 可能运行的各种服务。\
**另外，值得一提的是，你还可以准备一些** default username **和** passwords **列表，并尝试使用 [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) 对服务进行 bruteforce。**

## Domains

> 我们知道范围内的所有公司及其资产，现在是时候找出范围内的 domains 了。

_请注意，在下面提到的技术中，你也可以找到 subdomains，而且这些信息不应被低估。_

首先，你应该寻找每家公司的**主 domain**。例如，_Tesla Inc._ 的主 domain 是 _tesla.com_。

### **Reverse DNS**

既然你已经找到了这些 domain 的所有 IP ranges，你可以尝试对这些 **IPs** 执行 **reverse dns lookups**，以在范围内找到更多 domains。尝试使用受害者的某个 dns server，或者一些知名的 dns server（1.1.1.1、8.8.8.8）
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
对于这个方法有效，管理员必须手动启用 PTR。\
你也可以使用一个在线工具获取这些信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于大范围，像 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 这样的工具对于自动化 reverse lookups 和 enrichment 很有用。

### **Reverse Whois (loop)**

在一个 **whois** 里，你可以找到很多有趣的 **information**，比如 **organisation name**、**address**、**emails**、电话号码... 但更有趣的是，如果你对这些字段中的任意一个执行 **reverse whois lookups**，你可以找到与公司相关的 **more assets**（例如同一个 email 出现在其他 whois registries 中）。\
你可以使用以下在线工具：

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
你也可以使用 [amass](https://github.com/OWASP/Amass) 做一些自动化的 reverse whois discovery：`amass intel -d tesla.com -whois`

**注意，你可以在每次发现一个新 domain 时使用这个技术来发现更多 domain names。**

### **Trackers**

如果你在 2 个不同页面中找到 **同一个 tracker 的相同 ID**，你可以推断这 **两个页面** 是由 **同一个 team** 管理的。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或 **Adsense ID**。

有一些页面和工具可以让你通过这些 trackers 以及更多信息进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (通过共享的 analytics/trackers 查找相关站点)

### **Favicon**

你知道吗，我们可以通过查找相同的 favicon 图标 hash 来找到与目标相关的 domains 和 subdomains？这正是 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) 工具（由 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作）所做的事。下面是使用方法：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简单来说，favihash 可以让我们发现与目标具有相同 favicon icon hash 的域名。

此外，你还可以使用 favicon hash 搜索技术，正如在[**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)中所解释的那样。这意味着，如果你知道**某个 web tech 的易受攻击版本的 favicon 的 hash**，你就可以在 shodan 中搜索，并**找到更多易受攻击的位置**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
这是你可以 **计算一个 web 的 favicon hash** 的方法：
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
你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）批量获取 favicon hashes，然后在 Shodan/Censys 中继续 pivot。

### **Copyright / Uniq string**

在网页中搜索**可能在同一组织的不同网站之间共享的字符串**。**copyright string** 可能就是一个很好的例子。然后在 **google**、其他 **browsers** 甚至 **shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

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

### Mail DMARC 信息

你可以使用类似 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 的 web，或者使用类似 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 的工具，来查找**共享相同 dmarc 信息的域名和子域名**。\
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

> 我们知道范围内的所有公司、每家公司的所有资产，以及与这些公司相关的所有域名。

现在是时候找出每个已发现域名的所有可能子域名了。

> [!TIP]
> 注意，一些用于查找域名的工具和技术也可以帮助查找子域名

### **DNS**

让我们尝试从 **DNS** 记录中获取 **子域名**。我们也应该尝试 **Zone Transfer**（如果存在漏洞，你应该报告）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名的最快方式是从外部来源进行搜索。最常用的 **tools** 如下（为获得更好的结果，请配置 API keys）：

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
还有 **其他有趣的工具/APIs**，即使它们并不是专门用于查找 subdomains，也可能对查找 subdomains 有用，比如：

- [**IP.THC.ORG**](https://ip.thc.org) 免费 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用 API [https://sonar.omnisint.io](https://sonar.omnisint.io) 获取子域名
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) free API
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
- [**gau**](https://github.com/lc/gau)**:** 从 AlienVault 的 Open Threat Exchange、Wayback Machine 和 Common Crawl 中获取任意给定域名的已知 URLs。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 它们会抓取网页以寻找 JS 文件，并从中提取子域名。
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
- [**securitytrails.com**](https://securitytrails.com/) 有一个免费的 API，可用于搜索子域名和 IP 历史
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

这个项目**免费**提供与 bug-bounty programs 相关的所有子域名。你也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，甚至访问该项目使用的 scope [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到许多这些工具的**比较**： [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试通过使用可能的子域名名称对 DNS servers 进行 brute-forcing，以找到新的**subdomains**。

执行此操作时，你需要一些**常见的 subdomains wordlists，例如**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

还需要一些优质 DNS resolvers 的 IP。为了生成可信 DNS resolvers 列表，你可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载 resolvers，并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 进行过滤。或者你也可以使用： [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

最推荐用于 DNS brute-force 的工具是：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能够有效执行 DNS brute-force 的工具。它非常快，但容易产生 false positives。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 我认为这个只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个基于 `massdns` 的封装，使用 go 编写，允许你通过主动 bruteforce 枚举有效的子域名，同时还能进行子域名解析，支持 wildcard 处理以及方便的输入输出支持。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 异步爆破域名。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮 DNS Brute-Force

在使用开源情报和 brute-forcing 找到 subdomains 之后，你可以对已发现的 subdomains 生成变体，以尝试找到更多。为此有几个有用的工具：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 给定 domains 和 subdomains，生成 permutations。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 给定域名和子域名，生成排列组合。
- 你可以在[**这里**](https://github.com/subfinder/goaltdns/blob/master/words.txt)获取 goaltdns 的 permutations **wordlist**。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 给定 domains 和 subdomains 生成 permutations。如果没有指定 permutations file，gotator 将使用自己的。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 除了生成子域名排列组合外，它还可以尝试解析它们（但最好还是使用前面注释过的工具）。
- 你可以在 [**这里**](https://github.com/infosec-au/altdns/blob/master/words.txt) 获取 altdns 的排列组合 **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 另一个用于对子域名进行排列、变异和修改的工具。这个工具会暴力破解结果（它不支持 dns wild card）。
- 你可以在[**这里**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)获取 dmut 的 permutations wordlist。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于一个域名，它会根据指定的模式**生成新的潜在子域名**，以尝试发现更多子域名。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 更多信息请阅读这篇[**post**](https://cramppet.github.io/regulator/index.html)，但它基本上会从**已发现的子域名**中提取**主要部分**，并将它们进行组合，以寻找更多子域名。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个子域名暴力破解 fuzzing 工具，配合一种极其简单但有效的基于 DNS 响应引导的算法。它利用提供的一组输入数据，比如定制的 wordlist 或历史 DNS/TLS 记录，来准确合成更多相应的域名，并基于在 DNS 扫描期间收集到的信息，在循环中进一步扩展它们。
```
echo www | subzuf facebook.com
```
### **子域名发现工作流**

看看我写的这篇博客，介绍如何使用 **Trickest workflows** 从一个域名中**自动化子域名发现**，这样我就不需要在电脑上手动启动一堆工具了：


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / 虚拟主机**

如果你发现一个 IP 地址包含属于子域名的**一个或多个网页**，你可以通过查看该 IP 的**OSINT 源**中的域名，或者**对该 IP 中的 VHost 域名进行爆破**，来尝试**找到该 IP 上的其他子域名**。

#### OSINT

你可以使用 [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **或其他 API** 在 IP 中找到一些 **VHosts**。

**爆破**

如果你怀疑某个子域名可能隐藏在某个 web server 中，你可以尝试爆破它：

当 **IP 重定向到一个 hostname**（基于名称的 vhosts）时，直接 fuzz `Host` header，并让 ffuf **auto-calibrate**，以突出显示与默认 vhost 不同的响应：
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

有时你会发现，只有在 _**Origin**_ header 中设置了有效的 domain/subdomain 时，页面才会返回 header _**Access-Control-Allow-Origin**_。在这种情况下，你可以利用这种行为来 **discover** 新的 **subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

在查找 **subdomains** 时，留意它是否 **pointing** 到任何类型的 **bucket**，如果是这样，就 [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
另外，既然此时你已经知道作用域内的所有域名，试着 [**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **Monitorization**

你可以通过监控 **Certificate Transparency** 日志来 **monitor** 某个域名是否创建了 **new subdomains**， [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)就是这么做的。

### **Looking for vulnerabilities**

检查是否存在可能的 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果 **subdomain** 指向某个 **S3 bucket**，就 [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何 **subdomain with an IP different** 于你在资产发现阶段已经找到的 IP，你应该执行一次 **basic vulnerability scan**（使用 Nessus 或 OpenVAS）以及一些 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，使用 **nmap/masscan/shodan**。根据正在运行的服务，你可以在 **this book some tricks to "attack" them** 中找到一些相关技巧。\
_注意，有时 subdomain 托管在一个并不受客户端控制的 IP 上，因此它不在范围内，请小心。_

## IPs

在初始步骤中，你可能已经 **found some IP ranges, domains and subdomains**。\
现在是时候 **recollect all the IPs from those ranges**，以及针对 **domains/subdomains（DNS queries）** 进行收集了。

使用以下 **free apis** 的服务，你也可以找到域名和 subdomains 过去使用过的 **previous IPs**。这些 IP 可能仍然属于客户端（并且可能让你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向某个特定 IP 地址的域名

### **Looking for vulnerabilities**

**Port scan all the IPs that doesn’t belong to CDNs**（因为你很可能不会在那里找到任何有意思的东西）。在发现的正在运行的服务中，你也许能够 **find vulnerabilities**。

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> 我们已经找到了所有公司及其资产，并且知道作用域内的 IP ranges、domains 和 subdomains。现在是时候搜索 web servers 了。

在前面的步骤中，你可能已经对发现的 IP 和 domains 做过一些 **recon**，所以你也许已经找到了所有可能的 web servers。不过，如果还没有，我们现在要看一些在作用域内快速搜索 web servers 的技巧。

请注意，这会更偏向于 web apps discovery，因此你也应该进行 **vulnerability** 和 **port scanning**（如果作用域允许）。

使用 [**masscan** 可以找到](../pentesting-network/index.html#http-port-discovery) 与 **web** servers 相关的 **ports open** 的一种快速方法。\
另一个用于寻找 web servers 的友好工具是 [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入一个域名列表，它就会尝试连接 80 端口（http）和 443 端口（https）。此外，你还可以指定尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

现在你已经发现了范围内存在的**所有 web servers**（包括公司的所有 **IPs** 以及所有 **domains** 和 **subdomains**），你可能**不知道从哪里开始**。所以，让我们简单一点，先给它们全部截屏。仅仅通过**查看** **main page**，你就能发现一些**奇怪的** endpoints，它们更**容易**存在**漏洞**。

为了实现这个思路，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 对所有 **screenshots** 进行分析，告诉你**哪些更可能包含漏洞**，哪些不是。

## Public Cloud Assets

为了找到属于某个公司的潜在 cloud assets，你应该**先准备一份能识别该公司的关键词列表**。例如，对于一家 crypto 公司，你可能会使用诸如：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` 这样的词。

你还需要一些用于 buckets 的**常见词列表**：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，利用这些词你应该生成**permutations**（更多信息见 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

使用生成的 wordlists，你可以使用 [**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**。**

记住，在寻找 Cloud Assets 时，你应该**不仅仅只找 AWS 里的 buckets**。

### **Looking for vulnerabilities**

如果你发现了诸如**open buckets 或暴露的 cloud functions**，你应该**访问它们**，尝试看看它们提供了什么，以及你是否能加以利用。

## Emails

有了范围内的 **domains** 和 **subdomains**，你基本上就拥有了开始搜索 emails 所需的一切。以下是对我来说最有效的、用于找到公司 emails 的 **APIs** 和 **tools**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

emails 之后会很有用，可以用于**暴力破解 web logins 和 auth services**（例如 SSH）。此外，它们还用于 **phishings**。而且，这些 APIs 还能提供更多关于 email 背后那个人的**信息**，这对 phishing campaign 很有帮助。

## Credential Leaks

有了 **domains、** **subdomains** 和 **emails**，你就可以开始查找过去泄露、属于这些 email 的 credentials：

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

如果你找到了**有效的泄露** credentials，这就是一个非常容易的收获。

## Secrets Leaks

Credential leaks 与公司被黑有关，其中**敏感信息被泄露并出售**。然而，公司也可能受到**其他泄露**的影响，而这些信息并不在那些数据库里：

### Github Leaks

Credentials 和 APIs 可能泄露在该 **company** 的**public repositories** 中，或者泄露在使用该 github company 的员工的仓库中。\
你可以使用 **tool** [**Leakos**](https://github.com/carlospolop/Leakos) 来**下载**一个 **organization** 及其 **developers** 的所有 **public repos**，并自动对它们运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 也可以用来对传给它的所有 **text** 提供的 **URLs passed** 运行 **gitleaks**，因为有时 **web pages also contains secrets**。

#### Github Dorks

也看看这一 **page**，获取你在所攻击的 organization 中可以搜索的潜在 **github dorks**：


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

有时攻击者或者员工会把**公司内容**发布到 paste site 上。这可能包含也可能不包含**敏感信息**，但搜索它非常有意思。\
你可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时在 80 多个 paste sites 中搜索。

### Google Dorks

经典但依然好用的 google dorks 总是能帮助找到**本不该暴露**的信息。唯一的问题是 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 里有**几千**条可能的查询，你不可能手动全部运行。所以，你可以挑选你最喜欢的 10 条，或者使用类似 [**Gorks**](https://github.com/carlospolop/Gorks) 这样的 **tool** 把它们全部跑一遍。

_注意，那些期望使用普通 Google 浏览器把整个数据库都跑完的工具永远不会结束，因为 google 很快就会封掉你。_

### **Looking for vulnerabilities**

如果你找到了**有效的泄露** credentials 或 API tokens，这就是一个非常容易的收获。

## Public Code Vulnerabilities

如果你发现公司有**open-source code**，你可以**分析**它并搜索其中的 **vulnerabilities**。

**根据语言不同**，你可以使用不同的 **tools**：


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

也有一些免费的服务允许你**扫描 public repositories**，例如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

**绝大多数**由 bug hunters 找到的 vulnerabilities 都位于 **web applications** 内，所以到这里我想谈谈一个 **web application testing methodology**，你可以[**在这里找到这些信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提一下 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) 这一节，因为即使你不应该指望它们帮你找到非常敏感的漏洞，它们仍然很适合集成到 **workflows** 中，用来先获取一些 web 信息。

## Recapitulation

> 恭喜！到这里你已经完成了**所有基础枚举**。是的，它只是基础，因为还可以做更多枚举（后面会看到更多技巧）。

所以你已经：

1. 找到了范围内所有的 **companies**
2. 找到了属于这些公司的所有 **assets**（如果在范围内，还进行了 vuln scan）
3. 找到了属于这些公司的所有 **domains**
4. 找到了这些 domains 的所有 **subdomains**（有无 subdomain takeover？）
5. 找到了范围内所有 **IPs**（包括来自 **CDNs** 和**不来自 CDNs** 的）。
6. 找到了所有 **web servers** 并对它们做了 **screenshot**（有没有值得深入看的奇怪东西？）
7. 找到了属于该公司的所有潜在 public cloud assets。
8. 找到了可能会非常容易带来**巨大收获**的 **emails**、**credentials leaks** 和 **secret leaks**。
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

有一些工具可以对给定范围执行上述部分动作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点老，且未更新

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
