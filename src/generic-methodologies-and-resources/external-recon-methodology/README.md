# External Recon 方法论

{{#include ../../banners/hacktricks-training.md}}

## 资产发现

> 所以有人告诉你某公司的所有东西都在 scope 内，你想弄清这家公司实际拥有些什么。

此阶段的目标是获取所有由**主公司拥有的公司**，然后找出这些公司的所有**资产**。为此，我们将：

1. 找到主公司的收购记录，这会告诉我们有哪些公司在 scope 内。
2. 查找每家公司的 ASN（如果有的话），这将告诉我们每家公司拥有的 IP 段。
3. 使用 reverse whois 查找与第一个实体相关的其他条目（组织名称、域名等）（此过程可递归进行）。
4. 使用其他技术，比如 shodan 的 `org` 和 `ssl` 过滤来搜索其他资产（`ssl` 技巧也可以递归进行）。

### **收购**

首先，我们需要知道哪些是**由主公司拥有的其他公司**。\
一种方式是访问 [https://www.crunchbase.com/](https://www.crunchbase.com)，**搜索**主公司，**点击**“**收购**”。在那里你会看到被主公司收购的其他公司。\
另一种方式是访问主公司的 **Wikipedia** 页面并查找 **收购**。\
对于上市公司，请查看 **SEC/EDGAR filings**、**investor relations** 页面或当地的公司注册处（例如英国的 **Companies House**）。\
对于全球的公司结构和子公司，可以尝试 **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) 和 **GLEIF LEI** 数据库 ([https://www.gleif.org/](https://www.gleif.org/))。

> 好的，到这里你应该知道 scope 内的所有公司了。现在我们来找出它们的资产。

### **ASNs**

一个 autonomous system number（**ASN**）是由 **Internet Assigned Numbers Authority (IANA)** 分配给一个 autonomous system（**AS**）的**唯一编号**。\
一个 **AS** 包含若干 **IP 地址块**，这些地址块有明确的对外网络访问策略，由单一组织管理，但可能由多个运营商构成。

查明公司是否分配了 **ASN** 来获取其 **IP 段** 是很有价值的。对 scope 内的所有 **hosts** 进行 **vulnerability test** 并在这些 IP 中查找域名通常是有意义的。\
你可以在 [**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **或** [**https://ipinfo.io/**](https://ipinfo.io/) **按公司名称、IP 或域名进行**搜索**。**\
**根据公司所在地区，以下链接可能有助于收集更多数据：** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe)。无论如何，通常所有有用的信息（IP 段和 Whois）在第一个链接中就能找到。**
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
You can find the IP ranges of an organisation also using [http://asnlookup.com/](http://asnlookup.com) (it has free API).\
You can find the IP and ASN of a domain using [http://ipv4info.com/](http://ipv4info.com).

### **Looking for vulnerabilities**

At this point we know **范围内的所有资产**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## 域名

> 我们已经知道范围内的所有公司及其资产，现在是时候查找范围内的域名了。

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
要让此方法生效，管理员必须手动启用 PTR。\
你也可以使用在线工具获取此类信息：[http://ptrarchive.com/](http://ptrarchive.com)。\
对于大范围查询，像 [**massdns**](https://github.com/blechschmidt/massdns) 和 [**dnsx**](https://github.com/projectdiscovery/dnsx) 这样的工具有助于自动化反向查找和丰富化。

### **Reverse Whois (loop)**

在 **whois** 中你可以找到很多有趣的 **信息**，比如 **组织名称**、**地址**、**电子邮件**、电话号码等。但更有趣的是，如果你对这些字段中的任意一项执行 **reverse whois lookups**（例如查找在哪些其他 whois 注册记录中出现了相同的邮箱），你可以发现**更多与公司相关的资产**。\
你可以使用以下在线工具：

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **免费**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **免费**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **免费**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **免费** 网页，API 不免费。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 不免费
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 不免费（仅 **100 次免费** 搜索）
- [https://www.domainiq.com/](https://www.domainiq.com) - 不免费
- [https://securitytrails.com/](https://securitytrails.com/) - 不免费（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 不免费（API）

你可以使用 [**DomLink** ](https://github.com/vysecurity/DomLink) 来自动化此任务（需要一个 whoxy API key）。\
你也可以使用 [amass](https://github.com/OWASP/Amass) 执行一些自动的 reverse whois 发现： `amass intel -d tesla.com -whois`

**注意：每次发现新域名时，都可以使用该技术来发现更多域名。**

### **Trackers**

如果在两个不同页面中发现了**相同跟踪器的相同 ID**，你可以推断**两者页面由同一团队管理**。\
例如，如果你在多个页面上看到相同的 **Google Analytics ID** 或相同的 **Adsense ID**。

有一些网站和工具可以按这些跟踪器等进行搜索：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (通过共享 analytics/trackers 查找关联站点)

### **Favicon**

你知道吗，我们可以通过查找相同的 favicon 图标 hash 来发现与目标相关的域名和子域名？这正是 [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)（由 [@m4ll0k2](https://twitter.com/m4ll0k2) 制作）所做的事情。下面是如何使用它：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 发现具有相同 favicon icon hash 的域名](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

简而言之，favihash 允许我们发现与我们的目标具有相同 favicon icon hash 的域名。

此外，你也可以像 [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) 中解释的那样使用 favicon hash 来搜索技术。这意味着，如果你知道某个 web tech 易受攻击版本的 **favicon 的 hash**，你就可以在 shodan 中搜索并 **发现更多易受攻击的地方**：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
下面是如何 **计算网站的 favicon hash**：
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
你也可以使用 [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) 批量获取 favicon 哈希，然后在 Shodan/Censys 中 pivot。

### **版权 / 唯一字符串**

在网页中搜索 **可能在同一组织的不同站点间共享的字符串**。**版权字符串** 就是一个好例子。然后在 **google**、其他 **浏览器** 或甚至 **shodan** 中搜索该字符串：`shodan search http.html:"Copyright string"`

### **CRT Time**

通常会有一个 cron job，例如
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
用于在服务器上续签所有域的证书。  
这意味着即使为此使用的 CA 没有在 Validity time 中设置生成时间，也可能在 **certificate transparency** 日志中**找到属于同一公司的域名**。\
更多信息请参阅 [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

你可以使用像 [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) 这样的网站，或使用像 [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) 这样的工具来查找**共享相同 DMARC 信息的域名和子域**。\
其他有用的工具有 [**spoofcheck**](https://github.com/BishopFox/spoofcheck) 和 [**dmarcian**](https://dmarcian.com/)。

### **Passive Takeover**

通常人们会把子域名指向属于云提供商的 IP，但有时会失去该 IP 地址却忘记删除 DNS 记录。  
因此，只要在云上（例如 Digital Ocean）**spawning a VM**，你实际上就可能**taking over some subdomains(s)**。

[**This post**](https://kmsec.uk/blog/passive-takeover/) 讲述了这方面的一个案例并提供了一个脚本，该脚本**spawns a VM in DigitalOcean**，**gets** 新机器的 **IPv4**，并 **searches in Virustotal for subdomain records** 指向它。

### **Other ways**

**注意：每次发现新域名时都可以使用此技术发现更多域名。**

**Shodan**

由于你已经知道拥有该 IP 地址段的组织名称，你可以在 shodan 中基于该信息搜索：`org:"Tesla, Inc."`。检查找到的主机的 TLS 证书中是否包含新的意外域名。

你可以访问主网页的 **TLS certificate**，获取 **Organisation name**，然后在 **shodan** 已知的所有网页的 **TLS certificates** 中使用过滤器：`ssl:"Tesla Motors"` 搜索该名称，或使用像 [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) 这样的工具。

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) 是一个用于查找与主域名相关的 **相关域名** 及其 **子域** 的工具，非常好用。

### 被动 DNS / 历史 DNS

被动 DNS 数据非常适合发现仍然解析的或可能被接管的**旧的和被遗忘的记录**。查看：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。也许某家公司正在使用某个域名，但他们**失去了所有权**。只要注册它（如果价格合理），然后通知该公司即可。

如果你发现任何与资产发现中已找到的 IP 不同的域名，你应该执行一次 **基本漏洞扫描**（使用 Nessus 或 OpenVAS）以及一些 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)，使用 **nmap/masscan/shodan**。根据运行的服务，你可以在 **this book some tricks to "attack" them** 中找到一些攻击它们的技巧。\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

现在是时候查找每个已发现域名的所有可能子域了。

> [!TIP]
> 注意，有些用于查找域名的工具和技术也可以帮助发现子域名

### **DNS**

我们尝试从 **DNS** 记录中获取 **subdomains**。我们还应该尝试 **Zone Transfer**（如果存在漏洞，应当报告）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

获取大量子域名的最快方式是搜索外部来源。最常用的 **tools** 如下（为获得更好结果请配置 API keys）:

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
即使不是专门用于发现子域名，也有一些 **其他有趣的工具/API** 可能对发现子域名有用，例如：

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** 使用 API [https://sonar.omnisint.io](https://sonar.omnisint.io) 获取子域名
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
- [**gau**](https://github.com/lc/gau)**:** 为任何给定域名从 AlienVault's Open Threat Exchange、Wayback Machine 和 Common Crawl 获取已知 URLs。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): 它们爬取网页，查找 JS 文件并从中提取子域名。
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
- [**securitytrails.com**](https://securitytrails.com/) 提供一个免费 API 用于搜索 subdomains 和 IP history
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

该项目为 **free all the subdomains related to bug-bounty programs**。你也可以使用 [chaospy](https://github.com/dr-0x0x/chaospy) 访问这些数据，或者直接访问该项目使用的 scope：[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

你可以在这里找到这些工具的 **comparison**：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

让我们尝试通过对 DNS servers 使用可能的子域名进行 brute-forcing 来发现新的 **subdomains**。

为此操作你需要一些 **common subdomains wordlists like**：

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

另外还需要一些优质 DNS resolvers 的 IPs。为了生成一个受信任的 DNS resolvers 列表，你可以从 [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) 下载 resolvers 并使用 [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) 对其进行过滤。或者你可以使用： [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

推荐用于 DNS brute-force 的工具有：

- [**massdns**](https://github.com/blechschmidt/massdns)：这是第一个能有效执行 DNS brute-force 的工具。它非常快，然而容易产生 false positives。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): 我认为这个只使用 1 个 resolver
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) 是一个基于 `massdns` 的 wrapper，使用 go 编写，允许你使用 active bruteforce 枚举有效子域，并支持带通配符处理的子域解析以及简单的输入/输出支持。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): 它也使用 `massdns`.
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) 使用 asyncio 以异步方式对域名进行 brute force.
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二轮 DNS Brute-Force

在使用公开来源和 brute-forcing 找到子域名之后，你可以对已发现的子域名生成变体以尝试发现更多。几个工具对此很有用：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 给定域名和子域名，生成变体。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): 根据域名和子域名生成排列组合.
- 你可以在 [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) 获取 goaltdns 的排列组合 **wordlist**.
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** 给定域名和子域名，生成 permutations。若未指定 permutations 文件，gotator 将使用自带的文件。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): 除了生成 subdomains permutations 外，它还可以尝试解析它们（但最好使用前面提到的工具）。
- 你可以在 [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) 获取 altdns permutations **wordlist**。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): 另一个工具，用于对 subdomains 执行 permutations、mutations 和 alteration。该工具会对结果进行 brute force（它不支持 dns wild card）。
- 你可以在 [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) 获取 dmut permutations wordlist。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 基于一个 domain，它会根据指定模式 **生成新的潜在 subdomains 名称**，以尝试发现更多 subdomains。

#### 智能排列生成

- [**regulator**](https://github.com/cramppet/regulator): 更多信息请阅读此 [**post**](https://cramppet.github.io/regulator/index.html) ，它基本上会从 **discovered subdomains** 中获取 **main parts**，并混合它们以找到更多 subdomains。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ 是一个 subdomain brute-force fuzzer，结合了一个极其简单但有效的 DNS response-guided algorithm。它利用提供的一组输入数据，例如定制的 wordlist 或历史 DNS/TLS records，基于在 DNS scan 期间收集到的信息，准确合成更多对应的域名并在循环中进一步扩展。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Check this blog post I wrote about how to **automate the subdomain discovery** from a domain using **Trickest workflows** so I don't need to launch manually a bunch of tools in my computer:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

如果你发现一个包含属于 subdomains 的 **一个或多个网页** 的 IP 地址，你可以尝试通过在 **OSINT sources** 中查找该 IP 的域名，或者对该 IP 上的 **VHost domain names** 进行 **brute-forcing**，来尝试发现该 IP 上其他带有网站的 subdomains。

#### OSINT

你可以找到一些 **VHosts in IPs using** [**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**。

**Brute Force**

如果你怀疑某个 subdomain 可能隐藏在某个 web 服务器中，你可以尝试对其进行 brute force：

When the **IP redirects to a hostname** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> 使用此技术你甚至可能访问内部/隐藏的 endpoints.

### **CORS Brute Force**

有时你会发现某些页面只有在 _**Origin**_ header 设置为有效的 domain/subdomain 时才会返回 _**Access-Control-Allow-Origin**_ header。在这些场景中，你可以滥用这种行为来**发现**新的**subdomains**。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets 暴力破解**

在寻找 **subdomains** 时，注意是否有指向任何类型的 **bucket**，如果有的话 [**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
此外，在此阶段你应该知道范围内的所有域名，尝试对可能的 **bucket** 名称进行 [**暴力枚举并检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **监控**

你可以通过监控 **Certificate Transparency** 日志来监测某个域是否创建了 **new subdomains**，正如 [**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) 所做的那样。

### **寻找漏洞**

检查可能的 [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)。\
如果某个 **subdomain** 指向某个 **S3 bucket**，请 [**检查权限**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

如果你发现任何一个 **subdomain** 的 **IP** 与在资产发现中已发现的不同，你应该对其进行 **basic vulnerability scan**（使用 Nessus 或 OpenVAS），并用 **nmap/masscan/shodan** 进行一些 [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)。根据运行的服务，你可以在 **本书** 中找到一些“攻击”它们的技巧。\
_注意，有时 subdomain 承载在一个不由客户控制的 IP 上，因此不在测试范围内，请小心。_

## IPs

在初始步骤中，你可能已经 **found some IP ranges, domains and subdomains**。\
现在是时候 **recollect all the IPs from those ranges**，以及对这些 **domains/subdomains（DNS 查询）** 进行收集。

使用下面这些 **free apis** 的服务，你也可以找到 **previous IPs used by domains and subdomains**。这些 IP 可能仍然由客户拥有（并且可能帮助你找到 [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)）。

- [**https://securitytrails.com/**](https://securitytrails.com/)

你也可以使用工具 [**hakip2host**](https://github.com/hakluke/hakip2host) 检查指向特定 IP 地址的域名。

### **寻找漏洞**

**Port scan all the IPs that doesn’t belong to CDNs**（因为在那些地方你很可能找不到感兴趣的东西）。在发现的运行服务中，你可能**能够发现漏洞**。

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers hunting

> 我们已经找到了所有公司及其资产，并且知道范围内的 IP ranges、domains 和 subdomains。现在是时候搜索 web servers 了。

在前面的步骤中，你可能已经对发现的 IPs 和 domains 做了一些 **recon**，因此可能已经 **找到了所有可能的 web servers**。但是，如果还没有，我们现在将查看一些在范围内搜索 web servers 的 **快速技巧**。

请注意，这将以 **web apps discovery** 为导向，因此你也应该进行 **vulnerability** 和 **port scanning**（如果范围允许）。

一种使用 [**masscan**](../pentesting-network/index.html#http-port-discovery) 来发现与 **web** 服务器相关的 **开放端口** 的 **快速方法** 可以在这里找到。\
另一个友好的查找 web servers 的工具有 [**httprobe**](https://github.com/tomnomnom/httprobe)、[**fprobe**](https://github.com/theblackturtle/fprobe) 和 [**httpx**](https://github.com/projectdiscovery/httpx)。你只需传入域名列表，它会尝试连接到端口 80 (http) 和 443 (https)。此外，你可以指定尝试其他端口：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

现在你已经发现了范围内的**所有 web servers**（包括公司的**IPs**以及所有的**domains**和**subdomains**），可能会感到**不知道从哪里开始**。简单起见，先对它们全部做个截图。只要**看一下**主页，你就可能发现一些**奇怪的**端点，这些端点更**容易**存在**vulnerabilities**。

为了实现这个想法，你可以使用 [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) 或 [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**。**

此外，你还可以使用 [**eyeballer**](https://github.com/BishopFox/eyeballer) 对所有**screenshots**进行批量查看，以判断哪些页面**可能包含漏洞**，哪些不是。

## Public Cloud Assets

为了查找属于公司的潜在 cloud assets，你应该**从一个识别该公司的关键词列表开始**。例如，对于加密公司，你可能会使用诸如："crypto", "wallet", "dao", "<domain_name>", <"subdomain_names"> 之类的词。

你还需要关于**常见用于 buckets 的单词**的 wordlists：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

然后，使用这些单词生成**permutations**（更多信息请查看 [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)）。

使用生成的 wordlists，你可以使用诸如 [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **或** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** 等工具。**

记住，在查找 Cloud Assets 时，你应该**寻找的不仅仅是 AWS 的 buckets**。

### **Looking for vulnerabilities**

如果你发现诸如**open buckets 或 cloud functions 暴露**之类的东西，你应该**访问它们**，看看能得到什么，以及是否可以滥用它们。

## Emails

有了范围内的**domains**和**subdomains**，你基本上就具备了**开始搜索 emails** 的所有条件。以下是对我来说最有效的用于查找公司 emails 的 **APIs** 和 **tools**：

- [**theHarvester**](https://github.com/laramies/theHarvester) - 使用 APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

emails 在之后对**暴力破解 web 登录和 auth 服务**（例如 SSH）会很有用。此外，它们对于**phishings**也是必需的。而且，这些 APIs 还会提供关于邮箱所属人的更多**信息**，这对钓鱼活动很有帮助。

## Credential Leaks

有了**domains**, **subdomains**, 和 **emails**，你就可以开始搜索过去属于这些 emails 的泄露凭据：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

如果你找到**valid leaked** 凭据，这通常是一个非常容易的胜利。

## Secrets Leaks

Credential leaks 通常与公司被攻击后**敏感信息被泄露和售卖**有关。然而，公司也可能受到**其他形式的 leaks** 的影响，这些信息不会出现在上述数据库中：

### Github Leaks

凭据和 API 可能会泄露在该公司或为该公司工作的用户的**public repositories** 中。\
你可以使用工具 [**Leakos**](https://github.com/carlospolop/Leakos) 来**下载**一个组织及其开发者的所有**public repos**，并自动对它们运行 [**gitleaks**](https://github.com/zricethezav/gitleaks)。

**Leakos** 也可以用来对传入的所有**URLs**（文本形式）运行 **gitleaks**，因为有时**网页也包含 secrets**。

#### Github Dorks

同时也检查这 **page**，了解你可以在目标组织中搜索的潜在 **github dorks**：


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

有时攻击者或内部员工会在 paste 站点上**发布公司内容**。这些内容可能包含也可能不包含**敏感信息**，但值得检索。\
你可以使用工具 [**Pastos**](https://github.com/carlospolop/Pastos) 同时搜索 80 多个 paste 站点。

### Google Dorks

老而弥坚的 Google dorks 总是有助于发现**不应该公开的信息**。问题是 [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) 包含数**千**条可能的查询，人工无法全部运行。所以，你可以挑出你最喜欢的 10 条，或者使用诸如 [**Gorks**](https://github.com/carlospolop/Gorks) 的**工具来全部运行**。

注意，那些期望使用常规 Google 浏览器来运行整个数据库的工具几乎不可能完成，因为 google 很快就会封锁你。

### **Looking for vulnerabilities**

如果你发现**valid leaked** 的凭据或 API tokens，这通常是一个非常容易的胜利。

## Public Code Vulnerabilities

如果你发现公司有**开源代码**，你可以**分析**它并搜索其中的**vulnerabilities**。

**根据语言不同**，你可以使用不同的 **tools**：


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

还有一些免费服务允许你**扫描 public repositories**，比如：

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

大多数 bug hunters 发现的漏洞都存在于 **web applications** 中，所以在此我想谈谈一个**web application testing methodology**，你可以在[**这里找到这些信息**](../../network-services-pentesting/pentesting-web/index.html)。

我还想特别提到章节 [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)，虽然你不应指望它们能发现非常敏感的漏洞，但将它们集成到**工作流**中以获得一些初步的 web 信息是很有用的。

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

所以你已经完成了：

1. 找到范围内的所有**companies**
2. 找到属于这些公司的所有**assets**（并在 scope 内对部分资产做了一些 vuln scan）
3. 找到属于这些公司的所有**domains**
4. 找到这些 domains 的所有**subdomains**（是否存在 subdomain takeover？）
5. 找到范围内的所有**IPs**（包括来自或不来自 **CDNs** 的）
6. 找到所有的 **web servers** 并对它们做了**screenshot**（有没有值得深入查看的异常？）
7. 找到属于公司的所有潜在 public cloud assets。
8. **Emails**, **credentials leaks**, 和 **secret leaks**，这些可能会让你轻易获得**大胜利**。
9. **Pentesting** 你发现的所有 webs

## **Full Recon Automatic Tools**

市面上有一些工具可以对给定范围执行上面部分操作。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 有点旧且未更新

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
