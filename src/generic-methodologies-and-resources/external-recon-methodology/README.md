# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> つまり、ある会社に属するものはすべてスコープ内にあると言われていて、その会社が実際に何を所有しているのかを把握したい、ということです。

この段階の目的は、メイン会社が所有するすべての**companies**を見つけ、その後それらの会社のすべての**assets**を見つけることです。そのために、以下を行います。

1. メイン会社の買収先を見つける。これにより、スコープ内の会社が分かる。
2. 各会社の ASN（存在する場合）を見つける。これにより、各会社が所有する IP 範囲が分かる。
3. reverse whois lookups を使って、最初のものに関連する他のエントリ（組織名、ドメインなど）を検索する（これは再帰的に行える）。
4. shodan の `org` と `ssl` フィルタのような他の techniques を使って、他の assets を検索する（`ssl` のトリックも再帰的に行える）。

### **Acquisitions**

まず最初に、メイン会社が所有している**他の companies**を把握する必要があります。\
1つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) を訪れ、**main company** を**search**し、"**acquisitions**" を**click**することです。そこに、買収された他の companies が表示されます。\
別の方法は、メイン会社の **Wikipedia** ページを訪れて **acquisitions** を探すことです。\
公開会社の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または各国の企業登記（例: 英国の **Companies House**）を確認してください。\
グローバルな企業グループ構造や子会社を調べるには、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) と **GLEIF LEI** データベース ([https://www.gleif.org/](https://www.gleif.org/)) を試してください。

> ここまでで、スコープ内のすべての companies が分かっているはずです。では、その assets を見つける方法を確認しましょう。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority (IANA)** によって **autonomous system**（AS）に割り当てられる**固有の番号**です。\
**AS** は、外部ネットワークへのアクセスに関して明確に定義されたポリシーを持つ **IP addresses** の**blocks** で構成され、単一の organisation によって管理されますが、複数の operators で構成される場合があります。

会社に **assigned** された ASN があるかを確認して、その **IP ranges** を見つけるのは興味深いことです。スコープ内のすべての **hosts** に対して **vulnerability test** を実施し、これらの IP 内にある **domains** を探すとよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **or** [**https://ipinfo.io/**](https://ipinfo.io/) では、会社の **name**、**IP**、または **domain** で**search**できます。\
**会社の地域によっては、さらにデータを集めるのに次のリンクが役立つことがあります:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). といっても、おそらく有用な情報**（IP ranges と Whois）は最初のリンクですでに見つかります。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration は、スキャンの শেষে に ASN を自動的に集約して要約します。
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

### **脆弱性を探す**

この時点で私たちは**スコープ内のすべての資産**を把握しているので、許可されているなら、すべてのホストに対して**vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye のようなサービスを**使って** open ports を見つけたりできます。見つかったものに応じて、この本で動作している可能性のある各種サービスの pentest 方法を確認してください。\
**また、** デフォルトの username **と** passwords のリストを用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使ってサービスに bruteforce を試すのも価値があります。

## Domains

> 私たちはスコープ内のすべての会社とその資産を把握したので、次はスコープ内の domains を見つける番です。

_なお、以下で示す手法では subdomains も見つけられますが、その情報は軽視すべきではありません。_

まず最初に、各会社の**main domain**を調べるべきです。たとえば、_Tesla Inc._ なら _tesla.com_ です。

### **Reverse DNS**

各 domain の IP ranges をすべて見つけたら、それらの**IPs に対して reverse dns lookups** を行い、**スコープ内のさらに多くの domains を見つける**ことができます。被害者側の dns server か、よく知られた dns server（1.1.1.1、8.8.8.8）を使ってみてください
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、administrator が手動で PTR を有効化する必要があります。\
この情報については、オンラインツールも使えます: [http://ptrarchive.com/](http://ptrarchive.com)。\
大きな範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールが、reverse lookups と enrichment を自動化するのに便利です。

### **Reverse Whois (loop)**

**whois** の中では、**organisation name**、**address**、**emails**、電話番号など、多くの興味深い**information**を見つけられます。さらにもっと興味深いのは、これらの項目のどれかを使って **reverse whois lookups** を行うと、**会社に関連するより多くの assets** を見つけられることです（たとえば、同じ email が出てくる別の whois registries など）。\
以下のようなオンラインツールを使えます:

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

このタスクは [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、ある程度の automatic reverse whois discovery も実行できます: `amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、この technique を使ってさらに多くの domain names を見つけられることに注意してください。**

### **Trackers**

2つの異なるページで **同じ tracker の同じ ID** が見つかれば、**両方のページは同じ team によって managed されている** と推測できます。\
たとえば、複数のページで同じ **Google Analytics ID** や **Adsense ID** が見つかる場合です。

これらの tracker などで検索できるページやツールがいくつかあります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (共有された analytics/trackers から related sites を見つける)

### **Favicon**

同じ favicon icon hash を見ることで、target に関連する domain や subdomain を見つけられることをご存じでしたか？ これは、[@m4ll0k2](https://twitter.com/m4ll0k2) によって作られた [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool がまさに行っていることです。使い方は次のとおりです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihash を使うと、ターゲットと同じ favicon icon hash を持つドメインを見つけられます。

さらに、[**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) で説明されているように、favicon hash を使って技術を検索することもできます。つまり、**脆弱なバージョンの web tech の favicon の hash** を知っていれば、shodan で検索して **さらに多くの脆弱な場所を見つける** ことができます:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
これは、Web の **favicon hash** を計算する方法です:
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
[**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) を使って favicon hashes を大量に取得し、その後 Shodan/Censys で pivot できます。

### **Copyright / Uniq string**

Web ページ内で、**同じ組織の別の web 間で共有されている可能性のある strings** を検索します。**copyright string** は良い例です。次に、その string を **google**、他の **browsers**、あるいは **shodan** で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

次のような cron job があるのは一般的です:
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

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
Other useful tools are [**spoofcheck**](https://github.com/BishopFox/spoofcheck) and [**dmarcian**](https://dmarcian.com/).

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

多くのサブドメインを取得する最速の方法は、外部ソースを検索することです。最もよく使われる**tools**は以下のとおりです（より良い結果のためにAPIキーを設定してください）:

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
他にも、サブドメインの発見に直接特化していなくても、サブドメインを見つけるのに役立つ**興味深いツール/API**があります。たとえば:

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得します
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC free API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) 無料 API
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
- [**gau**](https://github.com/lc/gau)**:** AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から、任意のドメインに対して既知の URLs を取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): これらは Web をクロールして JS ファイルを探し、そこからサブドメインを抽出する。
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
- [**securitytrails.com**](https://securitytrails.com/) は、subdomains と IP 履歴を検索するための無料 API を提供しています
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは、**bug-bounty program に関連するすべての subdomains** を**無料**で提供しています。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスできるほか、このプロジェクトで使われている scope にもアクセスできます [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

これらのツールの多くの**比較**をここで見つけることができます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

DNS サーバーを brute-forcing して、可能性のある subdomain 名から新しい **subdomains** を見つけてみましょう。

この作業には、次のような**一般的な subdomains の wordlist** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、良質な DNS resolver の IP も必要です。信頼できる DNS resolver のリストを生成するには、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使ってフィルタリングできます。あるいは、次を使うこともできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨されるツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): これは、効果的な DNS brute-force を実行した最初のツールでした。非常に高速ですが、false positives が発生しやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは、たぶん 1 つの resolver だけを使っている
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、goで書かれた `massdns` のラッパーで、active bruteforce を使って有効なサブドメインを列挙でき、さらに wildcard handling と簡単な input-output サポート付きでサブドメインを解決できます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使ってドメイン名を非同期にブルートフォースします。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第2回 DNS ブルートフォース

オープンソースやブルートフォースでサブドメインを見つけた後、見つかったサブドメインの変形を生成して、さらに多くを見つけようとできます。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインが与えられると、パーミュテーションを生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインが与えられた場合に、permutations を生成します。
- goaltdns の permutations 用 **wordlist** は [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインが与えられたら、permutations を生成する。permutations file が指定されていない場合、gotator は独自のものを使用する。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成するだけでなく、それらの解決も試せます（ただし、前にコメントしたツールを使うほうがより良いです）。
- altdns の permutations **wordlist** は [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutation、mutation、alteration を行うための別のツールです。このツールは結果に対して brute force を行います（dns wild card はサポートしていません）。
- dmut の permutation wordlist は[**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)で入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを元に、指定されたパターンに基づいて新しい潜在的なサブドメイン名を生成し、より多くのサブドメインを見つける試みを行います。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 詳しくはこの[**post**](https://cramppet.github.io/regulator/index.html)を読んでください。基本的には、**発見済みのサブドメイン**から**主要な部分**を抽出し、それらを組み合わせてさらに多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルでありながら効果的な DNS 応答ガイドアルゴリズムと組み合わされたサブドメイン brute-force fuzzer です。これは、カスタマイズした wordlist や過去の DNS/TLS レコードのような入力データのセットを利用して、DNS scan 中に収集した情報に基づき、より多くの対応する domain name を正確に生成し、さらにループでそれらを拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン発見ワークフロー**

**Trickest workflows** を使って、ドメインから **サブドメイン discovery** を自動化する方法について書いたこのブログ記事をチェックしてください。これなら、PC上でたくさんのツールを手動で起動する必要がありません:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

サブドメインに属する **1つまたは複数の web pages** を含む IP address を見つけた場合、その IP 内の **他のサブドメインを見つける** ために、IP 内のドメインを **OSINT sources** で調べるか、その IP に対して **VHost domain names** を **brute-force** してみることができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他の APIs** を使って、IP 内の **VHosts** を見つけることができます。

**Brute Force**

サブドメインが web server に隠れていると疑う場合は、brute force を試してみることができます:

**IP が hostname にリダイレクトする** 場合（name-based vhosts）、`Host` ヘッダーを直接 fuzz し、ffuf の **auto-calibrate** を使って default vhost と異なるレスポンスを強調表示します:
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
> このテクニックを使うと、internal/hidden endpoints にアクセスできる場合さえあります。

### **CORS Brute Force**

時々、_**Origin**_ ヘッダーに有効な domain/subdomain が設定されている場合にのみ、ヘッダー _**Access-Control-Allow-Origin**_ を返すページが見つかります。このようなシナリオでは、この挙動を悪用して新しい **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を調べる際は、それが何らかの **bucket** を **pointing** していないか確認し、その場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
また、この時点でスコープ内のすべてのドメインが分かっているので、可能性のある bucket 名を [**brute force**] して [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) してみてください。

### **Monitorization**

ドメインの **new subdomains** が作成されていないか、**Certificate Transparency** Logs を監視することで **monitor** できます。[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) がそれを行います。

### **Looking for vulnerabilities**

可能な [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) を確認します。\
**subdomain** が何らかの **S3 bucket** を指している場合は、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) してください。

**assets discovery** で既に見つけたものとは **IPが異なるsubdomain** を見つけた場合は、**basic vulnerability scan**（Nessus や OpenVAS を使用）と、**nmap/masscan/shodan** による [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実施すべきです。実行中のサービスに応じて、この本の中でそれらを「attack」するためのいくつかのコツを見つけられます。\
_注意: 場合によっては、subdomain がクライアントの管理外の IP 上でホストされていることがあり、その場合はスコープ外です。注意してください。_

## IPs

初期段階で、**IP ranges、domains、subdomains** を見つけているかもしれません。\
**それらの range に含まれるすべての IP** と、**domains/subdomains の IP（DNS queries）** を再収集する時です。

以下の **free apis** のサービスを使うと、**domains と subdomains が過去に使用していた IP** も見つけられます。これらの IP は、まだクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つける助けになるかもしれません。

- [**https://securitytrails.com/**](https://securitytrails.com/)

ツール [**hakip2host**](https://github.com/hakluke/hakip2host) を使って、特定の IP address を指している domains も確認できます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IP** を **Port scan** してください（そこでは、おそらく興味深いものは見つからないためです）。見つかった稼働中のサービスからは、**vulnerabilities** を見つけられるかもしれません。

**ホストの scan 方法についての** [**guide**](../pentesting-network/index.html) **を見つけてください。**

## Web servers hunting

> スコープ内のすべての会社とその assets を特定し、IP ranges、domains、subdomains が分かっている。Web servers を探す時間です。

前の手順ですでに、発見した **IPs と domains の recon** をある程度行っているはずなので、**すべての可能な web servers** をすでに見つけているかもしれません。とはいえ、まだなら、ここではスコープ内で **web servers** を素早く探すためのいくつかのコツを見ていきます。

なお、これは **web apps discovery** 向けなので、（スコープで **allowed** されているなら）**vulnerability** と **port scanning** も実施してください。

[**masscan** を使って web servers に関連する **ports open** を見つける **fast method** はこちら](../pentesting-network/index.html#http-port-discovery) です。\
web servers を探す別の便利なツールとしては [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) および [**httpx**](https://github.com/projectdiscovery/httpx) があります。ドメインのリストを渡すだけで、port 80 (http) と 443 (https) に接続を試みます。さらに、他の ports を試すよう指定することもできます:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

さて、スコープ内に存在する **すべての web servers**（会社の **IP**、およびすべての **domains** と **subdomains**）を見つけたとしても、たぶん **どこから始めればよいか分からない** はずです。なので、まずは単純にそれらすべてのスクリーンショットを撮りましょう。**メインページ** を **見る** だけで、より **脆弱** である可能性が高い **変な** endpoint を見つけられることがあります。

提案したアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** を使えます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての **screenshots** を解析し、**どれが脆弱性を含みそうか**、どれがそうでないかを判定できます。

## Public Cloud Assets

会社に属する潜在的な cloud assets を見つけるには、まず **その会社を識別するキーワードのリスト** から始めるべきです。たとえば、crypto企業なら `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` のような語を使えます。

また、**buckets** でよく使われる **一般的な単語の wordlists** も必要です:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って **permutations** を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を参照）。

生成した wordlists を使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** のようなツールを使えます。

Cloud Assets を探すときは、**AWS の buckets だけを探せばよいわけではない**ことを忘れないでください。

### **Looking for vulnerabilities**

**open buckets** や **cloud functions exposed** のようなものを見つけたら、それらに **アクセス** して、何を提供しているのか、悪用できるかを確認すべきです。

## Emails

スコープ内の **domains** と **subdomains** があれば、基本的に emails を探し始めるのに必要なものはすべて揃っています。以下は、会社の email を見つけるのに特に役立った **APIs** と **tools** です:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails は後で **web logins や auth services**（SSH など）を **brute-force** するときに役立ちます。また、**phishings** にも必要です。さらに、これらの APIs は email の背後にいる人物についてさらに多くの **info** を与えてくれるので、phishing campaign にも有用です。

## Credential Leaks

**domains**, **subdomains**, **emails** があれば、過去に漏えいしたそれらの email に紐づく credentials を探し始められます:

- [https://leak-lookup.com/account/login](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**valid leaked** な credentials が見つかれば、これは非常に簡単な成果です。

## Secrets Leaks

Credential leaks は、**機密情報が漏えいして販売された**会社へのハッキングと関連しています。しかし、会社はデータベースに載っていない **他の leaks** の影響を受けている可能性もあります:

### Github Leaks

Credentials や APIs は、**company** の **public repositories** や、その github company で働く **users** のリポジトリに漏れている可能性があります。\
**tool** [**Leakos**](https://github.com/carlospolop/Leakos) を使えば、**organization** とその **developers** のすべての **public repos** を **download** し、自動で [**gitleaks**](https://github.com/zricethezav/gitleaks) を実行できます。

**Leakos** は、渡されたすべての **text** 提供 **URLs** に対して **gitleaks** を実行するためにも使えます。**web pages also contains secrets** であることがあるためです。

#### Github Dorks

攻撃対象の organization で検索できる潜在的な **github dorks** については、この **page** も確認してください:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

ときには攻撃者や単なる従業員が、会社のコンテンツを paste site に **publish** します。そこに **sensitive information** が含まれることもあれば、そうでないこともありますが、探す価値は非常に高いです。\
[**Pastos**](https://github.com/carlospolop/Pastos) を使えば、80以上の paste sites を同時に検索できます。

### Google Dorks

古いですが強力な google dorks は、そこにあってはならない **exposed information** を見つけるのに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) には手動では実行しきれない何千ものクエリが含まれていることです。そこで、お気に入りの10個だけを使うか、[**Gorks**](https://github.com/carlospolop/Gorks) のような **tool** を使って全部実行できます。

_Google の通常のブラウザを使ってデータベース全体を実行しようとする tools は、Google にすぐブロックされるので、最後まで終わることはありません。_

### **Looking for vulnerabilities**

**valid leaked** な credentials や API tokens が見つかれば、これは非常に簡単な成果です。

## Public Code Vulnerabilities

会社に **open-source code** があると分かったなら、それを **analyse** して **vulnerabilities** を探せます。

**言語によって** 使える **tools** は異なります:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

また、次のように public repositories を **scan** できる無料サービスもあります:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters によって見つかる **vulnerabilities の大半** は **web applications** の中にあります。そのため、ここでは **web application testing methodology** について話したいと思います。詳細は [**ここ**](../../network-services-pentesting/pentesting-web/index.html) で確認できます。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) のセクションも特筆したいです。そこまで **sensitive vulnerabilities** を見つけることは期待しすぎないほうがよいですが、最初の web 情報を得るために **workflows** に組み込むと便利です。

## Recapitulation

> おめでとうございます！ ここまでで、**すべての basic enumeration** はすでに終えています。そう、basic です。なぜなら、もっと多くの enumeration が可能だからです（後でもっとトリックを見ます）。

つまり、すでに以下を行っています:

1. スコープ内のすべての **companies** を見つけた
2. 会社に属するすべての **assets** を見つけた（スコープ内なら vuln scan も実施）
3. 会社に属するすべての **domains** を見つけた
4. domains のすべての **subdomains** を見つけた（subdomain takeover はあるか？）
5. スコープ内のすべての **IPs**（CDNs からのものとそうでないもの）を見つけた。
6. すべての **web servers** を見つけて **screenshot** を撮った（深く調べる価値のある変なものはあるか？）
7. 会社に属する潜在的な public cloud assets をすべて見つけた。
8. **Emails**、**credentials leaks**、**secret leaks** により、**非常に簡単に大きな成果** を得られる可能性があるものを見つけた。
9. 見つけたすべての webs に **Pentesting** を行った

## **Full Recon Automatic Tools**

提案された作業の一部を、あるスコープに対して実行してくれる tools がいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix) の無料コースすべて。たとえば [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
