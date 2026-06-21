# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> つまり、ある会社に属するものはすべて scope に含まれていると言われ、その会社が実際に何を所有しているかを把握したい、ということです。

このフェーズの目的は、まず **親会社が所有するすべての会社** を取得し、その後それらの会社の **すべての assets** を取得することです。そのために、次を行います。

1. メインの会社の acquisitions を見つける。これで scope 内の会社が分かる。
2. 各会社の ASN（ある場合）を見つける。これで各会社が所有する IP ranges が分かる。
3. reverse whois lookup を使って、最初のものに関連する他のエントリ（organisation names, domains...）を探す（再帰的に実行できる）。
4. shodan の `org` と `ssl` filters のような他の techniques を使って、他の assets を探す（`ssl` のトリックも再帰的に実行できる）。

### **Acquisitions**

まず最初に、**メインの会社が所有する他の会社** がどれかを知る必要があります。\
1つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**メインの会社を検索** して "**acquisitions**" を **クリック** することです。そこに、メインの会社に買収された他の会社が表示されます。\
別の方法として、メインの会社の **Wikipedia** ページにアクセスして **acquisitions** を検索します。\
公開会社の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または現地の企業登記簿（例: 英国の **Companies House**）を確認してください。\
グローバルな企業構造や子会社を調べるには、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) と **GLEIF LEI** データベース ([https://www.gleif.org/](https://www.gleif.org/)) を試してください。

> これで、この時点で scope 内のすべての会社が分かったはずです。では、それらの assets をどう見つけるかを考えましょう。

### **ASNs**

autonomous system number (**ASN**) は、**Internet Assigned Numbers Authority (IANA)** によって **autonomous system** (AS) に割り当てられる **一意の番号** です。\
**AS** は、外部ネットワークへアクセスするための方針が明確に定義された **IP addresses** の **blocks** で構成され、1つの organisation によって管理されますが、複数の operators で構成されている場合もあります。

会社が **ASN** を割り当てられているかを調べて、**IP ranges** を見つけるのは興味深いことです。\
scope 内のすべての **hosts** に対して **vulnerability test** を行い、これらの IP の中に **domains** がないか探すとよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) で、会社名、**IP**、または **domain** で **search** できます。\
**会社の地域によっては、より多くのデータを収集するのに役立つリンクがあります:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe). ただし、おそらく有用な情報**（IP ranges と Whois）は最初のリンクにすでに含まれています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s**
enumeration は、スキャンの最後に ASNs を自動的に集約し、要約します。
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

### **脆弱性の調査**

この時点で私たちは**スコープ内のすべてのアセット**を把握しているので、許可されているなら、すべてのホストに対して**vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEye のようなサービスを**使って** open ports を見つけたりすることもできます。見つかったものに応じて、この本で稼働している可能性のある各種サービスをどのように pentest するか確認してください。\
**また、デフォルトの username** と **passwords** のリストを用意して、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使ってサービスに bruteforce を試すのも有効です。

## Domains

> スコープ内のすべての企業とそのアセットは把握できたので、次はスコープ内の domains を見つける段階です。

_なお、以下の手法では subdomains も見つかる可能性があり、その情報を軽視すべきではありません。_

まず最初に、各企業の**main domain**を探す必要があります。たとえば、_Tesla Inc._ なら _tesla.com_ です。

### **Reverse DNS**

各 domain の IP ranges を把握できたら、それらの**IPs に対して reverse dns lookup** を行い、**スコープ内のより多くの domains を見つける**ことを試せます。被害者側の dns server か、よく知られた dns server（1.1.1.1、8.8.8.8）を使ってみてください
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者が手動で PTR を有効化する必要があります。\
この情報にはオンラインツールも使えます: [http://ptrarchive.com/](http://ptrarchive.com)。\
大きな範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールが reverse lookups と enrichment を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** の中には、**organization name**、**address**、**emails**、電話番号など、興味深い **information** がたくさんあります。さらに興味深いのは、これらの項目のどれかを使って **reverse whois lookups** を行うと、**その会社に関連するより多くの assets** を見つけられることです（たとえば、同じ email が出てくる別の whois registry など）。\
次のようなオンラインツールを使えます:

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

このタスクは [**DomLink** ](https://github.com/vysecurity/DomLink) を使って自動化できます（whoxy API key が必要）。\
また、[amass](https://github.com/OWASP/Amass) を使って一部の automatic reverse whois discovery もできます: `amass intel -d tesla.com -whois`

**この technique は、新しい domain を見つけるたびに、さらに多くの domain names を発見するために使えることに注意してください。**

### **Trackers**

2 つの異なるページで **同じ tracker の同じ ID** が見つかれば、**その両方のページが同じ team によって管理されている** と推測できます。\
たとえば、複数のページで同じ **Google Analytics ID** や同じ **Adsense ID** を見つけた場合です。

これらの tracker や他の情報で検索できるページやツールがいくつかあります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (shared analytics/trackers により related sites を見つける)

### **Favicon**

同じ favicon icon hash を見ることで、対象に関連する domain や subdomain を見つけられることを知っていましたか? まさにそれを [@m4ll0k2](https://twitter.com/m4ll0k2) による [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が行います。使い方は次のとおりです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じ favicon icon hash を持つドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihash は対象と同じ favicon icon hash を持つドメインを見つけるのに使えます。

さらに、[**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) で説明されているように、favicon hash を使って technologies を検索することもできます。つまり、**脆弱な version の web tech の favicon の hash** を知っていれば、shodan で検索して **さらに多くの脆弱な場所** を見つけられます:
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
これは、Webの**favicon hash**を**calculate**する方法です:
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
[**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) を使って favicon hashes を大量に取得し、その後 Shodan/Censys で pivot することもできます。

### **Copyright / Uniq string**

Webページ内で、**同じ組織の別のwebs間で共有されている可能性がある文字列**を探します。**copyright string** はその良い例です。その文字列を **google**、他の **browsers**、あるいは **shodan** で検索します: `shodan search http.html:"Copyright string"`

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

Webサイト such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) や tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) を使って、**同じ dmarc 情報を共有する domains and subdomain** を見つけることができます。\
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

大量のサブドメインを取得する最も速い方法は、外部ソースを検索することです。最もよく使われる**tools**は以下のとおりです（より良い結果のためにAPIキーを設定してください）:

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
他にも**興味深いツール/API**があり、サブドメイン探索に特化していなくても、サブドメインを見つけるのに役立つものがあります。例えば:

- [**IP.THC.ORG**](https://ip.thc.org) free API
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
- [**RapidDNS**](https://rapiddns.io) 無料API
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
- [**gau**](https://github.com/lc/gau)**:** AlienVaultのOpen Threat Exchange、Wayback Machine、Common Crawlから、指定したドメインに対して既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): これらはウェブをスキャンして JS ファイルを探し、そこからサブドメインを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) は、subdomains と IP 履歴を検索できる無料 API を提供している
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは、**bug-bounty programs に関連するすべての subdomains を無料で**提供している。このデータは [chaospy](https://github.com/dr-0x0x/chaospy) でも利用でき、さらにこのプロジェクトで使われている scope も参照できる [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

これら多くのツールの**比較**はこちらで見つけられる: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain 名を使って、DNS servers を brute-forcing して新しい **subdomains** を見つけてみよう。

この作業には、以下のような **一般的な subdomains の wordlists** が必要になる:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

さらに、良質な DNS resolvers の IP も必要になる。信頼できる DNS resolvers のリストを生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使ってフィルタリングできる。あるいは次を使ってもよい: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨されるツールは次のとおり:

- [**massdns**](https://github.com/blechschmidt/massdns): これは、効果的な DNS brute-force を行った最初のツールだった。非常に高速だが、false positives が出やすい。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは、たぶん 1 つの resolver だけを使っていると思う
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、go で書かれており、active bruteforce を使って有効なサブドメインを列挙できるほか、wildcard handling と簡単な input-output サポートを備えてサブドメインを解決できます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用して、ドメイン名を非同期にブルートフォースします。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### Second DNS Brute-Force Round

オープンソースを使ってサブドメインを見つけ、ブルートフォースした後、見つかったサブドメインの変種を生成して、さらに多くを見つけようとできます。この目的には、いくつかのツールが役立ちます:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** 与えられたドメインとサブドメインから permutation を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインが与えられた場合、permutation を生成する。
- [**goaltdns**](https://github.com/subfinder/goaltdns) の permutations 用 **wordlist** は [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) で入手できる。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインが与えられた場合、パーミュテーションを生成します。パーミュテーションファイルが指定されていない場合、gotator は独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutation を生成するだけでなく、解決も試みることができます（ただし、前述のコメント付きツールを使う方がよいです）。
- altdns の permutations 用 **wordlist** は [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインに対して permutation、mutation、alteration を行う別のツールです。このツールは結果に対して brute force を行います（dns wild card はサポートしていません）。
- dmut の permutations wordlist は [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) で入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づいて、指定されたパターンに基づく新しい潜在的なサブドメイン名を生成し、より多くのサブドメインを見つけようとします。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 詳しくはこの[**post**](https://cramppet.github.io/regulator/index.html)を読んでください。基本的には、**discovered subdomains** から**main parts**を取得し、それらを組み合わせてさらに多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルでありながら効果的な DNS 応答誘導アルゴリズムと組み合わされたサブドメインの brute-force fuzzer です。これは、カスタマイズされた wordlist や過去の DNS/TLS レコードのような、提供された入力データセットを利用して、より対応するドメイン名を正確に生成し、DNS scan 中に収集した情報に基づいてループ内でさらに拡張していきます。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows** を使ってドメインから **subdomain discovery** を自動化する方法について書いたこのブログ投稿を確認してください。これで、コンピュータ上でたくさんのツールを手動で起動する必要がなくなります:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

IP address に **1つまたは複数の web pages** が含まれていて、それらが subdomains に属しているのを見つけた場合、その IP 上の **webs を持つ他の subdomains** を、**OSINT sources** でその IP 内の domains を調べるか、その IP に対して **VHost domain names を brute-force** することで探せます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他の APIs を使って、IPs 内の VHosts を見つける** ことができます。

**Brute Force**

web server の中に subdomain が隠されていると подозう場合は、brute force を試せます:

**IP が hostname にリダイレクトする** 場合（name-based vhosts）、`Host` header を直接 fuzz し、ffuf に **auto-calibrate** させて default vhost との差分がある response を強調表示します:
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
> この technique を使うと、internal/hidden endpoints にもアクセスできる場合があります。

### **CORS Brute Force**

場合によっては、_**Origin**_ ヘッダーに有効な domain/subdomain が設定されたときだけ、_**Access-Control-Allow-Origin**_ ヘッダーを返すページが見つかります。こうした scenario では、この挙動を悪用して新しい **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を調べる際は、それが何らかの **bucket** を指していないか確認し、その場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
また、この時点でスコープ内のすべてのドメインが分かっているはずなので、[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) も試してください。

### **Monitorization**

ドメインの **new subdomains** が作成されるのを、**Certificate Transparency** Logs を監視することで **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行います。

### **Looking for vulnerabilities**

可能な [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) を確認してください。\
もし **subdomain** が **S3 bucket** を指しているなら、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) してください。

**assets discovery** で既に見つけたものと **IPが異なる subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**nmap/masscan/shodan** を使ったいくつかの [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行すべきです。稼働しているサービスによっては、**この book** にそれらを「attack」するためのトリックがいくつかあります。\
_Note that sometimes the subdomain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## IPs

最初の手順で、**いくつかの IP ranges、domains、subdomains** を見つけているかもしれません。\
**それらの ranges からすべての IP を再収集**し、さらに **domains/subdomains に対して (DNS queries)** も行いましょう。

以下の **free apis** のサービスを使うと、**domains and subdomains が過去に使用していた IP** も見つけられます。これらの IP は、まだクライアントが所有している可能性があり（[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけるのに役立つことがあります）

- [**https://securitytrails.com/**](https://securitytrails.com/)

ツール [**hakip2host**](https://github.com/hakluke/hakip2host) を使って、特定の IP address を指している domains も確認できます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IP を port scan** してください（そこで興味深いものが見つかる可能性はかなり低いためです）。発見した稼働中のサービスには、**vulnerabilities** が見つかるかもしれません。

**ホストの scan 方法についての** [**guide**](../pentesting-network/index.html) **を参照してください。**

## Web servers hunting

> スコープ内のすべての company とその assets を見つけ、IP ranges、domains、subdomains も把握しました。次は web servers を探す段階です。

前の手順ですでに、発見した IP と domains の **recon** をある程度行っているはずなので、**すべての可能な web servers** をすでに見つけているかもしれません。とはいえ、まだの場合は、これからスコープ内で web servers を探すための **fast tricks** を見ていきます。

なお、これは **web apps discovery** 向けの内容なので、（スコープで **許可されている場合** は）**vulnerability** と **port scanning** も実施してください。

[**masscan** を使って web servers に関連する **ports open** を発見する **fast method** はここにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すための別の使いやすいツールとして [**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) および [**httpx**](https://github.com/projectdiscovery/httpx) があります。domains のリストを渡すと、port 80 (http) と 443 (https) への接続を試みます。さらに、他の ports を試すよう指定することもできます:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内に存在する **すべての web server**（会社の **IP**、およびすべての **domains** と **subdomains**）を見つけたとしても、たぶん **どこから始めればよいかわからない** でしょう。では、シンプルにして、まずそれらすべてのスクリーンショットを撮りましょう。**メインページ** を **見るだけ** で、より **vulnerable** になりやすい **weird** な endpoint を見つけられることがあります。

提案したアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.** を使えます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての **screenshots** を解析し、**どれに vulnerabilities がありそうか**、どれにはないかを判定させることもできます。

## Public Cloud Assets

会社に属する可能性のある cloud assets を見つけるには、まず **その会社を識別するキーワードのリスト** から始めるべきです。たとえば crypto 企業なら、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` のような単語を使えます。

また、**bucket でよく使われる一般的な単語** の wordlists も必要になります:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

その後、それらの単語を使って **permutations** を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を参照）。

作成した wordlists を使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.** のようなツールを使えます。

Cloud Assets を探すときは、AWS の bucket だけでなく **もっと広く探す** ことを忘れないでください。

### **Looking for vulnerabilities**

**open buckets** や **cloud functions exposed** のようなものを見つけたら、それらに **アクセス** して、何を提供しているのか、悪用できるかを確認すべきです。

## Emails

スコープ内の **domains** と **subdomains** があれば、基本的に emails を探し始めるために必要なものは揃っています。会社の emails を見つけるのに最も役立った **APIs** と **tools** は次のとおりです:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

emails は後で、**web logins や auth services**（SSH など）を **brute-force** するときに役立ちます。さらに、**phishings** にも必要です。加えて、これらの APIs は email の裏にいる人物についての **さらに多くの info** を与えてくれるため、phishing campaign に有用です。

## Credential Leaks

**domains**、**subdomains**、および **emails** があれば、過去に漏えいした、それらの emails に属する credentials を探し始められます:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**valid leaked** credentials が見つかれば、これは非常に簡単な大当たりです。

## Secrets Leaks

Credential leaks は、**sensitive information が漏えいして売られた** 企業への hack と関連しています。しかし、企業はこれらのデータベースに情報が載っていない **別の leaks** の影響を受けている可能性もあります:

### Github Leaks

Credentials や APIs は、**company** の **public repositories** や、その github company で働く **users** のリポジトリに漏えいしているかもしれません。\
**tool** [**Leakos**](https://github.com/carlospolop/Leakos) を使うと、組織とその開発者の **public repos** をすべて **download** し、それらに対して自動で [**gitleaks**](https://github.com/zricethezav/gitleaks) を実行できます。

**Leakos** は、渡された **text** を含む **URLs passed** に対して **gitleaks** を実行することにも使えます。というのも、**web pages also contains secrets** のことがあるからです。

#### Github Dorks

攻撃中の組織で検索できる可能性のある **github dorks** については、この **page** も確認してください:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

攻撃者や単なる従業員が、会社のコンテンツを paste site に **publish** することがあります。そこに **sensitive information** が含まれることも含まれないこともありますが、検索してみる価値は非常にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos) を使うと、80以上の paste site を同時に検索できます。

### Google Dorks

古くても定番の google dorks は、そこにあるべきではない **exposed information** を見つけるのに常に役立ちます。問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) には手動では実行しきれない数千件ものクエリ候補があることです。そこで、お気に入りの 10 個だけ使うか、[**Gorks**](https://github.com/carlospolop/Gorks) のような **tool** を使ってすべて実行できます。

_Regular Google browser を使って database 全体を実行しようとする tools は、Google にすぐブロックされるため、最後まで終わることはないので注意してください。_

### **Looking for vulnerabilities**

**valid leaked** credentials や API tokens が見つかれば、これは非常に簡単な大当たりです。

## Public Code Vulnerabilities

会社に **open-source code** があることがわかったら、それを **analyse** して **vulnerabilities** を探せます。

**language によって** 使える **tools** は異なります:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

また、次のような、**public repositories** を **scan** できる無料サービスもあります:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters によって見つかる **vulnerabilities の大半** は **web applications** 内にあります。そのため、この時点で **web application testing methodology** について話したいと思います。詳細は [**こちら**](../../network-services-pentesting/pentesting-web/index.html) を参照してください。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) のセクションも特筆したいです。というのも、非常に重要な vulnerabilities を見つけられると期待すべきではないものの、**workflows** に組み込んで初期の web 情報を得るのに役立つからです。

## Recapitulation

> おめでとうございます！ この時点で、あなたはすでに **all the basic enumeration** を終えています。そう、basic です。というのも、もっと多くの enumeration が可能だからです（後でもっとトリックを見ます）。

つまり、すでに次のことを行いました:

1. スコープ内のすべての **companies** を見つけた
2. 会社に属するすべての **assets** を見つけた（スコープ内なら vuln scan も実施）
3. 会社に属するすべての **domains** を見つけた
4. domains のすべての **subdomains** を見つけた（subdomain takeover はあるか？）
5. スコープ内のすべての **IPs**（CDN 由来のものと **そうでないもの**）を見つけた
6. すべての **web servers** を見つけてスクリーンショットを撮った（深く調べる価値のある weird なものはあるか？）
7. 会社に属するすべての潜在的な public cloud assets を見つけた
8. **Emails**、**credentials leaks**、および **secret leaks** を見つけて、簡単に大きな成果を得られる可能性を確認した
9. 見つけたすべての webs を **Pentesting** した

## **Full Recon Automatic Tools**

指定されたスコープに対して、提案された作業の一部を実行してくれるツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix) のすべての無料コース、たとえば [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
