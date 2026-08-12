# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> つまり、ある会社に属するすべてのものが scope 内にあると伝えられ、その会社が実際に何を所有しているのかを把握したいということです。

このフェーズの目的は、**主要会社が所有するすべての会社**を特定し、次にそれらの会社のすべての**assets**を特定することです。そのために、以下を行います。<sup>[[1]](#references)</sup>

1. 主要会社による買収先を見つけます。これにより、scope 内の会社がわかります。
2. 各会社の ASN（存在する場合）を見つけます。これにより、各会社が所有する IP ranges がわかります。
3. reverse whois lookup を使用して、最初のエントリに関連する他のエントリ（organisation names、domains など）を検索します（これは再帰的に実行できます）。
4. shodan の `org` および `ssl` filters などの他の techniques を使用して、他の assets を検索します（`ssl` trick は再帰的に実行できます）。

### **Acquisitions**

まず、**主要会社が所有する他の会社**を把握する必要があります。\
[https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**主要会社を検索**して、**「acquisitions」**を**クリック**する方法があります。そこには、主要会社に買収された他の会社が表示されます。\
別の方法として、主要会社の **Wikipedia** ページにアクセスし、**acquisitions** を検索します。\
公開会社の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または各国の corporate registries（例：英国の **Companies House**）を確認します。\
グローバルな corporate trees と subsidiaries については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）および **GLEIF LEI** database（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、scope 内のすべての会社がわかったはずです。次に、それらの assets を見つける方法を確認しましょう。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS** は、外部 networks へのアクセスに関する明確に定義された policy を持ち、単一の organisation によって管理される **IP addresses** の**blocks**で構成されます。ただし、複数の operators で構成される場合があります。

**company に ASN が割り当てられているか**を確認し、その **IP ranges** を特定することは有用です。**scope** 内のすべての **hosts** に対して **vulnerability test** を実行し、これらの IP 内にある **domains** を探すことが有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company **name**、**IP**、または **domain** で**検索**できます。\
**company の region に応じて、より多くの data を収集するために、以下の links が役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにせよ、おそらく** useful information **（IP ranges と Whois）は最初の link にすでに表示されます。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の** enumeration はスキャン終了時に ASNs を自動的に集約して要約します。
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
組織の IP ranges は、[http://asnlookup.com/](http://asnlookup.com)（無料 API あり）でも確認できます。\
[http://ipv4info.com/](http://ipv4info.com) を使用すると、domain の IP と ASN を確認できます。

### **脆弱性の調査**

この時点で、**scope 内のすべての assets** が判明しているため、許可されている場合は、すべての hosts に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりできます。見つかったものに応じて**、稼働している可能性のある複数の services を pentest する方法について、この book を確認してください。\
**また、いくつかの** default username **と** passwords **の** lists **を用意し、** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **を使って services を** bruteforce **してみるのも有効です。**

## Domains

> scope 内のすべての companies とその assets が判明したので、次は scope 内の domains を見つけます。

_以下で説明する techniques では subdomains も見つかる可能性があるため、その情報を過小評価しないでください。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges が判明したら、それらの **IPs に対して reverse dns lookups** を実行し、**scope 内のより多くの domains を見つける**ことができます。対象の victim の dns server、またはよく知られた dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者が手動で PTR を有効にする必要があります。\
この情報には、オンラインツールも使用できます：[http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) などのツールが、reverse lookup と情報の追加を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** の中には、**organisation name**、**address**、**emails**、電話番号など、多くの興味深い **information** が含まれています。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookup** を実行すると、**会社に関連するさらなる asset** を見つけられることです（例：同じ email が出現する別の whois registry）。\
次のようなオンラインツールを使用できます：

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（Web および API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web は **無料**、API は有料。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（**100 回のみ無料**検索可能）
- [https://www.domainiq.com/](https://www.domainiq.com) - 有料
- [https://securitytrails.com/](https://securitytrails.com/) - 有料（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 有料（API）

[**DomLink** ](https://github.com/vysecurity/DomLink) を使用して、このタスクを自動化できます（whoxy API key が必要です）。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動化することもできます：`amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、 この technique を使ってさらに多くの domain name を発見できることに注意してください。**

### **Trackers**

2 つの異なるページで**同じ tracker の同じ ID** を見つけた場合、**両方のページ**が**同じ team によって管理されている**と推測できます。\
たとえば、複数のページで同じ **Google Analytics ID** または同じ **Adsense ID** が表示される場合です。

これらの tracker などを使って検索できるページやツールがあります：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有された analytics/tracker によって関連サイトを見つける）

### **Favicon**

同じ favicon icon hash を探すことで、target に関連する domain や subdomain を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) ツールが行うことです。使用方法は次のとおりです：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favicon hash を使用して同じ favicon hash を共有するドメインを発見した Favihash の結果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言えば、favihash を使用すると、対象と同じ favicon icon hash を持つドメインを発見できます。

![同じ favicon hash を持つドメインを発見するために使用された favihash の出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知の favicon hash を Shodan または FOFA の pivot として使用し、同じ technology の他の exposed instances を見つけます。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Webサイトの **favicon hash** を計算する方法です（**base64-encoded**された favicon のバイト列に対する MMH3）:
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
また、[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使えば favicon hash を大規模に取得し、その後 Shodan/Censys で pivot することもできます。

favicon fingerprint は手掛かりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく indicator として扱う**: MMH3 はコンパクトであり、collision、再利用された icon、意図的な spoofing の可能性があります。
- **`/favicon.ico` 以外も probe する**: framework/build path、manifest file、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTML の `<link rel="icon">` tag を確認します。
- **static asset は WAF/SSO/IdP control の背後でも到達可能な場合がある**: icon に直接 request し、`ETag`、`Last-Modified`、redirect、cache header を確認します。
- **match を周辺のシグナルで検証する**: title、HTML/body hash、header、TLS certificate の subject/SAN、product component、exposed port を比較します。
- **HTML/body hash で cluster 化する**: 一貫した template は fingerprint の確度を高めます。template が混在している場合は、generic または shared icon である可能性があります。
- **無関係な signature、port、product に hash が現れる場合は、潜在的な honeypot または placeholder として扱う。**
- **曖昧な target では、実在する page と存在しない path**（`/_favicon_probe_<8-hex>` など）を比較します。同じ hosting または parking response が、共有された icon の原因かもしれません。
- **favicon hash を product や CPE に対応付ける Nuclei detection rule または public dataset** から triage を開始します。
- **IP-centric な coverage gap を忘れない**: CDN-fronted、SNI-routed、anycast、domain-only の surface は、Shodan に類似した dataset から欠落している可能性があります。

### **Copyright / Uniq string**

web page 内で、**同じ organisation 内の異なる web サイト間で共有されている可能性のある string** を検索します。**copyright string** は良い例です。その後、その string を **google**、他の **browser**、または **shodan** で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job が次のように設定されていることは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプや certificate-transparency log の位置を相関させることで、関連するドメインを明らかにできます。<sup>[[6]](#references)</sup>

**certificate transparency** logs も直接使用してください：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような Web サイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のような tool を使用して、**同じ dmarc information を共有する domains and subdomains** を見つけられます。\
その他の useful tools は [**spoofcheck**](https://github.com/BishopFox/spoofcheck) と [**dmarcian**](https://dmarcian.com/) です。

### **Passive Takeover**

放置された A record は、cloud provider が IP を再割り当てした際に到達可能になることがあります。参照されている research では、instance を provision し、その address を passive DNS data と相関させる opportunistic workflow が示されています。takeover scenarios のテストは、許可された scope 内でのみ実施してください。<sup>[[7]](#references)</sup>

### **Other ways**

新しい domain を見つけるたびに、該当する discovery pivots を繰り返してください。各結果から、元の seed からは見えなかった追加の certificate names、passive-DNS relationships、favicon matches、organization identifiers が明らかになる可能性があります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP space を所有する organisation の名前はすでに分かっているため、Shodan では次のようにその data で検索できます：`org:"Tesla, Inc."` 見つかった hosts の TLS certificate を確認し、新しく予期しない domains がないか調べてください。

main web page の **TLS certificate** にアクセスして **Organisation name** を取得し、その名前を **Shodan** が把握しているすべての web pages の **TLS certificates** 内で、filter `ssl:"Tesla Motors"` を使って検索することもできます。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のような tool を使用してください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、main domain に**関連する domains** と、それらの **subdomains** を探す tool で、非常に便利です。

**Passive DNS / Historical DNS**

Passive DNS data は、現在も resolve する、または takeover 可能な**古く忘れられた records**を見つけるのに非常に役立ちます。以下を確認してください：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

いくつかの [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) を確認してください。ある company が**ある domain を使用している**ものの、**その ownership を失っている**可能性があります。十分に安ければ登録し、company に知らせてください。

すでに assets discovery で見つけたものとは**異なる IP を持つ domain**を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、`nmap/masscan/shodan` による [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行してください。実行中の services に応じて、**this book には、それらを「attack」するための tricks がいくつか記載されています**。\
_場合によっては、domain が client によって管理されていない IP 内で host されているため、scope 外となることがあります。注意してください。_

## Subdomains

> scope 内のすべての companies、各 company のすべての assets、および companies に関連するすべての domains を把握しています。

見つかった各 domain の、可能なすべての subdomains を見つける段階です。

> [!TIP]
> domains を見つけるための tools や techniques の一部は、subdomains を見つける際にも役立つことに注意してください。

### **DNS**

**DNS** records から **subdomains** を取得してみましょう。**Zone Transfer** も試す必要があります（vulnerable な場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多数のサブドメインを取得する最速の方法は、外部ソースを検索することです。最もよく使用される **tools** は次のとおりです（より良い結果を得るには、API keys を設定してください）。

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
**その他にも興味深いツール/API**があり、subdomains の発見に直接特化していなくても、subdomains の発見に役立つ可能性があります。例：

- [**IP.THC.ORG**](https://ip.thc.org) 無料API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得します
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC 無料 API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から既知の URL を取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Webを巡回してJSファイルを探し、そこからサブドメインを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) には、subdomains と IP history を検索するための無料 API があります。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project では、**bug-bounty programs に関連するすべての subdomains を無料で**提供しています。この data には [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、またこの project で使用されている scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます。

これらの tool の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain 名を使って DNS servers を brute-force し、新しい **subdomains** を探してみましょう。

この操作には、次のような**一般的な subdomains の wordlists**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

さらに、優れた DNS resolvers の IP も必要です。信頼できる DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。または、次のものを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという欠点があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverだけを使うと思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper で、go で記述されています。active bruteforce を使用した有効な subdomains の列挙や、wildcard handling による subdomains の解決、簡単な input-output サポートが可能です。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用してドメイン名を非同期に brute force します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 2回目の DNS Brute-Force ラウンド

オープンソースの利用と brute-forcing によってサブドメインを発見した後、発見したサブドメインのバリエーションを生成して、さらに多くのサブドメインを見つけられる可能性があります。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを指定すると、permutation を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定して、permutations を生成します。
- goaltdns の permutations **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutations を生成します。permutations file が指定されていない場合、gotator は独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains の permutation を生成するほか、それらの resolve も試行できます（ただし、前述のコメントアウトされた tools を使用するほうが適しています）。
- altdns の permutation 用 **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomain の permutations、mutations、alteration を実行するもう1つの tool。この tool は結果を brute force します（dns wildcard には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンから**新たな潜在的サブドメイン名を生成**し、より多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見されたサブドメインから正規表現に似たパターンを学習し、解決を試みる候補名を生成します。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルでありながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された input data を利用し、DNS scan 中に収集した情報に基づいて、対応する domain names を正確に合成し、ループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest の workflow の例では、再現可能な subdomain enumeration のために、OSINT、DNS brute force、permutation の stages を組み合わせています。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

subdomains に属する **1つ以上の web pages** を含む IP address を見つけた場合、その IP に存在する **他の subdomains** を、**OSINT sources** で IP 内の domains を検索するか、**その IP に対して VHost domain names を brute-force** することで見つけられる可能性があります。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他の APIs を使用して、IP 内の VHosts を見つけることができます**。

**Brute Force**

一部の subdomain が web server に隠されていると推測される場合は、brute force を試すことができます。

name-based vhosts の場合は、`Host` header を fuzz し、ffuf の auto-calibration を使用して default response を filter します。<sup>[[2]](#references)</sup>
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
> この technique を使うと、internal/hidden endpoints にアクセスできる可能性もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような状況では、この動作を悪用して新しい **サブドメイン** を **発見** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、何らかの **bucket** を**指している**かどうかを確認し、その場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点では scope 内のすべての domain を把握しているため、[**可能性のある bucket 名を brute force し、permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

### **Monitorization**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行う **Certificate Transparency** Logs を監視することで、domain に**新しい subdomains** が作成されたかどうかを**monitor**できます。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を指している場合は、[**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

**assets discovery** ですでに発見したものとは**異なる IP を持つ subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。実行中の services に応じて、**この book でそれらを「attack」するための tricks を見つけられます**。\
_場合によっては、subdomain が client によって管理されていない IP 内で host されているため、scope 外となることがあります。注意してください。_

## IPs

初期段階で、**IP ranges、domains、subdomains** をいくつか**発見している**可能性があります。\
それらの ranges からすべての IPs を、また **domains/subdomains** については **DNS queries** を使って、**recollect**する時です。

以下の **free apis** の services を使用すると、**domains と subdomains が以前使用していた IPs** も見つけることができます。これらの IPs は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) の発見につながる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool を使用して、特定の IP address を指している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IPs を port scan** してください（そこでは興味深いものが何も見つからない可能性が非常に高いためです）。発見された running services に**vulnerabilities** が存在する可能性があります。

**hosts の scan 方法についての** [**guide**](../pentesting-network/index.html) **を確認してください。**

## Web servers hunting

> すべての companies とその assets を発見し、scope 内の IP ranges、domains、subdomains を把握しました。次は web servers を探します。

これまでの steps で、発見した IPs と domains の **recon** をすでに実行している可能性が高いため、**可能性のあるすべての web servers** をすでに発見しているかもしれません。しかし、まだの場合は、scope 内の web servers を探すための**高速な tricks**をいくつか紹介します。

これは **web apps discovery** 向けであることに注意してください。そのため、scope で**許可されている場合**は、**vulnerability** と **port scanning** も実行してください。

[**masscan** を使用して web servers に関連する **open ports** を発見する高速な方法は、こちらにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すためのもう 1 つの使いやすい tool は、[**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、および [**httpx**](https://github.com/projectdiscovery/httpx) です。domains の list を渡すだけで、port 80 (http) と 443 (https) への接続を試みます。さらに、他の ports も試すよう指定できます。
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべての web servers**（会社の**IPs**、およびすべての**domains**と**subdomains**）を発見したので、次にどこから始めればよいか**わからない**かもしれません。そこで、簡単にするため、まずそれらすべてのスクリーンショットを取得しましょう。**main page**を**見るだけ**で、より**vulnerable**になりやすい**奇妙な**endpointを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**screenshots**を確認し、**vulnerabilitiesが含まれている可能性が高いもの**と、そうでないものを判定することもできます。

## Public Cloud Assets

企業に属する可能性のあるcloud assetsを見つけるには、まず**その企業を特定できるキーワードのリスト**を用意します。たとえば、crypto companyの場合は、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの語を使用できます。

また、**bucketsで一般的に使用される単語**のwordlistも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**permutations**を生成します。詳細については[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を確認してください。

生成したwordlistには、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのtoolを使用できます。**

Cloud Assetsを探す際は、AWSのbucketsだけに限定せず、**それ以上のものを探す**ことを忘れないでください。

### **vulnerabilitiesの探索**

**open bucketsやexposed cloud functions**などを見つけた場合は、**アクセス**して、何が提供されているか、またそれらをabuseできるかを確認してください。

## Emails

スコープ内の**domains**と**subdomains**があれば、基本的に**emailsの検索を開始するために必要なもの**はそろっています。以下は、私が企業のemailsを見つける際に最も効果的だった**APIs**と**tools**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs付き
- [**https://hunter.io/**](https://hunter.io/)のAPI（free version）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（free version）
- [**https://minelead.io/**](https://minelead.io/)のAPI（free version）

### **vulnerabilitiesの探索**

Emailsは、後で**web loginsやauth services**（SSHなど）を**brute-force**する際に役立ちます。また、**phishings**にも必要です。さらに、これらのAPIからはemailの背後にいる**人物に関するより多くの情報**も得られるため、phishing campaignに役立ちます。

## Credential Leaks

**domains、** **subdomains**、および**emails**を使って、それらのemailsに属する、過去にleakしたcredentialsを探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **vulnerabilitiesの探索**

**有効なleaked credentials**を見つけた場合、これは非常に簡単な成果です。

## Secrets Leaks

Credential leaksは、企業がhackされ、**sensitive informationがleakして販売された**ケースに関係します。しかし、企業は、それらのdatabaseに情報が含まれていない**別のleaks**の影響を受けている可能性もあります。

### Github Leaks

CredentialsやAPIsは、**企業**の**public repositories**、またはそのgithub企業で働く**users**のpublic repositoriesからleakしている可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**tool**を使えば、**organization**とその**developers**のすべての**public repos**を**download**し、[**gitleaks**](https://github.com/zricethezav/gitleaks)を自動的に実行できます。

**Leakos**は、指定された**URLs**から提供されたすべての**text**に対して**gitleaks**を実行するためにも使用できます。**web pagesにもsecretsが含まれている**ことがあるためです。

#### Github Dorks

organization内を検索するための**GitHub dorks**候補については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や単なる従業員が、**paste siteに企業の内容を公開**することがあります。そこに**sensitive information**が含まれている場合もあれば、含まれていない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)というtoolを使えば、80以上のpaste sitesを同時に検索できます。

### Google Dorks

古くても有用なgoogle dorksは、**そこに存在すべきでないexposed information**を見つける際に常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に数**千**もの検索候補が含まれており、それらを手動で実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **のようなtoolを使ってすべて実行**できます。

_通常のGoogle browserを使ってdatabase全体を実行しようとするtoolsは、Googleに非常に早くblockされるため、決して終了しないことに注意してください。_

### **vulnerabilitiesの探索**

**有効なleaked credentialsやAPI tokens**を見つけた場合、これは非常に簡単な成果です。

## Public Code Vulnerabilities

企業が**open-source code**を持っていることがわかった場合は、それを**analyse**して、そこに**vulnerabilities**がないか検索できます。

**languageによって**使用できる**tools**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を確認してください。

**public repositoriesをscan**できるfree servicesもあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug huntersが発見する**vulnerabilitiesの大部分**は**web applications**内に存在するため、ここでは**web application testing methodology**について説明します。この[**情報はこちら**](../../network-services-pentesting/pentesting-web/index.html)で確認できます。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)セクションについても特に触れておきます。非常にsensitiveなvulnerabilitiesを発見することを期待すべきではありませんが、**workflowsに組み込んで、初期のweb情報を得る**のに便利です。

## Recapitulation

> おめでとうございます！この時点で、すでに**すべての基本的なenumeration**を実行しました。もちろん、これはbasicです。さらに多くのenumerationが可能だからです（後ほどtricksを紹介します）。

すでに以下を実行しました。

1. スコープ内の**companies**をすべて発見した
2. 企業に属する**assets**をすべて発見した（スコープ内であればvuln scanも実行した）
3. 企業に属する**domains**をすべて発見した
4. domainsの**subdomains**をすべて発見した（subdomain takeoverはあるか？）
5. スコープ内のすべての**IPs**（**CDNs**由来のものと、そうでないもの）を発見した。
6. すべての**web servers**を発見し、スクリーンショットを取得した（詳しく調べる価値のある奇妙なものはあるか？）
7. 企業に属する可能性のある**public cloud assets**をすべて発見した。
8. **Emails**、**credentials leaks**、および**secret leaks**を発見した。これらは非常に簡単に**大きな成果**につながる可能性がある。
9. 発見したすべてのwebを**Pentesting**した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案したactionsの一部を実行してくれるtoolsがいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていない

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Faviconsについて：Browser IconsからAttack Surface Intelligenceまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties、OSINTなどのためのfavicon.icoのWeaponizing](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate TransparencyへのTime-Correlation AttackによるDomainsの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なSubdomain Takeover Campaignの発見（およびEmulating）](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：Subdomain EnumerationのユニークなMethod](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow、Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflowを使用したFull Subdomain Brute Force Discovery、Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
