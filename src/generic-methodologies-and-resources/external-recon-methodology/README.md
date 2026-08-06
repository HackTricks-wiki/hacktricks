# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets の発見

> ある会社に属するすべてのものが scope 内にあると伝えられたので、その会社が実際に所有しているものを把握したいとします。

このフェーズの目的は、**main company が所有するすべての companies**を特定し、続いてそれらの companies のすべての **assets** を特定することです。そのために、以下を行います。

1. main company による acquisitions を見つけ、scope 内の companies を把握する
2. 各 company の ASN（存在する場合）を見つけ、各 company が所有する IP ranges を把握する
3. reverse whois lookup を使用して、最初の company に関連する他の entries（organisation names、domains など）を検索する（これは再帰的に実行可能）
4. shodan の `org` および `ssl` filters などの他の techniques を使用して、他の assets を検索する（`ssl` trick は再帰的に実行可能）

### **Acquisitions**

まず、**main company が所有する他の companies**を把握する必要があります。\
その方法の1つは [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**main company を search**して、**「acquisitions」**を**click**することです。そこには main company によって買収された他の companies が表示されます。\
別の方法は、main company の **Wikipedia** page にアクセスし、**acquisitions**を検索することです。\
public companies については、**SEC/EDGAR filings**、**investor relations** pages、または地域の corporate registries（英国の **Companies House** など）を確認します。\
global corporate trees と subsidiaries については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）および **GLEIF LEI** database（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、scope 内のすべての companies を把握できたはずです。次に、それらの assets を見つける方法を確認します。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS** は、外部 networks への access に関する明確に定義された policy を持ち、単一の organisation によって管理される **IP addresses の blocks** で構成されますが、複数の operators から構成される場合もあります。

**company に ASN が割り当てられているか**を確認し、その **IP ranges** を把握することは有用です。**scope** 内のすべての **hosts** に対して **vulnerability test** を実行し、これらの IP 内にある **domains** を**探す**ことが有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **、または** [**https://ipinfo.io/**](https://ipinfo.io/) **では、company の** name **、**IP**、または **domain** で **search** できます。\
**company の region に応じて、より多くの data を収集するために以下の links が役立つ可能性があります：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、**[**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、**[**APNIC**](https://www.apnic.net) **（Asia）、**[**LACNIC**](https://www.lacnic.net) **（Latin America）、**[**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにしても、おそらく** useful information **（IP ranges と Whois）は、最初の link にすでに表示されています。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の** enumeration は、scan の最後に ASNs を自動的に集約して要約します。
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
組織の IP ranges は、[http://asnlookup.com/](http://asnlookup.com)（free API あり）を使って見つけることもできます。\
[http://ipv4info.com/](http://ipv4info.com) を使えば、domain の IP と ASN を見つけられます。

### **脆弱性の調査**

この時点で、**スコープ内のすべての asset** が判明しているため、許可されている場合は、すべての host に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりすることもできます。見つかったものに応じて**、実行中のさまざまな service を pentest する方法について、この book を確認するとよいでしょう。\
**また、いくつかの** default username **と** passwords **の** lists **を用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使って services を** bruteforce **することも可能です。**

## Domains

> スコープ内のすべての company とその asset を把握したので、次はスコープ内の domain を見つけます。

_以下で説明する techniques では subdomains も見つけられるため、その情報を過小評価してはいけないことに注意してください。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domain のすべての IP ranges を見つけたら、それらの **IPs に対して** **reverse dns lookups** を実行し、**スコープ内の domain をさらに見つける**ことができます。対象の victim の dns server、または well-known dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者が手動で PTR を有効にする必要があります。\
この情報には、オンラインツール [http://ptrarchive.com/](http://ptrarchive.com) も使用できます。\
大規模なレンジの場合、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) などのツールが、reverse lookup と情報の補完を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** 内では、**組織名**、**住所**、**メールアドレス**、電話番号など、多くの興味深い **情報** を見つけられます。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookup** を実行すると、**会社に関連する他の asset** を見つけられることです（例えば、同じメールアドレスが登録されている別の whois registry など）。\
次のようなオンラインツールを使用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（Web および API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web は **無料**、API は無料ではありません。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100 回のみ無料**検索可能）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 無料ではありません（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 無料ではありません（API）

この作業は [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動的に実行することもできます: `amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、この technique を使ってさらに多くの domain name を発見できることに注意してください。**

### **Trackers**

2 つの異なるページで、**同じ tracker の同じ ID** を見つけた場合、**両方のページ** が **同じ team によって管理されている** と推測できます。\
例えば、複数のページで同じ **Google Analytics ID** や同じ **Adsense ID** を確認した場合です。

これらの tracker などを使って検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有された analytics/trackers に基づいて関連サイトを発見）

### **Favicon**

同じ favicon icon hash を探すことで、target に関連する domain や subdomain を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool がまさに行うことです。使用方法は次のとおりです。
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じ favicon icon hash を持つドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihash を使用すると、target と同じ favicon icon hash を持つドメインを発見できます。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、favicon hash を使用して technologies を検索することもできます。つまり、**脆弱なバージョンの web tech の favicon の hash** が分かっていれば、Shodan で検索して、**さらに多くの脆弱な場所を発見**できます:<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、web の **favicon hash**（favicon の **base64-encoded** バイトに対する **MMH3**）を**計算する**方法です：
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
favicon hashes は [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) を使って scale で取得し、その後 Shodan/Censys で pivot することもできます。

favicon fingerprints を使用する際に覚えておくと便利なこと:<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく indicator として扱う**: MMH3 は compact であり、collision が発生する可能性があります。また、operators が favicon を置き換えたり、誤解を招く icon を意図的に再利用したりすることもあります。
- `/favicon.ico` 以外も **probe する**: 多くの products は、framework/build paths や `manifest.json`、`site.webmanifest`、`browserconfig.xml`、`apple-touch-icon*`、inline `data:` URLs、HTML の `<link rel="icon">` tags 経由で icons を公開します。path 自体が product family の fingerprint になる場合もあります。
- **app に到達できない場合でも static files には到達できることが多い**: WAF/SSO/IdP controls は dynamic routes を保護していても、static icons は公開されたままの場合があります。常に favicon を直接 request し、弱い version/build hints がないか `ETag`、`Last-Modified`、redirects、cache headers を確認してください。
- **周辺の signals で matches を validate する**: favicon が product を特定すると結論づける前に、title、HTML/body hash、headers、TLS certificate subjects/SANs、Shodan/Censys components、exposed ports を比較してください。
- **scale で pivot する場合は HTML/body hash で cluster 化する**: favicon を共有するほとんどの hosts が 1 つの page template に集約される場合、その fingerprint はより強力です。同じ hash が多数の無関係な templates に分かれる場合は、product label よりも `"generic/shared/honeypot"` を優先してください。
- **Honeypot heuristic**: 同じ favicon hash が、無関係な多数の HTML signatures、random ports、矛盾する products にまたがって現れる場合、実際の product fingerprint ではなく、probable honeypot または generic placeholder として扱ってください。
- **曖昧な targets では 404 probe を使用する**: browser で実際の page と、`/_favicon_probe_<8-hex>` のような存在しない path を fetch してください。hosting-provider/parking responses が一致する場合、true product overlap よりも shared favicons をよく説明できることがあります。
- **detection rules から mappings を bootstrap する**: Nuclei templates と public favicon datasets は、CVE disclosures 後の rapid triage に役立つ既知の `favicon` ↔ `product` ↔ `CPE` mappings を提供できます。
- **Coverage caveat**: Shodan-style datasets は IP-centric です。CDN-fronted、SNI-routed、anycast、domain-only の surfaces は過小カウントされる可能性があるため、hit count が少ないことは、実環境での deployment が少ないことを **意味しません**。

### **Copyright / Uniq string**

web pages 内で、**同じ organisation の異なる webs 間で共有されている可能性のある strings**を検索します。**copyright string** は良い例です。その後、その string を **google**、他の **browsers**、または **shodan** で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job such as設定されていることは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべてのドメイン証明書を更新するためです。これは、これに使用される CA が Validity time に生成時刻を設定していない場合でも、**certificate transparency logs 内から同じ会社に属するドメインを見つけられる**可能性があることを意味します。\
詳細については、こちらの[**writeup**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)を確認してください。<sup>[[6]](#references)</sup>

また、**certificate transparency** logs を直接使用することもできます。

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような web や、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のような tool を使用して、**同じ dmarc information を共有する domains and subdomain**を見つけられます。\
その他の useful tools として、[**spoofcheck**](https://github.com/BishopFox/spoofcheck) と [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

cloud providers に属する IP に subdomains を割り当て、その後、**その IP address を失ったにもかかわらず DNS record の削除を忘れる**人がいるのは、どうやら一般的なようです。そのため、cloud（Digital Ocean など）で **VM を spawn**するだけで、実際に**一部の subdomain(s) を takeover**できます。

[**この post**](https://kmsec.uk/blog/passive-takeover/)では、その事例を説明し、**DigitalOcean で VM を spawn**し、新しい machine の **IPv4** を**取得**して、それを指す subdomain records を Virustotal で**検索する**script を提案しています。<sup>[[7]](#references)</sup>

### **その他の方法**

**新しい domain を見つけるたびに、この technique を使用してさらに多くの domain names を発見できることに注意してください。**

**Shodan**

すでに IP space を所有する organisation の名前が分かっています。その data を使って、次のように shodan で検索できます：`org:"Tesla, Inc."` 見つかった hosts の TLS certificate を確認し、新しく予想外の domains がないか調べてください。

main web page の **TLS certificate** にアクセスし、**Organisation name** を取得してから、**shodan** が把握しているすべての web pages の **TLS certificates** 内で、その名前を filter `ssl:"Tesla Motors"` により検索できます。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のような tool を使用できます。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、main domain に**関連する domains**と、その**subdomains**を探す tool です。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNS data は、現在も resolve される、または takeover 可能な**古く忘れられた records**を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性の検索**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) がないか確認してください。会社が**ある domain を使用している**ものの、**その ownership を失っている**可能性があります。安価であれば登録し、会社に知らせてください。

すでに asset discovery で見つけたものとは**異なる IP**を持つ **domain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**port scan**（[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)）を **nmap/masscan/shodan** で実行してください。実行中の services に応じて、**それらを「attack」するための tricks**を**この book 内で見つけられます**。\
_場合によっては、その domain が client によって管理されていない IP 内で hosted されているため、scope 外であることがあります。注意してください。_

## Subdomains

> scope 内のすべての companies、各 company のすべての assets、そして companies に関連するすべての domains が分かっています。

見つかった各 domain の、可能性のあるすべての subdomains を見つける段階です。

> [!TIP]
> domain を見つけるための一部の tools と techniques は、subdomains を見つける際にも役立つことに注意してください

### **DNS**

**DNS** records から **subdomains** を取得してみましょう。また、**Zone Transfer** も試す必要があります（脆弱な場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のサブドメインを取得する最も速い方法は、外部ソースを検索することです。最もよく使用される **ツール** は以下のとおりです（より良い結果を得るには API keys を設定してください）。

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
**その他の興味深い tools/API** には、subdomains の発見に直接特化していなくても、subdomains の発見に役立つ可能性があるものがあります。

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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインの既知のURLを、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawlから取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): WebをスクレイピングしてJS filesを探し、そこからsubdomainsを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) には、subdomains と IP history を検索できる無料の API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project では、**bug-bounty programs に関連するすべての subdomains** を無料で提供しています。この data には [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、さらにこの project が使用している scope [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) にアクセスすることもできます

これらの tools の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain 名を使って DNS servers を brute-forcing し、新しい **subdomains** を見つけてみましょう。

この action には、次のような **common subdomains wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼性の高い DNS resolvers の IPs も必要です。trusted DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。または、次の list を使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという欠点があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つしか使わないと思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper で、go で書かれており、active bruteforce を使用した有効な subdomain の列挙、wildcard handling を伴う subdomain の解決、そして容易な input-output support を可能にします。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): `massdns`も使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用してドメイン名を非同期に brute force します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第2回 DNS Brute-Force

公開情報と brute-forcing を使用して subdomains を発見した後、発見した subdomains の variations を生成して、さらに多くの subdomains を見つけられる可能性があります。この目的には、いくつかの tools が役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains と subdomains を指定すると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとsubdomainsを指定すると、permutationsを生成します。
- goaltdnsのpermutations **wordlist**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutations を生成します。permutations file が指定されていない場合、gotator は独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの resolve も試行できます（ただし、前述のコメントアウトされた tools を使用するほうが適しています）。
- altdns の permutations 用 **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomain の permutations、mutations、alteration を実行する別の tool。この tool は結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンから**新たな潜在的サブドメイン名を生成**して、さらにサブドメインを発見できるようにします。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 詳細についてはこの[**投稿**](https://cramppet.github.io/regulator/index.html)を参照してください。基本的には、**発見されたサブドメイン**から**主要部分**を取得し、それらを組み合わせてさらにサブドメインを見つけます。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された input data を利用して、対応する可能性の高い domain names を正確に生成し、DNS scan 中に収集した情報に基づいて loop でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**を使用して、コンピューター上で多数のツールを手動で起動する必要なく、ドメインから**subdomain discoveryを自動化する**方法について私が書いたブログ記事を確認してください：

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

subdomainsに属する**1つ以上のwebページ**を含むIPアドレスを発見した場合、**OSINT sources**でIP上のdomainsを検索するか、**そのIPでVHost domain namesをbrute-force**することで、**そのIP上にある他のsubdomainsとwebs**を見つけられる可能性があります。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他のAPIsを使用して、IP内のVHostsを見つける**ことができます。

**Brute Force**

あるsubdomainがweb server内に隠されていると考えられる場合、次の方法でbrute forceを試すことができます：

**IPがhostnameへredirectする場合**（name-based vhosts）、`Host` headerを直接fuzzし、ffufの**auto-calibrate**によって、default vhostと異なるresponsesを強調表示します：<sup>[[2]](#references)</sup>
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
> この technique により、internal/hidden endpoints にアクセスできる場合もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような状況では、この挙動を悪用して、新しい **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探している際は、それが何らかの **bucket** を **pointing** していないか注意し、その場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点では scope 内のすべてのドメインが分かっているため、[**possible bucket names を brute force して permissions を check**](../../network-services-pentesting/pentesting-web/buckets/index.html) してみてください。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、ドメインの **new subdomains** が作成されたかどうかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行います。

### **Looking for vulnerabilities**

可能性のある [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) を確認してください。\
**subdomain** が何らかの **S3 bucket** を pointing している場合は、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

**assets discovery** ですでに見つけたものとは **different な IP** を持つ **subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**nmap/masscan/shodan** による [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行してください。実行中の services に応じて、**this book にはそれらを "attack" するための tricks がいくつかあります**。\
_場合によっては、subdomain が client によって管理されていない IP 内でホストされているため、scope 外であることに注意してください。_

## IPs

初期段階で、**IP ranges、domains、subdomains** をいくつか **found** している可能性があります。\
それらの ranges からすべての IPs を、また **domains/subdomains** については（DNS queries により）**recollect** するタイミングです。

以下の **free apis** の services を使用すると、**domains and subdomains が以前使用していた IPs** も見つけられます。これらの IPs は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけられる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool を使用して、特定の IP address を pointing している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IPs を port scan** してください（そこでは興味深いものが見つからない可能性が非常に高いため）。検出された running services に vulnerabilities が存在する可能性があります。

**hosts を scan する方法についての** [**guide**](../pentesting-network/index.html) **を確認してください。**

## Web servers hunting

> すべての companies とその assets を見つけ、scope 内の IP ranges、domains、subdomains を把握しました。次は web servers を探します。

前の手順ですでに、discovered した IPs と domains の **recon** を実行している可能性が高いため、すでに可能な web servers をすべて見つけているかもしれません。ただし、まだの場合は、scope 内の web servers を探すための **fast tricks** をいくつか見ていきます。

これは **web apps discovery** 向けの内容であるため、scope で **allowed** されている場合は、**vulnerability** と **port scanning** も実行してください。

[**masscan** による web servers 関連の **ports open** を discover するための **fast method** はここ](../pentesting-network/index.html#http-port-discovery)で確認できます。\
web servers を探すための別の使いやすい tool は [**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、そして [**httpx**](https://github.com/projectdiscovery/httpx) です。domains の list を渡すだけで、port 80 (http) と 443 (https) への接続を試行します。さらに、他の ports も試行するよう指定できます。
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内（会社の **IPs**、すべての **domains** および **subdomains**）に存在する**すべての web servers**を発見した今、おそらく**どこから始めればよいかわからない**でしょう。そこで、簡単にするため、まずすべての対象のスクリーンショットを撮りましょう。**main page**を**見るだけ**で、より**脆弱**である**可能性が高い**、**奇妙な** endpoints を見つけられることがあります。

このアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**screenshots**を確認し、**vulnerabilities を含んでいそうなもの**と、そうでないものを判定することもできます。

## Public Cloud Assets

企業に属する可能性のある cloud assets を見つけるには、まず**その企業を識別する keywords のリスト**から始めるべきです。たとえば、crypto company であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**buckets で一般的に使用される単語**の wordlists も必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**permutations**を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlists を使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などの tools を使用できます。**

Cloud Assets を探す際は、AWS の buckets だけを探せばよいわけではないことを覚えておいてください。

### **Looking for vulnerabilities**

**open buckets や exposed cloud functions**などを見つけた場合は、**アクセス**して、何を提供しているのか、またそれらを abuse できるかどうかを確認するべきです。

## Emails

スコープ内の **domains** と **subdomains** があれば、基本的に**emails の検索を始めるために必要なもの**はすべて揃っています。これらは、私が企業の emails を見つける際に最も効果的だった **APIs** と **tools** です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs 付き
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **Looking for vulnerabilities**

Emails は後で **web logins や auth services**（SSH など）に対する **brute-force**に役立ちます。また、**phishings**にも必要です。さらに、これらの APIs は email の背後にいる**人物に関するより多くの情報**も提供するため、phishing campaign に役立ちます。

## Credential Leaks

**domains、** **subdomains**、および **emails** を使って、それらの emails に関連する、過去に leak した credentials を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**有効な leaked credentials**を見つけられれば、非常に簡単な win です。

## Secrets Leaks

Credential leaks は、**sensitive information が leak され、販売された**企業への hacks に関連しています。しかし、企業は、それらの databases に情報が存在しない**別の leaks**の影響を受けている可能性もあります。

### Github Leaks

Credentials や APIs が、**company**の**public repositories**、またはその github company で働く**users**の public repositories に leak している可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という **tool**を使えば、**organization**およびその**developers**の**public repos**をすべて**download**し、その上で [**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos**は、指定された **URLs**から提供されたすべての**text**に対して **gitleaks**を実行するためにも使用できます。場合によっては、**web pages にも secrets が含まれている**ためです。

#### Github Dorks

organization に対して検索できる potential **github dorks**については、この**page**も確認してください。

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

攻撃者や単なる従業員が、**paste site に company content を publish**することがあります。そこに**sensitive information**が含まれているかどうかは場合によりますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos) tool を使えば、80以上の paste sites を同時に検索できます。

### Google Dorks

古いものですが、優れた google dorks は、**本来存在すべきでない exposed information**を見つける際に常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に、手動では実行できない数千もの query が含まれていることです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などの tool を使ってすべて実行**できます。

_通常の Google browser を使って database 全体を実行しようとする tools は、google が非常に早く block するため、決して終了しないことに注意してください。_

### **Looking for vulnerabilities**

**有効な leaked credentials または API tokens**を見つけられれば、非常に簡単な win です。

## Public Code Vulnerabilities

企業が **open-source code**を保有していることがわかった場合は、それを**analyse**し、そこに**vulnerabilities**がないか検索できます。

**language に応じて**、使用できる **tools**は異なります。

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

また、以下のように、**public repositories**を**scan**できる free services もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters が発見する**vulnerabilities の大部分**は**web applications**内に存在するため、ここでは**web application testing methodology**について説明します。この情報は[**こちらで確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)の section についても特別に言及したいと思います。非常に深刻な vulnerabilities を発見してくれるとは期待すべきではありませんが、**workflows に組み込んで、web に関する初期情報を得る**際に役立ちます。

## Recapitulation

> おめでとうございます！この時点で、すでに**基本的な enumeration をすべて**実行しました。はい、これは basic です。なぜなら、さらに多くの enumeration を実行できるからです（後ほどさらに tricks を紹介します）。

すでに以下を実行しました。

1. スコープ内の**すべての companies**を発見した
2. companies に属する**すべての assets**を発見した（スコープ内であれば vuln scan も実行した）
3. companies に属する**すべての domains**を発見した
4. domains の**すべての subdomains**を発見した（subdomain takeover はあるか？）
5. スコープ内の**すべての IPs**（**CDNs 由来のものと、そうでないもの**）を発見した
6. **すべての web servers**を発見し、それらの**screenshots**を撮影した（詳しく調べる価値のある奇妙なものはあるか？）
7. company に属する可能性のある**すべての public cloud assets**を発見した
8. 非常に簡単に**大きな win**をもたらす可能性のある **Emails**、**credentials leaks**、および **secret leaks**を発見した
9. 発見したすべての web に対して **Pentesting**を実行した

## **Full Recon Automatic Tools**

指定された scope に対して、提案した actions の一部を実行してくれる tools がいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていない

## References

- [1] [**@Jhaddix**](https://twitter.com/Jhaddix) のすべての free courses、たとえば [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [@Asm0d3us - Weaponizing Favicon Ico For Bugbounties Osint And What Not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [swarm.ptsecurity.com - Discovering Domains Via A Time Correlation Attack](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [kmsec.uk - Passive Takeover](https://kmsec.uk/blog/passive-takeover)
- [8] [cramppet.github.io - Regulator - Index](https://cramppet.github.io/regulator/index.html)

{{#include ../../banners/hacktricks-training.md}}
