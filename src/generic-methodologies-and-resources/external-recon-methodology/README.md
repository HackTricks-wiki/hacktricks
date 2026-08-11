# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Asset の調査

> ある会社に属するすべてのものが scope 内にあると伝えられ、その会社が実際に何を所有しているのかを把握したいとします。

このフェーズの目標は、**主要会社が所有するすべての会社**、そしてそれらの会社の**すべての asset**を取得することです。そのために、以下を行います。<sup>[[1]](#references)</sup>

1. 主要会社による買収を見つけます。これにより scope 内の会社がわかります。
2. 各会社の ASN（存在する場合）を見つけます。これにより、各会社が所有する IP range がわかります。
3. reverse whois lookup を使用して、最初のエントリに関連するその他のエントリ（organisation name、domain など）を検索します（これは再帰的に実行できます）。
4. Shodan の `org` および `ssl` filter などの他の technique を使用して、その他の asset を検索します（`ssl` trick は再帰的に実行できます）。

### **買収**

まず、**主要会社が所有するその他の会社**を把握する必要があります。\
1つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**主要会社を検索**して、**「acquisitions」**を**クリック**することです。そこには、主要会社が買収したその他の会社が表示されます。\
別の方法は、主要会社の **Wikipedia** ページにアクセスし、**acquisitions** を検索することです。\
公開会社の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または各国の corporate registry（例：英国の **Companies House**）を確認します。\
グローバルな corporate tree と subsidiary については、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) と **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) を試してください。

> ここまでで、scope 内のすべての会社がわかったはずです。次に、それらの asset を見つける方法を確認します。

### **ASN**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部 network への access に関する明確に定義された policy を持つ **IP address の block**で構成され、単一の organisation によって管理されますが、複数の operator で構成される場合があります。

**company に ASN が割り当てられているか**を調べて、その **IP range** を把握することは有益です。scope 内のすべての **host**に対して**vulnerability test**を実行し、これらの IP 内にある **domain**を探すとよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company **name**、**IP**、または **domain** で**検索**できます。\
**company の region に応じて、より多くの data を収集するために、以下の link が役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、**[**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、**[**APNIC**](https://www.apnic.net) **（Asia）、**[**LACNIC**](https://www.lacnic.net) **（Latin America）、**[**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにしても、おそらく** useful information **（IP range と Whois）は最初の link にすでに表示されています。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration は、scan の最後に ASNs を自動的に集約して要約します。
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
組織の IP ranges は、[http://asnlookup.com/](http://asnlookup.com)（free API があります）を使用して見つけることもできます。\
[http://ipv4info.com/](http://ipv4info.com) を使用すると、ドメインの IP と ASN を見つけることができます。

### **脆弱性の調査**

この時点で、**スコープ内にあるすべての asset** が把握できているため、許可されている場合は、すべての host に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりできます。見つけたものに応じて**、実行中の複数のサービスをどのように pentest するかについて、この book を確認するとよいでしょう。\
**また、いくつかの** default username **と** passwords **の lists を準備し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使用して services の** bruteforce **を試すことも有効です。**

## ドメイン

> スコープ内にあるすべての company とその asset がわかったので、次はスコープ内の domains を見つけます。

_以下で説明する techniques では subdomains も見つけられるため、その情報を過小評価してはいけないことに注意してください。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges を見つけたら、それらの **IPs に対して reverse dns lookups** を実行し、**スコープ内にあるさらに多くの domains を見つける**ことができます。victim の dns server、または well-known dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、administrator が手動で PTR を有効にする必要があります。\
この情報には、オンラインツールも使用できます: [http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のような tools が、reverse lookup と情報の追加を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** の中には、**organisation name**、**address**、**emails**、phone numbers など、多くの興味深い **information** が含まれています。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookups** を実行すると、**会社に関連するより多くの assets** を見つけられることです（たとえば、同じ email が表示される別の whois registries）。\
次のような online tools を使用できます:

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（Web and API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web は **無料**、API は無料ではありません。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100 回無料**の検索のみ）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 無料ではありません（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 無料ではありません（API）

この task は [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動化することもできます: `amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、この technique を使ってより多くの domain names を発見できることに注意してください。**

### **Trackers**

2 つの異なる pages で**同じ tracker の同じ ID**を見つけた場合、**両方の pages** が**同じ team によって管理されている**と推測できます。\
たとえば、複数の pages で同じ **Google Analytics ID** や同じ **Adsense ID** を見つけた場合です。

これらの trackers などから検索できる pages や tools があります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有された analytics/trackers により関連 sites を見つけます）

### **Favicon**

同じ favicon icon hash を検索することで、target に関連する domains と subdomains を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が行うことです。使用方法は次のとおりです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
簡単に言えば、favihash を使うと、対象と同じ favicon icon hash を持つドメインを発見できます。

![同じ favicon hash を持つドメインの発見に使用した favihash の出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知の favicon hash を Shodan または FOFA の pivot として使用し、同じ technology の他の公開インスタンスを見つけます。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Webサイトの **favicon hash**（faviconのバイト列を **base64-encoded** したものに対するMMH3）を**計算する**方法です：
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

favicon fingerprint は手掛かりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトであり、collision、再利用された icon、意図的な spoofing の可能性があります。
- **`/favicon.ico` 以外も probe する**: framework/build paths、manifest files、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URLs、HTML の `<link rel="icon">` tags を調査します。
- **Static assets は WAF/SSO/IdP controls の背後でも到達可能な場合がある**: icon に直接 request し、`ETag`、`Last-Modified`、redirects、cache headers を確認します。
- **matches を周辺のシグナルで検証する**: title、HTML/body hash、headers、TLS certificate subjects/SANs、product components、exposed ports を比較します。
- **HTML/body hash で cluster 化する**: 一貫した template は fingerprint をより強くします。異なる templates は、generic または shared icon であることを示します。
- **無関係な signatures、ports、products にまたがって hash が出現する場合は、potential honeypot または placeholder として扱う。**
- **曖昧な targets では、実在する page と存在しない path**（`/_favicon_probe_<8-hex>` など）を比較します。同一の hosting または parking responses が、shared icon の理由を説明できる場合があります。
- **favicon hashes を products および CPEs に対応付ける Nuclei detection rules または public datasets から triage を開始する。**
- **IP-centric coverage gap を忘れない**: CDN-fronted、SNI-routed、anycast、domain-only surfaces は、Shodan-like datasets から欠落している可能性があります。

### **Copyright / Uniq string**

Web pages 内で、**同じ organisation に属する異なる web sites 間で共有されている可能性のある strings**を検索します。**copyright string** は良い例です。次に、その string を **google**、他の **browsers**、または **shodan** でも検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job は次のようになることがよくあります。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべての certificates を同時に renew するためです。certificate の timestamps や certificate-transparency log の positions を相関させることで、関連する domains を明らかにできます。<sup>[[6]](#references)</sup>

また、**certificate transparency** logs を直接使用します：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような web や、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のような tool を使用して、**同じ dmarc information を共有する domains と subdomain** を見つけられます。\
その他の useful tools は [**spoofcheck**](https://github.com/BishopFox/spoofcheck) と [**dmarcian**](https://dmarcian.com/) です。

### **Passive Takeover**

放置された A record は、cloud provider が IP を再割り当てしたときに到達可能になることがあります。参照されている research では、instance を provision し、その address を passive DNS data と相関させる opportunistic workflow が示されています。takeover scenarios の test は、承認された scope 内でのみ実施してください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しい domain を見つけるたびに、該当する discovery pivots を繰り返してください。それぞれの結果から、元の seed からは見えなかった追加の certificate names、passive-DNS relationships、favicon matches、organization identifiers が明らかになる可能性があります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP space を所有している organisation の名前はすでにわかっているため、Shodan では次のようにその data で search できます：`org:"Tesla, Inc."` 見つかった hosts の TLS certificate に、新しく予期しない domains がないか確認します。

main web page の **TLS certificate** に access し、**Organisation name** を取得してから、**Shodan** が把握しているすべての web pages の **TLS certificates** 内でその名前を search することもできます。filter は `ssl:"Tesla Motors"` を使用するか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のような tool を使用します。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) は、main domain に**関連する domains** と、それらの **subdomains** を探す tool です。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNS data は、現在も resolve する、または takeover 可能な**古く忘れられた records**を見つけるのに最適です。次を確認してください：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) を確認してください。ある company が**ある domain を使用している**ものの、**ownership を失っている**可能性があります。その domain を（十分に安ければ）register し、company に知らせてください。

すでに asset discovery で見つけたものとは**異なる IP を持つ domain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**port scan**（[こちら](../pentesting-network/index.html#discovering-hosts-from-the-outside)）を **nmap/masscan/shodan** で実行してください。稼働している services によっては、**それらを「attack」するための tricks がこの book にあります**。\
_その domain が client によって管理されていない IP 内で hosted されている場合があるため、scope 外となります。注意してください。_

## Subdomains

> scope 内にあるすべての companies、各 company のすべての assets、そして companies に関連するすべての domains を把握しています。

見つかった各 domain について、可能性のあるすべての subdomains を見つける段階です。

> [!TIP]
> domains を見つけるための tools や techniques の一部は、subdomains の発見にも役立つことに注意してください

### **DNS**

**DNS** records から **subdomains** を取得してみましょう。また、**Zone Transfer** も試す必要があります（脆弱な場合は report してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のサブドメインを取得する最も速い方法は、外部ソースを検索することです。最もよく使用される **tools** は次のとおりです（より良い結果を得るには、API keys を設定してください）。

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
**その他にも興味深いtools/APIs**があり、subdomainsの発見に直接特化していなくても、subdomainsの発見に役立つ可能性があります。例：

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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインの既知のURLをAlienVaultのOpen Threat Exchange、Wayback Machine、Common Crawlから取得します。
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
- [**securitytrails.com**](https://securitytrails.com/) には、subdomains と IP history を検索するための無料 API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project は、**bug-bounty programs に関連するすべての subdomains を無料で**提供します。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使用してアクセスすることも、さらにこの project で使用されている scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます

これらの tools の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

考えられる subdomain names を使って DNS servers に対して brute-forcing を行い、新しい **subdomains** を見つけてみましょう。

この作業には、次のような **common subdomains wordlists が**必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れた DNS resolvers の IPs も必要です。信頼できる DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使用して filter できます。あるいは、次のものを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという問題があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverしか使わないと思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、Go で記述された `massdns` のラッパーで、active bruteforce を使用した有効なサブドメインの列挙や、wildcard handling に対応したサブドメインの解決、簡単な input-output サポートを可能にします。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): `massdns` も使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用してドメイン名を非同期で brute force します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 2回目の DNS Brute-Force Round

オープンソースの情報収集と brute-forcing を使用して subdomains を発見した後、発見した subdomains の変形を生成して、さらに多くのものを見つけられる可能性があります。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains と subdomains が与えられると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインから permutation を生成します。
- goaltdns の permutation **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、組み合わせを生成します。組み合わせファイルが指定されていない場合、gotator は独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの解決も試行できます（ただし、前述のコメントアウトされたツールを使用する方が適しています）。
- altdns の permutations **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別の tool。この tool は結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンから**新たな候補サブドメイン名を生成**し、より多くのサブドメインの発見を試みます。

#### スマートな permutation 生成

- [**regulator**](https://github.com/cramppet/regulator): 発見されたサブドメインから正規表現のようなパターンを学習し、名前解決を行う候補名を生成します。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。カスタマイズされた wordlist や過去の DNS/TLS records など、提供された入力データセットを利用して、対応するドメイン名を正確に合成し、DNS scan 中に収集した情報に基づいてループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflowの例では、再現性のあるsubdomain enumerationのために、OSINT、DNS brute force、permutationのステージを組み合わせています。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

subdomainに属する**1つまたは複数のwebページ**を含むIP addressを発見した場合、そのIPに存在する**他のsubdomainを見つける**ために、IPに紐づくドメインを**OSINT sources**で調査するか、そのIPで**VHostのdomain nameをbrute force**してみることができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter)**やその他のAPIを使用して、IP内の一部の**VHostを見つけることができます**。**

**Brute Force**

一部のsubdomainがweb serverに隠されていると考えられる場合は、brute forceを試すことができます。

name-based vhostの場合は、`Host` headerをfuzzし、ffufのauto-calibrationを使用してdefault responseをfilterします。<sup>[[2]](#references)</sup>
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
> この technique を使うと、internal/hidden endpoints にアクセスできる場合もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定された場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このようなシナリオでは、この挙動を悪用して、新しい **サブドメイン** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、それが何らかの **bucket** を **pointing** していないか確認し、該当する場合は [**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点では scope 内のすべての domain が判明しているため、[**考えられる bucket 名を brute force し、permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してみましょう。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、domain の **new subdomains** が作成されたかどうかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が実行するものです。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認します。\
**subdomain** が **S3 bucket** を pointing している場合は、[**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)します。

assets discovery で既に発見したものとは **異なる IP を持つ subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。稼働している service に応じて、**この book にはそれらを「attack」するための tricks がいくつかあります**。\
_場合によっては、subdomain が client によって管理されていない IP 内で hosted されているため scope 外となることに注意してください。_

## IPs

初期段階で、**IP ranges、domains、subdomains** がいくつか **見つかっている**はずです。\
ここで、それらの range から **すべての IP を収集**し、さらに **domains/subdomains（DNS queries）** の IP を収集します。

以下の **free apis** の service を利用すると、**domains と subdomains が過去に使用していた IP** も見つけられます。これらの IP は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけられる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) という tool を使用して、特定の IP address を pointing している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IP を port scan** します（おそらく、そこでは興味深いものを見つけられないためです）。発見した稼働中の service に **vulnerabilities が存在する**可能性があります。

**host の scan 方法に関する** [**guide**](../pentesting-network/index.html) **を確認してください。**

## Web servers hunting

> scope 内のすべての companies とその assets を発見し、IP ranges、domains、subdomains を把握しました。次は web servers を探します。

前の手順で、発見した IPs と domains の **recon** をすでに実行している可能性が高いため、**考えられるすべての web servers をすでに発見している**かもしれません。しかし、まだの場合は、scope 内の web servers を探すための **fast tricks** をいくつか見ていきます。

これは **web apps discovery 向け**であることに注意してください。そのため、scope で**許可されている**場合は、**vulnerability** と **port scanning** も実行してください。

[**masscan** を使用して web servers に関連する **ports open** を発見する**fast method** は、こちらにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すための別の使いやすい tool として、[**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) があります。domains の list を渡すだけで、port 80（http）と 443（https）への接続を試みます。さらに、他の ports も試すよう指定できます。
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべての web servers**（会社の**IPs**、およびすべての**domains**と**subdomains**）を発見したので、次にどこから始めればよいかわからないかもしれません。そこで、簡単にするため、まずすべての対象のスクリーンショットを撮りましょう。**main page**を**見るだけ**で、より**vulnerable**である可能性が高い**weird**な endpoint を見つけられることがあります。

このアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての**screenshots**を解析し、**vulnerabilities**を含んでいそうなものと、そうでないものを判定することもできます。

## Public Cloud Assets

会社に属する可能性のある cloud assets を見つけるには、まず**その会社を特定する keywords のリスト**から始めます。たとえば、crypto company であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**buckets で一般的に使われる words**の wordlists も必要になります。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの words を使って**permutations**を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlists を使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などの tools を使用できます。**

Cloud Assets を探す際は、AWS の buckets だけに限定しないように注意してください。

### **vulnerabilities の探索**

**open buckets や exposed cloud functions**などを見つけた場合は、**access**して、何が提供されているか、またそれらを abuse できるかどうかを確認してください。

## Emails

スコープ内の**domains**と**subdomains**があれば、基本的に**emails の検索を始めるために必要なもの**はすべて揃っています。以下は、私が会社の emails を見つける際に最もよく機能した**APIs**と**tools**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs とともに使用
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **vulnerabilities の探索**

Emails は、後で**web logins や auth services**（SSH など）を**brute-force**する際に役立ちます。また、**phishings**にも必要です。さらに、これらの APIs によって email の背後にいる**人物についてさらに多くの info**を得られるため、phishing campaign に役立ちます。

## Credential Leaks

**domains、** **subdomains**、および**emails**を使って、それらの emails に属する、過去に leak した credentials を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **vulnerabilities の探索**

**valid leaked** credentials を見つけられれば、非常に簡単な win です。

## Secrets Leaks

Credential leaks は、会社が hack され、**sensitive information が leak して売却された**ケースに関連しています。しかし、会社は、それらの databases に情報が存在しない**他の leaks**の影響を受けている可能性もあります。

### Github Leaks

Credentials や APIs は、**company**の**public repositories**、またはその github company で働く**users**の public repositories に leak している可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos) という**tool**を使えば、**organization**とその**developers**の**public repos**をすべて**download**し、[**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos**は、指定した **URLs passed** から提供されたすべての**text**に対して **gitleaks** を実行するためにも使えます。これは、**web pages にも secrets が含まれている**ことがあるためです。

#### Github Dorks

組織内で検索できる可能性のある **GitHub dorks** については、[GitHub dorks and leaks page](github-leaked-secrets.md) を確認してください。

### Pastes Leaks

攻撃者や単なる従業員が、**company content を paste site に publish**することがあります。そこに**sensitive information**が含まれている場合も、含まれていない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos) tool を使えば、80以上の paste sites を同時に検索できます。

### Google Dorks

古いながらも有用な google dorks は、**本来そこにあるべきではない exposed information**を見つける際に常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) に数千もの候補 query が含まれており、それらを手動で実行できないことです。そのため、お気に入りの 10 個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **のような tool を使ってすべてを実行**できます。

_通常の Google browser を使って database 全体を実行しようとする tools は、Google が非常に早く block するため、決して終了しないことに注意してください。_

### **vulnerabilities の探索**

**valid leaked** credentials や API tokens を見つけられれば、非常に簡単な win です。

## Public Code Vulnerabilities

会社が **open-source code** を保有していることがわかった場合は、それを**analyse**し、そこから**vulnerabilities**を探すことができます。

**language に応じて**使用できる**tools**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) の一覧を確認してください。

また、以下のように**public repositories を scan**できる free services もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters が発見する**vulnerabilities の大部分**は**web applications**内に存在するため、ここでは**web application testing methodology**について説明したいと思います。情報は[**こちらで確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) のセクションにも特に触れておきたいと思います。非常にセンシティブな vulnerabilities の発見を期待すべきではありませんが、**workflows に組み込んで初期の web information を得る**のに役立ちます。

## Recapitulation

> Congratulations！この時点で、すでに**all the basic enumeration**を実行しています。多くの追加 enumeration が可能であるため basic と呼んでいます（後でさらに tricks を紹介します）。

すでに以下を実行しました。

1. スコープ内の**companies**をすべて発見した
2. 会社に属する**assets**をすべて発見した（スコープ内であれば vuln scan も実行した）
3. 会社に属する**domains**をすべて発見した
4. domains の**subdomains**をすべて発見した（subdomain takeover はないか？）
5. スコープ内の**IPs**（**CDNs**経由のものと、経由していないもの）をすべて発見した
6. **web servers**をすべて発見し、それらの**screenshots**を撮影した（詳しく調べる価値のある weird なものはないか？）
7. 会社に属する可能性のある**public cloud assets**をすべて発見した
8. 非常に簡単に**大きな win**につながる可能性のある**Emails**、**credentials leaks**、**secret leaks**
9. 発見したすべての web に対して**Pentesting**を実行した

## **Full Recon Automatic Tools**

指定されたスコープに対して、提案した作業の一部を実行する tools がいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
