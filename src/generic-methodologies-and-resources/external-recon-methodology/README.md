# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するすべてのものがスコープ内にあると伝えられ、その会社が実際に何を所有しているのかを把握したいとします。

このフェーズの目的は、**主要な会社が所有するすべての会社**を特定し、続いてそれらの会社のすべての**資産**を特定することです。そのために、以下を実施します。

1. 主要な会社による買収を見つけ、スコープ内の会社を特定する。
2. 各会社のASN（存在する場合）を見つけ、各会社が所有するIP範囲を特定する。
3. reverse whois lookupを使用して、最初のエントリに関連するその他のエントリ（組織名、ドメインなど）を検索する（これは再帰的に実行可能）。
4. shodanの`org`および`ssl`フィルターなど、その他の手法を使用して、他の資産を検索する（`ssl`の手法は再帰的に実行可能）。

### **Acquisitions**

まず、**主要な会社が所有する他の会社**を把握する必要があります。\
1つの方法は、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**主要な会社を検索**して、**「acquisitions」**をクリックすることです。そこには、主要な会社が買収した他の会社が表示されます。\
別の方法は、主要な会社の**Wikipedia**ページにアクセスし、**買収（acquisitions）**を検索することです。\
公開会社の場合は、**SEC/EDGAR filings**、**investor relations**ページ、または各国の法人登記簿（英国の**Companies House**など）を確認します。\
グローバルな企業構造や子会社については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）および**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> これで、スコープ内のすべての会社を把握できたはずです。次に、それらの資産を見つける方法を確認しましょう。

### **ASNs**

Autonomous System Number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって**自律システム**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確に定義されたポリシーを持ち、単一の組織によって管理される**IPアドレスのブロック**で構成されます。ただし、複数のオペレーターで構成される場合があります。

**IP範囲**を特定するために、**会社にASNが割り当てられているか**を確認すると有用です。**スコープ**内にあるすべての**ホスト**に対して**脆弱性テスト**を実施し、これらのIP内にある**ドメインを探す**ことも有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、会社**名**、**IP**、または**ドメイン**から**検索**できます。\
**会社の地域によっては、より多くのデータを収集するために、以下のリンクが役立つ場合があります:** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにせよ、おそらく**有用な情報**（IP範囲とWhois）は、最初のリンクにすでに掲載されています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration は、scan の最後に ASN を自動的に集約して要約します。
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
組織の IP レンジは、[http://asnlookup.com/](http://asnlookup.com)（無料の API があります）でも確認できます。\
ドメインの IP と ASN は、[http://ipv4info.com/](http://ipv4info.com) で確認できます。

### **脆弱性の探索**

この時点で、**scope 内のすべての asset**が判明しているため、許可されている場合は、すべての host に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye **などの services を使用して** open ports **を探したりすることもできます。見つかったものに応じて、稼働している可能性のある各種 services の pentest 方法をこの book で確認してください。**\
**また、いくつかの** default username **と** passwords **の lists を用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使用して services を** bruteforce **することも検討する価値があります。**

## ドメイン

> scope 内のすべての company とその assets が判明したので、次は scope 内の domains を探します。

_以下で説明する techniques では subdomains も見つかる可能性があり、その情報を過小評価すべきではない点に注意してください。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges が判明しているため、それらの **IPs に対して** reverse dns lookups **を実行し、scope 内の別の domains を見つける**ことができます。対象の victim の dns server、または広く知られている dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、administrator が手動で PTR を有効にする必要があります。\
この情報には、オンラインツール [http://ptrarchive.com/](http://ptrarchive.com) も利用できます。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールが、reverse lookup と情報の補完を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** 内では、**organisation name**、**address**、**emails**、phone numbers など、多くの興味深い **information** を見つけられます。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookups** を実行すると、**company に関連する more assets** を見つけられることです（例：同じ email が登場する別の whois registries）。\
次のようなオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **Free**（Web and API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - **Free** web、API は有料
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（**100 回のみ free** searches）
- [https://www.domainiq.com/](https://www.domainiq.com) - 有料
- [https://securitytrails.com/](https://securitytrails.com/) - 有料（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 有料（API）

このタスクは [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動的に実行することもできます：`amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、より多くの domain names を発見するためにこの technique を利用できる点に注意してください。**

### **Trackers**

2 つの異なる pages で、**同じ tracker の同じ ID** を見つけた場合、**両方の pages** は **同じ team によって管理されている** と推測できます。\
例えば、複数の pages で同じ **Google Analytics ID** や同じ **Adsense ID** が表示される場合です。

これらの trackers などを使って検索できる pages や tools がいくつかあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有された analytics/trackers に基づいて related sites を見つける）

### **Favicon**

同じ favicon icon hash を探すことで、target に関連する domains や subdomains を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が実行していることそのものです。使用方法は次のとおりです。
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じ favicon icon hash を持つドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihash を使うと、対象と同じ favicon icon hash を持つドメインを発見できます。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、favicon hash を使用して technologies を検索することもできます。つまり、**脆弱なバージョンの web tech の favicon の hash** がわかっていれば、それを shodan で検索して、**より多くの脆弱な場所を発見**できます：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Webサイトの **favicon hash**（faviconの**base64-encoded**バイトに対するMMH3）を**計算する**方法です：
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
favicon hash は [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使って大規模に取得することもでき、その後 Shodan/Censys で pivot できます。

favicon fingerprint を使用する際に覚えておくべきこと：

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトで、collision が発生する可能性があります。また、operators が favicon を置き換えたり、意図的に誤解を招く icon を再利用したりすることもあります。
- **`/favicon.ico` 以外も probe する**: 多くの製品は、framework/build path や `manifest.json`、`site.webmanifest`、`browserconfig.xml`、`apple-touch-icon*`、inline `data:` URL、HTML の `<link rel="icon">` tag 経由で icon を公開しています。path 自体が product family の fingerprint になることもあります。
- **app に到達できない場合でも static file には到達できることが多い**: WAF/SSO/IdP の controls が dynamic route を保護していても、static icon は公開されている場合があります。常に favicon を直接 request し、`ETag`、`Last-Modified`、redirect、cache header を確認して、version/build に関する弱いヒントを確認してください。
- **周辺の signal で match を検証する**: favicon が product を識別すると結論する前に、title、HTML/body hash、header、TLS certificate の subject/SAN、Shodan/Censys の component、公開 port を比較してください。
- **大規模に pivot する際は HTML/body hash で cluster 化する**: 同じ favicon を共有する host の大半が 1 つの page template に集約される場合、その fingerprint はより強固です。同じ hash が複数の無関係な template に分かれる場合は、product label よりも「generic/shared/honeypot」を優先してください。
- **Honeypot heuristic**: 同じ favicon hash が、無関係な複数の HTML signature、random port、矛盾する product にまたがって現れる場合、実際の product fingerprint ではなく、probable honeypot または generic placeholder として扱ってください。
- **曖昧な target では 404 probe を使用する**: browser で実際の page と、`/_favicon_probe_<8-hex>` のような存在しない path を fetch します。hosting-provider/parking response が一致する場合、実際の product overlap よりも共有 favicon を適切に説明できることがあります。
- **detection rule から mapping を構築する**: Nuclei template と公開 favicon dataset は、CVE disclosure 後の迅速な triage に役立つ既知の `favicon` ↔ `product` ↔ `CPE` mapping を提供できます。
- **Coverage に関する注意点**: Shodan 形式の dataset は IP-centric です。CDN-fronted、SNI-routed、anycast、domain-only の surface は過少計上される可能性があるため、hit count が少ないことは、実環境での deployment が少ないことを意味しません。

### **Copyright / Uniq string**

web page 内で、**同じ organisation の異なる web 間で共有されている可能性のある string** を検索します。**copyright string** は良い例です。次に、その string を **google**、他の **browser**、または **shodan** で検索します：`shodan search http.html:"Copyright string"`

### **CRT Time**

cron job が次のように設定されていることは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべてのドメイン証明書を更新するためです。つまり、これに使用される CA が Validity time に生成時刻を設定していなくても、**certificate transparency logs から同じ会社に属するドメインを見つけることが可能です**。\
詳しくは、[**こちらの writeup**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/) を確認してください。

また、**certificate transparency** logs を直接利用することもできます。

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような web や、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のような tool を使用して、**同じ dmarc information を共有する domains and subdomain** を見つけることができます。\
その他の便利な tool として、[**spoofcheck**](https://github.com/BishopFox/spoofcheck) や [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

cloud providers に属する IP に subdomains を割り当て、ある時点で **その IP address を失ったにもかかわらず DNS record の削除を忘れる**人は、どうやらよくいるようです。そのため、cloud（Digital Ocean など）で **VM を spawn** するだけで、実際に **一部の subdomains を takeover** できてしまいます。

[**この post**](https://kmsec.uk/blog/passive-takeover/) では、その事例について説明し、**DigitalOcean に VM を spawn** し、新しい machine の **IPv4** を **取得**して、それを指す subdomain records を Virustotal で **検索する** script を提案しています。

### **Other ways**

**新しい domain を見つけるたびに、この technique を使用してさらに多くの domain names を発見できることに注意してください。**

**Shodan**

すでに IP space を所有する organisation の名前がわかっているため、次のように shodan でその data を検索できます：`org:"Tesla, Inc."`。見つかった hosts の TLS certificate を確認し、新しい予期しない domains がないか調べてください。

main web page の **TLS certificate** にアクセスして **Organisation name** を取得し、shodan が把握しているすべての web pages の **TLS certificates** 内でその名前を filter `ssl:"Tesla Motors"` を使って検索することもできます。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のような tool を使用できます。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) は、main domain に **関連する domains** と、それらの **subdomains** を探す tool です。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNS data は、現在も resolve される、または takeover 可能な **古く忘れられた records** を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) を確認してください。企業が **ある domain を使用しているものの、その ownership を失っている**可能性があります。安価であれば登録し、企業に知らせてください。

すでに asset discovery で発見したものとは **異なる IP を持つ domain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**port scan**（[こちら](../pentesting-network/index.html#discovering-hosts-from-the-outside)を参照）を **nmap/masscan/shodan** で実行してください。実行中の services に応じて、**それらを「attack」するための tricks がこの book に記載されています**。\
_ただし、domain が client によって管理されていない IP 内で hosted されている場合があり、その場合は scope 外となるため注意してください。_

## Subdomains

> scope 内にあるすべての companies、各 company のすべての assets、および companies に関連するすべての domains がわかっています。

見つかった各 domain の、考えられるすべての subdomains を見つける段階です。

> [!TIP]
> domains を見つけるための一部の tools と techniques は、subdomains を見つける際にも役立つことに注意してください

### **DNS**

**DNS** records から **subdomains** を取得してみましょう。また、**Zone Transfer** も試すべきです（脆弱な場合は report してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量の subdomains を取得する最も速い方法は、外部ソースを検索することです。最もよく使用される **tools** は以下のとおりです（より良い結果を得るには API keys を設定してください）。

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
**サブドメインの発見に直接特化していなくても、サブドメインの発見に役立つ可能性がある、その他の興味深い tools/APIs** には次のようなものがあります。

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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault の Open Threat Exchange、Wayback Machine、Common Crawl から既知の URL を取得します。
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
- [**securitytrails.com**](https://securitytrails.com/) には、subdomains と IP history を検索できる無料の API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project は、**bug-bounty programs に関連するすべての subdomains** を無料で提供しています。この data には [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、またこの project が使用している scope [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) に直接アクセスすることもできます。

これらの tools の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain names を使って DNS servers に対して brute-force を実行し、新しい **subdomains** を見つけてみましょう。

この action には、以下のような**一般的な subdomains の wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

さらに、優れた DNS resolvers の IPs も必要です。信頼できる DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。または、こちらを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は以下のとおりです:

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
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper で、go で記述されています。active bruteforce を使用して有効な subdomains を列挙できるほか、wildcard handling と容易な input-output support により subdomains を resolve できます。
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
### DNS Brute-Force 第2ラウンド

open sources と brute-forcing を使用して subdomains を発見した後、発見した subdomains のバリエーションを生成し、さらに多くの subdomains の発見を試みることができます。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains と subdomains を指定すると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutationsを生成します。
- goaltdnsのpermutations **wordlist**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationsを生成します。permutations fileが指定されていない場合、gotatorは独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの解決も試行できます（ただし、前述のコメント付きツールを使用する方が適しています）。
- altdns の permutations **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。このツールは結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンから**新たな潜在的サブドメイン名を生成**し、より多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 詳細については、この[**post**](https://cramppet.github.io/regulator/index.html)を参照してください。基本的には、**発見されたサブドメイン**から**主要な部分**を取得して組み合わせ、さらに多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された input data を利用して、より多くの対応する domain names を正確に生成し、DNS scan 中に収集した情報に基づいてループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**を使って、コンピューター上で多数のツールを手動で起動する必要なく、ドメインから**subdomain discoveryを自動化する**方法について書いた、このブログ記事を確認してください:


{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

subdomainに属する**1つまたは複数のWebページ**を含むIPアドレスを見つけた場合、そのIP上にある**他のsubdomainを持つWebサイトを見つける**ために、IP上のドメインを**OSINT sources**で検索するか、そのIPで**VHostのドメイン名をbrute-force**してみることができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他のAPIを使って、IP上のVHostsを見つける**ことができます。

**Brute Force**

一部のsubdomainがWeb server内に隠されている可能性があると思われる場合は、brute forceを試してみることができます:

**IPがhostnameにredirectする場合**（name-based vhosts）、`Host` headerを直接fuzzし、ffufに**auto-calibrate**させて、デフォルトのvhostと異なるresponseを強調表示します:
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
> この technique を使うと、内部/hidden endpoints にアクセスできる場合もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定された場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような場合、この挙動を悪用して新しい **subdomains** を**発見**できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、いずれかの種類の **bucket** を **pointing** していないか確認し、該当する場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点では scope 内のすべての domain が判明しているため、[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) も試してください。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、ドメインの **new subdomains** が作成されたかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行います。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を pointing している場合は、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

**assets discovery** ですでに発見したものとは **different IP** を持つ **subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を **nmap/masscan/shodan** で実行してください。稼働している service に応じて、**this book some tricks to "attack" them** を見つけられる可能性があります。\
_場合によっては、subdomain が client によって管理されていない IP 上でホストされているため、scope 外となることがあります。注意してください。_

## IPs

初期段階で、いくつかの **IP ranges, domains and subdomains** が **found** されている可能性があります。\
これらの range からすべての IP を、また **domains/subdomains** については（DNS queries）すべての IP を **recollect** する時です。

以下の **free apis** の service を使用すると、**domains and subdomains** が過去に使用していた **previous IPs** も見つけられます。これらの IP は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけられる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool を使用して、特定の IP address を pointing している domain を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IP を port scan** してください（そこでは興味深いものを何も見つけられない可能性が高いため）。発見された稼働中の service に **vulnerabilities** が存在する可能性があります。

host の scan 方法については、[**guide**](../pentesting-network/index.html) を確認してください。

## Web servers hunting

> すべての company とその asset を発見し、scope 内の IP ranges、domains、subdomains を把握しました。次は web servers を探します。

前の手順ですでに、発見した IP と domain の **recon** を実行している可能性が高いため、**all the possible web servers** をすでに発見しているかもしれません。しかし、まだの場合は、scope 内の web servers を探すための **fast tricks** をいくつか紹介します。

これは **web apps discovery** 向けの手順であることに注意してください。そのため、scope で **allowed** であれば、**vulnerability** と **port scanning** も実行してください。

[**masscan** を使用して web servers に関連する **ports open** を発見する **fast method** はここにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すための、より扱いやすい別の tool として [**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) があります。domain の list を渡すだけで、port 80（http）と 443（https）への接続を試みます。さらに、他の port も試すよう指定できます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内（企業の **IP**、すべての **domain**、**subdomain**）に存在する**すべての web server**を発見した今、おそらく**どこから始めればよいかわからない**でしょう。そこで、簡単にするため、まずすべての対象の **screenshot** を取得することから始めましょう。**main page**を**見るだけ**で、より**脆弱**である**可能性が高い**、**奇妙な**endpointを発見できる場合があります。

このアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての **screenshot** を調べ、**脆弱性を含んでいる可能性が高いもの**と、そうでないものを判定することもできます。

## パブリック Cloud Assets

企業に属する可能性のある cloud assets を見つけるには、まず**その企業を識別できるキーワードのリスト**を作成します。たとえば、crypto company であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**bucketでよく使われる単語**の wordlist も必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って **permutation** を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlist には、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを使用できます。**

Cloud Assets を探す際は、**AWS の bucket だけに目を向けない**ようにしてください。

### **脆弱性の探索**

**open bucket や exposed cloud function** などを発見した場合は、**アクセスして**どのような情報や機能が得られるか、また abuse できるかを確認してください。

## Email

スコープ内の **domain** と **subdomain** があれば、基本的に**email の検索を始めるために必要なもの**はそろっています。以下は、企業の email を見つけるために私が最も効果的だと感じた **API** と**ツール**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - API と併用
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **脆弱性の探索**

Email は、後で **web login や auth service**（SSH など）を **brute-force** する際に役立ちます。また、**phishing** にも必要です。さらに、これらの API からは email の**背後にいる人物に関する追加情報**も得られるため、phishing campaign に役立ちます。

## Credential Leaks

**domain**、**subdomain**、**email** を使って、それらの email に関連する、過去に leak した credential を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の探索**

**有効な leaked credential** を発見できれば、非常に簡単な勝利です。

## Secrets Leaks

Credential leak は、企業が hack され、**sensitive information が leak して販売された**ケースに関連しています。しかし、企業は、それらの database に情報が存在しない**別の leak** の影響を受けている可能性もあります。

### Github Leaks

企業の **public repository**、またはその企業で働く **user** の **public repository** から、credential や API が leak している可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos) という **tool** を使えば、**organization** とその **developer** のすべての **public repo** を **download** し、[**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos** は、指定した **URL** に含まれるすべての **text** に対して **gitleaks** を実行する用途にも使えます。**web page にも secret が含まれている**場合があるためです。

#### Github Dorks

潜在的な **github dork** については、この**ページ**も確認してください。攻撃対象の organization に対して検索できる可能性があります。


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

攻撃者や単なる従業員が、**paste site に企業のコンテンツを公開**することがあります。そこに**sensitive information**が含まれている場合も、含まれていない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos) を使えば、80以上の paste site を同時に検索できます。

### Google Dorks

古いものの今でも有効な google dork は、**本来存在すべきでない exposed information** を見つけるのに役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) に数千もの検索 query が存在し、手動では実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などの tool を使ってすべて実行**できます。

_通常の Google browser を使って database 全体を実行しようとする tool は、Google にすぐブロックされるため、処理が終わらないことに注意してください。_

### **脆弱性の探索**

**有効な leaked credential または API token** を発見できれば、非常に簡単な勝利です。

## Public Code Vulnerabilities

企業が **open-source code** を公開していることがわかった場合、そのコードを**分析**して**脆弱性**を探すことができます。

**language によって**、使用できる**tool**は異なります。


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

以下のように、**public repository を scan** できる free service もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter が発見する**脆弱性の大半**は **web application** 内に存在するため、ここでは **web application testing methodology** について説明します。情報は[**こちら**](../../network-services-pentesting/pentesting-web/index.html)で確認できます。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) の section についても特に触れておきたいと思います。非常にsensitiveな脆弱性を発見してくれると期待すべきではありませんが、**workflow に組み込んで web の初期情報を得る**のに役立ちます。

## Recapitulation

> おめでとうございます！この時点で、すでに**基本的な enumeration をすべて実行**できています。もちろん、これは basic なものです。さらに多くの enumeration を実行できるためです（後ほど、より多くの trick を紹介します）。

すでに以下を実行しました。

1. スコープ内の**すべての企業**を発見した
2. 企業に属する**すべての asset**を発見した（スコープ内であれば vuln scan も実行した）
3. 企業に属する**すべての domain**を発見した
4. domain の**すべての subdomain**を発見した（subdomain takeover は可能か？）
5. スコープ内の**すべての IP**（**CDN 由来のものと、そうでないもの**）を発見した
6. **すべての web server**を発見し、その **screenshot** を取得した（詳細に調査する価値のある奇妙なものはないか？）
7. 企業に属する可能性のある**すべての public cloud asset**を発見した
8. **Email**、**credential leak**、**secret leak** を発見した。これらは**非常に簡単に大きな成果**につながる可能性がある
9. 発見した**すべての web を pentesting** した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案した作業の一部を実行してくれる tool がいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - やや古く、更新されていません

## **References**

- [**@Jhaddix**](https://twitter.com/Jhaddix) のすべての free course。たとえば [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
