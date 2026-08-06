# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets の発見

> ある会社に属するすべてのものが scope 内にあると伝えられ、実際にその会社が何を所有しているのかを把握したいとします。

このフェーズの目的は、**main company が所有するすべての companies**を特定し、続いてこれらの companies の**すべての assets**を特定することです。そのために、以下を行います。

1. main company による acquisitions を見つけます。これにより scope 内の companies がわかります。
2. 各 company の ASN（存在する場合）を見つけます。これにより、各 company が所有する IP ranges がわかります。
3. reverse whois lookups を使用して、最初のエントリに関連するその他のエントリ（organisation names、domains など）を検索します（これは再帰的に実行できます）。
4. shodan の `org` および `ssl` filters など、その他の techniques を使用して他の assets を検索します（`ssl` trick は再帰的に実行できます）。

### **Acquisitions**

まず、**main company が所有する他の companies**を把握する必要があります。\
[https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**main company**を**search**して、 "**acquisitions**" を**click**する方法があります。そこには、main company によって acquired された他の companies が表示されます。\
別の方法として、main company の **Wikipedia** ページにアクセスし、**acquisitions**を検索します。\
public companies については、**SEC/EDGAR filings**、**investor relations** pages、または現地の corporate registries（例：英国の **Companies House**）を確認します。\
global corporate trees と subsidiaries については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）および **GLEIF LEI** database（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> これで scope 内のすべての companies がわかったはずです。次に、それらの assets を見つける方法を確認しましょう。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部 networks へのアクセスに関する明確に定義された policy を持ち、単一の organisation によって管理される**IP addresses**の**blocks**で構成されますが、複数の operators で構成される場合もあります。

**company が ASN を割り当てられているか**を確認し、その**IP ranges**を特定することは有用です。**scope**内のすべての**hosts**に対して**vulnerability test**を実行し、これらの IP 内の**domains**を**探す**ことが有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company の**name**、**IP**、または**domain**で**search**できます。\
**company の region によっては、より多くの data を収集するために、以下の links が役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにせよ、おそらく** useful information **（IP ranges と Whois）は、最初の link にすでに表示されています。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration は、スキャンの最後に ASN を自動的に集約して要約します。
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
組織の IP レンジは、[http://asnlookup.com/](http://asnlookup.com)（無料 API があります）を使って見つけることもできます。\
ドメインの IP と ASN は、[http://ipv4info.com/](http://ipv4info.com) を使って見つけることができます。

### **脆弱性の探索**

この時点で、**scope 内のすべての asset**が分かっているため、許可されている場合は、すべての host に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりすることもできます。見つかった内容に応じて**、稼働している可能性のある複数の services の pentest 方法について、この book を確認してください。\
**また、いくつかの** default username **と** passwords **の lists を準備し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使って services を** bruteforce **することも検討する価値があります。**

## ドメイン

> scope 内にあるすべての company とその asset が分かったので、次は scope 内の domains を見つけます。

_以下で提案する techniques では subdomains も見つけられることがあるため、その情報を過小評価してはいけません。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges を見つけたら、それらの **IPs に対して reverse DNS lookups** を実行し、**scope 内の追加の domains を見つける**ことができます。victim の dns server、または well-known dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者が手動で PTR を有効にする必要があります。\
この情報には、オンラインツール [http://ptrarchive.com/](http://ptrarchive.com) も利用できます。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールが、reverse lookup と情報の補完を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** では、**organisation name**、**address**、**emails**、電話番号など、多くの興味深い **information** を見つけられます。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookups** を実行すると、**company** に関連する **more assets** を見つけられることです（例えば、同じ email が存在する別の whois registry）。\
次のようなオンラインツールを利用できます。

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

この作業は [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動化することもできます: `amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、より多くの domain names を発見するため、この technique を利用できることに注意してください。**

### **Trackers**

2 つの異なるページで、**same tracker** の **same ID** を見つけた場合、**both pages** は **same team** によって **managed** されていると推測できます。\
例えば、複数のページで同じ **Google Analytics ID** または同じ **Adsense ID** が表示される場合です。

これらの tracker などを使って検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (共有された analytics/trackers によって関連サイトを見つけます)

### **Favicon**

同じ favicon icon hash を探すことで、target に関連する domain や subdomain を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が正確に行うことです。使用方法は次のとおりです。
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じ favicon icon hash を持つドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言えば、favihash を使うと、対象と同じ favicon icon hash を持つドメインを発見できます。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) で説明されているように、favicon hash を使用して technologies を検索することもできます。つまり、**脆弱なバージョンの web tech の favicon の hash** がわかっていれば、Shodan で検索して **さらに多くの脆弱な場所を見つける** ことができます：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Web の **favicon hash**（**base64-encoded** された favicon bytes に対する MMH3）を**計算する方法**です。
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

favicon fingerprints を使用する際に覚えておくと便利な点:<sup>[[3]](#references)[[4]](#references)</sup>

- **ハッシュは証拠ではなく指標として扱う**: MMH3 はコンパクトで、collision が発生する可能性があります。また、operators は favicon を置き換えたり、意図的に誤解を招く icon を再利用したりできます。
- `/favicon.ico` 以外も probe する: 多くの products は、framework/build paths や `manifest.json`、`site.webmanifest`、`browserconfig.xml`、`apple-touch-icon*`、inline の `data:` URLs、HTML の `<link rel="icon">` tags 経由で icons を公開しています。path 自体が product family の fingerprint になる場合もあります。
- **app に到達できない場合でも static files には到達できることが多い**: WAF/SSO/IdP controls は dynamic routes を保護していても、static icons は公開されたままの場合があります。常に favicon を直接 request し、弱い version/build hints がないか `ETag`、`Last-Modified`、redirects、cache headers を確認してください。
- **周辺 signals で matches を検証する**: favicon が product を識別すると結論付ける前に、title、HTML/body hash、headers、TLS certificate subjects/SANs、Shodan/Censys components、exposed ports を比較してください。
- **大規模に pivot する際は HTML/body hash で cluster 化する**: 同じ favicon を共有するほとんどの hosts が1つの page template に集約される場合、fingerprint の信頼性は高くなります。同じ hash が多数の無関係な templates に分かれる場合は、product label よりも `"generic/shared/honeypot"` を優先してください。
- **Honeypot heuristic**: 同じ favicon hash が、無関係な多数の HTML signatures、random ports、相反する products にまたがって現れる場合、実際の product fingerprint ではなく、probable honeypot または generic placeholder として扱ってください。
- **曖昧な targets には 404 probe を使用する**: browser で実際の page と、`/_favicon_probe_<8-hex>` のような存在しない path を fetch します。hosting-provider/parking responses が一致する場合、実際の product overlap よりも shared favicons をうまく説明できることがあります。
- **detection rules から mappings を bootstrap する**: Nuclei templates と public favicon datasets は、CVE disclosures 後の rapid triage に役立つ既知の `favicon` ↔ `product` ↔ `CPE` mappings を提供できます。
- **Coverage caveat**: Shodan-style datasets は IP-centric です。CDN-fronted、SNI-routed、anycast、domain-only surfaces は過少計上される可能性があるため、hit count が少ないことは、実際の deployment が少ないことを**意味しません**。

### **Copyright / Uniq string**

web pages 内で、**同じ organisation の異なる webs 間で共有されている可能性がある strings**を検索します。**copyright string** は良い例です。その後、**Google**、他の **browsers**、または **Shodan** でその string を検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job として次のようなものを設定するのは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべてのドメイン証明書を更新するためです。つまり、これに使用される CA が Validity time に生成時刻を設定していない場合でも、**certificate transparency logs から同じ会社に属するドメインを見つけることが可能です**。\
詳しくは[**この writeup を確認してください**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)。

また、**certificate transparency** logs を直接使用することもできます。

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メール DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような web や、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のような tool を使用して、**同じ dmarc information を共有する domains and subdomain** を見つけることができます。\
その他の useful tools として、[**spoofcheck**](https://github.com/BishopFox/spoofcheck) や [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

どうやら、cloud providers に属する IP に subdomains を割り当て、ある時点で **その IP address を失ったにもかかわらず DNS record の削除を忘れる** ことはよくあるようです。そのため、cloud（Digital Ocean など）で **VM を spawn する**だけで、実際に **いくつかの subdomains を takeover する**ことになります。

[**この post**](https://kmsec.uk/blog/passive-takeover/) では、その事例を説明し、**DigitalOcean で VM を spawn**し、新しい machine の **IPv4** を **取得**して、そこを指している subdomain records を Virustotal で **検索する** script を提案しています。

### **Other ways**

**新しい domain を見つけるたびに、この technique を使用してさらに多くの domain names を発見できることに注意してください。**

**Shodan**

すでに IP space を所有する organisation の名前が分かっています。その data を使って、次のように shodan で検索できます：`org:"Tesla, Inc."` 見つかった hosts の TLS certificate を確認し、新しい予期しない domains がないか調べます。

メイン web page の **TLS certificate** にアクセスして **Organisation name** を取得し、shodan が把握しているすべての web pages の **TLS certificates** 内でその名前を filter `ssl:"Tesla Motors"` により検索することもできます。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のような tool を使用できます。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) は、メイン domain に **関連する domains** と、それらの **subdomains** を探す tool です。非常に便利です。

**Passive DNS / Historical DNS**

Passive DNS data は、現在も resolve する、または takeover 可能な **古く忘れられた records** を見つけるのに非常に役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

いくつかの [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) を確認してください。企業が **ある domain を使用している**ものの、**その ownership を失っている**可能性があります。安価であれば register し、企業に知らせてください。

すでに asset discovery で見つけたものとは **異なる IP を持つ domain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。実行されている services に応じて、**それらを「attack」するためのいくつかの tricks がこの book にあります**。\
_ときどき、domain は client が管理していない IP 内で hosted されているため、scope 外となる場合があります。注意してください。_

## Subdomains

> scope 内のすべての companies、各 company のすべての assets、および companies に関連するすべての domains が分かっています。

見つかった各 domain の、考えられるすべての subdomains を見つける段階です。

> [!TIP]
> domains を見つけるための一部の tools や techniques は、subdomains の発見にも役立つことに注意してください。

### **DNS**

**DNS** records から **subdomains** を取得してみましょう。また、**Zone Transfer** も試す必要があります（vulnerable な場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のsubdomainsを取得する最速の方法は、外部ソースを検索することです。最もよく使用される**ツール**は次のとおりです（より良い結果を得るにはAPI keysを設定してください）。

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
**その他の興味深い tools/APIs**には、subdomains の発見に直接特化していなくても、subdomains の発見に役立つものがあります。

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API
```bash
curl https://ip.thc.org/tesla.com
```
- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得
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
- [**securitytrails.com**](https://securitytrails.com/) には、subdomains と IP history を検索するための無料 API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project は、**bug-bounty programs に関連するすべての subdomains** を無料で提供しています。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、この project が使用している scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます

これらの tools の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain 名を使って DNS servers に対して brute-force を実行し、新しい **subdomains** を探してみましょう。

この操作には、次のような**一般的な subdomains の wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れた DNS resolvers の IP も必要です。信頼できる DNS resolvers の list を作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。または、次を使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという欠点があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは 1 つの resolver だけを使用すると思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper として go で記述されており、active bruteforce による有効なサブドメインの列挙に加え、ワイルドカード処理と簡単な入出力対応によるサブドメインの解決が可能です。
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
### 2回目の DNS Brute-Force

open sources と brute-forcing を使用してサブドメインを見つけた後、発見したサブドメインの alter​ations を生成し、さらに多くのサブドメインの発見を試みることができます。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを指定すると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutations を生成します。
- [**goaltdns**](https://github.com/subfinder/goaltdns) の permutations **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationsを生成します。permutationsファイルが指定されていない場合、gotatorは独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの resolve も試行できます（ただし、前述のコメントアウトされた tools を使用する方が適しています）。
- altdns の permutations **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): subdomain の permutations、mutations、alteration を実行する別の tool。この tool は結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** domain に基づき、指定されたパターンをもとに**新しい候補のサブドメイン名を生成**して、さらに多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 詳細についてはこの[**post**](https://cramppet.github.io/regulator/index.html)を読んでください。基本的には、**discovered subdomains**から**主要な部分**を取得し、それらを組み合わせてさらに多くのサブドメインを発見します。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルでありながら効果的な DNS response-guided algorithm と組み合わせた、subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された入力データセットを利用して、対応する可能性の高い domain names を正確に合成し、DNS scan 中に収集した情報に基づいて、ループ処理でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

**Trickest workflows**を使用して、コンピューター上で多数のツールを手動で起動する必要なく、ドメインから**subdomain discoveryを自動化**する方法について私が書いたブログ記事を確認してください。

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}

{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

**1つ以上のwebページ**がsubdomainに属しているIPアドレスを発見した場合、**OSINT sources**でIP内のドメインを検索するか、**そのIPでVHost domain namesをbrute-force**することで、**そのIP上にある他のsubdomainでwebが使われているものを探す**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **またはその他のAPIを使用して、IP内のVHostsを見つける**ことができます。

**Brute Force**

web server内に一部のsubdomainが隠されている可能性がある場合は、brute forceを試すことができます。

**IPがhostnameへリダイレクトする場合**（name-based vhosts）、`Host` headerを直接fuzzし、ffufに**auto-calibrate**させて、デフォルトのvhostと異なるresponseを強調表示します。<sup>[[2]](#references)</sup>
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

有効な domain/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような状況では、この挙動を悪用して新しい **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、何らかの **bucket** を **pointing** していないか確認し、その場合は [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点では scope 内のすべての domain が判明しているため、[**possible bucket names を brute force し、permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html) してみてください。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、domain の **new subdomains** が作成されたかどうかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行うものです。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を pointing している場合は、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

**asset discovery** で既に発見したものとは異なる IP を持つ **subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。稼働している service に応じて、**this book でそれらを「attack」するための tricks** を見つけられる可能性があります。\
_場合によっては、subdomain が client の管理下にない IP 内で host されているため scope 外となることがあります。注意してください。_

## IPs

初期段階で、いくつかの **IP ranges、domains、subdomains** を**発見している**可能性があります。\
それらの range からすべての IP を**収集**し、**domains/subdomains** については **DNS queries** を行う時です。

以下の **free apis** の service を使用すると、**domains と subdomains が以前使用していた IPs** も見つけられます。これらの IPs は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけられる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

tool [**hakip2host**](https://github.com/hakluke/hakip2host) を使用して、特定の IP address を pointing している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IPs を port scan** してください（おそらく、そこでは興味深いものを何も見つけられないためです）。発見された稼働中の services に、**vulnerabilities** が存在する可能性があります。

host を scan する方法については、[**guide**](../pentesting-network/index.html) **を参照してください。**

## Web servers hunting

> すべての companies とその assets を発見し、scope 内の IP ranges、domains、subdomains を把握しました。次は web servers を探します。

前の手順で、発見した IPs と domains の **recon** をすでに実行している可能性があるため、**考えられるすべての web servers** をすでに発見しているかもしれません。しかし、まだの場合は、scope 内の web servers を探すための**高速な tricks** をいくつか見ていきます。

これは **web apps discovery** を目的としていることに注意してください。そのため、scope で**許可されている**場合は、**vulnerability** および **port scanning** も実行する必要があります。

[**masscan** を使用して web servers に関連する **ports open** を発見する高速な method はここにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すための、より使いやすい別の tool は [**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、および [**httpx**](https://github.com/projectdiscovery/httpx) です。domains の list を渡すだけで、port 80（http）と 443（https）への接続を試行します。さらに、他の ports も試行するよう指定できます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内に存在する**すべての web servers**（企業の**IPs**、すべての**domains**および**subdomains**）を発見した今、おそらく**どこから始めればよいか分からない**でしょう。そこで、簡単にするため、まずすべての対象のスクリーンショットを撮ることから始めましょう。**main page**を**見るだけ**で、より**vulnerable**である**可能性が高い**、**奇妙な**endpointを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**screenshots**を確認し、**vulnerabilitiesが含まれていそうなもの**と、そうでないものを判別することもできます。

## Public Cloud Assets

企業に属する可能性のある cloud assetsを見つけるには、まず**その企業を特定する keywordsのリスト**から始めるべきです。たとえば、crypto companyを対象とする場合、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使用できます。

また、**bucketsでよく使われる単語**のwordlistsも必要になります。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

その後、それらの単語を使って**permutations**を生成します（詳細は[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を確認してください）。

生成したwordlistsを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのtoolsを使用できます。**

Cloud Assetsを探す際は、**AWSのbucketsだけを探すのでは不十分**だということを忘れないでください。

### **Looking for vulnerabilities**

**open bucketsやexposed cloud functions**などを見つけた場合は、**access**して、何が提供されているのか、またそれらをabuseできるかどうかを確認してみるべきです。

## Emails

スコープ内の**domains**と**subdomains**があれば、基本的に**emailsの検索を始めるために必要なもの**はすべて揃っています。以下は、企業のemailsを見つけるうえで私にとって最も効果的だった**APIs**と**tools**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs付き
- [**https://hunter.io/**](https://hunter.io/)のAPI（free version）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（free version）
- [**https://minelead.io/**](https://minelead.io/)のAPI（free version）

### **Looking for vulnerabilities**

Emailsは、後で**web loginsやauth services**（SSHなど）を**brute-force**する際に役立ちます。また、**phishings**にも必要です。さらに、これらのAPIsからはemailの背後にいる**人物に関するより多くの情報**も得られるため、phishing campaignに役立ちます。

## Credential Leaks

**domains、subdomains**、および**emails**を使って、それらのemailsに属する、過去にleakedされたcredentialsを探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**validなleaked credentials**を見つけられれば、非常に簡単な勝利です。

## Secrets Leaks

Credential leaksは、**sensitive informationがleakedされ、販売された**企業へのhackに関連しています。しかし、企業は、それらのdatabasesに情報が存在しない**別のleaks**の影響を受けている可能性もあります。

### Github Leaks

CredentialsやAPIsが、**company**の**public repositories**、またはそのgithub companyで働く**users**のpublic repositoriesにleakedされている可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**tool**を使えば、**organization**とその**developers**の**public repos**をすべて**download**し、その上で[**gitleaks**](https://github.com/zricethezav/gitleaks)を自動的に実行できます。

**Leakos**は、指定した**URLs**から提供されたすべての**text**に対して**gitleaks**を実行する用途にも使えます。場合によっては、**web pagesにもsecretsが含まれている**ためです。

#### Github Dorks

この**page**も確認してください。攻撃対象のorganizationに対して検索できる、潜在的な**github dorks**が記載されています。

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

攻撃者や単なる従業員が、**company contentをpaste siteにpublish**することがあります。そこに**sensitive information**が含まれている場合もあれば、含まれていない場合もありますが、検索してみる価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)というtoolを使えば、80以上のpaste sitesを同時に検索できます。

### Google Dorks

古いものの有用なgoogle dorksは、常に**そこにあるべきではないexposed information**を見つけるのに役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に数**千件**ものquery候補が含まれており、手動では実行できないことです。そのため、お気に入りの10件を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **のようなtoolを使ってすべて実行**できます。

_通常のGoogle browserを使ってdatabase全体を実行しようとするtoolsは、googleに非常に早くblockされるため、決して終了しないことに注意してください。_

### **Looking for vulnerabilities**

**validなleaked credentialsやAPI tokens**を見つけられれば、非常に簡単な勝利です。

## Public Code Vulnerabilities

companyが**open-source code**を持っていることが分かった場合は、それを**analyse**して**vulnerabilities**を探すことができます。

**languageに応じて**、利用できる**tools**は異なります。

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

以下のように、**public repositories**を**scan**できるfree servicesもあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug huntersが発見する**vulnerabilitiesの大半**は**web applications**内に存在します。そのため、ここでは**web application testing methodology**について説明したいと思います。情報は[**こちら**](../../network-services-pentesting/pentesting-web/index.html)で確認できます。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)セクションについても特に触れておきたいと思います。非常にsensitiveなvulnerabilitiesを発見してくれると期待すべきではありませんが、**workflowsに組み込んで初期段階のweb informationを得る**のに役立ちます。

## Recapitulation

> おめでとうございます。この時点で、**basic enumeration**をすでに**すべて実行**しました。もちろんbasicです。実行できるenumerationは、まだ数多くあります（後ほどさらにtricksを紹介します）。

すでに以下を実行しました。

1. スコープ内の**companies**をすべて発見した
2. companiesに属するすべての**assets**を発見した（スコープ内であればvuln scanも実行した）
3. companiesに属するすべての**domains**を発見した
4. domainsの**subdomains**をすべて発見した（subdomain takeoverは可能か？）
5. スコープ内のすべての**IPs**（**CDNs**由来および**CDNs**由来ではないもの）を発見した
6. すべての**web servers**を発見し、それらの**screenshot**を撮った（深く調査する価値のある奇妙なものはないか？）
7. companyに属する可能性のある**public cloud assets**をすべて発見した
8. **Emails**、**credentials leaks**、および**secret leaks**を発見した。これらは非常に簡単に**大きな成果**をもたらす可能性がある
9. 発見したすべてのwebを**Pentesting**した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案した作業の一部を実行してくれるtoolsがいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## References

- [1] [**@Jhaddix**](https://twitter.com/Jhaddix)のすべてのfree courses。たとえば[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Bishop Fox – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)

{{#include ../../banners/hacktricks-training.md}}
