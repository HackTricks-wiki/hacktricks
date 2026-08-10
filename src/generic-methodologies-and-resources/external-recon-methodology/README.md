# External Recon Methodology

## Assets discoveries

> ある企業に属するものはすべて scope 内だと聞かされ、その企業が実際に何を所有しているのかを把握したいとします。

このフェーズの目的は、**main company が所有するすべての企業**を特定し、次にそれらの企業の**assets**をすべて特定することです。そのために、以下を行います。

1. main company の acquisitions を特定し、scope 内の企業を把握する。
2. 各企業の ASN（存在する場合）を特定し、各企業が所有する IP ranges を把握する。
3. reverse whois lookups を使用して、最初の企業に関連する他のエントリ（organisation names、domains など）を検索する（これは再帰的に実行できます）。
4. shodan の `org`および`ssl`filters などの他の techniques を使用して、他の assets を検索する（`ssl` trick は再帰的に実行できます）。

### **Acquisitions**

まず、**main company が所有する他の企業**を把握する必要があります。\
[https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**main company を検索**して、 "**acquisitions**" を**クリック**する方法があります。そこには main company が買収した他の企業が表示されます。\
別の方法として、main company の **Wikipedia** ページにアクセスし、**acquisitions** を検索します。\
公開企業の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または地域の corporate registries（例：英国の **Companies House**）を確認します。\
グローバルな corporate trees と subsidiaries については、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) と **GLEIF LEI** database ([https://www.gleif.org/](https://www.gleif.org/)) を試してください。

> ここまでで、scope 内のすべての企業を把握できたはずです。次に、それらの assets を見つける方法を確認しましょう。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部 networks へのアクセスに関する明確に定義された policy を持ち、単一の organisation によって管理される**IP addresses**の**blocks**で構成されます。ただし、複数の operators で構成される場合があります。

**company に ASN が割り当てられているか**を確認し、その **IP ranges** を特定することは有用です。**scope**内のすべての**hosts**に対して**vulnerability test**を実行し、これらの IP 内にある**domains**を探すことも有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company **name**、**IP**、または**domain**で**search**できます。\
**company の region によっては、より多くの data を収集するために以下の links が役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにしても、おそらく** useful information **（IP ranges と Whois）は最初の link にすでに表示されています。**
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の** enumeration は scan の最後に ASN を自動的に集約して要約します。
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
組織の IP ranges は、[http://asnlookup.com/](http://asnlookup.com)（free API があります）を使って見つけることもできます。\
[http://ipv4info.com/](http://ipv4info.com) を使えば、domain の IP と ASN を見つけられます。

### **脆弱性の調査**

この時点で、**scope 内のすべての assets** が分かっているため、許可されている場合は、すべての hosts に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使って** open ports **を見つけたりすることもできます。見つかったものに応じて**、実行中のさまざまな services を pentest する方法について、この book を参照してください。\
**また、いくつかの** default username **と** passwords **の lists を用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使って services を** bruteforce **することも検討する価値があります。**

## Domains

> scope 内のすべての companies とその assets が分かったので、次は scope 内の domains を見つけます。

_以下で説明する techniques では subdomains も見つけられることがあり、その情報を過小評価すべきではない点に注意してください。_

まず、各 company の **main domain**(s) を探します。例えば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains の IP ranges をすべて見つけたら、それらの **IPs に対して reverse dns lookups** を実行し、**scope 内のより多くの domains を見つける**ことができます。victim の dns server または、よく知られた dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者が手動で PTR を有効にする必要があります。\
この情報には online tool も利用できます：[http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) などの tools が、reverse lookup と情報の enrich を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** の中には、**organisation name**、**address**、**emails**、電話番号など、多くの興味深い **information** が含まれています。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookups** を実行すると、**会社に関連するより多くの assets** を発見できることです（たとえば、同じ email が登場する別の whois registries）。\
次のような online tools を利用できます：

- [https://ip.thc.org/](https://ip.thc.org/) - **Free**（Web and API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **Free**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **Free**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **Free**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web は **Free**、API は有料。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（**100 free** searches のみ）
- [https://www.domainiq.com/](https://www.domainiq.com) - 有料
- [https://securitytrails.com/](https://securitytrails.com/) - 有料（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 有料（API）

[**DomLink** ](https://github.com/vysecurity/DomLink) を使用して、この task を自動化できます（whoxy API key が必要です）。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動化することもできます：`amass intel -d tesla.com -whois`

**新しい domain を発見するたびに、この technique を使ってより多くの domain names を発見できることに注意してください。**

### **Trackers**

2 つの異なる pages で**同じ tracker の同じ ID** を見つけた場合、**両方の pages** が**同じ team によって管理されている**と推測できます。\
たとえば、複数の pages で同じ **Google Analytics ID** または同じ **Adsense ID** が表示される場合です。

これらの trackers やその他の情報から検索できる pages と tools があります：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有された analytics/trackers に基づいて関連 sites を見つける）

### **Favicon**

同じ favicon icon hash を検索することで、target に関連する domains と subdomains を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が正確に行うことです。使用方法は次のとおりです：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
簡単に言えば、favihash を使うと、対象と同じ favicon アイコン hash を持つドメインを発見できます。

既知の favicon hash を Shodan または FOFA の pivot として使用し、同じ technology の他の公開インスタンスを見つけます。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Webサイトの **favicon hash** を **計算する** 方法です（faviconのバイト列を **base64-encoded** したものに対する **MMH3**）：
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
[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使えば、favicon hashを大規模に取得し、Shodan/Censysでpivotすることもできます。

favicon fingerprintは手がかりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hashは証拠ではなくindicatorとして扱う**: MMH3はコンパクトであり、collision、再利用されたicon、意図的なspoofingが発生する可能性があります。
- **`/favicon.ico`以外もprobeする**: framework/build path、manifest file、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTMLの`<link rel="icon">` tagを調べます。
- **WAF/SSO/IdP controlの背後でもstatic assetにアクセスできる場合がある**: iconを直接requestし、`ETag`、`Last-Modified`、redirect、cache headerを確認します。
- **matchを周辺のシグナルで検証する**: title、HTML/body hash、header、TLS certificateのsubject/SAN、product component、exposed portを比較します。
- **HTML/body hashでcluster化する**: 一貫したtemplateはfingerprintの信頼性を高めます。templateが混在している場合は、genericまたはshared iconである可能性があります。
- **無関係なsignature、port、product全体でhashが出現する場合は、potential honeypotまたはplaceholderとして扱う。**
- **曖昧なtargetでは、実在するpageと、`/_favicon_probe_<8-hex>`のような存在しないpathを比較する**: hostingまたはparking responseが一致すれば、共有されたiconの理由を説明できる場合があります。
- **favicon hashをproductおよびCPEに紐付けるNuclei detection ruleまたはpublic datasetからtriageを開始する。**
- **IP-centricなcoverage gapを忘れない**: CDN-fronted、SNI-routed、anycast、domain-onlyのsurfaceは、Shodan系のdatasetに含まれていない可能性があります。

### **Copyright / Uniq string**

web page内で、**同じ組織の異なるwebサイト間で共有されている可能性のあるstring**を検索します。**copyright string**は良い例です。その後、そのstringを**Google**、他の**browser**、さらには**Shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

次のようなcron jobが存在するのは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプや certificate-transparency ログの位置を相関させることで、関連するドメインを明らかにできます。<sup>[[6]](#references)</sup>

また、**certificate transparency** ログを直接使用します：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メール DMARC 情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のような Web サイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のようなツールを使用して、**同じ dmarc 情報を共有しているドメインとサブドメイン**を見つけることができます。\
その他の便利なツールには、[**spoofcheck**](https://github.com/BishopFox/spoofcheck) と [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

放棄された A レコードは、cloud provider が IP を再割り当てしたときに到達可能になる場合があります。参照されている調査では、インスタンスをプロビジョニングし、そのアドレスを passive DNS データと相関させる機会的なワークフローが示されています。takeover のシナリオは、認可されたスコープ内でのみテストしてください。<sup>[[7]](#references)</sup>

### **その他の方法**

**Shodan**

すでに IP space を所有する組織の名前がわかっているため、Shodan で次のようにそのデータを検索できます：`org:"Tesla, Inc."` 見つかったホストの TLS 証明書を確認し、新しく予期しないドメインがないか調べます。

メイン Web ページの **TLS certificate** にアクセスし、**Organisation name** を取得した後、**Shodan** が把握しているすべての Web ページの **TLS certificates** 内でその名前を、次のフィルターを使って検索できます：`ssl:"Tesla Motors"` または [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のようなツールを使用します。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールで、とても便利です。

**Passive DNS / Historical DNS**

Passive DNS データは、現在も解決される、または takeover 可能な**古く忘れられたレコード**を見つけるのに役立ちます。以下を確認してください：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) を確認してください。ある企業が**ドメインを使用している**ものの、**所有権を失っている**可能性があります。そのドメインを（十分に安ければ）登録し、企業に知らせてください。

資産の discovery ですでに見つけたものとは**異なる IP を持つドメイン**を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**port scan**（[こちら](../pentesting-network/index.html#discovering-hosts-from-the-outside)を参照）を **nmap/masscan/shodan** で実行してください。実行されているサービスによっては、**この本でそれらを「attack」するためのトリックを見つけられます**。\
_ドメインが client によって管理されていない IP 内でホストされている場合があり、その場合はスコープ外なので注意してください。_

## サブドメイン

> スコープ内にあるすべての企業、各企業のすべての asset、および企業に関連するすべてのドメインがわかっています。

見つかった各ドメインについて、考えられるすべてのサブドメインを見つける段階です。

> [!TIP]
> ドメインを見つけるための一部のツールや手法は、サブドメインを見つける際にも役立つことに注意してください

### **DNS**

**DNS** レコードから**サブドメイン**を取得してみましょう。また、**Zone Transfer** も試す必要があります（脆弱な場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のサブドメインを取得する最速の方法は、外部ソースを検索することです。最もよく使用される**tools**は次のとおりです（より良い結果を得るにはAPI keysを設定してください）。

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
**subdomain の検索に直接特化していなくても、subdomain の発見に役立つ可能性がある、その他の興味深い tools/APIs** があります。

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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawlから既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): WebをscrapeしてJSファイルを探し、そこからsubdomainsを抽出します。
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
- [**Censys サブドメインファインダー**](https://github.com/christophetd/censys-subdomain-finder)
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

この project では、**bug-bounty programs に関連するすべての subdomains** を無料で提供しています。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、また、この project が使用している scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます。

これらのツールの多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

考えられる subdomain names を使って DNS servers に brute-force を行い、新しい **subdomains** を探してみましょう。

この作業には、以下のような**一般的な subdomains の wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

さらに、信頼できる DNS resolvers の IPs も必要です。信頼できる DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。または、こちらを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は以下のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという問題があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverしか使わないと思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は go で記述された `massdns` の wrapper で、active bruteforce を使用して有効なサブドメインを列挙できるほか、wildcard handling に対応したサブドメインの解決と、容易な input-output を実現します。
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

open sources と brute-forcing を使用して subdomains を発見した後、発見した subdomains の alterations を生成して、さらに多くの subdomains を見つけられる可能性があります。この目的には、いくつかの tools が役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domains と subdomains を指定すると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定して、permutations を生成します。
- [**ここ**](https://github.com/subfinder/goaltdns/blob/master/words.txt) から goaltdns の permutations **wordlist** を入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutations を生成します。permutations file が指定されていない場合、gotator は独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの resolve も試行できます（ただし、前述のコメントアウトされた tools を使用する方がよいでしょう）。
- altdns の permutations **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。このツールは結果を brute force します（dns wildcard には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンに基づいて**新たな候補となるサブドメイン名を生成**し、さらなるサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現に似たパターンを学習し、解決を試みる候補名を生成します。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された入力データセットを利用して、対応するドメイン名を正確に合成し、DNS scan 中に収集した情報に基づいてループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン検出ワークフロー**

Trickest workflowの例では、再現可能なサブドメイン列挙のために、OSINT、DNS brute force、permutationの各ステージを組み合わせています。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

**1つまたは複数のサブドメインに属するweb pages**を含むIPアドレスを発見した場合、**OSINT sources**でIP内のドメインを調べるか、**そのIPでVHostのドメイン名をbrute-force**することで、**そのIP上にある他のサブドメインにwebsが存在するかを探す**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他のAPIを使用して、IP内のVHostsを発見**できます。

**Brute Force**

一部のサブドメインがweb server内に隠されていると推測される場合は、brute forceを試すことができます。

name-based vhostsの場合は、`Host` headerをfuzzし、ffufのauto-calibrationを使用してdefault responseをフィルタリングします。<sup>[[2]](#references)</sup>
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

有効な domain/subdomain が _**Origin**_ header に設定された場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような状況では、この挙動を悪用して新しい **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探している間は、何らかの **bucket** を **pointing** していないか注意し、その場合は [**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)**してください。**\
また、この時点では scope 内のすべての domain が分かっているため、[**考えられる bucket 名を brute force し、permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、domain の **new subdomains** が作成されたかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行うものです。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を pointing している場合は、[**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

**assets discovery** ですでに発見したものとは**異なる IP を持つ subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。稼働している service に応じて、**この book でそれらを「attack」するための tricks** が見つかる可能性があります。\
_場合によっては、subdomain が client によって管理されていない IP 内で host されているため、scope 外となることがあります。注意してください。_

## IPs

初期段階で、**いくつかの IP ranges、domains、subdomains を発見している**可能性があります。\
ここで、それらの range から**すべての IP を収集**し、**domains/subdomains に対して DNS queries** を行う時です。

以下の **free apis** の service を使用すると、**domains と subdomains が過去に使用していた IPs** も発見できます。これらの IPs は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) の発見につながる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool を使用して、特定の IP address を pointing している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IPs を port scan** してください（そこでは興味深いものを発見できない可能性が非常に高いためです）。発見した稼働中の services から、**vulnerabilities を発見**できる可能性があります。

**hosts の scan 方法に関する** [**guide**](../pentesting-network/index.html) **を確認してください。**

## Web servers hunting

> すべての companies とその assets を発見し、scope 内の IP ranges、domains、subdomains を把握しました。ここで web servers を探します。

前の手順で、すでに発見した IPs と domains の **recon** を実行している可能性が高いため、**考えられるすべての web servers をすでに発見している**かもしれません。ただし、まだの場合は、scope 内の web servers を探すための**高速な tricks**をいくつか見ていきます。

これは **web apps discovery** 向けであることに注意してください。そのため、scope で**許可されている場合**は、**vulnerability** と **port scanning** も実行してください。

[**masscan** を使用して web servers に関連する **ports open** を発見する高速な方法は、こちらにあります](../pentesting-network/index.html#http-port-discovery)。\
web servers を探すための、より使いやすい別の tool は [**httprobe**](https://github.com/tomnomnom/httprobe)**、** [**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) です。domains の list を渡すだけで、port 80（http）と 443（https）への接続を試行します。さらに、他の ports も試行するよう指定できます:
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内（会社の **IP**、すべての **domain** と **subdomain**）に存在する **すべての web server** を発見したとしても、どこから始めればよいかはおそらく **わからない** でしょう。そこで、シンプルにするため、まずすべての対象のスクリーンショットを撮りましょう。**main page** を**見るだけ**で、より**脆弱性が存在する可能性が高い** **weird** な endpoint を見つけられることがあります。

このアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)** を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての **screenshots** を解析し、**脆弱性が含まれていそうなもの**と、そうでないものを判断することもできます。

## Public Cloud Assets

企業に属する可能性のある cloud assets を見つけるには、まずその企業を識別できるキーワードのリストを作成します。たとえば、crypto 企業なら、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**bucket** でよく使われる単語の wordlist も必要になります。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語を使って **permutations** を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlist には、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** を使用できます。**

Cloud Assets を探す際は、**AWS の bucket だけでなく、それ以上のもの**を探すべきであることを覚えておいてください。

### **Looking for vulnerabilities**

**open bucket や exposed cloud function** などを見つけた場合は、**access** して、それらが何を提供しているのか、また abuse できるかどうかを確認してください。

## Emails

スコープ内の **domain** と **subdomain** があれば、**email の検索を始める**ために必要なものは基本的にそろっています。以下は、私が企業の email を見つける際に最も効果的だった **API** と **tool** です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - API 付き
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **Looking for vulnerabilities**

Email は後で **web login や auth service**（SSH など）を **brute-force** する際に役立ちます。また、**phishings** にも必要です。さらに、これらの API は email の背後にいる **人物についてのより多くの情報**も提供するため、phishing campaign に役立ちます。

## Credential Leaks

**domain、subdomain、**および **email** を使って、それらの email に関連する、過去に **leak** した credential を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**有効な leaked credential** を見つけられれば、非常に簡単な勝利です。

## Secrets Leaks

Credential leaks は、企業が hack され、**sensitive information が leak して販売された**ケースに関連しています。しかし、企業は、それらの database に情報が存在しない**別の leak** の影響を受けている可能性もあります。

### Github Leaks

Credential や API が、**企業**の **public repository**、またはその企業で働く **user** の public repository に **leak** している可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos) **tool** を使うと、**organization** とその **developer** のすべての **public repo** を **download** し、[**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos** は、指定した **URL** から提供されたすべての **text** に対して **gitleaks** を実行する用途にも使えます。**web page にも secrets が含まれることがある**ためです。

#### Github Dorks

organization 内を検索するための潜在的な **GitHub dorks** については、[GitHub dorks and leaks page](github-leaked-secrets.md) を確認してください。

### Pastes Leaks

攻撃者や単なる従業員が、**paste site に企業のコンテンツを publish** することがあります。そこに **sensitive information** が含まれている場合もあれば、含まれていない場合もありますが、検索する価値は非常に高いです。\
[**Pastos**](https://github.com/carlospolop/Pastos) tool を使うと、80以上の paste site を同時に検索できます。

### Google Dorks

古くても有用な Google dorks は、**本来存在すべきでない exposed information** を見つける際に常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) に数千もの検索 query が含まれており、手動では実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **のような tool を使ってすべて実行**できます。

_通常の Google browser を使って database 全体を実行しようとする tool は、Google に非常に早く block されるため、決して終了しないことに注意してください。_

### **Looking for vulnerabilities**

**有効な leaked credential または API token** を見つけられれば、非常に簡単な勝利です。

## Public Code Vulnerabilities

企業が **open-source code** を保有していることがわかった場合は、それを **analyse** して **vulnerability** を探すことができます。

**language に応じて**使用できる **tool** は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md) の一覧を確認してください。

**public repository** を **scan** できる free service もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter が発見する **vulnerability の大半**は **web application** 内に存在するため、ここでは **web application testing methodology** について説明したいと思います。この情報は[**こちら**](../../network-services-pentesting/pentesting-web/index.html)で確認できます。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) セクションについても特に触れておきたいと思います。非常に重要な vulnerability の発見を期待すべきではありませんが、**初期の web 情報を得るための workflow に組み込む**際に役立ちます。

## Recapitulation

> おめでとうございます！この時点で、**basic enumeration のすべて**をすでに実行しました。多くの追加 enumeration が可能であるため basic なのです（後でさらに tricks を紹介します）。

すでに以下を実行しました。

1. スコープ内のすべての **company** を発見した
2. 企業に属するすべての **asset** を発見した（スコープ内であれば vuln scan も実行した）
3. 企業に属するすべての **domain** を発見した
4. domain のすべての **subdomain** を発見した（subdomain takeover はないか？）
5. スコープ内のすべての **IP**（**CDN 由来のもの**と**そうでないもの**）を発見した
6. すべての **web server** を発見し、スクリーンショットを撮った（詳しく調べる価値のある weird なものはないか？）
7. 企業に属する可能性のあるすべての **public cloud asset** を発見した
8. 非常に簡単に **big win** につながる可能性のある **email、credential leaks、secret leaks**
9. 発見したすべての web を **Pentesting** した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案した処理の一部を実行してくれる tool は複数存在します。

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
{{#include ../../banners/hacktricks-training.md}}
