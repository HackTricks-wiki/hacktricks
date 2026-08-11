# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets の発見

> ある会社に属するすべてのものが scope 内にあると伝えられ、その会社が実際に何を所有しているのかを把握したいとします。

このフェーズの目標は、**主要会社が所有するすべての会社**を特定し、次にそれらの会社の**すべての asset**を特定することです。そのために、以下を行います。

1. 主要会社による買収を特定し、scope 内の会社を把握する。
2. 各会社の ASN（存在する場合）を特定し、各会社が所有する IP range を把握する。
3. reverse whois lookup を使用して、最初の会社に関連するその他のエントリ（組織名、domain など）を検索する（これは再帰的に実行可能）。
4. Shodan の `org`および`ssl` filter など、その他の technique を使用して別の asset を検索する（`ssl` trick は再帰的に実行可能）。

### **Acquisitions**

まず、**主要会社が所有する他の会社**を把握する必要があります。\
方法の1つは [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**主要会社を検索**して、**「acquisitions」**を**クリック**することです。そこには、主要会社が買収した他の会社が表示されます。\
別の方法は、主要会社の **Wikipedia** ページにアクセスし、**acquisitions**を検索することです。\
上場企業については、**SEC/EDGAR filings**、**investor relations** ページ、または各国の企業登記（例：英国の **Companies House**）を確認します。\
グローバルな企業構造や子会社については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）および **GLEIF LEI** database（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> これで、scope 内のすべての会社が把握できたはずです。次に、それらの asset を見つける方法を確認しましょう。

### **ASNs**

自律システム番号（**ASN**）は、**Internet Assigned Numbers Authority (IANA)** によって**自律システム**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部 network へのアクセスに関して明確に定義された policy を持つ**IP address の block**で構成され、単一の組織によって管理されますが、複数の operator で構成される場合があります。

**company に ASN が割り当てられているか**を確認し、その**IP range**を特定することは有益です。scope 内のすべての**host**に対して**vulnerability test**を実施し、これらの IP 内にある**domain**を探すことも有効です。\
[**https://bgp.he.net/**](https://bgp.he.net)**,** [**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company **name**、**IP**、または **domain**で**検索**できます。\
**company の region によっては、より多くの data を収集するために以下の link が役立ちます：** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。いずれにしても、おそらく**有用な情報**（IP range と Whois）のすべては、最初の link にすでに表示されます。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の** enumeration は、scan の終了時に ASNs を自動的に集約して要約します。
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
[http://ipv4info.com/](http://ipv4info.com) を使えば、ドメインの IP と ASN を見つけられます。

### **脆弱性の検索**

この時点で、**scope 内にあるすべての asset** が判明しているため、許可されている場合は、すべての host に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりすることもできます。そして、**発見した内容に応じて**、稼働している可能性のある複数の services を pentest する方法について、この book を確認してください。\
**また、いくつかの** default username **と** passwords **の lists を準備し、** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **を使って services を** bruteforce **してみることも、検討する価値があります。**

## ドメイン

> scope 内のすべての companies とその assets が判明したので、次は scope 内の domains を見つけます。

_以下で説明する techniques では subdomains も見つかる可能性があるため、その情報を過小評価してはいけません。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges を見つけたら、それらの **IPs に対して reverse dns lookups** を実行し、**scope 内にある追加の domains を見つける**ことができます。victim の dns server、または well-known dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、administrator が手動で PTR を有効にする必要があります。\
この情報には online tool も使用できます: [http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のような tools が、reverse lookup と情報の補完を自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois** 内では、**organisation name**、**address**、**emails**、phone numbers など、多くの興味深い **information** を見つけられます。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って **reverse whois lookup** を実行すると、**company に関連するさらに多くの assets** を見つけられることです（例: 同じ email が登場する別の whois registries）。\
次のような online tools を使用できます:

- [https://ip.thc.org/](https://ip.thc.org/) - **無料** (Web and API)
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Web は **無料**、API は無料ではありません。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません (**100 回のみ無料**)
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 無料ではありません (API)
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 無料ではありません (API)

この task は [**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って自動化できます。\
[amass](https://github.com/OWASP/Amass) を使って、reverse whois discovery の一部を自動的に実行することもできます: `amass intel -d tesla.com -whois`

**新しい domain を見つけるたびに、この technique を使ってさらに多くの domain names を発見できることに注意してください。**

### **Trackers**

2 つの異なる pages で**同じ tracker の同じ ID**を見つけた場合、**両方の pages** が**同じ team によって管理されている**と推測できます。\
例えば、複数の pages で同じ **Google Analytics ID** や同じ **Adsense ID** が表示される場合です。

これらの trackers などを使って検索できる pages や tools があります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (共有された analytics/trackers に基づいて関連 sites を発見)

### **Favicon**

同じ favicon icon hash を検索することで、target に関連する domains や subdomains を見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が実行することそのものです。使用方法は次のとおりです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
簡単に言えば、favihash を使うと、ターゲットと同じ favicon アイコン hash を持つドメインを発見できます。

既知の favicon hash を Shodan または FOFA の pivot として使用し、同じ technology の他の exposed instances を見つけます。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
これは、Web の **favicon hash**（**base64-encoded** された favicon bytes に対する **MMH3**）を**計算する方法**です：
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
大規模に favicon hash を取得するには [**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）も使用でき、その後 Shodan/Censys で pivot できます。

favicon fingerprint は手掛かりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトであり、collision、再利用された icon、意図的な spoofing の可能性があります。
- **`/favicon.ico` 以外も probe する**: framework/build path、manifest file、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTML の `<link rel="icon">` tag を調査します。
- **Static asset は WAF/SSO/IdP control の背後でも到達可能な場合がある**: icon を直接 request し、`ETag`、`Last-Modified`、redirect、cache header を確認します。
- **match を周辺のシグナルで検証する**: title、HTML/body hash、header、TLS certificate の subject/SAN、product component、exposed port を比較します。
- **HTML/body hash で cluster 化する**: 一貫した template は fingerprint の信頼性を高めます。template が混在している場合は、generic または共有された icon である可能性があります。
- **無関係な signature、port、product に同じ hash が現れる場合は、honeypot または placeholder の可能性を考慮する。**
- **曖昧な target では、実在する page と存在しない path**（`/_favicon_probe_<8-hex>` など）を比較します。同一の hosting または parking response が、共有された icon の理由を説明できる場合があります。
- **favicon hash を product と CPE に対応付ける Nuclei detection rule または public dataset** から triage を開始します。
- **IP-centric な coverage gap に注意する**: CDN-fronted、SNI-routed、anycast、domain-only の surface は、Shodan に類似した dataset から欠落している可能性があります。

### **Copyright / Uniq string**

web page 内で、**同じ organisation に属する異なる web site 間で共有されている可能性のある string** を検索します。**copyright string** は良い例です。その後、その string を **Google**、他の **browser**、あるいは **Shodan** でも検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job として次のようなものを設定するのは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew all certificates on a server at the same time. 証明書のタイムスタンプまたはcertificate-transparency logの位置を相関させることで、関連するドメインを明らかにできます。<sup>[[6]](#references)</sup>

また、**certificate transparency** logsを直接使用します：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のようなtoolを使用して、**同じdmarc informationを共有するdomains and subdomain**を見つけることができます。\
その他の便利なtoolsとして、[**spoofcheck**](https://github.com/BishopFox/spoofcheck) や [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

放棄されたA recordは、cloud providerがIPを再割り当てした際に到達可能になることがあります。参照されているresearchは、instanceをprovisionし、そのaddressをpassive DNS dataと相関させるopportunistic workflowを示しています。takeover scenariosのtestは、認可されたscope内でのみ実施してください。<sup>[[7]](#references)</sup>

### **その他の方法**

**Shodan**

すでにIP spaceを所有するorganisationの名前が分かっています。そのdataを使用して、次のようにshodanで検索できます：`org:"Tesla, Inc."` 見つかったhostsについて、TLS certificateに新しい予期しないdomainsがないか確認します。

メインのWeb pageの**TLS certificate**にaccessし、**Organisation name**を取得した後、**shodan**が把握しているすべてのWeb pagesの**TLS certificates**内でその名前を検索できます。filterは `ssl:"Tesla Motors"` です。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のようなtoolを使用します。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、main domainに**relatedなdomains**と、それらの**subdomains**を探すtoolです。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNS dataは、現在もresolveされる、またはtakeover可能な**old and forgotten records**を見つけるのに有効です。以下を確認してください：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

いくつかの[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)を確認してください。あるcompanyが**some a domainを使用している**ものの、**ownershipを失っている**可能性があります。十分に安ければ登録し、companyに知らせてください。

すでにasset discoveryで見つけたものとは**異なるIPを持つdomain**を見つけた場合は、**basic vulnerability scan**（NessusまたはOpenVASを使用）と、**port scan**（[こちら](../pentesting-network/index.html#discovering-hosts-from-the-outside)）を **nmap/masscan/shodan**で実行してください。稼働しているservicesによっては、**このbook内でそれらを「attack」するためのtricks**を見つけられます。\
_そのdomainがclientの管理下にないIP内でhostされている場合があるため、scope外となることに注意してください。慎重に対応してください。_

## Subdomains

> scope内のすべてのcompanies、各companyのすべてのassets、およびcompaniesに関連するすべてのdomainsを把握しています。

見つかった各domainについて、考えられるすべてのsubdomainsを見つける段階です。

> [!TIP]
> domainを見つけるための一部のtoolsやtechniquesは、subdomainsの発見にも役立つことに注意してください

### **DNS**

**DNS** recordsから**subdomains**を取得してみましょう。また、**Zone Transfer**も試す必要があります（vulnerableな場合は、報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多数のサブドメインを取得する最も迅速な方法は、外部ソースを検索することです。より良い結果を得るには API keys を設定してください。最もよく使用される **ツール** は次のとおりです。

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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault の Open Threat Exchange、Wayback Machine、Common Crawl から既知の URL を取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper)：Webを巡回してJSファイルを探し、そこからsubdomainを抽出します。
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

この project では、**bug-bounty programs に関連するすべての subdomains** を**無料で**提供しています。この data には [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることもできます。また、この project が使用している scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます。

これらの tools の多くの**比較**は、こちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のある subdomain names を使って DNS servers に対して brute-forcing を行い、新しい **subdomains** を探してみましょう。

この作業には、以下のような**一般的な subdomains wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れた DNS resolvers の IPs も必要です。信頼できる DNS resolvers の list を作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers を download し、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使って filter できます。あるいは、こちらを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は以下のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという欠点があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverしか使わないと思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper で、go で記述されており、active bruteforce を使用した有効なサブドメインの列挙、wildcard handling に対応したサブドメインの解決、簡単な input-output サポートを利用できます。
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
### 2回目のDNS Brute-Forceラウンド

open sourcesとbrute-forcingを使用してsubdomainsを発見した後、発見したsubdomainsのalterationsを生成して、さらに多くのものを見つけられる可能性があります。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** domainsとsubdomainsを指定すると、permutationsを生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutations を生成します。
- goaltdns の permutations **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationsを生成します。permutationsファイルが指定されていない場合、gotatorは独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutations を生成できるほか、それらの解決も試行できます（ただし、前述のコメントアウトされた tools を使用する方が適しています）。
- [**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt) から altdns の permutations **wordlist** を取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。このツールは結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンから**新たな候補サブドメイン名を生成**して、さらに多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見されたサブドメインから正規表現に似たパターンを学習し、解決可能な候補名を生成します。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルでありながら効果的な DNS response-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された input data を利用して、より対応する domain names を正確に生成し、DNS scan 中に収集した情報に基づいて、ループ処理でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow の例では、再現可能な subdomain enumeration のために OSINT、DNS brute force、permutation の各 stage を組み合わせています。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

subdomains に属する **1 つまたは複数の web ページ** を含む IP address を見つけた場合、**OSINT sources** で IP 内の domains を検索するか、**その IP に対して VHost domain names を brute-force** することで、**その IP 上の他の subdomains に web が存在するかを見つける**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他の APIs を使用して、IP 内の VHosts を見つける**ことができます。

**Brute Force**

ある subdomain が web server に隠されていると考えられる場合は、次のように brute force を試すことができます。

name-based vhosts の場合は、`Host` header を fuzz し、ffuf の auto-calibration を使用して default response を除外します。<sup>[[2]](#references)</sup>
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
> この手法を使うと、internal/hidden endpoints にアクセスできる場合もあります。

### **CORS Brute Force**

有効なドメイン/サブドメインが _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような場合、この挙動を悪用して、**新しい** **サブドメイン**を**発見**できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、何らかの **bucket** を **pointing** していないか確認し、その場合は[**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)**してください。**\
また、この時点では scope 内のすべての domain を把握しているため、[**考えられる bucket 名を brute force し、permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してみてください。

### **Monitorization**

**Certificate Transparency** Logs を監視することで、domain に**新しい subdomains**が作成されたかを **monitor** できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行います。

### **Looking for vulnerabilities**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を pointing している場合は、[**permissions を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

assets discovery ですでに見つけたものとは**異なる IP を持つ subdomain**を発見した場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)（**nmap/masscan/shodan** を使用）を実行してください。実行されている service に応じて、**この book でそれらを「attack」するための tricks**を見つけられる可能性があります。\
_場合によっては、subdomain が client の管理下にない IP 内で hosted されているため scope 外となることがあります。注意してください。_

## IPs

初期ステップで、**IP ranges、domains、subdomains**をいくつか**発見している**可能性があります。\
ここで、それらの range に含まれるすべての **IP** と、**domains/subdomains（DNS queries）**の IP を**recollect**します。

以下の**free APIs**の service を使用すると、**domains と subdomains が過去に使用していた IP**も見つけられます。これらの IP は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) の発見につながる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

[**hakip2host**](https://github.com/hakluke/hakip2host) tool を使用して、特定の IP address を pointing している domains を確認することもできます。

### **Looking for vulnerabilities**

**CDNs に属さないすべての IP を port scan**してください（そこでは興味深いものを発見できる可能性が非常に低いためです）。検出された running services に**vulnerabilities**が存在する可能性があります。

host の scan 方法については[**guide**](../pentesting-network/index.html)を**確認してください。**

## Web servers hunting

> scope 内のすべての companies とその assets を発見し、IP ranges、domains、subdomains を把握しました。次は web servers を探します。

前のステップで、発見した IP と domains の**recon**をすでに実行している可能性が高いため、**考えられるすべての web servers**をすでに発見しているかもしれません。ただし、まだの場合は、scope 内の web servers を探すための**いくつかの高速な tricks**をこれから確認します。

これは**web apps discovery**向けの内容である点に注意してください。そのため、scope で**許可されている場合**は、**vulnerability**および**port scanning**も実行してください。

[**masscan** を使用して web servers に関連する**open ports**を発見する**高速な方法はこちら**](../pentesting-network/index.html#http-port-discovery)にあります。\
web servers を探すための、より使いやすい別の tool は [**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) です。domains の list を渡すだけで、port 80（http）と 443（https）への接続を試行します。さらに、他の ports も試行するよう指定できます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべての web サーバー**（会社の**IP**、すべての**ドメイン**および**サブドメイン**）を発見したので、次に何から始めればよいかおそらく**わからない**でしょう。そこで、簡単にするため、まずすべての対象のスクリーンショットを撮りましょう。**メインページ**を**見るだけ**でも、より**脆弱**である可能性が高い**奇妙な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての**スクリーンショット**を解析し、**脆弱性を含んでいる可能性が高いもの**と、そうでないものを判別することもできます。

## Public Cloud Assets

企業に属する可能性のある cloud assets を見つけるには、まず**その企業を特定できるキーワードのリスト**を作成します。たとえば、crypto 企業であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**bucket で一般的に使われる単語**の wordlist も必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**permutation**を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlist では、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などの**ツールを使用できます。**

Cloud Assets を探す際は、AWS の bucket だけに**目を向けない**ようにしてください。

### **Looking for vulnerabilities**

**open bucket や外部に公開された cloud functions**などを見つけた場合は、それらに**アクセス**し、どのようなものが提供されているか、また悪用できるかどうかを確認してください。

## Emails

スコープ内の**ドメイン**と**サブドメイン**があれば、基本的に**email の検索を開始するために必要なもの**はそろっています。以下は、企業の email を見つけるうえで私にとって最も効果的だった**API**と**ツール**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - API とともに使用
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **Looking for vulnerabilities**

Email は後で**web login や auth service に対する brute-force**（SSH など）に役立ちます。また、**phishing**にも必要です。さらに、これらの API からは email の背後にいる**人物に関するより多くの情報**も得られるため、phishing campaign に役立ちます。

## Credential Leaks

**ドメイン、****サブドメイン**、および**email**を使って、それらの email に紐づく、過去に leak した credential を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**有効な leaked credential**を見つけた場合、これは非常に簡単な勝利です。

## Secrets Leaks

Credential leaks は、**機密情報が leak され、販売された**企業への攻撃に関連しています。しかし、企業は、情報がこれらの database に存在しない**別の leak**の影響を受けている可能性もあります。

### Github Leaks

Credential と API は、**企業**の**public repository**や、その企業で働く**user**の public repository から leak している可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos) という**tool**を使用すると、**organization**およびその**developer**の**public repo**をすべて**download**し、それらに対して [**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos**は、指定した **URL**から取得したすべての**text**に対して **gitleaks**を実行するためにも使用できます。**web page にも secrets が含まれている**ことがあるためです。

#### Github Dorks

organization 内を検索するための有用な**GitHub dorks**については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や単なる従業員が、**企業の content を paste site に公開**することがあります。そこに**機密情報**が含まれている場合も、含まれていない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使用すると、80以上の paste site を同時に検索できます。

### Google Dorks

古いものですが、優れた google dorks は、**本来存在すべきでない公開情報**を見つけるために常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に数千もの候補 query が含まれており、それらを手動で実行できないことです。そのため、お気に入りの 10 個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **のような**tool**を使ってすべて実行できます**。

_通常の Google browser を使って database 全体を実行しようとする tool は、Google に非常に早く block されるため、決して終了しないことに注意してください。_

### **Looking for vulnerabilities**

**有効な leaked credential や API token**を見つけた場合、これは非常に簡単な勝利です。

## Public Code Vulnerabilities

企業が**open-source code**を持っていることがわかった場合は、それを**analyse**して**vulnerability**を探すことができます。

**language に応じて**使用できる**tool**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)のリストを確認してください。

**public repository を scan**できる free service もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunter が発見する**vulnerability の大半**は**web application**内に存在します。そのため、この時点で**web application testing methodology**について説明したいと思います。[**こちらで情報を確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションについても特に触れておきたいと思います。非常に重要な vulnerability を発見できるとは期待すべきではありませんが、**workflow に組み込んで初期の web 情報を取得する**際に役立ちます。

## Recapitulation

> おめでとうございます！この時点で、すでに**基本的な enumeration をすべて**実行しました。そう、これは基本的なものです。なぜなら、さらに多くの enumeration を実行できるからです（後でさらに多くの trick を紹介します）。

すでに以下を実行しました。

1. スコープ内の**企業**をすべて発見した
2. 企業に属する**asset**をすべて発見した（スコープ内であれば vuln scan も実行した）
3. 企業に属する**ドメイン**をすべて発見した
4. ドメインの**サブドメイン**をすべて発見した（subdomain takeover は可能か？）
5. スコープ内のすべての**IP**（**CDN 由来**および**CDN 由来ではない**もの）を発見した
6. すべての**web server**を発見し、スクリーンショットを撮影した（詳細に確認する価値のある奇妙なものはないか？）
7. 企業に属する可能性のある**public cloud asset**をすべて発見した
8. 非常に簡単に**大きな成果**につながる可能性のある**email**、**credential leak**、および**secret leak**を発見した
9. 発見したすべての web に対して**Pentesting**を実行した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案した作業の一部を実行してくれる tool がいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていない

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
