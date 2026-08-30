# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

> つまり、ある company に属するすべてのものが scope 内にあると伝えられ、その company が実際に何を所有しているのかを把握したいということです。

このフェーズの目的は、**main company が所有するすべての companies**を特定し、次にこれらの companies のすべての**assets**を特定することです。そのために、次のことを行います。<sup>[[1]](#references)</sup>

1. main company の acquisitions を特定します。これにより、scope 内の companies がわかります。
2. 各 company の ASN（存在する場合）を特定します。これにより、各 company が所有する IP ranges がわかります。
3. reverse whois lookups を使用して、最初の company に関連する他の entries（organisation names、domains など）を検索します（これは再帰的に実行できます）。
4. Shodan の `org` および `ssl` filters などの他の techniques を使用して、他の assets を検索します（`ssl` trick は再帰的に実行できます）。

### **Acquisitions**

まず、**main company が所有する他の companies**を把握する必要があります。\
1つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**main company を検索**して "**acquisitions**" を**クリック**することです。そこには、main company によって買収された他の companies が表示されます。\
別の方法は、main company の **Wikipedia** ページにアクセスし、**acquisitions** を検索することです。\
public companies の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または各地域の corporate registries（英国の **Companies House** など）を確認します。\
global corporate trees と subsidiaries については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）と **GLEIF LEI** database（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、scope 内のすべての companies が把握できたはずです。次に、それらの assets を見つける方法を確認しましょう。

### **ASNs**

autonomous system number（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS**は、外部 networks へのアクセスに関する明確に定義された policy を持ち、単一の organisation によって管理される**IP addresses の blocks**で構成されています。ただし、複数の operators から構成される場合があります。

**company に ASN が割り当てられているか**を確認し、その**IP ranges**を特定することは有用です。scope 内のすべての **hosts** に対して**vulnerability test**を実行し、これらの IP 内の**domains**を探すことができます。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **、または** [**https://ipinfo.io/**](https://ipinfo.io/) では、company **name**、**IP**、または **domain** で**検索**できます。\
**company の region に応じて、さらに data を収集するために次の links が役立つ場合があります:** [**AFRINIC**](https://www.afrinic.net) **（Africa）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（North America）、** [**APNIC**](https://www.apnic.net) **（Asia）、** [**LACNIC**](https://www.lacnic.net) **（Latin America）、** [**RIPE NCC**](https://www.ripe.net) **（Europe）。**いずれにせよ、おそらく**有用な情報**（IP ranges と Whois）のほとんどは、最初の link にすでに表示されています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**
enumeration は、scan の最後に ASN を自動的に集約して要約します。
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
組織の IP ranges は [http://asnlookup.com/](http://asnlookup.com)（free API あり）を使って見つけることもできます。\
[http://ipv4info.com/](http://ipv4info.com) を使えば、domain の IP と ASN を見つけることができます。

### **脆弱性の検索**

この時点で、**scope 内のすべての assets** が判明しているため、許可されている場合は、すべての hosts に対して **vulnerability scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの **services を使用して** open ports **を見つけたりすることもできます。見つかった内容に応じて**、稼働している可能性のある複数の services を pentest する方法について、この book を確認してください。\
**また、いくつかの** default username **と** passwords **の lists を準備し、** [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) **を使って services を** bruteforce **してみることも検討する価値があります。**

## Domains

> scope 内のすべての companies とその assets が判明したので、次は scope 内の domains を見つけます。

_以下で説明する techniques では subdomains も見つけられるため、その情報を過小評価してはいけない点に注意してください。_

まず、各 company の **main domain**(s) を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domains のすべての IP ranges が判明したので、それらの **IPs に対して reverse dns lookups** を実行し、**scope 内のさらに多くの domains を見つける**ことができます。victim の dns server、またはよく知られた dns server（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報にはオンラインツールも使用できます：[http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)などのツールが、reverse lookupと情報のenrichmentを自動化するのに役立ちます。

### **Reverse Whois (loop)**

**whois**の中には、**organisation name**、**address**、**emails**、電話番号など、多くの興味深い**information**が含まれています。しかし、さらに興味深いのは、これらのフィールドのいずれかを使って**reverse whois lookups**を実行すると、**companyに関連するより多くのassets**を発見できることです（たとえば、同じemailが表示される別のwhois registriesなど）。\
次のようなオンラインツールを使用できます：

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebおよびAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Webは**無料**、APIは無料ではありません。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回無料**の検索のみ）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 無料ではありません（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 無料ではありません（API）

このタスクは[**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API keyが必要）を使用して自動化できます。\
[amass](https://github.com/OWASP/Amass)を使って、reverse whois discoveryの一部を自動的に実行することもできます：`amass intel -d tesla.com -whois`

**新しいdomainを発見するたびに、より多くのdomain namesを発見するためにこのtechniqueを使用できることに注意してください。**

### **Trackers**

2つの異なるページで、同じtrackerの**同じID**を発見した場合、**両方のページ**が**同じteamによって管理されている**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**または同じ**Adsense ID**が確認できる場合です。

これらのtrackersなどを検索できるページやtoolsがいくつかあります：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有されたanalytics/trackersによって関連サイトを発見）
- [**StackScan**](https://www.stackscan.com) - **Free tier**（WebおよびAPI）。tracker IDsだけでなく、script path、self-hosted bundle name、assetの読み込み元hostなど、配信される任意のassetをpivotし、それを含むすべてのsiteを返します

APIは単一のdomainのstackを返します。これは、候補となるassetが同じestateに属していることを確認するのに役立ちます：
```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
"https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```
検出された各 technology とその category を返します。Asset pivoting は現在 web のみ対応しており、API ではドメイン単位の lookup が可能です。

### **Favicon**

同じ favicon icon hash を検索することで、target に関連するドメインやサブドメインを見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool が行うことです。使用方法は次のとおりです。
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favicon hashを使用して同じfavicon hashを共有するドメインを発見したfavihashの結果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言えば、favihashを使うと、対象と同じfavicon icon hashを持つドメインを発見できます。

![同じfavicon hashを持つドメインの発見に使用したfavihashの出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanまたはFOFAのpivotとして使用し、同じtechnologyの他の公開インスタンスを見つけます。<sup>[[5]](#references)</sup>
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```
Webサイトの **favicon hash**（**base64-encoded** された favicon のバイト列に対する MMH3）の**計算方法**は次のとおりです：
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
[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使えば、favicon hashも大規模に取得でき、その後 Shodan/Censys で pivot できます。

favicon fingerprintは手がかりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hashは証拠ではなく指標として扱う**: MMH3はコンパクトであり、collision、再利用されたicon、意図的なspoofingの可能性があります。
- **`/favicon.ico`以外もprobeする**: framework/build paths、manifest files、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URLs、HTMLの`<link rel="icon">` tagsを調査します。
- **WAF/SSO/IdP controlsの背後でもstatic assetsに到達できる場合がある**: iconを直接requestし、`ETag`、`Last-Modified`、redirects、cache headersを確認します。
- **周辺のシグナルでmatchesを検証する**: title、HTML/body hash、headers、TLS certificate subjects/SANs、product components、exposed portsを比較します。
- **HTML/body hashでcluster化する**: 一貫したtemplateはfingerprintの信頼性を高めます。異なるtemplateが混在している場合は、genericまたはshared iconである可能性があります。
- **無関係なsignatures、ports、productsにまたがってhashが現れる場合は、潜在的なhoneypotまたはplaceholderとして扱う。**
- **曖昧なtargetsでは、実在するpageと存在しないpath**（`/_favicon_probe_<8-hex>`など）を比較します。hostingまたはparking responsesが一致する場合、共通するiconの理由を説明できる可能性があります。
- **favicon hashesをproductsやCPEsに対応付けるNuclei detection rulesまたはpublic datasetsからtriageを開始する。**
- **IP-centricなcoverage gapを忘れない**: CDN-fronted、SNI-routed、anycast、domain-onlyのsurfacesは、Shodan-like datasetsに含まれていない可能性があります。

### **Copyright / Uniq string**

web pages内で、**同じ組織の異なるwebs間で共有されている可能性があるstrings**を検索します。**copyright string**は良い例です。次に、そのstringを**google**、他の**browsers**、さらには**shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

次のようなcron jobが存在することは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべての証明書を同時に更新するために。証明書のタイムスタンプまたはcertificate-transparencyログの位置を相関させることで、関連するドメインを明らかにできます。<sup>[[6]](#references)</sup>

**certificate transparency**ログも直接使用します：

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使用して、**同じDMARC情報を共有するドメインとサブドメイン**を見つけられます。\
その他の便利なツールとして、[**spoofcheck**](https://github.com/BishopFox/spoofcheck)や[**dmarcian**](https://dmarcian.com/)があります。

### **Passive Takeover**

放棄されたAレコードは、cloud providerがIPを再割り当てすると到達可能になる場合があります。参照されている調査では、インスタンスをプロビジョニングし、そのアドレスをpassive DNSデータと相関させる機会的なワークフローが示されています。takeoverのシナリオは、許可された範囲内でのみテストしてください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当するdiscovery pivotを繰り返してください。各結果から、元のseedからは確認できなかった追加の証明書名、passive-DNSの関係、faviconの一致、組織識別子が明らかになる可能性があります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織名はすでに分かっているため、次のようにShodanでそのデータを検索できます：`org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、新しく予期しないドメインがないか調べます。

メインWebページの**TLS certificate**にアクセスして**Organisation name**を取得し、その後、**Shodan**が把握しているすべてのWebページの**TLS certificates**内でその名前を検索することもできます。フィルターは `ssl:"Tesla Motors"` です。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使用します。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に便利です。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も解決される、またはtakeover可能な**古く忘れられたレコード**を見つけるのに役立ちます。以下を確認してください：

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)を確認してください。ある企業が**ドメインを使用しているものの**、**所有権を失っている**可能性があります。十分に安ければ登録し、企業に知らせてください。

すでにassets discoveryで見つけたものとは**異なるIPを持つドメイン**を見つけた場合は、**basic vulnerability scan**（NessusまたはOpenVASを使用）と、**port scan**（[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)）を**nmap/masscan/shodan**で実行してください。稼働しているサービスによっては、**この本でそれらを「攻撃」するためのトリック**を見つけられます。\
_ドメインがクライアントの管理下にないIP内でホストされている場合があるため、scope外になることがあります。注意してください。_

## サブドメイン

> scope内のすべての企業、それぞれの企業のすべてのasset、および企業に関連するすべてのドメインを把握しています。

見つかった各ドメインについて、考えられるすべてのサブドメインを見つける段階です。

> [!TIP]
> ドメインを見つけるための一部のツールや手法は、サブドメインの発見にも役立つことに注意してください。

### **DNS**

**DNS**レコードから**サブドメイン**を取得してみましょう。**Zone Transfer**も試すべきです（脆弱な場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のサブドメインを取得する最も速い方法は、外部ソースを検索することです。最もよく使用される**tools**は次のとおりです（より良い結果を得るにはAPIキーを設定してください）。

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
**サブドメインの発見に直接特化していなくても、サブドメインの発見に役立つ可能性がある、その他の興味深いツール/API**があります。

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
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): WebをスクレイピングしてJSファイルを探し、そこからサブドメインを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) には、サブドメインと IP 履歴を検索するための無料 API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

この project では、**bug-bounty programs に関連するすべてのサブドメインを無料で**提供しています。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使用してアクセスすることも、この project で使用されている scope に [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) からアクセスすることもできます

これらのツールの多くの**比較**はこちらで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

考えられるサブドメイン名を使用して DNS servers に対して brute-force を行い、新しい**サブドメイン**を見つけてみましょう。

この操作には、次のような**一般的なサブドメインの wordlists**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れた DNS resolvers の IP も必要です。信頼できる DNS resolvers の list を生成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使用して filter できます。または、次のものを使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨される tools は次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初の tool です。非常に高速ですが、false positives が発生しやすいという欠点があります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverしか使わないと思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` の wrapper で、go で記述されています。active bruteforce による有効なサブドメインの列挙に加え、wildcard handling と容易な input-output support によるサブドメインの解決が可能です。
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
### DNS Brute-Force の第2ラウンド

オープンソースの情報と brute-forcing を使用してサブドメインを発見した後、見つかったサブドメインのバリエーションを生成して、さらに多くのサブドメインを見つけられる可能性があります。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを指定すると、permutations を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定して、permutationsを生成します。
- goaltdnsのpermutations **wordlist**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から取得できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutations を生成します。permutations file が指定されていない場合、gotator は独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutation を生成するだけでなく、それらの解決も試行できます（ただし、前述のコメントアウトされたツールを使用する方がよいでしょう）。
- altdns の permutation **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)で取得できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別の tool。この tool は結果を brute force します（dns wild card には対応していません）。
- dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定したパターンから**新たな潜在的サブドメイン名を生成**し、より多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、解決対象となる候補名を生成します。<sup>[[8]](#references)</sup>
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS reponse-guided algorithm と組み合わせた subdomain brute-force fuzzer です。tailored wordlist や過去の DNS/TLS records など、提供された input data を利用し、DNS scan 中に収集した情報に基づいて、対応する domain names をより正確に合成し、ループ内でさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

Trickest workflow の例では、再現可能な subdomain enumeration のために OSINT、DNS brute force、permutation の各ステージを組み合わせています。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

subdomains に属する **1つまたは複数の web pages** を含む IP address を見つけた場合、その IP に存在する **他の subdomains** を、**OSINT sources** で IP 上の domains を検索するか、**その IP に対して VHost domain names を brute-force** することで探せます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **または他の APIs を使用して、IP 内の VHosts を見つける**ことができます。

**Brute Force**

ある subdomain が web server に隠れている可能性がある場合、brute force を試せます。

name-based vhosts の場合は、`Host` header を fuzz し、ffuf の auto-calibration を使用して default response をフィルタリングします。<sup>[[2]](#references)</sup>
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
> この technique を使うと、内部/hidden endpoint にアクセスできる場合もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような状況では、この動作を悪用して新たな **subdomains** を **discover** できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains** を探す際は、何らかの **bucket** を**指している**かどうかを確認し、その場合は[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)**してください。**\
また、この時点ではスコープ内のすべてのドメインが判明しているため、[**考えられる bucket 名を brute force し、権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してみてください。

### **監視**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行う **Certificate Transparency** Logs の監視により、ドメインの**新しい subdomains**が作成されたかどうかを**監視**できます。

### **脆弱性の確認**

[**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) の可能性を確認してください。\
**subdomain** が何らかの **S3 bucket** を指している場合は、[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

資産の discovery ですでに発見したものとは**異なる IP** を持つ **subdomain** を見つけた場合は、**basic vulnerability scan**（Nessus または OpenVAS を使用）と、**nmap/masscan/shodan** による [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行してください。実行中の service に応じて、**この book にはそれらを「attack」するための tricks がいくつか記載されています**。\
_ただし、subdomain が client に管理されていない IP 内でホストされている場合があり、その場合はスコープ外となるため注意してください。_

## IPs

初期段階で、**IP range、domain、subdomain**がいくつか**見つかっている**可能性があります。\
それらの range からすべての IP を**収集**し、**domain/subdomain については DNS query を実行する**時です。

以下の **free apis** の service を利用すると、**domain と subdomain が過去に使用していた IP** も確認できます。これらの IP は現在も client が所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) の発見につながる場合があります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

tool [**hakip2host**](https://github.com/hakluke/hakip2host) を使用して、特定の IP address を指している domain を確認することもできます。

### **脆弱性の確認**

**CDN に属さないすべての IP を port scan** してください（そこではおそらく興味深いものが何も見つからないためです）。発見した実行中の service に**脆弱性が存在する**可能性があります。

**host の scan 方法についての** [**guide**](../pentesting-network/index.html) **を確認してください。**

## Web server の探索

> すべての company とその asset を発見し、スコープ内の IP range、domain、subdomain を把握しました。次は web server を探します。

前の手順で、発見した IP と domain の **recon をすでに実行している**可能性が高いため、**考えられるすべての web server をすでに発見している**かもしれません。ただし、まだの場合は、スコープ内の web server を探すための**高速な tricks**をいくつか見ていきます。

これは**web app discovery 向け**であることに注意してください。そのため、スコープで**許可されている**場合は、**vulnerability** と **port scanning** も実行してください。

[**masscan** を使用して web server に関連する **open port** を発見する高速な方法は、こちら](../pentesting-network/index.html#http-port-discovery)にあります。\
web server を探すための、より扱いやすい別の tool として、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) があります。domain の list を渡すだけで、port 80（http）と 443（https）への接続を試行します。さらに、他の port も試行するよう指定できます。
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内に存在する**すべての web servers**（企業の**IP**、すべての**domains**および**subdomains**）を発見した now、どこから始めればよいか**わからない**でしょう。そこで、簡単にするため、まずすべての対象の screenshot を撮りましょう。**main page**を**見るだけ**で、より**脆弱**である**可能性が高い**、**奇妙な** endpoint を見つけられることがあります。

提案した方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使ってすべての**screenshots**を調べ、**脆弱性を含んでいる可能性が高いもの**と、そうでないものを判定することもできます。

## Public Cloud Assets

企業に属する可能性のある cloud assets を見つけるには、まずその企業を識別できる**キーワードのリスト**から始めるべきです。たとえば、crypto 企業の場合、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` などの単語を使用できます。

また、**buckets でよく使われる単語**の wordlists も必要になります。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**permutations**を生成します（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を確認してください）。

生成した wordlists では、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを使用できます。**

Cloud Assets を探す際は、**AWS の buckets だけではない**ことを忘れないでください。

### **Looking for vulnerabilities**

**open buckets や exposed cloud functions**などを見つけた場合は、**アクセス**して、それらが何を提供しているか、また悪用できるかを確認するべきです。

## Emails

スコープ内の**domains**と**subdomains**があれば、基本的に**emails を探し始めるために必要なもの**はすべて揃っています。以下は、企業の emails を見つけるために私が最も効果的だと感じた**APIs**と**tools**です。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIs とともに使用
- [**https://hunter.io/**](https://hunter.io/) の API（free version）
- [**https://app.snov.io/**](https://app.snov.io/) の API（free version）
- [**https://minelead.io/**](https://minelead.io/) の API（free version）

### **Looking for vulnerabilities**

Emails は後で **web logins や auth services**（SSH など）を**brute-force**する際に役立ちます。また、**phishings**にも必要です。さらに、これらの APIs からは email の**背後にいる人物に関する追加情報**も得られるため、phishing campaign に役立ちます。

## Credential Leaks

**domains、** **subdomains**、および**emails**を使って、それらの emails に属する、過去に**leak した credentials**を探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**有効な leaked credentials**を見つけた場合、これは非常に簡単な成果です。

## Secrets Leaks

Credential leaks は、企業が hack され、**sensitive information が leak して販売された**ケースに関連します。しかし、企業は、情報がそれらの databases に含まれていない**別の leaks**の影響を受けている可能性もあります。

### Github Leaks

企業の**public repositories**、またはその企業で働く**users**の public repositories から、credentials や APIs が**leak している**可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos) という**tool**を使えば、**organization**とその**developers**の**public repos**をすべて**download**し、[**gitleaks**](https://github.com/zricethezav/gitleaks) を自動的に実行できます。

**Leakos**は、指定された **URLs**から提供されるすべての**text**に対して **gitleaks**を実行するためにも使用できます。これは、**web pages にも secrets が含まれている**ことがあるためです。

#### Github Dorks

組織内で検索できる**GitHub dorks**の候補については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や単なる従業員が、**paste site に企業のコンテンツを公開**することがあります。そこに**sensitive information**が含まれている場合もあれば、含まれていない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)という tool を使えば、80を超える paste sites を同時に検索できます。

### Google Dorks

古いながらも有用な google dorks は、**本来そこにあるべきではない exposed information**を見つけるのに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) に数**千**もの候補 query が含まれており、手動では実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などの tool を使ってすべて実行**できます。

_通常の Google browser を使って database 全体を実行しようとする tools は、google に非常に早く block されるため、決して終了しないことに注意してください。_

### **Looking for vulnerabilities**

**有効な leaked credentials や API tokens**を見つけた場合、これは非常に簡単な成果です。

## Public Code Vulnerabilities

企業が**open-source code**を持っていることがわかった場合、それを**analyse**して**vulnerabilities**を探すことができます。

**language に応じて**使用できる**tools**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を確認してください。

**public repositories**を**scan**できる free services もあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunters が発見する**vulnerabilities の大半**は**web applications**内に存在するため、ここでは**web application testing methodology**について説明します。情報は[**こちらで確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションにも特に触れておきます。非常に高度な vulnerabilities の発見を期待すべきではありませんが、**初期の web 情報を得るための workflows に組み込む**際に役立ちます。

## Recapitulation

> おめでとうございます！この時点で、すでに**基本的な enumeration をすべて**実行しました。もちろん、これは基本的なものです。さらに多くの enumeration が可能だからです（後でより多くの tricks を紹介します）。

すでに以下を実行しました。

1. スコープ内の**companies**をすべて発見した
2. 企業に属する**assets**をすべて発見した（スコープ内であれば vuln scan も実行した）
3. 企業に属する**domains**をすべて発見した
4. domains の**subdomains**をすべて発見した（subdomain takeover はないか？）
5. スコープ内のすべての**IPs**（CDNs 由来のものと**そうでないもの**）を発見した
6. **web servers**をすべて発見し、その screenshot を撮影した（詳しく調べる価値のある奇妙なものはないか？）
7. 企業に属する**potential public cloud assets**をすべて発見した
8. 非常に簡単に**大きな成果**をもたらす可能性のある **Emails**、**credentials leaks**、および**secret leaks**
9. 発見したすべての web に対して**Pentesting**を実行した

## **Full Recon Automatic Tools**

指定された scope に対して、提案した actions の一部を実行する tools がいくつか存在します。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていない

## References

- [1] [Jason Haddix – Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Favicons について：Browser Icons から Attack Surface Intelligence まで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties、OSINT などのための favicon.ico の Weaponizing](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparency への Time-Correlation Attack による Domains の Discovering](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額な Subdomain Takeover Campaign の発見（および Emulating）](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：Subdomain Enumeration の独自手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow、Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Automated Trickest Workflow を使用した Full Subdomain Brute Force Discovery、Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
