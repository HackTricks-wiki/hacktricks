# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> So you were said that everything belonging to some company is inside the scope, and you want to figure out what this company actually owns.

このフェーズの目的は、まずメイン企業が所有するすべての **companies owned by the main company** を取得し、それからそれらの企業が持つすべての **assets** を特定することです。これを行うために、次を実施します:

1. メイン企業の買収先を見つけ、これによりスコープ内の企業を特定する。
2. 各企業の ASN (もしあれば) を見つけ、それにより各企業が所有する IP ranges を特定する。
3. reverse whois lookups を使って、最初のエントリに関連する他の情報（organisation names, domains...）を検索する（再帰的に行うことも可能）。
4. shodan の `org` や `ssl` フィルタなど他の手法を使って他のアセットを探索する（`ssl` トリックは再帰的に行える）。

### **Acquisitions**

まず最初に、どの **other companies are owned by the main company** を知る必要があります。\
一つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) を訪れ、**search** で **main company** を探し、**click** して "**acquisitions**" を見ることです。そこにメイン企業が買収した他の企業が表示されます。\
別の方法は、メイン企業の **Wikipedia** ページを訪れて **acquisitions** を探すことです。\
上場企業の場合は、**SEC/EDGAR filings**、**investor relations** ページ、または地域の企業登記（例：英国の **Companies House**）を確認してください。\
グローバルな企業ツリーや子会社を調べるには、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) や **GLEIF LEI** データベース ([https://www.gleif.org/](https://www.gleif.org/)) を試してみてください。

> Ok, at this point you should know all the companies inside the scope. Lets figure out how to find their assets.

### **ASNs**

An autonomous system number (**ASN**) は、**Internet Assigned Numbers Authority (IANA)** によって **autonomous system**（AS）に割り当てられる**一意の番号**です。\
**AS** は、外部ネットワークへのアクセスに関するポリシーが明確に定義された **blocks** の **IP addresses** で構成され、単一の組織によって管理されますが、複数の事業者で構成されることもあります。

企業が **ASN** を割り当てられているかを確認することは、その **IP ranges** を見つけるために有用です。スコープ内のすべての **hosts** に対して **vulnerability test** を行い、これらの IP 内にある **domains** を探すことに興味があるでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)、[**https://bgpview.io/**](https://bgpview.io/) または [**https://ipinfo.io/**](https://ipinfo.io/) で会社の **name**、**IP**、または **domain** で **search** できます。\
**会社の地域によっては追加で有用な情報が得られるリンク:** [**AFRINIC**](https://www.afrinic.net) **(アフリカ),** [**Arin**](https://www.arin.net/about/welcome/region/)**(北アメリカ),** [**APNIC**](https://www.apnic.net) **(アジア),** [**LACNIC**](https://www.lacnic.net) **(ラテンアメリカ),** [**RIPE NCC**](https://www.ripe.net) **(ヨーロッパ).** とにかく、たぶん最初のリンクですでに必要な**有用な情報**（IP ranges と Whois）は得られるでしょう。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration はスキャンの最後にASNsを自動的に集約して要約します。
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

### **Looking for vulnerabilities**

At this point we know **スコープ内のすべてのアセット**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
Also, you could launch some [**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) **or use services like** Shodan, Censys, or ZoomEye **to find** open ports **and depending on what you find you should** take a look in this book to how to pentest several possible services running.\
**Also, It could be worth it to mention that you can also prepare some** **default username** **and** **passwords** **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

## Domains

> We know all the companies inside the scope and their assets, it's time to find the domains inside the scope.

_Please, note that in the following purposed techniques you can also find subdomains and that information shouldn't be underrated._

First of all you should look for the **main domain**(s) of each company. For example, for _Tesla Inc._ is going to be _tesla.com_.

### **Reverse DNS**

As you have found all the IP ranges of the domains you could try to perform **reverse dns lookups** on those **IPs to find more domains inside the scope**. Try to use some dns server of the victim or some well-known dns server (1.1.1.1, 8.8.8.8)
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
For this to work, the administrator has to enable manually the PTR.\
オンラインツールでもこの情報を取得できます: [http://ptrarchive.com/](http://ptrarchive.com).\
大きなレンジの場合、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールはリバースルックアップやエンリッチメントの自動化に便利です。

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **情報** like **組織名**, **住所**, **メールアドレス**, 電話番号... しかしさらに興味深いのは、これらのフィールドのいずれかで**reverse whois lookups**を行うことで、（例えば同じメールアドレスが現れる他のwhoisレコードなど）**会社に関連するより多くの資産**を見つけられる点です。\
次のようなオンラインツールが使えます:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **無料**（web）、APIは有料
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（ただし**100回無料**の検索付き）
- [https://www.domainiq.com/](https://www.domainiq.com) - 有料
- [https://securitytrails.com/](https://securitytrails.com/) - 有料（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 有料（API）

このタスクは [**DomLink** ](https://github.com/vysecurity/DomLink) を使って自動化できます（whoxy API key が必要です）。\
また [amass](https://github.com/OWASP/Amass) を使って自動的に reverse whois の発見を行うこともできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法を使ってさらに多くのドメイン名を発見できることに注意してください。**

### **Trackers**

もし2つの異なるページで**同じトラッカーID**が見つかった場合、それらの**両方のページ**は**同じチームによって管理されている**と推測できます。\
例えば、複数のページで同じ **Google Analytics ID** や同じ **Adsense ID** を見かける場合です。

これらのトラッカーなどで検索できるウェブサイトやツールには次のようなものがあります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（analytics/trackersの共有から関連サイトを発見）

### **Favicon**

同じfaviconのハッシュを探すことで、ターゲットに関連するドメインやサブドメインを見つけられることをご存知でしたか？これはまさに [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)（作成: [@m4ll0k2](https://twitter.com/m4ll0k2)）が行うものです。使い方は次の通りです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

要するに、favihash はターゲットと同じ favicon アイコンの hash を持つドメインを発見することを可能にします。

さらに、favicon hash を使って技術を検索することもできます（詳細は [**this blog post**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139) を参照）。つまり、もし **web tech の脆弱なバージョンの favicon の hash** を知っていれば、shodan でそれを検索して **より多くの脆弱な箇所を見つける** ことができます：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
ウェブの **favicon hash** を計算する方法:
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
You can also get favicon hashes at scale with [**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) and then pivot in Shodan/Censys.

### **著作権 / ユニーク文字列**

ウェブページ内で、**同じ組織内の異なるウェブサイト間で共有される可能性のある文字列**を検索します。**著作権文字列**は良い例です。次に、その文字列を**google**や他の**ブラウザ**、あるいは**shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

例えば、次のようなcronジョブを設定していることがよくあります。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバ上のすべてのドメイン証明書を更新するために。これは、使用されたCAがValidity時間に生成時刻を設定していなくても、**certificate transparency logsで同じ会社に属するドメインを見つけることができる**ことを意味します。\
Check out this [**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/).

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メール DMARC 情報

You can use a web such as [https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) or a tool such as [https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) to find **domains and subdomain sharing the same dmarc information**.\
他に有用なツールは[**spoofcheck**](https://github.com/BishopFox/spoofcheck)と[**dmarcian**](https://dmarcian.com/)です。

### **Passive Takeover**

一般的に、サブドメインをクラウドプロバイダに属するIPに割り当て、その後そのIPアドレスを**失うがDNSレコードの削除を忘れる**ことがよくあります。したがって、単にクラウド（例: Digital Ocean）で**VMを起動する**だけで、実際に**いくつかのサブドメインを奪取する**ことができます。

[**This post**](https://kmsec.uk/blog/passive-takeover/) はこの件について説明し、**DigitalOceanでVMを作成**し、**新しいマシンのIPv4を取得**して、**Virustotalでそれを指すサブドメインレコードを検索する**スクリプトを提案しています。

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

既にIP空間を所有する組織名が分かっているので、shodanでその情報を使って検索できます: `org:"Tesla, Inc."`。見つかったホストのTLS証明書を確認し、予期しない新しいドメインがないかチェックしてください。

You could access the **TLS certificate** of the main web page, obtain the **Organisation name** and then search for that name inside the **TLS certificates** of all the web pages known by **shodan** with the filter : `ssl:"Tesla Motors"` or use a tool like [**sslsearch**](https://github.com/HarshVaragiya/sslsearch).

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに関連する**ドメイン**やそれらの**サブドメイン**を探すツールで、かなり優秀です。

**Passive DNS / Historical DNS**

Passive DNSデータは、まだ解決される古い忘れられたレコードや、奪取可能なレコードを見つけるのに最適です。以下を参照してください:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover). Maybe some company is **using some a domain** but they **lost the ownership**. Just register it (if cheap enough) and let know the company.

If you find any **domain with an IP different** from the ones you already found in the assets discovery, you should perform a **basic vulnerability scan** (using Nessus or OpenVAS) and some [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) with **nmap/masscan/shodan**. Depending on which services are running you can find in **this book some tricks to "attack" them**.\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## サブドメイン

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

これで、見つかった各ドメインの可能なすべてのサブドメインを見つける時です。

> [!TIP]
> ドメインを見つけるためのツールや手法の中には、サブドメインの発見にも役立つものがある点に注意してください。

### **DNS**

DNSレコードから**サブドメイン**を取得してみましょう。また、**Zone Transfer**も試すべきです（脆弱ならレポートしてください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多くのサブドメインを取得する最も速い方法は、外部ソースを検索することです。最もよく使われる**tools**は以下の通りです（より良い結果を得るにはAPI keysを設定してください）:

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
他にも、直接subdomainsの発見に特化していない場合でもsubdomainsを見つけるのに役立つ**other interesting tools/APIs**があります。例えば:

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用して subdomains を取得します
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC 無料 API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) 無料のAPI
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
- [**gau**](https://github.com/lc/gau)**:** 指定したドメインの既知のURLを AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): それらはWebをスクレイピングしてJSファイルを探し、そこからsubdomainsを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) は subdomains と IP history を検索するための無料の API を提供しています
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは **無料で bug-bounty programs に関連するすべての subdomains を提供しています**。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることも、プロジェクトで使用されているスコープにアクセスすることもできます: https://github.com/projectdiscovery/chaos-public-program-list

多くのこれらのツールの**比較**はここで確認できます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能な subdomain names を使って DNS servers をブルートフォースし、新しい subdomains を見つけてみましょう。

For this action you will need some **common subdomains wordlists like**:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

And also IPs of good DNS resolvers. In order to generate a list of trusted DNS resolvers you can download the resolvers from [https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) and use [**dnsvalidator**](https://github.com/vortexau/dnsvalidator) to filter them. Or you could use: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

The most recommended tools for DNS brute-force are:

- [**massdns**](https://github.com/blechschmidt/massdns): これは効果的な DNS brute-force を実行した最初のツールでした。非常に高速ですが、誤検知が発生しやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのresolverしか使わないと思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、goで書かれており、active bruteforce を使って有効なサブドメインを列挙できるほか、ワイルドカード処理と簡単な入出力サポートでサブドメインを解決できます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): `massdns` も使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使ってドメイン名を非同期に brute force します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 2回目の DNS Brute-Force ラウンド

公開ソースと brute-forcing を使ってサブドメインを見つけた後、見つかったサブドメインの派生を生成してさらに多く見つけることができます。この目的に役立つツールがいくつかあります：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを与えると、バリエーション（パーミュテーション）を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインからパーミュテーションを生成します。
- goaltdnsのパーミュテーション用**wordlist**は[**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt)で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインをもとにパーミュテーションを生成します。パーミュテーションファイルが指定されていない場合、gotatorは組み込みのものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutationsを生成するだけでなく、それらをresolveしようとすることもできます（ただし、前に挙げたツールを使う方が良いです）。
- altdns permutations用**wordlist**は[**here**](https://github.com/infosec-au/altdns/blob/master/words.txt)で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの順列、変異、変更を行う別のツールです。このツールは結果をbrute forceします（dns wild cardはサポートしていません）。
- dmut permutations wordlist は [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) で入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定されたパターンに従って**新しい潜在的なサブドメイン名を生成**し、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

- [**regulator**](https://github.com/cramppet/regulator): 詳細はこの[**post**](https://cramppet.github.io/regulator/index.html)を参照してください。基本的に、**主要部分**を**発見されたサブドメイン**から抽出し、それらを組み合わせてより多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常に単純だが効果的な DNS response-guided algorithm と組み合わされた subdomain brute-force fuzzer です。提供された入力データ（tailored wordlist や historical DNS/TLS records など）を利用して、より多くの対応する domain names を正確に合成し、DNS scan 中に収集された情報に基づいてループでさらに拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン発見ワークフロー**

私が書いたこのブログ記事をチェックしてください。ここでは、**ドメインからのサブドメイン探索を自動化する**方法を、**Trickest workflows**を使って説明しており、手元のコンピュータで多数のツールを手動で起動する必要がありません:

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

もしサブドメインに属する**1つまたは複数のウェブページ**を含むIPアドレスを見つけた場合、IP内のドメインを調べるために**OSINT sources**を参照するか、同じIPで**brute-forcing VHost domain names in that IP**を行って、**そのIP内の他のサブドメインを見つける**ことを試みることができます。

#### OSINT

いくつかの**VHosts in IPs using**を[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **or other APIs**で見つけることができます。

**Brute Force**

あるサブドメインがウェブサーバに隠されていると思われる場合、それをbrute forceで探すことを試みることができます:
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
> この手法を使うと、内部/隠れた endpoints にアクセスできることさえあります。

### **CORS Brute Force**

場合によっては、有効な domain/subdomain が _**Origin**_ ヘッダーに設定されているときにのみ、ページが _**Access-Control-Allow-Origin**_ ヘッダーを返すことがあります。こうした状況では、この挙動を悪用して新しい **subdomains** を **発見** することができます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

**subdomains**を探す際は、どのタイプの**bucket**に**pointing**しているか注意し、その場合は[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**.**\
また、この時点でスコープ内のすべてのドメインが分かっているはずなので、[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)を試してみてください。

### **監視**

ドメインの**new subdomains**が作成されたかどうかは、**Certificate Transparency** Logsを**monitor**することで確認できます。これは[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行うことです。

### **脆弱性の探索**

可能な[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)を確認してください。\
もし**subdomain**が**S3 bucket**を指している場合は、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

アセット発見で既に見つかっているものとは異なるIPを持つ**subdomain with an IP different**を見つけた場合は、**basic vulnerability scan**（Nessus や OpenVAS を使用）を行い、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を**nmap/masscan/shodan**で実施すべきです。どのサービスが動作しているかによっては、**this book some tricks to "attack" them**を見つけられることがあります。\
_注意: 場合によってはサブドメインがクライアント管理外のIP上にホストされており、そのためスコープ外であることがあるので注意してください。_

## IPs

初期のステップで**found some IP ranges, domains and subdomains**が見つかっているかもしれません。\
これらのレンジから**recollect all the IPs from those ranges**し、ドメイン/サブドメイン（DNS クエリ）についても収集する時です。

以下の**free apis**を利用すると、ドメインやサブドメインが以前に使用していた**previous IPs used by domains and subdomains**も見つけることができます。これらのIPはまだクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられることがあります。

- [**https://securitytrails.com/**](https://securitytrails.com/)

特定のIPアドレスを指しているドメインを調べるにはツール[**hakip2host**](https://github.com/hakluke/hakip2host)を使うこともできます。

### **脆弱性の探索**

**Port scan all the IPs that doesn’t belong to CDNs**（CDNに属さないすべてのIPをポートスキャンする）ことを推奨します（CDN内では興味深いものが見つかる可能性は低いです）。発見した稼働中のサービスから**able to find vulnerabilities**ことがあります。

**Find a** [**guide**](../pentesting-network/index.html) **about how to scan hosts.**

## Web servers 探索

> We have found all the companies and their assets and we know IP ranges, domains and subdomains inside the scope. It's time to search for web servers.

前のステップでおそらく既に**recon of the IPs and domains discovered**を行っているため、**already found all the possible web servers**である可能性があります。しかし、まだならこれからスコープ内で**fast tricks to search for web servers**を見ていきます。

これは**oriented for web apps discovery**向けなので、**perform the vulnerability**や**port scanning**も（スコープが許可していれば）実施すべきです。

[**masscan** can be found here](../pentesting-network/index.html#http-port-discovery)を使った**fast method**で**ports open**（web に関連するポート）を発見する方法があります。\
web servers を探す別の便利なツールは[**httprobe**](https://github.com/tomnomnom/httprobe)**,** [**fprobe**](https://github.com/theblackturtle/fprobe) と [**httpx**](https://github.com/projectdiscovery/httpx)です。ドメインのリストを渡すと、ポート80 (http) と443 (https) に接続を試みます。さらに他のポートを試すよう指定することもできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

今やスコープ内に存在する**all the web servers**（会社の**IPs**やすべての**domains**と**subdomains**の中で）を発見したので、おそらく**どこから始めればいいか分からない**でしょう。そこでシンプルにして、まずそれらすべてのスクリーンショットを撮ることから始めます。**main page**を一目見るだけで、より脆弱になりやすい**weird endpoints**を見つけられることがあります。

提案したアイデアを実行するには [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

さらに、すべての**screenshots**を解析して**what's likely to contain vulnerabilities**を教えてくれる [**eyeballer**](https://github.com/BishopFox/eyeballer) を使うこともできます。

## Public Cloud Assets

会社に属する可能性のあるクラウド資産を見つけるには、まず**その会社を識別するキーワードのリスト**を作るべきです。例えば、crypto 企業なら `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` のような単語を使います。

また、**common words used in buckets** のワードリストも必要です:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

それらの単語から**permutations**を生成する必要があります（詳細は [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を参照）。

生成したワードリストを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)** のようなツールを使うことができます。**

Cloud Assets を探す際は、**look for more than just buckets in AWS** べきだという点を忘れないでください。

### **Looking for vulnerabilities**

もし **open buckets or cloud functions exposed** のようなものを見つけたら、**access them** して何が得られるか、悪用できるかを試してみてください。

## Emails

スコープ内の**domains**と**subdomains**があれば、基本的に**emails 検索を始めるために必要なものは揃っています**。会社のメールを見つけるために私が最もよく使う**APIs**と**tools**は以下です:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails は後で **brute-force web logins and auth services**（例えば SSH）を試すのに役立ちます。また、**phishings** にも必要です。さらに、これらの APIs はメールの背後にいる人物についてさらに多くの**info about the person**を与えてくれるので、フィッシングキャンペーンに有用です。

## Credential Leaks

**domains**, **subdomains**, および **emails** があれば、それらのメールに属する過去の credential leaked を探し始めることができます:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

もし **valid leaked credentials** を見つけたら、これは非常に簡単な勝利です。

## Secrets Leaks

Credential leaks は企業のハックで**sensitive information が漏洩して販売されたケース**に関連します。しかし、企業はそのデータベースに載らない**その他の leaks**の影響を受けている可能性があります。

### Github Leaks

Credentials や APIs は、会社またはその会社で働くユーザーの**public repositories**で漏れている場合があります。\
ツール [**Leakos**](https://github.com/carlospolop/Leakos) を使って、組織とその開発者の**public repos** を**download**し、自動的に [**gitleaks**](https://github.com/zricethezav/gitleaks) を実行できます。

**Leakos** は渡された **URLs** 内の**text** に対しても **gitleaks** を実行するように使えます。なぜなら、時には **web pages also contains secrets** することがあるからです。

#### Github Dorks

攻撃対象の組織で検索できる潜在的な **github dorks** についてはこの**ページ**もチェックしてください:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

時には攻撃者や従業員が **company content を paste site に公開する**ことがあります。これには**sensitive information**が含まれることもあるので、検索する価値は高いです。\
ツール [**Pastos**](https://github.com/carlospolop/Pastos) を使えば、80 を超える paste sites を同時に検索できます。

### Google Dorks

古くて有用な google dorks は、**exposed information that shouldn't be there** を見つけるのに常に役立ちます。問題は [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) が数**thousands**ものクエリを含んでおり、それを手作業で実行することはできない点です。なので、自分のお気に入りの10個を使うか、すべてを実行するために [**Gorks**](https://github.com/carlospolop/Gorks) のような**tool**を使うことができます。

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

もし **valid leaked credentials or API tokens** を見つけたら、これは非常に簡単な勝利です。

## Public Code Vulnerabilities

もし会社が**open-source code**を持っていると分かったら、それを**analyse**して脆弱性を探すことができます。

**言語によって**使える**tools**が異なります:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

public repositories をスキャンできる無料サービスもあります。例えば:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

バグハンターが見つける**majority of the vulnerabilities**は**web applications**内にあるため、ここで**web application testing methodology**について触れたいと思います。詳細は[**こちら**](../../network-services-pentesting/pentesting-web/index.html)で確認できます。

また、セクション [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) を特別に挙げておきます。これらは非常にセンシティブな脆弱性を見つけてくれると期待すべきではありませんが、**workflows** に組み込んで**initial web information**を得る目的では便利です。

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

これまでに既に次のことを行っています:

1. スコープ内のすべての**companies**を見つけた
2. 会社に属するすべての**assets**を見つけた（スコープ内なら一部 vuln scan を実施）
3. 会社に属するすべての**domains**を見つけた
4. その domains のすべての**subdomains**を見つけた（any subdomain takeover?）
5. スコープ内のすべての**IPs**（CDNs 由来のものとそうでないもの）を見つけた
6. すべての**web servers**を見つけ、**screenshot**を撮った（何か deeper look に値する weird なものはあるか？）
7. 会社に属する可能性のあるすべての**potential public cloud assets**を見つけた
8. **Emails**, **credentials leaks**, および **secret leaks** — これらは非常に簡単に**big win**をもたらす可能性がある
9. 見つけたすべての webs の **pentesting**

## **Full Recon Automatic Tools**

与えられたスコープに対して提案されたアクションの一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
