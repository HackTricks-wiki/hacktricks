# 外部 Recon 方法論

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するものはすべてスコープ内にあると言われ、その会社が実際に何を所有しているかを突き止めたい状況です。

このフェーズの目的は、まず**主要な会社が所有するすべての companies**を取得し、次にこれらの会社が保有する**assets**をすべて把握することです。これを行うために、以下を実施します:

1. 主要会社の買収先を見つける — これでスコープ内の会社が分かります。
2. 各会社の ASN（ある場合）を見つける — これで各会社が所有する IP ranges が分かります。
3. reverse whois を使って、最初のエントリに関連する他のエントリ（組織名、ドメインなど）を検索する（再帰的に行うことも可能）。
4. shodan の `org` や `ssl` フィルタのような他の手法を使って他の資産を検索する（`ssl` トリックは再帰的に行うことができます）。

### **買収**

まず、どの**他の会社が主要会社に所有されているか**を把握する必要があります。\
一つの方法は [https://www.crunchbase.com/](https://www.crunchbase.com) にアクセスし、**主要会社**を**検索**して、"**acquisitions**" を**クリック**することです。そこに主要会社が買収した他の会社が表示されます。\
別の方法は主要会社の **Wikipedia** ページを確認して **acquisitions** を探すことです。\
上場企業の場合は **SEC/EDGAR filings**、**investor relations** ページ、または各国の商業登記（例: 英国の **Companies House**）を確認してください。\
グローバルな企業ツリーや子会社については **OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/)) や **GLEIF LEI** データベース ([https://www.gleif.org/](https://www.gleif.org/)) を試してみてください。

> ここまででスコープ内の全ての会社が分かっているはずです。次にこれらの会社の資産をどのように見つけるかを考えましょう。

### **ASNs**

an autonomous system number（**ASN**）は、Internet Assigned Numbers Authority (IANA) によって **autonomous system（AS）** に割り当てられる**一意の番号**です。\
**AS** は外部ネットワークへのアクセスに関して明確に定義されたポリシーを持つ **IP addresses のブロック**で構成され、通常は単一の組織によって管理されますが、複数のオペレーターで構成される場合もあります。

会社が ASN を割り当てられているかを調べると、その会社の **IP ranges** を特定できます。スコープ内のすべての **hosts** に対して **vulnerability test** を実施したり、これらの IP 上にある **domains** を探すのに有用です。\
https://bgp.he.net/、https://bgpview.io/、または https://ipinfo.io/ で会社名、IP、またはドメインで **検索**できます。\
**会社の所在地域によっては次のリンクが追加データ収集に有用です:** [**AFRINIC**](https://www.afrinic.net) **(Africa),** [**Arin**](https://www.arin.net/about/welcome/region/)**(North America),** [**APNIC**](https://www.apnic.net) **(Asia),** [**LACNIC**](https://www.lacnic.net) **(Latin America),** [**RIPE NCC**](https://www.ripe.net) **(Europe).** とにかく、おそらく最初のリンクですでに役立つ情報（IP ranges と Whois）が得られるでしょう。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、 [**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration は scan の最後に ASNs を自動的に集約して要約します。
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
ドメインのIPとASNは [http://ipv4info.com/](http://ipv4info.com) で確認できます。

### **Looking for vulnerabilities**

At this point we know **all the assets inside the scope**, so if you are allowed you could launch some **vulnerability scanner** (Nessus, OpenVAS, [**Nuclei**](https://github.com/projectdiscovery/nuclei)) over all the hosts.\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye のようなサービスを使って開いているポートを見つけ、見つかった内容に応じて本書を参照して各種サービスの pentest を行ってください。\
**Also, It could be worth it to mention that you can also prepare some** default username **and** passwords **lists and try to** bruteforce services with [https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray).

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
これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
You can also use a online tool for this info: [http://ptrarchive.com/](http://ptrarchive.com).\
この情報にはオンラインツールも利用できます: [http://ptrarchive.com/](http://ptrarchive.com).\
For large ranges, tools like [**massdns**](https://github.com/blechschmidt/massdns) and [**dnsx**](https://github.com/projectdiscovery/dnsx) are useful to automate reverse lookups and enrichment.
大きなレンジでは、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールが、逆引きルックアップとエンリッチメントの自動化に役立ちます。

### **Reverse Whois (loop)**

Inside a **whois** you can find a lot of interesting **information** like **organisation name**, **address**, **emails**, phone numbers... But which is even more interesting is that you can find **more assets related to the company** if you perform **reverse whois lookups by any of those fields** (for example other whois registries where the same email appears).\
**whois** の中には、**organisation name**、**address**、**emails**、電話番号など多くの興味深い**information**が含まれています。しかしさらに興味深いのは、これらのフィールドのいずれかで**reverse whois lookups**を行うことで、**会社に関連するより多くの資産**を見つけられる点です（例：同じメールが現れる他のwhoisレコードなど）。\

You can use online tools like:
次のようなオンラインツールを使用できます：

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com/) - **無料**（ウェブ）、APIは有料。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com/) - **有料**
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - **有料**（**100**回のみ無料検索）
- [https://www.domainiq.com/](https://www.domainiq.com) - **有料**
- [https://securitytrails.com/](https://securitytrails.com/) - **有料**（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - **有料**（API）

You can automate this task using [**DomLink** ](https://github.com/vysecurity/DomLink)(requires a whoxy API key).\
この作業は[**DomLink**](https://github.com/vysecurity/DomLink)を使って自動化できます（whoxyのAPIキーが必要です）。\
You can also perform some automatic reverse whois discovery with [amass](https://github.com/OWASP/Amass): `amass intel -d tesla.com -whois`
また、[amass](https://github.com/OWASP/Amass)を使って逆whoisの自動探索を行うこともできます: `amass intel -d tesla.com -whois`

**Note that you can use this technique to discover more domain names every time you find a new domain.**
**新しいドメインを見つけるたびに、この手法を使ってさらに多くのドメイン名を発見できることに注意してください。**

### **Trackers**

If find the **same ID of the same tracker** in 2 different pages you can suppose that **both pages** are **managed by the same team**.\
もし2つの異なるページで**同じトラッカーの同一ID**が見つかれば、**両方のページ**が**同じチームによって管理されている**と推測できます。\
For example, if you see the same **Google Analytics ID** or the same **Adsense ID** on several pages.
例えば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**を見かけた場合などです。

There are some pages and tools that let you search by these trackers and more:
これらのトラッカーなどで検索できるページやツールがいくつかあります：

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut) (finds related sites by shared analytics/trackers)

### **Favicon**

Did you know that we can find related domains and subdomains to our target by looking for the same favicon icon hash? This is exactly what [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) tool made by [@m4ll0k2](https://twitter.com/m4ll0k2) does. Here’s how to use it:
同じfaviconアイコンのハッシュを探すことで、ターゲットに関連するドメインやサブドメインを見つけられることを知っていましたか？これは[@m4ll0k2](https://twitter.com/m4ll0k2)が作成した[ favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)がまさに行うことです。使い方は以下の通りです：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - discover domains with the same favicon icon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihash を使うと、ターゲットと同じ favicon icon hash を持つドメインを発見できます。

さらに、favicon hash を使ってテクノロジーを検索することもできます（詳細は[**この記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)参照）。つまり、もし **脆弱なバージョンの web tech の favicon の hash** を知っていれば、shodan で検索して **より多くの脆弱な箇所を見つける** ことができます：
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
ウェブサイトの **favicon hash を計算する** 方法は次のとおりです:
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

### **著作権 / 一意の文字列**

ウェブページ内で、同じ組織内の複数のウェブで共有される可能性がある**文字列**を検索します。**著作権文字列**は良い例です。次に、その文字列を**google**、他の**browsers**、あるいは**shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cron job を設定していることがよくあります。例えば：
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
to renew the all the domain certificates on the server. これは、CA が Validity time に生成時刻を設定していなくても、**certificate transparency logs で同じ会社に属するドメインを見つける**ことが可能であることを意味します。\
詳しくはこの[**writeup for more information**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)を参照してください。

Also use **certificate transparency** logs directly:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### Mail DMARC information

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) のようなウェブサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) のようなツールを使って、**同じ DMARC 情報を共有する domains と subdomain** を見つけることができます。\
他の有用なツールには [**spoofcheck**](https://github.com/BishopFox/spoofcheck) や [**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

一般的に、サブドメインを cloud providers に属する IP に割り当てたものの、後でその IP を **lose that IP address but forget about removing the DNS record** してしまうことがよくあります。したがって、単に cloud（例: Digital Ocean）で **spawning a VM** するだけで、実際にいくつかの **taking over some subdomains(s)** を行うことができます。

[**This post**](https://kmsec.uk/blog/passive-takeover/) はその事例を説明しており、**DigitalOcean に VM を spawn** し、新しいマシンの **IPv4** を取得して、Virustotal でその IPv4 を指すサブドメインレコードを **searches in Virustotal for subdomain records** するスクリプトを提案しています。

### **Other ways**

**Note that you can use this technique to discover more domain names every time you find a new domain.**

**Shodan**

既に IP 空間を所有する組織名を知っている場合、shodan でそのデータを使って検索できます: `org:"Tesla, Inc."`。見つかったホストの TLS certificate をチェックして、予期しない新しいドメインがないか確認してください。

メインのウェブページの **TLS certificate** にアクセスして **Organisation name** を取得し、その名前で **shodan** が知っているすべてのウェブページの **TLS certificates** 内を `ssl:"Tesla Motors"` のようなフィルタで検索するか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のようなツールを使うこともできます。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder) は、メインドメインに関連する **domains related** やその **subdomains** を探すツールで、非常に便利です。

**Passive DNS / Historical DNS**

Passive DNS データは、まだ解決する古い忘れられたレコードや takeover 可能なレコードを見つけるのに優れています。下記を参照してください:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **Looking for vulnerabilities**

Check for some [domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)。会社がある domain を **using some a domain** していたが所有権を **lost the ownership** している可能性があります。価格が安ければその domain を登録して、会社に通知してください。

もし assets discovery で既に見つけたものとは異なる IP を持つ **domain** を見つけたら、**basic vulnerability scan**（Nessus や OpenVAS を使用）を実行し、**nmap/masscan/shodan** を使った [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を行うべきです。どのサービスが動作しているかに応じて、**this book** にあるいくつかのトリックでそれらを "attack" することができます。\
_Note that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._

## Subdomains

> We know all the companies inside the scope, all the assets of each company and all the domains related to the companies.

見つかった各 domain の可能な限りの subdomains を見つける時です。

> [!TIP]
> Note that some of the tools and techniques to find domains can also help to find subdomains

### **DNS**

**DNS** レコードから **subdomains** を取得してみましょう。Zone Transfer も試すべきです（脆弱であれば報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

大量のサブドメインを取得する最速の方法は外部ソースを検索することです。最もよく使われる**ツール**は以下の通りです（より良い結果を得るためにAPIキーを設定してください）:

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
直接的にサブドメインの発見に特化していなくても、サブドメインの発見に役立つ**他の興味深いツール/API**がいくつかあります。例えば：

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得します
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC の無料 API**](https://jldc.me/anubis/subdomains/google.com)
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
- [**gau**](https://github.com/lc/gau)**:** 任意のdomainに対して、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawlから既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ウェブをスクレイプしてJSファイルを探し、そこからサブドメインを抽出します。
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
- [**securitytrails.com**](https://securitytrails.com/) はサブドメインとIP履歴を検索するための無料APIを提供しています
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは、**bug-bounty programs に関連するすべてのサブドメインを無料で提供しています**。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使ってアクセスすることもできますし、プロジェクトが使用するスコープ自体は [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) から参照できます。

これらのツールの多くの**比較**は以下で見つけられます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能なサブドメイン名を使ってDNSサーバを brute-force し、新しい **subdomains** を見つけてみましょう。

この操作では、次のような一般的な subdomains wordlists が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼できるDNSリゾルバのIPも必要です。信頼できるDNSリゾルバの一覧を作成するには、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) からリゾルバをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使ってフィルタリングします。あるいは [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) を使うこともできます。

DNS brute-force に最も推奨されるツールは以下です:

- [**massdns**](https://github.com/blechschmidt/massdns): これは効果的なDNS brute-force を最初に実行したツールです。非常に高速ですが、false positives を引き起こしやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1 resolverだけを使用していると思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` をラップする go で書かれたツールで、active bruteforce を使って有効なサブドメインを列挙したり、ワイルドカード処理と簡単な入出力サポートでサブドメインを解決したりできます。
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

公開情報と brute-forcing を使ってサブドメインを見つけた後、見つかったサブドメインの派生形を生成してさらに多くを発見できます。この目的に役立つツールがいくつかあります:

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを与えると、バリエーションを生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインからパーミュテーションを生成します。
- goaltdns permutations **wordlist** は [**here**](https://github.com/subfinder/goaltdns/blob/master/words.txt) で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインからpermutationsを生成します。permutations fileが指定されていない場合、gotatorは独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): subdomains permutations を生成するだけでなく、それらを解決しようと試みることもできます（ただし、前に挙げたツールを使う方が良いです）。
- altdns permutations **wordlist** は [**here**](https://github.com/infosec-au/altdns/blob/master/words.txt) から入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインのpermutations、mutations、およびalterationを行う別のツールです。このツールは結果をbrute forceします（dns wild cardはサポートしていません）。
- dmut permutations wordlist は[**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づき、指定したパターンから**新しい潜在的なサブドメイン名を生成**して、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

- [**regulator**](https://github.com/cramppet/regulator): 詳細はこの[**post**](https://cramppet.github.io/regulator/index.html)を参照してください。基本的には**発見されたサブドメイン**から**主要部分**を抽出し、それらを組み合わせてより多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常に単純だが効果的な DNS response-guided algorithm と組み合わさった subdomain brute-force fuzzer です。提供された入力データ（たとえばカスタム wordlist や過去の DNS/TLS records）を利用して、より対応する domain names を正確に合成し、DNS scan 中に収集した情報に基づいてループでさらに拡張します。
```
echo www | subzuf facebook.com
```
### **Subdomain Discovery Workflow**

私が書いたこのブログ記事をチェックしてください。ドメインからの **automate the subdomain discovery** を **Trickest workflows** を使って自動化する方法について書いており、これにより自分のコンピュータで多数のツールを手動で起動する必要がなくなります：

{{#ref}}
https://trickest.com/blog/full-subdomain-discovery-using-workflow/
{{#endref}}


{{#ref}}
https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/
{{#endref}}

### **VHosts / Virtual Hosts**

もし、サブドメインに属する **one or several web pages** を含む IP アドレスを見つけたら、IP 内のドメインを調べる **OSINT sources** を使ってその IP にある他のサブドメインを探すか、あるいはその IP に対して **brute-forcing VHost domain names in that IP** を試すことができます。

#### OSINT

いくつかの **VHosts in IPs using** は [**HostHunter**](https://github.com/SpiderLabs/HostHunter) や他の APIs で見つけることができます。

**Brute Force**

もし、あるサブドメインがウェブサーバに隠されている疑いがあるなら、brute force を試みることができます：

When the **IP がホスト名にリダイレクトされる** (name-based vhosts), fuzz the `Host` header directly and let ffuf **auto-calibrate** to highlight responses that differ from the default vhost:
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
> この手法では、internal/hidden endpoints にアクセスできることさえあります。

### **CORS Brute Force**

場合によっては、有効な domain/subdomain が _**Origin**_ ヘッダに設定されている場合にのみ、ページが _**Access-Control-Allow-Origin**_ ヘッダを返すことがあります。こうした状況では、この挙動を悪用して新しい **subdomains** を**発見**できます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **Buckets Brute Force**

サブドメインを探す際は、そのサブドメインがいずれかのタイプのバケットを指しているかどうかに注意し、そうであれば [**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点でスコープ内のすべてのドメインが把握できているはずなので、[**brute force possible bucket names and check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html) を試してみてください。

### **監視**

ドメインの新しい **subdomains** が作成されているかどうかは、Certificate Transparency Logs を監視することで確認できます。これは [**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py) が行うものです。

### **脆弱性の探索**

可能な [**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover) を確認してください。\
もし **subdomain** が何らかの **S3 bucket** を指している場合、[**check the permissions**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

もし資産発見で既に見つけたものと異なるIPを持つ **subdomain with an IP different** を発見したら、Nessus や OpenVAS を使った **basic vulnerability scan** と、**nmap/masscan/shodan** を用いた [**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行してください。稼働しているサービスに応じて、本書中のそれらを「攻撃」するためのトリックが見つかる場合があります。\
_ただし、サブドメインがクライアントの管理外の IP 上にホストされていることがあり、その場合はスコープ外となるので注意してください。_

## IPs

初期段階でいくつかの IP レンジ、ドメイン、および subdomains を見つけているかもしれません。\
これらのレンジとドメイン/ subdomains（DNS クエリ）からすべての IP を収集する時です。

以下の無料 API サービスを利用すると、ドメインや subdomains が過去に使用していた IP も見つけられます。これらの IP はまだクライアント所有である可能性があり（そして [**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md) を見つけられることがあります）

- [**https://securitytrails.com/**](https://securitytrails.com/)

特定の IP アドレスを指すドメインを調べるには、ツール [**hakip2host**](https://github.com/hakluke/hakip2host) も利用できます。

### **脆弱性の探索**

CDN に属さないすべての IP をポートスキャンしてください（CDN 内ではほとんど有益なものは見つからない可能性が高いです）。発見された稼働サービスから脆弱性を見つけられる場合があります。

ホストのスキャン方法については [**guide**](../pentesting-network/index.html) を参照してください。

## Web servers hunting

> 我々は対象の企業とその資産をすべて見つけ、スコープ内の IP レンジ、ドメイン、subdomains を把握しました。次は web サーバを検索する段階です。

前のステップですでに発見した IP とドメインの recon を行っているはずなので、可能性のある web サーバは既にほとんど見つかっているかもしれません。しかしまだ見つかっていない場合は、ここでスコープ内の web サーバを探すための高速なトリックをいくつか紹介します。

これは web apps discovery 向けの手法なので、スコープで許可されている場合は vulnerability および port scanning も実行してください。

web サーバに関連するオープンポートを高速に発見するための masscan を使った高速な方法は [ここ](../pentesting-network/index.html#http-port-discovery) にあります。\
web サーバを探すための使いやすいツールとしては [**httprobe**](https://github.com/tomnomnom/httprobe)、[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx) などがあります。ドメインのリストを渡すだけで、ポート 80 (http) と 443 (https) に接続を試みます。さらに、他のポートを試すよう指定することもできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **Screenshots**

スコープ内に存在する**all the web servers**（会社の**IPs**や全ての**domains**および**subdomains**の中のもの）を発見したら、どこから始めればいいか**don't know where to start**ことが多いでしょう。なのでシンプルにして、まずはそれらすべてのスクリーンショットを撮ることから始めます。**main page**を**taking a look**するだけで、より**prone**に**vulnerable**になりやすい**weird**なエンドポイントを見つけられることがあります。

提案した作業を行うには [**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness), [**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot), [**Aquatone**](https://github.com/michenriksen/aquatone), [**Shutter**](https://shutter-project.org/downloads/third-party-packages/), [**Gowitness**](https://github.com/sensepost/gowitness) または [**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**

さらに、すべての**screenshots**に対して [**eyeballer**](https://github.com/BishopFox/eyeballer) を実行して、**what's likely to contain vulnerabilities**なものとそうでないものを識別することができます。

## Public Cloud Assets

会社に属する可能性のある cloud assets を見つけるには、まずその会社を特定する**キーワードのリスト**を作るべきです。例えば crypto 会社であれば `"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">` のような単語を使います。

また、**common words used in buckets** の wordlists が必要になります:

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

その単語群を使って**permutations**を生成するべきです（詳しくは [**Second Round DNS Brute-Force**](#second-dns-bruteforce-round) を参照）。

得られた wordlists を使って [**cloud_enum**](https://github.com/initstring/cloud_enum)**,** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**,** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **や** [**S3Scanner**](https://github.com/sa7mon/S3Scanner) **などのツールを利用できます。**

Cloud Assets を探す際は **look for more than just buckets in AWS** という点を忘れないでください。

### **Looking for vulnerabilities**

もし **open buckets or cloud functions exposed** のようなものを見つけたら、それらに**アクセス**して何ができるか、どう悪用できるかを試すべきです。

## Emails

スコープ内の **domains** と **subdomains** があれば、基本的に **emails** を検索するために必要なものは揃っています。以下は私が会社の emails を見つけるのに最もよく使う **APIs** と **tools** です:

- [**theHarvester**](https://github.com/laramies/theHarvester) - with APIs
- API of [**https://hunter.io/**](https://hunter.io/) (free version)
- API of [**https://app.snov.io/**](https://app.snov.io/) (free version)
- API of [**https://minelead.io/**](https://minelead.io/) (free version)

### **Looking for vulnerabilities**

Emails は後で **web logins and auth services**（例: SSH）を brute-force する際に役立ちます。また、phishings にも必要です。さらに、これらの APIs はそのメールの背後にいる人物についての追加情報を提供することが多く、phishing キャンペーンに有用です。

## Credential Leaks

**domains,** **subdomains,** および **emails** がわかれば、過去にそのメールに属する認証情報が leak していないかを探し始めることができます:

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

もし **valid leaked** な認証情報を見つけたら、これは非常に簡単な勝利になります。

## Secrets Leaks

Credential leaks は企業のハックによって **sensitive information** が漏洩・売買されたケースに関係します。しかし、企業はそれ以外の種類の leaks によって影響を受けることもあります。これらの情報は上記のデータベースに載っていないことがあります。

### Github Leaks

Credentials や APIs は、会社の**public repositories**やその会社に所属する**users**の public repos に漏洩していることがあります。\
[**Leakos**](https://github.com/carlospolop/Leakos) を使うと、ある **organization** やその **developers** の**public repos**を一括で download し、[**gitleaks**](https://github.com/zricethezav/gitleaks) を自動で実行できます。

**Leakos** はまた、渡された URL のテキストに対して **gitleaks** を実行するためにも使えます。なぜなら時折 **web pages** も secrets を含んでいることがあるからです。

#### Github Dorks

攻撃対象の organization 内で検索できる可能性のある **github dorks** については次の**page**も確認してください:


{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pastes Leaks

時々攻撃者や従業員が **company content** を paste サイトに公開することがあります。これは必ずしも **sensitive information** を含むとは限りませんが、検索する価値は高いです。\
80 を超える paste サイトを同時に検索できるツール [**Pastos**](https://github.com/carlospolop/Pastos) を使うことができます。

### Google Dorks

古くからあるが有用な google dorks は、**exposed information that shouldn't be there** を見つけるのに常に役立ちます。問題は [**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) が何千もの可能なクエリを含んでおり、それらを手動で実行するのは現実的でない点です。なので、あなたのお気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) のようなツールを使ってそれらを一括で実行することができます。

_Note that the tools that expect to run all the database using the regular Google browser will never end as google will block you very very soon._

### **Looking for vulnerabilities**

もし **valid leaked** な認証情報や API tokens を見つけたら、これも非常に簡単な勝利になります。

## Public Code Vulnerabilities

会社に **open-source code** があることがわかったら、そのコードを**analyse**して脆弱性を探すことができます。

**Depending on the language** によって使用すべき **tools** は異なります:


{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

また、public repositories をスキャンできる無料サービスもあります。例えば:

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

多くの bug hunters が見つける脆弱性の**majority**は **web applications** 内にあります。ここで web application testing methodology について述べたいと思いますが、詳細は [**こちら**](../../network-services-pentesting/pentesting-web/index.html) を参照してください。

また、セクション [**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners) には特に言及しておきます。これらは非常にセンシティブな脆弱性を見つけることを期待すべきではありませんが、initial web information を得るワークフローに組み込むには便利です。

## Recapitulation

> Congratulations! At this point you have already perform **all the basic enumeration**. Yes, it's basic because a lot more enumeration can be done (will see more tricks later).

ここまでで既に**基本的な列挙作業**は完了しています。基本的としたのは、さらに多くの列挙が可能だからです（後でさらにトリックを紹介します）。

なので、あなたはすでに以下を実行しています:

1. Found all the **companies** inside the scope
2. Found all the **assets** belonging to the companies (and perform some vuln scan if in scope)
3. Found all the **domains** belonging to the companies
4. Found all the **subdomains** of the domains (any subdomain takeover?)
5. Found all the **IPs** (from and **not from CDNs**) inside the scope.
6. Found all the **web servers** and took a **screenshot** of them (anything weird worth a deeper look?)
7. Found all the **potential public cloud assets** belonging to the company.
8. **Emails**, **credentials leaks**, and **secret leaks** that could give you a **big win very easily**.
9. **Pentesting all the webs you found**

## **Full Recon Automatic Tools**

与えられたスコープに対して提案したアクションの一部を自動で実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - A little old and not updated

## **References**

- All free courses of [**@Jhaddix**](https://twitter.com/Jhaddix) like [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)

{{#include ../../banners/hacktricks-training.md}}
