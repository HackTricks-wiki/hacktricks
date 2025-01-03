# 外部リコンメソドロジー

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するすべてのものがスコープ内にあると言われており、その会社が実際に所有しているものを把握したいと思っています。

このフェーズの目標は、**主要な会社が所有するすべての会社**と、これらの会社の**資産**を取得することです。そのために、以下を行います：

1. 主要な会社の買収を見つけます。これにより、スコープ内の会社がわかります。
2. 各会社のASN（もしあれば）を見つけます。これにより、各会社が所有するIP範囲がわかります。
3. 逆whois検索を使用して、最初のものに関連する他のエントリ（組織名、ドメインなど）を検索します（これは再帰的に行うことができます）。
4. shodanの`org`および`ssl`フィルターなどの他の技術を使用して、他の資産を検索します（`ssl`トリックは再帰的に行うことができます）。

### **買収**

まず最初に、**主要な会社が所有する他の会社**を知る必要があります。\
一つのオプションは、[https://www.crunchbase.com/](https://www.crunchbase.com)を訪れ、**主要な会社**を**検索**し、**「買収」**を**クリック**することです。そこで、主要な会社によって買収された他の会社を見ることができます。\
もう一つのオプションは、主要な会社の**Wikipedia**ページを訪れ、**買収**を検索することです。

> さて、この時点でスコープ内のすべての会社を知っているはずです。彼らの資産を見つける方法を考えましょう。

### **ASNs**

自律システム番号（**ASN**）は、**インターネット割り当て番号機関（IANA）**によって**自律システム**（AS）に割り当てられた**ユニークな番号**です。\
**AS**は、外部ネットワークへのアクセスに対して明確に定義されたポリシーを持つ**IPアドレス**の**ブロック**で構成され、単一の組織によって管理されますが、複数のオペレーターで構成される場合があります。

**会社が割り当てたASN**を見つけて、その**IP範囲**を特定することは興味深いです。**スコープ内のすべてのホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメイン**を探すことが興味深いでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)で会社の**名前**、**IP**、または**ドメイン**で**検索**できます。\
**会社の地域によっては、これらのリンクがより多くのデータを収集するのに役立つかもしれません：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/) **（北アメリカ）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。とにかく、おそらくすべての**有用な情報**（IP範囲とWhois）は最初のリンクにすでに表示されています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**サブドメイン列挙は、スキャンの最後にASNを自動的に集約して要約します。
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
あなたは、[http://asnlookup.com/](http://asnlookup.com)を使用して、組織のIP範囲を見つけることができます（無料のAPIがあります）。\
ドメインのIPとASNを見つけるには、[http://ipv4info.com/](http://ipv4info.com)を使用できます。

### **脆弱性の探索**

この時点で、**スコープ内のすべての資産**を把握しているので、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS）を実行することができます。\
また、[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行するか、shodanのようなサービスを使用して**オープンポートを見つけることができ、見つけたものに応じて、この本を参照して、実行中のさまざまなサービスをペンテストする方法を確認するべきです。**\
**また、デフォルトのユーザー名**と**パスワードのリストを準備し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使用してサービスをブルートフォースすることも価値があるかもしれません。**

## ドメイン

> スコープ内のすべての企業とその資産を把握しているので、スコープ内のドメインを見つける時です。

_次に提案する技術では、サブドメインも見つけることができ、その情報は過小評価すべきではありません。_

まず、各企業の**主要ドメイン**を探すべきです。例えば、_Tesla Inc._の主要ドメインは_tesla.com_になります。

### **逆引きDNS**

ドメインのすべてのIP範囲を見つけたので、それらの**IPに対して逆引きDNSルックアップを実行して、スコープ内のさらに多くのドメインを見つけることができます。**被害者のDNSサーバーまたは一般的なDNSサーバー（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
この機能を利用するには、管理者が手動でPTRを有効にする必要があります。\
この情報のためにオンラインツールを使用することもできます: [http://ptrarchive.com/](http://ptrarchive.com)

### **リバースWhois（ループ）**

**whois**の中には、**組織名**、**住所**、**メール**、電話番号などの多くの興味深い**情報**が含まれています... しかし、さらに興味深いのは、これらのフィールドのいずれかで**リバースWhois検索**を行うと、**会社に関連する他の資産**を見つけることができることです（例えば、同じメールが表示される他のwhoisレジストリ）。\
次のようなオンラインツールを使用できます:

- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**のウェブ、APIは無料ではありません。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回の無料**検索のみ）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません

[**DomLink** ](https://github.com/vysecurity/DomLink)を使用してこのタスクを自動化できます（whoxy APIキーが必要です）。\
また、[amass](https://github.com/OWASP/Amass)を使用して自動リバースWhois発見を行うこともできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この技術を使用してさらに多くのドメイン名を発見できることに注意してください。**

### **トラッカー**

異なる2つのページで**同じトラッカーの同じID**を見つけた場合、**両方のページ**が**同じチームによって管理されている**と推測できます。\
例えば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**を見た場合です。

これらのトラッカーやその他の情報を検索できるページやツールがあります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)

### **ファビコン**

同じファビコンアイコンのハッシュを探すことで、ターゲットに関連するドメインやサブドメインを見つけることができることをご存知でしたか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2)によって作成されたツール[favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)が行うことです。使用方法は次のとおりです:
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じfaviconアイコンハッシュを持つドメインを発見する](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashはターゲットと同じfaviconアイコンハッシュを持つドメインを発見することを可能にします。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、faviconハッシュを使用して技術を検索することもできます。つまり、**脆弱なバージョンのウェブ技術のfaviconのハッシュ**を知っていれば、shodanで検索して**より多くの脆弱な場所を見つける**ことができます。
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
これはウェブの**ファビコンハッシュ**を計算する方法です：
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
### **著作権 / ユニークな文字列**

ウェブページ内で、**同じ組織内の異なるウェブサイトで共有される可能性のある文字列**を検索します。**著作権文字列**は良い例かもしれません。その後、**google**、他の**ブラウザ**、または**shodan**でその文字列を検索します: `shodan search http.html:"Copyright string"`

### **CRT 時間**

cronジョブを持つことは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべてのドメイン証明書を更新することです。これは、これに使用されるCAが有効期限内に生成された時間を設定していなくても、**証明書透明性ログで同じ会社に属するドメインを見つけることが可能である**ことを意味します。\
この[**詳細情報のための書き込み**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)をチェックしてください。

### Mail DMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなウェブサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使用して、**同じDMARC情報を共有するドメインとサブドメインを見つけることができます**。

### **パッシブテイクオーバー**

人々がクラウドプロバイダーに属するIPにサブドメインを割り当て、ある時点で**そのIPアドレスを失い、DNSレコードを削除するのを忘れる**ことが一般的であるようです。したがって、クラウド（Digital Oceanなど）で**VMを生成する**だけで、実際に**いくつかのサブドメインを取得する**ことになります。

[**この投稿**](https://kmsec.uk/blog/passive-takeover/)はそのストーリーを説明し、**DigitalOceanでVMを生成し**、**新しいマシンの**IPv4を**取得し**、**それにポイントするサブドメインレコードをVirustotalで検索する**スクリプトを提案しています。

### **その他の方法**

**新しいドメインを見つけるたびに、この技術を使用してさらに多くのドメイン名を発見できることに注意してください。**

**Shodan**

IPスペースを所有する組織の名前がわかっているので、そのデータを使用してshodanで検索できます: `org:"Tesla, Inc."` 見つかったホストを確認して、TLS証明書に新しい予期しないドメインがないか確認してください。

メインウェブページの**TLS証明書**にアクセスし、**組織名**を取得し、その名前を持つ**shodan**で知られているすべてのウェブページの**TLS証明書**内で検索できます。フィルター: `ssl:"Tesla Motors"`を使用するか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使用します。

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)は、メインドメインに関連する**ドメイン**とその**サブドメイン**を探すツールで、非常に素晴らしいです。

### **脆弱性の検索**

いくつかの[ドメインテイクオーバー](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)を確認してください。ある会社が**ドメインを使用しているが、所有権を失った**可能性があります。十分に安価であれば、それを登録し、会社に知らせてください。

もし**資産発見で既に見つけたIPとは異なるIPを持つドメイン**を見つけた場合、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**を使用したいくつかの[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行するべきです。実行中のサービスに応じて、**この本で「攻撃」するためのいくつかのトリックを見つけることができます**。\
&#xNAN;_&#x4E;ote that sometimes the domain is hosted inside an IP that is not controlled by the client, so it's not in the scope, be careful._



## サブドメイン

> スコープ内のすべての会社、各会社のすべての資産、および会社に関連するすべてのドメインを知っています。

見つかった各ドメインのすべての可能なサブドメインを見つける時が来ました。

> [!TIP]
> ドメインを見つけるためのいくつかのツールや技術は、サブドメインを見つけるのにも役立つことに注意してください。

### **DNS**

**DNS**レコードから**サブドメイン**を取得しようとしましょう。**ゾーン転送**も試みるべきです（脆弱な場合は報告する必要があります）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多くのサブドメインを迅速に取得する最も効果的な方法は、外部ソースで検索することです。最も使用される**ツール**は以下の通りです（より良い結果を得るためにAPIキーを設定してください）：

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
他にも**興味深いツール/API**があり、サブドメインの発見に特化していなくてもサブドメインを見つけるのに役立つものがあります。例えば：

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io)を使用してサブドメインを取得します。
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
- [**JLDC無料API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
- [**RapidDNS**](https://rapiddns.io) 無料API
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
- [**gau**](https://github.com/lc/gau)**:** 指定されたドメインに対して、AlienVaultのOpen Threat Exchange、Wayback Machine、およびCommon Crawlから既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): これらはウェブをスクレイピングしてJSファイルを探し、そこからサブドメインを抽出します。
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
- [**Censysサブドメインファインダー**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
- [**securitytrails.com**](https://securitytrails.com/) は、サブドメインとIP履歴を検索するための無料APIを提供しています
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは、**バグバウンティプログラムに関連するすべてのサブドメインを無料で提供**しています。このデータには、[chaospy](https://github.com/dr-0x0x/chaospy)を使用してアクセスすることもできますし、このプロジェクトで使用されているスコープにアクセスすることもできます [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

これらのツールの**比較**はここで見つけることができます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNSブルートフォース**

可能なサブドメイン名を使用してDNSサーバーをブルートフォースして新しい**サブドメイン**を見つけてみましょう。

このアクションには、いくつかの**一般的なサブドメインのワードリスト**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、良好なDNSリゾルバのIPも必要です。信頼できるDNSリゾルバのリストを生成するために、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)からリゾルバをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator)を使用してフィルタリングすることができます。または、[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)を使用することもできます。

DNSブルートフォースに最も推奨されるツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): これは効果的なDNSブルートフォースを実行した最初のツールです。非常に高速ですが、誤検知が発生しやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
- [**gobuster**](https://github.com/OJ/gobuster): これは1つのリゾルバを使用していると思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、`massdns` のラッパーで、Go で書かれており、アクティブブルートフォースを使用して有効なサブドメインを列挙することができ、ワイルドカード処理と簡単な入出力サポートを使用してサブドメインを解決することができます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
- [**puredns**](https://github.com/d3mondev/puredns): それは `massdns` も使用します。
```
puredns bruteforce all.txt domain.com
```
- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は、asyncioを使用してドメイン名を非同期にブルートフォースします。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二のDNSブルートフォースラウンド

オープンソースとブルートフォースを使用してサブドメインを見つけた後、見つかったサブドメインの変種を生成してさらに多くを見つけることができます。この目的のためにいくつかのツールが役立ちます：

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを与えると、順列を生成します。
```bash
cat subdomains.txt | dnsgen -
```
- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを与えると、順列を生成します。
- **wordlist** の goaltdns 順列は [**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt) で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定して順列を生成します。順列ファイルが指定されていない場合、gotatorは独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの順列を生成するだけでなく、それらを解決しようとすることもできます（ただし、前述のツールを使用する方が良いです）。
- altdnsの順列の**wordlist**は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの順列、変異、変更を行うための別のツールです。このツールは結果をブルートフォースします（DNSワイルドカードはサポートしていません）。
- dmutの順列ワードリストは[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から取得できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
- [**alterx**](https://github.com/projectdiscovery/alterx)**:** 指定されたパターンに基づいて、ドメインに基づいて**新しい潜在的なサブドメイン名を生成**し、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

- [**regulator**](https://github.com/cramppet/regulator): 詳細についてはこの[**投稿**](https://cramppet.github.io/regulator/index.html)を読んでくださいが、基本的には**発見されたサブドメイン**の**主要部分**を取得し、それらを混ぜてより多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルで効果的なDNS応答ガイドアルゴリズムと組み合わされたサブドメインブルートフォースファズァです。提供された入力データセット（カスタマイズされたワードリストや過去のDNS/TLSレコードなど）を利用して、より対応するドメイン名を正確に合成し、DNSスキャン中に収集した情報に基づいてさらにループで拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン発見ワークフロー**

私が書いたブログ記事をチェックしてください。**Trickest workflows**を使用してドメインから**サブドメインの発見を自動化する**方法について説明しています。これにより、コンピュータでツールを手動で起動する必要がなくなります。

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/" %}

### **VHosts / バーチャルホスト**

サブドメインに属する**1つまたは複数のウェブページ**を含むIPアドレスを見つけた場合、そのIP内の**ウェブがある他のサブドメインを見つける**ために、**OSINTソース**でIP内のドメインを探すか、**そのIP内のVHostドメイン名をブルートフォースする**ことを試みることができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPIを使用してIP内のいくつかのVHostsを見つけることができます**。

**ブルートフォース**

ウェブサーバーに隠されたサブドメインがあると疑う場合は、それをブルートフォースしてみることができます：
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
> [!NOTE]
> この技術を使用すると、内部/隠れたエンドポイントにアクセスできる場合があります。

### **CORS ブルートフォース**

時々、_**Origin**_ ヘッダーに有効なドメイン/サブドメインが設定されている場合にのみ、_**Access-Control-Allow-Origin**_ ヘッダーを返すページを見つけることがあります。これらのシナリオでは、この動作を悪用して新しい **サブドメイン** を **発見** することができます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **バケットブルートフォース**

**サブドメイン**を探しているときは、**バケット**に**ポイント**しているかどうかに注意し、その場合は[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)**してください。**\
また、この時点でスコープ内のすべてのドメインを把握しているので、[**可能なバケット名をブルートフォースし、権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)してください。

### **モニタリング**

**新しいサブドメイン**が作成されたかどうかを**Certificate Transparency**ログを監視することで**モニタリング**できます。[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)がそれを行います。

### **脆弱性の検索**

可能な[**サブドメインテイクオーバー**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)を確認してください。\
もし**サブドメイン**が**S3バケット**に**ポイント**している場合は、[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/)してください。

もし**資産発見**で見つけたものとは異なるIPを持つ**サブドメイン**を見つけた場合は、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と、**ポートスキャン**（nmap/masscan/shodanを使用）を実施するべきです。実行中のサービスに応じて、**この本の中で「攻撃」するためのいくつかのトリックを見つけることができます**。\
&#xNAN;_&#x4E;oteとして、時々サブドメインがクライアントによって制御されていないIP内にホストされていることがあるため、スコープ外であることに注意してください。_

## IPs

初期段階で**いくつかのIP範囲、ドメイン、サブドメイン**を**見つけたかもしれません**。\
これらの範囲から**すべてのIPを収集する**時です。また、**ドメイン/サブドメイン（DNSクエリ）**のために。

以下の**無料API**のサービスを使用すると、**ドメインとサブドメインによって使用された以前のIP**も見つけることができます。これらのIPはまだクライアントによって所有されている可能性があり、[**CloudFlareのバイパス**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つける手助けになるかもしれません。

- [**https://securitytrails.com/**](https://securitytrails.com/)

特定のIPアドレスを指すドメインを確認するには、[**hakip2host**](https://github.com/hakluke/hakip2host)というツールを使用できます。

### **脆弱性の検索**

**CDNに属さないすべてのIPをポートスキャン**してください（そこでは興味深いものは見つからない可能性が高いです）。発見された実行中のサービスでは、**脆弱性を見つけることができるかもしれません**。

**ホストをスキャンする方法に関する**[**ガイド**](../pentesting-network/)を見つけてください。

## ウェブサーバーハンティング

> すべての企業とその資産を見つけ、スコープ内のIP範囲、ドメイン、サブドメインを把握しました。ウェブサーバーを探す時です。

前のステップで、**発見したIPとドメインのリコン**をすでに実施しているかもしれませんので、**すべての可能なウェブサーバーをすでに見つけているかもしれません**。しかし、もし見つけていない場合は、スコープ内のウェブサーバーを探すための**迅速なトリック**を見ていきます。

これは**ウェブアプリの発見**に**特化**しているため、**脆弱性**と**ポートスキャン**も実施するべきです（**スコープによって許可されている場合**）。

**ウェブ**サーバーに関連する**オープンポート**を発見するための**迅速な方法**は、[**masscan**を使用することができます](../pentesting-network/#http-port-discovery)。\
ウェブサーバーを探すためのもう一つの便利なツールは、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)および[**httpx**](https://github.com/projectdiscovery/httpx)です。ドメインのリストを渡すだけで、ポート80（http）と443（https）に接続を試みます。さらに、他のポートを試すように指示することもできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべてのウェブサーバー**（会社の**IP**やすべての**ドメイン**、**サブドメイン**の中で）を発見したので、どこから始めればよいかわからないかもしれません。そこで、シンプルにして、すべてのスクリーンショットを撮ることから始めましょう。**メインページ**を**見るだけで**、**脆弱性**がある可能性の高い**奇妙な**エンドポイントを見つけることができます。

提案されたアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使用して、すべての**スクリーンショット**を確認し、**脆弱性を含む可能性が高いもの**とそうでないものを教えてもらうことができます。

## パブリッククラウド資産

会社に属する潜在的なクラウド資産を見つけるには、**その会社を特定するキーワードのリストから始めるべきです**。たとえば、暗号会社の場合、次のような単語を使用することがあります：`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`。

また、**バケットで使用される一般的な単語のワードリスト**も必要です：

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使用して**順列**を生成する必要があります（詳細については[**第二ラウンドDNSブルートフォース**](./#second-dns-bruteforce-round)を確認してください）。

生成されたワードリストを使用して、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、** [**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、** [**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**を使用できます。**

クラウド資産を探す際には、**AWSのバケット以上のものを探すべきです**。

### **脆弱性の検索**

**オープンバケットや公開されたクラウド機能**などを見つけた場合は、それに**アクセスして**、何を提供しているのか、どのように悪用できるかを確認するべきです。

## メール

スコープ内の**ドメイン**と**サブドメイン**を持っているので、**メールを検索するために必要なすべてのもの**があります。これらは、会社のメールを見つけるために私が最も効果的だと感じた**API**と**ツール**です：

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の検索**

メールは、**ウェブログインや認証サービス**（SSHなど）の**ブルートフォース**に役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIは、メールの背後にいる**人物に関するさらなる情報**を提供してくれます。これはフィッシングキャンペーンに役立ちます。

## 資格情報の漏洩

**ドメイン、** **サブドメイン、** **メール**を持っているので、過去に漏洩したそのメールに関連する資格情報を探し始めることができます：

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の検索**

**有効な漏洩した**資格情報を見つけた場合、これは非常に簡単な勝利です。

## 秘密の漏洩

資格情報の漏洩は、**機密情報が漏洩して販売された**企業のハッキングに関連しています。ただし、企業は、これらのデータベースに情報がない**他の漏洩**の影響を受ける可能性があります：

### Githubの漏洩

資格情報やAPIは、**会社**やその**ユーザー**の**公開リポジトリ**で漏洩する可能性があります。\
**Leakos**という**ツール**を使用して、**組織**とその**開発者**のすべての**公開リポジトリ**を**ダウンロード**し、自動的に[**gitleaks**](https://github.com/zricethezav/gitleaks)を実行できます。

**Leakos**は、提供された**URLに渡された**すべての**テキスト**に対して**gitleaks**を実行するためにも使用できます。時には**ウェブページにも秘密が含まれている**ことがあります。

#### Github Dorks

攻撃している組織で検索できる潜在的な**github dorks**については、この**ページ**も確認してください：

{{#ref}}
github-leaked-secrets.md
{{#endref}}

### Pasteの漏洩

時には攻撃者や単なる従業員が**会社のコンテンツをペーストサイトに公開**します。これには**機密情報**が含まれている場合もあれば、含まれていない場合もありますが、検索するのは非常に興味深いです。\
[**Pastos**](https://github.com/carlospolop/Pastos)というツールを使用して、80以上のペーストサイトを同時に検索できます。

### Google Dorks

古いですが金のようなGoogle Dorksは、**そこにあるべきでない情報を見つける**のに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に、手動で実行できない**数千**の可能なクエリが含まれていることです。したがって、お気に入りの10個を取得するか、[**Gorks**](https://github.com/carlospolop/Gorks)のような**ツールを使用してすべてを実行**することができます。

_すべてのデータベースを通常のGoogleブラウザを使用して実行しようとするツールは、非常に早くGoogleにブロックされるため、決して終わらないことに注意してください。_

### **脆弱性の検索**

**有効な漏洩した**資格情報やAPIトークンを見つけた場合、これは非常に簡単な勝利です。

## パブリックコードの脆弱性

会社が**オープンソースコード**を持っていることがわかった場合、それを**分析**し、**脆弱性**を探すことができます。

**言語によって**異なる**ツール**を使用できます：

{{#ref}}
../../network-services-pentesting/pentesting-web/code-review-tools.md
{{#endref}}

また、**公開リポジトリをスキャン**するための無料サービスもあります：

- [**Snyk**](https://app.snyk.io/)

## [**ウェブペンテスティング手法**](../../network-services-pentesting/pentesting-web/)

**バグハンター**によって見つけられる**脆弱性の大部分**は**ウェブアプリケーション**内に存在するため、この時点で**ウェブアプリケーションテスト手法**について話したいと思います。詳細は[**こちらで確認できます**](../../network-services-pentesting/pentesting-web/)。

また、[**オープンソースツールのウェブ自動スキャナー**](../../network-services-pentesting/pentesting-web/#automatic-scanners)のセクションにも特別な言及をしたいと思います。非常に機密性の高い脆弱性を見つけることを期待すべきではありませんが、**初期のウェブ情報を得るためのワークフローに実装するのに役立ちます。**

## 再確認

> おめでとうございます！この時点で、**すべての基本的な列挙**をすでに実行しています。はい、これは基本的なもので、さらに多くの列挙が可能です（後でさらにトリックを見ていきます）。

したがって、すでに次のことを行っています：

1. スコープ内の**すべての会社**を見つけた
2. 会社に属する**すべての資産**を見つけた（スコープ内で脆弱性スキャンを実行）
3. 会社に属する**すべてのドメイン**を見つけた
4. ドメインの**すべてのサブドメイン**を見つけた（サブドメインの乗っ取りはありますか？）
5. スコープ内の**すべてのIP**（CDNからのものとそうでないもの）を見つけた。
6. **すべてのウェブサーバー**を見つけ、**スクリーンショット**を撮った（深く見る価値のある奇妙なものはありますか？）
7. 会社に属する**すべての潜在的なパブリッククラウド資産**を見つけた。
8. **メール**、**資格情報の漏洩**、および**秘密の漏洩**が、**非常に簡単に大きな勝利をもたらす可能性がある**。
9. **見つけたすべてのウェブをペンテストする**

## **フルリコン自動ツール**

特定のスコープに対して提案されたアクションの一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **参考文献**

- [**@Jhaddix**](https://twitter.com/Jhaddix)のすべての無料コース、例えば[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)

{{#include ../../banners/hacktricks-training.md}}
