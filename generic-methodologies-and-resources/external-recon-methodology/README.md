# 外部リコンメソドロジー

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**登録**する、ハッカーによって作られたプレミアムな**バグバウンティプラットフォーム**！今日[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**のバウンティを獲得し始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 資産の発見

> ある会社に属するすべてがスコープ内にあると言われ、その会社が実際に所有しているものを把握したいと思っています。

このフェーズの目的は、**主要会社によって所有されているすべての会社**を取得し、その後これらの会社の**資産**を取得することです。これを行うために、以下のことを行います:

1. 主要会社の買収を見つけることで、スコープ内の会社を知ることができます。
2. 各会社のASN（もしあれば）を見つけることで、各会社が所有するIP範囲を知ることができます。
3. 逆Whois検索を使用して、最初のもの（組織名、ドメインなど）に関連する他のエントリを検索します（これは再帰的に行うことができます）。
4. 他の資産を検索するためにshodanの`org`や`ssl`フィルターなどの他のテクニックを使用します（`ssl`のトリックは再帰的に行うことができます）。

### **買収**

まず、**主要会社によって所有されている他の会社**を知る必要があります。\
一つの選択肢は、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**主要会社**を**検索**し、"**acquisitions**"を**クリック**することです。そこでは、主要な会社によって買収された他の会社を見ることができます。\
もう一つの選択肢は、主要会社の**Wikipedia**ページを訪れて**買収**を検索することです。

> さて、この時点でスコープ内のすべての会社を知っているはずです。彼らの資産を見つける方法を見てみましょう。

### **ASNs**

自律システム番号（**ASN**）は、**インターネット割り当て番号機関（IANA）**によって自律システム（AS）に割り当てられた**ユニークな番号**です。\
**AS**は、外部ネットワークへのアクセスポリシーが明確に定義されており、単一の組織によって管理されていますが、複数のオペレーターで構成される可能性がある**IPアドレスのブロック**で構成されています。

**会社がASNを割り当てられているか**を見つけることは興味深いことです。これにより、その**IP範囲**を見つけることができます。スコープ内のすべての**ホスト**に対して**脆弱性テスト**を実行し、これらのIP内の**ドメイン**を**探す**ことが興味深いでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)で会社の**名前**、**IP**、または**ドメイン**で**検索**できます。\
**会社の地域によっては、次のリンクがデータ収集に役立つ可能性があります:** [**AFRINIC**](https://www.afrinic.net) **(アフリカ),** [**Arin**](https://www.arin.net/about/welcome/region/)**(北アメリカ),** [**APNIC**](https://www.apnic.net) **(アジア),** [**LACNIC**](https://www.lacnic.net) **(ラテンアメリカ),** [**RIPE NCC**](https://www.ripe.net) **(ヨーロッパ)。とにかく、おそらくすべての**有用な情報**（IP範囲とWhois）**は既に最初のリンクに表示されています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**サブドメイン列挙は、スキャンの終了時に自動的にASNを集約し、要約します。
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
組織のIP範囲も [http://asnlookup.com/](http://asnlookup.com) を使用して見つけることができます（無料APIがあります）。\
ドメインのIPとASNは [http://ipv4info.com/](http://ipv4info.com) を使用して見つけることができます。

### **脆弱性を探す**

この時点で、**スコープ内のすべての資産を知っています**ので、許可があれば、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS）を起動することができます。\
また、[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行するか、shodan のようなサービスを使用して**オープンポートを見つけ、見つかったものに応じて、この本でいくつかの可能なサービスのペネトレーションテストの方法を確認する必要があります**。\
**また、いくつかの** デフォルトのユーザー名 **と** パスワード **のリストを準備し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使用してサービスを** ブルートフォースする価値があるかもしれません。

## ドメイン

> スコープ内のすべての会社とその資産を知っているので、スコープ内のドメインを見つける時が来ました。

_次に提案される技術ではサブドメインも見つけることができ、その情報を過小評価してはいけません。_

まず、各会社の**メインドメイン**を探すべきです。例えば、_Tesla Inc._ の場合は _tesla.com_ になります。

### **リバースDNS**

ドメインのすべてのIP範囲を見つけたので、それらの**IPに対してリバースDNSルックアップを実行して、スコープ内のより多くのドメインを見つける**ことができます。被害者のDNSサーバーまたはよく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
この機能を利用するには、管理者がPTRを手動で有効にする必要があります。
また、この情報についてはオンラインツールを使用することもできます: [http://ptrarchive.com/](http://ptrarchive.com)

### **逆Whois (ループ)**

**whois**の中には、**組織名**、**住所**、**メールアドレス**、電話番号などの多くの興味深い**情報**が見つかります。しかし、さらに興味深いのは、これらのフィールドのいずれかで**逆Whois検索を実行することで、会社に関連する**より多くの資産を見つけることができることです（例えば、同じメールアドレスが表示される他のwhoisレジストリ）。\
以下のオンラインツールを使用できます:

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
* [https://www.whoxy.com/](https://www.whoxy.com) - **無料**ウェブ, APIは無料ではありません。
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 無料ではありません
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回の無料**検索のみ）
* [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません

このタスクを自動化するには、[**DomLink**](https://github.com/vysecurity/DomLink)（whoxy APIキーが必要）を使用できます。\
また、[amass](https://github.com/OWASP/Amass)を使用して自動的に逆Whois検索を行うこともできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この技術を使用してさらに多くのドメイン名を発見できることに注意してください。**

### **トラッカー**

2つの異なるページで**同じトラッカーの同じID**を見つけた場合、**両方のページ**が**同じチームによって管理されている**と推測できます。\
例えば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**を見る場合です。

これらのトラッカーを検索できるページやツールがいくつかあります:

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **ファビコン**

同じファビコンアイコンのハッシュを探すことで、ターゲットに関連するドメインやサブドメインを見つけることができることをご存知ですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2)が作成した[favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py)ツールが行うことです。使い方は次のとおりです：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
```markdown
![favihash - 同じファビコンアイコンハッシュを持つドメインを発見する](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使用すると、ターゲットと同じファビコンアイコンハッシュを持つドメインを発見できます。

さらに、[**このブログ投稿**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、ファビコンハッシュを使用してテクノロジーを検索することもできます。つまり、**脆弱なバージョンのウェブテクノロジーのファビコンのハッシュ**を知っていれば、shodanで検索し、**より多くの脆弱な場所を見つける**ことができます：
```
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
この方法でウェブの**faviconハッシュを計算**できます：
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

同じ組織内の異なるウェブサイトで**共有される可能性のある文字列**をウェブページ内で検索します。**著作権文字列**は良い例です。その文字列を**Google**で検索したり、他の**ブラウザ**や**shodan**でさえも検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

cronジョブを設定することは一般的です。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
サーバー上のすべてのドメイン証明書を更新すること。これは、証明書の有効期間に生成された時間が設定されていないCAを使用していても、**証明書の透明性ログで同じ会社に属するドメインを見つけることが可能**であることを意味します。
詳細については、[**こちらの記事をご覧ください**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)。

### **パッシブテイクオーバー**

どうやら、人々がサブドメインをクラウドプロバイダーのIPに割り当て、そのIPアドレスを失ったがDNSレコードの削除を忘れることが一般的のようです。したがって、クラウド（Digital Oceanなど）で**VMを起動するだけで**、実際にいくつかのサブドメインを**乗っ取ることになります**。

[**この投稿**](https://kmsec.uk/blog/passive-takeover/)ではそれについての話を説明し、DigitalOceanで**VMを起動し**、新しいマシンの**IPv4**を**取得し**、それを指すサブドメインレコードをVirustotalで**検索するスクリプトを提案しています**。

### **その他の方法**

**新しいドメインを見つけるたびに、この技術を使用してより多くのドメイン名を発見できることに注意してください。**

**Shodan**

IPスペースを所有している組織の名前が既にわかっているので、そのデータをshodanで検索できます：`org:"Tesla, Inc."` 見つかったホストでTLS証明書の新しい予期しないドメインをチェックします。

メインウェブページの**TLS証明書**にアクセスし、**組織名**を取得してから、**shodan**で知られているすべてのウェブページの**TLS証明書**内でその名前を検索できます。フィルターは：`ssl:"Tesla Motors"` または [**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のようなツールを使用します。

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder) は、メインドメインに**関連するドメイン**とそれらの**サブドメイン**を探すツールです。非常に素晴らしいです。

### **脆弱性を探す**

[ドメインの乗っ取り](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)をチェックしてください。もしかすると、ある会社が**ドメインを使用している**が、所有権を**失っている**かもしれません。十分に安ければ登録し、その会社に知らせてください。

資産発見で既に見つかったものとは**異なるIPを持つドメイン**を見つけた場合、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と**nmap/masscan/shodan**での[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行する必要があります。どのサービスが実行されているかによって、**この本でいくつかの攻撃のコツを見つけることができます**。\
_ドメインがクライアントによって制御されていないIP内でホストされていることがあるので、スコープ内にはないことに注意してください。注意が必要です。_

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**：**Intigriti**に**登録**してください。ハッカーによって作られたプレミアムな**バグバウンティプラットフォーム**です！今日 [**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) に参加して、最大**$100,000**の報酬を獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## サブドメイン

> スコープ内のすべての会社、各会社のすべての資産、および会社に関連するすべてのドメインを知っています。

見つかった各ドメインの可能なすべてのサブドメインを見つける時が来ました。

### **DNS**

**DNS**レコードから**サブドメイン**を取得しようとしましょう。また、**ゾーン転送**にも試みるべきです（脆弱であれば、報告する必要があります）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

外部ソースでサブドメインを多く迅速に取得する方法です。最も使用される**ツール**は以下の通りです（より良い結果のためにAPIキーを設定してください）:

* [**BBOT**](https://github.com/blacklanternsecurity/bbot)
```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```
* [**Amass**](https://github.com/OWASP/Amass)
```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```
* [**subfinder**](https://github.com/projectdiscovery/subfinder)
```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```
* [**findomain**](https://github.com/Edu4rdSHL/findomain/)
```bash
# findomain, use -silent to only have subdomains in the output
./findomain-linux -t tesla.com [--quiet]
```
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/en-us)
```bash
python3 oneforall.py --target tesla.com [--dns False] [--req False] [--brute False] run
```
* [**assetfinder**](https://github.com/tomnomnom/assetfinder)
```bash
assetfinder --subs-only <domain>
```
* [**Sudomy**](https://github.com/Screetsec/Sudomy)
```bash
# It requires that you create a sudomy.api file with API keys
sudomy -d tesla.com
```
* [**vita**](https://github.com/junnlikestea/vita)
```
vita -d tesla.com
```
* [**theHarvester**](https://github.com/laramies/theHarvester)
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
以下は、サブドメインを見つけるために直接専門化されていないが、サブドメインを見つけるのに役立つ可能性のある**他の興味深いツール/API**です：

* [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC 無料API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io) 無料API
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
Since the content provided does not contain any English text that requires translation, there is nothing to translate. The content is a URL which should remain unchanged.
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** 任意のドメインに対して、AlienVaultのOpen Threat Exchange、Wayback Machine、Common Crawlから既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **および** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ウェブをスクレイピングしてJSファイルを探し、そこからサブドメインを抽出します。
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys サブドメインファインダー**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/) は無料のAPIを提供しており、サブドメインやIP履歴を検索できます
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)

このプロジェクトは**バグ報奨金プログラムに関連するすべてのサブドメインを無料で提供しています**。このデータには [chaospy](https://github.com/dr-0x0x/chaospy) を使用するか、このプロジェクトが使用しているスコープにアクセスすることもできます [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

これらのツールの**比較**はこちらで見つけることができます: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS ブルートフォース**

DNSサーバーをブルートフォースして、可能性のあるサブドメイン名を使用して新しい**サブドメイン**を見つけてみましょう。

このアクションには、以下のような**一般的なサブドメインのワードリストが必要です**:

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れたDNSリゾルバのIPも必要です。信頼できるDNSリゾルバのリストを生成するためには、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt) からリゾルバをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使用してフィルタリングすることができます。または、以下を使用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNSブルートフォースに最も推奨されるツールは:

* [**massdns**](https://github.com/blechschmidt/massdns): これは効果的なDNSブルートフォースを行った最初のツールです。非常に高速ですが、誤検知を起こしやすいです。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): これは1つのリゾルバーを使用していると思います
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` をラップしたツールで、Go言語で書かれており、アクティブなブルートフォースを使用して有効なサブドメインを列挙すること、またワイルドカード処理と簡単な入出力サポートを備えたサブドメインを解決することができます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): これも`massdns`を使用します。
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用してドメイン名を非同期にブルートフォースします。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二ラウンド DNS ブルートフォース

オープンソースとブルートフォースを使用してサブドメインを見つけた後、さらに多くを見つけるために見つかったサブドメインの変更を生成することができます。この目的に役立ついくつかのツールがあります：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインが与えられたら、変異を生成します。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを与えると、順列を生成します。
* goaltdnsの順列 **ワードリスト** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインが与えられた場合、順列を生成します。順列ファイルが指定されていない場合、gotatorは独自のものを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): サブドメインの順列を生成するだけでなく、解決しようとすることもできます（ただし、前述のツールを使用する方が良いです）。
* altdnsの順列 **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)で入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): サブドメインの順列、変異、変更を実行する別のツールです。このツールは結果をブルートフォースします（dnsワイルドカードはサポートしていません）。
* dmutの順列ワードリストは[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)で入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインに基づいて、指定されたパターンに基づいて**新しい潜在的なサブドメイン名を生成し**、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

* [**regulator**](https://github.com/cramppet/regulator): 詳細はこの[**ポスト**](https://cramppet.github.io/regulator/index.html)を読んでくださいが、基本的には**発見されたサブドメイン**の**主要部分**を取得し、それらを混合してより多くのサブドメインを見つけることになります。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルで効果的なDNS応答ガイドアルゴリズムを備えたサブドメインブルートフォースファズです。提供された入力データ（特別に作成されたワードリストや歴史的なDNS/TLSレコードなど）を利用して、正確に対応するドメイン名を合成し、DNSスキャン中に収集した情報に基づいてループでさらに拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメイン発見ワークフロー**

私が書いたブログ記事をチェックしてください。ドメインから**Trickestワークフロー**を使用して**サブドメイン発見を自動化**する方法についてです。これにより、コンピュータで多数のツールを手動で起動する必要がありません：

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / バーチャルホスト**

IPアドレスに**一つまたは複数のウェブページ**が含まれているサブドメインを見つけた場合、そのIPで**他のウェブを持つサブドメインを見つける**ために、IP内のドメインに関する**OSINTソース**を調べるか、そのIPで**VHostドメイン名をブルートフォース**することができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPIを使用して**、IP内の**VHostsを見つける**ことができます。

**ブルートフォース**

ウェブサーバーに隠されたサブドメインがあると疑う場合、ブルートフォースを試みることができます：
```bash
ffuf -c -w /path/to/wordlist -u http://victim.com -H "Host: FUZZ.victim.com"

gobuster vhost -u https://mysite.com -t 50 -w subdomains.txt

wfuzz -c -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt --hc 400,404,403 -H "Host: FUZZ.example.com" -u http://example.com -t 100

#From https://github.com/allyshka/vhostbrute
vhostbrute.py --url="example.com" --remoteip="10.1.1.15" --base="www.example.com" --vhosts="vhosts_full.list"

#https://github.com/codingo/VHostScan
VHostScan -t example.com
```
{% hint style="info" %}
この技術を使用すると、内部/隠されたエンドポイントにアクセスできる場合があります。
{% endhint %}

### **CORS Brute Force**

場合によっては、有効なドメイン/サブドメインが _**Origin**_ ヘッダーに設定されているときにのみ _**Access-Control-Allow-Origin**_ ヘッダーを返すページに遭遇します。これらのシナリオでは、この振る舞いを悪用して新しい**サブドメイン**を**発見**することができます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **バケットブルートフォース**

**サブドメイン**を探している際に、それが何らかの**バケット**を**指している**かどうかを注意深く見て、その場合は[**権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)します。\
また、この時点でスコープ内のすべてのドメインを知っているので、[**可能性のあるバケット名をブルートフォースして権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)してみてください。

### **モニタリング**

ドメインの**新しいサブドメイン**が作成されたかどうかを、**Certificate Transparency** ログをモニタリングすることで**監視**できます。[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)がこれを行います。

### **脆弱性の探索**

[**サブドメインの乗っ取り**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性をチェックしてください。\
もし**サブドメイン**が何らかの**S3バケット**を指している場合は、[**権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)してください。

もし、資産発見で既に見つけたIPと**異なるIPのサブドメイン**を見つけた場合、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と**nmap/masscan/shodan**での[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実施するべきです。実行中のサービスに応じて、**この本にあるいくつかのトリックで"攻撃"することができます**。\
_クライアントがコントロールしていないIP内でサブドメインがホストされていることがあるので、スコープ内にない場合があります。注意してください。_

## IP

初期段階で、**いくつかのIP範囲、ドメイン、サブドメインを見つけた**かもしれません。\
これらの範囲から**すべてのIPを収集**し、**ドメイン/サブドメインのIP（DNSクエリ）**を収集する時が来ました。

以下の**無料API**のサービスを使用すると、ドメインとサブドメインが以前に使用していたIPも見つけることができます。これらのIPはまだクライアントが所有している可能性があり、[**CloudFlareのバイパス**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけることができるかもしれません。

* [**https://securitytrails.com/**](https://securitytrails.com/)

特定のIPアドレスを指しているドメインをチェックするためのツール[**hakip2host**](https://github.com/hakluke/hakip2host)もあります。

### **脆弱性の探索**

CDNに属していない**すべてのIPをポートスキャン**します（CDNでは興味深いものはほとんど見つからないでしょう）。発見された実行中のサービスでは、**脆弱性を見つけることができる**かもしれません。

**ホストをスキャンする方法**についての[**ガイド**](../pentesting-network/)を見つけてください。

## Webサーバーのハンティング

> すべての企業とその資産を見つけ、スコープ内のIP範囲、ドメイン、サブドメインを知っています。Webサーバーを探す時が来ました。

前のステップで、おそらくすでに**発見されたIPとドメインのリコン**を実施しているので、**可能なすべてのWebサーバーを既に見つけている**かもしれません。しかし、まだであれば、スコープ内のWebサーバーを探すための**迅速なトリック**をいくつか見ていきます。

これは**Webアプリの発見に向けたもの**であるため、スコープによって許可されている場合は、**脆弱性**と**ポートスキャン**も実施する必要があります。

[**masscan**を使用したWebサーバーに関連する**オープンポート**を発見する**迅速な方法**は[こちら](../pentesting-network/#http-port-discovery)にあります。\
Webサーバーを探すためのフレンドリーなツールには、[**httprobe**](https://github.com/tomnomnom/httprobe)、[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)があります。ドメインのリストを渡すと、ポート80（http）と443（https）に接続を試みます。さらに、他のポートを試すよう指示することもできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内に存在する**すべてのウェブサーバー**（会社の**IP**とすべての**ドメイン**および**サブドメイン**）を発見した今、**どこから始めればいいかわからない**かもしれません。そこで、簡単に始めるために、すべてのウェブサーバーのスクリーンショットを撮りましょう。**メインページ**を**見る**だけで、**変わった**エンドポイントが見つかり、**脆弱性**を持つ可能性が高くなります。

提案されたアイデアを実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、または [**webscreenshot**](https://github.com/maaaaz/webscreenshot) を使用できます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer) を使用して、すべての**スクリーンショット**を実行し、**脆弱性が含まれている可能性が高いもの**とそうでないものを教えてくれます。

## パブリッククラウドアセット

会社に属する可能性のあるクラウドアセットを見つけるためには、その会社を識別するキーワードのリストから**始めるべきです**。例えば、暗号通貨会社の場合は、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`のような単語を使用するかもしれません。

また、**バケットで一般的に使用される単語**のワードリストも必要です：

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語を使用して**置換**を生成します（詳細については[**第二ラウンドDNSブルートフォース**](./#second-dns-bruteforce-round)を確認してください）。

結果として得られたワードリストを使用して、[**cloud\_enum**](https://github.com/initstring/cloud\_enum)、[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)、[**cloudlist**](https://github.com/projectdiscovery/cloudlist)、または [**S3Scanner**](https://github.com/sa7mon/S3Scanner) などのツールを使用できます。

クラウドアセットを探すときは、AWSのバケットだけでなく、**さらに多くのものを探すべきです**。

### **脆弱性の探索**

**オープンなバケットや露出したクラウド関数**などを見つけた場合は、それらに**アクセス**して、提供されているものを確認し、悪用できるかどうかを試してみてください。

## メール

スコープ内の**ドメイン**と**サブドメイン**があれば、メールの検索を**始めるために必要なものがすべて揃っています**。これらは、会社のメールを見つけるために私にとって最も効果的だった**API**と**ツール**です：

* [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
* [**https://hunter.io/**](https://hunter.io/) のAPI（無料版）
* [**https://app.snov.io/**](https://app.snov.io/) のAPI（無料版）
* [**https://minelead.io/**](https://minelead.io/) のAPI（無料版）

### **脆弱性の探索**

メールは後で**ウェブログインや認証サービスのブルートフォース**（SSHなど）に役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIはメールの背後にいる**人物に関するさらなる情報**も提供します。これはフィッシングキャンペーンに役立ちます。

## クレデンシャルリーク

**ドメイン**、**サブドメイン**、および**メール**があれば、過去にこれらのメールに属するクレデンシャルがリークされたかどうかを調べ始めることができます：

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の探索**

**有効なリークされた**クレデンシャルを見つけた場合、これは非常に簡単な勝利です。

## シークレットリーク

クレデンシャルリークは、**機密情報がリークされて販売された**会社のハックに関連しています。しかし、その情報がこれらのデータベースにない**他のリーク**によって、会社が影響を受ける可能性があります：

### Githubリーク

クレデンシャルとAPIは、その**会社**またはそのgithub会社で働く**ユーザー**の**公開リポジトリ**でリークされる可能性があります。\
**ツール** [**Leakos**](https://github.com/carlospolop/Leakos) を使用して、**組織**とその**開発者**のすべての**公開リポ**を**ダウンロード**し、自動的に [**gitleaks**](https://github.com/zricethezav/gitleaks) を実行できます。

**Leakos** は、**ウェブページにもシークレットが含まれていることがある**ため、それに渡された**URLのすべてのテキスト**に対して**gitleaks**を実行するためにも使用できます。

#### Github Dorks

攻撃している組織で検索する可能性のある**github dorks**については、この**ページ**も確認してください：

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastesリーク

時々、攻撃者や単なる従業員が**ペーストサイトに会社のコンテンツを公開**することがあります。これには**機密情報が含まれているかもしれませんし、含まれていないかもしれません**が、それを検索することは非常に興味深いです。\
80以上のペーストサイトを同時に検索するツール [**Pastos**](https://github.com/carlospolop/Pastos) を使用できます。

### Google Dorks

古くからあるが金のGoogle dorksは、**そこにあるべきではない露出した情報**を見つけるのに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database) には手動で実行できない数千の可能なクエリが含まれていることです。したがって、お気に入りの10個を取得するか、または [**Gorks**](https://github.com/carlospolop/Gorks) のような**ツールを使用して**、それら**すべてを実行**できます。

_通常のGoogleブラウザーを使用してデータベース全体を実行しようとするツールは、Googleによって非常に早くブロックされるため、決して終わることはありません。_

### **脆弱性の探索**

**有効なリークされた**クレデンシャルやAPIトークンを見つけた場合、これは非常に簡単な勝利です。

## パブリックコードの脆弱性

会社が**オープンソースコード**を持っていることがわかった場合、それを**分析**し、その上で**脆弱性**を探すことができます。

**言語によって**異なる**ツール**があります：

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

また、**パブリックリポジトリをスキャン**する無料サービスもあります：

* [**Snyk**](https://app.snyk.io/)

## [**ウェブペネトレーションテスト方法論**](../../network-services-pentesting/pentesting-web/)

バグハンターが見つけた**脆弱性の大部分**は**ウェブアプリケーション内**に存在するため、この時点で**ウェブアプリケーションテスト方法論**について話したいと思います。この情報は[**こちらで見つけることができます**](../../network-services-pentesting/pentesting-web/)。

また、[**ウェブ自動スキャナーオープンソースツール**](../../network-services-pentesting/pentesting-web/#automatic-scanners)のセクションに特別な言及をしたいと思います。非常に敏感な脆弱性を見つけることを期待すべきではありませんが、**初期のウェブ情報を持つためのワークフローに実装する**のに便利です。

## まとめ

> おめでとうございます！この時点で、すでに**基本的な列挙**をすべて実行しました。はい、基本的なものですが、もっと多くの列挙ができます（後でさらにトリックを見ていきます）。

したがって、すでに以下のことを行っています：

1. スコープ内のすべての**会社**を見つけました。
2. 会社に属するすべての**アセット**を見つけました（スコープ内であればいくつかの脆弱性スキャンを実行）。
3. 会社に属するすべての**ドメイン**を見つけました。
4. ドメインのすべての**サブドメイン**を見つけました（サブドメインの乗っ取りはありますか？）。
5. スコープ内のすべての**IP**（**CDNからのものとそうでないもの**）を見つけました。
6. すべての**ウェブサーバー**を見つけ、それらの**スクリーンショット**を撮りました（深く見る価値のある何か変わったものはありますか？）。
7. 会社に属するすべての**潜在的なパブリッククラウドアセット**を見つけました。
8. **メール**、**クレデンシャルリーク**、および**シークレットリーク**を見つけました。これらは非常に簡単に**大きな勝利**をもたらす可能性があります。
9. 見つけたすべてのウェブの**ペネトレーションテスト**を実行しました。

## **完全なリコン自動ツール**

提案されたアクションの一部を特定のスコープに対して実行するいくつかのツールがあります。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **参考文献**

* [**@Jhaddix**](https://twitter.com/Jhaddix) の**すべての無料コース**（[**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)など）

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**：ハッカーによって作られたプレミアムな**バグバウンティプラットフォームであるIntigriti**に**登録**しましょう！[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks) で今日から参加し、**$100,000**までのバウンティを獲得し始めましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksに広告を掲載したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospol
