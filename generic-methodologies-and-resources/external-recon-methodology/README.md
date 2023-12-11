# 外部調査方法論

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**です！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**の報奨金を獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## 資産の発見

> ある会社が所有するすべてのものが対象であると言われ、この会社が実際に何を所有しているのかを把握したいと思っています。

このフェーズの目標は、まず**主要な会社が所有する他の会社**をすべて取得し、それらの会社の**資産**をすべて取得することです。これを行うために、以下の手順を実行します。

1. 主要な会社の買収を見つけることで、対象となる会社を把握します。
2. 各会社のASN（あれば）を見つけることで、各会社が所有するIP範囲を把握します。
3. リバースWhois検索を使用して、最初のエントリ（組織名、ドメインなど）に関連する他のエントリを検索します（これは再帰的に行うことができます）。
4. shodanの`org`および`ssl`フィルタのような他のテクニックを使用して、他の資産を検索します（`ssl`トリックは再帰的に行うことができます）。

### **買収**

まず、**主要な会社が所有する他の会社**を知る必要があります。\
一つのオプションは、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**主要な会社**を**検索**し、「**acquisitions**」を**クリック**することです。そこには、主要な会社によって買収された他の会社が表示されます。\
他のオプションは、主要な会社の**Wikipedia**ページを訪問し、**買収**を検索することです。

> この時点で、対象となるすべての会社を把握するはずです。次に、それらの資産を見つける方法を考えましょう。

### **ASNs**

自律システム番号（**ASN**）は、**インターネット割り当て番号機関（IANA）**によって**自律システム（AS）**に割り当てられる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに対する明確に定義されたポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織によって管理されますが、複数のオペレータで構成される場合もあります。

会社がどのような**ASNを割り当てているか**を見つけることは興味深いです。これにより、**IP範囲**を持つ**ホスト**全体に対して**脆弱性テスト**を実施し、これらのIP内のドメインを探すことができます。\
[**https://bgp.he.net/**](https://bgp.he.net)****で、会社の**名前**、**IP**、または**ドメイン**で**検索**することができます。\
**会社の地域によっては、次のリンクがより多くのデータを収集するのに役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）**、[**Arin**](https://www.arin.net/about/welcome/region/) **（北アメリカ）**、[**APNIC**](https://www.apnic.net) **（アジア）**、[**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）**、[**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。とは言え、おそらくすべての**有用な情報（IP範囲とWhois）**は、最初のリンクに既に表示されています。
```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```
また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**サブドメインの列挙は、スキャンの最後にASNを自動的に集約し、要約します。
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
組織のIP範囲を見つけるには、[http://asnlookup.com/](http://asnlookup.com)（無料のAPIがあります）を使用することもできます。\
ドメインのIPとASNを見つけるには、[http://ipv4info.com/](http://ipv4info.com)を使用できます。

### **脆弱性の検索**

この時点で、**スコープ内のすべての資産**がわかっているので、許可されている場合は、すべてのホストに対して**脆弱性スキャナ**（Nessus、OpenVAS）を実行することができます。\
また、[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行するか、shodanのようなサービスを使用して**オープンポートを見つけ、見つかったものに応じて**この本でいくつかの可能なサービスをペンテストする方法を確認する必要があります。\
**また、デフォルトのユーザー名**と**パスワードのリストを準備して、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使用してサービスをブルートフォースすることもできます。

## ドメイン

> スコープ内のすべての企業とその資産がわかっているので、スコープ内のドメインを見つける時が来ました。

_以下の提案された手法では、サブドメインも見つけることができることに注意してください。この情報は過小評価されるべきではありません。_

まず、各企業の**メインドメイン**を探す必要があります。例えば、_Tesla Inc._ の場合は _tesla.com_ になります。

### **逆引きDNS**

ドメインのIP範囲をすべて見つけたので、それらの**IPに対して逆引きDNSルックアップ**を試みて、スコープ内の他のドメインを見つけることができます。被害者のDNSサーバーまたは一部のよく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使用してみてください。
```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```
### **逆引き Whois (ループ)**

**whois** 内には、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**がたくさん含まれています。しかし、さらに興味深いのは、これらのフィールドのいずれかで**逆引き Whois ルックアップ**を実行すると、会社に関連する**さらなる資産**を見つけることができることです（たとえば、同じメールアドレスが登録されている他の whois レジストリ）。\
以下のようなオンラインツールを使用することができます：

* [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
* [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
* [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
* [https://www.whoxy.com/](https://www.whoxy.com) - **無料**（ウェブは無料ですが、APIは有料です）
* [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
* [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（**100回まで無料**）
* [https://www.domainiq.com/](https://www.domainiq.com) - 有料

[**DomLink** ](https://github.com/vysecurity/DomLink)を使用して、このタスクを自動化することもできます（whoxy API キーが必要です）。\
また、[amass](https://github.com/OWASP/Amass)を使用して、自動的な逆引き Whois の発見を行うこともできます：`amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この技術を使用してさらに多くのドメイン名を発見することができることに注意してください。**

### **トラッカー**

2つの異なるページで**同じトラッカーの ID**を見つけた場合、**両方のページ**が**同じチームによって管理されている**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**を見つけた場合です。

これらのトラッカーやその他の情報を検索できるいくつかのページやツールがあります：

* [**Udon**](https://github.com/dhn/udon)
* [**BuiltWith**](https://builtwith.com)
* [**Sitesleuth**](https://www.sitesleuth.io)
* [**Publicwww**](https://publicwww.com)
* [**SpyOnWeb**](http://spyonweb.com)

### **Favicon**

同じ favicon アイコンのハッシュを探すことで、ターゲットと関連するドメインやサブドメインを見つけることができることを知っていましたか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) ツールがまさにそれを行います。以下は、その使い方です：
```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```
![favihash - 同じファビコンアイコンハッシュを持つドメインを発見する](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言えば、favihashは、ターゲットと同じファビコンアイコンハッシュを持つドメインを発見することができます。

さらに、[**このブログ記事**](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)で説明されているように、ファビコンハッシュを使用して技術を検索することもできます。つまり、脆弱なバージョンのウェブ技術のファビコンのハッシュを知っている場合、shodanで検索してより多くの脆弱な場所を見つけることができます。
```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
```
これは、ウェブの**ファビコンハッシュを計算する方法**です：
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

同じ組織内の異なるウェブページで共有される可能性のある文字列を検索します。著作権の文字列は良い例です。その文字列をGoogleや他のブラウザ、さらにはShodanで検索します：`shodan search http.html:"著作権の文字列"`

### **CRT時間**

よくあるcronジョブの一つとして、以下のようなものがあります。
```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```
## 外部リコンの方法論

### **証明書透過性ログを使用したドメインの発見**

サーバー上のすべてのドメイン証明書を更新するためには、このために使用されるCAが発行時刻を有効期間内に設定していなくても、証明書透過性ログで同じ会社に所属するドメインを見つけることができます。

詳細については、[**こちらの記事**](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack/)をご覧ください。

### **パッシブな乗っ取り**

クラウドプロバイダーに属するIPにサブドメインを割り当て、ある時点でそのIPアドレスを失い、DNSレコードを削除するのを忘れることは一般的です。したがって、Digital OceanのようなクラウドでVMを起動するだけで、実際にはいくつかのサブドメインを乗っ取ることができます。

[**この記事**](https://kmsec.uk/blog/passive-takeover/)では、それについてのストーリーを説明し、DigitalOceanでVMを起動し、新しいマシンのIPv4を取得し、それを指すサブドメインレコードをVirustotalで検索するスクリプトを提案しています。

### **その他の方法**

**新しいドメインを見つけるたびに、この技術を使用してさらに多くのドメイン名を発見することができることに注意してください。**

**Shodan**

すでにIPスペースを所有している組織の名前を知っている場合、`org:"Tesla, Inc."`というデータでShodanで検索することができます。TLS証明書で新しい予期しないドメインを見つけてください。

メインのウェブページの**TLS証明書**にアクセスし、**組織名**を取得し、**shodan**で知られているすべてのウェブページの**TLS証明書**内でその名前を検索することもできます。フィルターを使用して `ssl:"Tesla Motors"` または [**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使用することもできます。

**Assetfinder**

[**Assetfinder**](https://github.com/tomnomnom/assetfinder)は、メインドメインに関連する**ドメイン**とその**サブドメイン**を探すツールで、非常に素晴らしいです。

### **脆弱性の検索**

[ドメイン乗っ取り](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)をチェックしてください。おそらく、会社が**ドメインを使用しているが所有権を失っている**場合があります。安価な場合は登録して、会社に知らせてください。

アセットの発見で既に見つかったIPとは異なる**IPを持つドメイン**を見つけた場合、基本的な脆弱性スキャン（NessusやOpenVASを使用）と[**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)（nmap/masscan/shodanを使用）を実行する必要があります。実行中のサービスに応じて、**この本にはそれらを"攻撃"するためのトリックがいくつかあります**。\
_なお、ドメインがクライアントによって制御されていないIP内にホストされている場合、スコープ外ですので注意してください。_

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**: **Intigriti**に**サインアップ**してください。これは、ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**です！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**の報奨金を獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

## サブドメイン

> スコープ内のすべての企業、各企業のアセット、および企業に関連するすべてのドメインを知っています。

見つかった各ドメインの可能なサブドメインをすべて見つける時が来ました。

### **DNS**

DNSレコードから**サブドメイン**を取得しましょう。また、**ゾーン転送**も試してみるべきです（脆弱性がある場合は報告してください）。
```bash
dnsrecon -a -d tesla.com
```
### **OSINT**

多くのサブドメインを取得する最速の方法は、外部ソースで検索することです。最もよく使われる**ツール**は以下のものです（より良い結果を得るためにはAPIキーを設定してください）：

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
* [**OneForAll**](https://github.com/shmilylty/OneForAll/tree/master/docs/ja-jp)
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

[theHarvester](https://github.com/laramies/theHarvester)は、外部リコンnaissanceのためのオープンソースのツールです。このツールは、特定のドメインに関連する情報を収集するために使用されます。theHarvesterは、電子メールアドレス、ユーザー名、サブドメイン、バナー、オープンポートなど、さまざまな情報を収集することができます。

theHarvesterを使用すると、ターゲットのドメインに関連する情報を収集し、その情報を分析することができます。これにより、ターゲットのインフラストラクチャやオンラインプレゼンスに関する洞察を得ることができます。

theHarvesterは、コマンドラインベースのツールであり、Pythonで書かれています。このツールは、さまざまなデータソースから情報を収集するためにAPIを使用します。theHarvesterは、Google、Bing、LinkedIn、Pgp、Twitterなどのデータソースにアクセスすることができます。

theHarvesterを使用するには、まずPythonと必要な依存関係をインストールする必要があります。その後、コマンドラインからtheHarvesterを実行し、ターゲットのドメインを指定します。theHarvesterは、指定されたドメインに関連する情報を収集し、結果を表示します。

theHarvesterは、外部リコンnaissanceの初期段階で非常に有用なツールです。ターゲットの情報収集を効率的かつ網羅的に行い、攻撃の準備をするためにtheHarvesterを活用しましょう。
```bash
theHarvester -d tesla.com -b "anubis, baidu, bing, binaryedge, bingapi, bufferoverun, censys, certspotter, crtsh, dnsdumpster, duckduckgo, fullhunt, github-code, google, hackertarget, hunter, intelx, linkedin, linkedin_links, n45ht, omnisint, otx, pentesttools, projectdiscovery, qwant, rapiddns, rocketreach, securityTrails, spyse, sublist3r, threatcrowd, threatminer, trello, twitter, urlscan, virustotal, yahoo, zoomeye"
```
他にも興味深いツール/APIがあります。これらは直接的にサブドメインを見つけることに特化していないかもしれませんが、サブドメインを見つけるのに役立つかもしれません。

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** [https://sonar.omnisint.io](https://sonar.omnisint.io)のAPIを使用してサブドメインを取得します。
```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```
* [**JLDC無料API**](https://jldc.me/anubis/subdomains/google.com)
```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
```
* [**RapidDNS**](https://rapiddns.io)は無料のAPIです。
```bash
# Get Domains from rapiddns free API
rapiddns(){
curl -s "https://rapiddns.io/subdomain/$1?full=1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
rapiddns tesla.com
```
* [**https://crt.sh/**](https://crt.sh)
```bash
# Get Domains from crt free API
crt(){
curl -s "https://crt.sh/?q=%25.$1" \
| grep -oE "[\.a-zA-Z0-9-]+\.$1" \
| sort -u
}
crt tesla.com
```
* [**gau**](https://github.com/lc/gau)**:** 特定のドメインからAlienVaultのOpen Threat Exchange、Wayback Machine、およびCommon Crawlに既知のURLを取得します。
```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```
* [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): ウェブをスクラップし、JSファイルを探し、そこからサブドメインを抽出します。
```bash
# Get only subdomains from SubDomainizer
python3 SubDomainizer.py -u https://tesla.com | grep tesla.com

# Get only subdomains from subscraper, this already perform recursion over the found results
python subscraper.py -u tesla.com | grep tesla.com | cut -d " " -f
```
* [**Shodan**](https://www.shodan.io/)

* [**Shodan**](https://www.shodan.io/)は、インターネット上のデバイスを検索するための検索エンジンです。Shodanは、オープンポートやバナー情報などの公開情報を収集し、それを利用してデバイスを特定します。このツールは、セキュリティ調査や脆弱性評価に役立ちます。Shodanは、インターネット上のデバイスの検索に特化しており、様々なデバイスやサービスを特定することができます。
```bash
# Get info about the domain
shodan domain <domain>
# Get other pages with links to subdomains
shodan search "http.html:help.domain.com"
```
* [**Censys サブドメイン検索ツール**](https://github.com/christophetd/censys-subdomain-finder)
```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```
* [**DomainTrail.py**](https://github.com/gatete/DomainTrail)
```bash
python3 DomainTrail.py -d example.com
```
* [**securitytrails.com**](https://securitytrails.com/)は、サブドメインとIPの履歴を検索するための無料のAPIを提供しています。
* [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)は、バグバウンティプログラムに関連するすべてのサブドメインを無料で提供しています。このデータには、[chaospy](https://github.com/dr-0x0x/chaospy)を使用してアクセスすることもできます。また、このプロジェクトが使用するスコープにもアクセスできます。[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)

ここでは、これらのツールの比較を見つけることができます：[https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNSブルートフォース**

可能なサブドメイン名を使用してDNSサーバーをブルートフォースして、新しい**サブドメイン**を見つけてみましょう。

この作業には、次のような**一般的なサブドメインのワードリスト**が必要です：

* [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
* [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
* [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
* [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
* [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼できるDNSリゾルバのIPも必要です。信頼できるDNSリゾルバのリストを生成するには、[https://public-dns.info/nameservers-all.txt](https://public-dns.info/nameservers-all.txt)からリゾルバをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator)を使用してフィルタリングすることができます。または、[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)を使用することもできます。

DNSブルートフォースに最も推奨されるツールは次のとおりです：

* [**massdns**](https://github.com/blechschmidt/massdns)：これは効果的なDNSブルートフォースを実行した最初のツールです。非常に高速ですが、誤検知のリスクがあります。
```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```
* [**gobuster**](https://github.com/OJ/gobuster): これは、私は1つのリゾルバを使用していると思います。
```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```
* [**shuffledns**](https://github.com/projectdiscovery/shuffledns)は、goで書かれた`massdns`のラッパーであり、アクティブなブルートフォースを使用して有効なサブドメインを列挙することができます。また、ワイルドカードの処理や簡単な入出力のサポートを行うこともできます。
```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```
* [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用しています。
```
puredns bruteforce all.txt domain.com
```
* [**aiodnsbrute**](https://github.com/blark/aiodnsbrute)は、非同期でドメイン名をブルートフォース攻撃するためにasyncioを使用します。
```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```
### 第二のDNSブルートフォースラウンド

オープンソースとブルートフォースを使用してサブドメインを見つけた後、さらに多くのサブドメインを見つけるために、見つかったサブドメインの変形を生成することができます。この目的には、いくつかのツールが役立ちます：

* [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを与えられた場合、順列を生成します。
```bash
cat subdomains.txt | dnsgen -
```
* [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを与えられた場合、順列を生成します。
* goaltdnsの順列の**ワードリスト**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)で入手できます。
```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```
* [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、順列を生成します。順列ファイルが指定されていない場合、gotatorは独自のファイルを使用します。
```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```
* [**altdns**](https://github.com/infosec-au/altdns): サブドメインの組み合わせを生成するだけでなく、それらを解決しようともします（ただし、前述のコメント付きツールを使用する方が良いです）。
* altdnsの組み合わせの**ワードリスト**は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から入手できます。
```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```
* [**dmut**](https://github.com/bp0lr/dmut): サブドメインのパーミュテーション、変異、および変更を実行するための別のツールです。このツールは結果をブルートフォースします（dnsワイルドカードはサポートされていません）。
* dmutのパーミュテーションのワードリストは[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)で入手できます。
```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
--dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```
* [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、新しい潜在的なサブドメイン名を生成し、より多くのサブドメインを発見しようとします。

#### スマートな順列生成

* [**regulator**](https://github.com/cramppet/regulator): 詳細については、この[**投稿**](https://cramppet.github.io/regulator/index.html)を読んでくださいが、基本的には**発見されたサブドメイン**から**主要な部分**を取得し、それらを組み合わせてより多くのサブドメインを見つけます。
```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```
* [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_は、サブドメインのブルートフォースファズツールであり、非常にシンプルで効果的なDNS応答ガイドアルゴリズムと組み合わせています。カスタマイズされたワードリストや過去のDNS/TLSレコードなどの提供された入力データを利用して、より対応するドメイン名を正確に合成し、DNSスキャン中に収集された情報に基づいてさらに拡張します。
```
echo www | subzuf facebook.com
```
### **サブドメインの発見ワークフロー**

このブログ記事をチェックしてください。そこでは、**Trickestワークフロー**を使用してドメインからのサブドメインの発見を自動化する方法について書いています。これにより、コンピュータで手動で多くのツールを起動する必要がありません。

{% embed url="https://trickest.com/blog/full-subdomain-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

{% embed url="https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

### **VHosts / 仮想ホスト**

サブドメインに属する**1つまたは複数のウェブページを含むIPアドレス**を見つけた場合、そのIP内の他のサブドメインを見つけるために、**OSINTソース**でIP内のドメインを検索するか、そのIP内のVHostドメイン名を**ブルートフォース**することができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPI**を使用して、いくつかのIP内のVHostを見つけることができます。

**ブルートフォース**

ウェブサーバーに隠されている可能性のあるいくつかのサブドメインを疑っている場合は、ブルートフォースしてみることができます。
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
このテクニックを使えば、内部/非公開のエンドポイントにアクセスすることもできるかもしれません。
{% endhint %}

### **CORS Brute Force**

時には、有効なドメイン/サブドメインが_**Origin**_ヘッダーに設定されている場合にのみ、ページがヘッダー_**Access-Control-Allow-Origin**_を返すページがあります。このようなシナリオでは、この動作を悪用して、新しい**サブドメイン**を**発見**することができます。
```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```
### **バケットのブルートフォース**

**サブドメイン**を探している間に、それがどの種類の**バケット**を指しているかを確認し、その場合は[**アクセス権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)してください。\
また、この時点でスコープ内のすべてのドメインを知っているので、[**可能なバケット名をブルートフォースし、アクセス権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)してみてください。

### **モニタリング**

ドメインの**新しいサブドメイン**が作成されたかどうかを**証明書の透過性ログ**のモニタリングで確認できます。[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)を使用してください。

### **脆弱性の探索**

[**サブドメインの乗っ取り**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性をチェックしてください。\
もし**サブドメイン**が**S3バケット**を指している場合は、[**アクセス権限をチェック**](../../network-services-pentesting/pentesting-web/buckets/)してください。

アセットの発見で既に見つかったIPとは異なるIPを持つ**サブドメイン**を見つけた場合は、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と[**nmap/masscan/shodan**による**ポートスキャン**](../pentesting-network/#discovering-hosts-from-the-outside)を実行する必要があります。実行中のサービスによっては、**この本にはそれらを"攻撃"するためのトリックがいくつかあります**。\
なお、サブドメインがクライアントによって制御されていないIP内にホストされている場合は、スコープ外なので注意してください。

## IP

初期のステップで**いくつかのIP範囲、ドメイン、サブドメイン**を見つけたかもしれません。\
これらの範囲から**すべてのIP**と**ドメイン/サブドメイン（DNSクエリ）**を収集する時が来ました。

以下の**無料API**のサービスを使用すると、ドメインとサブドメインが以前に使用していた**IP**を見つけることもできます。これらのIPはクライアントが所有している可能性があります（そして[**CloudFlareのバイパス**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけることができるかもしれません）。

* [**https://securitytrails.com/**](https://securitytrails.com/)

また、ツール[**hakip2host**](https://github.com/hakluke/hakip2host)を使用して、特定のIPアドレスを指すドメインをチェックすることもできます。

### **脆弱性の探索**

CDNに所属していない**すべてのIPにポートスキャン**を実行してください（おそらくそこに興味深いものは見つからないでしょう）。発見した実行中のサービスで**脆弱性を見つける**ことができるかもしれません。

ホストのスキャン方法についての[**ガイド**](../pentesting-network/)を**見つけてください**。

## Webサーバーの探索

> すべての企業とそのアセットを見つけ、IP範囲、ドメイン、スコープ内のサブドメインを知っています。Webサーバーを検索する時が来ました。

前のステップでおそらく既に**発見したIPとドメインの情報を収集**しているため、おそらく**すべての可能なWebサーバー**を既に見つけているかもしれません。ただし、まだ見つけていない場合は、スコープ内のWebサーバーを検索するための**高速なトリック**を見ていきます。

これは**Webアプリの発見に特化**しているため、スコープによっては**脆弱性スキャン**と**ポートスキャン**も実行する必要があります（**許可されている場合**）。

[**masscanを使用してWebサーバーに関連するオープンポートを発見する**高速な方法はこちら](../pentesting-network/#http-port-discovery)です。\
Webサーバーを検索するためのもう一つの便利なツールは[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)**、**[**httpx**](https://github.com/projectdiscovery/httpx)です。ドメインのリストを渡すだけで、ポート80（http）と443（https）に接続しようとします。さらに、他のポートを試すこともできます：
```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```
### **スクリーンショット**

スコープ内のすべてのウェブサーバー（会社のIPアドレス、ドメイン、サブドメインを含む）を発見したので、おそらくどこから始めればいいかわからないでしょう。だから、簡単にするために、まずはそれらのすべてのスクリーンショットを撮りましょう。メインページを見るだけで、脆弱性の可能性が高い奇妙なエンドポイントを見つけることができます。

提案されたアイデアを実行するために、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)を使用できます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使用して、すべてのスクリーンショットを実行し、脆弱性の可能性が高いものとそうでないものを判断することもできます。

## パブリッククラウドの資産

会社に関連する潜在的なクラウド資産を見つけるためには、その会社を識別するためのキーワードのリストから始める必要があります。たとえば、暗号通貨会社の場合、"crypto"、"wallet"、"dao"、"<domain_name>"、"<subdomain_names>"などの単語を使用することがあります。

また、バケットで使用される一般的な単語のワードリストも必要です。

* [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
* [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
* [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

それから、それらの単語を使用して**順列**を生成する必要があります（詳細については[**Second Round DNS Brute-Force**](./#second-dns-bruteforce-round)を参照）。

生成されたワードリストを使用して、[**cloud\_enum**](https://github.com/initstring/cloud\_enum)、[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)、[**cloudlist**](https://github.com/projectdiscovery/cloudlist)、または[**S3Scanner**](https://github.com/sa7mon/S3Scanner)などのツールを使用できます。

クラウド資産を探すときは、AWSのバケットだけでなく、他のものも探す必要があります。

### **脆弱性の探索**

オープンなバケットや公開されたクラウド関数などのものが見つかった場合は、それらにアクセスして提供されるものや悪用できるかどうかを確認してください。

## メール

スコープ内のドメインとサブドメインがあれば、基本的には企業のメールを検索するために必要なものがすべて揃っています。以下は、企業のメールを見つけるために最も効果的だったAPIとツールです。

* [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
* [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
* [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
* [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の探索**

メールは、ウェブログインや認証サービス（SSHなど）のブルートフォース攻撃や、フィッシング攻撃に使用するために後で役立ちます。さらに、これらのAPIは、メールの背後にいる人物についてのさらなる情報を提供してくれるため、フィッシングキャンペーンに役立ちます。

## 資格情報の漏洩

ドメイン、サブドメイン、およびメールがあれば、過去に漏洩したそれらのメールに関連する資格情報を探すことができます。

* [https://leak-lookup.com](https://leak-lookup.com/account/login)
* [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の探索**

有効な漏洩した資格情報が見つかった場合、これは非常に簡単な勝利です。

## 機密情報の漏洩

資格情報の漏洩は、機密情報が漏洩して売られた企業のハッキングに関連しています。ただし、企業はそのデータベースに含まれていない他の情報の漏洩の影響を受ける可能性もあります。

### Githubの漏洩

資格情報やAPIが、会社の公開リポジトリまたはそのgithub会社で働くユーザーの公開リポジトリで漏洩している可能性があります。[**Leakos**](https://github.com/carlospolop/Leakos)ツールを使用して、組織とその開発者のすべての公開リポジトリをダウンロードし、自動的に[**gitleaks**](https://github.com/zricethezav/gitleaks)を実行することができます。

**Leakos**は、URLが提供されたテキストのすべてに対して**gitleaks**を実行するためにも使用できます。

#### Github Dorks

攻撃対象の組織で検索することもできる潜在的な**github dorks**については、次の**ページ**も参照してください。

{% content-ref url="github-leaked-secrets.md" %}
[github-leaked-secrets.md](github-leaked-secrets.md)
{% endcontent-ref %}

### Pastes Leaks

攻撃者または作業者が企業のコンテンツをペーストサイトに公開することがあります。これには**機密情報**が含まれている場合もあります。[**Pastos**](https://github.com/carlospolop/Pastos)ツールを使用して、80以上のペーストサイトで一度に検索することができます。

### Google Dorks

古くても有用なGoogle Dorksは、そこにあってはならない**公開情報**を見つけるのに常に役立ちます。ただし、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)には数千ものクエリが含まれており、手動で実行することはできません。したがって、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks)などのツールを使用してすべて実行することができます。

_データベース全体を通常のGoogleブラウザで実行することを期待するツールは、Googleが非常にすぐにブロックするため、終了しないでしょう。_
### **脆弱性の探索**

もし**有効な漏洩した**資格情報やAPIトークンを見つけた場合、これは非常に簡単な勝利です。

## 公開コードの脆弱性

もし会社が**オープンソースのコード**を持っていることがわかった場合、それを**分析**して脆弱性を探すことができます。

**言語によって異なるツール**を使用することができます:

{% content-ref url="../../network-services-pentesting/pentesting-web/code-review-tools.md" %}
[code-review-tools.md](../../network-services-pentesting/pentesting-web/code-review-tools.md)
{% endcontent-ref %}

また、以下のような無料のサービスを使用して、**公開リポジトリをスキャン**することもできます:

* [**Snyk**](https://app.snyk.io/)

## [**Webペンテスト方法論**](../../network-services-pentesting/pentesting-web/)

バグハンターが見つける**脆弱性の大部分**は、**Webアプリケーション**に存在しているため、この段階で**Webアプリケーションのテスト方法論**について説明したいと思います。詳細は[**こちらで見つけることができます**](../../network-services-pentesting/pentesting-web/)。

また、[**Web自動スキャナのオープンソースツール**](../../network-services-pentesting/pentesting-web/#automatic-scanners)にも特別な言及をしたいと思います。非常に重要な脆弱性を見つけることは期待できませんが、**ワークフローに組み込んで初期のWeb情報を取得するのに便利です。**

## 総括

> おめでとうございます！この時点で、すでに**基本的な列挙**を実行しました。はい、基本的な列挙です。さらに多くの列挙ができます（後でさらなるトリックを見ることになります）。

したがって、すでに以下を行いました:

1. スコープ内の**会社**をすべて見つけました。
2. 会社に所属する**資産**をすべて見つけました（スコープ内で脆弱性スキャンも実行しました）。
3. 会社に所属する**ドメイン**をすべて見つけました。
4. ドメインの**サブドメイン**をすべて見つけました（サブドメインの乗っ取りはありましたか？）。
5. スコープ内の**CDN以外のIPアドレス**をすべて見つけました。
6. **Webサーバー**をすべて見つけ、それらの**スクリーンショット**を撮りました（何か奇妙なものはありましたか？詳しく調べる価値がありますか？）。
7. 会社に所属する**潜在的なパブリッククラウドの資産**をすべて見つけました。
8. **メール**、**資格情報の漏洩**、および**秘密の漏洩**を見つけました。これらは**非常に簡単に大きな勝利**をもたらす可能性があります。
9. 見つけたすべてのWebを**ペンテスト**しました。

## **完全な列挙の自動ツール**

与えられたスコープに対して提案されたアクションの一部を実行するいくつかのツールがあります。

* [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
* [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
* [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
* [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## **参考文献**

* [**@Jhaddix**](https://twitter.com/Jhaddix)の**すべての無料コース**（例: [**The Bug Hunter's Methodology v4.0 - Recon Edition**](https://www.youtube.com/watch?v=p4JgIu1mceI)）

<img src="../../.gitbook/assets/i3.png" alt="" data-size="original">\
**バグバウンティのヒント**: ハッカーによって作成されたプレミアムな**バグバウンティプラットフォーム**である**Intigriti**に**サインアップ**しましょう！今すぐ[**https://go.intigriti.com/hacktricks**](https://go.intigriti.com/hacktricks)に参加して、最大**$100,000**の報奨金を獲得しましょう！

{% embed url="https://go.intigriti.com/hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksであなたの会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。当社の独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
