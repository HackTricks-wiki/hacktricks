# 外部Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

追加のOSINTおよびWeb探索プロジェクトを分類した一覧については、[サードパーティのツールとリソース](../third-party-tools-and-resources.md#osint)を参照してください。

> ある企業に属するすべてのものがscope内だと聞き、その企業が実際に何を所有しているのか把握したいとします。

このフェーズの目標は、**主要企業が所有するすべての企業**を特定し、続いてそれらの企業の**すべての資産**を見つけることです。そのために、次のことを行います。<sup>[[1]](#references)</sup>

1. 主要企業による買収を調べ、scope内の企業を特定する。
2. 各企業のASN（存在する場合）を調べ、その企業が所有するIP範囲を特定する。
3. reverse whois検索を使い、最初の企業に関連する他の情報（組織名、ドメインなど）を検索する（再帰的に実施可能）。
4. Shodanの`org`フィルターや`ssl`フィルターなど、他の手法で資産を検索する（`ssl`の手法は再帰的に実施可能）。

解決済みサブドメインからHTTPクローリングおよびポート検出へ移行する段階的な引き継ぎについては、[Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline)を参照してください。

### **買収**

まず、**主要企業が所有する他の企業**を把握する必要があります。\
1つの方法は、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスして**主要企業を検索**し、「**acquisitions**」を**クリック**することです。そこには、主要企業が買収した他の企業が表示されます。\
もう1つの方法は、主要企業の**Wikipedia**ページにアクセスし、**買収**について検索することです。\
上場企業の場合は、**SEC/EDGARへの提出書類**、**投資家向け情報**ページ、または各地域の企業登録機関（英国の**Companies House**など）を確認してください。\
世界規模の企業グループや子会社については、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> これで、scope内の企業がすべてわかったはずです。次は、それらの資産を見つける方法を確認しましょう。

### **ASN**

自律システム番号（**ASN**）は、**Internet Assigned Numbers Authority（IANA）**が**自律システム（AS）**に割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確なポリシーを持つ**IPアドレス**の**ブロック**で構成され、単一の組織によって管理されますが、複数の事業者で構成される場合もあります。

**企業にASNが割り当てられているか**を調べると、**IP範囲**を特定するうえで役立ちます。**scope**内のすべての**ホスト**に対して**脆弱性テスト**を実施し、これらのIP内にある**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、企業の**名前**、**IP**、または**ドメイン**を使って**検索**できます。\
**企業の所在地によっては、以下のリンクからさらに情報を収集できます:** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（中南米）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、おそらく必要な情報**（IP範囲とWhois）**はすべて最初のリンクに掲載されています。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** 列挙処理は、スキャンの最後に ASN を自動的に集約して要約します。

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

組織のIP範囲は、無料APIの利用枠が限られている[ASNLookup](https://asnlookup.com/)でも調べられます。

### **脆弱性の調査**

この時点で、**スコープ内のすべての資産が分かっている**ため、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEyeなどのサービスを使って、**開いているポートを見つけたりすることもできます。**見つかったものに応じて、この本を参照し、稼働している可能性のあるさまざまなサービスのpentest方法を確認しましょう。\
**また、デフォルトのユーザー名と**パスワード**のリストを用意して、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスに対する**bruteforceを試すのも有効です。**

## ドメイン

> スコープ内のすべての企業とその資産が分かったので、次はスコープ内のドメインを見つけましょう。

_以下で紹介する手法ではサブドメインも見つかることがあります。その情報を軽視しないでください。_

まず、各企業の**メインドメイン**を探しましょう。たとえば、_Tesla Inc._の場合は_tesla.com_です。

### **Reverse DNS**

ドメインのIP範囲がすべて分かっているので、それらの**IPに対してreverse DNS lookupを行い、スコープ内のドメインをさらに見つけられるか試す**ことができます。被害者のDNSサーバーか、よく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使ってみましょう。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報には[SecurityTrails](https://securitytrails.com/)も利用できますが、過去のDNSデータを利用するには有料プランが必要です。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)などのツールを使うと、reverse lookupと情報の付加を自動化できます。

### **Reverse Whois (loop)**

**whois**には、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**が数多く含まれています。さらに興味深いのは、これらの項目を使って**reverse whois lookup**を行うと、**企業に関連する他の資産**を見つけられることです（たとえば、同じメールアドレスが登録されている他のwhoisレジストリなど）。\
次のようなオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebおよびAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**のWebインターフェース。有料API。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回まで無料**で検索可能）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 現在のDNS/サブドメイン情報に限り、APIを無料で利用できます。過去の情報やreverse lookupには有料プランが必要です。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 登録時にAPIクレジットを500回分無料で利用できます。その後は有料です。

[**DomLink** ](https://github.com/vysecurity/DomLink)を使って、この作業を自動化できます（whoxy API keyが必要です）。\
[amass](https://github.com/owasp-amass/amass)を使って、reverse whoisの探索を自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法を使ってさらにドメイン名を発見できます。**

### **Trackers**

2つの異なるページで**同じtrackerの同じID**が見つかった場合、**両方のページ**は**同じチームによって管理されている**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**が見つかった場合です。

これらのtrackerなどを検索できるページやツールがいくつかあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **有料**のWebおよびAPIサービス（[料金](https://www.stackscan.com/pricing)）。現在、無料プランは案内されていません。tracker IDに限らず、配信されているアセットを手がかりに調査できます。スクリプトのパス、セルフホストされているバンドル名、アセットの読み込み元ホストなどを使って、それを含むすべてのサイトを見つけられます。

APIは単一ドメインのスタックを返します。これは、候補となるアセットが同じ資産群に属していることを確認するのに役立ちます。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各テクノロジーをカテゴリとともに返します。Asset pivoting は現在 Web のみ対応しており、API ではドメインごとの検索が可能です。

### **Favicon**

同じ favicon アイコンのハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じですか？ これを実行するのが、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) ツールです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![favicon hashを共有するドメインの発見に使用したFavihashの結果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使うと、ターゲットと同じfaviconのハッシュを持つドメインを発見できます。

![同じfavicon hashを持つドメインの発見に使用したfavihashの出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanやFOFAのpivotとして使い、同じテクノロジーのほかの公開インスタンスを見つけます。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Webサイトのfavicon bytes（**base64エンコード**されたもの）に対するMMH3を使って、**favicon hashを計算**できます。

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

[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使って、大規模に favicon hash を取得し、Shodan/Censys でピボットすることもできます。

favicon fingerprint は手がかりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトなため、衝突、アイコンの使い回し、意図的な偽装が起こり得ます。
- **`/favicon.ico` 以外も調べる**: framework/build のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTML の `<link rel="icon">` タグを確認します。
- **静的アセットは WAF/SSO/IdP の制御下でも到達可能な場合がある**: アイコンを直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、cache header を確認します。
- **周辺のシグナルで一致を検証する**: title、HTML/body hash、header、TLS certificate の subject/SAN、product component、公開ポートを比較します。
- **HTML/body hash でクラスタリングする**: 一貫した template は fingerprint の信頼性を高めます。template が混在している場合は、汎用または共有アイコンの可能性があります。
- **無関係な signature、ポート、product 間で同じ hash が見つかった場合は、honeypot または placeholder の可能性を考慮する。**
- **判別が難しい target では、実際のページと存在しないパス（例: `/_favicon_probe_<8-hex>`）を比較する**: hosting または parking の応答が一致すれば、同じアイコンが使われている理由を説明できる場合があります。
- **favicon hash を product や CPE に対応付けた Nuclei の検出ルールまたは公開データセットを使って、初期トリアージを行う。**
- **IP 中心のカバレッジの限界を忘れない**: CDN 配下、SNI ルーティング、anycast、ドメインのみの surface は、Shodan のようなデータセットから漏れる場合があります。

### **著作権表示 / 固有の文字列**

同じ組織内の異なる web サイト間で共有されている可能性のある**文字列**を、Web ページ内から検索します。**著作権表示**はその好例です。その文字列を**google**、他の**browser**、または**shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT の時刻**

次のような cron job を設定するのは一般的です。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプやcertificate-transparencyログ上の位置を照合すると、関連するドメインが明らかになることがあります。<sup>[[6]](#references)</sup>

**certificate transparency**ログを直接使う方法もあります:

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使って、**同じDMARC情報を共有するドメインやサブドメイン**を見つけられます。\
ほかにも、[**dmarcian**](https://dmarcian.com/)が役立つサービスです。

### **Passive Takeover**

放棄されたAレコードは、cloud providerがIPを再割り当てすると到達可能になることがあります。参照されている調査では、インスタンスを作成し、そのアドレスをpassive DNSデータと照合する機会利用型の手順が示されています。takeoverのシナリオをテストするのは、許可された範囲内に限ってください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する発見手法を繰り返してください。それぞれの結果から、最初に調査を始めたドメインだけでは見つからなかった追加の証明書名、passive DNS上の関連性、faviconの一致、組織識別子が明らかになることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織の名前はすでに分かっています。Shodanでは、`org:"Tesla, Inc."`のように検索できます。見つかったホストのTLS証明書を確認し、予期しない新しいドメインがないか調べましょう。

メインWebページの**TLS証明書**にアクセスして**Organization name**を取得し、その名前を使って、**Shodan**が認識しているすべてのWebページの**TLS証明書**を`ssl:"Tesla Motors"`のようなフィルターで検索することもできます。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使います。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。とても優れています。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決できる、またはtakeover可能な**古くて忘れられたレコード**を見つけるのに役立ちます。次を確認してください:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **脆弱性の調査**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)がないか確認してください。企業が**あるドメインを使っているものの**、**所有権を失っている**場合があります。（十分に安ければ）そのドメインを登録し、企業に知らせましょう。

資産の調査ですでに見つかったものとは**異なるIPを持つドメイン**が見つかった場合は、NessusやOpenVASを使った**基本的な脆弱性スキャン**と、**nmap/masscan/shodan**を使った[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働しているサービスに応じて、**この本にある、そのサービスを「攻撃」するための手法**を利用できます。\
_ドメインがクライアントの管理下にないIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## Subdomains

> スコープ内のすべての企業、それぞれの企業のすべての資産、そして企業に関連するすべてのドメインが分かりました。

見つかった各ドメインについて、可能なサブドメインをすべて見つける段階です。

> [!TIP]
> ドメインを見つけるためのツールや手法の中には、サブドメインの発見にも役立つものがあります。

### **DNS**

**DNS**レコードから**サブドメイン**を取得してみましょう。**Zone Transfer**も試してください（脆弱な場合は報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

サブドメインの発見にとどまらず、インフラ、評判、漏洩記録、情報のエンリッチメントを対象とするAPIやプラットフォームについては、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

多くのサブドメインを最速で見つける方法は、外部ソースを検索することです。最もよく使われる**ツール**は次のとおりです（より良い結果を得るには、API keysを設定してください）。


- [**BBOT**](https://github.com/blacklanternsecurity/bbot)

```bash
# subdomains
bbot -t tesla.com -f subdomain-enum

# subdomains (passive only)
bbot -t tesla.com -f subdomain-enum -rf passive

# subdomains + port scan + web screenshots
bbot -t tesla.com -f subdomain-enum -m naabu gowitness -n my_scan -o .
```

- [**Amass**](https://github.com/owasp-amass/amass)

```bash
amass enum [-active] [-ip] -d tesla.com
amass enum -d tesla.com | grep tesla.com # To just list subdomains
```

- [**subfinder**](https://github.com/projectdiscovery/subfinder)

```bash
# Subfinder, use -silent to only have subdomains in the output
./subfinder-linux-amd64 -d tesla.com [-silent]
```

- [**findomain**](https://github.com/Findomain/Findomain)

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

サブドメインの検索に直接特化していなくても、サブドメインの発見に役立つ**興味深いツール/API**もあります。たとえば次のようなものです。

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 無料 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): WebをクロールしてJSファイルを探し、そこからサブドメインを抽出します。

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

- [**Censys サブドメイン検索ツール**](https://github.com/christophetd/censys-subdomain-finder)

```bash
export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
python3 censys-subdomain-finder.py tesla.com
```

- [**DomainTrail.py**](https://github.com/gatete/DomainTrail)

```bash
python3 DomainTrail.py -d example.com
```

- [**SecurityTrails**](https://securitytrails.com/) は、現在の DNS およびサブドメインデータに対する無料の API アクセスを一部提供しています。過去の DNS/IP データには有料プランが必要です。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bountyプログラムに関連するすべてのサブドメインを無料で**提供しています。このデータには [chaospy](https://github.com/Moaaz-0x/chaospy) を使ってアクセスすることもできます。また、このプロジェクトが使用するスコープは [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) から確認できます。

これらのツールの多くを**比較**したものはこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

サブドメイン名として考えられる名前を使って DNS サーバーに brute-force を行い、新しい**サブドメイン**を見つけてみましょう。

この作業には、次のような**一般的なサブドメイン用 wordlist**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼できる DNS resolver の IP も必要です。信頼できる DNS resolver のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使ってフィルタリングできます。または、こちらを使用できます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最も推奨されるツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初のツールです。非常に高速ですが、false positive が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster)：これは、resolverを1つだけ使うようです。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、goで書かれた `massdns` のラッパーです。アクティブなブルートフォースによる有効なサブドメインの列挙や、ワイルドカードを考慮したサブドメインの解決、簡単な入出力に対応しています。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用して、ドメイン名を非同期に brute force します。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### DNSブルートフォース第2ラウンド

オープンソースの情報収集やブルートフォースでサブドメインを見つけた後、見つかったサブドメインの別パターンを生成して、さらに多くのサブドメインを探すことができます。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** ドメインとサブドメインを指定すると、その順列を生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、組み合わせを生成します。
  - [**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)からgoaltdnsの組み合わせ生成用**ワードリスト**を入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、組み合わせを生成します。permutations fileが指定されていない場合、gotatorは独自のものを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの候補を生成するだけでなく、名前解決も試みます（ただし、前述のツールを使う方がおすすめです）。
  - altdns の permutations **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を行う別のツールです。このツールは結果を brute force します（DNSワイルドカードには対応していません）。
  - dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンから新たなサブドメイン候補名を**生成**し、さらにサブドメインを発見できるか試します。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、名前解決を試す候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な、DNS応答に基づくアルゴリズムを組み合わせたサブドメインのブルートフォースファザーです。カスタマイズしたワードリストや過去のDNS/TLSレコードなど、与えられた入力データを利用して、対応するドメイン名を正確に生成し、DNSスキャンで得た情報に基づいてループ処理でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン発見ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各段階を組み合わせ、再現可能なサブドメイン列挙を行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つまたは複数のWebページ**を含むIPアドレスが見つかった場合、**OSINTソース**でそのIP上のドメインを探すか、そのIP上で**VHostのドメイン名をbrute force**して、**同じIP上にある他のサブドメインのWebサイトを見つける**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter)**や他のAPIを使って、IP上のVHostsを見つける**ことができます。

**Brute Force**

Webサーバーにサブドメインが隠れている可能性がある場合、brute forceを試すことができます。

名前ベースのvhostでは、`Host`ヘッダーをfuzzし、ffufのauto-calibrationを使ってデフォルトのレスポンスを除外します。<sup>[[2]](#references)</sup>

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
> この手法を使えば、内部/非公開のエンドポイントにアクセスできることもあります。

### **CORS Brute Force**

有効なドメイン/サブドメインが_**Origin**_ヘッダーに設定されている場合にのみ、_**Access-Control-Allow-Origin**_ヘッダーを返すページが見つかることがあります。このような場合、この挙動を悪用して新たな**サブドメイン**を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains**を探す際は、何らかの**bucket**を**指している**かどうかに注意し、その場合は[**権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**。**\
また、この時点でスコープ内のすべてのドメインが分かっているはずなので、[**考えられるbucket名をbrute forceし、権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

### **モニタリング**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)のように、**Certificate Transparency** Logsを監視することで、ドメインに**新しいsubdomains**が作成されたかどうかを**監視**できます。

### **脆弱性の調査**

[**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**subdomain**が何らかの**S3 bucket**を指している場合は、[**権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

資産の発見時にすでに見つけたものとは**異なるIPを持つsubdomain**を見つけた場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働中のサービスに応じて、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_場合によっては、subdomainがクライアントの管理下にないIP上でホストされており、スコープ外であることに注意してください。気をつけてください。_

## IPs

初期段階で、**いくつかのIP範囲、ドメイン、subdomainsを見つけている**かもしれません。\
それらの範囲と**ドメイン/subdomains（DNSクエリ）から、すべてのIPを集める**段階です。

以下のようなサービスを利用すると、**ドメインやsubdomainsで過去に使われていたIP**も見つけられます。これらのIPは現在もクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられるかもしれません。

- [**SecurityTrails**](https://securitytrails.com/)（過去のDNS/IPデータには有料プランが必要）

[**hakip2host**](https://github.com/hakluke/hakip2host)ツール、または[**NetAPI**](https://netapi.com/lookup-ip/)のようなオンラインのreverse IP lookupを使って、特定のIPアドレスを指すドメインを調べることもできます。

### **脆弱性の調査**

**CDNに属さないすべてのIPをport scanしてください**（CDNでは興味深いものが見つかる可能性はかなり低いため）。検出した稼働中のサービスから、**脆弱性を見つけられる**可能性があります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を参照してください。

## Web servers hunting

> すべての企業とその資産を特定し、スコープ内のIP範囲、ドメイン、subdomainsが分かりました。次はweb serversを探します。

これまでの手順ですでに、検出した**IPやドメインのrecon**を実施しているはずなので、**考えられるweb serversをすべて見つけている**かもしれません。ただし、まだ見つけていない場合に備えて、ここではスコープ内のweb serversを**すばやく探す方法**をいくつか紹介します。

この手順は**web appsの発見に重点を置いている**点に注意してください。そのため、スコープで**許可されている場合**は、**脆弱性スキャン**と**port scan**も実施してください。

[**masscan**を使ってweb serversに関連する**open ports**をすばやく発見する方法はこちら](../pentesting-network/index.html#http-port-discovery)。\
web serversの調査に使いやすいツールとして、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)があります。ドメインのリストを渡すと、port 80（http）と443（https）への接続を試みます。さらに、ほかのポートも試すよう指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **スクリーンショット**

スコープ内に存在する**すべてのWebサーバー**（企業の**IP**、およびすべての**ドメイン**と**サブドメイン**）を特定できたら、次に何から始めればよいのかわからないかもしれません。そこで、簡単にするため、まずはすべてのスクリーンショットを撮ってみましょう。**メインページ**を**見てみる**だけで、より**脆弱性がある可能性の高い**、**不審な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を利用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を確認すれば、**脆弱性が含まれていそうなもの**と、そうでないものを判別できます。

## パブリッククラウドのアセット

企業に属する可能性のあるクラウドアセットを見つけるには、まず**その企業を特定できるキーワードのリスト**を用意します。たとえば、暗号資産企業の場合は、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、**バケット名によく使われる単語**のワードリストも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**組み合わせ**を生成します（詳細は[**2回目のDNSブルートフォース**](#second-dns-bruteforce-round)を参照）。

生成したワードリストを使い、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または**[**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを利用できます。**

Cloud Assetsを探す際は、**AWSのバケットだけでなく、ほかのものも探す**ことを忘れないでください。

### **脆弱性の調査**

**公開されたバケットや露出したCloud Functions**などを見つけたら、アクセスして、どのような情報が得られるか、悪用できるかを確認してください。

## メールアドレス

スコープ内の**ドメイン**と**サブドメイン**があれば、メールアドレスの**調査を始める**ために必要なものはほぼ揃っています。企業のメールアドレスを見つけるのに、私が特に効果的だと感じた**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の調査**

メールアドレスは、後で**Webログインや認証サービス（SSHなど）をブルートフォースする**際に役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIを使うと、メールアドレスの持ち主についてより多くの**情報**を得られるため、フィッシングキャンペーンに役立ちます。

## 認証情報のリーク

**ドメイン**、**サブドメイン**、および**メールアドレス**があれば、それらのメールアドレスに関連する過去の認証情報のリークを調査できます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の調査**

**有効な認証情報のリーク**を見つけられれば、簡単に成果を得られます。

## シークレットのリーク

認証情報のリークは、**機密情報が漏洩・販売された**企業へのハッキングに関連しています。しかし、企業は、情報がこれらのデータベースに含まれていない**別のリーク**の影響を受けていることもあります。

### Githubのリーク

認証情報やAPIキーは、**企業**や、その企業で働く**ユーザー**の**公開リポジトリ**からリークしていることがあります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**ツール**を使えば、**組織**とその**開発者**の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/gitleaks/gitleaks)を自動的に実行できます。

**Leakos**は、**テキスト**として渡されたすべての**URL**に対して**gitleaks**を実行する用途にも使えます。Webページにもシークレットが含まれていることがあるためです。

#### Github Dorks

組織内で検索する**GitHub dorks**の候補については、[GitHub dorks and leaksのページ](github-leaked-secrets.md)を確認してください。

### Pasteサイトのリーク

攻撃者や従業員が、企業の情報をpasteサイトに**公開する**ことがあります。**機密情報**が含まれているとは限りませんが、調査する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使えば、80以上のpasteサイトを一度に検索できます。

### Google Dorks

古くても有用なGoogle dorksは、**公開されるべきでない情報の発見**に役立ちます。問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に、手動では実行できないほど**数千件**ものクエリが含まれていることです。そこで、お気に入りの10件を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks)**などのツールを使って、すべて実行できます**。

_通常のGoogleブラウザーを使ってデータベース全体を実行しようとするツールは、Googleにすぐブロックされるため、いつまでたっても完了しないことに注意してください。_

### **脆弱性の調査**

**有効な認証情報やAPIトークンのリーク**を見つけられれば、簡単に成果を得られます。

## 公開コードの脆弱性

企業が**オープンソースコード**を公開しているとわかったら、そのコードを**分析**して**脆弱性**を探すことができます。

**言語によって**使える**ツール**は異なります。[ソースコードレビュー用ツール](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

公開リポジトリを**スキャン**できる無料サービスもあります。たとえば、次のサービスがあります。

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentestingの手法**](../../network-services-pentesting/pentesting-web/index.html)

bug hunterが発見する**脆弱性の大半**は**Webアプリケーション**に存在します。そこでこの段階では、**Webアプリケーションのテスト手法**について説明します。詳細は[**こちら**](../../network-services-pentesting/pentesting-web/index.html)をご覧ください。

また、[**Web自動スキャナーのオープンソースツール**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションも特に取り上げておきます。非常に深刻な脆弱性を見つけるものと期待すべきではありませんが、**ワークフローに組み込んで、Webに関する初期情報を得る**のに便利です。

## まとめ

> おめでとうございます！ここまでで、基本的な**列挙作業はすべて**完了しました。とはいえ、これはあくまで基本です。さらに多くの列挙を行うことができます（後ほど、より多くの手法を紹介します）。

ここまでに、次のことを行いました。

1. スコープ内の**企業**をすべて特定した
2. 企業に属する**アセット**をすべて特定した（スコープ内であれば、脆弱性スキャンも実施した）
3. 企業に属する**ドメイン**をすべて特定した
4. ドメインの**サブドメイン**をすべて特定した（subdomain takeoverの可能性は？）
5. スコープ内の**IP**をすべて特定した（CDN経由のものと、**CDN経由でない**もの）
6. **Webサーバー**をすべて特定し、スクリーンショットを撮った（詳しく調べる価値のある不審なものは？）
7. 企業に属する可能性のある**パブリッククラウドのアセット**をすべて特定した
8. **メールアドレス**、**認証情報のリーク**、**シークレットのリーク**を調査した。これらは簡単に**大きな成果を得る**手がかりになり得る
9. 見つけたすべてのWebサイトに対して**Pentesting**を行った

## **Reconを自動化する総合ツール**

指定したスコープに対して、ここで提案した作業の一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません



## References

- [1] [Jason Haddix – Bug Hunterの手法 v4.0: Recon編](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Faviconについて: ブラウザーアイコンから攻撃対象領域のインテリジェンスまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.icoを武器化する: Bug Bounty、OSINTなどへの活用](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyに対する時間相関攻撃によるドメインの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – パッシブな乗っ取り: 高額なsubdomain takeoverキャンペーンの発見と再現](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: サブドメイン列挙の独自手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – サブドメインをすべて発見するワークフロー、その1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Trickestの自動ワークフローを使ったサブドメインの総当たり探索、その2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
