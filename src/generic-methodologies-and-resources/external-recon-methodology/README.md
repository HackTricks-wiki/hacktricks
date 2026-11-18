# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## Assets discoveries

追加のOSINTおよびWeb-discoveryプロジェクトをカテゴリ別にまとめたリストについては、[Third-Party Tools and Resources](../third-party-tools-and-resources.md#osint)を参照してください。

> ある会社に属するものはすべてスコープ内だと聞き、その会社が実際に何を所有しているのか調べたいとします。

このフェーズの目的は、**親会社が所有するすべての会社**を特定し、次にそれらの会社の**すべての資産**を特定することです。そのために、以下の手順を実施します。<sup>[[1]](#references)</sup>

1. 親会社による買収を調べます。これにより、スコープ内の会社がわかります。
2. 各社のASN（存在する場合）を調べます。これにより、各社が所有するIP範囲がわかります。
3. reverse whois lookupを使って、最初のエントリに関連するほかのエントリ（組織名、ドメインなど）を検索します（再帰的に実施できます）。
4. shodanの`org`および`ssl`フィルターなど、ほかの手法を使って追加の資産を検索します（`ssl`の手法は再帰的に実施できます）。

解決済みのサブドメインからHTTP crawlingやport discoveryへ引き継ぐ手順については、[Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline)を参照してください。

### **Acquisitions**

まず、**親会社が所有するほかの会社**を把握する必要があります。\
方法の1つは、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**親会社を検索**して、**「acquisitions」をクリック**することです。ここで、親会社が買収した会社を確認できます。\
別の方法は、親会社の**Wikipedia**ページにアクセスし、**acquisitions**を検索することです。\
上場企業については、**SEC/EDGARへの提出書類**、**投資家向け情報**のページ、または各国の企業登記簿（英国の**Companies House**など）を確認してください。\
グローバルな企業グループや子会社を調べるには、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> これで、スコープ内の会社がすべてわかったはずです。次に、それらの資産を見つける方法を確認しましょう。

### **ASNs**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスについて明確に定められたポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織が管理しますが、複数の事業者で構成される場合もあります。

**会社にASNが割り当てられているか**を調べると、**IP範囲**を特定するうえで役立ちます。**スコープ**内の**すべてのホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、会社の**名前**、**IP**、または**ドメイン**から**検索**できます。\
**会社の所在地によっては、より多くのデータを集めるために次のリンクが役立ちます：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、役立つ情報**（IP範囲とWhois）**はおそらく最初のリンクにすべて掲載されています。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot) の enumeration は、スキャンの最後に ASN を自動的に集約して要約します。

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

組織のIP範囲は[ASNLookup](https://asnlookup.com/)でも調べられます。無料APIの利用枠には制限があります。

### **脆弱性の調査**

この時点で、**スコープ内のすべての資産が判明している**ため、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEyeなどのサービスを使って**開いているポートを調べたり**することもできます。**見つかった内容に応じて**、この本で該当するサービスのpentest方法を確認してください。\
**また、デフォルトの**username **と** password **のリストを用意して、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスの** bruteforce **を試すのも有効です。**

## ドメイン

> スコープ内のすべての企業とその資産が判明したので、次はスコープ内のドメインを見つけます。

_以下に示す手法ではサブドメインも見つかる可能性があり、その情報も軽視すべきではないことに注意してください。_

まず、各企業の**メインドメイン**を調べます。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

ドメインのIP範囲をすべて把握しているので、それらの**IPに対してreverse DNS lookupを実行し、スコープ内のドメインをさらに見つける**ことができます。被害者のDNSサーバー、またはよく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報の取得には[SecurityTrails](https://securitytrails.com/)も利用できますが、過去のDNSデータには有料プランが必要です。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)などのツールを使うと、逆引きと情報の付加を自動化できます。

### **Reverse Whois (loop)**

**whois**では、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**を多く見つけられます。さらに興味深いのは、これらの項目を使って**reverse whois lookup**を行うと、**会社に関連する他の資産**を見つけられることです（たとえば、同じメールアドレスが登録されている他のwhoisレジストリなど）。\
次のようなオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebおよびAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**のWebインターフェース。有料API。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回まで無料**）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 現在のDNS／サブドメインについてはAPIを限定的に無料で利用できます。過去データや逆引きには有料プランが必要です。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 登録時にAPIクレジットを500回分無料で取得できます。それ以降は有料です。

[**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy APIキーが必要）を使って、この作業を自動化できます。\
[amass](https://github.com/owasp-amass/amass)でreverse whoisの探索を自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法を使ってさらにドメイン名を発見できます。**

### **Trackers**

2つの異なるページで**同じtrackerの同じID**を見つけた場合、**両方のページ**は**同じチームが管理している**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**を見つけた場合です。

trackerなどを検索できるページやツールには、次のようなものがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **有料**のWebおよびAPIサービス（[料金](https://www.stackscan.com/pricing)）。現在、無料プランは案内されていません。tracker IDだけでなく、配信されているあらゆるassetを手掛かりに調査できます。たとえば、scriptのパス、セルフホストされたbundle名、assetの読み込み元hostなどを使って、それらを含むすべてのサイトを見つけられます。

APIは単一ドメインのstackを返します。候補となるassetが同じ環境に属していることを確認するのに便利です。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各テクノロジーを、そのカテゴリとともに返します。Asset pivoting は現在 Web のみ対応しており、API ではドメインごとの検索ができます。

### **Favicon**

同じ favicon のアイコンハッシュを探すことで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) ツールが行うことです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihashの結果を使って、同じfavicon hashを共有するドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、対象と同じfavicon hashを持つドメインを発見できます。

![同じfavicon hashを持つドメインの発見に使うfavihashの出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanまたはFOFAのpivotとして使い、同じ技術を使う、ほかの公開インスタンスを見つけます。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Webサイトのfavicon bytes（**base64エンコード**されたもの）に対するMMH3を使って、**favicon hashを計算**する方法は次のとおりです。

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

大規模に favicon hash を取得するには、[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）も使えます。その後、Shodan/Censys でピボットできます。

favicon fingerprint は手がかりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトなため、衝突、アイコンの使い回し、意図的な偽装があり得ます。
- **`/favicon.ico` 以外も調べる**: framework/build のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、インラインの data URL、HTML の `<link rel="icon">` タグを確認してください。
- **WAF/SSO/IdP の制御下でも静的アセットにアクセスできる場合がある**: アイコンに直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、cache header を確認してください。
- **周辺のシグナルで一致を検証する**: title、HTML/body hash、header、TLS 証明書の subject/SAN、製品コンポーネント、公開ポートを比較してください。
- **HTML/body hash でクラスタリングする**: template が一貫していれば fingerprint の信頼性が高まり、template が混在していれば汎用または共有アイコンの可能性があります。
- **無関係な signature、port、製品にまたがって hash が現れる場合は、honeypot または placeholder の可能性を考慮する。**
- **対象が曖昧な場合は、実在するページと `/_favicon_probe_<8-hex>` のような存在しないパスを比較する**: ホスティングやパーキングの応答が一致すれば、アイコンが共有されている理由を説明できる場合があります。
- **favicon hash を製品や CPE に対応付ける Nuclei の検出ルールや公開データセットを使って、初期トリアージを行う。**
- **IP 中心のカバレッジの限界を念頭に置く**: CDN 配下、SNI ルーティング、anycast、ドメインのみのサーフェスは、Shodan のようなデータセットから漏れている場合があります。

### **著作権表示 / 固有の文字列**

同じ組織内の異なる web サイト間で共有されている可能性のある**文字列**を、Web ページ内で検索します。**著作権表示**は良い例です。その文字列を **Google**、他の**ブラウザ**、あるいは **Shodan** で検索します: `shodan search http.html:"Copyright string"`

### **CRT の時刻**

次のような cron job を設定するのは一般的です。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプやCertificate Transparencyログ上の位置を照合すると、関連するドメインが見つかることがあります。<sup>[[6]](#references)</sup>

**Certificate Transparency**ログを直接使う方法もあります。

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使って、**同じDMARC情報を共有するドメインやサブドメイン**を探せます。\
ほかにも、[**dmarcian**](https://dmarcian.com/)が便利です。

### **Passive Takeover**

放置されたAレコードは、cloud providerがIPを再割り当てすると到達可能になることがあります。参照先の調査では、インスタンスを作成し、そのアドレスをpassive DNSデータと照合する機会活用型の手順が紹介されています。takeoverのシナリオは、許可された範囲内でのみテストしてください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する探索の切り口を繰り返してください。それぞれの結果から、最初の起点では見つからなかった追加の証明書名、passive DNS上の関連性、faviconの一致、組織識別子が見つかることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織の名前はすでに分かっているので、その情報を使ってShodanで検索できます。例: `org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、新たな予期しないドメインがないか調べてください。

メインのWebページの**TLS証明書**にアクセスして**組織名**を取得し、**Shodan**が把握しているすべてのWebページの**TLS証明書**からその名前を検索することもできます。フィルターは`ssl:"Tesla Motors"`です。または[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使ってください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。とても便利です。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決される、あるいはtakeover可能な**古く忘れられたレコード**を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **脆弱性の調査**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)を確認してください。会社が**あるドメインを使っているものの**、**所有権を失っている**可能性があります。十分に安ければ登録して、会社に知らせましょう。

資産探索で見つけたものとは**異なるIPを持つドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を行ってください。稼働中のサービスに応じて、**この本ではそれらを「攻撃」するためのテクニック**を紹介しています。\
_ドメインがクライアントの管理下にないIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## サブドメイン

> スコープ内のすべての会社、各社のすべての資産、そして各社に関連するすべてのドメインが分かっています。

見つかった各ドメインのサブドメインを、可能な限りすべて探す段階です。

> [!TIP]
> ドメインを探すためのツールや手法の中には、サブドメインの発見にも役立つものがあります。

### **DNS**

**DNS**レコードから**サブドメイン**を取得してみましょう。**Zone Transfer**も試してください（脆弱な場合は報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

インフラ、レピュテーション、漏洩記録、サブドメインの検出以外のエンリッチメントに対応する API やプラットフォームについては、[偵察および脅威インテリジェンス API カタログ](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

多くのサブドメインを最速で取得する方法は、外部ソースを検索することです。最もよく使われる**ツール**は次のとおりです（より良い結果を得るには API キーを設定してください）。


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

サブドメインの発見に特化しているわけではなくても、サブドメインの発見に役立つ**その他の興味深いツール/API**があります。たとえば:

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 無料 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から既知のURLを取得します。

```bash
# Get subdomains from GAUs found URLs
gau --subs tesla.com | cut -d "/" -f 3 | sort -u
```

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Webを巡回してJS filesを探し、そこからsubdomainsを抽出します。

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

- [**SecurityTrails**](https://securitytrails.com/) は、現在の DNS とサブドメインデータへの無料 API アクセスを制限付きで提供しています。過去の DNS/IP データには有料プランが必要です。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**バグバウンティプログラムに関連するすべてのサブドメイン**を無料で提供しています。このデータには [chaospy](https://github.com/Moaaz-0x/chaospy) からアクセスすることも、プロジェクトが使用しているスコープを [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) から確認することもできます。

これらのツールの多くを比較した記事はこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

DNS サーバーに対して、サブドメイン名として考えられる候補を brute-force し、新しい**サブドメイン**を探してみましょう。

この作業には、次のような**一般的なサブドメイン用 wordlist**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼性の高い DNS resolver の IP も必要です。信頼できる DNS resolver のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) でフィルタリングします。または、こちらを利用できます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最もおすすめのツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実現した最初のツールです。非常に高速ですが、false positive が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つだけ使っていると思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、Goで書かれています。active bruteforceによる有効なサブドメインの列挙や、ワイルドカードに対応したサブドメインの解決、簡単な入出力を可能にします。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns`も使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は、asyncioを使用してドメイン名を非同期にbrute forceします。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 第2回 DNS Brute-Force

オープンソースを調査し、Brute-Forceでサブドメインを発見した後は、見つかったサブドメインのバリエーションを生成して、さらに多くのサブドメインを探すことができます。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**：**ドメインとサブドメインを指定すると、パーミュテーションを生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを基に、名前のバリエーションを生成します。
  - goaltdnsのpermutation用**wordlist**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、パーミュテーションを生成します。パーミュテーションファイルが指定されていない場合、gotator は独自のものを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): subdomain の permutation を生成するだけでなく、それらの名前解決も試せます（ただし、前述のツールを使うほうがよいでしょう）。
  - altdns の permutation **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの置換、変異、変更を行う別のツールです。このツールは結果を brute force します（DNSワイルドカードには対応していません）。
  - dmut の置換用 wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンに基づいて**新たなサブドメイン候補名を生成**し、さらに多くのサブドメインの発見を試みます。

#### スマートな順列生成

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、名前解決を試みる候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的なDNS応答誘導型アルゴリズムを備えた、サブドメインのブルートフォースファザーです。カスタマイズしたwordlistや過去のDNS/TLSレコードなど、与えられた入力データを使って対応するドメイン名を正確に生成し、DNSスキャンで得られた情報を基にループ内でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **Subdomain Discovery Workflow**

Trickest workflowの例では、OSINT、DNS brute force、permutationの各段階を組み合わせ、再現可能なsubdomain enumerationを行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

subdomainに属する**1つまたは複数のWebページ**を含むIPアドレスが見つかった場合、**OSINT sources**でIPアドレスに関連するドメインを調べるか、そのIPアドレス上のVHostドメイン名を**brute force**することで、同じIPアドレス上にある他のsubdomainを**見つけられる**可能性があります。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **やその他のAPIを使って、IPアドレス上のVHostsを見つけられます**。

**Brute Force**

Webサーバー内にsubdomainが隠されている可能性がある場合は、brute forceを試せます。

名前ベースのvhostでは、`Host` headerをfuzzし、ffufのauto-calibrationを使ってデフォルトのレスポンスを除外します。<sup>[[2]](#references)</sup>

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

有効なドメイン/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような場合、この挙動を悪用して新しい **subdomains** を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**サブドメイン**を調べる際は、何らかの**bucket**を**指している**かどうかに注意し、該当する場合は[**権限を確認**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**してください。**\
また、この時点ではスコープ内のすべてのドメインが判明しているはずなので、[**bucket名をブルートフォースし、権限を確認**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)してみましょう。

### **監視**

[**sublert**](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)のように、**Certificate Transparency** Logsを監視することで、ドメインの**新しいサブドメイン**が作成されたかどうかを**監視**できます。

### **脆弱性の調査**

[**サブドメイン乗っ取り**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**サブドメイン**が**S3 bucket**を指している場合は、[**権限を確認**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)してください。

アセットの調査で見つけたものとは**異なるIPを持つサブドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働中のサービスによっては、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_サブドメインが、クライアントの管理下にないIPでホストされている場合があります。その場合はスコープ外となるため、注意してください。_

## IPs

初期段階で、**IP範囲、ドメイン、サブドメイン**がいくつか見つかっているかもしれません。\
それらの範囲内のすべてのIPと、**ドメイン／サブドメインのIP（DNSクエリ）**を**集める**段階です。

次のようなサービスを使うと、**ドメインやサブドメインで以前使われていたIP**も見つけられます。これらのIPはまだクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)の発見につながることもあります。

- [**SecurityTrails**](https://securitytrails.com/)（過去のDNS/IPデータの確認には有料プランが必要です）

ツール[**hakip2host**](https://github.com/hakluke/hakip2host)を使って、特定のIPアドレスを指すドメインを調べることもできます。

### **脆弱性の調査**

**CDNに属さないすべてのIPをport scan**してください（CDNでは興味深いものが見つかる可能性はかなり低いためです）。検出した稼働中のサービスから、**脆弱性を見つけられる**可能性があります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を確認してください。

## Webサーバーの調査

> すべての企業とそのアセットを見つけ、スコープ内のIP範囲、ドメイン、サブドメインも把握できました。次はWebサーバーを探します。

これまでの手順で、検出した**IPとドメインの調査**をすでにある程度行っており、**Webサーバーをすべて見つけている**かもしれません。まだ見つけていない場合に備えて、スコープ内のWebサーバーを探すための**手早いテクニック**をいくつか紹介します。

これは**Webアプリの発見を目的としている**ため、スコープで**許可されている場合**は、脆弱性スキャンとport scanも**実施してください**。

[**masscanを使ってWebサーバー関連のopen portを素早く見つける方法はこちら**](../pentesting-network/index.html#http-port-discovery)。\
Webサーバーの調査に使える別のツールとして、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)があります。ドメインのリストを渡すと、port 80（http）と443（https）への接続を試みます。さらに、ほかのportも試すよう指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

スコープ内に存在する**すべてのWebサーバー**（会社の**IP**、すべての**ドメイン**と**サブドメイン**）を見つけたとしても、おそらく**どこから始めればよいかわからない**でしょう。そこで、シンプルに、まずはすべてのスクリーンショットを撮ってみましょう。**メインページ**を**見るだけ**でも、**脆弱**である**可能性が高い**、**奇妙な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を**利用できます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を分析し、**脆弱性が含まれていそうなもの**とそうでないものを判定することもできます。

## Public Cloud Assets

会社に属する可能性のあるクラウドアセットを見つけるには、まず**その会社を特定するキーワードのリスト**を用意します。たとえば、暗号資産企業であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、バケットでよく使われる**一般的な単語のワードリスト**も必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語から**組み合わせ**を生成します（詳しくは[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を参照してください）。

生成したワードリストを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを利用できます。**

Cloud Assetsを探すときは、**AWSのバケットだけでなく、ほかのものも探す**ようにしてください。

### **脆弱性を探す**

**公開されたバケットやクラウド関数**などを見つけたら、**アクセス**して、どのような情報が得られるか、悪用できるかを確認しましょう。

## Emails

スコープ内の**ドメイン**と**サブドメイン**があれば、**メールアドレスの調査を始める**のに必要なものはほぼ揃っています。会社のメールアドレスを見つけるうえで、特に有効だった**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/) のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/) のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/) のAPI（無料版）

### **脆弱性を探す**

メールアドレスは、後で**Webログインや認証サービス（SSHなど）に対するbrute-force**や、**phishing**に役立ちます。さらに、これらのAPIからメールアドレスの所有者に関する**追加情報**を得られることもあり、phishingキャンペーンに役立ちます。

## Credential Leaks

**ドメイン**、**サブドメイン**、**メールアドレス**があれば、それらのメールアドレスに関連する過去の認証情報のleakを調査できます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性を探す**

**有効なleaked**認証情報を見つけられれば、簡単に成果を得られます。

## Secrets Leaks

Credential leaksは、**機密情報が漏えいして売られた**企業のハッキングに関連しています。しかし、企業は、情報がこうしたデータベースに含まれていない**別のleak**の影響を受けている可能性もあります。

### Github Leaks

会社の**公開リポジトリ**や、その会社で働く**ユーザー**の公開リポジトリから、認証情報やAPIがleakしていることがあります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**ツール**を使うと、**組織**とその**開発者**の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/gitleaks/gitleaks)を自動的に実行できます。

**Leakos**は、指定したURLの**テキスト**すべてに対して**gitleaks**を実行するのにも使えます。Webページにも秘密情報が含まれていることがあるためです。

#### Github Dorks

組織内で検索できる**GitHub dorks**については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や従業員が、paste siteに会社のコンテンツを**公開する**ことがあります。そこに**機密情報**が含まれているかどうかはわかりませんが、調査する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpaste siteを一度に検索できます。

### Google Dorks

古くても優れたGoogle dorksは、**公開されるべきではない情報を見つける**のに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)には手動で実行できないほど**何千もの**クエリが含まれていることです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などのツールで一括実行**できます。

_通常のGoogleブラウザーでデータベース全体を実行しようとするツールは、Googleにすぐにブロックされるため、処理が終わることはありません。_

### **脆弱性を探す**

**有効なleaked**認証情報やAPIトークンを見つけられれば、簡単に成果を得られます。

## Public Code Vulnerabilities

会社が**オープンソースコード**を公開しているとわかったら、それを**分析**して**脆弱性**を探すことができます。

**言語によって**使用できる**ツール**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

また、次のように**公開リポジトリをスキャン**できる無料サービスもあります。

- [**Snyk**](https://app.snyk.io/)

## [**Web Pentesting Methodology**](../../network-services-pentesting/pentesting-web/index.html)

バグハンターが見つける**脆弱性の大半**は**Webアプリケーション**に存在します。そのため、ここでは**Webアプリケーションのテスト方法**について説明します。詳しくは[**こちら**](../../network-services-pentesting/pentesting-web/index.html)をご覧ください。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションも特に紹介しておきます。非常に深刻な脆弱性を見つけることは期待できませんが、**ワークフローに組み込んで初期段階のWeb情報を得る**のに役立ちます。

## Recapitulation

> おめでとうございます！ここまでで、**基本的な列挙**はすべて完了しました。もちろん、これは基本にすぎません。さらに多くの列挙が可能です（後ほど、より多くのテクニックを紹介します）。

ここまでに、次のことを完了しています。

1. スコープ内の**すべての会社**を特定した
2. 会社に属する**すべてのアセット**を特定した（スコープ内であれば、脆弱性スキャンも実施した）
3. 会社に属する**すべてのドメイン**を特定した
4. ドメインの**すべてのサブドメイン**を特定した（subdomain takeoverはないか？）
5. スコープ内の**すべてのIP**を特定した（CDN経由のものと**CDN経由でないもの**）
6. **すべてのWebサーバー**を特定し、スクリーンショットを撮った（詳しく調べる価値のある奇妙なものはないか？）
7. 会社に属する**潜在的な公開クラウドアセット**をすべて特定した
8. **Emails**、**credential leaks**、**secret leaks**を調査した。これらは**簡単に大きな成果を得る**手がかりになる
9. 見つけたすべてのWebサイトを**Pentesting**した

## **Full Recon Automatic Tools**

指定したスコープに対して、提案した作業の一部を実行するツールはいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません



## References

- [1] [Jason Haddix – バグハンターの方法論 v4.0：Recon編](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Faviconについて：ブラウザーアイコンから攻撃対象領域のインテリジェンスまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.icoをBugBountiesやOSINTなどに活用する](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyに対する時間相関攻撃によるドメインの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なSubdomain Takeoverキャンペーンの発見と再現](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：独自のサブドメイン列挙手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – サブドメインの完全な発見ワークフロー、第1部](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 自動化されたTrickestワークフローによるサブドメインの完全なbrute-force発見、第2部](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
