# 外部偵察の方法論

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある企業に属するものはすべてスコープ内だと聞き、その企業が実際に何を所有しているのかを把握したいとします。

このフェーズの目的は、**主要企業が所有するすべての企業**を特定し、次にそれらの企業の**すべての資産**を特定することです。そのために、以下を行います。<sup>[[1]](#references)</sup>

1. 主要企業の買収先を調べ、スコープ内の企業を特定する。
2. 各企業のASN（あれば）を調べ、各企業が所有するIP範囲を特定する。
3. reverse whois lookupを使い、最初の企業に関連する他のエントリ（組織名、ドメインなど）を検索する（再帰的に実施可能）。
4. shodanの`org`フィルターや`ssl`フィルターなど、他の手法を使って別の資産を検索する（`ssl`の手法は再帰的に実施可能）。

### **買収**

まず、**主要企業が所有する他の企業**を把握する必要があります。\
方法の1つは、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスして**主要企業を検索**し、「**acquisitions**」を**クリック**することです。そこには、主要企業が買収した他の企業が表示されます。\
別の方法として、主要企業の**Wikipedia**ページにアクセスし、**acquisitions**を検索します。\
公開企業の場合は、**SEC/EDGARへの提出書類**、**投資家向け広報**ページ、または各国の企業登記簿（例：英国の**Companies House**）を確認します。\
グローバル企業グループや子会社を調べるには、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、スコープ内のすべての企業が分かったはずです。次に、それらの資産を見つける方法を確認しましょう。

### **ASN**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確なポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織が管理していますが、複数の事業者で構成される場合もあります。

**企業にASNが割り当てられているか**を調べると、その**IP範囲**を特定するうえで役立ちます。**スコープ**内の**すべてのホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、企業**名**、**IP**、または**ドメイン**から**検索**できます。\
**企業の地域によっては、データ収集に役立つ次のリンクがあります：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、役立つ情報**（IP範囲とWhois）は、すでに最初のリンクに掲載されている可能性が高いです。

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** enumeration はスキャン終了時に ASNs を自動的に集約して要約します。

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

組織のIP範囲は、無料APIの利用枠が限られている[ASNLookup](https://asnlookup.com/)を使って調べることもできます。

### **脆弱性を探す**

この時点で、**スコープ内のすべての資産が判明している**ため、許可されていれば、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEyeなどのサービスを使って、**open portを見つけたりすることもできます。**見つかったものに応じて、本書で実行中のさまざまなサービスをpentestする方法を確認してください。\
**また、デフォルトの** username **と** password **のリストを用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスに対して** bruteforce **を試すのも有効です。**

## ドメイン

> スコープ内の企業とその資産がすべて判明しました。次は、スコープ内のドメインを見つけましょう。

_以下で紹介する手法ではsubdomainも見つかる可能性があることに注意してください。この情報を軽視すべきではありません。_

まず、各企業の**メインドメイン**を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

ドメインのIP範囲がすべて判明したら、それらの**IPに対してreverse DNS lookup**を実行し、**スコープ内のドメインをさらに見つけられる**可能性があります。被害者のDNSサーバー、またはよく知られているDNSサーバー（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報には[SecurityTrails](https://securitytrails.com/)も利用できますが、過去のDNSデータの取得には有料プランが必要です。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)などのツールを使うと、逆引きと情報の拡充を自動化できます。

### **Reverse Whois (loop)**

**whois**には、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**が数多く含まれています。さらに興味深いのは、これらの項目を使って**reverse whois lookup**を行うと、**その企業に関連する他の資産を見つけられる**ことです（たとえば、同じメールアドレスが登録されている別のwhoisレコード）。\
次のオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebとAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**のWebインターフェース。APIは有料。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回まで無料**）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 現在のDNS/サブドメインについては無料APIアクセスに制限があります。過去のデータやreverse lookupには有料プランが必要です。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 登録時にAPIクレジット500件が無料。以降は有料。

[**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API keyが必要）を使って、この作業を自動化できます。\
[amass](https://github.com/owasp-amass/amass)を使って、reverse whoisの探索を自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法でさらに多くのドメイン名を発見できます。**

### **Trackers**

2つの異なるページで**同じtrackerの同じID**が見つかった場合、**両方のページ**は**同じチームによって管理されている**と考えられます。\
たとえば、複数のページで同じ**Google Analytics ID**または同じ**Adsense ID**が見つかった場合です。

これらのtrackerなどを検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **有料**のWebおよびAPIサービス（[料金](https://www.stackscan.com/pricing)）。現在、無料プランは案内されていません。tracker IDに限らず、配信される任意のアセットを手がかりに関連サイトを探せます。たとえば、スクリプトのパス、セルフホストされたbundle名、アセットの読み込み元ホストなどを指定すると、それを含むすべてのサイトが返されます。

APIは単一ドメインの技術スタックを返すため、候補となるアセットが同じサイト群に属していることの確認に役立ちます。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各テクノロジーを、そのカテゴリとともに返します。Asset pivoting は現在 Web のみで利用でき、API ではドメインごとの検索に対応しています。

### **ファビコン**

同じファビコンのアイコンハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じですか？ これを実現するのが、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) ツールです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、ターゲットと同じfavicon hashを持つドメインを見つけられます。

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanまたはFOFAのpivotとして使い、同じtechnologyのほかの公開インスタンスを見つけましょう。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Webサイトのfavicon bytesを**base64-encoded**したものに対するMMH3で、**favicon hashを計算**する方法は次のとおりです：

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

大規模に favicon hash を取得するには、[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）も使えます。その後、Shodan/Censysでピボットします。

favicon fingerprint は手がかりとして扱い、周辺のシグナルを使って検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3はコンパクトなため、衝突、アイコンの使い回し、意図的な偽装が起こり得ます。
- **`/favicon.ico` 以外も調べる**: framework/build のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTMLの`<link rel="icon">`タグを確認します。
- **WAF/SSO/IdP の制御下でも静的 asset にアクセスできる場合がある**: アイコンを直接リクエストし、`ETag`、`Last-Modified`、redirect、cache header を確認します。
- **周辺のシグナルで一致を検証する**: title、HTML/body hash、header、TLS certificate の subject/SAN、product component、公開ポートを比較します。
- **HTML/body hash でクラスタリングする**: 一貫した template は fingerprint の確度を高めます。template が混在していれば、汎用または共有アイコンの可能性があります。
- **無関係な signature、port、product にまたがって hash が現れる場合は、honeypot または placeholder の可能性を考慮する。**
- **判断が難しい target では、実際のページと存在しないパス（例: `/_favicon_probe_<8-hex>`）を比較する**: hosting または parking の応答が一致すれば、アイコンが共有されている理由を説明できる場合があります。
- **favicon hash を product や CPE に対応付けた Nuclei の detection rule や公開 dataset を使い、初期トリアージを行う。**
- **IP中心のカバレッジの限界に注意する**: CDN経由、SNI routing、anycast、domainのみの surface は、Shodanのような dataset から漏れている場合があります。

### **Copyright / 固有文字列**

Webページ内で、同じ組織の異なるWebサイト間で共有されている可能性のある**文字列**を検索します。**著作権表示**は、その好例です。その文字列を**google**、他の**browser**、さらには**shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT 時刻**

次のような cron job を設定するのは一般的です。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプやCertificate Transparencyログの位置を相関させると、関連するドメインが見つかることがあります。<sup>[[6]](#references)</sup>

**Certificate Transparency**ログを直接使う方法もあります。

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使うと、**同じDMARC情報を共有するドメインやサブドメイン**を見つけられます。\
もう一つ便利なサービスは[**dmarcian**](https://dmarcian.com/)です。

### **Passive Takeover**

放置されたAレコードは、cloud providerがIPを再割り当てすると、アクセス可能になることがあります。引用されている調査では、インスタンスを作成し、そのアドレスをPassive DNSデータと照合する機会主導型の手順が紹介されています。takeoverのシナリオは、許可された範囲内でのみテストしてください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインが見つかるたびに、該当する探索の切り口を繰り返してください。それぞれの結果から、元のseedからは見えなかった追加の証明書名、Passive DNSの関連性、faviconの一致、組織識別子が見つかることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織名はすでにわかっています。次のようにShodanで検索できます: `org:"Tesla, Inc."` 見つかったホストのTLS証明書を調べ、新たな予期しないドメインがないか確認してください。

メインWebページの**TLS証明書**にアクセスして**組織名**を取得し、その名前を**Shodan**が把握しているすべてのWebページの**TLS証明書**から検索できます。フィルター `ssl:"Tesla Motors"` を使うか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使用してください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決できる、またはtakeover可能な**古い忘れられたレコード**を見つけるのに便利です。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **脆弱性の調査**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)がないか確認してください。企業が**ドメインを使用しているものの**、**所有権を失っている**可能性があります。（十分に安ければ）そのドメインを登録し、企業に知らせましょう。

資産の探索ですでに見つけたものとは異なるIPを持つ**ドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行してください。稼働しているサービスによっては、**この本に「攻撃」するための手法が載っています**。\
_ドメインがクライアントの管理下にないIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## サブドメイン

> スコープ内の企業、各企業のすべての資産、そして企業に関連するすべてのドメインがわかりました。

見つかった各ドメインのサブドメインを可能な限りすべて見つけましょう。

> [!TIP]
> ドメインを見つけるツールや手法の中には、サブドメインの発見にも役立つものがあることに注意してください。

### **DNS**

**DNS**レコードから**サブドメイン**を探してみましょう。**Zone Transfer**も試してください（脆弱な場合は報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

サブドメインの発見以外にも、インフラ、レピュテーション、漏洩記録、エンリッチメントを扱うAPIやプラットフォームについては、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

大量のサブドメインを最も素早く取得する方法は、外部ソースを検索することです。最もよく使われる**ツール**は次のとおりです（より良い結果を得るには、APIキーを設定してください）。


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

**サブドメインの発見に特化しているわけではありませんが、サブドメインの発見に役立つ可能性がある興味深いツール/API**もあります。たとえば、次のものです。

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 無料 API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) 無料の API

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

- [**SubDomainizer**](https://github.com/nsonaniya2010/SubDomainizer) **&** [**subscraper**](https://github.com/Cillian-Collins/subscraper): Webを巡回してJSファイルを探し、そこからサブドメインを抽出します。

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

- [**SecurityTrails**](https://securitytrails.com/) は、現在の DNS と subdomains データへの限定的な無料 API access を提供します。過去の DNS/IP データには有料プランが必要です。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bounty programs に関連するすべての subdomains を無料で**提供しています。このデータには [chaospy](https://github.com/Moaaz-0x/chaospy) を使ってアクセスすることもできます。また、このプロジェクトで使用されている scope にもアクセスできます: [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs)

これらのツールの多くを**比較**したものはこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

subdomain 名として考えられる文字列を使って DNS servers を brute-force し、新しい **subdomains** を見つけてみましょう。

この作業には、次のような**一般的な subdomains wordlists** が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、優れた DNS resolvers の IP も必要です。信頼できる DNS resolvers のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolvers をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) を使ってフィルタリングします。または、こちらを使用できます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最もおすすめのツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実現した最初のツールです。非常に高速ですが、false positives が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つだけ使っていると思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、goで書かれており、active bruteforceを使って有効なサブドメインを列挙できるほか、ワイルドカード処理と簡単な入出力サポートを備え、サブドメインを解決できます。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): これも`massdns`を使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は、asyncio を使用してドメイン名を非同期に brute force します。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 第2回 DNS Brute-Force

オープンソースの情報を使い、brute-forcingによってサブドメインを見つけた後は、見つかったサブドメインの変形を生成して、さらに多くのサブドメインを探すことができます。この目的には、いくつかのツールが役立ちます。

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** ドメインとサブドメインを指定すると、組み合わせを生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、派生候補を生成します。
  - goaltdns の **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationsを生成します。permutations fileが指定されていない場合、gotatorは独自のものを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの組み合わせを生成するだけでなく、それらの名前解決も試せます（ただし、前述のツールを使う方がおすすめです）。
  - altdns の組み合わせ生成用 **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。このツールは結果を brute force します（DNS wildcard には対応していません）。
  - dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンから新たなサブドメイン候補名を生成し、さらなるサブドメインの発見を試みます。

#### スマートな permutation の生成

- [**regulator**](https://github.com/cramppet/regulator): 発見されたサブドメインから正規表現のようなパターンを学習し、名前解決する候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS 応答誘導型アルゴリズムを組み合わせたサブドメインのブルートフォースファザーです。カスタマイズしたワードリストや過去の DNS/TLS レコードなど、与えられた入力データを利用して、対応するドメイン名を正確に生成します。さらに、DNS スキャンで得られた情報に基づいてループ内で生成を繰り返し、対象を拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン発見ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各ステージを組み合わせ、再現可能なサブドメイン列挙を行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つまたは複数のWebページ**を含むIPアドレスを見つけた場合、**OSINTソース**でそのIP上のドメインを調べるか、そのIPに対してVHostのドメイン名を**brute-force**することで、**そのIP上にある別のサブドメインを探す**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **やその他のAPIを使って、IP上のVHostsを見つける**ことができます。

**Brute Force**

Webサーバーに隠れたサブドメインがあると思われる場合は、brute forceを試すことができます。

名前ベースのvhostsでは、`Host`ヘッダーをfuzzし、ffufの自動キャリブレーションを使ってデフォルトのレスポンスを除外します。<sup>[[2]](#references)</sup>

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
> この technique を使うと、internal/hidden endpoints にアクセスできる可能性もあります。

### **CORS Brute Force**

有効なドメインまたはサブドメインが _**Origin**_ ヘッダーに設定されている場合にのみ、_**Access-Control-Allow-Origin**_ ヘッダーを返すページが見つかることがあります。このような場合、この動作を悪用して新しい **サブドメイン**を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **バケットのブルートフォース**

**subdomains**を探すときは、何らかの**バケットを指している**ものがないか確認し、見つかった場合は[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
この時点では対象範囲内のドメインがすべて分かっているはずなので、[**バケット名をブルートフォースして、権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **監視**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)のように、**Certificate Transparency** Logsを監視して、ドメインの**新しいsubdomains**が作成されていないかを**監視**できます。

### **脆弱性の調査**

[**subdomain takeovers**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**subdomain**が**S3 bucket**を指している場合は、[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

資産の調査ですでに見つけたものとは**異なるIPを持つsubdomain**を見つけた場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働しているサービスに応じて、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_ただし、subdomainがクライアントの管理外のIP上でホストされている場合があり、その場合は対象範囲に含まれないので注意してください。_

## IPs

初期段階で、**いくつかのIP範囲、ドメイン、subdomainsを見つけている**かもしれません。\
それらの範囲に含まれるIPと、**ドメイン/subdomainsのIP（DNSクエリ）をすべて集める**段階です。

以下のようなサービスを使うと、**ドメインやsubdomainsが過去に使用していたIP**も見つけられます。これらのIPは現在もクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つける手がかりになることがあります。

- [**SecurityTrails**](https://securitytrails.com/)（過去のDNS/IPデータの利用には有料プランが必要です）

ツール[**hakip2host**](https://github.com/hakluke/hakip2host)を使って、特定のIPアドレスを指すドメインを調べることもできます。

### **脆弱性の調査**

**CDNに属さないすべてのIPをport scanしてください**（CDNでは、興味深いものが見つかる可能性はかなり低いためです）。検出した稼働中のサービスに、**脆弱性が見つかる**可能性があります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を**参照してください。**

## Webサーバーの探索

> 企業とその資産をすべて把握し、対象範囲内のIP範囲、ドメイン、subdomainsも分かりました。次はWebサーバーを探します。

これまでの手順で、見つかったIPやドメインの**reconをすでに実施している**と思われるため、**考えられるWebサーバーをすべて発見済み**かもしれません。まだの場合は、対象範囲内のWebサーバーを探すための**手早い方法**をいくつか紹介します。

これは**Webアプリの発見を目的としている**点に注意してください。そのため、対象範囲で許可されている場合は、**脆弱性スキャン**と**port scanning**も実施してください。

[**masscan**を使ってWebサーバー関連の**開放ポート**を素早く見つける方法はこちら](../pentesting-network/index.html#http-port-discovery)。\
Webサーバーを探すための使いやすいツールとしては、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)があります。ドメインのリストを渡すと、ポート80（http）と443（https）への接続を試みます。また、ほかのポートも試すように指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **スクリーンショット**

スコープ内（会社の**IP**、すべての**ドメイン**および**サブドメイン**）に存在する**すべての Web サーバー**を見つけたものの、**どこから始めればいいかわからない**かもしれません。そこで、簡単にするために、まずすべてのスクリーンショットを撮りましょう。**メインページ**を**ざっと見る**だけで、**脆弱**である**可能性が高い**、**不審な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**.**を使用できます。

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を分析し、**脆弱性がありそうなもの**と、そうでないものを判定できます。

## パブリッククラウド資産

会社に属する可能性のあるクラウド資産を見つけるには、まず**その会社を特定できるキーワードのリスト**を用意しましょう。たとえば、暗号資産企業なら、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、**バケットでよく使われる単語**のワードリストも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語を使って**組み合わせ**を生成します（詳しくは[**2回目の DNS brute-force**](#second-dns-bruteforce-round)を確認してください）。

生成したワードリストを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**.**などのツールを利用できます。

Cloud Assetsを探す際は、**AWSのバケットだけでなく**、ほかのものも探してください。

### **脆弱性を探す**

**公開されているバケットや、外部に公開されたクラウド関数**などを見つけたら、**アクセス**して、どのような情報が得られるか、悪用できるかを確認しましょう。

## メールアドレス

スコープ内の**ドメイン**と**サブドメイン**がわかれば、メールアドレスの検索を始めるために必要な情報はほぼ揃っています。会社のメールアドレスを探すうえで、特に効果があった**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性を探す**

メールアドレスは後で**Webログインや認証サービス（SSHなど）へのbrute-force**や、**フィッシング**に役立ちます。また、これらのAPIからはメールアドレスの持ち主に関する**追加情報**も得られるため、フィッシングキャンペーンに利用できます。

## 認証情報のLeaks

**ドメイン、サブドメイン**、メールアドレスがあれば、それらのメールアドレスに関連する、過去にleakした認証情報を探し始められます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性を探す**

**有効なleaked認証情報**が見つかれば、簡単に成果を得られます。

## SecretsのLeaks

認証情報のleakは、**機密情報がleakして売却された**企業への攻撃に関連しています。しかし、企業は、データベースに情報が載っていない**別のleak**の被害を受けている可能性もあります。

### Github Leaks

会社の**公開リポジトリ**や、その会社で働く**ユーザー**の公開リポジトリから、認証情報やAPIがleakしている可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**ツール**を使うと、**組織**とその**開発者**の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/gitleaks/gitleaks)を自動で実行できます。

**Leakos**は、引数として渡した**URL**から取得したすべての**テキスト**に対して**gitleaks**を実行する用途にも使えます。Webページにもsecretが含まれていることがあるためです。

#### Github Dorks

組織内で検索できる**GitHub dorks**については、[GitHub dorks and leaksのページ](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や従業員が、会社のコンテンツをpasteサイトに**公開する**ことがあります。**機密情報**が含まれている場合もそうでない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpasteサイトを同時に検索できます。

### Google Dorks

古くても役に立つGoogle dorksは、**公開されるべきでない情報**を探すのに便利です。問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)には手動では実行できないほど**何千もの**検索クエリがあることです。そこで、気に入ったものを10個選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などのツールを使ってすべて実行**できます。

_通常のGoogleブラウザーを使ってデータベース全体を実行するツールは、Googleにすぐブロックされるため、最後まで実行できない点に注意してください。_

### **脆弱性を探す**

**有効なleaked認証情報**やAPIトークンが見つかれば、簡単に成果を得られます。

## 公開コードの脆弱性

会社が**オープンソースコード**を公開している場合は、それを**分析**して**脆弱性**を探せます。

**言語によって**利用できる**ツール**は異なります。[ソースコードレビュー用ツール](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

また、次のように、公開リポジトリを**スキャン**できる無料サービスもあります。

- [**Snyk**](https://app.snyk.io/)

## [**Web pentestingの方法論**](../../network-services-pentesting/pentesting-web/index.html)

bug hunterが見つける**脆弱性の大半**は**Webアプリケーション**に存在します。そこでここでは、**Webアプリケーションのテスト方法**について説明します。[**詳しい情報はこちら**](../../network-services-pentesting/pentesting-web/index.html)を参照してください。

また、[**オープンソースのWeb自動スキャナーツール**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションも特に取り上げたいと思います。非常に深刻な脆弱性の発見は期待できませんが、**ワークフローに組み込んで初期のWeb情報を取得する**のに役立ちます。

## まとめ

> おめでとうございます！ここまでで、**基本的な列挙**はすべて完了しました。基本的な内容にすぎないのは、さらに多くの列挙を実施できるからです（後で追加のテクニックを紹介します）。

すでに、次のことを完了しています。

1. スコープ内の**すべての会社**を発見
2. 会社に属する**すべての資産**を発見（スコープ内であれば、脆弱性スキャンも実施）
3. 会社に属する**すべてのドメイン**を発見
4. ドメインの**すべてのサブドメイン**を発見（subdomain takeoverの可能性は？）
5. スコープ内の**すべてのIP**を発見（CDN経由のものと、**CDN経由でないもの**）
6. **すべてのWebサーバー**を発見し、スクリーンショットを撮影（詳しく調べる価値のあるものは？）
7. 会社に属する可能性のある**パブリッククラウド資産**をすべて発見
8. **メールアドレス**、**認証情報のleaks**、**secretのleaks**から、**簡単に大きな成果を得られる可能性**を確認
9. 見つけたすべてのWebサイトを**pentesting**

## **Reconを自動化するツール**

指定したスコープに対して、提案した作業の一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## References

- [1] [Jason Haddix – Bug Hunterの方法論 v4.0：Recon編](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – faviconについて：ブラウザーアイコンから攻撃対象領域の分析まで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Bug BountyやOSINTなどに向けたfavicon.icoのweaponize](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyへの時間相関攻撃によるドメインの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なsubdomain takeoverキャンペーンの発見と再現](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：サブドメイン列挙の独自手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – サブドメインの完全な発見ワークフロー、第1部](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 自動化されたTrickestワークフローを使ったサブドメインの完全なbrute-forceによる発見、第2部](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
