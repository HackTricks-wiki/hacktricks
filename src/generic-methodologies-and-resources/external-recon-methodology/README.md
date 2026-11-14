# 外部Recon手法

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するものはすべてscope内だと聞き、その会社が実際に何を所有しているのかを把握したいとします。

このフェーズの目標は、**親会社が所有するすべての会社**を特定し、次にそれらの会社の**すべての資産**を特定することです。そのために、次の手順を実施します。<sup>[[1]](#references)</sup>

1. 親会社による買収を調べ、scope内の会社を特定します。
2. 各社のASN（あれば）を調べ、各社が所有するIP範囲を特定します。
3. reverse whois lookupを使って、最初の会社に関連する他のエントリ（組織名、ドメインなど）を検索します（再帰的に実施できます）。
4. shodanの`org`フィルターや`ssl`フィルターなど、他の手法を使って追加の資産を検索します（`ssl`を使う手法は再帰的に実施できます）。

解決済みのサブドメインからHTTP crawlingとポート検出へ移行する段階的な手順については、[Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline)を参照してください。

### **買収**

まず、**親会社が所有する他の会社**を把握する必要があります。\
1つの方法は、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスして**親会社を検索**し、「**acquisitions**」を**クリック**することです。そこに、親会社が買収した他の会社が表示されます。\
別の方法は、親会社の**Wikipedia**ページにアクセスし、**acquisitions**を検索することです。\
上場企業については、**SEC/EDGAR filings**、**investor relations**ページ、または各国の企業登録機関（英国の**Companies House**など）を確認してください。\
グローバルな企業グループや子会社を調べるには、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、scope内のすべての会社が分かったはずです。それらの資産を見つける方法を確認しましょう。

### **ASN**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関するポリシーが明確に定められた**IPアドレスのブロック**で構成され、単一の組織が管理しますが、複数の事業者で構成される場合もあります。

**会社にASNが割り当てられているか**を調べると、**IP範囲**を特定するのに役立ちます。**scope**内のすべての**ホスト**に対して**脆弱性テスト**を実施し、これらのIP内にある**ドメインを探す**のも有効です。\
[**https://bgp.he.net/**](https://bgp.he.net) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、会社の**名前**、**IP**、**ドメイン**から検索できます。\
**会社の地域によっては、以下のリンクからさらに情報を集められます。** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにせよ、役立つ情報（IP範囲とWhois）はおそらく最初のリンクにすべて掲載されています。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** 列挙機能は、スキャン終了時に ASN を自動的に集約して要約します。

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

組織の IP range は、無料 API tier に制限がある [ASNLookup](https://asnlookup.com/) でも確認できます。

### **脆弱性の調査**

この時点で、**scope 内のすべての asset が判明している**ため、許可されている場合は、すべての host に対して**脆弱性 scanner**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside) を実行したり、Shodan、Censys、ZoomEye などの service を使って open port **を見つけたりすることもできます。見つかったものに応じて、この本を参照し、稼働している可能性のある各種 service の pentest 方法を確認してください。**\
**また、default username と password の list を用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray) を使って service に対して bruteforce を試すのも有効です。**

## Domains

> scope 内の企業とその asset がすべて判明しました。次は、scope 内の domain を探します。

_以下で紹介する手法では subdomain も見つかる可能性があるため、その情報を軽視しないでください。_

まずは各企業の**メイン domain**を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

domain の IP range がすべて判明しているので、それらの **IP に対して reverse DNS lookup を行い、scope 内の domain をさらに見つけられるか試してみましょう**。対象の DNS server、またはよく知られた DNS server（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報には[SecurityTrails](https://securitytrails.com/)も利用できますが、過去のDNSデータを利用するには有料プランが必要です。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)のようなツールを使うと、逆引きと情報の補完を自動化できます。

### **リバースWhois（ループ）**

**whois**からは、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**を多数見つけられます。さらに興味深いのは、これらの項目を使って**リバースWhois検索を行うと、企業に関連する他の資産を見つけられる**ことです（たとえば、同じメールアドレスが登録されている他のWhoisレジストリなど）。\
以下のオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebとAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**のWebインターフェース。APIは有料。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100回まで無料**で検索可能）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 現在のDNS/サブドメインにはAPIを限定的に無料利用できます。過去のデータやリバース検索には有料プランが必要です。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 登録時にAPIクレジットを500回分無料で利用できます。それ以降は有料です。

[**DomLink** ](https://github.com/vysecurity/DomLink)を使って、この作業を自動化できます（whoxyのAPIキーが必要です）。\
[amass](https://github.com/owasp-amass/amass)を使って、リバースWhoisによる探索を自動で行うこともできます。`amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法でさらに多くのドメイン名を発見できます。**

### **トラッカー**

2つの異なるページで**同じトラッカーの同じID**が見つかった場合、**両方のページ**は**同じチームが管理している**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や**Adsense ID**が使われている場合です。

これらのトラッカーなどを検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **有料**のWeb/APIサービス（[料金](https://www.stackscan.com/pricing)）。現在、無料プランは案内されていません。トラッカーIDだけでなく、配信されるアセットを手掛かりに調査しましょう。スクリプトのパス、セルフホストされたバンドル名、アセットの読み込み元ホストなどから、それを含むすべてのサイトを特定できます。

APIは単一ドメインのスタックを返すため、候補のアセットが同じ資産群に属していることを確認するのに役立ちます。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各テクノロジーをカテゴリとともに返します。Asset pivoting は現在 web のみ対応しており、API ではドメインごとの検索が可能です。

### **Favicon**

同じ favicon のアイコンハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じですか？ これを実現するのが、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) ツールです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![favicon hashが一致するドメインの発見に使われたFavihashの結果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、ターゲットと同じfavicon icon hashを持つドメインを発見できます。

![同じfavicon hashを持つドメインの発見に使われたfavihashの出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanまたはFOFAのpivotとして使い、同じtechnologyの他の公開インスタンスを探しましょう。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

これは、Webサイトの favicon hash（favicon のバイト列を **base64-encoded** したものに対する MMH3）を**計算する**方法です。

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

大規模に favicon hash を取得するには、[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）も利用でき、その後 Shodan/Censys でピボットできます。

favicon fingerprint は手掛かりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトなため、衝突、アイコンの再利用、意図的な偽装が起こり得ます。
- **`/favicon.ico` 以外も調べる**: framework/build のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、インラインの data URL、HTML の `<link rel="icon">` タグを確認します。
- **静的アセットは WAF/SSO/IdP の制御下でもアクセス可能な場合がある**: アイコンに直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、キャッシュヘッダーを確認します。
- **一致を周辺のシグナルで検証する**: title、HTML/body hash、ヘッダー、TLS 証明書の subject/SAN、製品コンポーネント、公開ポートを比較します。
- **HTML/body hash でクラスタリングする**: 一貫したテンプレートがあれば fingerprint の信頼性が高まります。テンプレートが混在している場合は、汎用または共有アイコンの可能性があります。
- **互いに無関係なシグネチャ、ポート、製品で同じ hash が見つかった場合、honeypot または placeholder の可能性を考慮する。**
- **対象が曖昧な場合、実在するページと存在しないパス**（`/_favicon_probe_<8-hex>`）**を比較する**: 同じホスティング応答やパーキング応答であれば、アイコンが共有されている理由を説明できる場合があります。
- **favicon hash を製品や CPE に対応づける Nuclei の検出ルールや公開データセットを使って、初期トリアージを行う。**
- **IP 中心のカバレッジの限界に注意する**: CDN を経由するサーフェス、SNI ルーティングされたサーフェス、anycast、ドメインのみのサーフェスは、Shodan などのデータセットから漏れている場合があります。

### **Copyright / 固有の文字列**

Web ページ内で、**同じ組織の異なる Web サイト間で共有されている可能性のある文字列**を検索します。**copyright の文字列**は、その良い例です。その文字列を **Google**、他の **browser**、または **Shodan** で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

次のような cron job がよく使われます。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためのものです。証明書のタイムスタンプやCertificate Transparencyログ上の位置を照合すると、関連するドメインが見つかることがあります。<sup>[[6]](#references)</sup>

**Certificate Transparency**ログを直接利用する方法もあります。

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサービスや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使って、**同じDMARC情報を共有するドメインやサブドメイン**を見つけられます。\
ほかに便利なサービスとして、[**dmarcian**](https://dmarcian.com/)があります。

### **Passive Takeover**

放置されたAレコードは、cloud providerがIPを再割り当てすると到達可能になることがあります。参照先の調査では、インスタンスを作成し、そのアドレスをPassive DNSデータと照合する機会的なワークフローが示されています。takeoverのシナリオをテストするのは、許可された範囲内に限ってください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する探索の切り口を繰り返してください。それぞれの結果から、最初のシードからは見つからなかった追加の証明書名、Passive DNS上の関連性、faviconの一致、組織識別子が判明することがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織名はすでに分かっているので、Shodanで次のように検索できます。`org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、新たな予期しないドメインがないか調べてください。

メインWebページの**TLS証明書**にアクセスして**Organization name**を取得し、その名前で、**Shodan**が把握しているすべてのWebページの**TLS証明書**を検索できます。フィルターは `ssl:"Tesla Motors"` を使うか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを利用してください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に便利です。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決される、またはtakeover可能な**古い忘れられたレコード**を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **脆弱性の調査**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)を確認してください。会社が**ドメインを使用している**ものの、**所有権を失っている**場合があります。十分に安ければ登録し、会社に知らせてください。

資産探索ですでに見つかったものとは**異なるIPを持つドメイン**が見つかった場合は、NessusまたはOpenVASを使った**基本的な脆弱性スキャン**と、**nmap/masscan/shodan**による[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働中のサービスに応じて、**この本にある「攻撃」するための手法**を試せます。\
_ドメインがクライアントの管理下にないIP上でホストされている場合もあり、その場合はスコープ外なので注意してください。_

## サブドメイン

> スコープ内のすべての企業、各社のすべての資産、そして各社に関連するすべてのドメインが分かりました。

次に、見つかった各ドメインのサブドメインを可能な限りすべて見つけます。

> [!TIP]
> ドメインを見つけるためのツールや手法の中には、サブドメインの発見にも役立つものがあります。

### **DNS**

DNSレコードから**サブドメイン**を取得してみましょう。**Zone Transfer**も試してください。（脆弱な場合は報告してください。）

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

subdomain discoveryだけでなく、インフラ、レピュテーション、漏洩記録、エンリッチメントを扱うAPIやプラットフォームについては、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

大量のsubdomainを入手する最速の方法は、外部ソースを検索することです。最もよく使われる**tools**は以下のとおりです（より良い結果を得るには、API keysを設定してください）。


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

サブドメインの発見に特化していなくても、サブドメインの発見に役立つ**その他の興味深いツール/API**があります。たとえば、次のとおりです。

- [**IP.THC.ORG**](https://ip.thc.org) の無料API

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

- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から既知のURLを取得します。

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

- [**SecurityTrails**](https://securitytrails.com/) は、現在の DNS とサブドメインデータに対する無料の API アクセスを一部提供しています。過去の DNS/IP データには有料プランが必要です。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bountyプログラムに関連するすべてのサブドメインを無料で**提供しています。このデータには [chaospy](https://github.com/Moaaz-0x/chaospy) を使ってアクセスすることも、[このプロジェクトで使用されているscope](https://github.com/projectdiscovery/public-bugbounty-programs) にアクセスすることもできます。

これらのツールの多くを比較した記事はこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

DNSサーバーに対して、サブドメイン名として考えられる名前を使って brute-force を行い、新しい**サブドメイン**を見つけてみましょう。

この作業には、次のような**一般的なサブドメインのwordlist**が必要です。

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼性の高い DNS resolver のIPも必要です。信頼できる DNS resolver のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) でフィルタリングします。または、こちらを使うこともできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最もおすすめのツールは次のとおりです。

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実現した最初のツールです。非常に高速ですが、false positive が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つだけ使うと思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、Go で書かれています。active bruteforce による有効なサブドメインの列挙や、ワイルドカードを処理しながらのサブドメイン解決、簡単な入出力に対応しています。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns`も使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使って、非同期でドメイン名を brute force します。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 2回目のDNSブルートフォース

公開情報の調査とブルートフォースによってサブドメインを見つけた後、見つかったサブドメインを変化させて、さらに多くのサブドメインを探すことができます。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** ドメインとサブドメインを指定すると、パーミュテーションを生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutationsを生成します。
  - goaltdnsのpermutations **wordlist**は[**ここ**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationsを生成します。permutations fileが指定されていない場合、gotatorは独自のものを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutation を生成するだけでなく、名前解決も試みます（ただし、先ほど紹介したツールを使うほうがおすすめです）。
  - [**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から altdns の permutation **wordlist**を入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。このツールは結果を brute force します（DNS wildcard には対応していません）。
  - [**here**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt) から dmut の permutations wordlist を取得できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンに基づいて新たな候補サブドメイン名を生成し、さらに多くのサブドメインの発見を試みます。

#### スマートな permutation の生成

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、名前解決を試す候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided アルゴリズムを組み合わせた、サブドメイン brute-force fuzzer です。カスタマイズした wordlist や過去の DNS/TLS records など、提供された入力データを活用して、対応するドメイン名を正確に合成し、DNS scan 中に収集した情報をもとにループ内でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン発見ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各ステージを組み合わせ、再現可能なサブドメイン列挙を行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つまたは複数のWebページ**を含むIPアドレスが見つかった場合、OSINTソースでそのIP上のドメインを調べるか、そのIP上のVHostドメイン名を**brute force**して、**同じIP上にある別のWebサイトを持つサブドメインを見つける**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **やその他のAPIを使って、IP上のVHostsを見つける**ことができます。

**Brute Force**

Webサーバー内にサブドメインが隠れている可能性がある場合、brute forceを試すことができます。

名前ベースのvhostでは、`Host`ヘッダーをfuzzし、ffufのauto-calibrationを使ってデフォルトの応答をフィルタリングします。<sup>[[2]](#references)</sup>

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
> この手法を使うと、内部/非公開のendpointにアクセスできる場合もあります。

### **CORS Brute Force**

有効なドメイン/サブドメインが_**Origin**_ヘッダーに設定されている場合にのみ、_**Access-Control-Allow-Origin**_ヘッダーを返すページが見つかることがあります。このような場合、この挙動を悪用して新しい**サブドメイン**を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**サブドメイン**を探す際は、何らかの**バケット**を**指している**かどうかを確認し、該当する場合は[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点ではスコープ内のすべてのドメインが分かっているはずなので、[**バケット名を推測して権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **監視**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行うように、**Certificate Transparency** Logsを監視すれば、ドメインの**新しいサブドメイン**が作成されたかどうかを**監視**できます。

### **脆弱性を探す**

[**サブドメイン乗っ取り**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**サブドメイン**が**S3バケット**を指している場合は、[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

資産の調査ですでに見つけたものとは**異なるIPを持つサブドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**を使った[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働しているサービスに応じて、**この本で、それらを「攻撃」するためのテクニックを見つけられます**。\
_サブドメインが、クライアントの管理下にないIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## IPs

最初の手順で、**いくつかのIPレンジ、ドメイン、サブドメインを見つけている**かもしれません。\
それらのレンジと、**ドメイン/サブドメイン（DNSクエリ）に関連するすべてのIPを収集する**段階です。

次のようなサービスを使えば、**ドメインやサブドメインが過去に使用していたIP**も見つけられます。これらのIPもクライアントがまだ所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられるかもしれません。

- [**SecurityTrails**](https://securitytrails.com/)（過去のDNS/IPデータを利用するには有料プランが必要です）

[**hakip2host**](https://github.com/hakluke/hakip2host)ツールを使って、特定のIPアドレスを指すドメインを確認することもできます。

### **脆弱性を探す**

**CDNに属さないすべてのIPをポートスキャンしてください**（CDNでは有益なものが見つからない可能性が高いためです）。検出された稼働中のサービスから、**脆弱性を見つけられる**可能性があります。

ホストのスキャン方法については[**ガイド**](../pentesting-network/index.html)を**確認してください。**

## Webサーバーの探索

> 企業とその資産をすべて見つけ、スコープ内のIPレンジ、ドメイン、サブドメインが分かりました。次はWebサーバーを探します。

これまでの手順で、見つけた**IPとドメインのrecon**をすでに実施していると思われるため、**Webサーバーをすべて見つけている**かもしれません。まだの場合は、スコープ内のWebサーバーを探すための**簡単なテクニック**をいくつか紹介します。

これは**Webアプリの発見を目的としている**点に注意してください。そのため、スコープで**許可されている場合**は、**脆弱性スキャン**と**ポートスキャン**も実施してください。

[**masscan**を使ってWebサーバー関連の**開放ポート**をすばやく見つける方法はこちら](../pentesting-network/index.html#http-port-discovery)にあります。\
Webサーバーを探すもう一つの便利なツールは、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)です。ドメインのリストを渡すと、ポート80（http）と443（https）への接続を試みます。さらに、ほかのポートも試すよう指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **スクリーンショット**

scope内に存在する**すべてのwebサーバー**（会社の**IP**、すべての**domain**と**subdomain**）を特定できても、どこから始めればよいか**わからない**かもしれません。そこで、シンプルに、まずはすべてのスクリーンショットを撮りましょう。**メインページ**を**見る**だけでも、**脆弱**である可能性がより**高い**、**奇妙な**endpointを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を解析し、**脆弱性が含まれていそうなもの**とそうでないものを判定できます。

## Public Cloud Assets

会社に属する可能性のあるcloud assetsを見つけるには、まず**その会社を特定できるキーワードのリスト**を用意します。たとえば、暗号資産関連の会社であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、**bucketでよく使われる単語**のwordlistも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語から**permutation**を生成します（詳細は[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を確認してください）。

生成したwordlistを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを実行できます。**

Cloud Assetsを探す際は、**AWSのbucketだけでなく**、ほかのものも探してください。

### **脆弱性の調査**

**公開されているbucketやcloud function**などを見つけた場合は、**アクセスして**、何ができるのか、悪用できるかどうかを確認してください。

## Emails

scope内の**domain**と**subdomain**があれば、**emailの検索**を始めるために必要なものは基本的に揃っています。会社のemailを見つけるうえで、特に役立った**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の調査**

emailは後で、**web loginやauth service（SSHなど）のbrute-force**に役立ちます。また、**phishing**にも必要です。さらに、これらのAPIを使うとemailの持ち主に関する情報をさらに得られるため、phishing campaignに役立ちます。

## 認証情報 Leaks

**domain、subdomain、email**があれば、それらのemailに関連する過去の認証情報 leaksを探し始められます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の調査**

**有効な leaked 認証情報**を見つけた場合、簡単に成果を得られます。

## Secret Leaks

認証情報 leaksは、**機密情報が漏えいして売られた**会社への攻撃に関連しています。しかし、会社は、情報がそれらのデータベースにない**別の leaks**の影響を受けている可能性もあります。

### Github Leaks

認証情報やAPIが、**会社**の**public repository**や、その会社で働く**ユーザー**のpublic repositoryから漏えいしていることがあります。\
ツール[**Leakos**](https://github.com/carlospolop/Leakos)を使って、**organization**とその**developer**の**public repository**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/gitleaks/gitleaks)を自動実行できます。

**Leakos**は、渡された**URL**の**テキスト**に対して**gitleaks**を実行する用途にも使えます。web pageにもsecretが含まれていることがあるためです。

#### Github Dorks

組織内で検索できる**GitHub dorks**については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や従業員が、会社のコンテンツをpaste siteに**公開する**ことがあります。**機密情報**が含まれている場合もそうでない場合もありますが、検索する価値は十分にあります。\
ツール[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpaste siteを同時に検索できます。

### Google Dorks

古くても便利なgoogle dorksは、**公開されるべきでない情報を見つける**のに常に役立ちます。問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に数千もの検索クエリがあり、手動では実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks)**などのツールを使ってすべて実行できます**。

_通常のGoogleブラウザーを使ってデータベース全体を実行するツールは、Googleにすぐブロックされるため、処理が終わらない点に注意してください。_

### **脆弱性の調査**

**有効な leaked 認証情報やAPI token**を見つけた場合、簡単に成果を得られます。

## Public Code Vulnerabilities

会社に**open-source code**があるとわかった場合、それを**分析**して**脆弱性**を探すことができます。

**言語によって**使用できる**ツール**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

また、次のように**public repositoryをscan**できる無料サービスもあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunterが発見する**脆弱性の大半**は**web application**に存在します。そこで、ここでは**web application testingの方法論**について説明します。[**こちらで詳細を確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションにも触れておきます。非常に重大な脆弱性の発見は期待できませんが、**初期のweb情報を得るためのworkflowに組み込む**のに役立ちます。

## Recapitulation

> おめでとうございます！ここまでで、**基本的なenumeration**はすべて完了しました。基本的な内容にすぎないのは、さらに多くのenumerationが可能だからです（後で追加のテクニックを紹介します）。

ここまでに、以下を完了しています。

1. scope内の**会社**をすべて特定した
2. 会社に属する**asset**をすべて特定した（scope内であればvuln scanも実施）
3. 会社に属する**domain**をすべて特定した
4. domainの**subdomain**をすべて特定した（subdomain takeoverの可能性は？）
5. scope内の**IP**をすべて特定した（**CDN経由のもの**とそうでないもの）
6. **web server**をすべて特定し、スクリーンショットを撮った（詳しく調べる価値のある奇妙なものは？）
7. 会社に属する可能性のある**public cloud asset**をすべて特定した
8. 簡単に**大きな成果**につながる可能性のある**email**、**認証情報 leaks**、**secret leaks**
9. 見つけた**webすべてをpentestingした**

## **Full Recon 自動化ツール**

指定したscopeに対して、提案した作業の一部を実行するツールはいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません



## References

- [1] [Jason Haddix – バグハンターの方法論 v4.0：Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Faviconについて：ブラウザーアイコンから攻撃対象領域のインテリジェンスまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.icoをWeaponizeする：Bug Bounty、OSINTなど](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyへの時間相関攻撃によるdomainの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なsubdomain takeover campaignの発見と再現](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：subdomain enumerationの独自手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – 完全なsubdomain discovery workflow、Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 自動化されたTrickest workflowを使った完全なsubdomain brute-force discovery、Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
