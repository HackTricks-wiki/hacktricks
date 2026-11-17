# 外部偵察の方法論

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するすべてのものがスコープ内だと聞き、その会社が実際に何を所有しているのかを把握したいとします。

このフェーズの目標は、**主要企業が所有するすべての会社**を特定し、次にそれらの会社の**すべての資産**を特定することです。そのために、以下を行います。<sup>[[1]](#references)</sup>

1. 主要企業による買収を調べます。これにより、スコープ内の会社がわかります。
2. 各社のASN（ある場合）を調べます。これにより、各社が所有するIP範囲がわかります。
3. reverse whois lookupを使って、最初のエントリに関連する他のエントリ（組織名、ドメインなど）を検索します（再帰的に実行できます）。
4. shodanの`org`フィルターや`ssl`フィルターなどの他の手法を使い、他の資産を検索します（`ssl`を使った方法は再帰的に実行できます）。

解決済みサブドメインからHTTP crawlingやポート探索へ段階的に引き継ぐ方法については、[Pentesting Methodology](../pentesting-methodology.md#11-modern-recon-pipeline)を参照してください。

### **買収**

まず、主要企業が**所有する他の会社**を把握する必要があります。\
方法の1つは、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**主要企業を検索**して、**「acquisitions」**をクリックすることです。ここで、主要企業が買収した他の会社を確認できます。\
別の方法は、主要企業の**Wikipedia**ページにアクセスし、**acquisitions**を検索することです。\
上場企業の場合は、**SEC/EDGARの提出書類**、**投資家向け情報**のページ、または各国の企業登記所（英国の**Companies House**など）を確認してください。\
グローバルな企業構造や子会社を調べるには、**OpenCorporates** ([https://opencorporates.com/](https://opencorporates.com/))や**GLEIF LEI**データベース ([https://www.gleif.org/](https://www.gleif.org/))を利用してください。

> これで、スコープ内の会社をすべて把握できたはずです。次に、それらの資産を見つける方法を確認しましょう。

### **ASN**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確なポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織によって管理されますが、複数の事業者で構成される場合があります。

**会社にASNが割り当てられているか**を調べると、その**IP範囲**を特定するのに役立ちます。**スコープ内**のすべての**ホスト**に対して**脆弱性テスト**を行い、これらのIP内にある**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、会社の**名前**、**IP**、または**ドメイン**から検索できます。\
**会社の地域によっては、より多くの情報を集める際に次のリンクが役立つ場合があります：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、役立つ情報（IP範囲とWhois）はおそらく最初のリンクにすべて掲載されています。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の**列挙では、スキャン終了時に ASN が自動的に集約・要約されます。

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

### **脆弱性を探す**

この時点で、スコープ内の**すべてのアセット**が分かっているので、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEyeなどのサービスを利用して、**開いているポートを見つけたりすることもできます**。見つかった内容に応じて、実行中のさまざまなサービスのpentest方法について、この本で確認してみてください。\
**また、デフォルトのユーザー名**と**パスワード**のリストを用意して、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスをbruteforceするのも有効です。

## ドメイン

> スコープ内の企業とそのアセットはすべて分かりました。次は、スコープ内のドメインを見つけましょう。

_以下に挙げる手法ではサブドメインも見つかることがあります。その情報を軽視しないでください。_

まず、各企業の**メインドメイン**を探しましょう。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

ドメインのIP範囲をすべて見つけたら、それらの**IPに対して逆引きDNS検索**を行い、**スコープ内のドメインをさらに見つける**ことができます。被害者のDNSサーバー、またはよく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者が手動で PTR を有効にする必要があります。\
この情報には [SecurityTrails](https://securitytrails.com/) も利用できますが、過去の DNS データを利用するには有料プランが必要です。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールを使うと、逆引きと情報の補完を自動化できます。

### **Reverse Whois (loop)**

**whois** では、**組織名**、**住所**、**メールアドレス**、電話番号など、多くの興味深い**情報**を見つけられます。しかし、さらに興味深いのは、これらの項目のいずれかを使って **reverse whois lookup** を行うことで、**企業に関連する他の資産**を見つけられることです（たとえば、同じメールアドレスが登録されている別の whois レコードなど）。\
次のようなオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（Web と API）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - **無料**の Web インターフェース。有料 API。
- [https://reversewhois.domaintools.com/](https://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 無料ではありません（**100 回まで無料**）
- [https://www.domainiq.com/](https://www.domainiq.com) - 無料ではありません
- [https://securitytrails.com/](https://securitytrails.com/) - 現在の DNS/サブドメイン情報には、無料 API を限定的に利用できます。過去の情報や reverse lookup には有料プランが必要です。
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 登録時に API クレジット 500 回分が無料。以降は有料です。

[**DomLink** ](https://github.com/vysecurity/DomLink)（whoxy API key が必要）を使って、この作業を自動化できます。\
[amass](https://github.com/owasp-amass/amass) を使って、reverse whois の探索をある程度自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法を使ってさらに多くのドメイン名を発見できます。**

### **トラッカー**

異なる 2 つのページで**同じトラッカーの同じ ID** が見つかった場合、**両方のページ**が**同じチームによって管理されている**と推測できます。\
たとえば、複数のページで同じ **Google Analytics ID** や **Adsense ID** が見つかった場合です。

これらのトラッカーなどを検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](https://spyonweb.net/)
- [**StackScan**](https://www.stackscan.com) - **有料**の Web および API サービス（[料金](https://www.stackscan.com/pricing)）。現在、無料プランは公開されていません。トラッカー ID だけでなく、配信されるあらゆるアセットを起点に調査できます。たとえば、スクリプトのパス、自社ホストの bundle 名、アセットの読み込み元ホストなどを使い、それを含むすべてのサイトを特定できます。

API は単一ドメインの技術スタックを返します。候補となるアセットが同じ環境に属していることを確認するのに役立ちます。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各技術をカテゴリーとともに返します。Asset pivoting は現在 Web のみ対応しており、API ではドメインごとの検索が可能です。

### **Favicon**

同じ favicon アイコンのハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じでしょうか？ これを実現するのが、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/BBTz/blob/master/favihash.py) ツールです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![同じfaviconハッシュを持つドメインの発見に使用したFavihashの結果](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、ターゲットと同じfaviconアイコンのハッシュを持つドメインを発見できます。

![同じfaviconハッシュを持つドメインの発見に使用したfavihashの出力](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfaviconハッシュをShodanやFOFAのピボットとして使い、同じテクノロジーを使用する、外部に公開された他のインスタンスを探します。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

これは、Webサイトの**favicon hashを計算する**方法です（faviconのバイト列を**base64エンコードした**ものに対するMMH3）:

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

favicon hashは[**httpx**](https://github.com/projectdiscovery/httpx)（`httpx -l targets.txt -favicon`）を使って大規模に取得し、Shodan/Censysでpivotすることもできます。

favicon fingerprintは手がかりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hashは証拠ではなく指標として扱う**: MMH3はコンパクトなため、衝突、アイコンの使い回し、意図的な偽装が起こり得ます。
- **`/favicon.ico` 以外も調べる**: framework/buildのパス、manifestファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、inline data URL、HTMLの`<link rel="icon">`タグを確認してください。
- **WAF/SSO/IdPの制御下でも静的アセットにアクセスできる場合がある**: アイコンを直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、cache headerを確認してください。
- **一致を周辺のシグナルで検証する**: title、HTML/body hash、header、TLS certificateのsubject/SAN、product component、公開ポートを比較してください。
- **HTML/body hashでクラスタリングする**: 一貫したtemplateがあればfingerprintの確度が高まります。templateが混在している場合は、汎用または共有アイコンの可能性があります。
- **無関係なsignature、port、productにまたがってhashが出現する場合は、honeypotまたはplaceholderの可能性を考慮する。**
- **判断が難しいtargetでは、実在するページと`/_favicon_probe_<8-hex>`のような存在しないパスを比較する**: hostingやparkingの応答が一致すれば、アイコンが共有されている理由を説明できる場合があります。
- **favicon hashをproductやCPEに対応付けるNuclei detection ruleや公開datasetを使って、初期triageを行う。**
- **IP中心のcoverage gapに注意する**: CDN経由、SNI routing、anycast、domain-onlyのsurfaceは、Shodanのようなdatasetから漏れている場合があります。

### **著作権 / 固有文字列**

同じ組織内の異なるwebサイト間で共有されている可能性のある**文字列**をwebページ内から検索してください。**著作権表記**はその好例です。その文字列を**Google**や他の**browser**、さらには**Shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT時刻**

次のようなcron jobを設定するのは一般的です。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプや Certificate Transparency ログ内の位置を照合すると、関連するドメインが見つかることがあります。<sup>[[6]](#references)</sup>

**Certificate Transparency** ログを直接使う方法もあります。

- [https://crt.sh/](https://crt.sh/)
- [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com) などのWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains) などのツールを使うと、**同じDMARC情報を共有するドメインやサブドメイン**を見つけられます。\
ほかに便利なサービスとして、[**dmarcian**](https://dmarcian.com/) があります。

### **Passive Takeover**

放置されたAレコードは、cloud providerがIPを再割り当てすると到達可能になる場合があります。参照されている調査では、インスタンスを作成し、そのアドレスをPassive DNSデータと照合する機会を狙ったワークフローが紹介されています。takeoverシナリオのテストは、許可された範囲内でのみ行ってください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する発見手法を繰り返してください。それぞれの結果から、元の起点では見つからなかった追加の証明書名、Passive DNS上の関連、faviconの一致、組織識別子が明らかになることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織名はすでに分かっているので、Shodanで次のように検索できます: `org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、新たな予期しないドメインがないか調べてください。

メインWebページの**TLS証明書**にアクセスして**組織名**を取得し、その名前を**Shodan**で把握されているすべてのWebページの**TLS証明書**から検索することもできます。フィルターには `ssl:"Tesla Motors"` を使うか、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch) のようなツールを使ってください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に便利です。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決できる、またはtakeover可能な**古い忘れられたレコード**を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://www.domaintools.com/platform](https://www.domaintools.com/platform)
- [https://docs.domaintools.com/dnsdb/](https://docs.domaintools.com/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover) がないか確認してください。企業が**あるドメインを使用していたものの、所有権を失った**可能性があります。そのドメインを（十分安ければ）登録して、企業に知らせてください。

資産の調査ですでに見つけたものとは**異なるIPを持つドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働しているサービスに応じて、**この本に「攻撃」するための手法が載っている**場合があります。\
_ドメインがクライアントの管理下にないIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## サブドメイン

> スコープ内のすべての企業、それぞれの企業のすべての資産、そして企業に関連するすべてのドメインが分かりました。

見つかった各ドメインの、考えられるすべてのサブドメインを探しましょう。

> [!TIP]
> ドメインを探すツールや手法の中には、サブドメイン探しにも役立つものがあります。

### **DNS**

**DNS**レコードから**サブドメイン**を見つけてみましょう。**Zone Transfer**も試してください（脆弱性があれば報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

サブドメインの発見にとどまらず、インフラ、評判、侵害記録、情報のエンリッチメントを扱うAPIやプラットフォームについては、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

大量のサブドメインを最も速く取得する方法は、外部ソースを検索することです。最もよく使われている**ツール**は次のとおりです（より良い結果を得るには、APIキーを設定してください）。


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

サブドメインの発見に特化しているわけではありませんが、サブドメインの発見に役立つ**興味深いツール/API**もあります。

- [**IP.THC.ORG**](https://ip.thc.org) 無料API

```bash
curl https://ip.thc.org/tesla.com
```

- [**AnubisDB 無料API**](https://github.com/jonluca/Anubis-DB)

```bash
curl https://anubisdb.com/anubis/subdomains/tesla.com | jq -r ".[]"
```

- [**RapidDNS**](https://rapiddns.io) の無料 API

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

- [**SecurityTrails**](https://securitytrails.com/) は、現在の DNS とサブドメインデータへの限定的な無料 API アクセスを提供しています。過去の DNS/IP データには有料プランが必要です。
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bounty program に関連するすべてのサブドメイン**を無料で提供しています。このデータは [chaospy](https://github.com/Moaaz-0x/chaospy) からも取得できます。また、このプロジェクトで使われている scope も [https://github.com/projectdiscovery/public-bugbounty-programs](https://github.com/projectdiscovery/public-bugbounty-programs) から確認できます。

これらのツールの多くを比較した記事はこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

サブドメイン名として考えられる文字列を使って DNS サーバーに brute-force を行い、新しい **サブドメイン**を見つけてみましょう。

この作業には、次のような**一般的なサブドメイン用 wordlist**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼性の高い DNS resolver の IP も必要です。信頼できる DNS resolver のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) でフィルタリングできます。あるいは、[https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt) を使用できます。

DNS brute-force で特におすすめのツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実現した最初のツールです。非常に高速ですが、false positive が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つだけ使用していると思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、Goで書かれた `massdns` のラッパーです。アクティブなブルートフォースによる有効なサブドメインの列挙や、ワイルドカードに対応したサブドメインの解決、簡単な入出力をサポートします。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): `massdns`も使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使用して、ドメイン名を非同期に総当たりします。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### DNS Brute-Force 第2ラウンド

オープンソースと brute-forcing を使ってサブドメインを見つけた後、見つかったサブドメインを変形して、さらに多くのサブドメインを見つけられるか試すことができます。この目的には、いくつかの便利なツールがあります。

- [**dnsgen**](https://github.com/AlephNullSK/dnsgen)**:** ドメインとサブドメインを指定すると、permutation を生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、組み合わせを生成します。
  - goaltdns の組み合わせ用 **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、permutationを生成します。permutationファイルが指定されていない場合、gotatorは独自のファイルを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの組み合わせを生成するだけでなく、それらの名前解決も試行できます（ただし、前述のツールを使うほうがよいでしょう）。
  - [**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)からaltdnsの組み合わせ用**ワードリスト**を入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutation、mutation、変更を行う別のツールです。結果を brute force します（DNS wildcard には対応していません）。
  - dmut の permutation wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンに沿って新たなサブドメイン候補名を**生成**し、さらにサブドメインを発見できるか試します。

#### スマートな permutation の生成

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現に似たパターンを学習し、名前解決できる候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS 応答ガイド型アルゴリズムを組み合わせた、サブドメインのブルートフォースファザーです。カスタマイズされたワードリストや過去の DNS/TLS レコードなど、提供された入力データを利用して、対応するドメイン名を高精度に生成し、DNS スキャンで得た情報に基づいてループ内でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン発見ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各段階を組み合わせ、サブドメイン列挙を再現可能な形で実行します。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つまたは複数のWebページ**を含むIPアドレスを見つけた場合、そのIP上の他のサブドメインを**見つける**ために、IPアドレスに紐づくドメインを**OSINTソース**で調べたり、そのIP上のVHostドメイン名を**brute force**したりできます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPIを使って、IP上のVHostsを見つけられます**。

**Brute Force**

Webサーバー上にサブドメインが隠れている可能性がある場合は、brute forceを試せます。

名前ベースのvhostでは、`Host`ヘッダーをfuzzし、ffufの自動キャリブレーションを使ってデフォルトのレスポンスを除外します。<sup>[[2]](#references)</sup>

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

有効なドメイン/subdomain を _**Origin**_ header に設定した場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような場合、この挙動を悪用して新しい **subdomains** を **発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **バケットのブルートフォース**

**サブドメイン**を探す際は、何らかの**バケットを指している**かどうかに注意し、その場合は[**権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)**。**\
また、この時点ではスコープ内のすべてのドメインがわかっているので、[**バケット名をブルートフォースして権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

### **モニタリング**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行うように、**Certificate Transparency** Logsを監視することで、ドメインに**新しいサブドメイン**が作成されたかどうかを**監視**できます。

### **脆弱性の調査**

[**サブドメインテイクオーバー**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**サブドメイン**が**S3バケット**を指している場合は、[**権限を確認してください**](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-unauthenticated-enum-access/aws-s3-unauthenticated-enum.html#aws---s3-unauthenticated-enum)。

資産の調査で見つけたものとは**異なるIPを持つサブドメイン**があれば、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と、**nmap/masscan/shodan**による[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行してください。稼働しているサービスに応じて、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_サブドメインが、クライアントの管理下にないIPでホストされている場合もあります。その場合はスコープ外なので注意してください。_

## IP

初期段階で、**IPレンジ、ドメイン、サブドメイン**がいくつか見つかっているかもしれません。\
これらのレンジと、**ドメイン／サブドメイン（DNSクエリ）**から、**すべてのIPを収集する**段階です。

以下のようなサービスを使うと、**ドメインやサブドメインが過去に使用していたIP**も見つけられます。これらのIPは現在もクライアントが所有している可能性があり、[**CloudFlareのバイパス**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられることもあります。

- [**SecurityTrails**](https://securitytrails.com/)（過去のDNS/IPデータの利用には有料プランが必要です）

特定のIPアドレスを指すドメインを、[**hakip2host**](https://github.com/hakluke/hakip2host)で調べることもできます。

### **脆弱性の調査**

**CDNに属さないIPをすべてポートスキャンしてください**（CDN上では興味深いものが見つかる可能性が低いためです）。検出された稼働中のサービスに、**脆弱性が見つかる**ことがあります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を**参照してください**。

## Webサーバーの探索

> すべての企業とその資産を見つけ、スコープ内のIPレンジ、ドメイン、サブドメインを把握しました。次はWebサーバーを探します。

前の手順で、見つかった**IPやドメインの偵察**をすでに行い、可能性のあるWebサーバーをすべて**見つけている**かもしれません。まだ見つけていない場合は、スコープ内のWebサーバーを探すための**手早いテクニック**をいくつか紹介します。

これは**Webアプリの発見を目的とした方法**です。スコープで許可されている場合は、**脆弱性スキャン**と**ポートスキャン**も実施してください。

[**masscan**を使ってWebサーバー関連の**オープンポート**を見つける手早い方法はこちら](../pentesting-network/index.html#http-port-discovery)にあります。\
Webサーバーを探すための使いやすいツールとして、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)もあります。ドメインのリストを渡すと、ポート80（http）と443（https）への接続を試みます。また、ほかのポートも試すように指定できます：

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **Screenshots**

対象範囲内（会社の**IP**、すべての**ドメイン**、**サブドメイン**）に存在する**すべてのWebサーバー**を見つけたものの、どこから始めればよいか**わからない**かもしれません。そこで、簡単にするために、まずはすべてのスクリーンショットを撮りましょう。**メインページ**を**ざっと見る**だけでも、**脆弱**である**可能性が高い**、**奇妙な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/RedSiege/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使用できます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を解析し、**脆弱性が含まれていそうなもの**とそうでないものを判別できます。

## Public Cloud Assets

会社に属する潜在的なクラウド資産を見つけるには、まずその会社を特定できるキーワードのリストを用意します。たとえば、暗号資産企業なら、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使うとよいでしょう。

また、バケットでよく使われる**一般的な単語**のワードリストも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語を使って**組み合わせ候補**を生成します（詳しくは[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を参照）。

生成したワードリストを使い、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを使用できます。**

Cloud Assetsを探す際は、**AWSのバケットだけでなく、ほかの資産も探す**ようにしてください。

### **Looking for vulnerabilities**

**公開されているバケットや、外部に公開されたクラウド関数**などを見つけたら、**アクセスして**、どのような情報が得られるか、悪用できるかどうかを確認してください。

## Emails

対象範囲内の**ドメイン**と**サブドメイン**があれば、**メールアドレスの調査**を始めるのに必要な情報はほぼそろっています。会社のメールアドレスを見つけるうえで、私が特に役立つと感じた**API**や**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **Looking for vulnerabilities**

メールアドレスは、後でWebログインや認証サービス（SSHなど）に対して**brute-force**を行う際に役立ちます。また、**phishing**にも必要です。さらに、これらのAPIからはメールアドレスの持ち主に関する**追加情報**も得られるため、phishingキャンペーンに役立ちます。

## Credential Leaks

**ドメイン**、**サブドメイン**、**メールアドレス**があれば、それらのメールアドレスに関連する過去のcredential leakを探し始めることができます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **Looking for vulnerabilities**

**有効なcredential leak**を見つければ、非常に簡単に成果を得られます。

## Secrets Leaks

Credential leaksは、**機密情報が漏えいして販売された**企業への攻撃に関連しています。しかし、企業は、情報がこうしたデータベースに含まれていない**別のleak**の影響を受けている可能性もあります。

### Github Leaks

**会社**や、その会社で働く**ユーザー**の**公開リポジトリ**から、credentialやAPIが漏えいしている可能性があります。\
ツールの[**Leakos**](https://github.com/carlospolop/Leakos)を使うと、**組織**とその**開発者**の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/gitleaks/gitleaks)を自動的に実行できます。

**Leakos**は、指定した**URL**のテキスト全体に対して**gitleaks**を実行することもできます。Webページにもsecretsが含まれている場合があるためです。

#### Github Dorks

組織内で検索する候補となる**GitHub dorks**については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pastes Leaks

攻撃者や従業員が、pasteサイトに会社のコンテンツを**公開する**ことがあります。そこに**機密情報が含まれている**場合もそうでない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpasteサイトを一度に検索できます。

### Google Dorks

古くても便利なGoogle dorksは、**公開されるべきでない情報を見つける**のに役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に何千もの検索クエリが含まれていて、手動では実行できないことです。そのため、お気に入りの10個を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などのツールを使ってすべて実行できます**。

_通常のGoogleブラウザーを使ってデータベース全体を実行しようとするツールは、Googleにすぐにブロックされるため、処理が終わらないことに注意してください。_

### **Looking for vulnerabilities**

**有効なcredential leak**やAPI tokenを見つければ、非常に簡単に成果を得られます。

## Public Code Vulnerabilities

会社が**オープンソースコード**を公開していることがわかった場合、そのコードを**分析**し、**脆弱性**を探すことができます。

**言語によって**使用できる**ツール**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

**公開リポジトリ**をスキャンできる無料サービスもあります。たとえば、次のサービスがあります。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

bug hunterが発見する**脆弱性の大部分**は**Webアプリケーション**に存在します。そこで、この段階では**Webアプリケーションのテスト方法**について説明します。[**こちらで詳細を確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションについても、特に触れておきたいと思います。非常に深刻な脆弱性の発見は期待できませんが、**初期のWeb情報を得るためにワークフローへ組み込む**と便利です。

## Recapitulation

> おめでとうございます！この時点で、基本的な**列挙作業**はすべて完了しています。基本的な作業にすぎないのは、さらに多くの列挙が可能だからです（後ほど、より多くのテクニックを紹介します）。

ここまでに、次の作業を完了しています。

1. 対象範囲内の**すべての会社**を特定した
2. 会社に属する**すべての資産**を特定した（対象範囲内であれば、脆弱性スキャンも実施した）
3. 会社に属する**すべてのドメイン**を特定した
4. それらのドメインの**すべてのサブドメイン**を特定した（subdomain takeoverの可能性は？）
5. 対象範囲内の**すべてのIP**（CDN経由のものと、**CDN経由でない**もの）を特定した
6. **すべてのWebサーバー**を特定し、スクリーンショットを撮った（詳しく調べる価値のある奇妙なものは？）
7. 会社に属する**公開クラウド資産の候補**をすべて特定した
8. **メールアドレス**、**credential leaks**、**secret leaks**を見つけた。それらがあれば、**非常に簡単に大きな成果を得られる**可能性がある
9. 見つけたすべてのWebサイトを**Pentesting**した

## **Full Recon Automatic Tools**

指定した対象範囲に対して、ここで提案した作業の一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません



## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – On Favicons: From Browser Icons to Attack Surface Intelligence](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – Weaponizing favicon.ico for BugBounties, OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Discovering Domains via a Time-Correlation Attack on Certificate Transparency](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover: Uncovering (and Emulating) an Expensive Subdomain Takeover Campaign](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator: A Unique Method of Subdomain Enumeration](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – Full Subdomain Discovery Workflow, Part 1](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Full Subdomain Brute Force Discovery Using Automated Trickest Workflow, Part 2](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihash output screenshot](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
