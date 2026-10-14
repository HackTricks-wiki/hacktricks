# External Recon Methodology

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある会社に属するものはすべてスコープ内だと聞き、その会社が実際に何を所有しているのかを調べたいとします。

このフェーズの目的は、**メインの会社が所有するすべての会社**を特定し、次にそれらの会社の**すべての資産**を特定することです。そのために、以下を行います。<sup>[[1]](#references)</sup>

1. メインの会社による買収を調べます。これにより、スコープ内の会社がわかります。
2. 各会社のASN（存在する場合）を調べます。これにより、各会社が所有するIP範囲がわかります。
3. reverse whois lookupを使用して、最初のエントリに関連する他のエントリ（組織名、ドメインなど）を検索します（再帰的に実行できます）。
4. shodanの`org`や`ssl`フィルターなど、他の手法を使って他の資産を検索します（`ssl`の手法は再帰的に実行できます）。

### **買収**

まず、**メインの会社が所有する他の会社**を把握する必要があります。\
方法の1つは、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**メインの会社を検索**して、**「acquisitions」**を**クリック**することです。ここで、メインの会社が買収した他の会社を確認できます。\
別の方法は、メインの会社の**Wikipedia**ページにアクセスして、**買収**について調べることです。\
上場企業の場合は、**SEC/EDGARの提出書類**、**投資家向け情報**のページ、または各国の企業登記簿（例：英国の**Companies House**）を確認してください。\
世界規模の企業グループ構造や子会社を調べるには、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> ここまでで、スコープ内の会社がすべてわかったはずです。次に、それらの資産を見つける方法を説明します。

### **ASNs**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確に定義されたポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織によって管理されますが、複数の事業者で構成される場合もあります。

**会社にASNが割り当てられているか**を調べると、**IP範囲**を特定するのに役立ちます。**スコープ**内のすべての**ホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **または** [**https://ipinfo.io/**](https://ipinfo.io/)で、会社の**名前**、**IP**、または**ドメイン**から**検索**できます。\
**会社の地域によっては、より多くの情報を集めるのに以下のリンクが役立ちます：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、**有用な情報**（IP範囲とWhois）はおそらく最初のリンクにすべて掲載されています。

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**'s** の列挙機能は、スキャン終了時にASNを自動的に集約して要約します。

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

組織の IP 範囲は、[http://asnlookup.com/](http://asnlookup.com)（無料 API あり）でも確認できます。\
ドメインの IP と ASN は、[http://ipv4info.com/](http://ipv4info.com)で確認できます。

### **脆弱性の調査**

この時点で、スコープ内の**すべての資産が判明している**ため、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**port scans**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEye などの**サービスを使って**開いているポート**を見つけたりすることもできます。見つかったものに応じて、この本を参照し、実行中のさまざまなサービスの pentest 方法を確認してください。\
**また、デフォルトの** username **と** password **のリストを用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスに対する**bruteforce**を試すのも有効です。

## ドメイン

> スコープ内の企業とその資産がすべて判明しました。次は、スコープ内のドメインを見つけましょう。

_以下に示す手法ではサブドメインも見つかる可能性があるため、その情報を軽視しないでください。_

まず、各企業の**メインドメイン**を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

ドメインの IP 範囲がすべて判明しているので、それらの**IP に対して reverse DNS lookup を行い、スコープ内のドメインをさらに見つける**ことができます。被害者の DNS server、またはよく知られた DNS server（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報を調べるには、オンラインツール [http://ptrarchive.com/](http://ptrarchive.com) も利用できます。\
大きな範囲を対象にする場合は、[**massdns**](https://github.com/blechschmidt/massdns) や [**dnsx**](https://github.com/projectdiscovery/dnsx) のようなツールを使うと、逆引きと情報の補完を自動化できます。

### **Reverse Whois（ループ）**

**whois**には、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**が多数含まれています。さらに興味深いのは、これらの項目を使って**reverse whois lookups**を行うと、**その会社に関連する資産をさらに発見できる**ことです（たとえば、同じメールアドレスが登録されている別のwhoisレコード）。\
次のようなオンラインツールを利用できます。

- [https://ip.thc.org/](https://ip.thc.org/) - **無料**（WebおよびAPI）
- [https://viewdns.info/reversewhois/](https://viewdns.info/reversewhois/) - **無料**
- [https://domaineye.com/reverse-whois](https://domaineye.com/reverse-whois) - **無料**
- [https://www.reversewhois.io/](https://www.reversewhois.io) - **無料**
- [https://www.whoxy.com/](https://www.whoxy.com) - Webは**無料**、APIは有料。
- [http://reversewhois.domaintools.com/](http://reversewhois.domaintools.com) - 有料
- [https://drs.whoisxmlapi.com/reverse-whois-search](https://drs.whoisxmlapi.com/reverse-whois-search) - 有料（**100回まで無料**）
- [https://www.domainiq.com/](https://www.domainiq.com) - 有料
- [https://securitytrails.com/](https://securitytrails.com/) - 有料（API）
- [https://whoisfreaks.com/](https://whoisfreaks.com/) - 有料（API）

[**DomLink** ](https://github.com/vysecurity/DomLink)を使って、この作業を自動化できます（whoxy APIキーが必要です）。\
[amass](https://github.com/OWASP/Amass)を使って、reverse whoisによる探索を自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法を使ってさらにドメイン名を発見できます。**

### **トラッカー**

2つの異なるページで**同じトラッカーの同じID**が見つかった場合、**両方のページ**は**同じチームによって管理されている**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**が見つかった場合です。

これらのトラッカーなどを検索できるページやツールがあります。

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（分析ツールやトラッカーの共有状況から関連サイトを検出）
- [**StackScan**](https://www.stackscan.com) - **無料枠**（WebおよびAPI）。トラッカーIDだけでなく、配信されている任意のアセットを起点に調査できます。スクリプトのパス、セルフホストされたバンドル名、アセットの読み込み元ホストなどを指定すると、それを含むすべてのサイトが返されます。

APIは単一ドメインのスタックを返すため、候補のアセットが同じ組織の資産に属していることを確認するのに便利です。

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各テクノロジーをカテゴリとともに返します。Asset pivoting は現在 Web のみ対応しており、API ではドメインごとの検索が可能です。

### **Favicon**

同じ favicon のアイコンハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じですか？これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) ツールで実現できます。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihashの結果を使って、favicon hashを共有するドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、ターゲットと同じfavicon icon hashを持つドメインを発見できます。

![favihashの出力を使って、同じfavicon hashを持つドメインを発見](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfavicon hashをShodanやFOFAのpivotとして使い、同じ技術の他の公開インスタンスを見つけましょう。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Webサイトの**favicon hashを計算する方法**（faviconのバイト列を**base64エンコード**したものに対するMMH3）:

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

[**httpx**](https://github.com/projectdiscovery/httpx) (`httpx -l targets.txt -favicon`) を使えば、大規模に favicon ハッシュを取得し、Shodan/Censys でピボットすることもできます。

favicon のフィンガープリントは手掛かりとして扱い、周辺のシグナルで検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **ハッシュは証拠ではなく指標として扱う**: MMH3 はコンパクトなため、衝突やアイコンの使い回し、意図的な偽装があり得ます。
- **`/favicon.ico` 以外も調べる**: フレームワークやビルド関連のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、インラインの data URL、HTML の `<link rel="icon">` タグを確認します。
- **WAF/SSO/IdP による制御下でも静的アセットにアクセスできる場合がある**: アイコンに直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、キャッシュヘッダーを確認します。
- **一致を周辺のシグナルで検証する**: タイトル、HTML/body ハッシュ、ヘッダー、TLS 証明書の subject/SAN、製品コンポーネント、公開ポートを比較します。
- **HTML/body ハッシュでクラスタリングする**: 一貫したテンプレートがあればフィンガープリントの信頼性が高まり、テンプレートが混在していれば、汎用アイコンまたは共有アイコンの可能性があります。
- **関連性のないシグネチャ、ポート、製品にまたがってハッシュが出現する場合、ハニーポットまたはプレースホルダーの可能性を考慮する。**
- **判断が難しいターゲットでは、実在するページと存在しないパス**（`/_favicon_probe_<8-hex>` など）を比較します。同じホスティング応答やパーキング応答が、アイコンの共有を説明する場合があります。
- **favicon ハッシュを製品や CPE に対応付けた Nuclei の検出ルールまたは公開データセット**を使って、初期トリアージを行います。
- **IP 中心のカバレッジのギャップに注意する**: CDN 経由、SNI ルーティング、anycast、ドメインのみのサーフェスは、Shodan のようなデータセットに含まれない場合があります。

### **著作権 / 固有の文字列**

同じ組織内の異なるウェブサイト間で共有されている可能性がある**文字列**をウェブページ内で検索します。**著作権表記**はそのよい例です。その文字列を**Google**や他の**ブラウザー**、あるいは**Shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT Time**

次のような cron job がよく使われます。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するためです。証明書のタイムスタンプやCertificate Transparencyログ内の位置を照合すると、関連するドメインを特定できることがあります。<sup>[[6]](#references)</sup>

**certificate transparency**ログを直接利用する方法もあります。

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使うと、**同じDMARC情報を共有するドメインやサブドメイン**を探せます。\
その他の便利なツールには、[**spoofcheck**](https://github.com/BishopFox/spoofcheck)や[**dmarcian**](https://dmarcian.com/)があります。

### **Passive Takeover**

放棄されたAレコードは、クラウドプロバイダーがIPを再割り当てすると、再び到達可能になることがあります。参照されている調査では、インスタンスを用意し、そのアドレスをPassive DNSデータと照合する機会主義的なワークフローが紹介されています。Takeoverのシナリオを試すのは、許可された範囲内に限ってください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する調査の切り口を繰り返してください。それぞれの結果から、最初の起点では見つからなかった追加の証明書名、Passive DNSの関連性、faviconの一致、組織識別子が見つかることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織の名前はすでに分かっています。その情報を使って、Shodanで次のように検索できます: `org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、予期しない新しいドメインがないか調べてください。

メインのWebページの**TLS証明書**にアクセスして**組織名**を取得し、**Shodan**が把握しているすべてのWebページの**TLS証明書**からその名前を検索することもできます。フィルターは `ssl:"Tesla Motors"` のように指定します。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使います。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に便利です。

**Passive DNS / Historical DNS**

Passive DNSデータは、現在も名前解決される、またはTakeover可能な**古い忘れられたレコード**を見つけるのに役立ちます。以下を確認してください。

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)がないか確認してください。会社が**あるドメインを使っているものの**、**所有権を失っている**場合があります。そのドメインを（十分安ければ）登録し、会社に知らせてください。

資産調査ですでに見つかったものとは**異なるIPを持つドメイン**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。稼働しているサービスによっては、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_ドメインがクライアントの管理下にないIPでホストされている場合があり、その場合はスコープ外となるため注意してください。_

## サブドメイン

> スコープ内のすべての会社、各社のすべての資産、そして各社に関連するすべてのドメインが分かりました。

次に、見つかった各ドメインで可能な限りすべてのサブドメインを探します。

> [!TIP]
> ドメインを探すツールや手法の中には、サブドメインの発見にも役立つものがあります。

### **DNS**

**DNS**レコードから**サブドメイン**を探してみましょう。また、**Zone Transfer**も試してください（脆弱な場合は報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

サブドメインの発見に加えて、インフラ、レピュテーション、漏洩記録、エンリッチメントを扱うAPIやプラットフォームについては、[Reconnaissance and Threat-Intelligence APIs catalog](reconnaissance-and-threat-intelligence-apis.md)を参照してください。

大量のサブドメインを最も速く取得する方法は、外部ソースを検索することです。最もよく使われる**ツール**は以下のとおりです（より良い結果を得るには、APIキーを設定してください）。


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

サブドメインの発見に特化しているわけではなくても、サブドメインの発見に役立つ**興味深いツール/API**もあります。たとえば、次のとおりです。

- [**IP.THC.ORG**](https://ip.thc.org) 無料API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用してサブドメインを取得します。

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**JLDC 無料 API**](https://jldc.me/anubis/subdomains/google.com)

```bash
curl https://jldc.me/anubis/subdomains/tesla.com | jq -r ".[]"
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

- [**gau**](https://github.com/lc/gau)**:** 指定したドメインについて、AlienVault's Open Threat Exchange、Wayback Machine、Common Crawl から既知のURLを取得します。

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

- [**securitytrails.com**](https://securitytrails.com/) には、サブドメインとIP履歴を検索できる無料APIがあります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bountyプログラムに関連するすべてのサブドメインを無料で提供しています**。このデータは[chaospy](https://github.com/dr-0x0x/chaospy)を使って取得することも、このプロジェクトで使用されているスコープを[https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list)から取得することもできます。

これらのツールの多くを比較した記事はこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

可能性のあるサブドメイン名を使ってDNSサーバーにbrute-forceを行い、新しい**サブドメイン**を探してみましょう。

この作業には、次のような**一般的なサブドメイン用wordlist**が必要です:

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

また、信頼性の高いDNS resolverのIPも必要です。信頼できるDNS resolverの一覧を作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt)からresolverをダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator)を使ってフィルタリングできます。または、こちらを利用することもできます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-forceに最もおすすめのツールは次のとおりです:

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的なDNS brute-forceを実現した最初のツールです。非常に高速ですが、false positiveが発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これは resolver を1つだけ使っていると思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は、goで書かれた `massdns` のラッパーで、active bruteforceによる有効なサブドメインの列挙や、wildcard handlingおよび簡単な入出力サポートによるサブドメインの名前解決ができます。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): これも`massdns`を使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使ってドメイン名を非同期にブルートフォースします。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### DNS Brute-Force の第2ラウンド

オープンソースの情報を使ったり、Brute-Force を行ったりしてサブドメインを見つけた後は、見つかったサブドメインを変化させて、さらに多くのサブドメインを探すことができます。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを指定すると、そのパーミュテーションを生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutationsを生成します。
  - goaltdnsのpermutations用**wordlist**は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、組み合わせを生成します。permutations file が指定されていない場合、gotator は独自のファイルを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutation を生成するだけでなく、それらの名前解決も試せます（ただし、前述のコメントで紹介したツールを使うほうがよいでしょう）。
  - [**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から altdns の permutation 用 **wordlist** を入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutation、mutation、alteration を行う別のツールです。このツールは結果を brute force します（DNS wildcard には対応していません）。
  - dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンから新たなサブドメイン候補名を生成し、さらに多くのサブドメインの発見を試みます。

#### Smart permutations generation

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、名前解決を試す候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS 応答誘導型アルゴリズムを組み合わせた、サブドメインのブルートフォース用 fuzzer です。カスタマイズした wordlist や過去の DNS/TLS レコードなど、指定された入力データを利用して、対応するドメイン名を正確に合成し、DNS スキャンで得られた情報をもとにループ内でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン発見ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各段階を組み合わせ、再現可能なサブドメイン列挙を行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つ以上のWebページ**を含むIPアドレスが見つかった場合、**OSINTソース**でそのIP上のドメインを調べたり、そのIP上の**VHostドメイン名をbrute force**したりして、**同じIP上にある他のサブドメインを見つける**ことができます。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **や他のAPIを使って、IP上のVHostsを見つける**ことができます。

**Brute Force**

Webサーバー上に隠れたサブドメインがあると思われる場合は、brute forceを試すことができます。

名前ベースのvhostでは、`Host`ヘッダーをfuzzし、ffufの自動キャリブレーションを使ってデフォルトの応答を除外します。<sup>[[2]](#references)</sup>

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
> この technique を使えば、内部/hidden endpoints にアクセスできる場合もあります。

### **CORS Brute Force**

有効な domain/subdomain が _**Origin**_ header に設定されている場合にのみ、_**Access-Control-Allow-Origin**_ header を返すページが見つかることがあります。このような場合、この挙動を悪用して新しい **subdomains** を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**サブドメイン**を探す際は、何らかの**バケットを指している**かどうかに注意し、その場合は[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)**。**\
また、この時点ではスコープ内のすべてのドメインがわかっているため、[**バケット名を推測して権限を確認してみてください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

### **監視**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)と同様に、**Certificate Transparency** Logsを監視して、ドメインに**新しいサブドメイン**が作成されたかどうかを**監視**できます。

### **脆弱性の調査**

[**サブドメインテイクオーバー**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**サブドメイン**が**S3 bucket**を指している場合は、[**権限を確認してください**](../../network-services-pentesting/pentesting-web/buckets/index.html)。

資産の発見時にすでに見つけたものとは**異なるIPを持つサブドメイン**を見つけた場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**を使った[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。実行中のサービスに応じて、**この本にある、それらを「攻撃」するための手法**を利用できます。\
_サブドメインがクライアントの管理外のIP上でホストされている場合があり、その場合はスコープ外です。注意してください。_

## IPs

初期段階で、いくつかの**IP範囲、ドメイン、サブドメイン**が見つかっているかもしれません。\
次に、それらの範囲に含まれるすべてのIPと、**ドメイン/サブドメインのIP（DNSクエリ）**を**集めます**。

以下の**無料API**を提供するサービスを使うと、**ドメインやサブドメインが過去に使用していたIP**も見つけられます。これらのIPはまだクライアントが所有している可能性があり、[**CloudFlare bypasses**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられるかもしれません。

- [**https://securitytrails.com/**](https://securitytrails.com/)

ツール[**hakip2host**](https://github.com/hakluke/hakip2host)を使って、特定のIPアドレスを指すドメインを調べることもできます。

### **脆弱性の調査**

**CDNに属さないすべてのIPをポートスキャンしてください**（CDNでは興味深いものが見つかる可能性が低いため）。検出した実行中のサービスに、**脆弱性が見つかる**可能性があります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を参照してください。

## Webサーバーの調査

> すべての企業とその資産を見つけ、スコープ内のIP範囲、ドメイン、サブドメインがわかりました。次はWebサーバーを探します。

これまでの手順で、発見した**IPとドメインの偵察**をすでに実施しているはずなので、Webサーバーをすべて見つけているかもしれません。まだ見つけていない場合は、スコープ内のWebサーバーを探すための**手早い方法**をいくつか紹介します。

これは**Webアプリの発見に特化した手順**なので、スコープで許可されている場合は、**脆弱性スキャン**と**ポートスキャン**も実施してください。

[**masscan**を使ってWebサーバーに関連するポートの開放をすばやく確認する方法はこちら](../pentesting-network/index.html#http-port-discovery)。\
Webサーバーを探すのに便利なツールとして、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)があります。ドメインのリストを渡すと、ポート80（http）と443（https）への接続を試みます。さらに、他のポートも試すように指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **スクリーンショット**

スコープ内に存在する**すべてのWebサーバー**（会社の**IP**、すべての**ドメイン**および**サブドメイン**）を発見したら、次にどこから始めればいいのか**分からない**かもしれません。そこで、簡単にするために、まずはすべてのサーバーのスクリーンショットを撮りましょう。**メインページ**を**見る**だけでも、より**脆弱**である可能性の高い**奇妙な**エンドポイントを見つけられます。

この方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使えます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を解析し、**脆弱性が含まれていそうなもの**とそうでないものを判別できます。

## パブリッククラウドのアセット

会社に属する可能性のあるクラウドアセットを見つけるには、まずその会社を特定できるキーワードのリストを作ります。たとえば、暗号資産関連の会社なら、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、**バケットでよく使われる単語**のワードリストも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、それらの単語を使って**組み合わせ**を生成します（詳しくは[**Second Round DNS Brute-Force**](#second-dns-bruteforce-round)を参照）。

生成したワードリストを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを利用できます。**

Cloud Assetsを探すときは、**AWSのバケットだけでなく、ほかのものも探す**ようにしてください。

### **脆弱性の調査**

**公開されているバケットや、外部に公開されたcloud functions**などを見つけたら、それらに**アクセス**し、何が提供されているか、悪用できるかを確認してください。

## メールアドレス

スコープ内の**ドメイン**と**サブドメイン**があれば、メールアドレスの検索を始めるのに**必要な情報はほぼ揃っています**。会社のメールアドレスを見つけるのに、特に役立った**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを使用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性の調査**

メールアドレスは、後でWebログインや認証サービス（SSHなど）に対する**brute-force**に役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIからメールアドレスの持ち主に関する**追加情報**を得られるため、フィッシングキャンペーンに役立ちます。

## 認証情報のleak

**ドメイン**、**サブドメイン**、**メールアドレス**があれば、過去にleakした認証情報のうち、それらのメールアドレスに関連するものを探し始められます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性の調査**

**有効なleak済み**認証情報を見つけたら、簡単に成果を得られます。

## シークレットのleak

認証情報のleakは、**機密情報がleakされ、販売された**会社への攻撃に関連しています。しかし、それらのデータベースに情報が含まれていない**別のleak**によって、会社が影響を受けている場合もあります。

### Githubのleak

認証情報やAPIが、**会社**の**公開リポジトリ**や、その会社で働く**ユーザー**の公開リポジトリからleakしている可能性があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**ツール**を使うと、**組織**とその開発者の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/zricethezav/gitleaks)を自動的に実行できます。

**Leakos**は、指定した**URL**のテキスト全体に対して**gitleaks**を実行する用途にも使えます。**Webページにもシークレットが含まれている**ことがあるためです。

#### Github Dorks

組織内で検索できる**GitHub dorks**については、[GitHub dorks and leaks page](github-leaked-secrets.md)を確認してください。

### Pasteサイトのleak

攻撃者や単なる従業員が、**会社のコンテンツをpasteサイトに公開する**ことがあります。そこに**機密情報が含まれている**場合もそうでない場合もありますが、検索する価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpasteサイトを同時に検索できます。

### Google Dorks

古くても有用なGoogle dorksは、**公開されるべきでない情報を見つける**のに常に役立ちます。唯一の問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に手動では実行できないほど**数千件**ものクエリが含まれていることです。そこで、お気に入りの10件を選ぶか、[**Gorks**](https://github.com/carlospolop/Gorks) **などのツールを使ってすべて実行**できます。

_通常のGoogleブラウザーを使ってデータベース全体を実行しようとするツールは、Googleにすぐブロックされるため、処理が終わらない点に注意してください。_

### **脆弱性の調査**

**有効なleak済み**認証情報やAPIトークンを見つけたら、簡単に成果を得られます。

## 公開コードの脆弱性

会社が**オープンソースコード**を公開していると分かったら、それを**解析**し、**脆弱性**を探すことができます。

**言語によって**使用できる**ツール**は異なります。[source-code review tools](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を参照してください。

公開リポジトリを**スキャン**できる無料サービスもあります。たとえば、次のとおりです。

- [**Snyk**](https://app.snyk.io/)

## [**Pentesting Web Methodology**](../../network-services-pentesting/pentesting-web/index.html)

バグハンターが発見する**脆弱性の大半**は**Webアプリケーション**に存在します。そこでこの時点で、**Webアプリケーションのテスト方法**について説明します。[**こちらで詳しく確認できます**](../../network-services-pentesting/pentesting-web/index.html)。

また、[**Web Automated Scanners open source tools**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションにも特に触れておきたいと思います。非常に重大な脆弱性を見つけることは期待できませんが、**ワークフローに組み込んで、初期段階でWebに関する情報を得る**のに役立ちます。

## まとめ

> おめでとうございます！この時点で、**基本的なenumerationはすべて**完了しています。もちろん、これは基本にすぎません。さらに多くのenumerationが可能です（後ほど、さらに詳しい手法を紹介します）。

ここまでに、次のことを実施しました。

1. スコープ内の**会社**をすべて発見した
2. 会社に属する**アセット**をすべて発見した（スコープ内であれば、vuln scanも実施した）
3. 会社に属する**ドメイン**をすべて発見した
4. ドメインの**サブドメイン**をすべて発見した（subdomain takeoverの可能性は？）
5. スコープ内の**IP**をすべて発見した（CDN経由のものと**そうでないもの**）
6. **Webサーバー**をすべて発見し、スクリーンショットを撮った（詳しく調べる価値のあるものは？）
7. 会社に属する可能性のある**パブリッククラウドのアセット**をすべて発見した
8. 大きな成果にすぐつながる可能性のある**メールアドレス**、**認証情報のleak**、**シークレットのleak**
9. 発見したWebサイトをすべて**Pentesting**した

## **Reconを自動化する総合ツール**

指定したスコープに対して、ここで紹介した作業の一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - 少し古く、更新されていません

## References

- [1] [Jason Haddix – The Bug Hunter's Methodology v4.0: Recon Edition](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB: Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – Faviconについて：ブラウザーアイコンから攻撃対象領域インテリジェンスまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – BugBounties、OSINTなどにfavicon.icoを活用する](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyに対する時間相関攻撃によるドメインの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なSubdomain Takeoverキャンペーンを発見（および再現）する](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：独自のSubdomain Enumeration手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – サブドメインをすべて発見するワークフロー、第1部](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – 自動化されたTrickest Workflowを使ったサブドメインの総当たりによる発見、第2部](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
