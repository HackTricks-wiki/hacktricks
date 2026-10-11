# 外部偵察の方法論

{{#include ../../banners/hacktricks-training.md}}

## 資産の発見

> ある企業に属するものはすべてスコープ内だと言われ、その企業が実際に何を所有しているのかを突き止めたいとします。

このフェーズの目的は、**親会社が所有するすべての企業**を特定し、次にそれらの企業の**すべての資産**を特定することです。そのために、次の手順を実施します。<sup>[[1]](#references)</sup>

1. 親会社による買収を調べ、スコープ内の企業を特定します。
2. 各企業のASN（存在する場合）を調べ、各企業が所有するIP範囲を特定します。
3. Reverse whois lookupを使って、最初の企業に関連する他の情報（組織名、ドメインなど）を検索します（この手順は再帰的に実施できます）。
4. Shodanの`org`や`ssl`フィルターなど、他の手法を使って追加の資産を検索します（`ssl`を使う手法は再帰的に実施できます）。

### **買収**

まず、**親会社が所有する他の企業**を把握する必要があります。\
1つの方法は、[https://www.crunchbase.com/](https://www.crunchbase.com)にアクセスし、**親会社を検索**して、**「acquisitions」**を**クリック**することです。そこに、親会社が買収した他の企業が表示されます。\
別の方法は、親会社の**Wikipedia**ページにアクセスし、**買収**について調べることです。\
上場企業の場合は、**SEC/EDGARへの提出書類**、**投資家向け情報**ページ、または各国の企業登記簿（例：英国の**Companies House**）を確認してください。\
世界規模の企業グループや子会社を調べるには、**OpenCorporates**（[https://opencorporates.com/](https://opencorporates.com/)）や**GLEIF LEI**データベース（[https://www.gleif.org/](https://www.gleif.org/)）を試してください。

> さて、この時点でスコープ内のすべての企業が把握できているはずです。次に、それらの資産の見つけ方を確認しましょう。

### **ASN**

自律システム番号（**ASN**）は、**自律システム**（AS）に対して**Internet Assigned Numbers Authority（IANA）**が割り当てる**一意の番号**です。\
**AS**は、外部ネットワークへのアクセスに関する明確に定義されたポリシーを持つ**IPアドレスのブロック**で構成され、単一の組織が管理しますが、複数の事業者で構成される場合もあります。

**企業にASNが割り当てられているか**を調べると、**IP範囲**を特定するのに役立ちます。**スコープ**内のすべての**ホスト**に対して**脆弱性テスト**を実施し、これらのIP内の**ドメインを探す**とよいでしょう。\
[**https://bgp.he.net/**](https://bgp.he.net)**、**[**https://bgpview.io/**](https://bgpview.io/) **、または** [**https://ipinfo.io/**](https://ipinfo.io/)で、企業**名**、**IP**、または**ドメイン**を使って**検索**できます。\
**企業の地域によっては、次のリンクが追加情報の収集に役立ちます：** [**AFRINIC**](https://www.afrinic.net) **（アフリカ）、** [**Arin**](https://www.arin.net/about/welcome/region/)**（北米）、** [**APNIC**](https://www.apnic.net) **（アジア）、** [**LACNIC**](https://www.lacnic.net) **（ラテンアメリカ）、** [**RIPE NCC**](https://www.ripe.net) **（ヨーロッパ）。いずれにしても、役立つ情報（IP範囲とWhois）はおそらく最初のリンクですでに確認できます。**

```bash
#You can try "automate" this with amass, but it's not very recommended
amass intel -org tesla
amass intel -asn 8911,50313,394161
```

また、[**BBOT**](https://github.com/blacklanternsecurity/bbot)**の** enumeration は、スキャンの最後に ASN を自動的に集約して要約します。

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

組織のIP範囲は、[http://asnlookup.com/](http://asnlookup.com)（無料APIあり）を使って調べることもできます。\
ドメインのIPとASNは、[http://ipv4info.com/](http://ipv4info.com)で調べられます。

### **脆弱性の調査**

この時点で、**スコープ内のすべてのアセットが判明している**ので、許可されている場合は、すべてのホストに対して**脆弱性スキャナー**（Nessus、OpenVAS、[**Nuclei**](https://github.com/projectdiscovery/nuclei)）を実行できます。\
また、[**ポートスキャン**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実行したり、Shodan、Censys、ZoomEyeなどの**サービスを使って**開いているポートを**見つけたりすることもできます。見つかった内容に応じて、この本を参照し、実行中のさまざまなサービスのpentesting方法を確認してください。\
**また、デフォルトの**ユーザー名**と**パスワード**のリストを用意し、[https://github.com/x90skysn3k/brutespray](https://github.com/x90skysn3k/brutespray)を使ってサービスへの**bruteforceを試みることも有用です。**

## ドメイン

> スコープ内のすべての企業とそのアセットが判明したので、次はスコープ内のドメインを見つけます。

_以下に示す手法ではサブドメインも見つかる可能性があることに注意してください。この情報を軽視してはいけません。_

まず、各企業の**メインドメイン**を探します。たとえば、_Tesla Inc._ の場合は _tesla.com_ です。

### **Reverse DNS**

ドメインのIP範囲がすべて判明しているので、それらの**IPに対してreverse DNS lookupを実行し、スコープ内のドメインをさらに見つける**ことができます。被害者のDNSサーバー、またはよく知られたDNSサーバー（1.1.1.1、8.8.8.8）を使ってみてください。

```bash
dnsrecon -r <DNS Range> -n <IP_DNS>   #DNS reverse of all of the addresses
dnsrecon -d facebook.com -r 157.240.221.35/24 #Using facebooks dns
dnsrecon -r 157.240.221.35/24 -n 1.1.1.1 #Using cloudflares dns
dnsrecon -r 157.240.221.35/24 -n 8.8.8.8 #Using google dns
```

これを機能させるには、管理者がPTRを手動で有効にする必要があります。\
この情報には、オンラインツールも利用できます: [http://ptrarchive.com/](http://ptrarchive.com)。\
大規模な範囲では、[**massdns**](https://github.com/blechschmidt/massdns)や[**dnsx**](https://github.com/projectdiscovery/dnsx)などのツールを使うと、逆引きと情報の補完を自動化できます。

### **Reverse Whois (loop)**

**whois**には、**組織名**、**住所**、**メールアドレス**、電話番号など、興味深い**情報**が数多く含まれています。しかし、さらに興味深いのは、それらの項目を使って**reverse whois検索を実行すると、その会社に関連する他の資産を見つけられる**ことです（たとえば、同じメールアドレスが登録されている別のwhoisレコードなど）。\
次のオンラインツールを利用できます:

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

[**DomLink**](https://github.com/vysecurity/DomLink)を使って、この作業を自動化できます（whoxy APIキーが必要です）。\
[amass](https://github.com/OWASP/Amass)を使って、reverse whoisによる探索を自動化することもできます: `amass intel -d tesla.com -whois`

**新しいドメインを見つけるたびに、この手法でさらに多くのドメイン名を見つけられる点に注意してください。**

### **Trackers**

異なる2つのページで**同じtrackerの同じID**が見つかった場合、**両方のページ**は**同じチームが管理している**と推測できます。\
たとえば、複数のページで同じ**Google Analytics ID**や同じ**Adsense ID**が見つかった場合です。

これらのtrackerなどを検索できるページやツールがいくつかあります:

- [**Udon**](https://github.com/dhn/udon)
- [**BuiltWith**](https://builtwith.com)
- [**Sitesleuth**](https://www.sitesleuth.io)
- [**Publicwww**](https://publicwww.com)
- [**SpyOnWeb**](http://spyonweb.com)
- [**Webscout**](https://github.com/straightblast/Sc0ut)（共有されたanalytics/trackerから関連サイトを見つける）
- [**StackScan**](https://www.stackscan.com) - **無料プラン**（WebおよびAPI）。tracker IDに限らず、配信される任意のアセットを手掛かりに検索できます。スクリプトのパス、セルフホストされたbundle名、アセットの読み込み元ホストなどを指定すると、それを含むすべてのサイトが返されます

APIは単一ドメインのstackを返すため、候補のアセットが同じ環境に属していることを確認するのに役立ちます:

```bash
curl -H "Authorization: Bearer $TOKEN" -H "X-Tenant-Id: $WORKSPACE" \
  "https://api.stackscan.com/v1/tech-lookup/domains/lookup?domain=tesla.com"
```

検出された各技術をカテゴリとともに返します。Asset pivotingは現在webのみ対応しており、APIではドメインごとの検索が可能です。

### **Favicon**

同じfaviconのアイコンハッシュを調べることで、ターゲットに関連するドメインやサブドメインを見つけられることをご存じでしょうか？ これは、[@m4ll0k2](https://twitter.com/m4ll0k2) が作成した [favihash.py](https://github.com/m4ll0k/Bug-Bounty-Toolz/blob/master/favihash.py) ツールが行うことです。使い方は次のとおりです。

```bash
cat my_targets.txt | xargs -I %% bash -c 'echo "http://%%/favicon.ico"' > targets.txt
python3 favihash.py -f https://target/favicon.ico -t targets.txt -s
```

![Favihash results used to discover domains sharing a favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)

簡単に言うと、favihashを使えば、対象と同じfaviconアイコンのハッシュを持つドメインを見つけられます。

![favihash output used to discover domains with the same favicon hash](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)<sup>[[11]](#references)</sup>

既知のfaviconハッシュをShodanやFOFAのpivotとして使い、同じ技術を使用する、ほかに公開されているインスタンスを見つけましょう。<sup>[[5]](#references)</sup>

```bash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}'
# FOFA
icon_hash="116323821"
```

Webサイトのfaviconの**favicon hash**（faviconのバイト列を**base64-encoded**したものに対するMMH3）は、次のように**計算**できます。

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

favicon fingerprint は手がかりとして扱い、周辺のシグナルと照合して検証してください。<sup>[[3]](#references)[[4]](#references)</sup>

- **hash は証拠ではなく指標として扱う**: MMH3 はコンパクトなため、衝突、アイコンの使い回し、意図的な偽装が起こり得ます。
- **`/favicon.ico` 以外も調べる**: framework/build のパス、manifest ファイル、`browserconfig.xml`、`site.webmanifest`、`apple-touch-icon*`、インラインの data URL、HTML の `<link rel="icon">` タグを確認します。
- **WAF/SSO/IdP の制御下でも静的アセットにアクセスできる場合がある**: アイコンに直接リクエストし、`ETag`、`Last-Modified`、リダイレクト、キャッシュヘッダーを確認します。
- **周辺のシグナルで一致を検証する**: タイトル、HTML/body hash、ヘッダー、TLS 証明書の subject/SAN、製品コンポーネント、公開ポートを比較します。
- **HTML/body hash でクラスタリングする**: 一貫したテンプレートは fingerprint の確度を高めます。テンプレートが混在している場合は、汎用または共有アイコンの可能性があります。
- **関連性のない signature、ポート、製品に同じ hash が見つかった場合、潜在的な honeypot またはプレースホルダーとして扱います。**
- **判断が難しい対象では、実在するページと存在しないパス**（例: `/_favicon_probe_<8-hex>`）を比較します。ホスティング用またはパーキング用の応答が一致すれば、アイコンが共有されている理由を説明できる場合があります。
- **favicon hash を製品や CPE に対応づける Nuclei の検出ルールや公開データセットを使って、初期トリアージを行います。**
- **IP 中心のカバレッジの不足に注意する**: CDN 経由、SNI ルーティング、anycast、ドメインのみのサーフェスは、Shodan のようなデータセットに含まれないことがあります。

### **Copyright / 固有文字列**

Web ページ内で、同じ組織の異なる Web サイト間で共有されている可能性のある**文字列**を検索します。**copyright 文字列**はその好例です。その文字列を**Google**、他の**ブラウザー**、さらには**Shodan**で検索します: `shodan search http.html:"Copyright string"`

### **CRT 時刻**

次のような cron job を設定するのは一般的です。

```bash
# /etc/crontab
37 13 */10 * * certbot renew --post-hook "systemctl reload nginx"
```

サーバー上のすべての証明書を同時に更新するために使われます。証明書のタイムスタンプやcertificate-transparencyログの位置を相関させると、関連するドメインが見つかることがあります。<sup>[[6]](#references)</sup>

**certificate transparency**ログを直接使う方法もあります:

- [https://crt.sh/](https://crt.sh/)
- [https://certspotter.com/](https://certspotter.com/)
- [https://search.censys.io/](https://search.censys.io/)
- [https://chaos.projectdiscovery.io/](https://chaos.projectdiscovery.io/) + [**chaos-client**](https://github.com/projectdiscovery/chaos-client)

### メールのDMARC情報

[https://dmarc.live/info/google.com](https://dmarc.live/info/google.com)のようなWebサイトや、[https://github.com/Tedixx/dmarc-subdomains](https://github.com/Tedixx/dmarc-subdomains)のようなツールを使って、**同じDMARC情報を共有するドメインやサブドメイン**を見つけられます。\
ほかに役立つツールとして、[**spoofcheck**](https://github.com/BishopFox/spoofcheck)や[**dmarcian**](https://dmarcian.com/)があります。

### **Passive Takeover**

放置されたAレコードは、cloud providerがIPを再割り当てすると到達可能になることがあります。参照先の研究では、インスタンスを用意し、そのアドレスをpassive DNSデータと相関させる機会利用型の手順が示されています。takeoverのシナリオは、許可されたスコープ内でのみテストしてください。<sup>[[7]](#references)</sup>

### **その他の方法**

新しいドメインを見つけるたびに、該当する探索の切り口を繰り返してください。それぞれの結果から、最初の手掛かりだけでは見えなかった追加の証明書名、passive DNSの関連性、faviconの一致、組織識別子が見つかることがあります。<sup>[[9]](#references)[[10]](#references)</sup>

**Shodan**

IP空間を所有する組織名はすでにわかっています。Shodanでは、次のようにその情報を使って検索できます: `org:"Tesla, Inc."` 見つかったホストのTLS証明書を確認し、新しく見つかった想定外のドメインがないか調べてください。

メインのWebページの**TLS証明書**にアクセスして**組織名**を取得し、その名前を**Shodan**が把握しているすべてのWebページの**TLS証明書**から検索することもできます。フィルターは`ssl:"Tesla Motors"`です。または、[**sslsearch**](https://github.com/HarshVaragiya/sslsearch)のようなツールを使ってください。

**Assetfinder**

[**Assetfinder** ](https://github.com/tomnomnom/assetfinder)は、メインドメインに**関連するドメイン**と、それらの**サブドメイン**を探すツールです。非常に優れています。

**Passive DNS / Historical DNS**

Passive DNSデータは、今も名前解決できる、またはtakeover可能な**古く忘れられたレコード**を見つけるのに役立ちます。以下を確認してください:

- [https://securitytrails.com/](https://securitytrails.com/)
- [https://community.riskiq.com/](https://community.riskiq.com/) (PassiveTotal)
- [https://www.domaintools.com/products/iris/](https://www.domaintools.com/products/iris/)
- [https://www.farsightsecurity.com/solutions/dnsdb/](https://www.farsightsecurity.com/solutions/dnsdb/)

### **脆弱性を探す**

[domain takeover](../../pentesting-web/domain-subdomain-takeover.md#domain-takeover)がないか確認してください。会社が**あるドメインを使用しているものの、所有権を失っている**可能性があります。（十分に安ければ）そのドメインを登録し、会社に知らせてください。

資産探索ですでに見つけたものとは**異なるIPを持つドメイン**を見つけた場合は、**基本的な脆弱性スキャン**（NessusやOpenVASを使用）と、**nmap/masscan/shodan**を使った[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。実行中のサービスに応じて、**この本でそれらを「攻撃」するためのテクニックを見つけられます**。\
_ドメインがクライアントの管理下にないIP上でホストされていることがあり、その場合はスコープ外です。注意してください。_

## サブドメイン

> スコープ内のすべての会社、それぞれの会社のすべての資産、会社に関連するすべてのドメインがわかりました。

見つかった各ドメインについて、考えられるすべてのサブドメインを探します。

> [!TIP]
> ドメインを見つけるためのツールやテクニックの中には、サブドメインの発見にも役立つものがあります。

### **DNS**

**DNS**レコードから**サブドメイン**を取得してみましょう。**Zone Transfer**も試してください（脆弱な場合は報告してください）。

```bash
dnsrecon -a -d tesla.com
```

### **OSINT**

大量のサブドメインを最も速く取得する方法は、外部ソースを検索することです。最もよく使われる **tools** は次のとおりです（より良い結果を得るには、API keys を設定してください）。


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

サブドメインの発見に特化しているわけではありませんが、サブドメインの発見に役立つ**興味深いツール/API**もあります。

- [**IP.THC.ORG**](https://ip.thc.org) 無料 API

```bash
curl https://ip.thc.org/tesla.com
```

- [**Crobat**](https://github.com/cgboal/sonarsearch)**:** サブドメインを取得するために API [https://sonar.omnisint.io](https://sonar.omnisint.io) を使用します。

```bash
# Get list of subdomains in output from the API
## This is the API the crobat tool will use
curl https://sonar.omnisint.io/subdomains/tesla.com | jq -r ".[]"
```

- [**JLDC 無料 API**](https://jldc.me/anubis/subdomains/google.com)

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

- [**securitytrails.com**](https://securitytrails.com/) には、サブドメインと IP 履歴を検索できる無料 API があります
- [**chaos.projectdiscovery.io**](https://chaos.projectdiscovery.io/#/)
- [**activedns.net**](https://activedns.net/)

このプロジェクトでは、**bug-bounty プログラムに関連するすべてのサブドメインを無料で提供しています**。このデータは [chaospy](https://github.com/dr-0x0x/chaospy) を使って取得することも、このプロジェクトで使用されているスコープを [https://github.com/projectdiscovery/chaos-public-program-list](https://github.com/projectdiscovery/chaos-public-program-list) から取得することもできます。

これらのツールの多くを比較した記事はこちらです: [https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off](https://blog.blacklanternsecurity.com/p/subdomain-enumeration-tool-face-off)

### **DNS Brute force**

候補となるサブドメイン名を使って DNS サーバーに brute-force を行い、新しい **サブドメイン**を探してみましょう。

この作業には、次のような**一般的なサブドメイン用 wordlist**が必要です。

- [https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056)
- [https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt](https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt)
- [https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip](https://localdomain.pw/subdomain-bruteforce-list/all.txt.zip)
- [https://github.com/pentester-io/commonspeak](https://github.com/pentester-io/commonspeak)
- [https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

信頼性の高い DNS resolver の IP も必要です。信頼できる DNS resolver のリストを作成するには、[https://www.wirewiki.com/dns-servers/all.txt](https://www.wirewiki.com/dns-servers/all.txt) から resolver をダウンロードし、[**dnsvalidator**](https://github.com/vortexau/dnsvalidator) でフィルタリングできます。または、こちらを使用できます: [https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt](https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt)

DNS brute-force に最もおすすめのツールは次のとおりです。

- [**massdns**](https://github.com/blechschmidt/massdns): 効果的な DNS brute-force を実行した最初のツールです。非常に高速ですが、false positive が発生しやすいです。

```bash
sed 's/$/.domain.com/' subdomains.txt > bf-subdomains.txt
./massdns -r resolvers.txt -w /tmp/results.txt bf-subdomains.txt
grep -E "tesla.com. [0-9]+ IN A .+" /tmp/results.txt
```

- [**gobuster**](https://github.com/OJ/gobuster): これはresolverを1つだけ使うと思います。

```
gobuster dns -d mysite.com -t 50 -w subdomains.txt
```

- [**shuffledns**](https://github.com/projectdiscovery/shuffledns) は `massdns` のラッパーで、Go で書かれており、active bruteforce による有効なサブドメインの列挙や、ワイルドカード処理と簡単な入出力に対応したサブドメインの解決を行えます。

```
shuffledns -d example.com -list example-subdomains.txt -r resolvers.txt
```

- [**puredns**](https://github.com/d3mondev/puredns): これも `massdns` を使用します。

```
puredns bruteforce all.txt domain.com
```

- [**aiodnsbrute**](https://github.com/blark/aiodnsbrute) は asyncio を使ってドメイン名を非同期にブルートフォースします。

```
aiodnsbrute -r resolvers -w wordlist.txt -vv -t 1024 domain.com
```

### 2回目のDNS Brute-Force

オープンソースの情報と brute-forcing を使ってサブドメインを見つけた後、見つかったサブドメインを変化させて、さらに多くのサブドメインを探すことができます。この目的には、次のツールが役立ちます。

- [**dnsgen**](https://github.com/ProjectAnte/dnsgen)**:** ドメインとサブドメインを指定すると、さまざまな permutation を生成します。

```bash
cat subdomains.txt | dnsgen -
```

- [**goaltdns**](https://github.com/subfinder/goaltdns): ドメインとサブドメインを指定すると、permutations を生成します。
  - goaltdns の permutations **wordlist** は[**こちら**](https://github.com/subfinder/goaltdns/blob/master/words.txt)から入手できます。

```bash
goaltdns -l subdomains.txt -w /tmp/words-permutations.txt -o /tmp/final-words-s3.txt
```

- [**gotator**](https://github.com/Josue87/gotator)**:** ドメインとサブドメインを指定すると、置換候補を生成します。置換ファイルが指定されていない場合、gotatorは独自のものを使用します。

```
gotator -sub subdomains.txt -silent [-perm /tmp/words-permutations.txt]
```

- [**altdns**](https://github.com/infosec-au/altdns): サブドメインの permutation を生成するだけでなく、名前解決も試せます（ただし、前述のコメントアウトされたツールを使う方がよいでしょう）。
  - altdns の permutation **wordlist** は[**こちら**](https://github.com/infosec-au/altdns/blob/master/words.txt)から入手できます。

```
altdns -i subdomains.txt -w /tmp/words-permutations.txt -o /tmp/asd3
```

- [**dmut**](https://github.com/bp0lr/dmut): サブドメインの permutations、mutations、alteration を実行する別のツールです。結果を brute force します（DNSワイルドカードには対応していません）。
  - dmut の permutations wordlist は[**こちら**](https://raw.githubusercontent.com/bp0lr/dmut/main/words.txt)から入手できます。

```bash
cat subdomains.txt | dmut -d /tmp/words-permutations.txt -w 100 \
    --dns-errorLimit 10 --use-pb --verbose -s /tmp/resolvers-trusted.txt
```

- [**alterx**](https://github.com/projectdiscovery/alterx)**:** ドメインを基に、指定されたパターンに基づいて新たなサブドメイン候補名を生成し、さらに多くのサブドメインの発見を試みます。

#### スマートな permutations の生成

- [**regulator**](https://github.com/cramppet/regulator): 発見したサブドメインから正規表現のようなパターンを学習し、名前解決を試す候補名を生成します。<sup>[[8]](#references)</sup>

```bash
python3 main.py adobe.com adobe adobe.rules
make_brute_list.sh adobe.rules adobe.brute
puredns resolve adobe.brute --write adobe.valid
```

- [**subzuf**](https://github.com/elceef/subzuf)**:** _subzuf_ は、非常にシンプルながら効果的な DNS response-guided algorithm を組み合わせたサブドメイン brute-force fuzzer です。カスタマイズした wordlist や過去の DNS/TLS records など、提供された入力データを利用して、対応するドメイン名を正確に合成し、DNS scan 中に収集した情報に基づいてループ内でさらに拡張します。

```
echo www | subzuf facebook.com
```

### **サブドメイン探索ワークフロー**

Trickestのワークフロー例では、OSINT、DNS brute force、permutationの各ステージを組み合わせ、再現可能なサブドメイン列挙を行います。<sup>[[9]](#references)[[10]](#references)</sup>

### **VHosts / Virtual Hosts**

サブドメインに属する**1つ以上のWebページ**を含むIPアドレスが見つかった場合、**OSINTソース**でIPアドレスに関連するドメインを調べるか、そのIPアドレス上のVHostドメイン名を**brute force**することで、同じIPアドレス上にあるほかのサブドメインを**見つけられる**可能性があります。

#### OSINT

[**HostHunter**](https://github.com/SpiderLabs/HostHunter) **やほかのAPIを使って、IPアドレス上のVHostsを見つけられます**。

**Brute Force**

Webサーバー上にサブドメインが隠れている可能性がある場合は、brute forceを試せます。

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
> この手法を使うと、内部/非公開のendpointにもアクセスできる場合があります。

### **CORS Brute Force**

有効なドメイン/subdomainを_**Origin**_ヘッダーに設定した場合にのみ、_**Access-Control-Allow-Origin**_ヘッダーを返すページが見つかることがあります。このような状況では、この挙動を悪用して新しい**subdomain**を**発見**できます。

```bash
ffuf -w subdomains-top1million-5000.txt -u http://10.10.10.208 -H 'Origin: http://FUZZ.crossfit.htb' -mr "Access-Control-Allow-Origin" -ignore-body
```

### **Buckets Brute Force**

**subdomains**を探す際は、何らかの**bucket**を**指している**かどうかに注意し、該当する場合は[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)**してください。**\
また、この時点でスコープ内のすべてのドメインが分かっているはずなので、[**考えられるbucket名をブルートフォースし、権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してみてください。

### **監視**

[**sublert** ](https://github.com/yassineaboukir/sublert/blob/master/sublert.py)が行うように、**Certificate Transparency** Logsを監視することで、ドメインに**新しいsubdomain**が作成されたかどうかを**監視**できます。

### **脆弱性の調査**

[**subdomain takeover**](../../pentesting-web/domain-subdomain-takeover.md#subdomain-takeover)の可能性を確認してください。\
**subdomain**が**S3 bucket**を指している場合は、[**権限を確認**](../../network-services-pentesting/pentesting-web/buckets/index.html)してください。

アセットの調査ですでに見つかったものとは**異なるIPを持つsubdomain**が見つかった場合は、**基本的な脆弱性スキャン**（NessusまたはOpenVASを使用）と、**nmap/masscan/shodan**による[**port scan**](../pentesting-network/index.html#discovering-hosts-from-the-outside)を実施してください。実行中のサービスによっては、この書籍に**それらを「攻撃」するための手法**が載っています。\
_場合によっては、subdomainがクライアントの管理外のIP上でホストされており、スコープ外であることに注意してください。気をつけてください。_

## IPs

初期段階で、**IP範囲、ドメイン、subdomain**をいくつか**見つけている**かもしれません。\
それらの範囲に含まれるIPと、**ドメイン/subdomainのIP（DNSクエリ）**を**すべて集める**段階です。

以下の**無料API**を利用するサービスを使えば、**ドメインやsubdomainが過去に使用していたIP**も見つけられます。これらのIPは現在もクライアントが所有している可能性があり、[**CloudFlare bypass**](../../network-services-pentesting/pentesting-web/uncovering-cloudflare.md)を見つけられるかもしれません。

- [**https://securitytrails.com/**](https://securitytrails.com/)

また、[**hakip2host**](https://github.com/hakluke/hakip2host)ツールを使って、特定のIPアドレスを指すドメインを調べることもできます。

### **脆弱性の調査**

**CDNに属さないすべてのIPをport scan**してください（CDNでは興味深いものは見つからない可能性が高いため）。検出した実行中のサービスに、**脆弱性が見つかる**ことがあります。

ホストのスキャン方法については、[**ガイド**](../pentesting-network/index.html)を参照してください。

## Webサーバーの探索

> すべての企業とそのアセットを見つけ、スコープ内のIP範囲、ドメイン、subdomainも把握できました。Webサーバーを探す段階です。

前の手順で、見つかった**IPやドメインのrecon**をすでに実施していると思います。そのため、考えられる**Webサーバーをすべて発見済み**かもしれません。まだの場合は、スコープ内のWebサーバーを探すための**手早い方法**をいくつか紹介します。

ここでは**Webアプリの発見**に重点を置いているため、スコープで許可されている場合は、**脆弱性スキャン**と**port scan**も実施してください。

[masscanを使ってWebサーバー関連の**open port**を素早く発見する方法は、こちら](../pentesting-network/index.html#http-port-discovery)にあります。\
Webサーバーを探すための使いやすいツールとして、[**httprobe**](https://github.com/tomnomnom/httprobe)**、**[**fprobe**](https://github.com/theblackturtle/fprobe)、[**httpx**](https://github.com/projectdiscovery/httpx)もあります。ドメインのリストを渡すと、port 80（http）と443（https）への接続を試みます。さらに、ほかのportも試すよう指定できます。

```bash
cat /tmp/domains.txt | httprobe #Test all domains inside the file for port 80 and 443
cat /tmp/domains.txt | httprobe -p http:8080 -p https:8443 #Check port 80, 443 and 8080 and 8443
```

### **スクリーンショット**

スコープ内にある**すべてのWebサーバー**（会社の**IP**、すべての**ドメイン**と**サブドメイン**）を見つけたものの、**どこから始めればよいかわからない**かもしれません。そこで、簡単に始められるよう、まずはすべてのスクリーンショットを撮りましょう。**メインページ**を**見る**だけで、**脆弱**である**可能性が高い**、**奇妙な**エンドポイントを見つけられることがあります。

この方法を実行するには、[**EyeWitness**](https://github.com/FortyNorthSecurity/EyeWitness)、[**HttpScreenshot**](https://github.com/breenmachine/httpscreenshot)、[**Aquatone**](https://github.com/michenriksen/aquatone)、[**Shutter**](https://shutter-project.org/downloads/third-party-packages/)、[**Gowitness**](https://github.com/sensepost/gowitness)、または[**webscreenshot**](https://github.com/maaaaz/webscreenshot)**を使えます。**

さらに、[**eyeballer**](https://github.com/BishopFox/eyeballer)を使ってすべての**スクリーンショット**を解析すれば、**脆弱性がありそうなもの**とそうでないものを判別できます。

## パブリッククラウドの資産

会社に属する可能性のあるクラウド資産を見つけるには、まずその会社を特定する**キーワードのリストを用意**します。たとえば、暗号資産関連の会社であれば、`"crypto", "wallet", "dao", "<domain_name>", <"subdomain_names">`などの単語を使えます。

また、bucketでよく使われる**一般的な単語**のwordlistも必要です。

- [https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt](https://raw.githubusercontent.com/cujanovic/goaltdns/master/words.txt)
- [https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt](https://raw.githubusercontent.com/infosec-au/altdns/master/words.txt)
- [https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt](https://raw.githubusercontent.com/jordanpotti/AWSBucketDump/master/BucketNames.txt)

次に、これらの単語を使って**組み合わせを生成**します（詳しくは[**2回目のDNSブルートフォース**](#second-dns-bruteforce-round)を確認してください）。

生成したwordlistを使って、[**cloud_enum**](https://github.com/initstring/cloud_enum)**、**[**CloudScraper**](https://github.com/jordanpotti/CloudScraper)**、**[**cloudlist**](https://github.com/projectdiscovery/cloudlist) **、または** [**S3Scanner**](https://github.com/sa7mon/S3Scanner)**などのツールを実行できます。**

Cloud Assetsを探す際は、**AWSのbucketだけでなく、ほかの資産も探す**ことを忘れないでください。

### **脆弱性を探す**

**公開されているbucketやクラウド関数**などを見つけた場合は、**アクセスして**何ができるか、悪用できるかを確認しましょう。

## メールアドレス

スコープ内の**ドメイン**と**サブドメイン**がわかれば、**メールアドレスの検索**を始めるために必要なものはほぼ揃っています。会社のメールアドレスを見つけるのに、特に効果があった**API**と**ツール**は次のとおりです。

- [**theHarvester**](https://github.com/laramies/theHarvester) - APIを利用
- [**https://hunter.io/**](https://hunter.io/)のAPI（無料版）
- [**https://app.snov.io/**](https://app.snov.io/)のAPI（無料版）
- [**https://minelead.io/**](https://minelead.io/)のAPI（無料版）

### **脆弱性を探す**

メールアドレスは、後で**Webログインや認証サービス（SSHなど）をブルートフォースする**際に役立ちます。また、**フィッシング**にも必要です。さらに、これらのAPIからメールアドレスの持ち主に関する情報をより多く得られるため、フィッシングキャンペーンにも役立ちます。

## 認証情報のleak

**ドメイン**、**サブドメイン**、**メールアドレス**が揃ったら、それらのメールアドレスに紐づく過去の認証情報のleakを探し始められます。

- [https://leak-lookup.com](https://leak-lookup.com/account/login)
- [https://www.dehashed.com/](https://www.dehashed.com/)

### **脆弱性を探す**

**有効なleaked**認証情報が見つかれば、非常に簡単に成果を得られます。

## Secretのleak

認証情報のleakは、**機密情報が漏えいして販売された**企業への攻撃に関連しています。しかし、企業は、情報がこれらのデータベースに含まれていない**別のleak**の影響を受けていることもあります。

### Githubのleak

認証情報やAPIが、**会社の公開リポジトリ**や、その会社で働く**ユーザーの公開リポジトリ**からleakしている場合があります。\
[**Leakos**](https://github.com/carlospolop/Leakos)という**ツール**を使うと、**組織**とその**開発者**の**公開リポジトリ**をすべて**ダウンロード**し、[**gitleaks**](https://github.com/zricethezav/gitleaks)を自動で実行できます。

**Leakos**は、渡された**URL**にあるすべての**テキスト**に対して**gitleaks**を実行する用途にも使えます。Webページにもsecretが含まれていることがあるためです。

#### Github Dorks

組織内で検索するための**GitHub dorks**については、[GitHub dorksとleakのページ](github-leaked-secrets.md)を確認してください。

### Pasteサイトのleak

攻撃者や従業員が、pasteサイトに会社の情報を**公開する**ことがあります。**機密情報が含まれている**とは限りませんが、探してみる価値は十分にあります。\
[**Pastos**](https://github.com/carlospolop/Pastos)を使うと、80以上のpasteサイトを一度に検索できます。

### Google Dorks

古くても優秀なGoogle dorksは、**公開されるべきではない情報**を見つけるのにいつでも役立ちます。問題は、[**google-hacking-database**](https://www.exploit-db.com/google-hacking-database)に何千もの検索クエリが含まれていて、手動では実行できないことです。そこで、お気に入りの10個を使うか、[**Gorks**](https://github.com/carlospolop/Gorks) **などのツールを使ってすべて実行**できます。

_通常のGoogleブラウザーでデータベース全体を実行しようとするツールは、Googleにすぐブロックされるため、処理が終わらない点に注意してください。_

### **脆弱性を探す**

**有効なleaked**認証情報やAPI tokenが見つかれば、非常に簡単に成果を得られます。

## 公開コードの脆弱性

会社が**オープンソースコード**を公開しているとわかったら、それを**解析**して**脆弱性**を探せます。

**言語によって**使える**ツール**は異なります。[ソースコードレビュー用ツール](../../network-services-pentesting/pentesting-web/code-review-tools.md)の一覧を確認してください。

また、公開リポジトリを**スキャン**できる無料サービスもあります。

- [**Snyk**](https://app.snyk.io/)

## [**WebアプリケーションのPentesting手法**](../../network-services-pentesting/pentesting-web/index.html)

バグハンターが見つける**脆弱性の大半**は**Webアプリケーション**に存在します。そこで、この段階では**Webアプリケーションのテスト手法**について説明します。[**詳しくはこちら**](../../network-services-pentesting/pentesting-web/index.html)をご覧ください。

また、[**オープンソースのWeb自動スキャナーツール**](../../network-services-pentesting/pentesting-web/index.html#automatic-scanners)のセクションにも触れておきます。非常に深刻な脆弱性を見つけることは期待できませんが、**ワークフローに組み込んで初期段階のWeb情報を得る**のに役立ちます。

## まとめ

> おめでとうございます！ここまでで、基本的な**列挙作業はすべて完了**しました。もちろん、これは基本的な作業にすぎません。ほかにも多くの列挙方法があります（後ほどさらに紹介します）。

すでに次のことを行いました。

1. スコープ内の**すべての会社**を特定
2. 会社に属する**すべての資産**を特定（スコープ内であれば脆弱性スキャンも実施）
3. 会社に属する**すべてのドメイン**を特定
4. ドメインの**すべてのサブドメイン**を特定（subdomain takeoverはあるか？）
5. スコープ内の**すべてのIP**を特定（CDN経由のものと**そうでないもの**）
6. **すべてのWebサーバー**を見つけてスクリーンショットを撮影（詳しく調べる価値のあるものはあるか？）
7. 会社に属する**パブリッククラウド資産の候補**をすべて特定
8. **メールアドレス**、**認証情報のleak**、**secretのleak**から、**簡単に大きな成果を得られる可能性**を特定
9. 見つけた**すべてのWebサイトをPentesting**

## **Recon自動化ツール一式**

指定したスコープに対して、ここで提案した作業の一部を実行するツールがいくつかあります。

- [**https://github.com/yogeshojha/rengine**](https://github.com/yogeshojha/rengine)
- [**https://github.com/j3ssie/Osmedeus**](https://github.com/j3ssie/Osmedeus)
- [**https://github.com/six2dez/reconftw**](https://github.com/six2dez/reconftw)
- [**https://github.com/hackerspider1/EchoPwn**](https://github.com/hackerspider1/EchoPwn) - やや古く、更新されていません

## References

- [1] [Jason Haddix – バグハンターの手法 v4.0：Recon編](https://www.youtube.com/watch?v=p4JgIu1mceI)
- [2] [0xdf – HTB：Guardian](https://0xdf.gitlab.io/2026/02/28/htb-guardian.html)
- [3] [Aaron Ringo (Bishop Fox) – faviconについて：ブラウザーアイコンから攻撃対象領域のインテリジェンスまで](https://bishopfox.com/blog/on-favicons-from-browser-icons-to-attack-surface-intelligence)
- [4] [BishopFox/Favicons](https://github.com/BishopFox/Favicons)
- [5] [Devansh Batham (@Asm0d3us) – favicon.icoを武器化する：Bug Bounty、OSINTなどに活用](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)
- [6] [Arseniy Sharoglazov – Certificate Transparencyへの時間相関攻撃によるドメインの発見](https://swarm.ptsecurity.com/discovering-domains-via-a-time-correlation-attack)
- [7] [Kieran Miyamoto (kmsec.uk) – Passive Takeover：高額なsubdomain takeoverキャンペーンの発見と再現](https://kmsec.uk/blog/passive-takeover/)
- [8] [cramppet – Regulator：独自のサブドメイン列挙手法](https://cramppet.github.io/regulator/index.html)
- [9] [Carlos Polop – サブドメインを完全に発見するワークフロー、第1部](https://trickest.com/blog/full-subdomain-discovery-using-workflow/)
- [10] [Carlos Polop – Trickestの自動ワークフローを使ったサブドメインのブルートフォースによる完全な発見、第2部](https://trickest.com/blog/full-subdomain-brute-force-discovery-using-workflow/)
- [11] [InfoSecMatter – favihashの出力スクリーンショット](https://www.infosecmatter.com/wp-content/uploads/2020/07/favihash.jpg)
{{#include ../../banners/hacktricks-training.md}}
