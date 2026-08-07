# Phishingの検出

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Phishingの試みを検出するには、**現在使われているPhishing techniquesを理解することが重要です**。この投稿の親ページにはこの情報が記載されているため、現在使われているtechniquesを把握していない場合は、親ページに移動して少なくともそのセクションを読むことを推奨します。

この投稿は、**攻撃者が何らかの方法で被害者のdomain nameを模倣または使用しようとする**という考えに基づいています。あなたのdomainが`example.com`で、何らかの理由により`youwonthelottery.com`のような完全に異なるdomain nameを使ってPhishingされた場合、これらのtechniquesでは発見できません。

## Domain name variations

メール内で**類似したdomain name**を使用する**Phishing**の試みを**発見する**のは、かなり**簡単**です。\
攻撃者が使用する可能性の高い**Phishing nameのリストを生成**し、それが**登録済みか確認**するか、そのdomainを使用している**IP**が存在するか確認するだけで十分です。

### Finding suspicious domains

この目的には、以下のいずれかのtoolsを使用できます。これらのtoolsは、domainに割り当てられたIPが存在するか確認するため、DNS requestsも自動的に実行することに注意してください。

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: candidate listを生成した場合は、それをDNS resolver logsにも入力して、**org内部からのNXDOMAIN lookups**（攻撃者が実際に登録する前に、ユーザーがtypoしたdomainへアクセスしようとする動作）を検出してください。policyで許可されている場合は、これらのdomainをsinkholeするか事前にblockしてください。

### Bitflipping

**このtechniqueの簡単な説明は親ページにあります。または、元のresearchを** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)<sup>[[1]](#references)</sup> **で読むことができます**

例えば、domain microsoft.comの1 bit modificationによって、_windnws.com._ に変換できます。\
**攻撃者は、正規ユーザーを自身のinfrastructureへredirectするため、被害者に関連するbit-flipping domainを可能な限り多数登録する可能性があります**。<sup>[[1]](#references)</sup>

**考えられるすべてのbit-flipping domain nameもmonitoring対象にする必要があります。**

homoglyph/IDN lookalikes（Latin/Cyrillic charactersの混在など）も考慮する必要がある場合は、以下を確認してください。

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

potential suspicious domain nameのリストを作成したら、それらを**確認**し（主にHTTPおよびHTTPSのports）、被害者のdomainに似たlogin formを**使用しているか確認**してください。\
port 3333を確認して、open状態で`gophish`のinstanceが実行されているか確認することもできます。\
**発見した各suspicious domainの登録時期**を把握するのも有用です。新しいdomainほどriskが高くなります。\
HTTPおよび/またはHTTPSのsuspicious web pageの**screenshots**を取得し、疑わしいか確認できます。疑わしい場合は、**accessして詳しく調査**してください。

### Advanced checks

さらに一歩進めたい場合は、これらのsuspicious domainを**monitoringし、定期的に（毎日？数秒から数分しかかかりません）追加のdomainを検索する**ことを推奨します。関連するIPのopen **ports**も**確認**し、**`gophish`または類似したtoolsのinstancesを検索**してください（攻撃者もミスをするためです）。また、suspicious domainおよびsubdomainのHTTPおよびHTTPS web pageを**monitoringして**、被害者のweb pageからlogin formをコピーしていないか確認してください。\
これを**automateする**には、被害者のdomainにあるlogin formのリストを用意し、suspicious web pageをspiderし、suspicious domain内で見つかった各login formと被害者のdomainの各login formを`ssdeep`のようなtoolで比較することを推奨します。\
suspicious domainのlogin formを特定できた場合は、**junk credentialsを送信**し、**被害者のdomainへredirectされるか確認**してみてください。

---

### faviconおよびweb fingerprintsによるHunting（Shodan/ZoomEye/Censys）

多くのPhishing kitは、偽装対象のbrandのfaviconを再利用します。Internet-wide scannersは、base64-encoded faviconのMurmurHash3を計算します。hashを生成し、それをpivotに使用できます。

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan にクエリを実行: `http.favicon.hash:309020573`
- Tooling を使用: favfreak などの community tools を確認し、Shodan/ZoomEye/Censys 用の hash と dork を生成する。

Notes
- Favicon は再利用されるため、一致結果は手がかりとして扱い、行動する前に content と certs を検証する。
- より高い精度を得るには、domain-age および keyword heuristics と組み合わせる。

### URL telemetry hunting (urlscan.io)

`urlscan.io` は、送信された URL の過去の screenshots、DOM、requests、TLS metadata を保存する。これを利用して brand abuse や clones を hunting できる:<sup>[[2]](#references)</sup>

Example queries (UI or API):
- 正規の domains を除外して lookalikes を検索: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 自分の assets を hotlinking している sites を検索: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- recent results に制限: `AND date:>now-7d` を追加

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON では、以下を基準に pivot します:
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays` を確認し、lookalike 用の非常に新しい cert を検出する
- `task.source` の `certstream-suspicious` などの値を使用し、検出結果を CT monitoring と関連付ける

### RDAP による Domain age（scriptable）

RDAP は machine-readable な creation event を返します。**newly registered domain（NRD）** の flag に役立ちます。
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
ドメインに登録期間の年齢バケット（例：<7日、<30日）をタグ付けしてパイプラインを強化し、それに応じてトリアージの優先順位を付けます。

### AiTMインフラを特定するTLS/JAxフィンガープリント

Modern credential-phishing increasingly uses **Adversary-in-the-Middle (AiTM)** reverse proxies (e.g., Evilginx) to steal session tokens. You can add network-side detections:

- イグレスでTLS/HTTPフィンガープリント（JA3/JA4/JA4S/JA4H）を記録します。一部のEvilginxビルドでは、安定したJA4クライアント/サーバー値が観測されています。既知の悪性フィンガープリントには弱いシグナルとしてのみアラートを出し、必ずコンテンツおよびドメインインテリジェンスで確認してください。<sup>[[3]](#references)</sup>
- CTまたはurlscanで発見したlookalikeホストについて、TLS証明書メタデータ（発行者、SAN数、ワイルドカードの使用、Validity）をプロアクティブに記録し、DNSの経過期間およびジオロケーションと相関させます。

> 注：フィンガープリントは単独のブロッカーではなく、エンリッチメントとして扱ってください。フレームワークは進化し、ランダム化または難読化される可能性があります。

### キーワードを使用するドメイン名

親ページでは、**被害者のドメイン名をより大きなドメイン内に含める**ドメイン名の変形手法（例：paypal.comに対するpaypal-financial.com）についても説明しています。

#### Certificate Transparency

以前の「Brute-Force」アプローチを使用することはできませんが、Certificate Transparencyのおかげで、このようなフィッシング試行を**発見することは実際に可能です**。CAによって証明書が発行されるたびに、その詳細が公開されます。つまり、Certificate Transparencyを読み取る、または監視することで、**名前の中にキーワードを使用しているドメインを見つけることが可能です**。たとえば、攻撃者が[https://paypal-financial.com](https://paypal-financial.com)の証明書を生成した場合、その証明書を見ることで「paypal」というキーワードを見つけ、疑わしいメールが使用されていることを把握できます。

投稿[https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/)では、Censysを使用して特定のキーワードに該当する証明書を検索し、日付（「新しい」証明書のみ）およびCA発行者「Let's Encrypt」でフィルタリングできると提案しています。<sup>[[4]](#references)</sup>

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

ただし、無料のWebサービス[**crt.sh**](https://crt.sh)を使用して「同じこと」を実行できます。**キーワードを検索**し、必要に応じて結果を**日付およびCAでフィルタリング**できます。

![ドメイン名でキーワードを使用する - Certificate Transparency：ただし、無料のWebサービスcrt.shを使用して「同じこと」を実行できます。キーワードを検索し、結果を日付およびCAでフィルタリングできます。](<../../images/image (519).png>)

この最後のオプションでは、Matching Identitiesフィールドを使用して、実際のドメインのIDが疑わしいドメインのいずれかと一致するかどうかを確認することもできます（疑わしいドメインはfalse positiveである可能性がある点に注意してください）。

**もう1つの代替手段**は、素晴らしいプロジェクト[**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)です。CertStreamは、新しく生成された証明書のリアルタイムストリームを提供し、指定したキーワードを（ほぼ）リアルタイムで検出できます。実際、これを実行する[**phishing_catcher**](https://github.com/x0rz/phishing_catcher)というプロジェクトがあります。

実践的なヒント：CTのヒットをトリアージする際は、NRD、信頼されていない/不明なregistrar、privacy-proxy WHOIS、そして非常に最近の`NotBefore`時刻を持つ証明書を優先してください。ノイズを減らすため、所有するドメイン/ブランドのallowlistを維持してください。

#### **新しいドメイン**

**最後の代替手段の1つ**は、一部のTLDについて**新しく登録されたドメイン**のリストを取得し（[Whoxy](https://www.whoxy.com/newly-registered-domains/)がそのようなサービスを提供しています）、これらのドメイン内の**キーワードを確認する**ことです。ただし、長いドメインでは通常、1つ以上のサブドメインが使用されるため、キーワードがFLD内に現れず、フィッシングサブドメインを見つけられない場合があります。

追加のヒューリスティック：特定の**ファイル拡張子TLD**（例：`.zip`、`.mov`）は、アラート時に特に疑わしいものとして扱ってください。これらはlure内のファイル名と混同されやすいため、精度を高めるにはTLDシグナルをブランドキーワードおよびNRDの経過期間と組み合わせます。

## References

- [1] [bitflippingによるMicrosoftのwindows.comへのトラフィックのHijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [2] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [3] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [4] [Finding Phishing: Tools and Techniques](https://0xpatrik.com/phishing-domains/)

{{#include ../../banners/hacktricks-training.md}}
