# Phishingの検知

{{#include ../../banners/hacktricks-training.md}}

## Introduction

Phishingの試みを検知するには、**現在使用されているPhishing techniquesを理解すること**が重要です。この投稿の親ページにはこの情報が記載されているため、現在どのようなtechniquesが使われているか把握していない場合は、親ページに移動して少なくともそのセクションを読むことをお勧めします。

この投稿は、**attackersが何らかの方法でvictimのdomain nameを模倣または使用しようとする**という考えに基づいています。あなたのdomainが`example.com`で、何らかの理由で`youwonthelottery.com`のようなまったく異なるdomain nameを使ってphishingされた場合、これらのtechniquesでは発見できません。

## Domain name variations

メール内で**類似したdomain name**を使用する**phishing**の試みを**発見する**のは、ある程度**簡単**です。\
attackerが使用する可能性の高いphishing nameのリストを**生成**し、それが**登録済み**かどうかを**確認**するか、そのdomainを使用している**IP**が存在するかを確認するだけで十分です。

### Finding suspicious domains

この目的には、以下のtoolsのいずれかを使用できます。どちらも候補domainをresolveし、使用中かどうかを確認します。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

Tip: 候補リストを生成した場合は、それをDNS resolverのlogsにも入力し、**組織内部からのNXDOMAIN lookups**（attackerが実際に登録する前に、usersがtypoしたdomainへアクセスしようとしている状態）を検知します。policyで許可されている場合は、これらのdomainをsinkholeするか、事前にblockします。

### Bitflipping

**簡単な説明については親ページを参照してください。Windows.comのbitsquattingに関する一次researchについては、[Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/)および[BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください**。<sup>[[1]](#references)[[2]](#references)</sup>

例えば、domain microsoft.comの1 bit modificationによって、_windnws.com_に変化させることができます。\
**Attackersは、victimに関連するbit-flipping domainを可能な限り多数登録し、正規のusersを自身のinfrastructureへredirectする可能性があります**。<sup>[[1]](#references)[[2]](#references)</sup>

**考えられるすべてのbit-flipping domain nameもmonitorすべきです。**

homoglyph/IDN lookalike（Latin/Cyrillic characterの混在など）も考慮する必要がある場合は、以下を確認してください。

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

潜在的にsuspiciousなdomain nameのリストを作成したら、それらを**check**し（主にHTTPおよびHTTPS ports）、victimのdomainのlogin formに似たものを使用しているかどうかを**確認**します。\
port 3333がopenで、`gophish`のinstanceが実行されているかどうかを確認することもできます。\
発見したsuspicious domainが**どの程度古いか**を把握することも有用です。新しいdomainほどriskが高くなります。\
HTTPおよび/またはHTTPSのsuspiciousなweb pageの**screenshots**を取得し、それがsuspiciousかどうかを確認できます。suspiciousな場合は、**accessして詳しく調査**することもできます。

### Advanced checks

さらに一歩進めたい場合は、これらのsuspicious domainを**monitorし、定期的に（毎日？数秒から数分しかかかりません）追加のdomainを検索する**ことをお勧めします。また、関連するIPのopen **ports**を**check**し、**`gophish`または類似したtoolsのinstanceを検索**し（そうです、attackersもミスをします）、suspicious domainおよびsubdomainのHTTPとHTTPS web pageを**monitorして、victimのweb pageからlogin formがコピーされていないか確認**すべきです。\
これを**automateする**には、victimのdomainのlogin formのリストを用意し、suspiciousなweb pageをspiderで巡回し、suspicious domain内で発見した各login formとvictimのdomainの各login formを`ssdeep`のようなものを使って比較することをお勧めします。\
suspicious domainのlogin formを特定した場合は、**junk credentialsを送信し、victimのdomainへredirectされるか確認**してみることができます。

---

### faviconとweb fingerprintによるHunting（Shodan/Censys）

多くのphishing kitは、偽装対象のbrandのfaviconを再利用します。Shodanはbase64-encoded favicon dataをMurmurHash3でhashし、Censysは独自のfavicon hash fieldsを公開しています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan互換のhashを生成し、それをpivotに使用できます。

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan を検索: `http.favicon.hash:309020573`
- Tooling を使用: favfreak のような community tools を確認して、hash を計算し Shodan dorks を生成します。<sup>[[16]](#references)</sup>

ノート
- Favicon は再利用されるため、一致結果は手がかりとして扱い、実行に移す前にコンテンツと証明書を検証してください。
- domain-age および keyword heuristics と組み合わせることで、精度を向上できます。

### URL telemetry hunting (urlscan.io)

`urlscan.io` は、送信された URL の過去のスクリーンショット、DOM、リクエスト、TLS metadata を保存します。brand abuse や clone を調査できます:<sup>[[8]](#references)</sup>

Example queries (UI または API):
- 正規ドメインを除外して lookalike を検索: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- アセットを hotlinking しているサイトを検索: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 最近の結果に限定: `AND date:>now-7d` を追加

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON から以下の項目を軸に調査します：
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays` を利用して、lookalike に使われている非常に新しい証明書を特定する
- `certstream-suspicious` のような `task.source` の値を利用して、検出結果を CT monitoring と関連付ける

### RDAP によるドメインの登録期間（scriptable）

RDAP は、機械で読み取り可能な登録イベントを返します。**新たに登録されたドメイン（NRDs）**の検出に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
ドメインに登録経過時間のバケット（例：7日未満、30日未満）を付与してパイプラインを強化し、それに応じてトリアージの優先順位を付けます。

### AiTM インフラを発見するための TLS/JAx フィンガープリント

Credential-phishing では、**Adversary-in-the-Middle (AiTM)** の reverse proxy（例：Evilginx）を使用してセッショントークンを窃取することがあります。<sup>[[11]](#references)</sup> ネットワーク側で次の検知を追加できます。

- egress で TLS/HTTP フィンガープリント（JA3/JA4/JA4S/JA4H）をログに記録します。一部の Evilginx build では、安定した JA4 client/server 値が観測されています。既知の悪性フィンガープリントに対する alert は弱いシグナルとしてのみ扱い、必ず content と domain intel で確認します。<sup>[[12]](#references)</sup>
- CT または urlscan で発見した lookalike host について、TLS certificate metadata（issuer、SAN count、wildcard の使用、validity）を事前に記録し、DNS age および geolocation と相関させます。

> 注：フィンガープリントは enrichment として扱い、単独の blocker として使用しないでください。framework は進化し、randomise や obfuscate が行われる可能性があります。

### キーワードを使用するドメイン名

親ページでは、**victim の domain name をより大きな domain の内部に含める**ドメイン名 variation technique（例：paypal.com に対する paypal-financial.com）についても説明しています。

#### Certificate Transparency

Certificate Transparency (CT) logs は certificate identity を公開するため、Subject または SAN name で brand keyword を検索すると lookalike domain を発見できます（たとえば、`paypal-financial.com` の certificate から `paypal` keyword が分かります）。必要に応じて issuance date と CA で結果を filter し、keyword match は false positive の可能性があるため、候補を validate してください。<sup>[[13]](#references)</sup>

Patrik Hudak のオリジナルの [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) では、Let's Encrypt などの certificate date と issuer の filter を含め、この workflow を Censys で実行する方法を示しています。<sup>[[13]](#references)</sup>

無料の [**crt.sh**](https://crt.sh) service を使用して keyword を検索し、date と CA で結果を filter することもできます。<sup>[[13]](#references)</sup>

その Matching Identities field は、real domain と suspicious domain の identity の比較に役立ちますが、match は証拠ではなく lead として扱ってください。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) は CT update をほぼ real time で stream し、[*phishing_catcher*](https://github.com/x0rz/phishing_catcher) はその stream を取り込んで suspicious certificate name を score 付けします。<sup>[[14]](#references)[[15]](#references)</sup>

実践的な tip：CT hit のトリアージでは、NRD、untrusted/unknown registrar、privacy-proxy WHOIS、および `NotBefore` time が非常に新しい cert を優先します。所有する domain/brand の allowlist を維持して noise を減らしてください。

#### **新しいドメイン**

2 つ目の option は、TLD ごとに新しく登録された domain を収集し（たとえば [Whoxy](https://www.whoxy.com/newly-registered-domains/) 経由）、brand keyword で filter することです。registered domain に keyword が含まれていない場合、subdomain 上で host される phishing を見逃します。<sup>[[13]](#references)</sup>

追加の heuristic：特定の **file-extension TLD**（例：`.zip`、`.mov`）は、alerting でより強く疑ってください。これらは lure 内の filename と頻繁に混同されます。TLD signal を brand keyword および NRD age と組み合わせることで、より高い precision を得られます。

## References

- [1] [Remy Hax – Bitsquatting Windows.com](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [bitflipping による Microsoft の windows.com への traffic hijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol の JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics：cloud token theft を防止、検知、対応する方法](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Finding Phishing：Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream の紹介](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
