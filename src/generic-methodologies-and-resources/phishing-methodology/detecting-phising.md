# フィッシングの検出

{{#include ../../banners/hacktricks-training.md}}

## Introduction

フィッシング攻撃を検出するには、**現在使用されているフィッシングの手法を理解すること**が重要です。この投稿の親ページにはこの情報が記載されているため、現在使用されている手法を把握していない場合は、親ページに移動して少なくともそのセクションを読むことをおすすめします。

この投稿は、**攻撃者が何らかの方法で被害者のドメイン名を模倣または使用しようとする**という考えに基づいています。あなたのドメインが `example.com` で、何らかの理由により `youwonthelottery.com` のようなまったく異なるドメイン名を使ったフィッシングの被害に遭った場合、これらの手法では検出できません。

## Domain name variations

メール内で**類似したドメイン**名を使用する**フィッシング**攻撃を**見つける**のは、比較的**簡単**です。\
攻撃者が使用する可能性が最も高い**フィッシング用の名前のリストを生成**し、それが**登録済み**かどうかを**確認**するか、その名前を使用している**IP**が存在するかを確認するだけで十分です。

### Finding suspicious domains

この目的には、以下のツールのいずれかを使用できます。どちらも候補ドメインを解決し、使用中かどうかを確認します。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

ヒント: 候補リストを生成した場合は、それを DNS resolver のログにも入力して、**組織内部からの NXDOMAIN lookup**（攻撃者が実際に登録する前に、ユーザーが typo を入力してアクセスしようとした記録）を検出してください。ポリシーで許可されている場合は、これらのドメインを Sinkhole するか、事前にブロックしてください。

### Bitflipping

**簡単な説明については親ページを参照してください。Windows.com に関する主要な bitsquatting の調査については、[Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) と [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照してください**。<sup>[[1]](#references)[[2]](#references)</sup>

たとえば、ドメイン microsoft.com の 1 ビットを変更すると、_windnws.com_ に変化する可能性があります。\
**攻撃者は、正規ユーザーを自身のインフラへリダイレクトするため、被害者に関連する bit-flipping ドメインを可能な限り多く登録することがあります**。<sup>[[1]](#references)[[2]](#references)</sup>

**考えられるすべての bit-flipping ドメイン名も監視する必要があります。**

homoglyph/IDN の lookalike（Latin/Cyrillic 文字の混在など）も考慮する必要がある場合は、以下を確認してください。

{{#ref}}
homograph-attacks.md
{{#endref}}

### Basic checks

疑わしい可能性のあるドメイン名のリストを作成したら、それらを**確認**し（主に HTTP と HTTPS のポート）、被害者のドメインに似た login form を使用しているかどうかを**確認**してください。\
ポート 3333 が open で、`gophish` の instance が実行されているかどうかを確認することもできます。\
発見した疑わしいドメインが**どの程度古いものか**を把握することも重要です。新しいドメインほどリスクが高くなります。\
疑わしい HTTP and/or HTTPS web page の**screenshots**を取得して、疑わしいかどうかを確認し、その場合は**アクセスして詳しく調査**することもできます。

### Advanced checks

さらに一歩進めたい場合は、**疑わしいドメインを監視し、時々（毎日でしょうか？数秒から数分しかかかりません）追加のドメインを検索する**ことをおすすめします。また、関連する IP の open **ports**を**確認**し、**`gophish` または類似ツールの instance を検索**してください（攻撃者もミスをすることがあります）。さらに、疑わしいドメインと subdomain の HTTP and HTTPS web page を**監視**し、被害者の web page から login form をコピーしていないか確認してください。\
これを**自動化する**には、被害者のドメインにある login form のリストを用意し、疑わしい web page を spider で巡回して、疑わしいドメイン内で見つかった各 login form と被害者のドメインの各 login form を `ssdeep` などを使って比較することをおすすめします。\
疑わしいドメインの login form の場所を特定できた場合は、**junk credentials を送信**し、**被害者のドメインへリダイレクトされるかどうかを確認**してみてください。

---

### favicon and web fingerprints による Hunting (Shodan/Censys)

多くの phishing kit は、偽装対象のブランドの favicon を再利用します。Shodan は base64-encoded favicon data を MurmurHash3 で hash 化し、Censys は独自の favicon hash fields を公開しています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan-compatible hash を生成し、それを使って pivot できます。

Python example (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodanをクエリする: `http.favicon.hash:309020573`
- Toolingを使用する: favfreakなどのcommunity toolsでハッシュを計算し、Shodan dorksを生成する。<sup>[[16]](#references)</sup>

メモ
- ファビコンは再利用されるため、一致結果は手がかりとして扱い、行動する前にコンテンツと証明書を検証する。
- より高い精度を得るには、ドメインの登録年数とキーワードのヒューリスティクスを組み合わせる。

### URL telemetry hunting (urlscan.io)

`urlscan.io`は、送信されたURLの過去のスクリーンショット、DOM、リクエスト、TLSメタデータを保存する。ブランドの悪用やクローンを探索できる:<sup>[[8]](#references)</sup>

Example queries (UI or API):
- 正規ドメインを除外して類似サイトを検索する: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 自社アセットをhotlinkしているサイトを検索する: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 最近の結果に限定する: `AND date:>now-7d`を追加する

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON から以下の項目を軸に調査します:
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays` を使用して、lookalike 用の非常に新しい証明書を特定する
- `certstream-suspicious` のような `task.source` の値を使用して、調査結果を CT monitoring と関連付ける

### RDAP によるドメインの登録期間（scriptable）

RDAP は機械で読み取り可能な登録イベントを返します。**新しく登録されたドメイン（NRDs）** の検出に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
ドメインに登録期間のバケット（例：<7日、<30日）をタグ付けしてパイプラインを強化し、それに応じてトリアージの優先順位を付けます。

### AiTMインフラストラクチャを発見するためのTLS/JAxフィンガープリント

Credential-phishingでは、**Adversary-in-the-Middle (AiTM)** reverse proxy（例：Evilginx）を使用してセッションtokenを盗むことがあります。<sup>[[11]](#references)</sup> ネットワーク側に以下の検知を追加できます。

- egressでTLS/HTTPフィンガープリント（JA3/JA4/JA4S/JA4H）をログに記録します。一部のEvilginxビルドでは、安定したJA4 client/server値が確認されています。既知の悪性フィンガープリントは弱いシグナルとしてのみalertし、必ずcontentおよびdomain intelで確認してください。<sup>[[12]](#references)</sup>
- CTまたはurlscanで発見したlookalike hostについて、TLS certificate metadata（issuer、SAN count、wildcardの使用、validity）を事前に記録し、DNS ageおよびgeolocationと相関させます。

> 注：フィンガープリントは単独のblockerではなく、enrichmentとして扱ってください。frameworkは進化し、randomiseまたはobfuscateされる可能性があります。

### キーワードを使用するドメイン名

親ページでは、**victimのdomain nameをより大きなdomain内に含める**domain name variation technique（例：paypal.comに対するpaypal-financial.com）についても説明しています。

#### Certificate Transparency

Certificate Transparency (CT) logsにはcertificate identityが公開されるため、SubjectまたはSAN nameでbrand keywordを検索すると、lookalike domainを発見できます（たとえば、`paypal-financial.com`のcertificateから`paypal` keywordが明らかになります）。必要に応じてissuance dateおよびCAで結果をfilterし、keyword matchはfalse positiveになる可能性があるため、候補をvalidateしてください。<sup>[[13]](#references)</sup>

Patrik Hudakによるオリジナルの[phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/)では、Let's Encryptなどのcertificate dateおよびissuerのfilterを含め、このworkflowをCensysで実行する方法を説明しています。<sup>[[13]](#references)</sup>

![lookalike domainの特定に使用したCensys certificate search results](<../../images/image (1115).png>)

無料の[**crt.sh**](https://crt.sh) serviceを使用してkeywordを検索し、dateおよびCAで結果をfilterすることもできます。<sup>[[13]](#references)</sup>

![疑わしいcertificate identityを検索するcrt.sh keyword search](<../../images/image (519).png>)

そのMatching Identities fieldは、real domainのidentityとsuspicious domainのidentityを比較するのに役立ちますが、matchは証拠ではなく手がかりとして扱ってください。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)はCT updateをほぼリアルタイムでstreamし、[*phishing_catcher*](https://github.com/x0rz/phishing_catcher)はそのstreamを消費して疑わしいcertificate nameをscoreします。<sup>[[14]](#references)[[15]](#references)</sup>

実践的なヒント：CT hitをtriageする際は、NRD、untrusted/unknown registrar、privacy-proxy WHOIS、および非常に新しい`NotBefore` timeを持つcertを優先してください。noiseを減らすため、所有するdomain/brandのallowlistを維持します。

#### **新しいドメイン**

2つ目の方法は、TLDごとに新たに登録されたdomainを収集し（たとえば[Whoxy](https://www.whoxy.com/newly-registered-domains/)経由）、brand keywordでfilterすることです。registered domainにkeywordがない場合、subdomain上でhostされているphishingを見逃します。<sup>[[13]](#references)</sup>

追加のheuristic：特定の**file-extension TLD**（例：`.zip`、`.mov`）は、alertingでより強く疑ってください。これらはlure内のfilenameと頻繁に混同されるため、精度を高めるにはTLD signalをbrand keywordおよびNRD ageと組み合わせます。

## References

- [1] [Remy Hax – Windows.comのBitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [bitflippingによるMicrosoftのwindows.comへのtraffic hijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [Deep Dive: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol向けJSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics：cloud token theftを防止、検知、対応する方法](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishingの発見：Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStreamの紹介](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
