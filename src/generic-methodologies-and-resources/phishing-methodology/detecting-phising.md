# フィッシングの検出

## はじめに

フィッシング攻撃を検出するには、**現在使われているフィッシング手法を理解すること**が重要です。この投稿の親ページにはこの情報が掲載されているため、現在どのような手法が使われているのか把握していない場合は、親ページに移動して少なくともそのセクションを読むことをお勧めします。

この投稿は、**攻撃者が何らかの方法で被害者のドメイン名を模倣または使用しようとする**という考えに基づいています。ドメインが `example.com` で、何らかの理由により `youwonthelottery.com` のようなまったく異なるドメイン名を使ってフィッシングされた場合、これらの手法では発見できません。

## ドメイン名のバリエーション

メール内で**類似したドメイン**名を使用する**フィッシング**攻撃を**発見**するのは、ある程度**簡単**です。\
攻撃者が使用する可能性が最も高い**フィッシング用の名前のリストを生成**し、それが**登録**されているか確認するか、その名前を使用している**IP**が存在するか確認するだけで十分です。

### 不審なドメインの発見

この目的には、以下のツールを使用できます。どちらも候補ドメインを解決し、使用中かどうかを確認します。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

ヒント: 候補リストを生成した場合は、それを DNS resolver のログにも入力し、**組織内部からの NXDOMAIN ルックアップ**（攻撃者が実際に登録する前に、ユーザーが typo を入力してアクセスしようとした記録）を検出してください。ポリシーで許可されている場合は、これらのドメインを Sinkhole に設定するか、事前にブロックしてください。

### Bitflipping

**簡単な説明については親ページを参照してください。Windows.com に関する主要な bitsquatting の調査については、[Remy Hax's write-up](https://remyhax.xyz/posts/bitsquatting-windows/) と [BleepingComputer's report](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/) を参照してください**。<sup>[[1]](#references)[[2]](#references)</sup>

たとえば、ドメイン microsoft.com の 1 ビットを変更すると、_windnws.com_ に変換できます。\
**攻撃者は、正規ユーザーを自身のインフラへリダイレクトするため、被害者に関連するビット反転ドメインを可能な限り多く登録する可能性があります**。<sup>[[1]](#references)[[2]](#references)</sup>

**考えられるすべてのビット反転ドメイン名も監視する必要があります。**

homoglyph/IDN の lookalike（例: Latin/Cyrillic 文字の混在）も考慮する必要がある場合は、以下を確認してください。

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本的なチェック

潜在的に不審なドメイン名のリストを作成したら、それらを**チェック**し（主に HTTP と HTTPS のポート）、被害者のドメインにあるものと**類似したログインフォームを使用しているか**を**確認**する必要があります。\
ポート 3333 を確認し、開いていて `gophish` のインスタンスが実行されていないか調べることもできます。\
また、**発見した不審なドメインがそれぞれどの程度古いか**を把握することも有用です。新しいドメインほどリスクが高くなります。\
HTTP および/または HTTPS の不審な Web ページの**スクリーンショット**を取得し、不審な点がないか確認し、その場合は**アクセスして詳しく調査**することもできます。

### 高度なチェック

さらに一歩進めたい場合は、**これらの不審なドメインを監視し、時々（毎日？数秒から数分しかかかりません）追加のドメインを検索する**ことをお勧めします。また、関連する IP の開いている**ポート**を**チェック**し、**`gophish` または類似ツールのインスタンスを検索**し（そうです、攻撃者もミスをします）、**不審なドメインとサブドメインの HTTP および HTTPS Web ページを監視**して、被害者の Web ページからログインフォームをコピーしていないか確認する必要があります。\
これを**自動化する**には、被害者のドメインにあるログインフォームのリストを用意し、不審な Web ページを spider で巡回し、不審なドメイン内で見つかった各ログインフォームと被害者のドメインにある各ログインフォームを、`ssdeep` のようなツールを使って比較することをお勧めします。\
不審なドメインのログインフォームを特定できた場合は、**ダミーの認証情報を送信**し、**被害者のドメインへリダイレクトされるか確認**できます。

---

### favicon と Web フィンガープリントによる探索（Shodan/Censys）

多くのフィッシングキットは、偽装対象のブランドの favicon を再利用します。Shodan は base64 でエンコードされた favicon データを MurmurHash3 でハッシュ化し、Censys は独自の favicon ハッシュフィールドを提供しています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan 互換のハッシュを生成し、それを基に pivot できます。

Python の例（mmh3）：
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodan をクエリする: `http.favicon.hash:309020573`
- ツールを使用する: favfreak などの community tools でハッシュを計算し、Shodan dorks を生成する。<sup>[[16]](#references)</sup>

注記
- Favicons は再利用されるため、一致結果は手がかりとして扱い、実際に行動する前にコンテンツと証明書を検証する。
- 精度を高めるには、ドメインの登録年数とキーワードのヒューリスティックを組み合わせる。

### URL telemetry hunting (urlscan.io)

`urlscan.io` は、送信された URL の過去のスクリーンショット、DOM、リクエスト、TLS メタデータを保存する。brand abuse やクローンをハンティングできる:<sup>[[8]](#references)</sup>

クエリの例（UI または API）:
- 正規ドメインを除外して lookalikes を検索する: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- アセットを hotlinking しているサイトを検索する: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 最近の結果に限定する: `AND date:>now-7d` を追加する

API の例:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
JSON から次の項目を基に pivot します:
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays` を使用して、lookalike 用の非常に新しい証明書を検出する
- `certstream-suspicious` のような `task.source` の値を使用して、検出結果を CT monitoring に関連付ける

### RDAP によるドメインの経過期間（scriptable）

RDAP は machine-readable な登録イベントを返します。**新規登録ドメイン（NRDs）**の検出に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
パイプラインを、ドメインを登録経過期間のバケット（例: 7日未満、30日未満）でタグ付けするよう拡張し、それに応じて triage の優先順位を設定します。

### AiTM インフラストラクチャを検出するための TLS/JAx fingerprints

Credential-phishing では、**Adversary-in-the-Middle (AiTM)** reverse proxies（例: Evilginx）を使用して session tokens を窃取することがあります。<sup>[[11]](#references)</sup> ネットワーク側で以下の detections を追加できます。

- egress で TLS/HTTP fingerprints（JA3/JA4/JA4S/JA4H）を記録します。一部の Evilginx builds では、安定した JA4 client/server values が観測されています。既知の悪性 fingerprints についてのみ、弱いシグナルとして alert を生成し、必ず content と domain intel で確認してください。<sup>[[12]](#references)</sup>
- CT または urlscan で発見した lookalike hosts について、TLS certificate metadata（issuer、SAN count、wildcard の使用、validity）を事前に記録し、DNS age および geolocation と相関付けます。

> 注: fingerprints は enrichment として扱い、単独の blocker として使用しないでください。frameworks は進化し、randomise または obfuscate される可能性があります。

### キーワードを使用するドメイン名

親ページでは、**victim の domain name をより大きな domain 内に含める** domain name variation technique（例: paypal.com に対する paypal-financial.com）についても説明しています。

#### Certificate Transparency

Certificate Transparency (CT) logs には certificate identities が公開されるため、Subject または SAN names で brand keywords を検索すると、lookalike domains を発見できます（たとえば、`paypal-financial.com` の certificate から `paypal` keyword が確認できます）。必要に応じて issuance date と CA で結果を絞り込み、keyword matches は false positives の可能性があるため、候補を検証してください。<sup>[[13]](#references)</sup>

Patrik Hudak の original [phishing-domain hunting write-up](https://0xpatrik.com/phishing-domains/) では、Let's Encrypt などの certificate date および issuer の filters を含め、この workflow を Censys で実行する方法を説明しています。<sup>[[13]](#references)</sup>

無料の [**crt.sh**](https://crt.sh) service を使用して keyword を検索し、date と CA で結果を絞り込むこともできます。<sup>[[13]](#references)</sup>

その Matching Identities field は、real domain と suspicious domains の identities を比較する際に役立ちますが、matches は proof ではなく leads として扱ってください。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) は CT updates をほぼ real time で stream し、[*phishing_catcher*](https://github.com/x0rz/phishing_catcher) はその stream を利用して suspicious certificate names を score します。<sup>[[14]](#references)[[15]](#references)</sup>

実用的なヒント: CT hits を triage する際は、NRDs、untrusted/unknown registrars、privacy-proxy WHOIS、および非常に最近の `NotBefore` times を持つ certs を優先してください。ノイズを減らすため、所有している domains/brands の allowlist を維持します。

#### **新規ドメイン**

2つ目の選択肢は、TLD ごとに newly registered domains を収集し（例: [Whoxy](https://www.whoxy.com/newly-registered-domains/) 経由）、brand keywords で filter する方法です。この方法では、registered domain に keyword が含まれない subdomains 上でホストされた phishing を見逃します。<sup>[[13]](#references)</sup>

追加の heuristic: 一部の **file-extension TLDs**（例: `.zip`、`.mov`）は、alerting で特に suspicious として扱います。これらは lures 内の filenames と間違われやすいため、精度を高めるには TLD signal を brand keywords および NRD age と組み合わせてください。

## References

- [1] [Remy Hax – Windows.com の Bitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [bitflipping による Microsoft の windows.com への traffic hijacking](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [詳細解説: http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3 documentation](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search API Reference](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocol Help](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083: Registration Data Access Protocol の JSON Responses](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [Token tactics: cloud token theft の prevent、detect、respond の方法](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ network fingerprinting](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – Phishing の発見: Tools and Techniques](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStream の紹介](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
