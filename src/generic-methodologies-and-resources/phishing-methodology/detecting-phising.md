# Detecting Phishing

{{#include ../../banners/hacktricks-training.md}}

## Introduction

phishingの試行を検出するには、**現在使われているphishing techniquesを理解することが重要です**。この投稿の親ページにその情報があるので、もしどのtechniquesが使われているか分からない場合は親ページの少なくとも該当セクションを読むことをおすすめします。

この投稿は**攻撃者が被害者のドメイン名を何らかの方法で模倣するか利用しようとする**という考えに基づいています。もしあなたのドメインが`example.com`で、`youwonthelottery.com`のような全く別のドメインでphishingされた場合、これらの手法は検出できません。

## ドメイン名のバリエーション

メール内で類似したドメイン名を使う**phishing**の試みは、比較的**簡単**に**発見**できます。\
攻撃者が使用する可能性が高いドメイン名のリストを**生成**し、それが**登録されているか**、またはそのドメインに割り当てられた**IP**が存在するかどうかを**確認**するだけで十分です。

### 疑わしいドメインの見つけ方

この目的には、以下のツールのいずれかを使用できます。これらのツールはドメインに割り当てられたIPがあるかどうかを確認するために、DNSクエリを自動的に実行する点に注意してください：

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

ヒント: 候補リストを生成した場合は、それをDNSリゾルバログに入れて**NXDOMAIN lookups from inside your org**（攻撃者が実際に登録する前にユーザがタイプミスで到達しようとしたもの）を検出してください。ポリシーが許すなら、これらのドメインをシンクホール化するか事前にブロックしてください。

### Bitflipping

**You can find a short the explanation of this technique in the parent page. Or read the original research in** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

例えば、ドメインmicrosoft.comの1ビット変更で_windnws.com_のようになることがあります。\
**攻撃者は被害者に関連する可能な限り多くのbit-flippingドメインを登録して、正当なユーザを自分たちのインフラにリダイレクトする可能性があります。**

**すべての可能なbit-flippingドメイン名も監視するべきです。**

もしhomoglyph/IDNの類似（例：Latin/Cyrillic文字の混合）も考慮する必要があるなら、次を確認してください：

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本的なチェック

潜在的に疑わしいドメイン名のリストを入手したら、まずそれらを**チェック**してください（主にHTTPおよびHTTPSのポート）そしてそれらが被害者のドメインのものと**類似したログインフォームを使用しているかどうかを確認**します。\
また、ポート3333が開いていて`gophish`のインスタンスが動作しているかを確認することもできます。\
発見した各疑わしいドメインが**どれくらい古いか（登録日）**を知ることは興味深いです。若いほどリスクが高いです。\
HTTPおよび/またはHTTPSの疑わしいウェブページの**スクリーンショット**を取得して、疑わしいかどうか確認し、その場合はさらに詳しく**アクセスして調査**してください。

### 高度なチェック

さらに踏み込むなら、これらの疑わしいドメインを**監視し、時々（毎日？数秒/分しかかかりません）追加のドメインを検索する**ことをお勧めします。関連IPの開いている**ポート**を**チェック**し、`gophish`や類似ツールのインスタンスを**検索**するべきです（はい、攻撃者もミスをします）。疑わしいドメインやサブドメインのHTTPおよびHTTPSのウェブページを**監視**して、被害者のウェブページからログインフォームをコピーしていないか確認してください。\
この作業を**自動化する**ために、被害者ドメインのログインフォーム一覧を用意し、疑わしいウェブページをスパイダーで巡回して、疑わしいドメイン内で見つかった各ログインフォームを`ssdeep`のようなものを使って被害者ドメインの各ログインフォームと比較することを推奨します。\
もし疑わしいドメインのログインフォームを見つけたら、ダミーの資格情報を**送信**して、それが被害者のドメインへ**リダイレクトするかどうか**を**確認**できます。

---

### Hunting by favicon and web fingerprints (Shodan/ZoomEye/Censys)

多くのphishingキットは、なりすますブランドのfaviconを再利用します。ネットワーク全体のスキャナはbase64エンコードされたfaviconのMurmurHash3を計算します。ハッシュを生成してそれを起点に調査できます：

Pythonの例 (mmh3):
```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```
- Shodanで検索: `http.favicon.hash:309020573`
- ツールを使う場合: favfreakのようなコミュニティツールを参照して、Shodan/ZoomEye/Censys向けのハッシュやdorksを生成する。

注意
- Faviconsは再利用されることが多いので、一致は手がかりとして扱い、行動する前にコンテンツとcertsを検証する。
- 精度を上げるために、domain-ageやkeyword heuristicsと組み合わせる。

### URLテレメトリのハンティング (urlscan.io)

`urlscan.io`は、提出されたURLの過去のスクリーンショット、DOM、リクエスト、TLSメタデータを保存します。ブランドの悪用やクローンを探索できます：

Example queries (UI or API):
- Find lookalikes excluding your legit domains: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- Find sites hotlinking your assets: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- Restrict to recent results: append `AND date:>now-7d`

API example:
```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
-H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```
From the JSON, pivot on:
- `page.tlsIssuer`, `page.tlsValidFrom`, `page.tlsAgeDays` — lookalikesの判別のため、非常に新しいcertsを検出する
- `task.source` の値（例: `certstream-suspicious`） — 所見をCT監視に紐づけるため

### RDAPによるドメイン年齢（スクリプト可能）

RDAPは機械可読な作成イベントを返す。**新規登録ドメイン (NRDs)** のフラグ付けに有用。
```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```
Enrich your pipeline by tagging domains with registration age buckets (e.g., <7 days, <30 days) and prioritise triage accordingly.

### TLS/JAx fingerprints to spot AiTM infrastructure

近年の credential-phishing では、セッション・トークンを盗むために **Adversary-in-the-Middle (AiTM)** 型の reverse proxies（例: Evilginx）が増えています。ネットワーク側での検出を追加できます:

- Log TLS/HTTP fingerprints (JA3/JA4/JA4S/JA4H) at egress. 一部の Evilginx ビルドでは安定した JA4 クライアント/サーバー値が観測されています。known-bad なフィンガープリントに対しては弱いシグナルとしてアラートを出し、必ずコンテンツと domain intel で確認してください。
- Proactively record TLS certificate metadata (issuer, SAN count, wildcard use, validity) for lookalike hosts discovered via CT or urlscan and correlate with DNS age and geolocation.

> Note: Treat fingerprints as enrichment, not as sole blockers; frameworks evolve and may randomise or obfuscate.

### Domain names using keywords

親ページでは、ドメイン名バリエーションの手法として、**victim's domain name inside a bigger domain**（例: paypal-financial.com が paypal.com の場合）のように被害者ドメインをより大きなドメイン名の中に含める手法も紹介されています。

#### Certificate Transparency

前述の "Brute-Force" アプローチは実行困難な場合がありますが、証明書透明性のおかげでこのようなフィッシング試行を発見することは実際に可能です。CA が証明書を発行するたびにその詳細は公開されます。つまり、証明書透明性を読む、あるいは監視することで、名前の中にキーワードを含むドメインを見つけることができます。たとえば攻撃者が [https://paypal-financial.com](https://paypal-financial.com) の証明書を作成すると、その証明書から "paypal" というキーワードを見つけ、不審なメールに使われていると判断できます。

投稿 [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) では、Censys を使って特定のキーワードに該当する証明書を検索し、日付（新しい証明書のみ）や CA 発行者 "Let's Encrypt" でフィルタする方法が提案されています:

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

しかし、無料のウェブサービス [**crt.sh**](https://crt.sh) を使って同様のことができます。キーワードで検索し、必要に応じて日付や CA で結果をフィルタできます。

![](<../../images/image (519).png>)

この方法では、Matching Identities フィールドを使って実際のドメインのいずれかの identity が不審なドメインと一致するかを確認できます（不審なドメインは誤検知である場合もあります）。

**Another alternative** は [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067) という素晴らしいプロジェクトです。CertStream は新しく生成された証明書のリアルタイムストリームを提供し、指定したキーワードを（ほぼ）リアルタイムで検出するのに使えます。実際に [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) というプロジェクトがこれを実装しています。

実践的なヒント: CT ヒットをトリアージする際は、NRDs、untrusted/unknown registrars、privacy-proxy WHOIS、および非常に最近の `NotBefore` 時刻を持つ cert を優先してください。所有しているドメイン/ブランドの allowlist を維持してノイズを減らしましょう。

#### **New domains**

**One last alternative** は、いくつかの TLD について newly registered domains のリストを集め（[Whoxy](https://www.whoxy.com/newly-registered-domains/) などが提供）、それらのドメインに含まれるキーワードをチェックすることです。ただし、長いドメインは通常 1 つ以上のサブドメインを使うため、キーワードが FLD の中に現れず、フィッシング用サブドメインを見つけられないことがあります。

追加のヒューリスティック: 特定の file-extension TLD（例: `.zip`, `.mov`）は、誘い文句でファイル名と誤認されやすいため、アラートで追加の疑いを持って扱ってください。TLD シグナルをブランドキーワードや NRD 年齢と組み合わせると精度が上がります。

## References

- urlscan.io – Search API reference: https://urlscan.io/docs/search/
- APNIC Blog – JA4+ network fingerprinting (includes Evilginx example): https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/

{{#include ../../banners/hacktricks-training.md}}
