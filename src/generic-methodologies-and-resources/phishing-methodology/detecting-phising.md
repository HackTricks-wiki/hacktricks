# フィッシングの検出

{{#include ../../banners/hacktricks-training.md}}

## はじめに

フィッシングの試みを検出するには、**現在使われているフィッシング手法を理解することが重要です**。この投稿の親ページにその情報があります。現在どのような手法が使われているか把握していない場合は、親ページに移動して、少なくともそのセクションを読むことをおすすめします。

この投稿は、**攻撃者が何らかの方法で被害者のドメイン名をまねたり、利用したりする**ことを前提としています。ドメインが `example.com` で、何らかの理由で `youwonthelottery.com` のようなまったく異なるドメイン名を使ったフィッシングの標的になった場合、ここで紹介する手法では検出できません。

## ドメイン名のバリエーション

メール内で**類似したドメイン**名を使う**フィッシング**の試みは、比較的**簡単に**見つけることができます。\
攻撃者が使う可能性の高いフィッシング用の名前をリストとして**生成**し、それらが**登録済み**かどうか、または使用している**IP**があるかどうかを確認するだけで十分です。

### 疑わしいドメインを見つける

この目的には、以下のツールを使用できます。どちらも候補ドメインを名前解決し、使用されているかどうかを確認します。<sup>[[3]](#references)[[4]](#references)</sup>

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

ヒント: 候補リストを生成した場合は、DNS resolver のログにも照合してください。**組織内からの NXDOMAIN クエリ**（攻撃者が登録する前に、ユーザーが入力ミスしたドメインにアクセスしようとしているケース）を検出できます。ポリシーで許可されている場合は、これらのドメインを Sinkhole するか、事前にブロックしてください。

### Bitflipping

**簡単な説明については親ページを参照してください。Windows.com の bitsquatting に関する一次調査については、[Remy Hax の記事](https://remyhax.xyz/posts/bitsquatting-windows/)と [BleepingComputer のレポート](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)を参照してください**。<sup>[[1]](#references)[[2]](#references)</sup>

たとえば、ドメイン microsoft.com の1ビットを変更すると、_windnws.com_ に変わることがあります。\
**攻撃者は、正規のユーザーを自分たちのインフラへリダイレクトするため、被害者に関連するビット反転ドメインをできるだけ多く登録する可能性があります**。<sup>[[1]](#references)[[2]](#references)</sup>

**考えられるすべてのビット反転ドメイン名も監視する必要があります。**

Homoglyph/IDN の類似ドメイン（例: ラテン文字とキリル文字の混在）も考慮する必要がある場合は、こちらを参照してください。

{{#ref}}
homograph-attacks.md
{{#endref}}

### 基本的なチェック

疑わしいドメイン名の候補リストを作成したら、それらを**確認**します（主に HTTP と HTTPS のポート）。被害者のドメインにあるものと似たログインフォームを使っているかどうかを**調べます**。\
ポート3333が開いていて、`gophish` のインスタンスが実行されているか確認することもできます。\
見つかった疑わしいドメインがそれぞれ**どれくらい前に作成されたか**を把握することも重要です。新しいドメインほどリスクが高くなります。\
疑わしい HTTP および/または HTTPS の Web ページの**スクリーンショット**を取得し、疑わしいかどうか確認したうえで、該当する場合は**アクセスして詳しく調べる**こともできます。

### 高度なチェック

さらに一歩進めるなら、疑わしいドメインを**監視し、定期的に（毎日など）新たなドメインがないか検索する**ことをおすすめします。数秒から数分で済みます。また、関連する IP の開いている**ポート**を**確認**し、`gophish` や類似ツールのインスタンスがないか**検索**してください（攻撃者もミスをします）。さらに、疑わしいドメインやサブドメインの HTTP および HTTPS の Web ページを**監視**して、被害者の Web ページからログインフォームをコピーしていないか確認してください。\
これを**自動化**するには、被害者のドメインにあるログインフォームのリストを用意し、疑わしい Web ページを spider で巡回して、疑わしいドメイン内で見つかった各ログインフォームを、`ssdeep` のようなツールを使って被害者のドメインにある各ログインフォームと比較することをおすすめします。\
疑わしいドメインのログインフォームを特定できたら、**ダミーの認証情報を送信**し、**被害者のドメインにリダイレクトされるか確認**できます。

---

### favicon と Web フィンガープリントによる探索（Shodan/Censys）

多くのフィッシングキットは、なりすますブランドの favicon を再利用します。Shodan は base64 エンコードされた favicon データのハッシュに MurmurHash3 を使用し、Censys は独自の favicon ハッシュフィールドを公開しています。<sup>[[5]](#references)[[6]](#references)[[7]](#references)</sup> Shodan 互換のハッシュを生成して、それを使って検索範囲を広げることができます。

Python の例（mmh3）:

```python
import base64, requests, mmh3
url = "https://www.paypal.com/favicon.ico"  # change to your brand icon
b64 = base64.encodebytes(requests.get(url, timeout=10).content)
print(mmh3.hash(b64))  # e.g., 309020573
```

- Shodanで検索: `http.favicon.hash:309020573`
- ツールを使う場合: favfreakなどのコミュニティツールを使って、ハッシュを計算し、Shodan dorkを生成します。<sup>[[16]](#references)</sup>

注意事項
- ファビコンは再利用されます。一致した結果は手がかりとして扱い、行動に移す前にコンテンツと証明書を検証してください。
- 精度を高めるには、ドメインの登録時期やキーワードのヒューリスティックと組み合わせてください。

### URLテレメトリのハンティング（urlscan.io）

`urlscan.io`には、送信されたURLの過去のスクリーンショット、DOM、リクエスト、TLSメタデータが保存されています。ブランドの不正使用やクローンサイトをハンティングできます。<sup>[[8]](#references)</sup>

クエリの例（UIまたはAPI）:
- 正規ドメインを除外して類似サイトを検索: `page.domain:(/.*yourbrand.*/ AND NOT yourbrand.com AND NOT www.yourbrand.com)`
- 自社のアセットをホットリンクしているサイトを検索: `domain:yourbrand.com AND NOT page.domain:yourbrand.com`
- 最近の結果に絞り込む: `AND date:>now-7d`を追加

APIの例:

```bash
# Search recent scans mentioning your brand
curl -s 'https://urlscan.io/api/v1/search/?q=page.domain:(/.*yourbrand.*/%20AND%20NOT%20yourbrand.com)%20AND%20date:>now-7d' \
  -H 'API-Key: <YOUR_URLSCAN_KEY>' | jq '.results[].page.url'
```

JSON から、以下の値を手がかりに調査します。
- `page.tlsIssuer`、`page.tlsValidFrom`、`page.tlsAgeDays` から、類似ドメインに使われている発行間もない証明書を特定する
- `task.source` の `certstream-suspicious` などの値から、検出結果を CT monitoring に関連付ける

### RDAP によるドメインの登録期間（スクリプトで取得可能）

RDAP は機械可読な登録イベントを返します。**新規登録ドメイン（NRD）**の検出に役立ちます。<sup>[[9]](#references)[[10]](#references)</sup>

```bash
# .com/.net RDAP (Verisign)
curl -s https://rdap.verisign.com/com/v1/domain/suspicious-example.com | \
  jq -r '.events[] | select(.eventAction=="registration") | .eventDate'

# Generic helper using rdap.net redirector
curl -s https://www.rdap.net/domain/suspicious-example.com | jq
```

パイプラインを拡充し、ドメインに登録経過期間の区分（例：<7日、<30日）のタグを付け、優先度に応じてトリアージしましょう。

### AiTMインフラを検出するTLS/JAxフィンガープリント

認証情報を狙うフィッシングでは、セッショントークンを盗むために**Adversary-in-the-Middle（AiTM）**のリバースプロキシ（例：Evilginx）が使われることがあります。<sup>[[11]](#references)</sup> ネットワーク側で次の検出を追加できます。

- 出口でTLS/HTTPフィンガープリント（JA3/JA4/JA4S/JA4H）を記録します。一部のEvilginxビルドでは、安定したJA4クライアント／サーバー値が観測されています。既知の悪意あるフィンガープリントは弱いシグナルとしてのみアラートし、必ずコンテンツやドメインの情報と照合してください。<sup>[[12]](#references)</sup>
- CTやurlscanで見つかった類似ホストについて、TLS証明書のメタデータ（発行者、SAN数、ワイルドカードの使用、有効期間）をあらかじめ記録し、DNSの経過期間や位置情報と相関させます。

> 注：フィンガープリントはブロックの唯一の根拠ではなく、情報の補強として扱ってください。フレームワークは進化し、フィンガープリントをランダム化または難読化する可能性があります。

### キーワードを含むドメイン名

親ページでは、**被害者のドメイン名をより大きなドメイン名の中に含める**ドメイン名の変化手法（例：paypal.comに対するpaypal-financial.com）についても説明しています。

#### Certificate Transparency

Certificate Transparency（CT）ログには証明書の識別情報が公開されるため、Subject名やSAN名からブランドキーワードを検索すると、類似ドメインを発見できます（たとえば、`paypal-financial.com`の証明書には`paypal`というキーワードが含まれます）。必要に応じて発行日やCAで結果を絞り込み、キーワードの一致は誤検知の可能性があるため、候補を検証してください。<sup>[[13]](#references)</sup>

Patrik Hudakによる元の[フィッシングドメイン探索に関する記事](https://0xpatrik.com/phishing-domains/)では、Let's Encryptなどの証明書の日付や発行者で絞り込む方法も含め、Censysを使ったこのワークフローを紹介しています。<sup>[[13]](#references)</sup>

![類似ドメインの特定に使用するCensysの証明書検索結果](<../../images/image (1115).png>)

無料サービスの[**crt.sh**](https://crt.sh)でも、キーワードを検索し、日付やCAで結果を絞り込めます。<sup>[[13]](#references)</sup>

![不審な証明書の識別情報をキーワード検索するcrt.sh](<../../images/image (519).png>)

Matching Identitiesフィールドを使うと、実際のドメインと不審なドメインの識別情報を比較できますが、一致は証拠ではなく調査の手掛かりとして扱ってください。<sup>[[13]](#references)</sup>

[*CertStream*](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)はCTの更新をほぼリアルタイムで配信し、[*phishing_catcher*](https://github.com/x0rz/phishing_catcher)はそのストリームを利用して、不審な証明書名をスコアリングします。<sup>[[14]](#references)[[15]](#references)</sup>

実践的なヒント：CTの検出結果をトリアージする際は、NRD、信頼できない／不明なレジストラ、プライバシープロキシWHOIS、`NotBefore`の時刻がごく最近の証明書を優先してください。ノイズを減らすため、自社が保有するドメインやブランドの許可リストを維持しましょう。

#### **新規ドメイン**

2つ目の方法として、TLDごとに新規登録ドメインを収集し（例：[Whoxy](https://www.whoxy.com/newly-registered-domains/)を利用）、ブランドキーワードで絞り込む方法があります。この方法では、登録ドメインにキーワードが含まれない場合、サブドメイン上でホストされているフィッシングを見逃します。<sup>[[13]](#references)</sup>

追加のヒューリスティック：特定の**ファイル拡張子のように見えるTLD**（例：`.zip`、`.mov`）は、アラート時に特に疑わしいものとして扱います。これらは誘導メッセージ内のファイル名と誤認されやすいため、精度を高めるにはTLDのシグナルをブランドキーワードやNRDの経過期間と組み合わせてください。

## References

- [1] [Remy Hax – Windows.comのBitsquatting](https://remyhax.xyz/posts/bitsquatting-windows/)
- [2] [ビット反転によるMicrosoftのwindows.comへのトラフィックの乗っ取り](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)
- [3] [dnstwist](https://github.com/elceef/dnstwist)
- [4] [urlcrazy](https://github.com/urbanadventurer/urlcrazy)
- [5] [詳細解説：http.favicon](https://blog.shodan.io/deep-dive-http-favicon/)
- [6] [mmh3のドキュメント](https://mmh3.readthedocs.io/en/stable/quickstart.html)
- [7] [Platform Web Property Dataset](https://docs.censys.com/docs/platform-web-property-dataset)
- [8] [urlscan.io – Search APIリファレンス](https://urlscan.io/docs/search/)
- [9] [Registration Data Access Protocolヘルプ](https://www.verisign.com/news-insights/registration-data-access-protocol/help/)
- [10] [RFC 9083：Registration Data Access ProtocolのJSONレスポンス](https://www.rfc-editor.org/rfc/rfc9083.html)
- [11] [トークン戦術：クラウドトークンの窃取を防止、検出し、対応する方法](https://www.microsoft.com/en-us/security/blog/2022/11/16/token-tactics-how-to-prevent-detect-and-respond-to-cloud-token-theft/)
- [12] [APNIC Blog – JA4+ネットワークフィンガープリンティング](https://blog.apnic.net/2023/11/22/ja4-network-fingerprinting/)
- [13] [Patrik Hudak – フィッシングの発見：ツールと手法](https://0xpatrik.com/phishing-domains/)
- [14] [Ryan Sears – CertStreamの紹介](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067)
- [15] [x0rz – Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [16] [Devansh Batham – FavFreak](https://github.com/devanshbatham/FavFreak)
{{#include ../../banners/hacktricks-training.md}}
