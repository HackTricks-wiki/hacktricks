# E2EEメッセンジャーにおける配信確認のサイドチャネル攻撃

{{#include ../banners/hacktricks-training.md}}

現代のエンドツーエンド暗号化（E2EE）メッセンジャーでは、クライアントが暗号文の復号時点を把握し、ラチェット状態やエフェメラルキーを破棄できるよう、配信確認が必須です。サーバーは内容を解読できないデータを転送するため、受信者が復号に成功するとデバイス確認応答（二重チェックマーク）が送信されます。攻撃者が起こしたアクションから対応する配信確認までのラウンドトリップ時間（RTT）を測定すると、高解像度のタイミングチャネルが得られ、デバイスの状態やオンライン状況が漏洩します。また、これを利用した covert DoS も可能です。複数デバイスの「client-fanout」構成では、登録済みのすべてのデバイスがプローブを復号して個別に確認応答を返すため、漏洩が増幅されます。<sup>[[1]](#references)</sup>

## 配信確認の発生源とユーザーに見えるシグナル

配信確認は常に発生する一方で、被害者の UI に痕跡を残さないメッセージタイプを選びます。以下の表は、実証的に確認された挙動をまとめたものです。<sup>[[1]](#references)</sup>

| メッセンジャー | アクション | 配信確認 | 被害者への通知 | 備考 |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | テキストメッセージ | ● | ● | 常に目立つ → 状態の初期確認にのみ有用。 |
| | リアクション | ● | ◐（被害者のメッセージへのリアクション時のみ） | 自分のメッセージへのリアクションと削除は通知されない。 |
| | 編集 | ● | プラットフォームによってはサイレントプッシュ | 編集可能時間は約20分。期限切れ後も確認応答は返る。 |
| | 全員から削除 | ● | ○ | UI では約60時間まで可能だが、それ以降に送信したパケットにも確認応答が返る。 |
| **Signal** | テキストメッセージ | ● | ● | WhatsApp と同じ制限。 |
| | リアクション | ● | ◐ | 自分のメッセージへのリアクションは被害者に表示されない。 |
| | 編集/削除 | ● | ○ | サーバーは約48時間の制限を適用し、編集は最大10回まで許可するが、期限後のパケットにも確認応答が返る。 |
| **Threema** | テキストメッセージ | ● | ● | マルチデバイスの確認応答は集約されるため、各プローブにつき1つのRTTしか観測できない。 |

凡例：● = 常に、◐ = 条件付き、○ = なし。プラットフォームによって UI の挙動が異なる場合は、表中に記載しています。必要に応じて既読通知を無効にできますが、WhatsApp や Signal では配信確認を無効にできません。<sup>[[1]](#references)</sup>

## 攻撃者の目的とモデル

* **G1 – デバイスフィンガープリンティング:** 各プローブに対して届く確認応答の数を数え、RTT をクラスタリングして OS/クライアント（Android、iOS、デスクトップなど）を推定し、オンライン/オフラインの切り替わりを監視する。
* **G2 – 行動の監視:** 高頻度のRTT系列（約1 Hzで安定）を時系列データとして扱い、画面のオン/オフ、アプリのフォアグラウンド/バックグラウンド、通勤時間と勤務時間などを推定する。
* **G3 – リソース枯渇:** 終わりのないサイレントプローブを送り、被害者のすべてのデバイスの無線機能や CPU を起動状態に保つことで、バッテリーやデータ通信量を消費させ、ビデオ通話の品質を低下させる。<sup>[[1]](#references)</sup>

この悪用の範囲を説明するには、次の2種類の脅威アクターで十分です。<sup>[[1]](#references)</sup>

1. **不気味な知人:** すでに被害者とチャットをしており、自分のメッセージへのリアクション、リアクションの削除、既存のメッセージ ID に紐づく編集/削除の繰り返しを悪用する。
2. **不気味な見知らぬ人:** 捨てアカウントを登録し、ローカルの会話には存在しないメッセージ ID を参照するリアクションを送る。WhatsApp と Signal は UI が状態変更を破棄する場合でも復号して確認応答を返すため、事前に会話をしておく必要はない。

## 生プロトコルにアクセスするためのツール

UI の制約を越えて、サポートされているパケットを作成し、正確なタイムスタンプを記録するには、E2EE プロトコルの内部に十分アクセスできるクライアントを使います。任意のメッセージ ID が使えるかどうかは、各実装で確認する必要があります。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go、WhatsApp Web のマルチデバイス API）は、配信確認の送受信について説明しています。[Cobalt](https://github.com/Auties00/Cobalt)（非公式の Java/Kotlin Web・モバイル API）は、リアクション、編集、削除などのメッセージ操作について説明しています。内部フレームがすべて公開されていると決めつけず、ドキュメントに記載された API を使用してください。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) は CLI、JSON-RPC、D-Bus インターフェースを提供します。[libsignal-service-java](https://github.com/signalapp/libsignal-service-java) は Signal と通信するための Java ライブラリです。<sup>[[5]](#references)[[7]](#references)</sup> 現在の `signal-cli` の構文では `sendReaction RECIPIENT --target-author --target-timestamp` を使います。プロトコルの更新が引き続き処理されるよう、`receive` または `daemon` を実行したままにしてください。<sup>[[6]](#references)</sup> 自分のメッセージへのリアクションを切り替える例:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Careless Whisper 論文での測定では、配信確認はデバイス間で同期されるため、マルチデバイス環境でもメッセージごとに公開される確認は1つだけであることが判明した。<sup>[[1]](#references)</sup>
* **すぐ使える PoC:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) には WhatsApp/Signal のバックエンドが含まれ、デフォルトではサイレントな削除プローブを使い、ローリング中央値のしきい値（`RTT < 0.9 * median`）で `active` と `standby` を判定する。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) は、WhatsApp を主な対象とする軽量な CLI で、`--delay`、`--concurrent`、CSV/Prometheus エクスポーター、Grafana と連携しやすい出力を備える。<sup>[[9]](#references)</sup> どちらもプロトコルの参考資料ではなく、偵察を支援するツールとして扱うこと。重要なのは、生のクライアントにアクセスできれば、必要なコードがいかに少ないかという点である。

専用ツールが使えない場合でも、公式クライアントやブラウザーの開発者ツールからサイレントな操作を実行し、暗号化されたトラフィックのタイミングを観測できる。生の API を使えば UI による遅延がなくなり、無効な操作も実行できる。<sup>[[1]](#references)</sup>

## 不気味な応用例: サイレントなサンプリングループ

1. チャット内で自分が送信した過去のメッセージを選ぶ。そうすれば、被害者には「リアクション」の吹き出しの変化が見えない。
2. 表示される絵文字と空のリアクションペイロード（WhatsApp の protobuf では `""`、signal-cli では `--remove` としてエンコード）を交互に送信する。送信のたびに、被害者側の UI に変化がなくてもデバイス ACK が返る。
3. 送信時刻と各配信確認の到着時刻を記録する。次のような 1 Hz のループを実行すれば、デバイスごとの RTT トレースを無期限に取得できる。
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. WhatsApp/Signal は reaction updates を無制限に受け入れるため、攻撃者は新しいチャット内容を投稿する必要も、編集可能な時間枠を気にする必要もありません。<sup>[[1]](#references)</sup>

## 不気味な見知らぬ相手: 任意の電話番号をプロービングする

1. 新しい WhatsApp/Signal アカウントを登録し、標的の電話番号に対応する公開 identity keys を取得します（セッション設定時に自動で行われます）。
2. どちらの当事者も見たことのないランダムな `message_id` を参照する reaction packet を作成します。論文によると、WhatsApp と Signal はこのような reactions を受け入れ、delivery receipts も生成します。<sup>[[1]](#references)</sup>
3. スレッドが存在しなくても packet を送信します。被害者のデバイスはこれを復号し、元のメッセージと一致しないため状態変更を破棄しますが、受信した ciphertext には応答し、デバイスの receipts を攻撃者に返します。
4. 事前の会話や目に見える通知なしに RTT の時系列を作成するため、これを継続的に繰り返します。<sup>[[1]](#references)</sup>

登録済みの番号を先に特定したい場合や、大規模にデバイスの一覧を事前に取得したい場合は、ランダムな E.164 範囲を手作業で推測するのではなく、[contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) と組み合わせてください。

公開された contact-discovery の研究は、これが実際の運用で重要となる理由を示しています。正確な電話番号プレフィックス表と比較的少ないリソースを使い、研究者は標的型プロービングに移る前に、WhatsApp では米国の携帯番号の約 `10%`、Signal では `100%` を照会できました。<sup>[[11]](#references)</sup> 実際には、先に有効なアカウントを絞り込むことで、パケットを実際に復号する番号にサイレントプローブの予算を集中できます。

最近の WhatsApp ビルドには、`Settings -> Privacy -> Advanced -> Block unknown account messages` もあります。<sup>[[10]](#references)</sup> これはスループット制限として扱ってください。tracker のドキュメントによると、WhatsApp は不明なアカウントからの大量のメッセージをブロックしますが、しきい値は公開していないため、プローブ用の reactions を完全に防止するものではありません。<sup>[[8]](#references)</sup>

## 編集と削除を covert trigger として再利用する

* **削除の繰り返し:** メッセージが一度「全員に対して削除」された後は、同じ `message_id` を参照する追加の削除 packet は UI 上の影響を与えませんが、すべてのデバイスが引き続き復号して応答します。
* **時間枠外の操作:** WhatsApp は UI 上で削除を約60時間、編集を約20分に制限し、Signal は約48時間に制限しています。これらの時間枠を過ぎてから作成した protocol messages は、被害者のデバイスで黙って無視されますが receipts は送信されるため、会話が終わった後も攻撃者は無期限にプローブできます。
* **無効な payloads:** 論文によると、無効なメッセージでも応答される場合があります。不正な本文や削除済み ID に対する正確な挙動は実装によって異なるため、これを当てにする前にテストしてください。<sup>[[1]](#references)</sup>

## マルチデバイスでの増幅とフィンガープリンティング

* WhatsApp と Signal では、関連付けられた各デバイス（電話、デスクトップアプリ、ブラウザーの companion）がプローブを個別に復号し、それぞれ独自の ack を返します。プローブごとの receipts を数えると、正確なデバイス数が分かります。<sup>[[1]](#references)</sup>
* デバイスがオフラインの場合、その receipt はキューに入り、再接続時に送信されます。したがって、間隔からオンライン／オフラインの周期や通勤スケジュールまで漏れることがあります（例: 移動中はデスクトップの receipts が止まる）。
* OS、モデル、クライアント、ネットワークの条件によってタイミングが変わるため、RTT の分布はプラットフォームや環境ごとに異なります。RTT をクラスタリングし（例: 中央値／分散の特徴量に k-means を適用）、“Android handset”、“iOS handset”、“Electron desktop” などに分類します。
* 送信者は暗号化の前に受信者の key inventory を取得する必要があるため、攻撃者は新しいデバイスがペアリングされたタイミングも監視できます。デバイス数の急増や新たな RTT クラスタは、その強い兆候です。<sup>[[1]](#references)</sup>

**キューに入った receipts からフィンガープリントする:** 標的のデバイスがオフラインの間に、異なる message IDs を使った複数のプローブを送信します。再接続したら、返された delivery receipts 内の ID を照合し、それぞれ別々の receipt になっているか、1つの receipt にまとめられているか、またまとめられた ID の順序が送信順を維持するか逆転するかを確認します。テストしたクライアントでは、WhatsApp Android/iOS は別々の delivery receipts を返した一方、Web、Windows、macOS はまとめて返し、macOS ではまとめられた順序が逆転しました。Signal Desktop は receipts をまとめましたが、モバイルクライアントはそうしませんでした。この方法なら、RTT の分布が重なる場合でも、再接続したクライアントを分類できます。delivery receipts と read receipts を混同しないでください。まとめ方のルールは異なります。<sup>[[1]](#references)</sup>

メッセージを配信せずに **server-side prekey refills** を読み取る、別の WhatsApp プローブについては、[Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md) を参照してください。

## サンプリング間隔、キューイング、まとめられた receipts

* **WhatsApp のバースト耐性:** 公開測定によると、WhatsApp はサーバー側で明らかなキューイングを起こさず、`50 ms` に1回という速さのサイレント reaction のバーストを受け入れました。短時間のキャリブレーションバースト、迅速なデバイス数の確認、drain attack の素早い立ち上げに役立ちます。
* **Signal の長時間にわたるキューイング:** Signal は短いバーストには耐えましたが、1秒あたり複数回のプローブを継続するとキューイングが始まりました。長時間監視する場合は、間隔をおよそ `1 Hz`（またはそれ以下）に保ち、各 receipt が滞留分の処理ではなく、現在のデバイス状態を反映するようにしてください。
* **再接続時のアーティファクト:** デバイスがオンラインに戻ると、一部のクライアントは遅延した複数の receipts をまとめるか、短時間に一気に送信します。これらの receipt のバーストは独立した RTT サンプルではなく状態遷移のマーカーとして扱ってください。そうしないと、クラスタリングや `active`／`idle` の分類器が再接続時のノイズに過剰適合します。<sup>[[1]](#references)</sup>

## RTT のトレースから行動を推定する

1. OS のスケジューリングの影響を捉えるため、1 Hz 以上でサンプリングします。iOS 上の WhatsApp では、1秒未満の RTT は画面オン／フォアグラウンド状態と強く相関し、1秒を超える RTT は画面オフ／バックグラウンドでのスロットリングと相関します。
2. しきい値処理や2クラスタの k-means など、単純な分類器を構築し、各 RTT を “active” または “idle” とラベル付けします。ラベルの連続区間を集計すると、就寝時刻、通勤時間、勤務時間、デスクトップ companion がアクティブな時間を推定できます。
3. すべてのデバイスに同時にプローブを送り、ユーザーがモバイルからデスクトップに切り替える時間、companion がオフラインになる時間、アプリが push と永続ソケットのどちらによってレート制限されているかを確認します。
4. 実際のネットワークでは、`1 s` の固定しきい値を使わないでください。各デバイスを短いウォームアップ期間で初期化し、ローリングベースラインを維持します（たとえば device-activity-tracker の PoC では `threshold = 0.9 * median RTT` を使用します）。これにより、Wi-Fi／携帯回線の変動で分類器が機能しなくなるのを防げます。<sup>[[1]](#references)[[8]](#references)</sup>

## 配信 RTT から位置を推定する

同じタイミング測定の手法を使い、受信者がアクティブかどうかだけでなく、どこにいるかを推定することもできます。`Hope of Delivery` の研究では、既知の受信者の位置における RTT 分布を使って学習すると、攻撃者は後から配信確認だけで被害者の位置を分類できることが示されました。<sup>[[2]](#references)</sup>

* 同じ標的が複数の既知の場所（自宅、職場、キャンパス、国Aと国Bなど）にいる間のベースラインを作成します。
* 各場所で通常のメッセージの RTT を多数収集し、中央値、分散、パーセンタイル区分などの単純な特徴量を抽出します。
* 実際の攻撃では、新たなプローブ系列を学習済みクラスタと比較します。論文によると、同じ都市内の場所でも区別できることが多く、3つの場所を使った設定では精度が `>80%` に達しました。
* 測定経路には受信者のアクセスネットワーク、wake-up latency、メッセンジャーのインフラが含まれるため、攻撃者が送信側の環境を管理し、類似したネットワーク条件でプローブを行う場合に最も有効です。<sup>[[2]](#references)</sup>

上記のサイレントな reaction／編集／削除攻撃とは異なり、位置推定には無効な message IDs や、状態を変更する隠密な packet は必要ありません。通常の delivery confirmations を伴う通常のメッセージで十分です。そのため、隠密性は低くなりますが、より多くのメッセンジャーで利用できます。

## 隠密なリソース枯渇

サイレントプローブはすべて復号され、応答される必要があるため、reaction toggles、無効な編集、全員に対する削除 packet を継続的に送信すると、アプリケーション層の DoS が発生します。<sup>[[1]](#references)</sup>

* 無線／モデムに毎秒送受信を強制するため、特にアイドル状態の端末では、目に見えるバッテリー消費が発生します。
* 上り／下りのトラフィックが発生し、モバイルデータ通信量を消費するほか、ビデオ通話など遅延に敏感な機能と帯域を取り合うことがあります。<sup>[[1]](#references)</sup>
* 大きな無効な payloads は処理負荷を増やしますが、論文によると、暗号処理自体がバッテリー消費に占める割合はごくわずかです。<sup>[[1]](#references)</sup>
* WhatsApp では、無効な reactions は通常の絵文字から想像されるよりはるかに多くのデータを受け入れます。公開測定では、reaction 1件あたり最大でおよそ `1 MB` がサーバー側で受け入れられました。
* 本文が約 `30 bytes` を超えると、大きすぎる reactions は信頼できる delivery receipts を生成しなくなりますが、破棄される前に転送・処理はされます。ACK が必要な場合は reaction の本文を小さく保ち、純粋な drain や covert な一方向通信が目的の場合にのみ大きくしてください。
* 公開測定では、このモードで被害者側のトラフィックが約 `3.7 MB/s`（`~13.3 GB/h`）に達しました。



## References

- [1] [Careless Whisper: モバイルインスタントメッセンジャーのユーザーを監視するためのサイレント配信 receipts の悪用](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: モバイルインスタントメッセンジャーからのユーザー位置情報の抽出](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [不明なメッセージの大量送信をブロックする方法 | WhatsApp ヘルプセンター](https://faq.whatsapp.com/3379690015658337)
- [11] [電話番号はすべて米国のもの: モバイルメッセンジャーにおける contact discovery の大規模な悪用](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
