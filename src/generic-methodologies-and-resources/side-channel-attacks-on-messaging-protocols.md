# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

Delivery receipts はモダンな end-to-end encrypted (E2EE) メッセンジャーで必須です。クライアントは ciphertext が復号された時点を知る必要があり、その後に ratcheting state や ephemeral keys を破棄します。サーバは opaque blobs を転送するため、device acknowledgements (double checkmarks) は受信側が復号に成功した後に発行されます。攻撃者がトリガーしたアクションと対応する delivery receipt の間の round-trip time (RTT) を計測すると、高解像度の timing channel が開き、device state や online presence を leak し、covert DoS に悪用できます。マルチデバイスの "client-fanout" 展開は各登録デバイスが probe を復号して各自の receipt を返すため、leakage を増幅します。

## Delivery receipt sources vs. user-visible signals

被害者の UI に痕跡を残さないが常に delivery receipt を発生させる message type を選んでください。以下の表は実証済みの振る舞いを要約しています:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常にノイジー → state をブートストラップする用途のみ有用。 |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions と removal は無音のまま。 |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; 期限切れ後でも ack される。 |
| | Delete for everyone | ● | ○ | UI は約60時間まで許容するが、後続パケットも ack される。 |
| **Signal** | Text message | ● | ● | WhatsApp と同様の制約。 |
| | Reaction | ● | ◐ | Self-reactions は被害者には見えない。 |
| | Edit/Delete | ● | ○ | サーバは約48時間のウィンドウを強制、最大10回の編集を許可するが、遅延パケットも ack される。 |
| **Threema** | Text message | ● | ● | マルチデバイスの receipts は集約されるため、probe ごとに見える RTT は1つだけ。 |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent な UI 振る舞いはインラインで注記しています。read receipts を無効にできても、WhatsApp と Signal では delivery receipts をオフにすることはできません。

## Attacker goals and models

* **G1 – Device fingerprinting:** probe ごとに到着する receipt の数を数え、RTT をクラスタリングして OS/クライアント（Android vs iOS vs desktop）を推定し、online/offline の遷移を監視します。
* **G2 – Behavioural monitoring:** 高頻度の RTT シリーズ（≈1 Hz が安定）を時系列として扱い、画面の ON/OFF、アプリの foreground/background、通勤時間帯と労働時間などを推定します。
* **G3 – Resource exhaustion:** 終わりのない silent probes を送り続けて被害者デバイスの radio/CPU を常時起こし、バッテリ/データを枯渇させ、VoIP/RTC の品質を劣化させます。

濫用面を説明するのに十分な脅威アクターは二つです:

1. **Creepy companion:** 既に被害者とチャットを共有しており、self-reactions、reaction removals、あるいは既存メッセージID に紐づく繰り返しの edits/deletes を悪用します。
2. **Spooky stranger:** burner アカウントを登録し、ローカル会話に存在しない message ID を参照する reaction を送ります; WhatsApp と Signal は UI が state 変更を破棄してもそれらを復号して acknowledge するため、事前の会話は不要です。

## Tooling for raw protocol access

UI 制約外でパケットを作成し、任意の `message_id` を指定し、正確なタイムスタンプを記録するには、基盤となる E2EE プロトコルを露出するクライアントに依存してください:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) や [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) は、ReactionMessage、ProtocolMessage (edit/delete)、Receipt フレームを raw に送出しつつ double-ratchet state を同期したままにできます。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) と [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) を組み合わせると、すべての message type を CLI/API 経由で扱えます。self-reaction のトグル例:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android クライアントのソースは、delivery receipts がデバイス上でどのように集約されるかを文書化しており、それがこのサイドチャネルの帯域が有意に小さい理由を説明します。

カスタムツールが無い場合でも、WhatsApp Web や Signal Desktop から silent actions をトリガーし、暗号化された websocket/WebRTC チャネルをスニッフすることで同様のことが可能ですが、raw API は UI の遅延を排除し無効な操作も可能にします。

## Creepy companion: silent sampling loop

1. 被害者が変化を気づかないよう、自分がチャットに投稿した任意の過去メッセージを選びます。
2. 目に見える emoji と空の reaction ペイロード（WhatsApp protobuf では `""`、signal-cli では `--remove` としてエンコード）を交互に送ります。UI に変化がなくても各送信で device ack が返ります。
3. 送信時刻と各 delivery receipt 到着時刻をタイムスタンプします。以下のような 1 Hz ループは、デバイスごとの RTT トレースを無期限に与えます:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal は無制限の reaction 更新を受け入れるため、攻撃者は新しいチャット内容を投稿したり edit ウィンドウを気にしたりする必要がありません。

## Spooky stranger: probing arbitrary phone numbers

1. 新しい WhatsApp/Signal アカウントを登録し、ターゲット番号の public identity keys を取得します（これはセッション設定時に自動で行われます）。
2. どちらの当事者も見たことがないランダムな `message_id` を参照する reaction/edit/delete パケットを作成します（WhatsApp は任意の `key.id` GUID を受け入れ、Signal はミリ秒タイムスタンプを使用します）。
3. スレッドが存在しなくてもそのパケットを送信します。被害者デバイスはそれを復号し、ベースメッセージとマッチしないため state 変更を破棄しますが、受信した ciphertext を acknowledge し、device receipts を攻撃者に返します。
4. これを繰り返して RTT シリーズを構築すれば、被害者のチャット一覧に現れることなく監視できます。

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 一度 delete-for-everyone した後でも、同じ `message_id` を参照する追加の delete パケットは UI に影響を与えませんが、各デバイスはそれらを復号して acknowledge します。
* **Out-of-window operations:** WhatsApp は UI 上で約60時間の delete / 約20分の edit ウィンドウを強制し、Signal は約48時間を強制します。これらのウィンドウ外で作成した protocol messages は被害者デバイス上で無音で無視されますが、receipts は送信されるため、会話終了後も攻撃者は無期限にプローブできます。
* **Invalid payloads:** 破損した edit 本文や既に purge されたメッセージを参照する deletes も同様の振る舞いを引き起こします — 復号して receipt を返し、ユーザーには何も見えません。

## Multi-device amplification & fingerprinting

* それぞれの紐づいた device（電話、デスクトップアプリ、ブラウザ companion）は probe を個別に復号し各自の ack を返します。probe ごとの receipt 数を数えると正確なデバイス数が判明します。
* デバイスがオフラインの場合、その receipt はキューに入り再接続時に発行されます。したがってギャップは online/offline サイクルや通勤スケジュール（例: 旅行中に desktop の receipt が止まる）を漏らします。
* OS の電源管理や push wakeup の違いにより RTT 分布はプラットフォームごとに異なります。RTT をクラスタリング（例: median/variance 特徴で k-means）すると “Android handset”, “iOS handset”, “Electron desktop” などのラベル付けが可能です。
* 送信者は暗号化前に受信者の key inventory を取得する必要があるため、攻撃者は新しいデバイスがペアリングされた時期も監視できます。デバイス数の急増や新しい RTT クラスターの出現は有力なインジケータです。

## Behaviour inference from RTT traces

1. OS のスケジューリング効果を捉えるために ≥1 Hz でサンプリングします。WhatsApp on iOS では、<1 s の RTT は画面オン/フォアグラウンドと強く相関し、>1 s は画面オフ/バックグラウンドのスロットリングと相関します。
2. 単純な分類器（閾値判定や2クラスタ k-means）を構築し、各 RTT を "active" または "idle" とラベル付けします。ラベルをストリークに集約して就寝時間、通勤、勤務時間、あるいは desktop companion の稼働時間を導出します。
3. 全デバイスに対する同時プローブを相関させることで、ユーザーが mobile から desktop に切り替えた時、companion がオフラインになった時、アプリが push と persistent socket によってどちらでレート制限されているかを見分けられます。

## Stealthy resource exhaustion

すべての silent probe は復号して acknowledge される必要があるため、reaction トグル、無効な edits、delete-for-everyone パケットを継続的に送ることでアプリケーション層の DoS が発生します:

* 無音のプローブを毎秒送らせることで radio/modem を継続的に送受信させ → 特に未使用のハンドセットで顕著なバッテリ消費を引き起こします。
* TLS/WebSocket ノイズに紛れてモバイルデータプランを消費する上り/下りトラフィックが発生します。
* 暗号スレッドを占有して VoIP やビデオ通話のようなレイテンシに敏感な機能にジッタを導入します — ユーザーは通知を一切見ません。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
