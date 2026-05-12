# E2EEメッセンジャーにおけるDelivery Receiptサイドチャネル攻撃

{{#include ../banners/hacktricks-training.md}}

Delivery receipts は、現代のエンドツーエンド暗号化(E2EE)メッセンジャーでは必須です。クライアントは、ciphertext がいつ復号されたかを知る必要があり、そうしないと ratcheting state と ephemeral keys を破棄できないからです。サーバーは opaque blobs を転送するだけなので、device acknowledgements (double checkmarks) は受信者が復号成功後に送信します。攻撃者が引き起こした操作と対応する delivery receipt の間の round-trip time (RTT) を測定すると、高解像度のタイミングチャネルが露出し、device state や online presence が leak し、covert DoS にも悪用できます。マルチデバイスの "client-fanout" 配置では、登録済みの各デバイスが probe を復号してそれぞれ自身の receipt を返すため、leak が増幅されます。

## Delivery receipt の送信元 vs. ユーザー可視シグナル

被害者側のUIに何の痕跡も出さず、それでも必ず delivery receipt を出すメッセージ種別を選びます。下表は、実測で確認された挙動をまとめたものです。

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常にノイズが出る → state 初期化にのみ有用。 |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions と removals は静かなまま。 |
| | Edit | ● | Platform-dependent silent push | Edit window は約20分; 期限切れ後でも ack は返る。 |
| | Delete for everyone | ● | ○ | UI では約60 h までだが、後続パケットでも ack は返る。 |
| **Signal** | Text message | ● | ● | WhatsApp と同じ制約。 |
| | Reaction | ● | ◐ | Self-reactions は被害者に見えない。 |
| | Edit/Delete | ● | ○ | サーバーは約48 h window を強制し、最大10回の編集を許すが、遅延パケットでも ack は返る。 |
| **Threema** | Text message | ● | ● | Multi-device receipts は集約されるため、probe ごとに見える RTT は1回だけ。 |

凡例: ● = always, ◐ = conditional, ○ = never。Platform-dependent なUI挙動は本文中で補足しています。必要なら read receipts は無効化できますが、delivery receipts は WhatsApp や Signal ではオフにできません。

## 攻撃者の目的とモデル

* **G1 – Device fingerprinting:** probe ごとに何件の receipt が来るかを数え、RTT をクラスタリングして OS/client (Android vs iOS vs desktop) を推定し、online/offline の遷移を監視する。
* **G2 – Behavioural monitoring:** 高頻度の RTT series (≈1 Hz で安定) を time-series として扱い、screen on/off、app foreground/background、通勤時間 vs 勤務時間などを推定する。
* **G3 – Resource exhaustion:** 終わりのない静かな probe を送り続けて被害者デバイスの radio/CPU を起こし続け、battery/data を消費させ、VoIP/RTC 品質を低下させる。

悪用面を説明するには、次の2種類の threat actor で十分です。

1. **Creepy companion:** すでに被害者と chat を共有しており、self-reactions、reaction removals、または既存の message IDs に紐づく repeated edits/deletes を悪用する。
2. **Spooky stranger:** burner account を登録し、ローカル conversation では一度も存在しなかった message IDs を参照する reactions を送る。WhatsApp と Signal は UI が state change を破棄してもそれらを復号して acknowledge するため、事前の conversation は不要です。

## raw protocol access のための tooling

基盤の E2EE protocol を露出する client に依存すると、UI 制約の外で packet を組み立て、任意の `message_id`s を指定し、正確な timestamp を記録できます。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) や [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) を使うと、double-ratchet state を同期したまま raw の `ReactionMessage`、`ProtocolMessage` (edit/delete)、`Receipt` フレームを送信できます。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) と [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) を組み合わせると、CLI/API 経由であらゆる message type にアクセスできます。現在の `signal-cli` の構文は `sendReaction RECIPIENT --target-author --target-timestamp` を使います。delivery receipts が実際に集められるように `receive` または `daemon` を動かし続けてください。self-reaction toggle の例:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client のソースには、delivery receipts が device を離れる前に集約される方法が記述されており、この side channel の bandwidth がほぼ無い理由を説明しています。
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) は WhatsApp/Signal backends を同梱し、デフォルトで silent delete probes を使い、`active` と `standby` を rolling-median threshold (`RTT < 0.9 * median`) で分類します。[careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) はより軽量な WhatsApp-first CLI で、`--delay`、`--concurrent`、CSV/Prometheus exporters、Grafana-friendly な出力を備えています。どちらも protocol reference というより reconnaissance helper と見るべきです。重要なのは、raw client access があれば必要な code はこれだけで済む、という点です。

専用 tool が使えない場合でも、WhatsApp Web や Signal Desktop から silent action を起こし、暗号化された websocket/WebRTC channel を sniff できますが、raw API なら UI の遅延を取り除け、invalid operations も可能です。

## Creepy companion: silent sampling loop

1. チャット内で自分が過去に送った任意の message を選び、被害者に "reaction" balloon の変化を見せないようにします。
2. 見える emoji と空の reaction payload (`WhatsApp protobufs` では `""`、`signal-cli` では `--remove`) を交互に送ります。各 transmission は、被害者側に UI 差分がなくても device ack を返します。
3. 送信時刻と各 delivery receipt の到着時刻を記録します。次のような 1 Hz loop なら、各 device ごとの RTT trace を無期限に得られます。
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal は無制限の reaction updates を受け付けるため、攻撃者は新しい chat content を投稿したり edit window を気にしたりする必要がありません。

## Spooky stranger: 任意の電話番号への probing

1. 新しい WhatsApp/Signal account を登録し、target number の public identity keys を取得します (session setup 中に自動で行われます)。
2. 当事者のどちらにも見られたことのない random な `message_id` を参照する reaction/edit/delete packet を作成します (WhatsApp は任意の `key.id` GUID を受け付け、Signal は millisecond timestamps を使います)。
3. thread が存在しなくても packet を送信します。被害者 device はそれを復号し、base message の一致に失敗し、state change を破棄しますが、それでも incoming ciphertext を acknowledge し、device receipts を攻撃者へ返します。
4. これを継続して繰り返し、被害者の chat list に一度も現れずに RTT series を構築します。

どの番号が登録済みかを先に調べたい場合、あるいは大規模に device inventory を事前投入したい場合は、ランダムな E.164 範囲を手当たり次第に推測するのではなく、これを [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) と連携させます。

最近の WhatsApp build では `Settings -> Privacy -> Advanced -> Block unknown account messages` も使えます。これは修正策ではなく throughput limiter と考えてください。主に持続的な stranger-only flooding を妨げるだけで、すでに known contact である相手には無関係です。

## edit と delete を covert trigger として再利用する

* **Repeated deletes:** 一度 `delete-for-everyone` された後は、同じ `message_id` を参照する追加の delete packet は UI に影響しませんが、各 device はそれでも復号して acknowledge します。
* **Out-of-window operations:** WhatsApp は UI 上で約60 h の delete / 約20 min の edit window を強制し、Signal は約48 h を強制します。これらの window 外で作られた protocol messages は被害者 device 上では静かに無視されますが、receipt は送信されるため、会話終了後かなり経っても無期限に probing できます。
* **Invalid payloads:** 形式不正な edit body や、すでに purge 済みの message を参照する delete でも同じ挙動になります。つまり、復号 + receipt、ユーザー可視 artifact はゼロです。

## Multi-device amplification & fingerprinting

* 各 associated device (phone、desktop app、browser companion) は probe を独立に復号し、自身の ack を返します。probe ごとの receipt 数を数えれば、正確な device 数が分かります。
* device が offline だと、receipt は queue され、再接続時に送信されます。したがって欠落は online/offline cycle、さらには通勤スケジュールまでも leak します (例: 移動中は desktop receipts が止まる)。
* RTT 分布は、OS の power management と push wakeup の違いにより platform ごとに異なります。RTT をクラスタリング (例: median/variance 特徴量への k-means) して、「Android handset」「iOS handset」「Electron desktop」などにラベル付けします。
* sender は暗号化前に受信者の key inventory を取得する必要があるため、攻撃者は新しい device が pair されたタイミングも監視できます。device 数の急増や新しい RTT cluster は強い指標です。

## RTT trace からの behaviour 推定

1. OS の scheduling 影響を捉えるため、≥1 Hz でサンプリングします。iOS 上の WhatsApp では、<1 s の RTT は screen-on/foreground と強く相関し、>1 s は screen-off/background throttling と相関します。
2. 各 RTT を "active" または "idle" と判定する単純な classifier (thresholding や2クラスタ k-means) を作ります。ラベルを連続区間にまとめると、就寝時刻、通勤、勤務時間、desktop companion が有効な時間帯などを導けます。
3. すべての device への同時 probe を相関させ、ユーザーが mobile から desktop に切り替える瞬間、companion が offline になる瞬間、app が push か persistent socket のどちらで rate limit されているかを確認します。
4. 実ネットワークでは、単一の固定 `1 s` threshold は避けます。短い warm-up window で各 device を初期化し、rolling baseline (たとえば `threshold = 0.9 * median RTT`) を維持して、Wi-Fi/cellular の揺らぎで classifier が崩れないようにします。

## delivery RTT からの location 推定

同じ timing primitive は、相手が active かどうかだけでなく、どこにいるかの推定にも再利用できます。`Hope of Delivery` の研究では、既知の receiver location における RTT distribution で学習すると、後から delivery confirmations だけで被害者の location を分類できることが示されました。

* 同じ target について、いくつかの既知の場所 (home、office、campus、country A vs country B など) にいる間の baseline を構築します。
* 各 location について、多数の通常の message RTT を収集し、median、variance、percentile bucket などの単純な特徴を抽出します。
* 実際の攻撃では、新しい probe series を学習済み cluster と比較します。論文では、同じ city 内の location でもしばしば分離でき、3-location 設定で `>80%` の accuracy が報告されています。
* この手法は、attacker が sender 環境を制御し、似た network conditions で probe する場合に最も有効です。測定 path には受信者 access network、wake-up latency、messenger infrastructure が含まれるからです。

上記の静かな reaction/edit/delete 攻撃とは異なり、location 推定には invalid message IDs や stealthy な state-changing packet は不要です。通常の delivery confirmations を伴う plain messages だけで十分なので、stealth は下がりますが、対応する messenger の範囲は広がります。

## Stealthy resource exhaustion

各 silent probe は必ず復号されて acknowledge されるため、reaction toggles、invalid edits、delete-for-everyone packets を継続送信すると application-layer DoS になります。

* 毎秒 radio/modem に送受信を強制する → 特に idle な handset では顕著な battery drain。
* 料金対象外の upstream/downstream traffic を生成し、mobile data plan を消費しつつ TLS/WebSocket noise に紛れ込む。
* crypto threads を占有し、遅延に敏感な機能 (VoIP、video calls) に jitter を入れる。ユーザーには通知が一切見えなくてもです。
* WhatsApp では、無効な reaction は通常の emoji の想定を大きく超えるデータを受け付けます。公開計測では、server-side acceptance は reaction ごとにおよそ `1 MB` まで確認されています。
* oversized reaction は body が約 `30 bytes` を超えると安定した delivery receipts を返さなくなりますが、それでも転送・処理された後に破棄されます。ACK が必要なときは reaction body を小さく保ってください。純粋な drain や covert な一方向 transport が目的のときだけ大きくします。
* 公開計測では、このモードで被害者トラフィックが約 `3.7 MB/s` (`~13.3 GB/h`) に達しました。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)

{{#include ../banners/hacktricks-training.md}}
