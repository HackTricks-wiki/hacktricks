# E2EE Messenger における Delivery Receipt のサイドチャネル攻撃

{{#include ../banners/hacktricks-training.md}}

Delivery receipt は、現代の end-to-end encrypted (E2EE) messenger では必須です。なぜなら、クライアントは ciphertext がいつ復号されたかを知る必要があり、そうして初めて ratcheting state と ephemeral key を破棄できるからです。サーバは opaque blob を転送するだけなので、device acknowledgement（double checkmarks）は受信者が復号成功後に送信します。攻撃者が引き起こした操作と対応する delivery receipt の間の round-trip time (RTT) を測定すると、高解像度の timing channel が露出し、device state、online presence を leak でき、covert DoS にも悪用できます。multi-device の "client-fanout" 展開では、登録済みの各 device が probe を復号してそれぞれの receipt を返すため、漏えいが増幅されます。

## Delivery receipt の送信元 vs. ユーザーに見えるシグナル

被害者の UI に目立つ artifacts を出さず、それでも必ず delivery receipt を発生させる message type を選びます。以下の表は、実測で確認された挙動を要約したものです。

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常に noisy → state の初期化にしか使えない。 |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions と removals は静かに保たれる。 |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; 期限切れ後も引き続き ack される。 |
| | Delete for everyone | ● | ○ | UI では約60 h までだが、その後の packet も引き続き ack される。 |
| **Signal** | Text message | ● | ● | WhatsApp と同じ制約。 |
| | Reaction | ● | ◐ | Self-reactions は被害者に見えない。 |
| | Edit/Delete | ● | ○ | Server は約48 h の window を強制し、最大10回の edit を許可するが、遅延 packet も引き続き ack される。 |
| **Threema** | Text message | ● | ● | multi-device receipt は集約されるため、probe ごとに見える RTT は1つだけ。 |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent な UI 挙動は本文中に記載。必要なら read receipt は無効化できるが、WhatsApp と Signal では delivery receipt はオフにできない。

## 攻撃者の目的とモデル

* **G1 – Device fingerprinting:** probe ごとに到着する receipt 数を数え、RTT を cluster して OS/client（Android vs iOS vs desktop）を推定し、online/offline の遷移を観察する。
* **G2 – 行動監視:** 高頻度の RTT series（≈1 Hz で安定）を time-series として扱い、screen on/off、app foreground/background、通勤 vs 勤務時間などを推定する。
* **G3 – Resource exhaustion:** 終わらない silent probe を送って被害者 device の radio/CPU を起こし続け、battery/data を消費させ、VoIP/RTC 品質を劣化させる。

悪用面を説明するのに十分な threat actor は2種類です。

1. **Creepy companion:** すでに被害者と chat を共有しており、既存の message ID に紐づく self-reaction、reaction removal、繰り返しの edit/delete を悪用する。
2. **Spooky stranger:** burner account を登録し、ローカル会話では一度も存在しなかった message ID を参照する reaction を送る。WhatsApp と Signal は UI が state change を破棄してもそれらを復号して acknowledge するため、事前の会話は不要です。

## 生の protocol access のための tool

基盤の E2EE protocol を露出する client に依存すると、UI の制約外で packet を作成し、任意の `message_id`s を指定し、正確な timestamp を記録できます。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) または [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) を使うと、double-ratchet state を同期したまま、生の `ReactionMessage`、`ProtocolMessage` (edit/delete)、`Receipt` frame を送信できます。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) と [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) を組み合わせると、CLI/API 経由で全 message type にアクセスできます。self-reaction の切り替え例:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client の source は、delivery receipt が device を離れる前にどのように集約されるかを文書化しており、この side channel の bandwidth がそこで無視できる理由を説明しています。
* **Turnkey PoCs:** `device-activity-tracker` や `careless-whisper-python` のような public project は、silent delete/reaction probe と RTT classification をすでに自動化しています。これらは protocol reference というより、すぐ使える reconnaissance helper とみなすべきです。重要なのは、raw client access があれば攻撃が運用上きわめて単純であることを確認している点です。

custom tooling が使えない場合でも、WhatsApp Web や Signal Desktop から silent action を起こし、暗号化された websocket/WebRTC channel を sniff することはできますが、raw API なら UI の遅延を排除でき、無効な操作も可能になります。

## Creepy companion: silent sampling loop

1. chat 内で自分が作成した過去の message を任意に選び、被害者に "reaction" balloon の変化を見せないようにします。
2. 可視な emoji と空の reaction payload（WhatsApp protobuf では `""`、または signal-cli では `--remove`）を交互に送ります。各 transmission は、被害者側に UI 上の差分がなくても device ack を返します。
3. 送信時刻と各 delivery receipt 到着時刻に timestamp を付けます。以下のような 1 Hz loop により、device ごとの RTT trace を無期限に取得できます:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal は無制限の reaction update を受け付けるため、攻撃者は新しい chat content を投稿する必要も、edit window を気にする必要もありません。

## Spooky stranger: 任意の電話番号への probing

1. 新しい WhatsApp/Signal account を登録し、対象番号の public identity key を取得します（session setup 中に自動で行われます）。
2. どちらの当事者にも見られたことのない random な `message_id` を参照する reaction/edit/delete packet を作成します（WhatsApp は任意の `key.id` GUID を受け入れ、Signal は millisecond timestamp を使います）。
3. thread が存在しなくても packet を送信します。被害者 device はそれを復号し、base message に一致しないため state change を破棄しますが、それでも受信 ciphertext を acknowledge し、device receipt を attacker に返します。
4. これを継続して繰り返し、被害者の chat list に一度も現れずに RTT series を構築します。

## Edit と delete の再利用による covert trigger

* **Repeated deletes:** メッセージが一度 delete-for-everyone された後、同じ `message_id` を参照するそれ以降の delete packet は UI には影響しませんが、各 device はそれでも復号して acknowledge します。
* **Out-of-window operations:** WhatsApp は UI で約60 h の delete / 約20 min の edit window を強制し、Signal は約48 h を強制します。これらの window 外で作成された protocol message は被害者 device では静かに無視されますが、receipt は送信されるため、会話終了後ずっと probe できます。
* **Invalid payloads:** 壊れた edit body や、すでに purge 済みの message を参照する delete も同じ挙動を引き起こします—復号と receipt は行われ、ユーザーに見える artifacts はゼロです。

## Multi-device amplification と fingerprinting

* 関連付けられた各 device（phone、desktop app、browser companion）は probe を独立に復号し、それぞれ独自の ack を返します。probe ごとの receipt 数を数えると、正確な device 数が分かります。
* ある device が offline の場合、その receipt は queue され、再接続時に送信されます。したがって、gap から online/offline の周期、さらには通勤スケジュール（例: 移動中は desktop receipt が止まる）まで leak します。
* RTT distribution は、OS の power management と push wakeup の違いにより platform ごとに異なります。RTT を cluster（例: median/variance feature での k-means）して、「Android handset」「iOS handset」「Electron desktop」などにラベル付けします。
* 送信者は暗号化前に受信者の key inventory を取得する必要があるため、攻撃者は新しい device が pair されたタイミングも観察できます。device 数の急増や新しい RTT cluster は強い指標です。

## RTT trace からの行動推定

1. OS の scheduling 効果を捉えるために ≥1 Hz で sample します。WhatsApp を iOS で使う場合、<1 s の RTT は screen-on/foreground と強く相関し、>1 s は screen-off/background throttling と相関します。
2. 各 RTT を "active" または "idle" とラベル付けする単純な classifier（thresholding か 2-cluster k-means）を作ります。ラベルを streak に集約して、就寝時刻、通勤、勤務時間、desktop companion が active になる時間などを導き出します。
3. 全 device への同時 probe を相関させて、ユーザーが mobile から desktop に切り替える瞬間、companion が offline になる瞬間、app が push と persistent socket のどちらで rate limit されているかを確認します。

## Delivery RTT からの location 推定

同じ timing primitive は、受信者が active かどうかだけでなく、どこにいるかを推定するためにも再利用できます。`Hope of Delivery` の研究では、既知の receiver location に対する RTT distribution で training すると、後で delivery confirmation だけから被害者の location を分類できることが示されました。

* 同じ対象について、いくつかの既知の場所（home、office、campus、country A vs country B など）にいる間の baseline を作ります。
* 各 location について、多数の通常 message の RTT を収集し、median、variance、percentile bucket などの単純な feature を抽出します。
* 実際の攻撃時には、新しい probe series を学習済み cluster と比較します。論文では、同じ都市内の location でもしばしば分離可能で、3-location の設定では `>80%` の accuracy が報告されています。
* これは、攻撃者が sender 環境を制御し、同様の network condition で probe する場合に最もよく機能します。なぜなら、測定される path には受信者の access network、wake-up latency、messenger infrastructure が含まれるからです。

上記の silent reaction/edit/delete 攻撃とは異なり、location 推定には無効な message ID や stealthy な state-changing packet は不要です。通常の delivery confirmation を伴う plain message で十分なので、stealth は低いものの、さまざまな messenger に広く適用できます。

## Stealthy resource exhaustion

silent probe は毎回復号と acknowledge を必要とするため、reaction toggle、無効な edit、delete-for-everyone packet を継続的に送ると application-layer DoS になります。

* 1秒ごとに radio/modem に送受信を強制する → とくに idle な handset では目立つ battery drain。
* 上り/下りの unmetered traffic を生成し、TLS/WebSocket noise に紛れながら mobile data plan を消費する。
* crypto thread を占有し、ユーザーが通知を一切見なくても、latency に敏感な機能（VoIP、video call）に jitter を生む。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
