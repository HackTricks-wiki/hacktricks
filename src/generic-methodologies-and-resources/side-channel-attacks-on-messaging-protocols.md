# E2EE MessengerにおけるDelivery Receiptのサイドチャネル攻撃

{{#include ../banners/hacktricks-training.md}}

Delivery receipts は、現代の end-to-end encrypted (E2EE) messenger では必須です。クライアントは ciphertext がいつ復号されたかを知る必要があり、そうしないと ratcheting state や ephemeral keys を破棄できないためです。サーバーは opaque blobs を転送するだけなので、device acknowledgements (double checkmarks) は受信側が復号成功後に送信します。攻撃者が引き起こした動作と対応する delivery receipt の間の round-trip time (RTT) を測定すると、高解像度のタイミングチャネルが露出し、device state、online presence が漏洩し、covert DoS に悪用できます。multi-device の "client-fanout" デプロイでは、登録済みの各 device が probe を復号してそれぞれの receipt を返すため、漏洩が増幅されます。

## Delivery receipt の送信源 vs. ユーザー可視シグナル

被害者の UI にアーティファクトを出さず、かつ必ず delivery receipt を送る message type を選びます。下表は実測で確認された挙動を要約したものです。

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常にノイズが出る → state の初期化にのみ有用。 |
| | Reaction | ● | ◐ (victim message に対する reaction の場合のみ) | self-reactions と removals は静かなまま。 |
| | Edit | ● | Platform-dependent silent push | Edit window は約20分; 期限後も ack は返る。 |
| | Delete for everyone | ● | ○ | UI 上は約60 h までだが、後続 packet も ack される。 |
| **Signal** | Text message | ● | ● | WhatsApp と同じ制約。 |
| | Reaction | ● | ◐ | self-reactions は被害者に見えない。 |
| | Edit/Delete | ● | ○ | Server は約48 h window を強制し、最大10回の edit を許可するが、遅延 packet も ack される。 |
| **Threema** | Text message | ● | ● | multi-device receipt は集約されるため、probe ごとに見える RTT は1つだけ。 |

凡例: ● = 常に, ◐ = 条件付き, ○ = なし。Platform-dependent な UI 挙動は本文中で補足しています。必要なら read receipts を無効化できますが、delivery receipts は WhatsApp や Signal ではオフにできません。

## 攻撃者の目標とモデル

* **G1 – Device fingerprinting:** probe ごとに何個の receipt が届くかを数え、RTT をクラスタリングして OS/client (Android vs iOS vs desktop) を推定し、online/offline の遷移を監視する。
* **G2 – 行動監視:** 高頻度の RTT series (≈1 Hz で安定) を time-series として扱い、screen on/off、app foreground/background、通勤時間 vs 就業時間などを推定する。
* **G3 – Resource exhaustion:** 終わりのない silent probes を送って被害者 device の radio/CPU を起こし続け、battery/data を消費させ、VoIP/RTC の品質を劣化させる。

悪用面を説明するには、2種類の threat actor で十分です。

1. **Creepy companion:** すでに被害者と chat を共有しており、既存 message ID に紐づく self-reactions、reaction removals、または repeated edits/deletes を悪用する。
2. **Spooky stranger:** burner account を登録し、ローカルの会話には存在しなかった message ID を参照する reaction を送る。WhatsApp と Signal は UI が state change を破棄しても復号して acknowledgement を返すため、事前の会話は不要です。

## 生の protocol access のための tooling

基盤となる E2EE protocol を公開する client を使えば、UI 制約の外で packet を作成し、任意の `message_id` を指定し、正確な timestamp を記録できます。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) または [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) を使うと、double-ratchet state を同期したまま raw な `ReactionMessage`、`ProtocolMessage` (edit/delete)、`Receipt` frame を送れます。
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) と [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) を組み合わせると、CLI/API 経由で全 message type にアクセスできます。現在の `signal-cli` の syntax は `sendReaction RECIPIENT --target-author --target-timestamp` を使います。delivery receipts が実際に収集されるように `receive` または `daemon` を動かし続けてください。self-reaction の toggle 例:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client のソースには、delivery receipts が device を離れる前に集約される方法が文書化されており、この side channel の bandwidth がほぼ無視できる理由を説明しています。
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) は WhatsApp/Signal backend を搭載し、既定で silent delete probes を使い、rolling-median threshold (`RTT < 0.9 * median`) で `active` と `standby` を分類します。[careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) はより軽量な WhatsApp-first CLI で、`--delay`、`--concurrent`、CSV/Prometheus exporter、Grafana 向け出力を備えています。どちらも protocol reference というより recon helper として扱ってください。重要なのは、生の client access があれば必要な code が非常に少ないことです。

専用 tooling が使えない場合でも、WhatsApp Web や Signal Desktop から silent action を発火させ、暗号化された websocket/WebRTC channel を sniff できます。ただし raw API を使えば UI 遅延を取り除け、無効な操作も可能になります。

## Creepy companion: silent sampling loop

1. 被害者に "reaction" の balloon 変化を見せないよう、チャット内で自分が過去に送った message を任意に選びます。
2. 可視 emoji と空の reaction payload (`WhatsApp protobufs` では `""`、`signal-cli` では `--remove`) を交互に送ります。各 transmission は、被害者側に UI 差分がなくても device ack を返します。
3. 送信時刻と各 delivery receipt の到着時刻を記録します。次のような 1 Hz ループで、device ごとの RTT trace を無期限に取得できます:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal は unlimited な reaction updates を受け付けるため、攻撃者は新しい chat content を投稿する必要も、edit window を気にする必要もありません。

## Spooky stranger: 任意の電話番号への probe

1. 新規の WhatsApp/Signal account を登録し、target number の public identity keys を取得します (session setup 中に自動実行されます)。
2. 当事者のどちらからも見たことのない random な `message_id` を参照する reaction/edit/delete packet を作成します (WhatsApp は任意の `key.id` GUID を受け入れ、Signal は millisecond timestamps を使います)。
3. thread が存在しなくても packet を送ります。被害者 device はそれを復号し、base message に一致しないため state change を破棄しますが、それでも incoming ciphertext を acknowledge し、device receipts を攻撃者に返します。
4. これを継続して繰り返し、被害者の chat list に一切現れずに RTT series を構築します。

もし先に登録済み番号の発見や、device inventory の大規模な事前投入が必要なら、手作業で random な E.164 range を当てるのではなく、[contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) を連鎖させてください。

公開された contact-discovery の研究は、これが運用上なぜ重要かを示しています。正確な phone-prefix table と少量の資源があれば、研究者は WhatsApp で米国の mobile numbers の約 `10%`、Signal で `100%` を問い合わせ、その後 targeted probing に移れました。実際には、最初に live account を pre-filter しておくと、silent-probe の予算を実際に packet を復号する番号に集中できます。

最近の WhatsApp build では `Settings -> Privacy -> Advanced -> Block unknown account messages` も公開されています。これは修正ではなく throughput limiter と考えてください。主に継続的な stranger-only flooding に効くだけで、すでに known contact であれば無関係です。

## Edit と delete を covert trigger として再利用する

* **Repeated deletes:** message が一度 delete-for-everyone されると、同じ `message_id` を参照する後続の delete packet は UI に影響しませんが、各 device は依然として復号して acknowledge します。
* **Out-of-window operations:** WhatsApp は UI 上で約60 h の delete / 約20 min の edit window を強制し、Signal は約48 h を強制します。これらの window 外で作成された protocol message は被害者 device では静かに無視されますが receipt は送信されるため、会話終了後どれだけ時間が経っても攻撃者は probe し続けられます。
* **Invalid payloads:** 壊れた edit body や、すでに消去された message を参照する delete は同じ挙動を引き起こします。つまり、復号 + receipt、ユーザー可視アーティファクトはゼロです。

## Multi-device の増幅と fingerprinting

* 各関連 device (phone、desktop app、browser companion) は probe を独立に復号し、それぞれ独自の ack を返します。probe ごとの receipt 数を数えると、正確な device 数が分かります。
* device が offline だと receipt はキューされ、再接続時に送信されます。したがって、欠損は online/offline cycle、さらには通勤スケジュールまでも漏洩します (例: 移動中は desktop receipt が止まる)。
* RTT distribution は、OS の power management と push wakeup の違いにより platform ごとに異なります。RTT をクラスタリングし (例: median/variance feature に対する k-means)、"Android handset"、"iOS handset"、"Electron desktop" などにラベル付けします。
* sender は暗号化前に受信者の key inventory を取得する必要があるため、攻撃者は新しい device が pair されたタイミングも監視できます。device 数の急増や新しい RTT cluster は強い指標です。

## サンプリング cadence、queueing、stacked receipts

* **WhatsApp の burst 耐性:** 公開された計測では、WhatsApp は server-side queueing が目立たないまま、1 probe あたり `50 ms` という速さの silent-reaction burst を受け付けました。これは短い calibration burst、素早い device 数の把握、または drain attack の急速な立ち上げに有用です。
* **Signal の長期 queueing:** Signal は短い burst に耐えましたが、継続的な毎秒複数 probe の traffic では queueing を始めました。長時間の monitoring では、各 receipt が backlog の排出ではなく現在の device state を反映するよう、cadence を約 `1 Hz` (またはそれ以下) に保ってください。
* **Reconnect artefacts:** device が online に戻ると、いくつかの client は遅延した複数の receipt をまとめて、または素早く flush します。これらの receipt burst は独立した RTT sample ではなく state-transition の marker として扱ってください。そうしないと、クラスタリングや `active` vs `idle` classifier が reconnect ノイズに過学習します。

## RTT trace からの行動推定

1. OS の scheduling 効果を捉えるため、≥1 Hz でサンプルします。WhatsApp on iOS では、<1 s の RTT は screen-on/foreground と強く相関し、>1 s は screen-off/background throttling と相関します。
2. 各 RTT を "active" または "idle" に分類する単純な classifier (thresholding や 2-cluster k-means) を構築します。ラベルを streak に集約して、就寝時刻、通勤、勤務時間、desktop companion が active になる時間を導きます。
3. 全 device への同時 probe を相関させ、ユーザーが mobile から desktop に切り替えるタイミング、companion が offline になるタイミング、app が push か persistent socket のどちらで rate limit されているかを見ます。
4. 実ネットワークでは、単一の固定 `1 s` threshold を避けます。短い warm-up window で各 device を bootstrap し、rolling baseline (たとえば `threshold = 0.9 * median RTT`) を維持して、Wi-Fi/cellular の変動で classifier が崩れないようにします。

## Delivery RTT からの位置推定

同じタイミング原始を使って、相手が active かどうかだけでなく、どこにいるかも推定できます。`Hope of Delivery` の研究は、既知の受信者ロケーションにおける RTT distribution で学習すると、後から delivery confirmation だけで被害者の location を分類できることを示しました。

* 対象が複数の既知の場所にいる間 (home、office、campus、country A vs country B など) に baseline を作ります。
* 各 location について、多数の通常メッセージ RTT を収集し、median、variance、percentile bucket などの単純な feature を抽出します。
* 実際の攻撃時には、新しい probe series を学習済み cluster と比較します。論文では、同一都市内の location でさえしばしば分離でき、3-location の設定で `>80%` の精度が報告されています。
* これは、攻撃者が sender 環境を制御し、類似した network condition で probe する場合に特に有効です。測定 path には受信者の access network、wake-up latency、messenger infrastructure が含まれるためです。

上記の silent reaction/edit/delete 攻撃とは異なり、位置推定に invalid な message ID や stealthy な state-changing packet は必要ありません。通常の delivery confirmation を伴う通常の message で十分なので、stealth は下がりますが、より多くの messenger に適用できます。

## Stealthy resource exhaustion

各 silent probe は必ず復号され、acknowledge されるため、reaction toggle、invalid edit、delete-for-everyone packet を継続送信すると application-layer DoS になります。

* 毎秒 radio/modem を送受信させる → 特に待機中の handset では顕著な battery drain。
* 上り/下り traffic を発生させ、mobile data plan を消費しつつ TLS/WebSocket noise に紛れ込む。
* crypto thread を占有し、遅延に敏感な機能 (VoIP、video call) に jitter を生じさせるが、ユーザーには通知が一切見えない。
* WhatsApp では、無効な reaction は通常の emoji からは想像できないほど多くの data を受け入れます。公開計測では、server-side の受理は reaction あたりおよそ `1 MB` まで確認されました。
* oversized な reaction は body が約 `30 bytes` を超えると reliable な delivery receipt を出さなくなりますが、それでも転送され、破棄前に処理されます。ACK が必要なときは reaction body を小さく保ってください。純粋な drain や covert な一方向 transport が目的のときだけ大きくします。
* 公開計測では、このモードで被害者 traffic が約 `3.7 MB/s` (`~13.3 GB/h`) に達しました。

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
