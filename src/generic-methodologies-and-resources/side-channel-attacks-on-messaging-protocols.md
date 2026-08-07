# E2EE Messenger における Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

現代の end-to-end encrypted (E2EE) messenger では、client が ciphertext の decrypt 完了時点を把握し、ratcheting state と ephemeral keys を破棄できるように、delivery receipts が必須となっている。server は opaque blobs を転送するだけなので、device acknowledgements（double checkmarks）は recipient が正常に decrypt した後に発行される。attacker が誘発した action と、それに対応する delivery receipt の間の round-trip time (RTT) を測定すると、高解像度の timing channel が生じ、device state や online presence が leak するほか、covert DoS に悪用できる。Multi-device の "client-fanout" deployment では、登録されているすべての device が probe を decrypt して自身の receipt を返すため、leak がさらに増幅される。<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

常に delivery receipt を発行する一方で、victim の UI に artifact を表示しない message type を選択する。以下の table は、実測で確認された挙動をまとめたものである。<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常に noisy → state の bootstrap にのみ有用。 |
| | Reaction | ● | ◐ (victim の message に反応した場合のみ) | Self-reaction と removal は silent のまま。 |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min。期限切れ後も ack される。 |
| | Delete for everyone | ● | ○ | UI では約 60 h だが、その後の packet も ack される。 |
| **Signal** | Text message | ● | ● | WhatsApp と同じ制限。 |
| | Reaction | ● | ◐ | Self-reaction は victim から見えない。 |
| | Edit/Delete | ● | ○ | server は約 48 h の window を適用し、最大 10 回の edit を許可するが、遅れて届いた packet も ack される。 |
| **Threema** | Text message | ● | ● | Multi-device の receipt は集約されるため、probe ごとに見える RTT は 1 つだけ。 |

Legend: ● = 常時、◐ = 条件付き、○ = なし。Platform-dependent な UI の挙動は inline で示している。必要に応じて read receipts を無効化できるが、WhatsApp や Signal では delivery receipts を無効化できない。<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** probe ごとに到着する receipt 数を数え、RTT を cluster 化して OS/client（Android、iOS、desktop）を推測し、online/offline の遷移を監視する。
* **G2 – Behavioural monitoring:** 高頻度の RTT series（≈1 Hz が安定）を time-series として扱い、screen の on/off、app の foreground/background、通勤時間と勤務時間の違いなどを推測する。
* **G3 – Resource exhaustion:** 終わりのない silent probe を送信して、すべての victim device の radio/CPU を起動状態に保ち、battery/data を消費させ、VoIP/RTC の品質を低下させる。<sup>[[1]](#references)</sup>

abuse surface を説明するには、2 つの threat actor で十分である。<sup>[[1]](#references)</sup>

1. **Creepy companion:** すでに victim と chat を共有しており、self-reaction、reaction removal、または既存の message ID に紐付いた反復的な edit/delete を悪用する。
2. **Spooky stranger:** burner account を登録し、local conversation に存在しない message ID を参照する reaction を送信する。WhatsApp と Signal は、UI が state change を破棄する場合でも decrypt と acknowledge を行うため、prior conversation は不要である。

## Tooling for raw protocol access

基盤となる E2EE protocol を公開している client を使用すると、UI の制約外で packet を作成し、任意の `message_id` を指定し、正確な timestamp を記録できる。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) または [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented) により、double-ratchet state を同期したまま、raw の `ReactionMessage`、`ProtocolMessage` (edit/delete)、`Receipt` frame を送信できる。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli) と [libsignal-service-java](https://github.com/signalapp/libsignal-service-java) を組み合わせると、CLI/API 経由ですべての message type を利用できる。<sup>[[5]](#references)[[7]](#references)</sup> 現在の `signal-cli` syntax では `sendReaction RECIPIENT --target-author --target-timestamp` を使用する。delivery receipt を確実に収集するには、`receive` または `daemon` を実行し続ける。<sup>[[6]](#references)</sup> Self-reaction toggle の例:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client の source には、device 外部へ送信される前に delivery receipt がどのように統合されるかが記載されており、ここでの side channel の bandwidth が negligible である理由を説明している。<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker) には WhatsApp/Signal backend が含まれ、silent delete probe を default とし、rolling-median threshold (`RTT < 0.9 * median`) により `active` と `standby` を分類する。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python) は、`--delay`、`--concurrent`、CSV/Prometheus exporter、Grafana に適した output を備えた、より軽量な WhatsApp-first CLI である。<sup>[[9]](#references)</sup> どちらも protocol reference ではなく reconnaissance helper として扱うべきである。重要な点は、raw client access が存在すれば必要な code がいかに少ないかということである。

custom tooling を利用できない場合でも、WhatsApp Web または Signal Desktop から silent action を trigger し、暗号化された websocket/WebRTC channel を sniff できる。ただし raw API により、UI delay を除去し、invalid operation を実行できる。

## Creepy companion: silent sampling loop

1. chat 内で自分が作成した過去の message を選ぶ。これにより、victim には "reaction" balloon の変更が表示されない。
2. visible emoji と空の reaction payload（WhatsApp protobuf では `""`、signal-cli では `--remove` として encode）を交互に送信する。victim 側に UI delta がないにもかかわらず、各 transmission は device ack を生成する。
3. send time と、すべての delivery receipt の到着時刻を timestamp 化する。以下のような 1 Hz loop により、device ごとの RTT trace を無期限に取得できる。
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal は reaction update を無制限に受け付けるため、attacker は新しい chat content を投稿する必要も、edit window を気にする必要もない。<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. 新しい WhatsApp/Signal account を登録し、target number の public identity keys を取得する（session setup 中に自動的に実行される）。
2. どちらの party も見たことのない random な `message_id` を参照する reaction/edit/delete packet を作成する（WhatsApp は任意の `key.id` GUID を受け付け、Signal は millisecond timestamp を使用する）。
3. thread が存在しなくても packet を送信する。victim device は packet を decrypt し、base message との match に失敗して state change を破棄するが、incoming ciphertext は acknowledge し、device receipt を attacker に返す。
4. victim の chat list に一度も表示されることなく、これを継続的に繰り返して RTT series を構築する。<sup>[[1]](#references)</sup>

登録済みの number を先に発見する必要がある場合、または大規模に device inventory を事前作成したい場合は、E.164 range を手作業でランダムに推測するのではなく、[contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md) と chain する。

公開された contact-discovery research は、これが operational に重要な理由を示している。正確な phone-prefix table と適度な resource により、researcher は targeted probing に移る前に、WhatsApp では米国 mobile number の約 `10%`、Signal では `100%` を query できた。<sup>[[11]](#references)</sup> 実際には、まず live account を pre-filter しておくことで、silent-probe budget を実際に packet を decrypt する number に集中できる。

最近の WhatsApp build では、`Settings -> Privacy -> Advanced -> Block unknown account messages` も公開されている。<sup>[[10]](#references)</sup> これは fix ではなく throughput limiter として扱うべきである。主に stranger-only の sustained flooding に影響するだけで、すでに known contact である場合は関係ない。

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** message が一度 Delete for everyone された後も、同じ `message_id` を参照する delete packet を追加送信すると UI effect はないが、すべての device が decrypt して acknowledge する。
* **Out-of-window operations:** WhatsApp は UI で約 60 h の delete window / 約 20 min の edit window を適用し、Signal は約 48 h を適用する。これらの window 外の crafted protocol message は victim device 上で silent に無視されるが、receipt は送信されるため、conversation 終了後も長期間 probe できる。
* **Invalid payloads:** malformed edit body や、すでに purge された message を参照する delete でも同じ挙動（decryption と receipt、user-visible artefact はゼロ）が発生する。<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* 関連付けられた各 device（phone、desktop app、browser companion）は probe を独立して decrypt し、それぞれ自身の ack を返す。probe ごとの receipt 数を数えることで、正確な device 数を把握できる。
* device が offline の場合、その receipt は queue され、reconnection 時に発行される。そのため gap から online/offline cycle や commuting schedule まで leak する（例: desktop receipt は移動中に停止する）。
* RTT distribution は OS power management と push wakeup の違いにより platform ごとに異なる。RTT を cluster 化し（例: median/variance feature に対する k-means）、“Android handset”、“iOS handset”、“Electron desktop” などの label を付ける。
* sender は encrypt 前に recipient の key inventory を取得する必要があるため、attacker は新しい device が pair された時点も監視できる。device 数の突然の増加や新しい RTT cluster は強い indicator となる。<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 公開された measurement では、WhatsApp が明らかな server-side queueing なしに、最短で 1 probe / `50 ms` の silent-reaction burst を受け付けたと報告されている。これは短い calibration burst、素早い device count、または drain attack の迅速な ramp-up に有用である。
* **Signal long-run queueing:** Signal は短い burst には耐えたが、sustained な multi-probe-per-second traffic では queueing が始まった。long-lived monitoring では cadence を約 `1 Hz`（またはそれ以下）に保ち、各 receipt が backlog drain ではなく現在の device state を反映するようにする。
* **Reconnect artefacts:** device が online に戻ると、一部の client は遅延した receipt を batch 処理するか、急速に flush する。これらの receipt burst は独立した RTT sample ではなく state-transition marker として扱う。そうしないと、clustering / `active` vs `idle` classifier が reconnect noise に overfit する。<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effect を取得するため、≥1 Hz で sample する。iOS 上の WhatsApp では、<1 s の RTT は screen-on/foreground と強く相関し、>1 s は screen-off/background throttling と相関する。
2. 単純な classifier（thresholding または 2-cluster k-means）を構築し、各 RTT を "active" または "idle" と label する。label を streak として集約し、就寝時間、通勤時間、勤務時間、desktop companion が active な時間などを導出する。
3. すべての device に対する同時 probe を correlate し、user が mobile から desktop に切り替えるタイミング、companion が offline になるタイミング、app が push と persistent socket のどちらによって rate limit されているかを確認する。
4. 実 network では、単一の hardcoded な `1 s` threshold を避ける。各 device を短い warm-up window で bootstrap し、rolling baseline（例: `threshold = 0.9 * median RTT`）を維持することで、Wi-Fi/cellular drift により classifier が機能しなくなるのを防ぐ。<sup>[[1]](#references)</sup>

## Location inference from delivery RTT

同じ timing primitive を、recipient が active かどうかだけでなく、recipient の location を推測するためにも転用できる。`Hope of Delivery` research は、既知の receiver location における RTT distribution で training すると、delivery confirmation だけから後に victim の location を分類できることを示した。<sup>[[2]](#references)</sup>

* target が複数の既知の場所（home、office、campus、country A と country B など）にいる間、同じ target の baseline を構築する。
* 各 location について、多数の通常 message RTT を収集し、median、variance、percentile bucket などの単純な feature を抽出する。
* 実際の attack では、新しい probe series を training 済みの cluster と比較する。paper では、同じ city 内の location であっても分離できることが多く、3-location setting で `>80%` の accuracy が得られたと報告している。
* 測定された path には recipient の access network、wake-up latency、messenger infrastructure が含まれるため、attacker が sender environment を control し、同様の network condition で probe する場合に最も効果的である。<sup>[[2]](#references)</sup>

上記の silent reaction/edit/delete attack とは異なり、location inference では invalid message ID や stealthy な state-changing packet は必要ない。通常の delivery confirmation を伴う plain message だけで十分である。そのため stealth は低下するが、messenger をまたいだ applicability は広くなる。

## Stealthy resource exhaustion

すべての silent probe は decrypt と acknowledge が必要であるため、reaction toggle、invalid edit、Delete for everyone packet を継続的に送信すると application-layer DoS が発生する。<sup>[[1]](#references)</sup>

* radio/modem に毎秒 transmit/receive を強制する → 特に idle handset で、目立つ battery drain が発生する。
* unmetered な upstream/downstream traffic を生成し、TLS/WebSocket noise に紛れながら mobile data plan を消費する。
* crypto thread を占有し、user に notification が表示されない場合でも、latency-sensitive feature（VoIP、video call）に jitter を発生させる。
* WhatsApp では、invalid reaction は通常の emoji から想像されるよりはるかに多くの data を受け付ける。公開された measurement では、reaction あたり約 `1 MB` まで server-side で受け付けられた。
* reaction body が約 `30 bytes` を超えると oversized reaction は reliable な delivery receipt を生成しなくなるが、discard 前に転送・処理はされる。ACK が必要な場合は reaction body を小さく保ち、純粋な drain または covert one-way transport が目的の場合のみ inflate する。
* 公開 measurement では、この mode で victim traffic が約 `3.7 MB/s`（`~13.3 GB/h`）に達した。

## References

- [1] [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [How to block high volumes of unknown messages | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Large-scale Abuse of Contact Discovery in Mobile Messengers](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
