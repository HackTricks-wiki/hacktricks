# E2EE MessengerにおけるDelivery Receipt Side-Channel Attacks

Delivery receiptsは、現代のend-to-end encrypted (E2EE) messengerでは必須です。クライアントはciphertextがいつ復号されたかを把握し、ratcheting stateとephemeral keysを破棄する必要があるためです。サーバーはopaque blobを転送するだけなので、device acknowledgement（double checkmarks）は復号に成功したrecipientによって送信されます。攻撃者が誘発したアクションから対応するdelivery receiptまでのround-trip time (RTT)を測定すると、高解像度のtiming channelが得られ、device stateやonline presenceがleakします。また、covert DoSにも悪用できます。Multi-deviceの「client-fanout」構成では、登録されたすべてのdeviceがprobeを復号してそれぞれのreceiptを返すため、leakageが増幅されます。<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

victimのUIに痕跡を表示せず、常にdelivery receiptを生成するmessage typeを選択します。以下の表は、実測で確認された動作をまとめたものです。<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常に目立つため、stateのbootstrapにのみ有用。 |
| | Reaction | ● | ◐ (victimのmessageにreactした場合のみ) | Self-reactionとremovalは無音のまま。 |
| | Edit | ● | Platform-dependent silent push | Edit windowは約20分。期限後もackされる。 |
| | Delete for everyone | ● | ○ | UIでは約60時間だが、後続packetもackされる。 |
| **Signal** | Text message | ● | ● | WhatsAppと同じ制限。 |
| | Reaction | ● | ◐ | Self-reactionはvictimから見えない。 |
| | Edit/Delete | ● | ○ | サーバーは約48時間のwindowを強制し、最大10回のeditを許可するが、遅延packetもackされる。 |
| **Threema** | Text message | ● | ● | Multi-deviceのreceiptはaggregateされるため、probeごとに見えるRTTは1つだけ。 |

凡例: ● = 常に、◐ = 条件付き、○ = なし。Platform-dependentなUI動作は本文中に記載しています。必要に応じてread receiptsを無効化できますが、WhatsAppまたはSignalではdelivery receiptsを無効化できません。<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** probeごとに到着するreceipt数を数え、RTTをcluster化してOS/client（Android、iOS、desktopなど）を推測し、online/offlineの切り替わりを監視する。
* **G2 – Behavioural monitoring:** 高頻度のRTT系列（約1 Hzが安定）をtime-seriesとして扱い、screenのon/off、appのforeground/background、通勤時間と勤務時間などを推測する。
* **G3 – Resource exhaustion:** 終わりのないsilent probeを送信して、victimのすべてのdeviceのradio/CPUを起動状態に保ち、battery/dataを消費させ、video-callの品質を低下させる。<sup>[[1]](#references)</sup>

悪用範囲を説明するには、2種類のthreat actorで十分です。<sup>[[1]](#references)</sup>

1. **Creepy companion:** すでにvictimとchatを共有しており、self-reaction、reaction removal、または既存のmessage IDに紐づく繰り返しのedit/deleteを悪用する。
2. **Spooky stranger:** burner accountを登録し、local conversationに存在しないmessage IDを参照するreactionを送信する。WhatsAppとSignalは、UIがstate changeを破棄する場合でも復号してackするため、事前のconversationは必要ありません。

## Tooling for raw protocol access

UIの制約外でサポートされたpacketを作成し、正確なtimestampを記録できる、基盤となるE2EE protocolを十分に公開しているclientを使用します。任意のmessage IDに対応しているかは各実装で確認する必要があります。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go、WhatsApp Web multidevice API）はdelivery receiptの送受信を文書化しています。[Cobalt](https://github.com/Auties00/Cobalt)（非公式のJava/Kotlin Webおよびmobile API）は、react、edit、deleteなどのmessage operationを文書化しています。すべてのinternal frameが公開されていると仮定せず、文書化されたAPIを使用してください。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)はCLI、JSON-RPC、D-Bus interfaceを公開し、[libsignal-service-java](https://github.com/signalapp/libsignal-service-java)はSignalとの通信に使用するJava libraryです。<sup>[[5]](#references)[[7]](#references)</sup> 現在の`signal-cli` syntaxでは`sendReaction RECIPIENT --target-author --target-timestamp`を使用します。protocol updateの処理を継続するため、`receive`または`daemon`を実行したままにしてください。<sup>[[6]](#references)</sup> Self-reaction toggleの例:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paperの測定では、delivery receiptはdevice間でsynchronizeされるため、multi-device setupでもmessageごとに公開されるreceiptは1つだけでした。<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)はWhatsApp/Signal backendを提供し、silent delete probeをdefaultに設定し、rolling-median threshold（`RTT < 0.9 * median`）で`active`と`standby`を分類します。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)は、`--delay`、`--concurrent`、CSV/Prometheus exporter、Grafana向けoutputを備えた、より軽量なWhatsApp-first CLIです。<sup>[[9]](#references)</sup> これらはprotocol referenceではなくreconnaissance helperとして扱ってください。重要な点は、raw client accessがあれば必要なcodeが非常に少ないことです。

custom toolingを利用できない場合でも、official clientまたはbrowser developer toolsでsilent actionをtriggerし、encrypted trafficのtimingを確認できます。raw APIを使えばUI delayを排除し、invalid operationを実行できます。<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. chat内で自分が作成した過去のmessageを選びます。これにより、victimには「reaction」balloonの変化が表示されません。
2. visibleなemojiと空のreaction payload（WhatsApp protobufでは`""`、signal-cliでは`--remove`としてencode）を交互に送信します。victim側でUI deltaがなくても、各送信はdevice ackを生成します。
3. send timeと、すべてのdelivery receiptの到着時刻をtimestamp記録します。以下のような1 Hz loopにより、deviceごとのRTT traceを無期限に取得できます。
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signalはreaction updateを無制限に受け入れるため、攻撃者は新しいchat contentを投稿したり、edit windowを気にしたりする必要がありません。<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. 新しいWhatsApp/Signal accountを登録し、target numberのpublic identity keyを取得します（session setup中に自動的に実行されます）。
2. どちらのpartyにも存在しないrandomな`message_id`を参照するreaction packetを作成します。paperでは、WhatsAppとSignalの両方がこのようなreactionを受け入れ、delivery receiptも生成すると報告されています。<sup>[[1]](#references)</sup>
3. threadが存在しなくてもpacketを送信します。victimのdeviceはそれを復号し、base messageとのmatchに失敗してstate changeを破棄しますが、incoming ciphertextはackするため、device receiptを攻撃者へ返します。
4. 事前のconversationやvisible notificationなしでRTT系列を構築するため、これを継続的に繰り返します。<sup>[[1]](#references)</sup>

登録済みのnumberを先に発見する必要がある場合、または大規模にdevice inventoryを事前投入したい場合は、randomなE.164 rangeを手作業で推測するのではなく、[contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)とchainしてください。

公開されたcontact-discovery researchは、これが運用上重要な理由を示しています。正確なphone-prefix tableと少量のresourceにより、researcherはtargeted probingに移る前に、WhatsAppでは米国mobile numberの約`10%`、Signalでは`100%`をqueryできました。<sup>[[11]](#references)</sup> 実際には、まずlive accountをpre-filterすることで、silent-probe budgetを実際にpacketを復号するnumberに集中できます。

最近のWhatsApp buildでは、`Settings -> Privacy -> Advanced -> Block unknown account messages`も公開されています。<sup>[[10]](#references)</sup> これはthroughput limiterとして扱ってください。tracker documentationによると、WhatsAppはunknown accountからのhigh-volume messageをblockしますが、thresholdは公開していないため、probe reactionを完全に防ぐことはできません。<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** messageが一度Delete for everyoneされると、同じ`message_id`を参照する後続のdelete packetはUIに影響を与えませんが、すべてのdeviceが引き続き復号してackします。
* **Out-of-window operations:** WhatsAppはUIで約60時間のdelete windowと約20分のedit windowを強制し、Signalは約48時間を強制します。これらのwindow外で作成されたprotocol messageはvictim device上でsilentに無視されますが、receiptは送信されるため、conversation終了後も無期限にprobeできます。
* **Invalid payloads:** paperでは、invalid messageもackされる可能性があると報告されています。malformed bodyまたはpurged IDの正確な動作は実装依存のため、依存する前にテストしてください。<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsAppとSignalでは、関連付けられた各device（phone、desktop app、browser companion）がprobeを個別に復号し、それぞれ独自のackを返します。probeごとのreceipt数を数えることで、正確なdevice数が分かります。<sup>[[1]](#references)</sup>
* deviceがofflineの場合、そのreceiptはqueueに入り、reconnection時に送信されます。そのため、空白期間からonline/offline cycleや通勤scheduleまでleakします（例: desktop receiptは移動中に停止する）。
* RTT distributionはplatformとenvironmentによって異なります。OS、model、client、network conditionがtimingに影響するためです。RTTをcluster化し（例: median/variance featureに対するk-means）、“Android handset”、“iOS handset”、“Electron desktop”などのlabelを付けます。
* senderは暗号化前にrecipientのkey inventoryを取得する必要があるため、攻撃者は新しいdeviceがpairされた時期も監視できます。device数の突然の増加や新しいRTT clusterは強いindicatorです。<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 公開測定では、WhatsAppは明らかなserver-side queueingなしに、最短`50 ms`ごとのsilent-reaction burstを受け入れました。これは短いcalibration burst、迅速なdevice count、またはdrain attackの急速な開始に有用です。
* **Signal long-run queueing:** Signalは短いburstには耐えましたが、持続的なmulti-probe-per-second trafficではqueueingが始まりました。長時間のmonitoringではcadenceを約`1 Hz`（またはそれ以下）に保ち、各receiptがbacklog drainではなく現在のdevice stateを反映するようにします。
* **Reconnect artefacts:** deviceがonlineに戻ると、一部のclientは遅延したreceiptをbatch処理したり、急速にflushしたりします。これらのreceipt burstは独立したRTT sampleではなくstate-transition markerとして扱ってください。そうしないと、clusteringや`active`対`idle` classifierがreconnect noiseにoverfitします。<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effectを捉えるため、≥1 Hzでsampleします。iOS上のWhatsAppでは、1秒未満のRTTはscreen-on/foregroundと強く相関し、1秒超はscreen-off/background throttlingと相関します。
2. 単純なclassifier（thresholdingまたはtwo-cluster k-means）を構築し、各RTTを`active`または`idle`としてlabel付けします。labelをstreakに集約して、就寝時刻、通勤、勤務時間、desktop companionがactiveな時間などを導出します。
3. すべてのdeviceに対する同時probeを相関させ、userがmobileからdesktopへ切り替えた時期、companionがofflineになった時期、appがpushとpersistent socketのどちらによってrate limitされているかを確認します。
4. 実際のnetworkでは、単一のhardcodedな`1 s` thresholdを避けます。各deviceを短いwarm-up windowでbootstrapし、rolling baselineを維持します（例えばdevice-activity-tracker PoCは`threshold = 0.9 * median RTT`を使用します）。これにより、Wi-Fi/cellular driftでclassifierが機能しなくなるのを防げます。<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

同じtiming primitiveを再利用して、recipientがactiveかどうかだけでなく、どこにいるかも推測できます。`Hope of Delivery` researchでは、既知のreceiver locationにおけるRTT distributionでtrainingすると、後からdelivery confirmationだけでvictimのlocationを分類できることが示されています。<sup>[[2]](#references)</sup>

* 同じtargetについて、複数の既知の場所（home、office、campus、country Aとcountry Bなど）にいる間のbaselineを構築します。
* 各locationで通常のmessage RTTを多数収集し、median、variance、percentile bucketなどの単純なfeatureを抽出します。
* 実際のattack中に、新しいprobe seriesをtrained clusterと比較します。paperでは、同じcity内のlocationでも分離できることが多く、3-location settingで`>80%`のaccuracyが報告されています。
* 測定されたpathにはrecipientのaccess network、wake-up latency、messenger infrastructureが含まれるため、attackerがsender environmentを制御し、類似したnetwork conditionでprobeすると最も効果的です。<sup>[[2]](#references)</sup>

上記のsilent reaction/edit/delete attackとは異なり、location inferenceにはinvalid message IDやstealthyなstate-changing packetは必要ありません。通常のdelivery confirmationを伴うplain messageだけで十分です。そのためstealthは低下しますが、messengerを問わず幅広く適用できます。

## Stealthy resource exhaustion

すべてのsilent probeは復号してackする必要があるため、reaction toggle、invalid edit、Delete for everyone packetを継続的に送信すると、application-layer DoSが発生します。<sup>[[1]](#references)</sup>

* radio/modemに毎秒transmit/receiveを強制するため、特にidle handsetではbattery drainが目立ちます。
* upstream/downstream trafficを生成し、mobile data planを消費するとともに、video callなどlatency-sensitiveなfeatureと競合する可能性があります。<sup>[[1]](#references)</sup>
* 大きなinvalid payloadはprocessing workを増加させますが、paperではcryptography自体のbattery costは無視できる程度と報告されています。<sup>[[1]](#references)</sup>
* WhatsAppでは、invalid reactionは通常のemojiから想定されるよりはるかに多くのdataを受け入れます。公開測定では、server-sideでreactionあたり約`1 MB`まで受け入れられました。
* reaction bodyが約`30 bytes`を超えると、oversized reactionは信頼できるdelivery receiptを生成しなくなりますが、discard前に転送および処理されます。ACKが必要な場合はreaction bodyを小さく保ち、純粋なdrainまたはcovert one-way transportが目的の場合のみ大きくします。
* 公開測定では、このmodeで約`3.7 MB/s`（`~13.3 GB/h`）のvictim trafficに達しました。

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
