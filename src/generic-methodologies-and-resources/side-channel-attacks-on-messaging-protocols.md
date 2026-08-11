# E2EE Messengerにおける配信確認サイドチャネル攻撃

{{#include ../banners/hacktricks-training.md}}

現代のエンドツーエンド暗号化（E2EE）Messengerでは、クライアントが暗号文の復号時刻を把握し、ratcheting stateやephemeral keysを破棄できるようにするため、配信確認は必須です。サーバーはopaque blobsを転送するだけなので、デバイスのacknowledgement（ダブルチェックマーク）は、受信者が復号に成功した後に送信されます。攻撃者がトリガーしたアクションと、それに対応する配信確認との間のround-trip time（RTT）を測定すると、高解像度のタイミングチャネルが明らかになり、デバイスの状態、online presenceがleakします。また、covert DoSにも悪用できます。Multi-deviceの「client-fanout」構成では、登録されたすべてのデバイスがprobeを復号してそれぞれのreceiptを返すため、leakが増幅されます。<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

常に配信確認を生成する一方で、被害者側にUI artifactsを表示しないメッセージタイプを選択します。以下の表は、実測で確認された動作をまとめたものです。<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 常にnoisy → stateのbootstrapにのみ有用。 |
| | Reaction | ● | ◐（被害者のメッセージに反応した場合のみ） | Self-reactionsとremovalsはsilentのまま。 |
| | Edit | ● | Platform-dependent silent push | Edit windowは約20分。期限後もackされる。 |
| | Delete for everyone | ● | ○ | UIでは約60時間可能だが、後続packetもackされる。 |
| **Signal** | Text message | ● | ● | WhatsAppと同じ制限。 |
| | Reaction | ● | ◐ | Self-reactionsは被害者に表示されない。 |
| | Edit/Delete | ● | ○ | Serverは約48時間のwindowを適用し、最大10回のeditを許可するが、遅れて到着したpacketもackされる。 |
| **Threema** | Text message | ● | ● | Multi-deviceのreceiptsは集約されるため、probeごとに表示されるRTTは1つだけ。 |

凡例: ● = 常に、◐ = 条件付き、○ = なし。Platform-dependentなUI動作は行内に記載しています。必要に応じてread receiptsを無効化できますが、WhatsAppまたはSignalではdelivery receiptsを無効化できません。<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** probeごとに到着するreceipt数を数え、RTTをcluster化してOS/client（Android対iOS対desktop）を推測し、online/offlineの遷移を監視します。
* **G2 – Behavioural monitoring:** 高頻度のRTT series（約1 Hzが安定）をtime-seriesとして扱い、screenのon/off、appのforeground/background、通勤時間と勤務時間などを推測します。
* **G3 – Resource exhaustion:** 終わりのないsilent probeを送信して、被害者のすべてのデバイスのradio/CPUを起動状態に保ち、battery/dataを消耗させ、video-callの品質を低下させます。<sup>[[1]](#references)</sup>

abuse surfaceを説明するには、2つのthreat actorで十分です。<sup>[[1]](#references)</sup>

1. **Creepy companion:** すでに被害者とchatを共有しており、self-reactions、reaction removals、または既存のmessage IDに紐づくrepeated edits/deletesを悪用します。
2. **Spooky stranger:** burner accountを登録し、local conversationに存在しないmessage IDを参照するreactionを送信します。WhatsAppとSignalは、UIがstate changeを破棄する場合でもそれらを復号してackするため、事前のconversationは必要ありません。

## Tooling for raw protocol access

UIの制約外でsupported packetsを作成し、正確なtimestampをlogできるだけのunderlying E2EE protocolを公開しているclientに依存します。arbitrary message IDについては各implementationの確認が必要です。

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)（Go、WhatsApp Web multidevice API）はdelivery receiptsの送受信を文書化しています。[Cobalt](https://github.com/Auties00/Cobalt)（unofficial Java/Kotlin Webおよびmobile API）は、react、edit、deleteなどのmessage operationsを文書化しています。すべてのinternal frameが公開されていると仮定せず、文書化されたAPIを使用してください。<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)はCLI、JSON-RPC、D-Bus interfacesを公開し、[libsignal-service-java](https://github.com/signalapp/libsignal-service-java)はSignalとの通信に使用するJava libraryです。<sup>[[5]](#references)[[7]](#references)</sup> 現在の`signal-cli` syntaxでは`sendReaction RECIPIENT --target-author --target-timestamp`を使用します。protocol updatesの処理を継続するため、`receive`または`daemon`を実行し続けてください。<sup>[[6]](#references)</sup> Self-reaction toggleの例:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paperの測定では、delivery receiptsがデバイス間でsynchronizeされるため、multi-device構成でもmessageごとに公開されるreceiptは1つだけであることが確認されました。<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)はWhatsApp/Signal backendsを備え、silent delete probesをdefaultとし、rolling-median threshold（`RTT < 0.9 * median`）で`active`と`standby`を区別します。<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)は、`--delay`、`--concurrent`、CSV/Prometheus exporters、Grafana向けoutputを備えた、より軽量なWhatsApp-first CLIです。<sup>[[9]](#references)</sup> どちらもprotocol referencesではなくreconnaissance helpersとして扱ってください。重要な点は、raw client accessが存在すれば、必要なcodeがいかに少ないかということです。

custom toolingが利用できない場合でも、official clientsまたはbrowser developer toolsを使用してsilent actionsをトリガーし、encrypted trafficのtimingを確認できます。raw APIsを使えばUI delaysを取り除き、invalid operationsを実行できます。<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. 自分がchat内で作成した過去のmessageを任意に選びます。これにより、被害者側では「reaction」balloonの変更が表示されません。
2. visible emojiとempty reaction payload（WhatsApp protobufsでは`""`、signal-cliでは`--remove`としてencode）を交互に送信します。各transmissionは、被害者側にUI deltaがないにもかかわらずdevice ackを生成します。
3. send timeと各delivery receiptのarrivalをtimestampとして記録します。以下のような1 Hz loopにより、deviceごとのRTT tracesを無期限に取得できます。
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signalはunlimited reaction updatesを受け入れるため、攻撃者は新しいchat contentを投稿する必要も、edit windowsを気にする必要もありません。<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. 新しいWhatsApp/Signal accountを登録し、target numberのpublic identity keysを取得します（session setup中に自動的に実行されます）。
2. どちらのpartyにも一度も見られていないrandomな`message_id`を参照するreaction packetを作成します。paperでは、WhatsAppとSignalの両方がこのようなreactionを受け入れ、delivery receiptsも生成することが報告されています。<sup>[[1]](#references)</sup>
3. threadが存在しなくてもpacketを送信します。被害者のデバイスはそれを復号し、base messageとの一致に失敗してstate changeを破棄しますが、incoming ciphertextはackし、device receiptsを攻撃者へ返します。
4. これを継続的に繰り返し、事前のconversationやvisible notificationなしでRTT seriesを構築します。<sup>[[1]](#references)</sup>

登録済みのnumberを先にdiscoverする必要がある場合や、scaleでdevice inventoriesをpre-seedしたい場合は、randomなE.164 rangesを手作業で推測するのではなく、[contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)とchainしてください。

公開されたcontact-discovery workは、これがoperationalに重要である理由を示しています。正確なphone-prefix tablesと適度なresourcesにより、研究者はtargeted probingに移る前に、WhatsAppでは米国mobile numbersの約`10%`、Signalでは`100%`をqueryできました。<sup>[[11]](#references)</sup> 実際には、まずlive accountsをpre-filterすることで、silent-probe budgetを実際にpacketを復号するnumberへ集中できます。

最近のWhatsApp buildsでは、`Settings -> Privacy -> Advanced -> Block unknown account messages`も公開されています。<sup>[[10]](#references)</sup> これはthroughput limiterとして扱ってください。tracker documentationによると、WhatsAppはunknown accountsからのhigh-volume messagesをblockしますが、thresholdは公開していないため、probe reactionsを完全に防ぐものではありません。<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** あるmessageが一度Delete for everyoneされると、同じ`message_id`を参照する後続のdelete packetsはUI effectを持ちませんが、すべてのデバイスが引き続きそれらを復号してackします。
* **Out-of-window operations:** WhatsAppはUI上で約60時間のdelete / 約20分のedit windowsを適用し、Signalは約48時間を適用します。これらのwindow外で作成されたprotocol messagesは、被害者のdevice上ではsilentにignoreされますが、receiptsは送信されるため、conversationが終了してから長時間経過した後も無期限にprobeできます。
* **Invalid payloads:** paperでは、invalid messagesもackされる可能性が報告されています。malformed bodiesまたはpurged IDsの正確な動作はimplementation-dependentであるため、依存する前にtestしてください。<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsAppとSignalでは、各associated device（phone、desktop app、browser companion）がprobeを独立して復号し、それぞれのackを返します。probeごとのreceipt数を数えることで、正確なdevice countが明らかになります。<sup>[[1]](#references)</sup>
* deviceがofflineの場合、そのreceiptはqueueされ、reconnection時に送信されます。そのため、gapからonline/offline cyclesやcommuting schedules（例: desktop receiptsが移動中に停止する）がleakします。
* RTT distributionsはplatformとenvironmentによって異なります。これはOS、model、client、network conditionsがtimingに影響するためです。RTTをcluster化し、median/variance featuresに対してk-meansなどを適用して、「Android handset」「iOS handset」「Electron desktop」などのlabelを付けます。
* senderはencryptingの前にrecipientのkey inventoryを取得する必要があるため、攻撃者は新しいdeviceがpairedされた時期も監視できます。device countの突然の増加や新しいRTT clusterは、強いindicatorです。<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 公開された測定では、WhatsAppは明らかなserver-side queueingなしに、1 probe every `50 ms`という速さのsilent-reaction burstsを受け入れました。これはshort calibration bursts、fast device counting、またはdrain attackを素早く開始する用途に有用です。
* **Signal long-run queueing:** Signalはshort burstsには耐えましたが、sustained multi-probe-per-second trafficではqueueingが発生し始めました。長期monitoringではcadenceを約`1 Hz`（またはそれ以下）に保ち、各receiptがbacklog drainではなく現在のdevice stateを反映するようにします。
* **Reconnect artefacts:** deviceがonlineに戻ると、一部のclientsは遅延した複数のreceiptsをbatch処理または急速にflushします。これらのreceipt burstsは独立したRTT samplesではなくstate-transition markerとして扱ってください。そうしないと、clustering / `active`対`idle` classifierがreconnect noiseにoverfitします。<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effectsを捉えるため、≥1 Hzでsampleします。iOS上のWhatsAppでは、1秒未満のRTTはscreen-on/foregroundと強く相関し、1秒超はscreen-off/background throttlingと相関します。
2. 各RTTを`active`または`idle`としてlabel付けするsimple classifiers（thresholdingまたはtwo-cluster k-means）を構築します。labelをstreaksにaggregateして、就寝時刻、通勤時間、勤務時間、またはdesktop companionがactiveな時間を導出します。
3. すべてのdeviceへの同時probeをcorrelateし、ユーザーがmobileからdesktopへ切り替える時刻、companionsがofflineになる時刻、appがpushとpersistent socketのどちらでrate limitedされているかを確認します。
4. 実際のnetworkでは、単一の固定`1 s` thresholdを避けます。各deviceを短いwarm-up windowでbootstrapし、rolling baselineを維持します（例えばdevice-activity-tracker PoCは`threshold = 0.9 * median RTT`を使用します）。これにより、Wi-Fi/cellular driftによってclassifierが機能しなくなるのを防ぎます。<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

同じtiming primitiveを、recipientがactiveかどうかだけでなく、recipientの位置の推測にも利用できます。`Hope of Delivery` workでは、既知のreceiver locationsにおけるRTT distributionsでtrainingすることで、攻撃者が後からdelivery confirmationsだけを使って被害者のlocationをclassifyできることが示されました。<sup>[[2]](#references)</sup>

* targetが複数の既知の場所（home、office、campus、country A対country Bなど）にいる間に、同じtargetのbaselineを構築します。
* 各locationについて、多数の通常message RTTsを収集し、median、variance、percentile bucketsなどのsimple featuresを抽出します。
* 実際のattack中に、新しいprobe seriesをtrained clustersと比較します。paperでは、同じcity内のlocationsでも区別できる場合が多く、3-location settingで`>80%`のaccuracyが報告されています。
* 測定されたpathにはrecipient access network、wake-up latency、messenger infrastructureが含まれるため、attackerがsender environmentを管理し、同様のnetwork conditionsでprobeする場合に最も効果的です。<sup>[[2]](#references)</sup>

上記のsilent reaction/edit/delete attacksとは異なり、location inferenceにはinvalid message IDsやstealthy state-changing packetsは必要ありません。通常のdelivery confirmationsを伴うplain messagesで十分です。そのため、stealthは低くなりますが、messengers全体でより広く適用できます。

## Stealthy resource exhaustion

すべてのsilent probeは復号およびackされる必要があるため、reaction toggles、invalid edits、またはdelete-for-everyone packetsを継続的に送信すると、application-layer DoSが発生します。<sup>[[1]](#references)</sup>

* 毎秒radio/modemに送受信を強制する → 特にidle handsetsで、明らかなbattery drainが発生します。
* upstream/downstream trafficを生成してmobile data plansを消費し、video callsなどlatency-sensitive featuresと競合する可能性があります。<sup>[[1]](#references)</sup>
* large invalid payloadsはprocessing workを増加させますが、paperではcryptography自体のbattery costはnegligibleであると報告されています。<sup>[[1]](#references)</sup>
* WhatsAppでは、invalid reactionsは通常のemojiから想定されるよりはるかに多くのdataを受け入れます。公開された測定では、server-side acceptanceはreactionあたりおよそ`1 MB`まで達しました。
* oversized reactionsは、bodyが約`30 bytes`を超えると信頼できるdelivery receiptsを生成しなくなりますが、discardされる前にforwardおよびprocessされます。ACKが必要な場合はreaction bodiesを小さく保ち、純粋なdrainまたはcovert one-way transportが目的の場合のみinflateしてください。
* 公開された測定では、このmodeで被害者trafficが約`3.7 MB/s`（`~13.3 GB/h`）に達しました。

## References

- [1] [Careless Whisper: Silent Delivery Receiptsを悪用したMobile Instant Messengers上のユーザー監視](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Mobile Instant MessengersからのユーザーLocation抽出](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Unknown messagesの大量送信をblockする方法 | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Mobile MessengersにおけるContact Discoveryの大規模な悪用](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
