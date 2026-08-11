# E2EE Messenger의 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

현대의 종단간 암호화(E2EE) messenger에서는 클라이언트가 ciphertext가 언제 decrypt되었는지 알아야 ratcheting state와 ephemeral keys를 폐기할 수 있으므로 delivery receipt가 필수적입니다. 서버는 opaque blob을 전달할 뿐이며, device acknowledgement(이중 체크 표시)는 성공적으로 decrypt한 수신자가 전송합니다. 공격자가 유발한 동작과 해당 delivery receipt 사이의 round-trip time(RTT)을 측정하면 device state, online presence를 leak하는 고해상도 timing channel이 노출되며, 은밀한 DoS에도 악용될 수 있습니다. Multi-device "client-fanout" deployment에서는 등록된 모든 device가 probe를 decrypt하고 각자의 receipt를 반환하므로 leak가 증폭됩니다.<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

항상 delivery receipt를 생성하지만 victim의 UI에는 흔적을 표시하지 않는 message type을 선택합니다. 아래 표는 실증적으로 확인된 동작을 요약합니다:<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noise가 발생하므로 state를 bootstrap할 때만 유용합니다. |
| | Reaction | ● | ◐ (victim message에 반응한 경우에만) | Self-reaction과 removal은 조용히 처리됩니다. |
| | Edit | ● | Platform-dependent silent push | Edit window는 약 20분이며, 만료 후에도 ack됩니다. |
| | Delete for everyone | ● | ○ | UI에서는 약 60시간을 허용하지만, 이후 packet도 ack됩니다. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한이 있습니다. |
| | Reaction | ● | ◐ | Self-reaction은 victim에게 표시되지 않습니다. |
| | Edit/Delete | ● | ○ | 서버는 약 48시간 window를 적용하고 최대 10회의 edit를 허용하지만, 늦게 도착한 packet도 ack됩니다. |
| **Threema** | Text message | ● | ● | Multi-device receipt가 aggregate되므로 probe마다 하나의 RTT만 표시됩니다. |

범례: ● = 항상, ◐ = 조건부, ○ = 없음. Platform-dependent UI 동작은 각 항목에 표시했습니다. 필요한 경우 read receipt를 비활성화할 수 있지만, WhatsApp이나 Signal에서는 delivery receipt를 끌 수 없습니다.<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** Probe마다 도착하는 receipt 수를 세고 RTT를 cluster하여 OS/client(Android와 iOS 및 desktop)를 추론하며 online/offline 전환을 관찰합니다.
* **G2 – Behavioural monitoring:** 고주파 RTT series(약 1 Hz가 안정적)를 time-series로 취급하여 screen on/off, app foreground/background, 통근 시간과 근무 시간 등을 추론합니다.
* **G3 – Resource exhaustion:** 끝나지 않는 silent probe를 보내 모든 victim device의 radio/CPU를 계속 활성 상태로 유지하고, battery/data를 소모하며 video-call quality를 저하시킵니다.<sup>[[1]](#references)</sup>

악용 범위를 설명하는 데는 두 가지 threat actor면 충분합니다:<sup>[[1]](#references)</sup>

1. **Creepy companion:** 이미 victim과 chat을 공유하며 self-reaction, reaction removal 또는 기존 message ID에 연결된 반복적인 edit/delete를 악용합니다.
2. **Spooky stranger:** burner account를 등록하고 local conversation에 존재하지 않았던 message ID를 참조하는 reaction을 전송합니다. WhatsApp과 Signal은 UI에서 state change를 폐기하더라도 이를 decrypt하고 acknowledge하므로 사전 conversation이 필요하지 않습니다.

## Tooling for raw protocol access

UI 제약을 벗어나 지원되는 packet을 작성하고 정확한 timestamp를 log할 수 있을 만큼 underlying E2EE protocol을 노출하는 client를 사용합니다. 임의의 message ID 지원 여부는 각 implementation에서 확인해야 합니다.

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)(Go 기반 WhatsApp Web multidevice API)는 delivery receipt의 송수신을 문서화하고, [Cobalt](https://github.com/Auties00/Cobalt)(비공식 Java/Kotlin Web 및 mobile API)는 reaction, edit, delete와 같은 message operation을 문서화합니다. 모든 internal frame이 노출된다고 가정하지 말고 문서화된 API를 사용합니다.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)는 CLI, JSON-RPC 및 D-Bus interface를 제공하며, [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)는 Signal과 통신하기 위한 Java library입니다.<sup>[[5]](#references)[[7]](#references)</sup> 현재 `signal-cli` syntax는 `sendReaction RECIPIENT --target-author --target-timestamp`를 사용합니다. Protocol update가 계속 처리되도록 `receive` 또는 `daemon`을 실행 상태로 유지합니다.<sup>[[6]](#references)</sup> Self-reaction toggle 예시:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paper의 측정 결과, delivery receipt는 device 간에 synchronize되므로 multi-device setup에서도 message당 하나의 receipt만 노출됩니다.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal backend를 제공하고 기본값으로 silent delete probe를 사용하며, rolling-median threshold(`RTT < 0.9 * median`)로 `active`와 `standby`를 구분합니다.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)는 `--delay`, `--concurrent`, CSV/Prometheus exporter 및 Grafana 친화적 output을 제공하는 더 가벼운 WhatsApp-first CLI입니다.<sup>[[9]](#references)</sup> 두 도구 모두 protocol reference가 아닌 reconnaissance helper로 취급해야 합니다. 중요한 점은 raw client access가 확보된 후에는 필요한 code가 매우 적다는 것입니다.

Custom tooling을 사용할 수 없는 경우에도 official client 또는 browser developer tools로 silent action을 trigger하고 encrypted traffic timing을 확인할 수 있습니다. Raw API를 사용하면 UI delay를 제거하고 invalid operation을 수행할 수 있습니다.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. 자신이 chat에서 작성한 과거 message를 선택하여 victim에게 "reaction" balloon의 변화가 표시되지 않도록 합니다.
2. visible emoji와 empty reaction payload를 번갈아 전송합니다(WhatsApp protobuf에서는 `""`, signal-cli에서는 `--remove`로 encode). 각 transmission은 victim의 UI delta가 없어도 device ack를 생성합니다.
3. Send time과 모든 delivery receipt 도착 시각을 timestamp로 기록합니다. 다음과 같은 1 Hz loop를 사용하면 device별 RTT trace를 무기한 수집할 수 있습니다.
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal은 reaction update를 제한 없이 허용하므로 공격자는 새로운 chat content를 게시하거나 edit window를 걱정할 필요가 없습니다.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. 새 WhatsApp/Signal account를 등록하고 target number의 public identity key를 가져옵니다(session setup 중 자동으로 수행됨).
2. 어느 쪽도 본 적 없는 random `message_id`를 참조하는 reaction packet을 작성합니다. 해당 paper는 WhatsApp과 Signal 모두 이러한 reaction을 accept하고 delivery receipt를 생성한다고 보고합니다.<sup>[[1]](#references)</sup>
3. Thread가 존재하지 않더라도 packet을 전송합니다. Victim device는 이를 decrypt하고 base message를 찾지 못해 state change를 폐기하지만, 수신한 ciphertext는 acknowledge하여 device receipt를 공격자에게 반환합니다.
4. 사전 conversation이나 visible notification 없이 RTT series를 구축할 수 있도록 계속 반복합니다.<sup>[[1]](#references)</sup>

어떤 number가 등록되어 있는지 먼저 확인해야 하거나, 대규모로 device inventory를 미리 구축하려는 경우에는 임의의 E.164 range를 수동으로 추측하는 대신 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 연계합니다.

공개된 contact-discovery 연구는 이것이 운영상 중요한 이유를 보여주었습니다. 정확한 phone-prefix table과 적당한 resource를 사용하여 연구자들은 targeted probing으로 넘어가기 전에 WhatsApp에서는 미국 mobile number의 약 `10%`, Signal에서는 `100%`를 query할 수 있었습니다.<sup>[[11]](#references)</sup> 실제로 live account를 먼저 pre-filter하면 실제로 packet을 decrypt할 number에 silent-probe budget을 집중할 수 있습니다.

최근 WhatsApp build는 `Settings -> Privacy -> Advanced -> Block unknown account messages`도 제공합니다.<sup>[[10]](#references)</sup> 이를 throughput limiter로 취급해야 합니다. Tracker documentation에 따르면 WhatsApp은 unknown account에서 오는 high-volume message를 차단하지만 threshold는 공개하지 않으므로 probe reaction을 완전히 방지하지는 못합니다.<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** Message가 처음으로 everyone에게 delete된 후에도 동일한 `message_id`를 참조하는 추가 delete packet은 UI effect를 발생시키지 않지만 모든 device는 계속 decrypt하고 acknowledge합니다.
* **Out-of-window operations:** WhatsApp은 UI에서 약 60시간의 delete / 약 20분의 edit window를 적용하고, Signal은 약 48시간을 적용합니다. 이러한 window를 벗어난 crafted protocol message는 victim device에서 조용히 무시되지만 receipt는 전송되므로 conversation이 끝난 뒤에도 공격자가 무기한 probe할 수 있습니다.
* **Invalid payloads:** 해당 paper는 invalid message도 acknowledge될 수 있다고 보고합니다. Malformed body 또는 purged ID에 대한 정확한 동작은 implementation-dependent이므로 이에 의존하기 전에 테스트해야 합니다.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsApp과 Signal에서는 연결된 각 device(phone, desktop app, browser companion)가 probe를 독립적으로 decrypt하고 자체 ack를 반환합니다. Probe별 receipt 수를 세면 정확한 device 수를 알 수 있습니다.<sup>[[1]](#references)</sup>
* Device가 offline이면 해당 receipt는 queue에 저장되었다가 재연결 시 전송됩니다. 따라서 gap은 online/offline cycle과 통근 일정까지 leak합니다(예: 이동 중에는 desktop receipt가 중단됨).
* OS, model, client 및 network condition이 timing에 영향을 주므로 RTT distribution은 platform과 environment에 따라 다릅니다. RTT를 cluster하여(예: median/variance feature에 k-means 적용) “Android handset”, “iOS handset”, “Electron desktop” 등으로 label할 수 있습니다.
* Sender는 encrypt하기 전에 recipient의 key inventory를 가져와야 하므로, 공격자는 새 device가 pairing되는 시점도 관찰할 수 있습니다. 갑작스러운 device 수 증가 또는 새로운 RTT cluster는 강력한 indicator입니다.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 공개된 측정에서는 WhatsApp이 명확한 server-side queueing 없이  `50 ms`마다 하나의 probe를 보내는 속도의 silent-reaction burst를 수용했습니다. 이는 짧은 calibration burst, 빠른 device counting 또는 drain attack의 신속한 ramp-up에 유용합니다.
* **Signal long-run queueing:** Signal은 짧은 burst는 허용했지만 sustained multi-probe-per-second traffic에서는 queueing을 시작했습니다. 장시간 monitoring에서는 cadence를 약 `1 Hz`(또는 그 이하)로 유지하여 각 receipt가 backlog drain이 아닌 현재 device state를 반영하도록 합니다.
* **Reconnect artefacts:** Device가 online으로 돌아오면 일부 client는 지연된 receipt를 batch 처리하거나 빠르게 flush합니다. 이러한 receipt burst는 독립적인 RTT sample이 아니라 state-transition marker로 취급해야 합니다. 그렇지 않으면 clustering 또는 `active`와 `idle` classifier가 reconnect noise에 overfit됩니다.<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effect를 capture하기 위해 ≥1 Hz로 sample합니다. WhatsApp을 iOS에서 사용할 때 <1 s RTT는 screen-on/foreground와 강하게 correlation되고, >1 s는 screen-off/background throttling과 correlation됩니다.
2. 각 RTT를 `"active"` 또는 `"idle"`로 label하는 간단한 classifier(thresholding 또는 two-cluster k-means)를 구축합니다. Label을 streak로 aggregate하여 취침 시간, 통근 시간, 근무 시간 또는 desktop companion이 active인 시점을 도출합니다.
3. 모든 device를 대상으로 동시에 probe하여 사용자가 mobile에서 desktop으로 전환하는 시점, companion이 offline이 되는 시점, app이 push와 persistent socket 중 무엇에 의해 rate limit되는지를 확인합니다.
4. 실제 network에서는 하나의 hardcoded `1 s` threshold를 사용하지 않습니다. 짧은 warm-up window로 각 device를 bootstrap하고 rolling baseline을 유지합니다(예를 들어 device-activity-tracker PoC는 `threshold = 0.9 * median RTT`를 사용). 이렇게 해야 Wi-Fi/cellular drift가 classifier를 무너뜨리지 않습니다.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

동일한 timing primitive를 사용하면 recipient가 active인지뿐 아니라 어디에 있는지도 추론할 수 있습니다. `Hope of Delivery` 연구는 알려진 receiver location의 RTT distribution으로 training하면 공격자가 이후 delivery confirmation만으로 victim의 location을 분류할 수 있음을 보여주었습니다:<sup>[[2]](#references)</sup>

* 동일한 target이 여러 known location(home, office, campus, country A와 country B 등)에 있을 때 baseline을 구축합니다.
* 각 location에서 많은 normal message RTT를 수집하고 median, variance 또는 percentile bucket과 같은 간단한 feature를 추출합니다.
* 실제 attack 중에는 새로운 probe series를 trained cluster와 비교합니다. 해당 paper는 동일한 city 내의 location도 종종 구분할 수 있으며, 3-location setting에서 `>80%` accuracy를 달성했다고 보고합니다.
* 측정된 path에는 recipient access network, wake-up latency 및 messenger infrastructure가 포함되므로, 공격자가 sender environment를 제어하고 유사한 network condition에서 probe할 때 가장 효과적입니다.<sup>[[2]](#references)</sup>

위의 silent reaction/edit/delete attack과 달리 location inference에는 invalid message ID나 stealthy state-changing packet이 필요하지 않습니다. Normal delivery confirmation이 포함된 plain message만으로 충분하므로, stealth는 낮아지지만 messenger 전반에 더 폭넓게 적용할 수 있습니다.

## Stealthy resource exhaustion

모든 silent probe는 decrypt되고 acknowledge되어야 하므로 reaction toggle, invalid edit 또는 delete-for-everyone packet을 지속적으로 전송하면 application-layer DoS가 발생합니다:<sup>[[1]](#references)</sup>

* 매초 radio/modem이 transmit/receive하도록 강제하여 특히 idle handset에서 눈에 띄는 battery drain을 발생시킵니다.
* upstream/downstream traffic을 생성하여 mobile data plan을 소모하고 video call과 같은 latency-sensitive feature와 contention을 일으킬 수 있습니다.<sup>[[1]](#references)</sup>
* Large invalid payload는 processing work를 증가시키지만, 해당 paper는 cryptography 자체가 battery cost에서 차지하는 비중은 negligible하다고 보고합니다.<sup>[[1]](#references)</sup>
* WhatsApp에서는 invalid reaction이 일반적인 emoji가 암시하는 것보다 훨씬 많은 data를 accept합니다. 공개된 측정에서는 reaction당 약 `1 MB`까지 server-side acceptance가 가능했습니다.
* Oversized reaction은 body가 약 `30 bytes`를 초과하면 reliable delivery receipt 생성을 중단하지만, discard되기 전에 여전히 forward되고 process됩니다. ACK가 필요할 때는 reaction body를 작게 유지하고, 순수한 drain 또는 covert one-way transport가 목적일 때만 크게 만듭니다.
* 공개된 측정에서는 이 mode에서 약 `3.7 MB/s`(`~13.3 GB/h`)의 victim traffic에 도달했습니다.

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
