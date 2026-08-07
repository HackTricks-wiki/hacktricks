# E2EE Messenger의 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

현대의 종단간 암호화(E2EE) Messenger에서는 클라이언트가 ciphertext가 복호화된 시점을 알아야 ratcheting state와 ephemeral key를 폐기할 수 있으므로 delivery receipt가 필수적입니다. 서버는 opaque blob을 전달할 뿐이므로 device acknowledgement(이중 체크 표시)는 수신자가 성공적으로 복호화한 후 생성합니다. 공격자가 유발한 동작과 해당 delivery receipt 사이의 round-trip time(RTT)을 측정하면 높은 해상도의 timing channel이 노출되어 device state와 online presence가 leak되며, 은밀한 DoS에도 악용될 수 있습니다. Multi-device "client-fanout" deployment에서는 등록된 모든 device가 probe를 복호화하고 각자의 receipt를 반환하므로 leakage가 증폭됩니다.<sup>[[1]](#references)</sup>

## Delivery receipt sources와 user-visible signals 비교

항상 delivery receipt를 생성하지만 피해자에게 UI artifact를 표시하지 않는 message type을 선택합니다. 아래 표는 실증적으로 확인된 동작을 요약합니다.<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noisy하므로 state bootstrap에만 유용합니다. |
| | Reaction | ● | ◐ (피해자의 message에 반응하는 경우에만) | Self-reaction과 removal은 silent 상태로 유지됩니다. |
| | Edit | ● | Platform-dependent silent push | Edit window는 약 20분이며, 만료 후에도 ack됩니다. |
| | Delete for everyone | ● | ○ | UI에서는 약 60시간을 허용하지만, 이후 packet도 여전히 ack됩니다. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한이 있습니다. |
| | Reaction | ● | ◐ | Self-reaction은 피해자에게 보이지 않습니다. |
| | Edit/Delete | ● | ○ | 서버는 약 48시간 window를 적용하고 최대 10회의 edit을 허용하지만, 늦게 도착한 packet도 여전히 ack됩니다. |
| **Threema** | Text message | ● | ● | Multi-device receipt가 aggregate되므로 probe당 하나의 RTT만 표시됩니다. |

범례: ● = 항상, ◐ = 조건부, ○ = 없음. Platform-dependent UI 동작은 각 항목에 표시했습니다. 필요한 경우 read receipt를 비활성화할 수 있지만, WhatsApp이나 Signal에서는 delivery receipt를 끌 수 없습니다.<sup>[[1]](#references)</sup>

## Attacker goals와 models

* **G1 – Device fingerprinting:** Probe당 도착하는 receipt 수를 세고, RTT를 cluster화하여 OS/client(Android와 iOS 및 desktop)을 추론하며, online/offline 전환을 관찰합니다.
* **G2 – Behavioural monitoring:** 고주파 RTT series(약 1 Hz가 안정적)를 time-series로 취급하여 screen on/off, app foreground/background, 출퇴근 시간과 근무 시간 등을 추론합니다.
* **G3 – Resource exhaustion:** 모든 피해자 device의 radio/CPU를 never-ending silent probe로 계속 깨어 있게 하여 battery/data를 소모시키고 VoIP/RTC 품질을 저하시킵니다.<sup>[[1]](#references)</sup>

두 threat actor만으로 abuse surface를 설명할 수 있습니다.<sup>[[1]](#references)</sup>

1. **Creepy companion:** 이미 피해자와 chat을 공유하고 있으며, self-reaction, reaction removal 또는 기존 message ID에 연결된 반복적인 edit/delete를 악용합니다.
2. **Spooky stranger:** burner account를 등록하고 local conversation에 존재하지 않았던 message ID를 참조하는 reaction을 전송합니다. WhatsApp과 Signal은 UI가 state change를 폐기하더라도 이를 복호화하고 acknowledge하므로 사전 conversation이 필요하지 않습니다.

## Raw protocol access를 위한 Tooling

기반 E2EE protocol을 노출하는 client에 의존하면 UI 제약을 벗어나 packet을 생성하고, 임의의 `message_id`를 지정하며, 정밀한 timestamp를 기록할 수 있습니다.

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)(Go, WhatsApp Web protocol) 또는 [Cobalt](https://github.com/Auties00/Cobalt)(mobile-oriented)를 사용하면 double-ratchet state를 동기화한 상태로 raw `ReactionMessage`, `ProtocolMessage` (edit/delete), `Receipt` frame을 전송할 수 있습니다.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)를 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)와 함께 사용하면 CLI/API를 통해 모든 message type에 접근할 수 있습니다.<sup>[[5]](#references)[[7]](#references)</sup> 현재 `signal-cli` syntax는 `sendReaction RECIPIENT --target-author --target-timestamp`를 사용합니다. delivery receipt가 실제로 수집되도록 `receive` 또는 `daemon`을 실행 상태로 유지합니다.<sup>[[6]](#references)</sup> Self-reaction toggle 예시:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client의 source는 delivery receipt가 device를 떠나기 전에 어떻게 consolidate되는지 설명하며, 이를 통해 해당 side channel의 bandwidth가 매우 낮은 이유를 알 수 있습니다.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal backend를 제공하고, 기본값으로 silent delete probe를 사용하며, rolling-median threshold(`RTT < 0.9 * median`)로 `active`와 `standby`를 구분합니다.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)은 `--delay`, `--concurrent`, CSV/Prometheus exporter 및 Grafana 친화적 output을 제공하는 더 가벼운 WhatsApp-first CLI입니다.<sup>[[9]](#references)</sup> 둘 다 protocol reference가 아니라 reconnaissance helper로 취급해야 합니다. 중요한 점은 raw client access가 있으면 필요한 code가 얼마나 적은가입니다.

Custom tooling을 사용할 수 없는 경우에도 WhatsApp Web 또는 Signal Desktop에서 silent action을 trigger하고 encrypted websocket/WebRTC channel을 sniff할 수 있지만, raw API를 사용하면 UI delay가 제거되고 invalid operation이 가능합니다.

## Creepy companion: silent sampling loop

1. 자신이 chat에서 작성한 과거 message를 선택하여 피해자에게 "reaction" balloon의 변화가 표시되지 않도록 합니다.
2. visible emoji와 빈 reaction payload를 번갈아 전송합니다(WhatsApp protobuf에서는 `""`, signal-cli에서는 `--remove`로 encode). 각 transmission은 피해자에게 UI delta가 없어도 device ack를 생성합니다.
3. Send time과 모든 delivery receipt arrival을 timestamp로 기록합니다. 다음과 같은 1 Hz loop는 device별 RTT trace를 무기한 제공합니다.
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp과 Signal은 reaction update를 무제한으로 허용하므로 공격자는 새로운 chat content를 게시하거나 edit window를 걱정할 필요가 없습니다.<sup>[[1]](#references)</sup>

## Spooky stranger: 임의의 phone number probing

1. 새 WhatsApp/Signal account를 등록하고 target number의 public identity key를 가져옵니다(session setup 중 자동으로 수행됨).
2. 어느 쪽도 본 적 없는 random `message_id`를 참조하는 reaction/edit/delete packet을 생성합니다(WhatsApp은 임의의 `key.id` GUID를 허용하고, Signal은 millisecond timestamp를 사용함).
3. Thread가 존재하지 않아도 packet을 전송합니다. 피해자 device는 이를 복호화하고 base message와 일치하지 않음을 확인한 뒤 state change를 폐기하지만, 수신한 ciphertext는 여전히 acknowledge하여 device receipt를 공격자에게 전송합니다.
4. 이를 지속적으로 반복하여 피해자의 chat list에 전혀 표시되지 않는 RTT series를 구축합니다.<sup>[[1]](#references)</sup>

등록된 number를 먼저 확인해야 하거나 대규모로 device inventory를 사전 구축하려면, E.164 range를 직접 추측하지 말고 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 chain하십시오.

공개된 contact-discovery 연구는 이것이 운영상 중요한 이유를 보여주었습니다. 정확한 phone-prefix table과 적당한 resource를 사용하여 연구자들은 targeted probing으로 넘어가기 전에 WhatsApp에서 미국 mobile number의 약 `10%`, Signal에서 `100%`를 query할 수 있었습니다.<sup>[[11]](#references)</sup> 실제로는 live account를 먼저 pre-filter하면 silent-probe budget을 실제로 packet을 복호화할 number에 집중할 수 있습니다.

최근 WhatsApp build는 `Settings -> Privacy -> Advanced -> Block unknown account messages`도 제공합니다.<sup>[[10]](#references)</sup> 이를 fix가 아닌 throughput limiter로 취급해야 합니다. 주로 지속적인 stranger-only flooding을 어렵게 할 뿐이며, 이미 known contact인 경우에는 무관합니다.

## Covert trigger로 edit과 delete 재활용

* **Repeated deletes:** 한 번 Delete for everyone된 message에 대해 동일한 `message_id`를 참조하는 추가 delete packet은 UI effect를 발생시키지 않지만, 모든 device는 여전히 이를 복호화하고 acknowledge합니다.
* **Out-of-window operations:** WhatsApp은 UI에서 약 60시간의 delete window와 약 20분의 edit window를 적용하며, Signal은 약 48시간을 적용합니다. 이 window를 벗어난 crafted protocol message는 피해자 device에서 조용히 무시되지만 receipt는 전송되므로, conversation이 끝난 후에도 장기간 probe할 수 있습니다.
* **Invalid payloads:** Malformed edit body 또는 이미 purge된 message를 참조하는 delete도 동일하게 동작합니다. 즉, decryption과 receipt는 수행되지만 user-visible artefact는 없습니다.<sup>[[1]](#references)</sup>

## Multi-device amplification 및 fingerprinting

* 연결된 각 device(phone, desktop app, browser companion)는 probe를 독립적으로 복호화하고 자체 ack를 반환합니다. Probe당 receipt 수를 세면 정확한 device 수를 확인할 수 있습니다.
* Device가 offline이면 receipt가 queue에 저장되었다가 reconnect 시 전송됩니다. 따라서 공백은 online/offline cycle과 commuting schedule까지 leak합니다(예: desktop receipt가 이동 중 중단됨).
* RTT distribution은 OS power management와 push wakeup으로 인해 platform마다 다릅니다. RTT를 cluster화하면(k-means에서 median/variance feature 사용) “Android handset”, “iOS handset”, “Electron desktop” 등으로 label할 수 있습니다.
* Sender는 encrypt하기 전에 recipient의 key inventory를 가져와야 하므로, 공격자는 새 device가 paired되는 시점도 관찰할 수 있습니다. Device 수의 갑작스러운 증가나 새로운 RTT cluster는 강력한 지표입니다.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing 및 stacked receipt

* **WhatsApp burst tolerance:** 공개된 측정에 따르면 WhatsApp은 명확한 server-side queueing 없이 50ms마다 probe 하나에 해당하는 속도로 silent-reaction burst를 수용했습니다. 이는 짧은 calibration burst, 빠른 device counting 또는 drain attack의 신속한 ramp-up에 유용합니다.
* **Signal long-run queueing:** Signal은 짧은 burst는 허용했지만, 지속적인 초당 multi-probe traffic이 시작되면 queueing했습니다. 장시간 monitoring에서는 cadence를 약 `1 Hz`(또는 그 이하)로 유지하여 각 receipt가 backlog drain이 아니라 현재 device state를 반영하도록 합니다.
* **Reconnect artefacts:** Device가 online으로 돌아오면 일부 client는 지연된 receipt를 batch 처리하거나 빠르게 flush합니다. 이러한 receipt burst는 독립적인 RTT sample이 아니라 state-transition marker로 취급해야 합니다. 그렇지 않으면 clustering 또는 `active`와 `idle` classifier가 reconnect noise에 overfit됩니다.<sup>[[1]](#references)</sup>

## RTT trace를 이용한 Behaviour inference

1. OS scheduling effect를 포착하려면 ≥1 Hz로 sample합니다. iOS의 WhatsApp에서는 1초 미만의 RTT가 screen-on/foreground와 강하게 연관되고, 1초 초과는 screen-off/background throttling과 연관됩니다.
2. 각 RTT를 "active" 또는 "idle"로 label하는 간단한 classifier(thresholding 또는 two-cluster k-means)를 구축합니다. Label을 streak로 aggregate하여 취침 시간, 출퇴근 시간, 근무 시간 또는 desktop companion이 active인 시점을 도출합니다.
3. 모든 device를 대상으로 동시에 수행한 probe를 correlate하여 사용자가 mobile에서 desktop으로 전환하는 시점, companion이 offline되는 시점, app이 push와 persistent socket 중 무엇에 의해 rate limited되는지를 확인합니다.
4. 실제 network에서는 단일 hardcoded `1 s` threshold를 사용하지 않습니다. 각 device를 짧은 warm-up window로 bootstrap하고 rolling baseline(예: `threshold = 0.9 * median RTT`)을 유지하여 Wi-Fi/cellular drift가 classifier를 무너뜨리지 않도록 합니다.<sup>[[1]](#references)</sup>

## Delivery RTT를 이용한 Location inference

동일한 timing primitive를 사용하여 recipient가 active인지 여부뿐 아니라 위치도 추론할 수 있습니다. `Hope of Delivery` 연구는 알려진 receiver location의 RTT distribution으로 training하면 공격자가 이후 delivery confirmation만으로 피해자의 위치를 classify할 수 있음을 보여주었습니다.<sup>[[2]](#references)</sup>

* Target이 여러 known location(home, office, campus, country A와 country B 등)에 있을 때 동일한 target에 대한 baseline을 구축합니다.
* 각 location에서 많은 수의 정상적인 message RTT를 수집하고 median, variance 또는 percentile bucket과 같은 간단한 feature를 추출합니다.
* 실제 attack 중에는 새로운 probe series를 trained cluster와 비교합니다. 해당 논문에 따르면 같은 city 내의 location도 종종 구분할 수 있으며, 3-location setting에서 `>80%` accuracy를 보였습니다.
* 측정된 path에는 recipient access network, wake-up latency 및 messenger infrastructure가 포함되므로, 공격자가 sender environment를 통제하고 유사한 network condition에서 probe할 때 가장 잘 동작합니다.<sup>[[2]](#references)</sup>

위의 silent reaction/edit/delete attack과 달리 location inference에는 invalid message ID나 stealthy state-changing packet이 필요하지 않습니다. 정상적인 delivery confirmation이 포함된 plain message만으로 충분하므로 stealth는 낮아지지만 messenger 전반에 더 폭넓게 적용할 수 있습니다.

## Stealthy resource exhaustion

모든 silent probe는 복호화되고 acknowledge되어야 하므로 reaction toggle, invalid edit 또는 Delete for everyone packet을 지속적으로 전송하면 application-layer DoS가 발생합니다.<sup>[[1]](#references)</sup>

* 매초 radio/modem이 transmit/receive하도록 강제하여, 특히 idle handset에서 눈에 띄는 battery drain을 유발합니다.
* TLS/WebSocket noise에 섞인 채 unmetered upstream/downstream traffic을 생성하여 mobile data plan을 소모합니다.
* Crypto thread를 점유하고 사용자가 notification을 전혀 보지 못하는 상황에서도 latency-sensitive feature(VoIP, video call)에 jitter를 발생시킵니다.
* WhatsApp에서는 invalid reaction이 일반적인 emoji가 암시하는 것보다 훨씬 많은 data를 수용합니다. 공개된 측정에서는 reaction당 약 `1 MB`까지 server-side acceptance가 확인되었습니다.
* Oversized reaction은 body가 약 `30 bytes`를 초과하면 안정적인 delivery receipt 생성을 중단하지만, 폐기되기 전까지는 여전히 전달되고 처리됩니다. ACK가 필요할 때는 reaction body를 작게 유지하고, 순수한 drain 또는 covert one-way transport가 목적일 때만 크게 만드십시오.
* 공개 측정에서는 이 mode에서 피해자 traffic이 약 `3.7 MB/s`(`~13.3 GB/h`)에 도달했습니다.

## References

- [1] [Careless Whisper: Silent Delivery Receipt를 악용한 Mobile Instant Messenger 사용자 Monitoring](https://arxiv.org/html/2411.11194v4)
- [2] [Hope of Delivery: Mobile Instant Messenger에서 User Location 추출](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [Unknown message의 대량 수신을 차단하는 방법 | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [All the Numbers are US: Mobile Messenger에서 Contact Discovery의 대규모 Abuse](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)

{{#include ../banners/hacktricks-training.md}}
