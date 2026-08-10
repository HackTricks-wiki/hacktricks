# E2EE 메신저의 Delivery Receipt Side-Channel Attacks

현대의 종단간 암호화(E2EE) 메신저에서는 클라이언트가 ciphertext가 언제 복호화되었는지 알아야 ratcheting state와 ephemeral keys를 폐기할 수 있으므로 delivery receipts가 필수적이다. 서버는 opaque blobs를 전달할 뿐이므로, device acknowledgements(이중 체크 표시)는 성공적으로 복호화한 수신자가 생성한다. 공격자가 유발한 동작과 그에 대응하는 delivery receipt 사이의 round-trip time(RTT)을 측정하면 device state, online presence를 leak하는 고해상도 timing channel이 노출되며, covert DoS에도 악용될 수 있다. Multi-device "client-fanout" 배포에서는 등록된 모든 device가 probe를 복호화하고 자체 receipt를 반환하므로 leakage가 증폭된다.<sup>[[1]](#references)</sup>

## Delivery receipt sources vs. user-visible signals

항상 delivery receipt를 생성하지만 피해자에게 UI artifact를 표시하지 않는 message type을 선택한다. 아래 표는 경험적으로 확인된 동작을 요약한다.<sup>[[1]](#references)</sup>

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noisy하므로 state bootstrap에만 유용하다. |
| | Reaction | ● | ◐ (피해자의 message에 반응하는 경우에만) | Self-reaction과 removal은 silent 상태로 유지된다. |
| | Edit | ● | Platform-dependent silent push | Edit window는 약 20분이며, 만료 후에도 ack된다. |
| | Delete for everyone | ● | ○ | UI에서는 약 60시간을 허용하지만, 이후 packet도 ack된다. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한이 있다. |
| | Reaction | ● | ◐ | Self-reaction은 피해자에게 표시되지 않는다. |
| | Edit/Delete | ● | ○ | 서버는 약 48시간 window를 적용하고 최대 10회의 edit을 허용하지만, 늦은 packet도 ack된다. |
| **Threema** | Text message | ● | ● | Multi-device receipt가 aggregate되므로 probe당 하나의 RTT만 표시된다. |

범례: ● = 항상, ◐ = 조건부, ○ = 없음. Platform-dependent UI 동작은 행 안에 표시했다. 필요하면 read receipts를 비활성화할 수 있지만, WhatsApp이나 Signal에서는 delivery receipts를 끌 수 없다.<sup>[[1]](#references)</sup>

## Attacker goals and models

* **G1 – Device fingerprinting:** Probe당 도착하는 receipt 수를 세고 RTT를 cluster하여 OS/client(Android와 iOS 및 desktop)를 추론하며 online/offline 전환을 관찰한다.
* **G2 – Behavioural monitoring:** 고주파 RTT series(약 1 Hz가 안정적)를 time-series로 취급하여 screen on/off, app foreground/background, 통근 시간과 근무 시간 등을 추론한다.
* **G3 – Resource exhaustion:** 끝나지 않는 silent probe를 전송하여 모든 피해자 device의 radio/CPU를 계속 깨어 있게 하고, battery/data를 소모하며 video-call 품질을 저하시킨다.<sup>[[1]](#references)</sup>

두 threat actor만으로 abuse surface를 설명할 수 있다.<sup>[[1]](#references)</sup>

1. **Creepy companion:** 이미 피해자와 chat을 공유하고 있으며 self-reaction, reaction removal 또는 기존 message ID에 연결된 반복적인 edit/delete를 악용한다.
2. **Spooky stranger:** burner account를 등록하고 local conversation에 존재하지 않았던 message ID를 참조하는 reaction을 전송한다. WhatsApp과 Signal은 UI가 state change를 폐기하더라도 이를 복호화하고 acknowledge하므로 사전 conversation이 필요하지 않다.

## Tooling for raw protocol access

UI 제약을 벗어나 supported packet을 생성하고 정확한 timestamp를 기록할 수 있도록, 기반 E2EE protocol을 충분히 노출하는 client를 사용한다. 임의의 message ID는 각 implementation을 확인해야 한다.

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)(Go, WhatsApp Web multidevice API)는 delivery receipt의 송수신을 문서화한다. [Cobalt](https://github.com/Auties00/Cobalt)(unofficial Java/Kotlin Web 및 mobile API)는 reacting, editing, deleting과 같은 message operation을 문서화한다. 모든 internal frame이 노출된다고 가정하지 말고 문서화된 API를 사용한다.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)는 CLI, JSON-RPC 및 D-Bus interface를 제공하며, [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)는 Signal과 통신하기 위한 Java library다.<sup>[[5]](#references)[[7]](#references)</sup> 현재 `signal-cli` syntax는 `sendReaction RECIPIENT --target-author --target-timestamp`를 사용한다. protocol update가 계속 처리되도록 `receive` 또는 `daemon`을 실행 상태로 유지한다.<sup>[[6]](#references)</sup> Self-reaction toggle 예시:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Careless Whisper paper의 측정에 따르면 delivery receipt는 device 간에 synchronize되므로 multi-device setup에서도 message당 하나의 receipt만 노출된다.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal backend를 제공하고, 기본값으로 silent delete probe를 사용하며, rolling-median threshold(`RTT < 0.9 * median`)로 `active`와 `standby`를 구분한다.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)는 `--delay`, `--concurrent`, CSV/Prometheus exporter 및 Grafana 친화적 output을 제공하는 더 가벼운 WhatsApp-first CLI다.<sup>[[9]](#references)</sup> 둘 다 protocol reference가 아니라 reconnaissance helper로 취급한다. 중요한 점은 raw client access가 있으면 필요한 code가 얼마나 적은가이다.

custom tooling을 사용할 수 없을 때도 official client 또는 browser developer tools로 silent action을 trigger하고 encrypted traffic timing을 노출할 수 있다. raw API를 사용하면 UI delay가 제거되고 invalid operation이 허용된다.<sup>[[1]](#references)</sup>

## Creepy companion: silent sampling loop

1. 자신이 chat에서 작성한 과거 message를 하나 선택하여 피해자에게 "reaction" balloon의 변화가 표시되지 않도록 한다.
2. visible emoji와 empty reaction payload(WhatsApp protobuf에서는 `""`, signal-cli에서는 `--remove`로 encode)를 번갈아 사용한다. 각 transmission은 피해자에게 UI delta가 없어도 device ack를 생성한다.
3. 전송 시간과 모든 delivery receipt 도착 시간을 timestamp로 기록한다. 다음과 같은 1 Hz loop는 device별 RTT trace를 무기한 제공한다.
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal은 reaction update를 무제한으로 허용하므로 공격자는 새로운 chat content를 게시하거나 edit window를 걱정할 필요가 없다.<sup>[[1]](#references)</sup>

## Spooky stranger: probing arbitrary phone numbers

1. 새로운 WhatsApp/Signal account를 등록하고 target number의 public identity key를 가져온다(session setup 중 자동으로 수행됨).
2. 어느 쪽도 본 적 없는 임의의 `message_id`를 참조하는 reaction packet을 생성한다. 논문에 따르면 WhatsApp과 Signal 모두 이러한 reaction을 수락하고 delivery receipt도 생성한다.<sup>[[1]](#references)</sup>
3. thread가 존재하지 않더라도 packet을 전송한다. 피해자 device는 이를 복호화하고 base message와 일치하지 않음을 확인한 뒤 state change를 폐기하지만, 수신한 ciphertext는 acknowledge하여 device receipt를 공격자에게 돌려보낸다.
4. 사전 conversation이나 visible notification 없이 RTT series를 구축할 때까지 계속 반복한다.<sup>[[1]](#references)</sup>

먼저 어떤 number가 등록되어 있는지 확인하거나 대규모로 device inventory를 pre-seed해야 한다면, 무작위 E.164 range를 수작업으로 추측하는 대신 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 chain한다.

Published contact-discovery 연구는 이것이 operationally 중요한 이유를 보여주었다. 정확한 phone-prefix table과 적당한 resource를 사용해 연구자들은 targeted probing으로 넘어가기 전에 WhatsApp에서 미국 mobile number의 약 `10%`, Signal에서 `100%`를 query할 수 있었다.<sup>[[11]](#references)</sup> 실제로는 먼저 live account를 pre-filter하면 실제로 packet을 decrypt할 number에 silent-probe budget을 집중할 수 있다.

최근 WhatsApp build에는 `Settings -> Privacy -> Advanced -> Block unknown account messages`도 노출된다.<sup>[[10]](#references)</sup> 이를 throughput limiter로 취급한다. tracker documentation에 따르면 WhatsApp은 unknown account에서 오는 high-volume message를 block하지만 threshold는 공개하지 않으므로 probe reaction을 완전히 방지하지는 못한다.<sup>[[8]](#references)</sup>

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** message가 한 번 Delete for everyone된 후에도 동일한 `message_id`를 참조하는 추가 delete packet은 UI effect를 발생시키지 않지만 모든 device는 계속 복호화하고 acknowledge한다.
* **Out-of-window operations:** WhatsApp은 UI에서 약 60시간의 delete / 약 20분의 edit window를 적용하며 Signal은 약 48시간을 적용한다. 이 window 밖에서 생성된 protocol message는 피해자 device에서 silent하게 무시되지만 receipt는 전송되므로, conversation이 종료된 뒤에도 공격자는 무기한 probe할 수 있다.
* **Invalid payloads:** 논문에 따르면 invalid message도 acknowledge될 수 있다. malformed body 또는 purged ID의 정확한 동작은 implementation-dependent이므로 의존하기 전에 테스트해야 한다.<sup>[[1]](#references)</sup>

## Multi-device amplification & fingerprinting

* WhatsApp과 Signal에서는 연결된 각 device(phone, desktop app, browser companion)가 probe를 독립적으로 복호화하고 자체 ack를 반환한다. Probe당 receipt 수를 세면 정확한 device 수를 확인할 수 있다.<sup>[[1]](#references)</sup>
* device가 offline이면 receipt는 queue에 저장되었다가 reconnect 시 생성된다. 따라서 공백은 online/offline cycle과 통근 일정까지 leak한다(예: 이동 중에는 desktop receipt가 중단됨).
* OS, model, client 및 network condition이 timing에 영향을 주므로 RTT distribution은 platform과 environment에 따라 다르다. RTT를 cluster하여(예: median/variance feature에 k-means 적용) "Android handset", "iOS handset", "Electron desktop" 등으로 label한다.
* sender는 encryption 전에 recipient의 key inventory를 가져와야 하므로, 공격자는 새로운 device가 paired되는 시점도 관찰할 수 있다. 갑작스러운 device 수 증가나 새로운 RTT cluster는 강력한 indicator다.<sup>[[1]](#references)</sup>

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** Published measurement에 따르면 WhatsApp은 명확한 server-side queueing 없이 probe당 1회, `50 ms` 간격만큼 빠른 silent-reaction burst를 수락했다. 이는 짧은 calibration burst, 빠른 device counting 또는 drain attack의 신속한 ramp-up에 유용하다.
* **Signal long-run queueing:** Signal은 짧은 burst는 허용했지만 sustained multi-probe-per-second traffic에서는 queueing을 시작했다. 장기 monitoring에서는 cadence를 약 `1 Hz` 이하로 유지하여 각 receipt가 backlog drain이 아니라 현재 device state를 반영하도록 한다.
* **Reconnect artefacts:** device가 online으로 돌아오면 일부 client는 지연된 receipt 여러 개를 batch 처리하거나 빠르게 flush한다. 이러한 receipt burst는 독립적인 RTT sample이 아니라 state-transition marker로 취급해야 한다. 그렇지 않으면 clustering 또는 `active`와 `idle` classifier가 reconnect noise에 overfit한다.<sup>[[1]](#references)</sup>

## Behaviour inference from RTT traces

1. OS scheduling effect를 포착하려면 ≥1 Hz로 sample한다. WhatsApp을 iOS에서 사용할 때 <1초 RTT는 screen-on/foreground와 강하게 상관되고, >1초는 screen-off/background throttling과 상관된다.
2. 각 RTT를 "active" 또는 "idle"로 label하는 간단한 classifier(thresholding 또는 two-cluster k-means)를 구축한다. label을 streak로 aggregate하여 취침 시간, 통근 시간, 근무 시간 또는 desktop companion이 active인 시점을 도출한다.
3. 모든 device를 대상으로 simultaneous probe를 수행하여 사용자가 mobile에서 desktop으로 전환하는 시점, companion이 offline이 되는 시점, 그리고 app이 push와 persistent socket 중 어느 방식에서 rate limit되는지를 확인한다.
4. 실제 network에서는 하나의 고정된 `1 s` threshold를 사용하지 않는다. 각 device에 짧은 warm-up window를 적용하고 rolling baseline을 유지한다(예: device-activity-tracker PoC는 `threshold = 0.9 * median RTT`를 사용). 이렇게 해야 Wi-Fi/cellular drift로 classifier가 무너지는 것을 방지할 수 있다.<sup>[[1]](#references)[[8]](#references)</sup>

## Location inference from delivery RTT

동일한 timing primitive를 수신자가 active인지 여부뿐 아니라 어디에 있는지 추론하는 데에도 사용할 수 있다. `Hope of Delivery` 연구는 알려진 receiver location의 RTT distribution으로 training하면 공격자가 이후 delivery confirmation만으로 피해자의 location을 classify할 수 있음을 보여주었다.<sup>[[2]](#references)</sup>

* 동일한 target이 여러 알려진 장소(home, office, campus, country A와 country B 등)에 있을 때 baseline을 구축한다.
* 각 location에서 정상적인 message RTT를 많이 수집하고 median, variance 또는 percentile bucket과 같은 간단한 feature를 추출한다.
* 실제 attack 중 새 probe series를 trained cluster와 비교한다. 논문에 따르면 동일한 도시 내의 location도 종종 구분할 수 있으며, 3-location setting에서 `>80%`의 accuracy를 보였다.
* 측정된 path에는 recipient access network, wake-up latency 및 messenger infrastructure가 포함되므로, 공격자가 sender environment를 제어하고 유사한 network condition에서 probe할 때 가장 효과적이다.<sup>[[2]](#references)</sup>

위의 silent reaction/edit/delete attack과 달리 location inference에는 invalid message ID나 stealthy state-changing packet이 필요하지 않다. 일반적인 delivery confirmation이 포함된 plain message만으로 충분하므로, tradeoff는 stealth가 낮아지는 대신 messenger 전반에서 더 폭넓게 적용할 수 있다는 점이다.

## Stealthy resource exhaustion

모든 silent probe는 복호화되고 acknowledge되어야 하므로 reaction toggle, invalid edit 또는 Delete for everyone packet을 지속적으로 전송하면 application-layer DoS가 발생한다.<sup>[[1]](#references)</sup>

* 매초 radio/modem이 transmit/receive하도록 강제하여 idle handset에서 특히 눈에 띄는 battery drain을 유발한다.
* upstream/downstream traffic을 생성하여 mobile data plan을 소모하고 video call과 같은 latency-sensitive feature와 경합할 수 있다.<sup>[[1]](#references)</sup>
* Large invalid payload는 processing work를 증가시키지만, 논문에 따르면 cryptography 자체는 battery cost에서 무시할 수 있는 수준이다.<sup>[[1]](#references)</sup>
* WhatsApp에서는 invalid reaction이 일반적인 emoji가 암시하는 것보다 훨씬 많은 data를 수락한다. Published measurement에서는 reaction당 약 `1 MB`까지 server-side acceptance가 확인되었다.
* Oversized reaction은 body가 약 `30 bytes`를 초과하면 reliable delivery receipt를 생성하지 않지만, discard되기 전까지는 여전히 전달되고 처리된다. ACK가 필요할 때는 reaction body를 작게 유지하고, 순수한 drain 또는 covert one-way transport가 목적일 때만 크게 만든다.
* Public measurement에서는 이 mode에서 피해자 traffic이 약 `3.7 MB/s`(`~13.3 GB/h`)에 도달했다.

## References

- [1] [Silent Delivery Receipts를 악용해 Mobile Instant Messenger 사용자를 모니터링하기: Careless Whisper](https://arxiv.org/html/2411.11194v4)
- [2] [Delivery의 희망: Mobile Instant Messenger에서 사용자 위치 추출하기](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [3] [whatsmeow](https://github.com/tulir/whatsmeow)
- [4] [Cobalt](https://github.com/Auties00/Cobalt)
- [5] [signal-cli](https://github.com/AsamK/signal-cli)
- [6] [signal-cli manpage](https://github.com/AsamK/signal-cli/blob/master/man/signal-cli.1.adoc)
- [7] [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [8] [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)
- [9] [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)
- [10] [알 수 없는 message의 대량 수신을 차단하는 방법 | WhatsApp Help Center](https://faq.whatsapp.com/3379690015658337)
- [11] [모든 번호는 미국에 있다: Mobile Messenger의 대규모 Contact Discovery 악용](https://www.ndss-symposium.org/ndss-paper/all-the-numbers-are-us-large-scale-abuse-of-contact-discovery-in-mobile-messengers/)
{{#include ../banners/hacktricks-training.md}}
