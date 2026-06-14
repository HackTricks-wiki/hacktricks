# E2EE Messengers의 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipt는 modern end-to-end encrypted (E2EE) messengers에서 필수적이다. 클라이언트는 ciphertext가 언제 decrypted 되었는지 알아야 ratcheting state와 ephemeral keys를 버릴 수 있기 때문이다. server는 opaque blobs를 전달하므로, device acknowledgements (double checkmarks)는 성공적인 decryption 이후 수신자에 의해 전송된다. 공격자가 유발한 action과 그에 대응하는 delivery receipt 사이의 round-trip time (RTT)을 측정하면, high-resolution timing channel이 노출되어 device state, online presence를 leak하고 covert DoS에도 악용될 수 있다. multi-device "client-fanout" deployment는 leak을 증폭시키는데, 등록된 모든 device가 probe를 decrypt하고 각자 receipt를 반환하기 때문이다.

## Delivery receipt sources vs. user-visible signals

항상 delivery receipt를 발생시키지만 피해자에게 UI artifact를 노출하지 않는 message type을 선택하라. 아래 표는 실험적으로 확인된 동작을 요약한 것이다:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noisy하므로 state를 bootstrap하는 용도로만 유용하다. |
| | Reaction | ● | ◐ (only if reacting to victim message) | 자기 자신에 대한 reaction과 removal은 조용히 유지된다. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20min; 만료 후에도 여전히 ack’d 된다. |
| | Delete for everyone | ● | ○ | UI는 약 60 h를 허용하지만, 이후 packet도 여전히 ack’d 된다. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한이 있다. |
| | Reaction | ● | ◐ | 자기 자신에 대한 reaction은 피해자에게 보이지 않는다. |
| | Edit/Delete | ● | ○ | server는 약 48 h window를 enforce하며, 최대 10 edits를 허용하지만, 늦은 packet도 여전히 ack’d 된다. |
| **Threema** | Text message | ● | ● | multi-device receipts가 aggregated되므로, probe당 RTT는 하나만 보인다. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour는 본문에 따로 적었다. 필요하면 read receipts는 끌 수 있지만, delivery receipts는 WhatsApp이나 Signal에서 끌 수 없다.

## Attacker goals and models

* **G1 – Device fingerprinting:** probe마다 도착하는 receipt 수를 세고, RTT를 cluster하여 OS/client (Android vs iOS vs desktop)를 추론하며, online/offline 전환을 관찰한다.
* **G2 – Behavioural monitoring:** high-frequency RTT series(≈1 Hz가 안정적)를 time-series로 취급해 screen on/off, app foreground/background, commuting vs working hours 등을 추론한다.
* **G3 – Resource exhaustion:** 끝없이 이어지는 silent probe를 보내 피해자 device들의 radio/CPU를 깨워두고, battery/data를 소모시키며 VoIP/RTC 품질을 저하시킨다.

악용 surface를 설명하기 위해서는 두 명의 threat actor면 충분하다:

1. **Creepy companion:** 이미 피해자와 chat을 공유하고 있으며, 기존 message ID에 연결된 self-reaction, reaction removal, 반복 edit/delete를 악용한다.
2. **Spooky stranger:** burner account를 등록하고 local conversation에 존재하지 않았던 message ID를 참조하는 reaction을 보낸다. WhatsApp과 Signal은 UI가 state change를 버리더라도 이를 여전히 decrypt하고 acknowledge하므로, 사전 대화가 필요 없다.

## Tooling for raw protocol access

기저의 E2EE protocol을 노출하는 client에 의존하면 UI 제약 밖에서 packet을 만들고, 임의의 `message_id`를 지정하며, 정확한 timestamp를 기록할 수 있다:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) 또는 [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented)는 double-ratchet state를 동기화한 채 raw `ReactionMessage`, `ProtocolMessage` (edit/delete), `Receipt` frame을 전송할 수 있게 해준다.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)와 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)를 함께 쓰면 CLI/API를 통해 모든 message type에 접근할 수 있다. 현재 `signal-cli` syntax는 `sendReaction RECIPIENT --target-author --target-timestamp`를 사용한다; delivery receipts가 실제로 수집되도록 `receive` 또는 `daemon`을 실행 상태로 두어야 한다. 자기 자신 reaction toggle 예시:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client의 source는 delivery receipt가 device를 떠나기 전에 어떻게 consolidated 되는지 문서화하고 있으며, 이것이 side channel bandwidth가 사실상 무시할 수준인 이유를 설명한다.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal backend를 포함하고, 기본값으로 silent delete probe를 사용하며, rolling-median threshold(`RTT < 0.9 * median`)로 `active`와 `standby`를 구분한다. [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)은 `--delay`, `--concurrent`, CSV/Prometheus exporter, Grafana-friendly output을 갖춘 더 가벼운 WhatsApp-first CLI이다. 둘 다 protocol reference라기보다 reconnaissance helper로 보아야 하며, 핵심은 raw client access가 생긴 뒤에는 얼마나 적은 code만으로도 충분한가 하는 점이다.

커스텀 tooling을 사용할 수 없더라도, WhatsApp Web이나 Signal Desktop에서 여전히 silent action을 유발하고 encrypted websocket/WebRTC channel을 sniff할 수 있지만, raw API는 UI 지연을 제거하고 invalid operation을 허용한다.

## Creepy companion: silent sampling loop

1. chat에서 본인이 작성한 historical message를 아무거나 고른다. 그러면 피해자는 "reaction" balloon이 변하는 것을 보지 않는다.
2. 보이는 emoji와 빈 reaction payload(WhatsApp protobuf에서는 `""`, signal-cli에서는 `--remove`로 인코딩됨)를 번갈아 보낸다. 각 transmission은 피해자에게 UI delta가 없어도 device ack를 발생시킨다.
3. send time과 각 delivery receipt arrival를 timestamp한다. 다음과 같은 1 Hz loop는 device별 RTT trace를 무기한 제공한다:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal은 unlimited reaction update를 허용하므로, attacker는 새 chat content를 올릴 필요가 없고 edit window도 걱정할 필요가 없다.

## Spooky stranger: probing arbitrary phone numbers

1. 새 WhatsApp/Signal account를 등록하고 target number에 대한 public identity key를 가져온다(session setup 중 자동으로 수행됨).
2. 양쪽 누구에게도 보이지 않았던 random `message_id`를 참조하는 reaction/edit/delete packet을 만든다(WhatsApp는 arbitrary `key.id` GUID를 허용하고, Signal은 millisecond timestamp를 사용한다).
3. thread가 없더라도 packet을 전송한다. 피해자 device는 이를 decrypt하고, base message와 매칭에 실패해 state change를 버리지만, incoming ciphertext는 여전히 acknowledge하여 device receipt를 attacker에게 돌려보낸다.
4. 피해자의 chat list에 한 번도 나타나지 않은 채로 RTT series를 만들기 위해 이를 계속 반복한다.

먼저 어떤 number가 registered 되어 있는지 알아내거나, 대규모로 device inventory를 pre-seed해야 한다면, random E.164 range를 수작업으로 추측하는 대신 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 연결하라.

공개된 contact-discovery 연구는 이것이 운영상 왜 중요한지 보여준다. 정확한 phone-prefix table과 적당한 자원을 사용하면, 연구자들은 WhatsApp에서 미국 mobile number의 약 `10%`, Signal에서 `100%`를 대상으로 질의할 수 있었고, 그 다음에 targeted probing으로 넘어갈 수 있었다. 실제로는 live account를 먼저 pre-filtering하면 silent-probe 예산을 실제로 packet을 decrypt할 number에 집중시킬 수 있다.

최근 WhatsApp build에는 `Settings -> Privacy -> Advanced -> Block unknown account messages`도 있다. 이것은 fix가 아니라 throughput limiter로 보아야 한다. 주로 지속적인 stranger-only flooding에 타격을 줄 뿐이며, 이미 known contact가 된 뒤에는 무관하다.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** message가 한 번 `delete-for-everyone` 된 뒤, 같은 `message_id`를 참조하는 추가 delete packet은 UI 효과가 없지만 모든 device는 여전히 이를 decrypt하고 acknowledge한다.
* **Out-of-window operations:** WhatsApp는 UI에서 약 60 h delete / 약 20 min edit window를 enforce하고, Signal은 약 48 h를 enforce한다. 이 window 밖에서 만든 protocol message는 피해자 device에서 조용히 무시되지만 receipt는 전송되므로, 대화가 끝난 한참 뒤에도 공격자는 무기한 probe할 수 있다.
* **Invalid payloads:** 이미 purged 된 message를 참조하는 malformed edit body나 delete도 같은 동작을 유발한다. 즉, decryption plus receipt, user-visible artefacts는 0이다.

## Multi-device amplification & fingerprinting

* 연결된 각 device(phone, desktop app, browser companion)는 probe를 독립적으로 decrypt하고 자기 own ack를 반환한다. probe당 receipt 수를 세면 정확한 device 수를 알 수 있다.
* device가 offline이면 receipt는 queue에 쌓였다가 reconnection 시 전송된다. 따라서 gap은 online/offline cycle과, 심지어 commuting schedule까지 leak한다(예: travel 동안 desktop receipt가 멈춘다).
* RTT distribution은 OS power management와 push wakeup 때문에 platform마다 다르다. RTT를 cluster(예: median/variance feature에 대한 k-means)하여 “Android handset", “iOS handset", “Electron desktop", 등으로 라벨링하라.
* sender는 encrypt하기 전에 recipient의 key inventory를 가져와야 하므로, attacker는 새 device가 pair되는 시점도 관찰할 수 있다. device 수의 갑작스런 증가나 새로운 RTT cluster는 강한 indicator다.

## Sampling cadence, queueing, and stacked receipts

* **WhatsApp burst tolerance:** 공개된 측정에 따르면 WhatsApp는 명백한 server-side queueing 없이 빠르면 `50 ms`마다 한 번의 probe 수준으로 silent-reaction burst를 받아들였다. 이는 짧은 calibration burst, 빠른 device counting, 또는 drain attack을 신속히 가속하는 데 유용하다.
* **Signal long-run queueing:** Signal은 짧은 burst는 견뎠지만, 초당 여러 probe가 지속되는 traffic부터는 queueing하기 시작했다. 장기 monitoring에서는 cadence를 약 `1 Hz`(또는 그 이하)로 유지하여 각 receipt가 backlog drain이 아니라 현재 device state를 반영하도록 하라.
* **Reconnect artefacts:** device가 다시 online이 되면 일부 client는 지연된 receipt 여러 개를 batch로 묶거나 빠르게 flush한다. 그런 receipt burst는 독립적인 RTT sample이 아니라 state-transition marker로 취급하라. 그렇지 않으면 clustering / `active` vs `idle` classifier가 reconnect noise에 overfit 된다.

## Behaviour inference from RTT traces

1. OS scheduling effect를 잡기 위해 ≥1 Hz로 sample한다. WhatsApp on iOS에서 1 s 미만 RTT는 screen-on/foreground와 강하게 상관하고, 1 s 초과 RTT는 screen-off/background throttling과 상관한다.
2. 각 RTT를 "active" 또는 "idle"로 라벨링하는 간단한 classifier(thresholding 또는 two-cluster k-means)를 만든다. 라벨을 streak로 묶어 bedtime, commute, work hours, 또는 desktop companion 활성 시점을 추론한다.
3. 모든 device로 향하는 simultaneous probe를 상관분석하여 사용자가 mobile에서 desktop으로 전환하는 시점, companion이 offline이 되는 시점, 그리고 app이 push vs persistent socket 때문에 rate limited 되는지 확인한다.
4. 실제 network에서는 단일 hardcoded `1 s` threshold를 피하라. 짧은 warm-up window로 각 device를 bootstrap하고 rolling baseline(예: `threshold = 0.9 * median RTT`)을 유지하여 Wi-Fi/cellular drift 때문에 classifier가 무너지지 않게 하라.

## Location inference from delivery RTT

같은 timing primitive는 recipient가 active인지 여부뿐 아니라, 어디에 있는지도 추론하는 데 재사용될 수 있다. `Hope of Delivery` 연구는 알려진 receiver location의 RTT distribution으로 training하면, attacker가 나중에 delivery confirmation만으로 피해자의 location을 분류할 수 있음을 보여주었다:

* 피해자가 여러 알려진 장소(home, office, campus, country A vs country B 등)에 있을 때 같은 target에 대한 baseline을 만든다.
* 각 location마다 일반 message RTT를 많이 수집하고 median, variance, percentile bucket 같은 간단한 feature를 추출한다.
* 실제 공격 중에는 새 probe series를 학습된 cluster와 비교한다. 논문은 같은 city 안의 location도 종종 분리할 수 있으며, 3-location 설정에서 `>80%` accuracy를 보고했다고 밝힌다.
* 이 방법은 attacker가 sender environment를 제어하고 유사한 network conditions에서 probe할 때 가장 잘 동작한다. 측정 경로에 recipient access network, wake-up latency, messenger infrastructure가 모두 포함되기 때문이다.

위의 silent reaction/edit/delete 공격과 달리 location inference는 invalid message ID나 stealthy state-changing packet을 요구하지 않는다. 정상 delivery confirmation이 있는 plain message만으로 충분하므로, tradeoff는 stealth는 낮아지지만 messengers 전반에 대한 적용 범위는 넓어진다.

## Stealthy resource exhaustion

각 silent probe는 반드시 decrypt되고 acknowledge되어야 하므로, reaction toggle, invalid edit, delete-for-everyone packet을 계속 보내면 application-layer DoS가 된다:

* 매초 radio/modem이 transmit/receive하도록 강제 → 특히 idle handset에서 눈에 띄는 battery drain.
* mobile data plan을 소모하는 unmetered upstream/downstream traffic을 생성하면서 TLS/WebSocket noise에 섞여 들어감.
* crypto thread를 점유하고 latency-sensitive feature(VoIP, video calls)에 jitter를 유발함에도 사용자는 notification을 보지 못함.
* WhatsApp에서는 invalid reaction이 normal emoji보다 훨씬 많은 data를 받아들인다. 공개된 측정에 따르면 server-side acceptance가 reaction당 대략 `1 MB`까지였다.
* oversized reaction은 body가 대략 `30 bytes`를 넘으면 신뢰할 수 있는 delivery receipt를 더 이상 만들지 못하지만, 여전히 forward되고 discard되기 전에 처리된다. ACK가 필요할 때는 reaction body를 작게 유지하라. pure drain이나 covert one-way transport가 목표일 때만 크게 부풀려라.
* 공개 측정에서는 이 mode에서 피해자 traffic이 약 `3.7 MB/s`(`~13.3 GB/h`)에 도달했다.

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
