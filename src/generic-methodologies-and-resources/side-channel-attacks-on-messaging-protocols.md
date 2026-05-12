# E2EE 메신저의 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipt은 현대의 end-to-end encrypted (E2EE) messenger에서 필수적이다. 클라이언트는 ciphertext가 언제 복호화되었는지 알아야 ratcheting state와 ephemeral keys를 폐기할 수 있기 때문이다. 서버는 opaque blobs를 전달하므로, device acknowledgements(double checkmarks)는 수신자가 성공적으로 복호화한 뒤에 전송된다. 공격자가 유도한 동작과 해당 delivery receipt 사이의 round-trip time (RTT)을 측정하면, device state, online presence를 유출하고 covert DoS에도 악용할 수 있는 고해상도 timing channel이 드러난다. multi-device "client-fanout" 배포에서는 모든 등록된 device가 probe를 복호화하고 각자 자신의 receipt를 반환하므로 leak이 증폭된다.

## Delivery receipt sources vs. user-visible signals

피해자에게 UI artifact를 노출하지 않으면서 항상 delivery receipt을 발생시키는 message types를 선택하라. 아래 표는 실험적으로 확인된 동작을 요약한 것이다:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noisy → state를 bootstrap하는 데만 유용하다. |
| | Reaction | ● | ◐ (only if reacting to victim message) | 자기 자신에 대한 reaction과 제거는 조용히 유지된다. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; 만료 후에도 still ack’d. |
| | Delete for everyone | ● | ○ | UI는 약 60 h를 허용하지만, 더 늦은 packet도 still ack’d. |
| **Signal** | Text message | ● | ● | WhatsApp과 같은 제한이 있다. |
| | Reaction | ● | ◐ | 자기 자신에 대한 reaction은 피해자에게 보이지 않는다. |
| | Edit/Delete | ● | ○ | Server가 약 48 h window를 강제하고, 최대 10 edits를 허용하지만, 늦은 packet도 still ack’d. |
| **Threema** | Text message | ● | ● | multi-device receipt가 집계되므로 probe당 RTT는 하나만 보인다. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour is noted inline. 필요하다면 read receipts는 비활성화할 수 있지만, delivery receipt은 WhatsApp이나 Signal에서 끌 수 없다.

## Attacker goals and models

* **G1 – Device fingerprinting:** probe마다 도착하는 receipt 수를 세고, RTT를 cluster하여 OS/client(Android vs iOS vs desktop)를 추론하며, online/offline 전환을 관찰한다.
* **G2 – Behavioural monitoring:** 고주파 RTT series(≈1 Hz가 안정적)를 time-series로 취급해 screen on/off, app foreground/background, 출퇴근 vs 근무 시간 등을 추론한다.
* **G3 – Resource exhaustion:** 끝나지 않는 silent probe를 보내 각 피해자 device의 radio/CPU를 계속 깨워 battery/data를 소모시키고 VoIP/RTC 품질을 저하시킨다.

악용 표면을 설명하기 위해서는 두 종류의 threat actor면 충분하다:

1. **Creepy companion:** 이미 피해자와 chat을 공유하고 있으며, 기존 message ID에 연결된 self-reaction, reaction removal, 반복 edit/delete를 악용한다.
2. **Spooky stranger:** burner account를 등록하고 로컬 conversation에 존재하지 않았던 message ID를 참조하는 reaction을 보낸다. WhatsApp과 Signal은 UI가 state change를 버리더라도 이를 여전히 복호화하고 acknowledge하므로, 사전 conversation이 필요 없다.

## Tooling for raw protocol access

기본 E2EE protocol을 노출하는 client를 사용해 UI 제약 밖에서 packet을 만들고, 임의의 `message_id`를 지정하며, 정확한 timestamp를 기록하라:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) 또는 [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented)는 double-ratchet state를 동기화한 채 raw `ReactionMessage`, `ProtocolMessage` (edit/delete), `Receipt` frame을 전송할 수 있게 해준다.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)와 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)를 함께 쓰면 CLI/API를 통해 모든 message type에 접근할 수 있다. 현재 `signal-cli` syntax는 `sendReaction RECIPIENT --target-author --target-timestamp`를 사용한다; delivery receipt이 실제로 수집되도록 `receive` 또는 `daemon`을 실행 상태로 유지하라. self-reaction 토글 예시:
```bash
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --emoji "👍"
signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
--target-timestamp 1712345678901 --remove
```
* **Threema:** Android client의 source는 delivery receipt이 device를 떠나기 전에 어떻게 consolidated되는지 문서화하며, 이 side channel의 bandwidth가 왜 그곳에서는 사실상 무시할 수준인지 설명한다.
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal backend를 제공하고, 기본값으로 silent delete probe를 사용하며, rolling-median threshold(`RTT < 0.9 * median`)로 `active`와 `standby`를 구분한다. [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)은 `--delay`, `--concurrent`, CSV/Prometheus exporter, Grafana-friendly output을 갖춘 더 가벼운 WhatsApp-first CLI이다. 둘 다 protocol reference라기보다 reconnaissance helper로 보아야 한다. 핵심은 raw client access만 있으면 얼마나 적은 code로도 충분한지이다.

커스텀 tooling을 사용할 수 없더라도 WhatsApp Web이나 Signal Desktop에서 silent action을 유도하고 암호화된 websocket/WebRTC channel을 sniff할 수는 있지만, raw API는 UI 지연을 제거하고 invalid operation을 가능하게 한다.

## Creepy companion: silent sampling loop

1. chat에서 자신이 작성한 과거 message 하나를 골라라. 그러면 피해자는 "reaction" balloon이 바뀌는 것을 보지 못한다.
2. 보이는 emoji와 빈 reaction payload를 번갈아 보낸다(WhatsApp protobuf에서는 `""`, signal-cli에서는 `--remove`로 인코딩). 각 transmission은 피해자에게 UI 변화가 없어도 device ack를 생성한다.
3. send time과 모든 delivery receipt 도착 시각을 기록한다. 아래와 같은 1 Hz loop는 device별 RTT trace를 무한히 제공한다:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal은 무제한 reaction update를 허용하므로, 공격자는 새 chat content를 올리거나 edit window를 걱정할 필요가 없다.

## Spooky stranger: probing arbitrary phone numbers

1. 새 WhatsApp/Signal account를 등록하고 target number의 public identity key를 가져온다(session setup 중 자동으로 수행됨).
2. 당사자 어느 쪽에도 보인 적 없는 임의의 `message_id`를 참조하는 reaction/edit/delete packet을 만든다(WhatsApp은 arbitrary `key.id` GUID를 허용하고, Signal은 millisecond timestamp를 사용한다).
3. thread가 존재하지 않아도 packet을 보낸다. 피해자 device는 이를 복호화하고, base message와 매칭에 실패한 뒤 state change를 버리지만, incoming ciphertext는 여전히 acknowledge하므로 device receipt이 공격자에게 돌아간다.
4. 피해자의 chat list에 한 번도 나타나지 않으면서 RTT series를 만들기 위해 계속 반복한다.

먼저 어떤 number가 registered인지 알아내거나, 대규모로 device inventory를 미리 채워야 한다면, 무작정 random E.164 range를 추측하는 대신 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 연결하라.

최근 WhatsApp build는 `Settings -> Privacy -> Advanced -> Block unknown account messages`도 제공한다. 이것을 fix가 아니라 throughput limiter로 보아라. 주로 지속적인 stranger-only flooding을 어렵게 만들 뿐이며, 이미 known contact가 된 뒤에는 무의미하다.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 메시지가 한 번 `delete-for-everyone` 된 뒤에는, 같은 `message_id`를 참조하는 추가 delete packet이 UI에는 아무 영향도 주지 않지만 모든 device는 여전히 이를 복호화하고 acknowledge한다.
* **Out-of-window operations:** WhatsApp은 UI에서 약 60 h delete / 약 20 min edit window를 강제하고, Signal은 약 48 h를 강제한다. 이 window 밖에서 조작된 protocol message는 피해자 device에서 조용히 무시되지만 receipt은 전송되므로, conversation이 끝난 한참 뒤에도 공격자는 무한히 probe할 수 있다.
* **Invalid payloads:** 잘못된 edit body나 이미 purge된 message를 참조하는 delete도 같은 동작을 유발한다. 즉, 복호화 plus receipt, 사용자에게 보이는 artifact는 zero이다.

## Multi-device amplification & fingerprinting

* 연결된 각 device(phone, desktop app, browser companion)는 probe를 독립적으로 복호화하고 각자 ack를 반환한다. probe당 receipt 수를 세면 정확한 device 수를 알 수 있다.
* device가 offline이면 receipt이 queued되어 재연결 시 전송된다. 따라서 간격은 online/offline cycle과 심지어 commute schedule(예: 이동 중에는 desktop receipt이 멈춤)까지 leak한다.
* RTT 분포는 OS power management와 push wakeup 때문에 platform마다 다르다. RTT를 cluster(k-means의 median/variance feature 등)하여 "Android handset", "iOS handset", "Electron desktop" 등을 라벨링하라.
* sender는 encryption 전에 recipient의 key inventory를 가져와야 하므로, 공격자는 새로운 device가 pair되는 시점도 관찰할 수 있다. device 수의 급증이나 새로운 RTT cluster는 강한 지표다.

## Behaviour inference from RTT traces

1. OS scheduling 효과를 포착하려면 ≥1 Hz로 샘플링하라. iOS의 WhatsApp에서는 <1 s RTT가 screen-on/foreground와 강하게 상관되고, >1 s는 screen-off/background throttling과 상관된다.
2. 각 RTT를 "active" 또는 "idle"로 라벨링하는 단순 classifier(thresholding 또는 two-cluster k-means)를 만든다. 라벨을 streak로 집계해 bedtime, commute, work hours, desktop companion 활성 시간 등을 도출한다.
3. 모든 device를 향한 동시 probe를 상관분석하여 사용자가 mobile에서 desktop으로 전환하는 시점, companion이 offline 되는 시점, app이 push vs persistent socket에 의해 rate limited 되는지 확인한다.
4. 실제 network에서는 단일 hardcoded `1 s` threshold를 피하라. 각 device를 짧은 warm-up window로 bootstrap하고 rolling baseline(예: `threshold = 0.9 * median RTT`)을 유지해 Wi-Fi/cellular drift 때문에 classifier가 무너지지 않게 하라.

## Location inference from delivery RTT

같은 timing primitive는 상대가 active인지뿐 아니라 어디에 있는지도 추론하는 데 재사용할 수 있다. `Hope of Delivery` 연구는 알려진 수신자 위치에서의 RTT 분포로 training한 뒤, 나중에는 delivery confirmation만으로 피해자의 위치를 분류할 수 있음을 보였다:

* 피해자가 여러 알려진 장소(home, office, campus, country A vs country B 등)에 있을 때 같은 target에 대한 baseline을 구축한다.
* 각 위치마다 많은 normal message RTT를 수집하고 median, variance, percentile bucket 같은 간단한 feature를 추출한다.
* 실제 공격 중에는 새 probe series를 학습된 cluster와 비교한다. 논문은 같은 city 내 위치도 종종 구분 가능하며, 3-location 설정에서 `>80%` accuracy를 보고한다.
* 공격자가 sender environment를 통제하고 유사한 network condition에서 probe할 때 가장 잘 동작한다. 측정 경로에는 recipient access network, wake-up latency, messenger infrastructure가 포함되기 때문이다.

위의 silent reaction/edit/delete 공격과 달리, location inference는 invalid message ID나 stealthy state-changing packet을 요구하지 않는다. 일반 delivery confirmation이 있는 plain message만으로 충분하므로, stealth는 낮지만 다양한 messenger에 더 넓게 적용된다.

## Stealthy resource exhaustion

모든 silent probe는 복호화되고 acknowledge되어야 하므로, reaction toggle, invalid edit, delete-for-everyone packet을 계속 보내면 application-layer DoS가 된다:

* radio/modem이 매초 송수신하게 만들어 배터리 소모가 눈에 띄게 증가한다. 특히 idle handset에서 심하다.
* 측정되지 않는 upstream/downstream traffic을 발생시켜 TLS/WebSocket noise에 섞이면서도 mobile data plan을 소모한다.
* crypto thread를 점유하고 latency-sensitive feature(VoIP, video call)에 jitter를 유발하지만 사용자는 notification을 보지 못한다.
* WhatsApp에서는 invalid reaction이 일반 emoji가 암시하는 것보다 훨씬 많은 data를 받아들인다. 공개된 측정에서는 reaction당 서버 측 허용치가 대략 `1 MB`까지 보고되었다.
* oversized reaction은 body가 대략 `30 bytes`를 넘으면 신뢰할 수 있는 delivery receipt을 더 이상 만들지 않지만, discard되기 전까지는 여전히 전달되고 처리된다. ACK가 필요하면 reaction body는 작게 유지하라. 순수 drain이나 covert one-way transport가 목표일 때만 크게 부풀려라.
* 공개 측정은 이 모드에서 피해자 traffic이 약 `3.7 MB/s`(`~13.3 GB/h`)에 도달했음을 보였다.

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
