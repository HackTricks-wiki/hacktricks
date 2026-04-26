# E2EE 메신저의 Delivery Receipt Side-Channel Attacks

{{#include ../banners/hacktricks-training.md}}

Delivery receipts는 현대의 end-to-end encrypted (E2EE) 메신저에서 필수적이다. 클라이언트는 ciphertext가 언제 복호화되었는지 알아야 ratcheting state와 ephemeral keys를 폐기할 수 있기 때문이다. 서버는 opaque blobs만 전달하므로, device acknowledgements(double checkmarks)는 성공적인 복호화 후 수신자에 의해 전송된다. 공격자가 유도한 동작과 대응하는 delivery receipt 사이의 round-trip time (RTT)을 측정하면, 디바이스 상태, online presence를 leak하는 고해상도 타이밍 채널이 드러나며, covert DoS에도 악용될 수 있다. Multi-device "client-fanout" 배포에서는 각 등록된 device가 probe를 복호화하고 자신의 receipt를 반환하므로 leak이 증폭된다.

## Delivery receipt sources vs. user-visible signals

피해자에게 UI artifact를 노출하지 않으면서도 항상 delivery receipt를 발생시키는 message types를 선택하라. 아래 표는 실험적으로 확인된 동작을 요약한 것이다:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 noisy → state bootstrap에만 유용하다. |
| | Reaction | ● | ◐ (victim message에 반응한 경우에만) | Self-reactions와 removals는 조용히 유지된다. |
| | Edit | ● | Platform-dependent silent push | Edit window ≈20 min; 만료 후에도 여전히 ack’d 된다. |
| | Delete for everyone | ● | ○ | UI는 ~60 h를 허용하지만, 그 이후 패킷도 여전히 ack’d 된다. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한이 있다. |
| | Reaction | ● | ◐ | Self-reactions는 피해자에게 보이지 않는다. |
| | Edit/Delete | ● | ○ | Server가 ~48 h window를 강제하고, 최대 10 edits를 허용하지만, 늦은 패킷도 여전히 ack’d 된다. |
| **Threema** | Text message | ● | ● | Multi-device receipts가 집계되므로, probe당 RTT는 하나만 보인다. |

Legend: ● = always, ◐ = conditional, ○ = never. Platform-dependent UI behaviour는 인라인으로 표시했다. 필요하면 read receipts를 끄되, delivery receipts는 WhatsApp이나 Signal에서 끌 수 없다.

## Attacker goals and models

* **G1 – Device fingerprinting:** probe당 몇 개의 receipt가 도착하는지 세고, RTT를 cluster하여 OS/client(Android vs iOS vs desktop)를 추론하며, online/offline 전환을 관찰한다.
* **G2 – Behavioural monitoring:** 고주파 RTT series(≈1 Hz가 안정적)를 time-series로 취급해 screen on/off, app foreground/background, commuting vs working hours 등을 추론한다.
* **G3 – Resource exhaustion:** 끝없이 silent probes를 보내 각 피해자 device의 radio/CPU를 깨워두고, battery/data를 소모시키며 VoIP/RTC 품질을 저하시킨다.

오남용 공격면을 설명하기 위해서는 두 종류의 threat actor면 충분하다:

1. **Creepy companion:** 이미 피해자와 채팅을 공유하고 있으며, 기존 message IDs에 묶인 self-reactions, reaction removals, 또는 반복적인 edits/deletes를 악용한다.
2. **Spooky stranger:** burner account를 등록하고, local conversation에 존재하지 않았던 message IDs를 참조하는 reactions를 보낸다. WhatsApp과 Signal은 UI가 상태 변경을 버리더라도 여전히 이를 복호화하고 acknowledge하므로, 사전 대화가 필요 없다.

## Tooling for raw protocol access

기본 E2EE protocol을 노출하는 client에 의존하면, UI 제약 밖에서 packet을 만들고, 임의의 `message_id`s를 지정하며, 정확한 timestamp를 기록할 수 있다:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) 또는 [Cobalt](https://github.com/Auties00/Cobalt) (mobile-oriented)는 double-ratchet state를 동기화한 채 raw `ReactionMessage`, `ProtocolMessage` (edit/delete), `Receipt` frame을 전송할 수 있게 해준다.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)와 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)는 CLI/API를 통해 모든 message type을 노출한다. 예시 self-reaction toggle:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android client의 source는 delivery receipts가 device를 떠나기 전에 어떻게 consolidated되는지 문서화하고 있으며, 이것이 side channel의 bandwidth가 왜 그곳에서 무시할 만한 수준인지 설명한다.
* **Turnkey PoCs:** `device-activity-tracker`와 `careless-whisper-python` 같은 공개 프로젝트는 이미 silent delete/reaction probes와 RTT classification을 자동화한다. 이를 protocol reference라기보다는 바로 쓸 수 있는 reconnaissance helper로 보아야 한다. 중요한 점은 raw client access만 있으면 공격이 operationally simple하다는 사실을 이들이 확인해 준다는 것이다.

맞춤형 tooling이 없더라도, WhatsApp Web이나 Signal Desktop에서 여전히 silent action을 유발하고 encrypted websocket/WebRTC channel을 sniff할 수 있다. 하지만 raw API는 UI 지연을 제거하고 invalid operations를 허용한다.

## Creepy companion: silent sampling loop

1. 채팅에서 자신이 작성한 과거 메시지 아무거나 선택해 피해자가 "reaction" balloon 변경을 보지 못하게 한다.
2. 보이는 emoji와 빈 reaction payload(WhatsApp protobufs에서는 `""`, signal-cli에서는 `--remove`로 인코딩됨)를 번갈아 보낸다. 각 전송은 피해자에게 UI delta가 없어도 device ack를 생성한다.
3. 전송 시각과 모든 delivery receipt 도착 시각을 기록한다. 다음과 같은 1 Hz loop는 device별 RTT trace를 무기한 제공한다:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal은 무제한 reaction update를 허용하므로, 공격자는 새 chat content를 올릴 필요도 없고 edit window를 걱정할 필요도 없다.

## Spooky stranger: probing arbitrary phone numbers

1. 새로운 WhatsApp/Signal account를 등록하고 대상 번호의 public identity keys를 가져온다(session setup 중 자동으로 수행됨).
2. 어느 쪽에서도 본 적 없는 임의의 `message_id`를 참조하는 reaction/edit/delete packet을 만든다. (WhatsApp은 임의의 `key.id` GUID를 허용하고, Signal은 millisecond timestamps를 사용한다.)
3. thread가 존재하지 않아도 packet을 전송한다. 피해자 device는 이를 복호화하고, base message를 매칭하지 못해 state change를 버리지만, 들어온 ciphertext는 여전히 acknowledge하여 device receipts를 공격자에게 되돌려 보낸다.
4. 이를 계속 반복해 피해자 chat list에 나타나지 않으면서 RTT series를 구축한다.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 메시지가 한 번 delete-for-everyone 된 뒤에는, 동일한 `message_id`를 참조하는 추가 delete packet이 UI에는 영향을 주지 않지만 각 device는 여전히 이를 복호화하고 acknowledge한다.
* **Out-of-window operations:** WhatsApp은 UI에서 ~60 h delete / ~20 min edit window를 강제한다. Signal은 ~48 h를 강제한다. 이 window 밖에서 만들어진 protocol messages는 피해자 device에서 조용히 무시되지만 receipt는 전송되므로, 대화가 끝난 한참 뒤에도 공격자는 무한히 probe할 수 있다.
* **Invalid payloads:** 이미 purged된 메시지를 참조하는 malformed edit body나 delete도 같은 동작을 유발한다—복호화와 receipt, 사용자에게 보이는 artifact는 0개.

## Multi-device amplification & fingerprinting

* 연결된 각 device(phone, desktop app, browser companion)는 probe를 독립적으로 복호화하고 자신의 ack를 반환한다. probe당 receipt 수를 세면 정확한 device 수가 드러난다.
* device가 offline이면 receipt는 queued 되었다가 재연결 시 전송된다. 따라서 gap은 online/offline cycle과, 심지어 commuting schedule(예: travel 중 desktop receipts 중단)까지 leak한다.
* RTT 분포는 OS power management와 push wakeup 때문에 platform별로 다르다. RTT를 cluster(k-means on median/variance features 등)하여 “Android handset", “iOS handset", “Electron desktop", 등을 라벨링하라.
* sender는 encrypt 전에 recipient의 key inventory를 가져와야 하므로, 공격자는 새 device가 pair되는 시점도 관찰할 수 있다. device 수의 급증이나 새로운 RTT cluster는 강한 지표다.

## Behaviour inference from RTT traces

1. OS scheduling effects를 포착하기 위해 ≥1 Hz로 샘플링한다. WhatsApp on iOS에서는 <1 s RTT가 screen-on/foreground와 강하게 상관되고, >1 s는 screen-off/background throttling과 상관된다.
2. 각 RTT를 "active" 또는 "idle"로 라벨링하는 단순 classifier(thresholding 또는 two-cluster k-means)를 만든다. 라벨을 streak로 집계해 bedtime, commute, work hours, 또는 desktop companion이 활성화되는 시점을 추론한다.
3. 모든 device를 향한 동시 probe를 상관분석해 사용자가 mobile에서 desktop으로 전환하는 시점, companions가 offline 되는 시점, app이 push vs persistent socket 때문에 rate limited 되는지 확인한다.

## Location inference from delivery RTT

같은 타이밍 primitive는 수신자가 active인지 여부뿐 아니라 어디에 있는지도 추론하는 데 재사용될 수 있다. `Hope of Delivery` 연구는 알려진 수신자 위치의 RTT 분포로 training하면, 나중에 공격자가 delivery confirmations만으로 피해자의 위치를 분류할 수 있음을 보여주었다:

* 대상이 여러 알려진 장소(home, office, campus, country A vs country B 등)에 있을 때 동일한 target에 대한 baseline을 만든다.
* 각 위치마다 많은 정상 message RTT를 수집하고, median, variance, percentile bucket 같은 단순 feature를 추출한다.
* 실제 공격 중에는 새 probe series를 학습된 cluster와 비교한다. 논문은 같은 도시 내부의 위치도 종종 구분 가능하며, 3-location 설정에서 `>80%` accuracy를 보고한다.
* 이는 공격자가 sender environment를 제어하고 유사한 network conditions에서 probe할 때 가장 잘 동작한다. 측정된 path에는 recipient access network, wake-up latency, messenger infrastructure가 포함되기 때문이다.

위의 silent reaction/edit/delete 공격과 달리, location inference는 invalid message IDs나 stealthy state-changing packet을 요구하지 않는다. 정상 delivery confirmation이 있는 plain message만으로 충분하므로, stealth는 낮지만 다양한 messenger에 더 넓게 적용된다.

## Stealthy resource exhaustion

각 silent probe는 복호화되고 acknowledge되어야 하므로, reaction toggle, invalid edit, delete-for-everyone packet을 계속 보내면 application-layer DoS가 발생한다:

* radio/modem이 매초 송수신하도록 강제한다 → 특히 idle handset에서 눈에 띄는 battery drain.
* TLS/WebSocket noise에 섞여 보이면서 mobile data plan을 소모하는 unmetered upstream/downstream traffic을 생성한다.
* 사용자는 아무 notification도 보지 못하지만 crypto thread를 점유하고 latency-sensitive feature(VoIP, video calls)에 jitter를 유발한다.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [Hope of Delivery: Extracting User Locations From Mobile Instant Messengers](https://www.ndss-symposium.org/wp-content/uploads/2023-188-paper.pdf)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)
- [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)

{{#include ../banners/hacktricks-training.md}}
