# Delivery Receipt Side-Channel Attacks in E2EE Messengers

{{#include ../banners/hacktricks-training.md}}

배달 확인(Delivery receipts)은 현대의 end-to-end encrypted (E2EE) 메신저에서 필수적입니다. 클라이언트는 ciphertext가 복호화된 시점을 알아야 ratcheting 상태와 일회성 키를 폐기할 수 있기 때문입니다. 서버는 불투명한 블롭을 전달하므로, 기기 응답(더블 체크마크)은 수신자가 복호화에 성공한 후에 전송됩니다. 공격자가 유발한 동작과 이에 대응하는 delivery receipt 간의 왕복 시간(RTT)을 측정하면 고해상도 타이밍 채널이 device state, 온라인 존재 상태를 leaks하고 은밀한 DoS에 악용될 수 있습니다. Multi-device "client-fanout" 배포는 모든 등록된 장치가 probe를 복호화하고 자체 receipt를 반환하기 때문에 leakage를 증폭시킵니다.

## Delivery receipt sources vs. user-visible signals

항상 delivery receipt를 발행하지만 피해자 UI에 아티팩트를 남기지 않는 메시지 타입을 선택하세요. 아래 표는 실험적으로 확인된 동작을 요약합니다:

| Messenger | Action | Delivery receipt | Victim notification | Notes |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | Text message | ● | ● | 항상 노이즈가 있음 → 상태 부트스트랩 용도로만 유용. |
| | Reaction | ● | ◐ (only if reacting to victim message) | Self-reactions와 제거는 조용함. |
| | Edit | ● | Platform-dependent silent push | 편집 창 ≈20분; 만료 후에도 ack 됨. |
| | Delete for everyone | ● | ○ | UI는 ~60시간 허용하지만 이후 패킷도 ack 됨. |
| **Signal** | Text message | ● | ● | WhatsApp과 동일한 제한. |
| | Reaction | ● | ◐ | Self-reactions는 피해자에게 보이지 않음. |
| | Edit/Delete | ● | ○ | 서버는 약 48시간 창을 강제하며 최대 10회 편집 허용, 지연된 패킷도 ack 됨. |
| **Threema** | Text message | ● | ● | Multi-device receipts가 집계되므로 probe당 가시화되는 RTT는 하나뿐임. |

Legend: ● = 항상, ◐ = 조건부, ○ = 절대 없음. 플랫폼 의존 UI 동작은 괄호 내에 표기했습니다. read receipts를 비활성화할 수는 있지만, WhatsApp이나 Signal에서는 delivery receipts는 끌 수 없습니다.

## Attacker goals and models

* **G1 – Device fingerprinting:** probe 당 도착하는 receipt 수를 세고, RTT를 클러스터링하여 OS/클라이언트(Android vs iOS vs desktop)를 추정하며 온라인/오프라인 전환을 관찰합니다.
* **G2 – Behavioural monitoring:** 고주파 RTT 시계열(≈1 Hz가 안정적)을 시계열로 취급하여 화면 켜짐/꺼짐, 앱 전경/백그라운드, 통근 시간 vs 근무 시간 등을 추론합니다.
* **G3 – Resource exhaustion:** 끝없이 silent probe를 보내 모든 피해자 장치의 라디오/CPU를 깨어있게 만들어 배터리/데이터를 소모시키고 VoIP/RTC 품질을 저하시킵니다.

위 남용 표면을 설명하기 위해 두 가지 위협 행위자가 충분합니다:

1. **Creepy companion:** 이미 피해자와 채팅을 공유하고 있으며 self-reactions, reaction removals, 또는 기존 메시지 ID에 묶인 반복적인 edits/deletes를 악용합니다.
2. **Spooky stranger:** burner 계정을 등록하고 로컬 대화에 존재하지 않는 message IDs를 참조하는 reactions을 보냅니다; WhatsApp과 Signal은 UI가 상태 변경을 폐기하더라도 이를 복호화하고 인정하므로 사전 대화가 필요하지 않습니다.

## Tooling for raw protocol access

UI 제약 밖에서 패킷을 제작하고 임의의 `message_id`를 지정하며 정밀한 타임스탬프를 로깅하려면 기본 E2EE 프로토콜을 노출하는 클라이언트를 사용하세요:

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow) (Go, WhatsApp Web protocol) 또는 [Cobalt](https://github.com/Auties00/Cobalt) (모바일 지향)은 double-ratchet 상태를 동기화한 상태에서 raw `ReactionMessage`, `ProtocolMessage` (edit/delete), 및 `Receipt` 프레임을 전송할 수 있게 합니다.
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)와 [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)를 결합하면 모든 메시지 타입을 CLI/API로 노출합니다. 예제 self-reaction 토글:
```bash
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --emoji "👍"
signal-cli -u +12025550100 sendReaction --target +12025550123 \
--message-timestamp 1712345678901 --remove  # encodes empty emoji
```
* **Threema:** Android 클라이언트의 소스는 delivery receipts가 기기를 떠나기 전에 어떻게 통합되는지 문서화하고 있어, 그쪽에서는 사이드 채널의 대역폭이 거의 없음을 설명합니다.

커스텀 툴이 없을 때는 WhatsApp Web 또는 Signal Desktop에서 silent action을 트리거하고 암호화된 websocket/WebRTC 채널을 스니핑할 수 있지만, raw API는 UI 지연을 제거하고 유효하지 않은 동작을 허용합니다.

## Creepy companion: silent sampling loop

1. 피해자가 변경 사항을 보지 않도록 채팅에서 본인이 작성한 과거 메시지를 하나 선택합니다.
2. 가시적인 이모지와 빈 reaction 페이로드(WhatsApp protobuf에서는 `""`로, signal-cli에서는 `--remove`로 인코딩)를 번갈아 전송합니다. 각 전송은 피해자에게 UI 변화가 없어도 장치 ack를 생성합니다.
3. 전송 시간과 모든 delivery receipt 도착 시각을 타임스탬프합니다. 다음과 같은 1 Hz 루프는 장치별 RTT 트레이스를 무기한 제공합니다:
```python
while True:
send_reaction(msg_id, "👍")
log_receipts()
send_reaction(msg_id, "")  # removal
log_receipts()
time.sleep(0.5)
```
4. WhatsApp/Signal이 무제한 reaction 업데이트를 허용하므로 공격자는 새 채팅 내용을 올리거나 편집 창을 걱정할 필요가 없습니다.

## Spooky stranger: probing arbitrary phone numbers

1. 새 WhatsApp/Signal 계정을 등록하고 대상 번호의 공개 identity keys를 가져옵니다(세션 설정 중 자동으로 수행).
2. 양 당사자가 본 적이 없는 임의의 `message_id`를 참조하는 reaction/edit/delete 패킷을 제작합니다(WhatsApp은 임의의 `key.id` GUID를 허용; Signal은 밀리초 타임스탬프를 사용).
3. 스레드가 없어도 패킷을 전송합니다. 피해자 장치는 이를 복호화하고 원본 메시지와 매치에 실패해 상태 변경을 폐기하지만, 여전히 들어온 ciphertext를 인정하여 기기 receipts를 공격자에게 보냅니다.
4. 채팅 목록에 나타나지 않고도 RTT 시리즈를 구축하기 위해 이를 연속적으로 반복합니다.

## Recycling edits and deletes as covert triggers

* **Repeated deletes:** 메시지가 한 번 delete-for-everyone 된 후에도 동일한 `message_id`를 참조하는 추가 delete 패킷은 UI에 영향이 없지만 모든 장치는 여전히 이를 복호화하고 인정합니다.
* **Out-of-window operations:** WhatsApp은 UI에서 약 60시간 삭제 / 약 20분 편집 창을 강제하며 Signal은 약 48시간을 강제합니다. 이 창 밖에서 제작된 프로토콜 메시지는 피해자 기기에서 조용히 무시되지만 receipts는 전송되므로 공격자는 대화가 끝난 이후에도 무기한으로 프로브할 수 있습니다.
* **Invalid payloads:** 잘못된 편집 본문이나 이미 정리된 메시지를 참조하는 삭제는 동일한 동작—복호화 후 receipt 전송, 사용자에게는 전혀 보이지 않음—을 유발합니다.

## Multi-device amplification & fingerprinting

* 연결된 각 장치(전화, 데스크톱 앱, 브라우저 동반자)는 probe를 개별적으로 복호화하고 자체 ack를 반환합니다. probe당 receipt 수를 세면 정확한 장치 수가 드러납니다.
* 장치가 오프라인이면 그 receipt는 큐에 쌓여 재접속 시 전송됩니다. 따라서 간격은 온라인/오프라인 사이클과 심지어 통근 일정(예: 여행 중 데스크톱 receipt 중단)을 leaks합니다.
* RTT 분포는 OS 전원 관리와 푸시 웨이크업 차이로 플랫폼별로 다릅니다. median/variance 특성에 대해 k-means 같은 클러스터링을 수행하면 “Android handset”, “iOS handset”, “Electron desktop” 등을 라벨링할 수 있습니다.
* 송신자는 암호화 전에 수신자의 key inventory를 조회해야 하므로 공격자는 새 장치가 페어링될 때를 감시할 수도 있습니다; 장치 수의 급격한 증가나 새로운 RTT 클러스터는 강력한 지표입니다.

## Behaviour inference from RTT traces

1. OS 스케줄링 효과를 포착하려면 ≥1 Hz로 샘플링하세요. WhatsApp on iOS의 경우 <1 s RTT는 화면 켜짐/전경과 강하게 상관하고, >1 s는 화면 꺼짐/백그라운드 스로틀링과 상관합니다.
2. 간단한 분류기(임계값 기반 또는 두 클러스터 k-means)를 만들어 각 RTT를 "active" 또는 "idle"로 라벨링하세요. 라벨을 연속 구간으로 집계해 취침 시간, 통근, 근무 시간, 혹은 데스크톱 동반자가 활성화된 시점을 도출합니다.
3. 모든 장치에 동시 프로브를 연관시켜 사용자가 모바일에서 데스크톱으로 전환할 때, 동반자가 오프라인이 될 때, 앱이 푸시 대기와 영구 소켓 중 어느 쪽으로 제한되는지를 확인하세요.

## Stealthy resource exhaustion

모든 silent probe는 복호화되고 인정되어야 하므로 reaction 토글, 잘못된 편집, delete-for-everyone 패킷을 지속적으로 전송하면 애플리케이션 계층 DoS를 발생시킵니다:

* 라디오/모뎀이 매초 전송/수신하도록 강제 → 특히 유휴 핸드셋에서 눈에 띄는 배터리 소모.
* TLS/WebSocket 잡음에 섞여 모바일 데이터 요금제를 소모하는 무계량 업스트림/다운스트림 트래픽 생성.
* 암호화 스레드를 점유하고 지연 민감 기능(VoIP, 영상 통화)에 지터를 유발, 사용자는 알지 못함.

## References

- [Careless Whisper: Exploiting Silent Delivery Receipts to Monitor Users on Mobile Instant Messengers](https://arxiv.org/html/2411.11194v4)
- [whatsmeow](https://github.com/tulir/whatsmeow)
- [Cobalt](https://github.com/Auties00/Cobalt)
- [signal-cli](https://github.com/AsamK/signal-cli)
- [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)

{{#include ../banners/hacktricks-training.md}}
