# E2EE 메신저의 전달 확인 사이드 채널 공격

{{#include ../banners/hacktricks-training.md}}

최신 종단간 암호화(E2EE) 메신저에서는 클라이언트가 암호문이 복호화된 시점을 알아야 래칫 상태와 임시 키를 폐기할 수 있으므로 전달 확인이 필수입니다. 서버는 불투명한 데이터 블롭을 전달하므로, 수신자가 성공적으로 복호화한 후 기기 확인(이중 체크 표시)을 보냅니다. 공격자가 유발한 동작과 그에 대응하는 전달 확인 사이의 왕복 시간(RTT)을 측정하면 고해상도 타이밍 채널이 드러나 기기 상태와 온라인 여부가 leak되며, 은밀한 DoS에도 악용될 수 있습니다. 여러 기기에 메시지를 전달하는 "client-fanout" 배포 방식은 등록된 모든 기기가 프로브를 복호화하고 각자 확인을 반환하므로 leak을 증폭합니다.<sup>[[1]](#references)</sup>

## 전달 확인의 출처와 사용자에게 보이는 신호

전달 확인은 항상 보내지만 피해자에게 UI 흔적은 남기지 않는 메시지 유형을 선택하세요. 아래 표는 실험으로 확인된 동작을 요약합니다.<sup>[[1]](#references)</sup>

| 메신저 | 동작 | 전달 확인 | 피해자 알림 | 참고 |
|-----------|--------|------------------|---------------------|-------|
| **WhatsApp** | 문자 메시지 | ● | ● | 항상 흔적이 남으므로 상태 파악을 위한 초기 단계에만 유용합니다. |
| | 리액션 | ● | ◐ (피해자의 메시지에 리액션한 경우에만) | 자기 메시지에 대한 리액션과 리액션 취소는 표시되지 않습니다. |
| | 편집 | ● | 플랫폼에 따라 조용한 푸시 알림 | 편집 가능 시간은 약 20분이며, 만료 후에도 확인이 반환됩니다. |
| | 모두에게서 삭제 | ● | ○ | UI에서는 약 60시간 동안 가능하지만, 이후 패킷도 확인됩니다. |
| **Signal** | 문자 메시지 | ● | ● | WhatsApp과 같은 제한이 있습니다. |
| | 리액션 | ● | ◐ | 피해자에게 자기 메시지에 대한 리액션은 표시되지 않습니다. |
| | 편집/삭제 | ● | ○ | 서버는 약 48시간의 제한을 적용하고 최대 10회까지 편집을 허용하지만, 늦게 도착한 패킷도 확인됩니다. |
| **Threema** | 문자 메시지 | ● | ● | 여러 기기의 확인이 통합되므로 프로브당 RTT 하나만 확인할 수 있습니다. |

범례: ● = 항상, ◐ = 조건부, ○ = 없음. 플랫폼에 따라 다른 UI 동작은 표에 표시했습니다. 필요하면 읽음 확인을 비활성화할 수 있지만 WhatsApp이나 Signal에서는 전달 확인을 끌 수 없습니다.<sup>[[1]](#references)</sup>

## 공격자의 목표와 모델

* **G1 – 기기 핑거프린팅:** 프로브당 도착하는 확인 수를 세고 RTT를 군집화해 OS/클라이언트(Android, iOS, 데스크톱)를 추론하며, 온라인/오프라인 전환을 감시합니다.
* **G2 – 행동 모니터링:** 고빈도 RTT 시계열(약 1Hz가 안정적)을 분석해 화면 켜짐/꺼짐, 앱의 포그라운드/백그라운드 상태, 출퇴근 시간과 근무 시간 등을 추론합니다.
* **G3 – 리소스 고갈:** 끝없이 조용한 프로브를 보내 피해자의 모든 기기에서 무선 통신 모듈과 CPU가 깨어 있도록 해 배터리와 데이터를 소모시키고 영상 통화 품질을 저하시킵니다.<sup>[[1]](#references)</sup>

악용 가능 범위는 다음 두 종류의 공격자로 충분히 설명할 수 있습니다.<sup>[[1]](#references)</sup>

1. **소름 끼치는 지인:** 이미 피해자와 채팅을 공유하고 있으며, 자기 메시지에 대한 리액션, 리액션 취소 또는 기존 메시지 ID에 연결된 반복적인 편집/삭제를 악용합니다.
2. **수상한 낯선 사람:** 버너 계정을 등록하고 로컬 대화에 존재하지 않았던 메시지 ID를 참조하는 리액션을 보냅니다. WhatsApp과 Signal은 UI에서 상태 변경을 버리더라도 해당 내용을 복호화하고 확인을 반환하므로 이전 대화가 필요하지 않습니다.

## 원시 프로토콜 액세스 도구

UI 제약을 벗어나 지원되는 패킷을 만들고 정확한 타임스탬프를 기록할 수 있도록, 기본 E2EE 프로토콜을 충분히 노출하는 클라이언트를 사용하세요. 임의의 메시지 ID를 사용할 수 있는지는 구현마다 확인해야 합니다.

* **WhatsApp:** [whatsmeow](https://github.com/tulir/whatsmeow)(Go, WhatsApp Web 멀티디바이스 API)는 전달 확인 송수신을 문서화합니다. [Cobalt](https://github.com/Auties00/Cobalt)(비공식 Java/Kotlin Web 및 모바일 API)는 리액션, 편집, 삭제와 같은 메시지 작업을 문서화합니다. 모든 내부 프레임이 노출된다고 가정하지 말고 문서화된 API를 사용하세요.<sup>[[3]](#references)[[4]](#references)</sup>
* **Signal:** [signal-cli](https://github.com/AsamK/signal-cli)는 CLI, JSON-RPC, D-Bus 인터페이스를 제공하며, [libsignal-service-java](https://github.com/signalapp/libsignal-service-java)는 Signal과 통신하기 위한 Java 라이브러리입니다.<sup>[[5]](#references)[[7]](#references)</sup> 현재 `signal-cli` 문법은 `sendReaction RECIPIENT --target-author --target-timestamp`입니다. 프로토콜 업데이트가 계속 처리되도록 `receive` 또는 `daemon`을 실행 상태로 유지하세요.<sup>[[6]](#references)</sup> 자기 메시지에 대한 리액션을 토글하는 예:
  ```bash
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --emoji "👍"
  signal-cli -a +12025550100 sendReaction +12025550123 --target-author +12025550100 \
      --target-timestamp 1712345678901 --remove
  ```
* **Threema:** Careless Whisper 논문의 측정 결과, 전달 확인은 기기 간 동기화되므로 여러 기기를 사용하는 환경에서도 메시지당 확인은 하나만 노출됩니다.<sup>[[1]](#references)</sup>
* **Turnkey PoCs:** [device-activity-tracker](https://github.com/gommzystudio/device-activity-tracker)는 WhatsApp/Signal 백엔드를 제공하고, 기본적으로 조용한 삭제 probe를 사용하며, 이동 중앙값 임계값(`RTT < 0.9 * median`)으로 `active`와 `standby`를 구분합니다.<sup>[[8]](#references)</sup> [careless-whisper-python](https://github.com/ctrlsam/careless-whisper-python)는 WhatsApp을 우선 지원하는 더 가벼운 CLI로, `--delay`, `--concurrent`, CSV/Prometheus exporter, Grafana에 적합한 출력을 제공합니다.<sup>[[9]](#references)</sup> 두 도구 모두 프로토콜 참고 자료가 아니라 정찰 보조 도구로 취급하세요. 중요한 점은 raw client에 접근할 수 있으면 얼마나 적은 코드만으로도 충분한지입니다.

맞춤형 도구를 사용할 수 없는 경우에도 공식 클라이언트나 브라우저 개발자 도구로 조용한 작업을 실행하고 암호화된 트래픽의 타이밍을 노출할 수 있습니다. raw API를 사용하면 UI 지연이 사라지고 유효하지 않은 작업도 실행할 수 있습니다.<sup>[[1]](#references)</sup>

## 소름 끼치는 보조 도구: 조용한 샘플링 루프

1. 채팅에서 자신이 작성한 과거 메시지를 아무거나 선택해 피해자에게 "reaction" 말풍선이 바뀌는 모습이 보이지 않도록 합니다.
2. 눈에 보이는 이모지와 빈 reaction payload를 번갈아 전송합니다(WhatsApp protobuf에서는 `""`로 인코딩하고, signal-cli에서는 `--remove`를 사용). 피해자에게 UI 변화가 없어도 전송할 때마다 기기 ack가 발생합니다.
3. 전송 시각과 각 전달 확인의 도착 시각을 기록합니다. 다음과 같은 1 Hz 루프를 사용하면 기기별 RTT trace를 무기한 얻을 수 있습니다:
   ```python
   while True:
       send_reaction(msg_id, "👍")
       log_receipts()
       send_reaction(msg_id, "")  # removal
       log_receipts()
       time.sleep(0.5)
   ```
4. WhatsApp/Signal은 반응 업데이트를 무제한으로 허용하므로, 공격자는 새 채팅 내용을 게시하거나 편집 가능 시간 제한을 걱정할 필요가 없습니다.<sup>[[1]](#references)</sup>

## 으스스한 낯선 사람: 임의의 전화번호 탐색

1. 새 WhatsApp/Signal 계정을 등록하고 대상 번호의 공개 identity key를 가져옵니다(세션 설정 중 자동으로 수행됨).
2. 어느 쪽도 본 적 없는 임의의 `message_id`를 참조하는 reaction packet을 만듭니다. 논문에 따르면 WhatsApp과 Signal은 이러한 reaction을 모두 수락하고 delivery receipt도 생성합니다.<sup>[[1]](#references)</sup>
3. thread가 없어도 packet을 전송합니다. 피해자 기기는 이를 decrypt하지만 base message와 일치하지 않아 state 변경을 폐기합니다. 그래도 수신한 ciphertext를 acknowledge하고, device receipt를 공격자에게 다시 보냅니다.
4. 이전 대화나 눈에 보이는 알림 없이 RTT 시리즈를 만들도록 계속 반복합니다.<sup>[[1]](#references)</sup>

If 먼저 어떤 번호가 등록되어 있는지 알아내거나 대규모로 기기 인벤토리를 미리 구축하려면, 임의의 E.164 범위를 직접 추측하는 대신 [contact-discovery / registration oracles](../pentesting-web/registration-vulnerabilities.md)와 연계하세요.

공개된 contact-discovery 연구는 이것이 실무적으로 중요한 이유를 보여 주었습니다. 정확한 전화번호 접두사 테이블과 적당한 리소스를 사용해 연구자들은 표적 프로빙으로 넘어가기 전에 WhatsApp에서는 미국 휴대전화 번호의 약 `10%`, Signal에서는 `100%`를 조회할 수 있었습니다.<sup>[[11]](#references)</sup> 실제로는 활성 계정을 먼저 사전 필터링하면 silent-probe 예산을 실제로 패킷을 복호화할 번호에 집중할 수 있습니다.

최신 WhatsApp 빌드에는 `설정 -> 개인정보 보호 -> 고급 -> 알 수 없는 계정의 메시지 차단`도 있습니다.<sup>[[10]](#references)</sup> 처리량 제한 장치로 간주하세요. tracker 문서에 따르면 WhatsApp은 알 수 없는 계정에서 오는 대량 메시지를 차단하지만, 임계값은 공개하지 않으므로 probe 반응을 완전히 방지하지는 못합니다.<sup>[[8]](#references)</sup>

## 은밀한 트리거로 재활용되는 편집 및 삭제

* **반복 삭제:** 메시지를 모든 사용자에게서 한 번 삭제한 뒤에는, 같은 `message_id`를 참조하는 추가 삭제 패킷이 UI에 아무런 영향을 주지 않지만 모든 기기는 여전히 이를 복호화하고 확인 응답을 보냅니다.
* **허용 시간 범위 밖의 작업:** WhatsApp은 UI에서 삭제 가능 시간을 약 60시간, 편집 가능 시간을 약 20분으로 제한하며, Signal은 약 48시간으로 제한합니다. 이 시간 범위를 벗어난 조작된 프로토콜 메시지는 피해자 기기에서 조용히 무시되지만 확인 응답은 전송되므로, 대화가 끝난 뒤에도 공격자는 무기한으로 탐색할 수 있습니다.
* **유효하지 않은 payload:** 논문에 따르면 유효하지 않은 메시지도 확인 응답을 받을 수 있습니다. 형식이 잘못된 본문이나 제거된 ID의 정확한 동작은 구현에 따라 다르므로, 이에 의존하기 전에 테스트하세요.<sup>[[1]](#references)</sup>

## Multi-device 증폭 및 fingerprinting

* WhatsApp과 Signal에서는 연결된 각 기기(휴대폰, 데스크톱 앱, 브라우저 companion)가 probe를 독립적으로 복호화하고 자체 ack를 반환합니다. probe별 receipt 수를 세면 정확한 기기 수를 알 수 있습니다.<sup>[[1]](#references)</sup>
* 기기가 오프라인이면 receipt가 대기열에 추가되었다가 다시 연결될 때 전송됩니다. 따라서 연결/해제 주기가 leak되며, 통근 일정까지 드러날 수 있습니다(예: 이동 중에는 데스크톱 receipt 전송이 중단됨).
* OS, 모델, 클라이언트, 네트워크 상태가 타이밍에 영향을 주므로 플랫폼과 환경에 따라 RTT 분포가 달라집니다. RTT를 클러스터링하면(예: 중앙값/분산 특성에 k-means 적용) “Android 단말”, “iOS 단말”, “Electron 데스크톱” 등으로 분류할 수 있습니다.
* 발신자는 암호화 전에 수신자의 키 인벤토리를 가져와야 하므로, 공격자는 새 기기가 페어링되는 시점도 관찰할 수 있습니다. 기기 수가 갑자기 늘거나 새 RTT 클러스터가 나타나면 강력한 징후입니다.<sup>[[1]](#references)</sup>

**대기열에 쌓인 receipt로 fingerprinting:** 대상 기기가 오프라인일 때 서로 다른 message ID를 사용해 여러 probe를 보냅니다. 기기가 다시 연결되면 반환된 delivery receipt에서 ID를 대조해 ID가 각각 별도의 receipt로 반환되는지, 하나의 receipt에 묶이는지, 그리고 묶인 ID의 순서가 전송 순서를 유지하는지 아니면 뒤집히는지 확인합니다. 테스트한 클라이언트 중 WhatsApp Android/iOS는 별도의 delivery receipt를 반환했지만, Web, Windows, macOS는 ID를 묶어 반환했습니다. macOS는 묶인 순서를 뒤집었습니다. Signal Desktop도 모바일 클라이언트와 달리 receipt를 묶어 반환했습니다. 이 방법을 사용하면 RTT 분포가 겹치는 경우에도 다시 연결되는 클라이언트를 분류할 수 있습니다. delivery receipt를 read receipt와 혼동하지 마세요. read receipt의 묶음 처리 규칙은 다릅니다.<sup>[[1]](#references)</sup>

별도의 WhatsApp probe로 메시지를 전달하지 않고 **server-side prekey refills**를 읽는 방법은 [Prekey Bundle Depletion and Refill Side Channel](whatsapp-prekey-bundle-side-channel.md)을 참조하세요.

## 샘플링 주기, 큐잉 및 누적 영수증

* **WhatsApp의 burst 허용치:** 공개된 측정 결과에 따르면 WhatsApp은 서버 측에서 뚜렷한 큐잉 없이 `50 ms`마다 probe를 하나씩 보내는 silent-reaction burst를 수용했습니다. 이는 짧은 보정 burst, 빠른 기기 수 확인 또는 drain attack의 신속한 속도 상승에 유용합니다.
* **Signal의 장시간 큐잉:** Signal은 짧은 burst는 허용했지만, 초당 여러 probe를 지속적으로 보내면 큐잉이 시작됐습니다. 장시간 모니터링할 때는 각 영수증이 대기열을 처리한 결과가 아니라 현재 기기 상태를 반영하도록 주기를 `1 Hz`(또는 그 이하)로 유지하세요.
* **재연결 아티팩트:** 기기가 다시 온라인 상태가 되면 일부 클라이언트는 지연된 영수증을 묶어서 보내거나 빠르게 flush합니다. 이런 영수증 burst는 독립적인 RTT 샘플이 아니라 상태 전환의 표시로 취급하세요. 그렇지 않으면 클러스터링이나 `active`와 `idle`을 구분하는 classifier가 재연결 노이즈에 과적합됩니다.<sup>[[1]](#references)</sup>

## RTT trace에서 행동 추론

1. OS 스케줄링 효과를 포착할 수 있도록 ≥1 Hz로 샘플링합니다. iOS의 WhatsApp에서는 RTT가 <1 s일 때 화면이 켜져 있거나 앱이 foreground 상태인 경우와 강한 상관관계를 보이고, >1 s일 때는 화면 꺼짐/background 상태에서의 throttling과 강한 상관관계를 보입니다.
2. thresholding이나 two-cluster k-means를 사용해 각 RTT에 "활성" 또는 "유휴" 레이블을 지정하는 간단한 classifier를 만듭니다. 레이블을 연속 구간으로 집계해 취침 시간, 통근 시간, 근무 시간 또는 desktop companion이 활성화된 시간을 추정합니다.
3. 모든 기기를 대상으로 동시에 probe를 수행해 사용자가 모바일에서 desktop으로 전환하는 시점, companion이 오프라인 상태가 되는 시점, 앱이 push와 persistent socket 중 어느 방식으로 rate limit되는지 확인합니다.
4. 실제 네트워크에서는 `1 s`라는 단일 고정 threshold를 사용하지 않습니다. 각 기기를 짧은 warm-up window로 초기 설정하고 rolling baseline을 유지합니다(예: device-activity-tracker PoC는 `threshold = 0.9 * median RTT`를 사용). 이렇게 하면 Wi-Fi/cellular 환경의 변동으로 classifier가 제대로 작동하지 않는 상황을 방지할 수 있습니다.<sup>[[1]](#references)[[8]](#references)</sup>

## delivery RTT를 통한 위치 추론

같은 타이밍 primitive를 재활용하면 수신자가 활성 상태인지 여부뿐 아니라 수신자가 어디에 있는지도 추론할 수 있습니다. `Hope of Delivery` 연구에서는 알려진 수신자 위치의 RTT 분포를 학습하면 공격자가 나중에 delivery confirmation만으로 피해자의 위치를 분류할 수 있음을 보여주었습니다:<sup>[[2]](#references)</sup>

* 동일한 target이 여러 알려진 장소(집, 사무실, 캠퍼스, 국가 A와 국가 B 등)에 있을 때 baseline을 구축합니다.
* 각 장소에서 정상적인 메시지 RTT를 여러 번 수집하고 중앙값, 분산, 백분위수 구간 등의 간단한 특징을 추출합니다.
* 실제 공격 중에는 새 probe 시리즈를 학습된 클러스터와 비교합니다. 논문에 따르면 같은 도시 내의 장소도 흔히 구분할 수 있으며, 3개 장소 설정에서 정확도는 `>80%`입니다.
* 공격자가 sender 환경을 제어하고 비슷한 네트워크 조건에서 probe를 보내면 가장 효과적입니다. 측정되는 경로에는 수신자의 access network, wake-up latency, 메신저 인프라가 포함되기 때문입니다.<sup>[[2]](#references)</sup>

위의 silent reaction/edit/delete 공격과 달리, 위치 추론에는 유효하지 않은 메시지 ID나 은밀한 상태 변경 패킷이 필요하지 않습니다. 정상적인 delivery confirmation이 포함된 일반 메시지만으로 충분하므로, 은밀성은 낮아지는 대신 더 많은 메신저에 적용할 수 있습니다.

## 은밀한 리소스 고갈

모든 silent probe는 복호화되고 확인 응답을 받아야 하므로, reaction 토글, 유효하지 않은 편집 또는 모두에게 삭제 패킷을 계속 전송하면 애플리케이션 계층 DoS가 발생합니다:<sup>[[1]](#references)</sup>

* radio/modem이 매초 송수신하도록 해 특히 유휴 상태의 휴대폰에서 배터리가 눈에 띄게 소모됩니다.
* 업스트림/다운스트림 트래픽을 발생시켜 모바일 데이터 요금제를 소모하고 영상 통화처럼 지연 시간에 민감한 기능의 성능을 저하시킬 수 있습니다.<sup>[[1]](#references)</sup>
* 큰 유효하지 않은 payload는 처리 작업을 늘리지만, 논문에 따르면 암호화 자체는 배터리 소모에서 무시할 수 있는 수준입니다.<sup>[[1]](#references)</sup>
* WhatsApp에서 잘못된 reaction은 일반적인 이모지가 암시하는 것보다 훨씬 많은 데이터를 허용합니다. 공개된 측정 결과에 따르면 서버는 reaction 하나에 최대 약 `1 MB`까지 수락했습니다.
* 본문이 약 `30 bytes`를 넘으면 oversized reaction은 신뢰할 수 있는 delivery receipt를 더 이상 생성하지 않지만, 폐기되기 전에 여전히 전달되고 처리됩니다. ACK가 필요하면 reaction 본문을 아주 작게 유지하고, 순수한 drain이나 은밀한 단방향 전송이 목적일 때만 크기를 늘리세요.
* 공개된 측정에서는 이 모드에서 피해자 트래픽이 약 `3.7 MB/s` (`~13.3 GB/h`)에 도달했습니다.



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
