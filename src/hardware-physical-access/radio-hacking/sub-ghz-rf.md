# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## 차고문

차고문 리모컨은 지역과 제품에 따라 다양한 Sub-GHz 대역을 사용합니다. 300, 310, 315, 390, 433.92 MHz 등의 주파수가 쓰이지만, 보편적인 “300–190 MHz” 차고문 대역은 없습니다. 전송하기 전에 대상 장치의 라벨, 규제 지역, 관측된 신호를 확인하세요.<sup>[[1]](#references)</sup>

## 자동차 문

많은 자동차 키 포브는 **315 MHz 또는 433.92 MHz**를 사용하며, 지역별 규정과 차량 설계에 따라 선택이 달라집니다. 433 MHz가 315 MHz보다 더 멀리 도달하는 것은 주파수만으로 결정되지 않습니다. 송신 전력, 안테나 효율, 변조 방식, 수신기 감도, 전파 특성, 현지 규정이 모두 영향을 미칩니다. 유럽에서는 일반적으로 433.92 MHz를 사용하고, 북미와 일본에서는 315 MHz가 흔합니다.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

시연된 고정 코드 시스템에서는 각 코드를 다섯 번이 아닌 한 번만 전송하면 예상 시간이 6분으로 줄어듭니다.

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

신호 사이의 2 ms 대기 시간을 없애면 해당 시연에 걸리는 시간은 약 3분으로 줄어듭니다.

De Bruijn sequence를 사용해 후보 비트 문자열을 겹치면, 수신기가 필수 preamble이나 프레임 초기화 없이 연속된 시퀀스를 받아들이는 경우 시연된 공격을 약 8초로 줄일 수 있습니다.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame은 호환되는 고정 코드 시스템을 대상으로 이 공격을 구현합니다.<sup>[[5]](#references)</sup>

**Preamble이 필요하면 De Bruijn Sequence 최적화를 방지할 수 있으며**, **rolling code를 사용하면 이 공격을 막을 수 있습니다** (코드 길이가 충분히 길어 brute-force가 불가능하다고 가정).

## Sub-GHz 공격

Flipper Zero로 이러한 신호를 공격하는 방법은 다음을 확인하세요.

{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Code 보호

자동 차고문 개폐기는 일반적으로 무선 리모컨을 사용해 차고문을 열고 닫습니다. 리모컨은 **차고문 개폐기에 RF 신호를 전송**하고, 개폐기는 모터를 작동시켜 문을 열거나 닫습니다.

누군가 code grabber라는 장치를 사용해 RF 신호를 가로채고 나중에 사용할 수 있도록 기록할 수 있습니다. 이를 **replay attack**이라고 합니다. 이러한 공격을 방지하기 위해 최신 차고문 개폐기 상당수는 **rolling code** 시스템이라는 더 안전한 암호화 방식을 사용합니다.

**RF 신호는 일반적으로 rolling code를 사용해 전송되며**, 이는 사용할 때마다 코드가 바뀐다는 뜻입니다. 이 때문에 신호를 **가로채서** 차고에 무단으로 접근하는 데 **사용하기가 어려워집니다**.

Rolling code 시스템에서는 리모컨과 차고문 개폐기가 **공유 알고리즘**을 사용해 리모컨을 사용할 때마다 **새 코드를 생성합니다**. 차고문 개폐기는 **올바른 코드**에만 응답하므로, 코드를 캡처하는 것만으로 차고에 무단으로 접근하기가 훨씬 어려워집니다.

### **Missing Link Attack**

기본적으로 버튼 신호를 듣고, 리모컨이 장치(예: 자동차나 차고문)의 범위 밖에 있을 때 **신호를 캡처합니다**. 그런 다음 장치 가까이 이동해 **캡처한 코드로 문을 엽니다**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> 의도적인 RF 간섭은 여러 관할 지역에서 불법이며 안전과 관련된 시스템을 방해할 수 있습니다. 전파 규정을 준수하고 허가된 차폐 실험실에서만 jamming 테스트를 수행하세요.<sup>[[6]](#references)</sup>

공격자는 **차량이나 수신기 근처에서 신호를 방해**해 수신기가 코드를 디코딩하지 못하게 한 뒤, 차단된 전송 신호를 별도로 캡처하고 jamming을 중단한 다음 캡처한 코드를 재전송할 수 있습니다.<sup>[[2]](#references)</sup>

피해자가 어느 순간 **키를 사용해 자동차를 잠그려** 하지만, 공격은 문을 열 때 재전송할 수 있도록 충분한 “문 닫기” 코드를 **기록해 두었을 수 있습니다** (같은 코드를 열기와 닫기에 사용하는 차량이 있지만 두 명령을 서로 다른 주파수에서 수신하는 경우, **주파수를 바꿔야 할 수도 있습니다**).

> [!WARNING]
> **Jamming은 효과가 있지만**, 눈에 띌 수 있습니다. **차를 잠그는 사람이 문을 직접 확인**해 잠겼는지 살피면 차가 잠기지 않은 것을 알아차릴 수 있기 때문입니다. 또한 이런 공격을 알고 있다면 ‘잠금’ 버튼을 눌렀을 때 문 잠금 **소리**가 나지 않거나 차량 **등이** 깜박이지 않는 것을 알아챌 수 있습니다.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

이는 더 **은밀한 jamming 기법**입니다. 공격자는 신호를 방해해 피해자가 문을 잠그려 해도 잠기지 않도록 하면서, **해당 코드를 기록합니다**. 그런 다음 피해자는 버튼을 다시 눌러 **차를 다시 잠그려 하고**, 차량은 **두 번째 코드를 기록합니다**.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
이 직후 **공격자가 첫 번째 코드를 전송하면** **차량이 잠깁니다** (피해자는 두 번째 버튼 누름으로 잠겼다고 생각합니다). 그런 다음 공격자는 **도난한 두 번째 코드를 전송해** 차를 열 수 있습니다 (**“차량 잠금” 코드를 열 때도 사용할 수 있다고 가정**). 같은 코드를 열기와 닫기에 사용하지만 두 명령을 서로 다른 주파수에서 수신하는 차량이라면 주파수를 바꿔야 할 수 있습니다.

한 가지 RollJam 구현은 수신기 대역폭을 이용합니다. jammer는 리모컨의 반송파에 충분히 가까운 주파수로 전송해 차량의 더 넓은 대역폭 수신기를 둔감하게 만들고, 공격자의 더 좁은 대역폭 수신기는 리모컨 주파수에 맞춘 채 신호를 기록할 수 있습니다. 정확한 주파수 오프셋과 대역폭은 대상 하드웨어에 따라 달라집니다.<sup>[[2]](#references)</sup>

> [!WARNING]
> 사양에서 확인된 다른 구현 방식에서는 **rolling code가 전송되는 전체 코드의 일부**입니다. 즉, 전송되는 코드는 **24비트 키**이며, 처음 **12비트는 rolling code**, 다음 **8비트는 명령**(예: 잠금 또는 잠금 해제), 마지막 4비트는 **체크섬**입니다. 이 유형을 구현한 차량도 공격자가 rolling code 부분을 바꾸기만 하면 **두 주파수 모두에서 어떤 rolling code든 사용할 수 있으므로** 자연스럽게 취약합니다.

> [!CAUTION]
> 공격자가 첫 번째 코드를 전송하는 동안 피해자가 세 번째 코드를 보내면 첫 번째 코드와 두 번째 코드가 무효화됩니다.

### Alarm Sounding Jamming Attack

차량에 설치된 애프터마켓 rolling code 시스템을 대상으로 테스트했을 때, **같은 코드를 두 번 전송하자** 즉시 **경보와 이모빌라이저가 작동**해 독특한 **서비스 거부** 기회가 생겼습니다. 아이러니하게도 경보와 이모빌라이저를 **해제하는 방법은** 리모컨을 **누르는 것**이어서 공격자가 **DoS 공격을 지속적으로 수행**할 수 있었습니다. 또는 이 공격을 **앞선 공격과 조합해 코드를 더 많이 확보**할 수도 있습니다. 피해자는 공격을 가능한 한 빨리 멈추고 싶어 할 테니까요.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero 문서 - 지역별 Sub-GHz 주파수](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Rolling Code 시스템 우회 - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: 해킹한 대로 운전하기 (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [자동차 해킹 방법 - YARD Stick One / RTL-SDR을 이용한 RollJam 재현](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame 소스 코드](https://github.com/samyk/opensesame)
- [6] [FCC 집행 권고 - Jammer 단속](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
