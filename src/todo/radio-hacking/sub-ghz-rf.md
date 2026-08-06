# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

차고 문 개폐기는 일반적으로 300~190 MHz 범위의 주파수에서 작동하며, 가장 일반적인 주파수는 300 MHz, 310 MHz, 315 MHz, 390 MHz입니다. 이 주파수 범위는 다른 주파수 대역보다 혼잡하지 않고 다른 장치의 간섭을 받을 가능성이 낮기 때문에 차고 문 개폐기에 흔히 사용됩니다.

## Car Doors

대부분의 자동차 키 리모컨은 **315 MHz 또는 433 MHz**에서 작동합니다. 둘 다 무선 주파수이며 다양한 용도로 사용됩니다. 두 주파수의 주요 차이점은 433 MHz가 315 MHz보다 더 긴 범위를 가진다는 것입니다. 따라서 433 MHz는 remote keyless entry와 같이 더 긴 범위가 필요한 용도에 더 적합합니다.\
유럽에서는 433.92MHz가 일반적으로 사용되고, 미국과 일본에서는 315MHz가 사용됩니다.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

각 코드를 5번씩 보내는 대신(수신기가 확실히 수신하도록 이렇게 전송함) 한 번만 보내면 시간이 6분으로 단축됩니다.

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

또한 신호 사이의 **2 ms 대기** 시간을 **제거**하면 **시간을 3분으로 줄일 수 있습니다.**

게다가 De Bruijn Sequence(모든 가능한 이진수를 brute-force하기 위해 전송해야 하는 비트 수를 줄이는 방법)를 사용하면 이 **시간을 8초까지 줄일 수 있습니다**:<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

이 공격의 예시는 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)에 구현되어 있습니다.

**preamble을 요구하면 De Bruijn Sequence** 최적화를 방지할 수 있으며, **rolling codes는 이 공격을 방지합니다**(코드가 brute-force할 수 없을 만큼 충분히 길다고 가정).

## Sub-GHz Attack

Flipper Zero로 이러한 신호를 공격하려면 다음을 확인하세요:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

자동 차고 문 개폐기는 일반적으로 무선 리모컨을 사용하여 차고 문을 열고 닫습니다. 리모컨은 **무선 주파수(RF) 신호를 전송**하며, 차고 문 개폐기는 이 신호를 수신해 모터를 작동시키고 문을 열거나 닫습니다.

code grabber라는 장치를 사용하여 누군가 RF 신호를 가로채고 나중에 사용할 수 있도록 기록할 수 있습니다. 이를 **replay attack**이라고 합니다. 이러한 공격을 방지하기 위해 많은 최신 차고 문 개폐기는 **rolling code** 시스템이라는 더욱 안전한 암호화 방식을 사용합니다.

**RF 신호는 일반적으로 rolling code를 사용하여 전송**되며, 이는 사용할 때마다 코드가 변경된다는 의미입니다. 따라서 누군가 신호를 **가로채서** 차고에 **무단**으로 접근하는 데 **사용하기**가 **어렵습니다**.

rolling code 시스템에서는 리모컨과 차고 문 개폐기가 **공유 알고리즘**을 가지고 있으며, 리모컨을 사용할 때마다 새로운 코드를 **생성**합니다. 차고 문 개폐기는 **올바른 코드**에만 응답하므로, 누군가 코드를 캡처하는 것만으로 차고에 무단으로 접근하기가 훨씬 어려워집니다.

### **Missing Link Attack**

기본적으로 버튼 입력을 감시하면서 리모컨이 장치(예: 자동차 또는 차고)의 **범위 밖에 있는 동안 신호를 캡처**합니다. 그런 다음 장치로 이동하여 **캡처한 코드를 사용해 장치를 엽니다**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

공격자는 차량 또는 **수신기** 근처에서 신호를 **jam**하여 **수신기가 실제로 코드를 ‘들을’ 수 없도록** 만들 수 있습니다. 이렇게 되면 jamming을 중단한 후 코드를 간단히 **캡처하고 replay**할 수 있습니다.<sup>[[2]](#references)</sup>

피해자는 어느 시점에 **키를 사용하여 자동차를 잠그게** 되지만, 공격자는 문을 열기 위해 다시 전송할 수 있는 충분한 수의 **"문 닫기" 코드**를 이미 **기록**했을 가능성이 있습니다(문을 열고 닫는 데 동일한 코드를 사용하지만 두 명령을 서로 다른 주파수에서 수신하는 자동차가 있으므로 **주파수 변경이 필요할 수 있습니다**).

> [!WARNING]
> **Jamming은 작동**하지만 눈에 띕니다. 자동차를 잠그는 사람이 잠겼는지 확인하기 위해 **단순히 문을 테스트**하면 자동차가 잠기지 않았다는 것을 알 수 있기 때문입니다. 또한 이러한 공격을 알고 있다면 ‘lock’ 버튼을 눌렀을 때 문이 잠기는 **소리**가 나지 않거나 자동차의 **라이트**가 깜박이지 않는 것을 알아챌 수도 있습니다.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

이는 더욱 **은밀한 Jamming technique**입니다. 공격자는 신호를 jam하므로 피해자가 문을 잠그려고 해도 작동하지 않지만, 공격자는 이 **코드를 기록**합니다. 그런 다음 피해자는 버튼을 눌러 다시 자동차를 **잠그려고 시도**하고, 자동차는 이 두 번째 코드를 **기록**합니다.<sup>[[2]](#references)[[4]](#references)</sup>\
그 직후 **공격자는 첫 번째 코드를 전송**할 수 있으며, **자동차가 잠깁니다**(피해자는 두 번째 버튼 입력으로 잠겼다고 생각합니다). 이후 공격자는 도난한 두 번째 코드를 **전송하여** 자동차를 **열 수 있습니다**(**"자동차 닫기" 코드가 자동차를 여는 데에도 사용될 수 있다고 가정**). 주파수 변경이 필요할 수 있습니다(문을 열고 닫는 데 동일한 코드를 사용하지만 두 명령을 서로 다른 주파수에서 수신하는 자동차가 있기 때문입니다).

공격자는 자신의 수신기가 아니라 **자동차 수신기를 jam**할 수 있습니다. 예를 들어 자동차 수신기가 1MHz broadband를 수신하고 있다면, 공격자는 리모컨이 사용하는 정확한 주파수가 아니라 해당 스펙트럼에서 **가까운 주파수**를 **jam**하게 됩니다. 반면 **공격자의 수신기는 더 좁은 범위에서 수신**하므로 jam 신호 없이 리모컨 신호를 들을 수 있습니다.

> [!WARNING]
> 사양에서 확인되는 다른 구현에서는 **rolling code가 전송되는 전체 코드의 일부**로 나타납니다. 예를 들어 전송되는 코드는 **24 bit key**이며, 처음 **12비트는 rolling code**, 다음 **8비트는 명령**(예: lock 또는 unlock), 마지막 4비트는 **checksum**입니다. 이러한 유형을 구현한 차량도 자연스럽게 취약합니다. 공격자는 rolling code 부분만 교체하면 **두 주파수 모두에서 어떤 rolling code든 사용할 수 있기 때문**입니다.

> [!CAUTION]
> 피해자가 공격자가 첫 번째 코드를 전송하는 동안 세 번째 코드를 전송하면 첫 번째 코드와 두 번째 코드가 무효화된다는 점에 유의하세요.

### Alarm Sounding Jamming Attack

차량에 설치된 aftermarket rolling code 시스템을 대상으로 테스트한 결과, **동일한 코드를 두 번** 연속으로 **전송하면 alarm과 immobiliser가 즉시 활성화**되어 독특한 **denial of service** 기회가 발생했습니다. 아이러니하게도 **alarm과 immobiliser를 비활성화하는 방법**은 **리모컨을 누르는 것**이었으므로, 공격자는 **지속적으로 DoS attack을 수행**할 수 있었습니다. 또는 피해자가 공격을 최대한 빨리 중단하려 할 것이므로 이 공격을 **이전 공격과 조합하여 더 많은 코드를 얻을 수도 있습니다**.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-do-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
