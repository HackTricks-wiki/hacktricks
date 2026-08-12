# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage-door remote는 여러 지역 및 제품별 Sub-GHz 할당 대역을 사용합니다. 300, 310, 315, 390, 433.92 MHz와 같은 주파수가 사용되지만, 보편적인 "300–190 MHz" garage-door 대역은 없습니다. 전송 전에 대상의 라벨, 규제 지역 및 관측된 신호를 확인하십시오.<sup>[[1]](#references)</sup>

## Car Doors

많은 car key fob은 **315 MHz 또는 433.92 MHz**를 사용하며, 지역별 규정과 차량 설계에 따라 선택이 달라집니다. 주파수만으로 433 MHz가 315 MHz보다 더 긴 range를 갖는 것은 아닙니다. 송신 전력, 안테나 효율, modulation, receiver sensitivity, propagation 및 현지 규정이 모두 영향을 줍니다. 유럽에서는 일반적으로 433.92 MHz를 사용하고, 북미와 일본에서는 315 MHz가 일반적입니다.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

시연된 fixed-code system에서는 각 code를 5번 대신 한 번씩 전송하면 예상 시간이 6분으로 줄어듭니다.

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

신호 사이의 2 ms 대기를 제거하면 해당 시연이 약 3분으로 줄어듭니다.

De Bruijn sequence를 사용해 후보 bit string을 겹치면, receiver가 필수 preamble이나 frame reset 없이 연속 sequence를 수락하는 경우 시연된 attack을 약 8초로 줄일 수 있습니다.<sup>[[3]](#references)</sup>

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

OpenSesame은 호환되는 fixed-code system을 대상으로 이 attack을 구현합니다.<sup>[[5]](#references)</sup>

**preamble을 요구하면 De Bruijn Sequence** 최적화를 방지할 수 있으며, **rolling code는 이 attack을 방지합니다**(code가 bruteforce할 수 없을 정도로 충분히 길다고 가정).

## Sub-GHz Attack

Flipper Zero로 이러한 신호를 attack하려면 다음을 확인하십시오:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door opener는 일반적으로 wireless remote control을 사용해 garage door를 열고 닫습니다. Remote control은 **radio frequency (RF) signal을 전송**하고, garage door opener는 이를 받아 motor를 작동시켜 문을 열거나 닫습니다.

code grabber라고 알려진 device를 사용해 누군가 RF signal을 가로채고 나중에 사용하도록 기록할 수 있습니다. 이를 **replay attack**이라고 합니다. 이러한 attack을 방지하기 위해 많은 최신 garage door opener는 **rolling code** system이라는 더 안전한 encryption method를 사용합니다.

**RF signal은 일반적으로 rolling code를 사용해 전송**되며, 이는 사용할 때마다 code가 변경된다는 의미입니다. 따라서 누군가 signal을 **intercept**하여 이를 사용해 garage에 **unauthorised** access를 얻기가 **어려워집니다**.

Rolling code system에서 remote control과 garage door opener는 remote를 사용할 때마다 새 code를 **생성하는 shared algorithm**을 갖습니다. Garage door opener는 **correct code**에만 응답하므로, code를 capture하는 것만으로 garage에 unauthorised access를 얻기가 훨씬 어려워집니다.

### **Missing Link Attack**

기본적으로 button을 누르는 것을 감청하고 remote가 device(예: car 또는 garage)의 **범위 밖에 있을 때 signal을 capture**합니다. 그런 다음 device로 이동해 **capture한 code를 사용하여 문을 엽니다**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

> [!CAUTION]
> 의도적인 RF interference는 많은 관할권에서 불법이며 safety-relevant system을 방해할 수 있습니다. Jamming test는 shielded되고 허가된 laboratory에서 관련 radio regulations에 따라 수행해야 합니다.<sup>[[6]](#references)</sup>

Attacker는 **vehicle 또는 receiver 근처에서 signal을 jam**하여 receiver가 code를 decode하지 못하게 만들고, 차단된 transmission을 별도로 capture한 다음, jamming을 중지하고 capture한 code를 replay할 수 있습니다.<sup>[[2]](#references)</sup>

피해자는 어느 시점에 **keys를 사용해 car를 lock**하지만, 그때쯤 attack은 문을 열기 위해 다시 전송할 수 있는 충분한 **"close door" code**를 **record**했을 수 있습니다(문을 열고 닫는 데 동일한 code를 사용하지만 두 command를 서로 다른 frequency에서 감청하는 car도 있으므로 **frequency 변경이 필요할 수 있습니다**).

> [!WARNING]
> **Jamming은 작동**하지만 눈에 띕니다. car를 lock한 사람이 단순히 문이 잠겼는지 확인하려고 문을 테스트하면 car가 unlock 상태라는 것을 알 수 있기 때문입니다. 또한 이러한 attack을 알고 있다면 ‘lock’ button을 눌렀을 때 문이 lock **sound**를 내지 않았거나 car의 **lights**가 깜박이지 않았다는 사실을 알아챌 수도 있습니다.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

이는 더욱 **stealth한 Jamming technique**입니다. Attacker는 signal을 jam하므로 피해자가 문을 lock하려고 해도 작동하지 않지만, attacker는 이 **code를 record**합니다. 그런 다음 피해자는 button을 눌러 car를 다시 **lock하려고 시도**하고, car는 이 두 번째 code를 **record**합니다.<sup>[[2]](#references)</sup><sup>[[4]](#references)</sup>\
그 직후 **attacker는 첫 번째 code를 전송**할 수 있고, **car는 lock됩니다**(피해자는 두 번째 button 입력으로 lock되었다고 생각합니다). 그런 다음 attacker는 도난한 두 번째 code를 **전송하여 car를 open**할 수 있습니다(**"close car" code를 사용해 car를 open할 수도 있다고 가정**). 문을 열고 닫는 데 동일한 code를 사용하지만 두 command를 서로 다른 frequency에서 감청하는 car도 있으므로 frequency 변경이 필요할 수 있습니다.

한 RollJam implementation은 receiver bandwidth를 악용합니다. Jammer는 remote의 carrier에 충분히 가까운 곳에서 transmission하여 vehicle의 더 넓은 receiver를 desensitize하는 반면, attacker의 더 좁은 receiver는 remote에 계속 맞춰져 signal을 record할 수 있습니다. 정확한 offset과 bandwidth는 대상 hardware에 따라 달라집니다.<sup>[[2]](#references)</sup>

> [!WARNING]
> specifications에서 확인되는 다른 implementation에서는 **rolling code가 전송되는 전체 code의 일부**임을 보여줍니다. 예를 들어 전송되는 code가 **24 bit key**이고, 첫 **12 bit는 rolling code**, 다음 **8 bit는 command**(예: lock 또는 unlock), 마지막 4 bit는 **checksum**일 수 있습니다. 이러한 type을 구현한 vehicle도 attacker가 rolling code segment만 교체하면 **어떤 rolling code든 두 frequency에서 사용할 수 있으므로** 자연스럽게 취약합니다.

> [!CAUTION]
> 피해자가 attacker가 첫 번째 code를 전송하는 동안 세 번째 code를 전송하면 첫 번째와 두 번째 code가 무효화된다는 점에 유의하십시오.

### Alarm Sounding Jamming Attack

차량에 설치된 aftermarket rolling code system을 대상으로 테스트한 결과, **동일한 code를 두 번 전송하면** 즉시 **alarm과 immobiliser가 활성화**되어 고유한 **denial of service** 기회가 발생했습니다. 아이러니하게도 **alarm과 immobiliser를 disable하는 방법**은 **remote를 누르는 것**이었으므로, attacker는 지속적으로 **DoS attack을 수행**할 수 있었습니다. 또는 피해자가 attack을 최대한 빨리 중지하려 할 것이므로 이 attack을 **이전 attack과 조합해 더 많은 code를 얻을** 수도 있습니다.<sup>[[2]](#references)</sup>

## References

- [1] [Flipper Zero documentation - regional Sub-GHz frequencies](https://docs.flipper.net/zero/sub-ghz/frequencies)
- [2] [Bypassing Rolling Code Systems - Andrew Mohawk](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Samy Kamkar - DEF CON 23: Drive It Like You Hacked It (OpenSesame)](https://samy.pl/defcon2015/)
- [4] [How To Hack A Car - RollJam recreation with YARD Stick One / RTL-SDR](https://hackaday.io/project/164566-how-to-hack-a-car/details)
- [5] [OpenSesame source code](https://github.com/samyk/opensesame)
- [6] [FCC Enforcement Advisory - Jammer Enforcement](https://www.fcc.gov/document/jammer-enforcement)
{{#include ../../banners/hacktricks-training.md}}
