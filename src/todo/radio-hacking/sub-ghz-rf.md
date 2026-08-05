# Sub-GHz RF

{{#include ../../banners/hacktricks-training.md}}

## Garage Doors

Garage door opener는 일반적으로 300~190 MHz 범위의 주파수에서 작동하며, 가장 일반적으로 사용되는 주파수는 300 MHz, 310 MHz, 315 MHz 및 390 MHz입니다. 이 주파수 범위는 다른 주파수 대역보다 혼잡하지 않고 다른 장치의 간섭을 받을 가능성이 낮기 때문에 Garage door opener에 일반적으로 사용됩니다.

## Car Doors

대부분의 car key fob은 **315 MHz 또는 433 MHz**에서 작동합니다. 둘 다 radio frequency이며 다양한 애플리케이션에 사용됩니다. 두 주파수의 주요 차이점은 433 MHz가 315 MHz보다 더 긴 범위를 가진다는 것입니다. 즉, 433 MHz는 remote keyless entry와 같이 더 긴 범위가 필요한 애플리케이션에 더 적합합니다.\
유럽에서는 433.92MHz가 일반적으로 사용되고, 미국과 일본에서는 315MHz가 사용됩니다.<sup>[[1]](#references)</sup>

## **Brute-force Attack**

<figure><img src="../../images/image (1084).png" alt=""><figcaption></figcaption></figure>

각 코드를 5번씩 보내는 대신(수신기가 코드를 수신하도록 하기 위해 이렇게 전송함) 한 번만 보내면 시간이 6분으로 줄어듭니다:

<figure><img src="../../images/image (622).png" alt=""><figcaption></figcaption></figure>

또한 신호 사이의 **2 ms 대기** 시간을 **제거하면 시간을 3분으로 줄일 수 있습니다.**

더 나아가 De Bruijn Sequence(무차별 대입을 위해 가능한 모든 이진수를 전송하는 데 필요한 비트 수를 줄이는 방법)를 사용하면 이 **시간을 단 8초로 줄일 수 있습니다**:

<figure><img src="../../images/image (583).png" alt=""><figcaption></figcaption></figure>

이 공격의 예제는 [https://github.com/samyk/opensesame](https://github.com/samyk/opensesame)에 구현되어 있습니다.<sup>[[3]](#references)</sup>

**preamble을 요구하면 De Bruijn Sequence** 최적화를 방지할 수 있으며, **rolling codes는 이 공격을 방지합니다**(코드가 무차별 대입이 불가능할 정도로 충분히 길다고 가정).

## Sub-GHz Attack

Flipper Zero로 이러한 신호를 공격하려면 다음을 확인하세요:


{{#ref}}
flipper-zero/fz-sub-ghz.md
{{#endref}}

## Rolling Codes Protection

Automatic garage door opener는 일반적으로 wireless remote control을 사용하여 차고 문을 열고 닫습니다. Remote control은 **radio frequency (RF) signal을 전송**하며, garage door opener가 이를 수신하면 motor를 작동시켜 문을 열거나 닫습니다.

누군가 code grabber라고 알려진 장치를 사용하여 RF signal을 가로채고 나중에 사용할 수 있도록 기록할 수 있습니다. 이를 **replay attack**이라고 합니다. 이러한 유형의 공격을 방지하기 위해 많은 최신 garage door opener는 **rolling code** system이라는 더 안전한 encryption method를 사용합니다.

**RF signal은 일반적으로 rolling code를 사용하여 전송**되며, 이는 사용할 때마다 코드가 변경된다는 의미입니다. 따라서 누군가 신호를 **intercept**하여 이를 **unauthorised** access 획득에 **사용하기**가 **어려워집니다**.

Rolling code system에서는 remote control과 garage door opener가 **공유 algorithm**을 사용하여 remote가 사용될 때마다 **새로운 code를 생성**합니다. Garage door opener는 **올바른 code**에만 응답하므로, 누군가 code를 capture하는 것만으로 차고에 unauthorised access를 얻기가 훨씬 더 어려워집니다.

### **Missing Link Attack**

기본적으로 button을 누르는 것을 listen하면서 remote가 장치(예: car 또는 garage)의 **범위를 벗어나 있는 동안 signal을 capture**합니다. 그런 다음 장치로 이동하여 **capture한 code를 사용해 장치를 엽니다**.<sup>[[2]](#references)</sup>

### Full Link Jamming Attack

공격자는 vehicle 또는 receive**r** 근처에서 **signal을 jam**하여 **receiver가 실제로 code를 ‘듣지’ 못하도록** 할 수 있습니다. 이렇게 되면 jamming을 중단한 후 code를 간단히 **capture하고 replay**할 수 있습니다.

피해자는 어느 시점에 **keys를 사용해 car를 lock**하지만, 그때까지 공격자는 문을 열기 위해 다시 보낼 수 있는 **충분한 "close door" codes**를 기록했을 수 있습니다(**open과 close에 동일한 codes를 사용하지만 서로 다른 frequencies에서 두 명령을 listen하는 car도 있으므로 주파수 변경이 필요할 수 있습니다**).

> [!WARNING]
> **Jamming은 작동**하지만 눈에 띕니다. 차를 lock하는 사람이 단순히 문이 잠겼는지 확인하기 위해 문을 **테스트한다면**, car가 unlock된 것을 알아차릴 수 있기 때문입니다. 또한 이러한 공격을 알고 있다면 ‘lock’ button을 눌렀을 때 문에서 lock **sound**가 나지 않았거나 car의 **lights**가 깜박이지 않았다는 사실을 알아차릴 수도 있습니다.

### **Code Grabbing Attack ( aka ‘RollJam’ )**

이는 더욱 **은밀한 Jamming technique**입니다. 공격자는 signal을 jam하므로 피해자가 문을 lock하려고 해도 작동하지 않지만, 공격자는 이 **code를 기록**합니다. 그런 다음 피해자는 button을 눌러 car를 다시 **lock하려고 시도하고**, car는 **두 번째 code를 기록**합니다.\
그 직후 **공격자는 첫 번째 code를 전송**할 수 있으며, **car가 lock**됩니다(피해자는 두 번째 press로 문이 닫혔다고 생각함). 그런 다음 공격자는 도난한 **두 번째 code를 전송하여** car를 열 수 있습니다(**"close car" code를 사용해 car를 열 수도 있다고 가정**). open과 close에 동일한 codes를 사용하지만 서로 다른 frequencies에서 두 명령을 listen하는 car도 있으므로 주파수 변경이 필요할 수 있습니다.<sup>[[3]](#references)[[2]](#references)</sup>

공격자는 자신의 receiver가 아니라 **car receiver를 jam**할 수 있습니다. car receiver가 예를 들어 1MHz broadband를 listen하는 경우, 공격자는 remote가 사용하는 정확한 frequency가 아니라 해당 spectrum에서 **가까운 frequency**를 jam하게 됩니다. 반면 **공격자의 receiver는 더 좁은 범위에서 listen**하므로 jam signal 없이 remote signal을 listen할 수 있습니다.

> [!WARNING]
> 사양에서 확인된 다른 구현에서는 **rolling code가 전송되는 전체 code의 일부**임을 보여줍니다. 즉, 전송되는 code가 **24 bit key**이고, 첫 번째 **12 bit는 rolling code**, **다음 8 bit는 command**(예: lock 또는 unlock), 마지막 4 bit는 **checksum**입니다. 이러한 유형을 구현한 vehicle도 자연스럽게 취약합니다. 공격자는 rolling code segment만 교체하면 **두 frequencies 모두에서 어떤 rolling code든 사용할 수 있기** 때문입니다.

> [!CAUTION]
> 피해자가 공격자가 첫 번째 code를 전송하는 동안 세 번째 code를 보내면 첫 번째와 두 번째 code가 무효화된다는 점에 유의하세요.

### Alarm Sounding Jamming Attack

차량에 설치된 aftermarket rolling code system을 대상으로 테스트한 결과, **동일한 code를 두 번 연속 전송하면** alarm과 immobiliser가 **즉시 활성화**되어 고유한 **denial of service** 기회를 제공했습니다. 아이러니하게도 **alarm**과 immobiliser를 **비활성화하는 방법**은 **remote를 press**하는 것이었으므로, 공격자는 **계속해서 DoS attack을 수행**할 수 있었습니다. 또는 피해자가 가능한 한 빨리 공격을 중단하려 할 것이므로 이 attack을 **앞선 attack과 혼합하여 더 많은 codes를 얻을** 수도 있습니다.<sup>[[2]](#references)</sup>

## References

- [1] [What Radio Frequency Does Car Key Fobs Run On?](https://www.americanradioarchives.com/what-radio-frequency-does-car-key-fobs-run-on/)
- [2] [Bypassing Rolling Code Systems](https://www.andrewmohawk.com/2016/02/05/bypassing-rolling-code-systems/)
- [3] [Drive It Like You Hacked It (DEF CON 23) - OpenSesame / RollJam](https://samy.pl/defcon2015/)
- [4] [How to hack a car (RollJam recreation)](https://hackaday.io/project/164566-how-to-hack-a-car/details)

{{#include ../../banners/hacktricks-training.md}}
