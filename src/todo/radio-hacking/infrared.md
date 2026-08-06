# 적외선

{{#include ../../banners/hacktricks-training.md}}

## 적외선 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선은 사람의 눈에 보이지 않습니다**. IR 파장은 **0.7~1000마이크론**입니다. 가정용 리모컨은 데이터 전송에 IR 신호를 사용하며, 0.75~1.4마이크론 파장 범위에서 작동합니다. 리모컨의 microcontroller는 적외선 LED를 특정 주파수로 깜박이게 하여 digital signal을 IR 신호로 변환합니다.

IR 신호를 수신하려면 **photoreceiver**를 사용합니다. photoreceiver는 **IR 빛을 voltage pulse로 변환**하며, 이 신호는 이미 **digital signal**입니다. 일반적으로 수신기 내부에는 **dark light filter**가 있어 **원하는 파장만 통과**시키고 noise를 제거합니다.<sup>[[1]](#references)</sup>

### IR Protocol의 종류 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocol은 다음 3가지 요소에서 차이가 납니다:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — 보통 36~38 kHz 범위

#### Bit encoding 방식 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

bit는 pulse 사이의 space 지속 시간을 modulation하여 encoding합니다. pulse 자체의 폭은 일정합니다.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

bit는 pulse width를 modulation하여 encoding합니다. pulse burst 이후 space의 폭은 일정합니다.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Manchester encoding이라고도 합니다. 논리값은 pulse burst와 space 사이 transition의 polarity로 결정됩니다. "Space to pulse burst"는 logic "0", "pulse burst to space"는 logic "1"을 나타냅니다.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 앞선 방식들의 조합 및 기타 특수 방식**

> [!TIP]
> 여러 종류의 장치에서 사용할 수 있는 **universal protocol이 되려는** IR protocol도 있습니다. 가장 유명한 것은 RC5와 NEC입니다. 그러나 가장 유명하다는 것이 **가장 일반적으로 사용된다는 의미는 아닙니다**. 제가 사용하는 환경에서는 NEC remote 두 개만 보았고 RC5 remote는 하나도 보지 못했습니다.
>
> Manufacturer는 같은 종류의 장치 범위 내에서도(예: TV-box) 자신들만의 고유한 IR protocol을 사용하는 것을 선호합니다. 따라서 서로 다른 회사의 remote와 때로는 같은 회사의 서로 다른 model의 remote는 같은 종류의 다른 장치에서 작동하지 않습니다.

### IR 신호 탐색

remote의 IR 신호가 실제로 어떻게 생겼는지 확인하는 가장 신뢰할 수 있는 방법은 oscilloscope를 사용하는 것입니다. oscilloscope는 수신된 신호를 demodulate하거나 invert하지 않고, 단순히 "있는 그대로" 표시합니다. 이는 testing 및 debugging에 유용합니다. 여기서는 NEC IR protocol을 예로 예상되는 signal을 설명하겠습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

일반적으로 encoded packet의 시작 부분에는 preamble이 있습니다. 이를 통해 receiver는 gain level과 background를 판단할 수 있습니다. Sharp와 같이 preamble이 없는 protocol도 있습니다.

그 다음 data가 전송됩니다. structure, preamble 및 bit encoding method는 특정 protocol에 의해 결정됩니다.

**NEC IR protocol**에는 짧은 command와 button을 누르고 있는 동안 전송되는 repeat code가 포함됩니다. command와 repeat code 모두 시작 부분에 동일한 preamble이 있습니다.

NEC **command**는 preamble 외에도 address byte와 command-number byte로 구성되며, 이를 통해 장치는 수행해야 할 작업을 판단합니다. 전송 무결성을 확인하기 위해 address 및 command-number byte는 inverse value와 함께 중복됩니다. command 끝에는 추가 stop bit가 있습니다.

**repeat code**에는 preamble 다음에 "1"이 있으며, 이것이 stop bit입니다.

**logic "0"과 "1"**에 대해 NEC는 Pulse Distance Encoding을 사용합니다. 먼저 pulse burst가 전송되고 그 뒤에 pause가 이어지며, pause의 길이가 bit 값을 결정합니다.

### 에어컨

다른 remote와 달리 **에어컨은 눌린 button의 code만 전송하지 않습니다**. 또한 **button을 누를 때 모든 정보도 전송**하여 **에어컨 장치와 remote가 동기화된 상태를 유지하도록** 합니다.\
이렇게 하면 한 remote로 20ºC로 설정된 장치를 21ºC로 올린 다음, 온도가 여전히 20ºC로 설정된 다른 remote를 사용해 온도를 더 올릴 때 장치가 21ºC로 "증가"하는 문제를 방지할 수 있습니다(장치가 이미 21ºC라고 생각하여 22ºC로 올리는 것이 아님).<sup>[[1]](#references)</sup>

---

## 공격 및 Offensive Research <a href="#attacks" id="attacks"></a>

Flipper Zero로 Infrared를 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box 탈취 (EvilScreen)

최근 academic work(EvilScreen, 2022)에서는 **Infrared와 Bluetooth 또는 Wi-Fi를 결합한 multi-channel remote가 최신 smart-TV를 완전히 hijack하는 데 악용될 수 있음**을 입증했습니다. 이 공격은 높은 privilege의 IR service code를 authenticated Bluetooth packet과 결합하여 channel isolation을 우회하고, 물리적 접근 없이 임의의 app 실행, microphone 활성화 또는 factory reset을 가능하게 합니다. ISO/IEC 27001 compliance를 주장한 Samsung model을 포함해 서로 다른 vendor의 mainstream TV 8대가 취약한 것으로 확인되었습니다. Mitigation에는 vendor firmware fix 또는 사용하지 않는 IR receiver의 완전한 disable이 필요합니다.<sup>[[2]](#references)</sup>

### IR LED를 통한 Air-Gapped Data Exfiltration (aIR-Jumper family)

Security camera, router 또는 악성 USB stick에는 **night-vision IR LED**가 포함된 경우가 많습니다. Research에 따르면 malware는 이러한 LED를 modulation하여(간단한 OOK 사용 시 <10~20 kbit/s) **벽과 창문을 통과해 수십 미터 떨어진 외부 camera로 secret을 exfiltrate**할 수 있습니다.<sup>[[3]](#references)</sup> 이 빛은 visible spectrum 밖에 있으므로 operator가 알아차리는 경우가 드뭅니다. Counter-measure:

* 민감한 구역의 IR LED를 물리적으로 차폐하거나 제거
* camera LED duty-cycle 및 firmware integrity 모니터링
* 창문과 surveillance camera에 IR-cut filter 배치

공격자는 강력한 IR projector를 사용해 데이터를 불안전한 camera로 flashing하여 network에 command를 **infiltrate**할 수도 있습니다.

### Flipper Zero 1.0을 사용한 장거리 Brute-Force 및 Extended Protocol

Firmware 1.0(2024년 9월)은 **수십 개의 추가 IR protocol과 선택적 external amplifier module**을 추가했습니다. universal-remote brute-force mode와 결합하면 Flipper는 high-power diode를 사용해 최대 30m 거리에서 대부분의 public TV/AC를 disable하거나 reconfigure할 수 있습니다.

---

## Tooling 및 Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay 및 dictionary-bruteforce mode를 지원하는 portable transceiver(위 참조).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 저렴하게 직접 제작할 수 있는 analyser/transmitter입니다. `Arduino-IRremote` library와 결합해 사용합니다(v4.x는 40개 이상의 protocol 지원).
* **Logic analyser** (Saleae/FX2) – protocol을 알 수 없을 때 raw timing을 capture합니다.
* **IR-blaster가 탑재된 smartphone**(예: Xiaomi) – 빠른 현장 테스트에 유용하지만 range가 제한적입니다.

### Software

* **`Arduino-IRremote`** – 지속적으로 유지 관리되는 C++ library:
```cpp
#include <IRremote.hpp>
IRsend sender;
void setup(){ sender.begin(); }
void loop(){
sender.sendNEC(0x20DF10EF, 32); // Samsung TV Power
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw capture를 import하고 protocol을 자동으로 식별하며 Pronto/Arduino code를 생성하는 GUI decoder입니다.
* **LIRC / ir-keytable (Linux)** – command line에서 IR을 수신하고 inject합니다:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* public space에 배치된 장치에서 필요하지 않은 경우 IR receiver를 disable하거나 덮습니다.
* smart-TV와 remote 간에 *pairing* 또는 cryptographic check를 강제하고, privileged "service" code를 isolate합니다.
* classified area 주변에 IR-cut filter 또는 continuous-wave detector를 배치해 optical covert channel을 차단합니다.
* 제어 가능한 IR LED를 노출하는 camera/IoT appliance의 firmware integrity를 모니터링합니다.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Smart TV Hijacking via Multi-channel Remote Control Mimicry (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Covert Air-Gap Exfiltration/Infiltration via Security Cameras & Infrared (IR) (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)

{{#include ../../banners/hacktricks-training.md}}
