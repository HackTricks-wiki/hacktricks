# 적외선

{{#include ../../banners/hacktricks-training.md}}

## 적외선 포트 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선은 사람의 눈에 보이지 않습니다**. IR 파장은 **0.7~1000마이크론**입니다. 가정용 리모컨은 데이터 전송에 IR 신호를 사용하며, 0.75..1.4마이크론의 파장 범위에서 작동합니다. 리모컨의 microcontroller는 적외선 LED를 특정 주파수로 깜박이게 하여 디지털 신호를 IR 신호로 변환합니다.

IR 신호를 수신하려면 **photoreceiver**를 사용합니다. photoreceiver는 **IR 광을 전압 펄스로 변환**하며, 이 펄스는 이미 **디지털 신호**입니다. 일반적으로 수신기 내부에는 **어두운 광 필터**가 있어 **원하는 파장만 통과**시키고 노이즈를 제거합니다.<sup>[[1]](#references)</sup>

### IR Protocol의 종류 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocol은 3가지 요소에서 서로 다릅니다:<sup>[[1]](#references)</sup>

- bit encoding
- data structure
- carrier frequency — 일반적으로 36..38 kHz 범위

#### Bit encoding 방식 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

펄스 사이의 space 지속 시간을 변조하여 bit를 인코딩합니다. 펄스 자체의 너비는 일정합니다.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

펄스 너비를 변조하여 bit를 인코딩합니다. 펄스 burst 이후 space의 너비는 일정합니다.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Manchester encoding이라고도 합니다. 논리값은 펄스 burst와 space 사이 전환의 polarity로 정의됩니다. "Space to pulse burst"는 logic "0"을, "pulse burst to space"는 logic "1"을 나타냅니다.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 이전 방식의 조합 및 기타 특수 방식**

> [!TIP]
> 여러 종류의 장치에서 **범용화되도록 설계된** IR protocol이 있습니다. 가장 유명한 것은 RC5와 NEC입니다. 안타깝게도 **가장 유명하다는 것이 가장 흔하다는 의미는 아닙니다**. 제가 사용하는 환경에서는 NEC 리모컨 두 개만 보았고 RC5 리모컨은 하나도 보지 못했습니다.
>
> 제조업체는 같은 장치 범위(예: TV-box) 내에서도 고유한 자체 IR protocol을 사용하는 것을 선호합니다. 따라서 서로 다른 회사의 리모컨은 물론이고, 같은 회사의 서로 다른 모델 리모컨도 같은 유형의 다른 장치와 작동하지 않는 경우가 있습니다.

### IR 신호 탐색

리모컨의 IR 신호가 실제로 어떻게 보이는지 확인하는 가장 신뢰할 수 있는 방법은 oscilloscope를 사용하는 것입니다. oscilloscope는 수신된 신호를 demodulate하거나 invert하지 않고 단지 "있는 그대로" 표시합니다. 이는 테스트와 debugging에 유용합니다. 여기서는 NEC IR protocol을 예로 들어 예상 신호를 보여드리겠습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

일반적으로 encoded packet의 시작 부분에는 preamble이 있습니다. 이를 통해 수신기는 gain level과 background를 판단할 수 있습니다. Sharp와 같이 preamble이 없는 protocol도 있습니다.

그다음 data가 전송됩니다. 구조, preamble 및 bit encoding 방식은 특정 protocol에 의해 결정됩니다.

**NEC IR protocol**에는 짧은 command와 버튼을 누르고 있는 동안 전송되는 repeat code가 포함됩니다. command와 repeat code 모두 시작 부분에 동일한 preamble이 있습니다.

NEC **command**는 preamble 외에도 address byte와 command-number byte로 구성되며, 장치는 이를 통해 수행할 작업을 파악합니다. 전송 무결성을 확인하기 위해 address와 command-number byte는 inverse value와 함께 중복됩니다. command 끝에는 추가 stop bit가 있습니다.

**repeat code**에는 preamble 뒤에 "1"이 있으며, 이는 stop bit입니다.

**logic "0"과 "1"**에 대해 NEC는 Pulse Distance Encoding을 사용합니다. 먼저 pulse burst가 전송되고 그다음 pause가 이어지며, pause의 길이가 bit 값을 결정합니다.

### 에어컨

다른 리모컨과 달리 **에어컨은 눌린 버튼의 code만 전송하지 않습니다**. 또한 버튼을 누를 때 **모든 정보도 전송**하여 **에어컨과 리모컨이 동기화되도록** 합니다.\
이를 통해 20ºC로 설정된 장치를 한 리모컨으로 21ºC로 올린 다음, 온도가 여전히 20ºC로 설정된 다른 리모컨으로 온도를 더 올릴 때 21ºC가 아닌 22ºC로 올리도록 "증가"하는 문제를 방지할 수 있습니다.<sup>[[1]](#references)</sup>

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Flipper Zero로 Infrared를 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box 탈취 (EvilScreen)

최근 academic work(EvilScreen, 2022)에서는 **Infrared와 Bluetooth 또는 Wi-Fi를 결합한 multi-channel 리모컨을 악용하여 최신 smart-TV를 완전히 hijack할 수 있음**을 보여주었습니다. 이 attack은 높은 권한의 IR service code를 인증된 Bluetooth packet과 연계하여 channel-isolation을 우회하고, 물리적 접근 없이 임의의 app 실행, microphone 활성화 또는 factory-reset을 수행할 수 있도록 합니다. ISO/IEC 27001 준수를 주장한 Samsung 모델을 포함해 서로 다른 vendor의 mainstream TV 8대가 취약한 것으로 확인되었습니다. 완화하려면 vendor firmware 수정 또는 사용하지 않는 IR receiver의 완전한 비활성화가 필요합니다.<sup>[[2]](#references)</sup>

### IR LED를 통한 Air-Gapped Data Exfiltration (aIR-Jumper family)

Security camera에는 일반적으로 **night-vision IR LED**가 포함됩니다. aIR-Jumper prototype은 이러한 LED를 제어하는 malware가 **창문을 통해 secrets를 외부 camera로 exfiltrate**할 수 있음을 보여주었습니다. 전송 속도는 수십 미터 거리에서 **surveillance camera당 최대 20 bit/s**였습니다. 반대 방향으로는 수백 미터에서 수 킬로미터 거리까지 **100 bit/s를 초과하는 속도**로 infiltration이 가능함을 연구진이 입증했습니다.<sup>[[3]](#references)</sup> 이 빛은 visible spectrum 밖에 있으므로 운영자가 알아차리지 못할 수 있습니다. Countermeasure에는 다음이 포함됩니다:

* 민감한 영역의 IR LED를 물리적으로 차폐하거나 제거
* camera LED duty-cycle 및 firmware integrity 모니터링
* 창문과 surveillance camera에 IR-cut filter 배치

공격자는 강력한 IR projector를 사용하여 데이터를 안전하지 않은 camera로 다시 flashing함으로써 network에 command를 **infiltrate**할 수도 있습니다.

### Flipper Zero 1.0을 사용한 Long-Range Brute-Force 및 Extended Protocol

Firmware 1.0(2024년 9월)은 universal-remotes library를 확장하고 microSD에서 infrared asset file을 동적으로 load하는 기능을 추가했습니다.<sup>[[4]](#references)</sup> 학습 및 universal-remote 기능을 사용하면 인근 TV와 에어컨에 알려진 command를 replay하거나 시도할 수 있습니다. Range는 emitter, optics, ambient light 및 receiver에 크게 좌우됩니다. 외부 IR hardware로 range를 확장할 수 있지만, 고정된 거리를 가정해서는 안 됩니다.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay 및 dictionary-bruteforce mode를 지원하는 portable transceiver(위 내용 참조).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 저렴한 DIY analyser/transmitter. `Arduino-IRremote` library와 결합하여 사용합니다(v4.x는 40개 이상의 protocol 지원).
* **Logic analyser**(Saleae/FX2) – protocol을 알 수 없을 때 raw timing을 capture.
* **IR-blaster가 있는 Smartphone**(예: Xiaomi) – 빠른 현장 테스트에 유용하지만 range가 제한적입니다.

### Software

* **`Arduino-IRremote`** – 활발히 유지 관리되는 C++ library:<sup>[[5]](#references)</sup>
```cpp
#include <IRremote.hpp>
void setup(){ IrSender.begin(3); }
void loop(){
IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
delay(5000);
}
```
* **IRscrutinizer / AnalysIR** – raw capture를 import하고 protocol을 자동 식별하며 Pronto/Arduino code를 생성하는 GUI decoder.
* **LIRC / ir-keytable (Linux)** – command line에서 IR을 receive하고 inject:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* 필요하지 않은 경우 public space에 배치된 device의 IR receiver를 disable하거나 덮습니다.
* smart-TV와 리모컨 사이에 *pairing* 또는 cryptographic check를 적용하고, 권한이 높은 "service" code를 isolate합니다.
* classified area 주변에 IR-cut filter 또는 continuous-wave detector를 배치하여 optical covert channel을 차단합니다.
* 제어 가능한 IR LED를 노출하는 camera/IoT appliance의 firmware integrity를 모니터링합니다.

## References

- [1] [Flipper Zero Infrared 블로그 게시물](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen Attack: Multi-channel Remote Control Mimicry를 통한 Smart TV Hijacking (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: Security Camera 및 Infrared (IR)을 통한 은밀한 Air-Gap Exfiltration/Infiltration (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero 블로그 - Firmware 1.0 출시](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - 사용법 및 protocol 문서](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
