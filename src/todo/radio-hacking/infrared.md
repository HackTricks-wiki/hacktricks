# 적외선

{{#include ../../banners/hacktricks-training.md}}

## 적외선 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선은 사람의 눈에 보이지 않습니다**. IR 파장은 **0.7~1000마이크론**입니다. 가정용 리모컨은 데이터 전송에 IR 신호를 사용하며, 0.75..1.4마이크론 파장 범위에서 작동합니다. 리모컨의 microcontroller는 적외선 LED를 특정 주파수로 깜박이게 하여 digital signal을 IR signal로 변환합니다.<sup>[[1]](#references)</sup>

IR signal을 수신하기 위해 **photoreceiver**가 사용됩니다. photoreceiver는 **IR light를 voltage pulse로 변환**하며, 이 신호는 이미 **digital signal**입니다. 일반적으로 receiver 내부에는 **dark light filter**가 있어 **원하는 파장만 통과**시키고 noise를 제거합니다.

### IR Protocol의 종류 <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocol은 다음 3가지 요소에 따라 달라집니다.

- bit encoding
- data structure
- carrier frequency — 일반적으로 36..38 kHz 범위

#### Bit encoding 방식 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. Pulse Distance Encoding**

bit는 pulse 사이의 space 지속 시간을 modulation하여 encoding됩니다. pulse 자체의 폭은 일정합니다.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. Pulse Width Encoding**

bit는 pulse width를 modulation하여 encoding됩니다. pulse burst 이후 space의 폭은 일정합니다.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. Phase Encoding**

Manchester encoding이라고도 합니다. logical value는 pulse burst와 space 사이 transition의 polarity로 결정됩니다. "Space to pulse burst"는 logic "0"을, "pulse burst to space"는 logic "1"을 나타냅니다.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 이전 방식의 조합 및 기타 특수 방식**

> [!TIP]
> 여러 유형의 device에서 universal해지려는 **IR protocol**이 있습니다. 가장 유명한 것은 RC5와 NEC입니다. 하지만 안타깝게도 가장 유명하다는 것이 **가장 널리 사용된다는 의미는 아닙니다**. 제가 접한 환경에서는 NEC remote는 두 개뿐이었고 RC5 remote는 하나도 없었습니다.
>
> Manufacturer는 같은 device 범위 내에서도(예: TV-box) 자신만의 고유한 IR protocol을 사용하기를 좋아합니다. 따라서 서로 다른 회사의 remote와 때로는 같은 회사의 서로 다른 model remote는 같은 유형의 다른 device와 작동하지 않습니다.

### IR signal 탐색

Remote의 IR signal이 어떻게 보이는지 확인하는 가장 신뢰할 수 있는 방법은 oscilloscope를 사용하는 것입니다. oscilloscope는 수신된 signal을 demodulate하거나 invert하지 않고, 단지 수신된 그대로 표시합니다. 이는 testing과 debugging에 유용합니다. 여기서는 NEC IR protocol을 예로 들어 예상 signal을 보여드리겠습니다.

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

일반적으로 encoding된 packet의 시작 부분에는 preamble이 있습니다. 이를 통해 receiver는 gain level과 background를 결정할 수 있습니다. Sharp와 같이 preamble이 없는 protocol도 있습니다.

그런 다음 data가 전송됩니다. structure, preamble 및 bit encoding 방식은 특정 protocol에 의해 결정됩니다.

**NEC IR protocol**에는 짧은 command와 button을 누르고 있는 동안 전송되는 repeat code가 포함됩니다. command와 repeat code 모두 시작 부분에 동일한 preamble이 있습니다.

NEC **command**는 preamble 외에도 device가 수행할 작업을 이해하는 데 사용하는 address byte와 command-number byte로 구성됩니다. transmission의 integrity를 확인하기 위해 address byte와 command-number byte는 inverse value로 복제됩니다. command 끝에는 추가 stop bit가 있습니다.

**repeat code**에는 preamble 뒤에 stop bit인 "1"이 있습니다.

**logic "0"과 "1"**에 대해 NEC는 Pulse Distance Encoding을 사용합니다. 먼저 pulse burst가 전송되고 그 뒤에 pause가 이어지며, pause의 길이가 bit 값을 결정합니다.

### Air Conditioner

다른 remote와 달리 **air conditioner는 누른 button의 code만 전송하지 않습니다**. 또한 button을 누를 때 **모든 정보도 전송**하여 **air conditioner와 remote가 synchronise된 상태를 유지하도록** 합니다.\
이렇게 하면 한 remote로 20ºC로 설정된 기기를 21ºC로 높인 뒤, 여전히 온도가 20ºC로 설정된 다른 remote를 사용해 온도를 더 높일 때 21ºC로 "높이는" 문제가 발생하지 않습니다(기기가 이미 21ºC라고 생각하여 22ºC로 높이지 않음).

---

## Attacks & Offensive Research <a href="#attacks" id="attacks"></a>

Flipper Zero를 사용하여 Infrared를 attack할 수 있습니다:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / Set-top Box Takeover (EvilScreen)

최근 academic research(EvilScreen, 2022)에서는 Infrared와 Bluetooth 또는 Wi-Fi를 결합한 **multi-channel remote를 악용하여 최신 smart-TV를 완전히 hijack할 수 있음**을 입증했습니다. 이 attack은 높은 privilege의 IR service code를 authenticated Bluetooth packet과 함께 사용하여 channel-isolation을 bypass하고, physical access 없이 임의의 app 실행, microphone 활성화 또는 factory-reset을 허용합니다. Samsung model(ISO/IEC 27001 compliance를 주장한 model)을 포함해 서로 다른 vendor의 mainstream TV 8종에서 취약점이 확인되었습니다. Mitigation을 위해서는 vendor firmware fix를 적용하거나 사용하지 않는 IR receiver를 완전히 disable해야 합니다.<sup>[[2]](#references)</sup>

### IR LED를 통한 Air-Gapped Data Exfiltration (aIR-Jumper family)

Security camera, router 또는 malicious USB stick에도 **night-vision IR LED**가 포함된 경우가 많습니다. Research에 따르면 malware는 이 LED를 modulation하여(간단한 OOK 사용 시 <10–20 kbit/s) **수십 미터 떨어진 외부 camera로 벽과 창문을 통해 secret을 exfiltrate**할 수 있습니다. 이 light는 visible spectrum 밖에 있으므로 operator가 알아차리는 경우가 거의 없습니다. Counter-measure는 다음과 같습니다.

* 민감한 영역의 IR LED를 물리적으로 차폐하거나 제거
* camera LED duty-cycle 및 firmware integrity 모니터링
* 창문과 surveillance camera에 IR-cut filter 배치

Attacker는 강력한 IR projector를 사용하여 data를 불안정한 camera로 다시 flashing함으로써 network에 command를 **infiltrate**할 수도 있습니다.

### Flipper Zero 1.0을 사용한 Long-Range Brute-Force 및 Extended Protocol

Firmware 1.0(2024년 9월)은 **수십 가지의 추가 IR protocol과 선택적 external amplifier module**을 추가했습니다. universal-remote brute-force mode와 결합하면 Flipper는 high-power diode를 사용하여 최대 30m 거리에서 대부분의 public TV/AC를 disable하거나 reconfigure할 수 있습니다.

---

## Tooling & Practical Examples <a href="#tooling" id="tooling"></a>

### Hardware

* **Flipper Zero** – learning, replay 및 dictionary-bruteforce mode를 지원하는 portable transceiver(위 내용 참조).
* **Arduino / ESP32** + IR LED / TSOP38xx receiver – 저렴한 DIY analyser/transmitter. `Arduino-IRremote` library와 함께 사용할 수 있습니다(v4.x는 40개 이상의 protocol 지원).
* **Logic analyser**(Saleae/FX2) – protocol을 알 수 없을 때 raw timing을 capture.
* **IR-blaster가 장착된 smartphone**(예: Xiaomi) – 간단한 현장 test에 유용하지만 range가 제한적입니다.

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
* **IRscrutinizer / AnalysIR** – raw capture를 import하고 protocol을 자동 식별하며 Pronto/Arduino code를 생성하는 GUI decoder.
* **LIRC / ir-keytable (Linux)** – command line에서 IR을 receive하고 inject:
```bash
sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
irsend SEND_ONCE samsung KEY_POWER
```

---

## Defensive Measures <a href="#defense" id="defense"></a>

* 필요하지 않은 경우 public space에 배치된 device의 IR receiver를 disable하거나 가립니다.
* smart-TV와 remote 사이에 *pairing* 또는 cryptographic check를 적용하고, privilege가 높은 "service" code를 isolate합니다.
* classified area 주변에 IR-cut filter 또는 continuous-wave detector를 배치하여 optical covert channel을 차단합니다.
* 제어 가능한 IR LED를 노출하는 camera/IoT appliance의 firmware integrity를 모니터링합니다.

## References

- [1] [Flipper Zero Infrared blog post](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen: remote control mimicry를 통한 Smart TV hijacking](https://arxiv.org/abs/2210.03014)

{{#include ../../banners/hacktricks-training.md}}
