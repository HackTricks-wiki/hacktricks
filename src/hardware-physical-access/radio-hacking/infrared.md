# Infrared

{{#include ../../banners/hacktricks-training.md}}

## 적외선 작동 방식 <a href="#how-the-infrared-port-works" id="how-the-infrared-port-works"></a>

**적외선은 사람의 눈에 보이지 않습니다**. IR 파장은 **0.7~1000마이크론**입니다. 가정용 리모컨은 데이터 전송에 IR 신호를 사용하며, 0.75~1.4마이크론 파장 범위에서 작동합니다. 리모컨의 마이크로컨트롤러는 적외선 LED를 특정 주파수로 깜박이게 해 디지털 신호를 IR 신호로 변환합니다.

IR 신호를 수신하려면 **광수신기(photoreceiver)**를 사용합니다. 광수신기는 **IR 빛을 전압 펄스로 변환**하며, 이 펄스는 이미 **디지털 신호**입니다. 일반적으로 수신기 내부에는 **어두운 빛 필터**가 있어 **원하는 파장만 통과시키고** 노이즈를 차단합니다.<sup>[[1]](#references)</sup>

### 다양한 IR Protocol <a href="#variety-of-ir-protocols" id="variety-of-ir-protocols"></a>

IR protocol은 다음 세 가지 요소에서 차이가 납니다.<sup>[[1]](#references)</sup>

- 비트 인코딩
- 데이터 구조
- 반송파 주파수 — 대개 36~38 kHz 범위

#### 비트 인코딩 방식 <a href="#bit-encoding-ways" id="bit-encoding-ways"></a>

**1. 펄스 간격 인코딩(Pulse Distance Encoding)**

펄스 사이의 간격 길이를 변조해 비트를 인코딩합니다. 펄스 자체의 폭은 일정합니다.

<figure><img src="../../images/image (295).png" alt=""><figcaption></figcaption></figure>

**2. 펄스 폭 인코딩(Pulse Width Encoding)**

펄스 폭을 변조해 비트를 인코딩합니다. 펄스 버스트 뒤의 간격 길이는 일정합니다.

<figure><img src="../../images/image (282).png" alt=""><figcaption></figcaption></figure>

**3. 위상 인코딩(Phase Encoding)**

Manchester 인코딩이라고도 합니다. 펄스 버스트와 간격 사이의 전이 극성으로 논리값을 결정합니다. "간격에서 펄스 버스트로"의 전이는 논리 "0"을, "펄스 버스트에서 간격으로"의 전이는 논리 "1"을 나타냅니다.

<figure><img src="../../images/image (634).png" alt=""><figcaption></figcaption></figure>

**4. 앞선 방식의 조합 및 기타 특수 방식**

> [!TIP]
> 여러 종류의 기기에서 **범용으로 사용되도록 만들어진** IR protocol도 있습니다. 가장 유명한 것은 RC5와 NEC입니다. 안타깝게도 **가장 유명하다고 가장 흔한 것은 아닙니다**. 제가 접한 환경에서는 NEC 리모컨은 두 개뿐이었고 RC5 리모컨은 하나도 없었습니다.
>
> 제조업체는 같은 기기 범위(예: TV-box) 안에서도 고유한 IR protocol을 사용하는 것을 선호합니다. 따라서 서로 다른 회사의 리모컨은 물론, 같은 회사의 서로 다른 모델의 리모컨도 같은 종류의 다른 기기와 작동하지 않을 수 있습니다.

### IR 신호 살펴보기

리모컨의 IR 신호가 어떻게 생겼는지 확인하는 가장 신뢰할 수 있는 방법은 오실로스코프를 사용하는 것입니다. 오실로스코프는 수신된 신호를 복조하거나 반전하지 않고, "있는 그대로" 표시합니다. 테스트와 디버깅에 유용합니다. NEC IR protocol을 예로 들어 예상 신호를 보여드리겠습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (235).png" alt=""><figcaption></figcaption></figure>

일반적으로 인코딩된 패킷의 시작 부분에는 프리앰블이 있습니다. 이를 통해 수신기가 게인 레벨과 배경 신호를 파악할 수 있습니다. 예를 들어 Sharp처럼 프리앰블이 없는 protocol도 있습니다.

그다음 데이터가 전송됩니다. 구조, 프리앰블, 비트 인코딩 방식은 해당 protocol에 따라 정해집니다.

**NEC IR protocol**에는 짧은 명령과 버튼을 누르고 있는 동안 전송되는 반복 코드가 있습니다. 명령과 반복 코드 모두 시작 부분에 같은 프리앰블이 있습니다.

NEC **명령**은 프리앰블 외에도 주소 바이트와 명령 번호 바이트로 구성되며, 이를 통해 기기가 수행할 작업을 파악합니다. 전송 무결성을 확인하기 위해 주소 바이트와 명령 번호 바이트는 각각 역값과 함께 중복 전송됩니다. 명령 끝에는 추가 정지 비트가 있습니다.

**반복 코드**에는 프리앰블 뒤에 정지 비트인 "1"이 옵니다.

논리 **"0"과 "1"**을 표현하기 위해 NEC는 Pulse Distance Encoding을 사용합니다. 먼저 펄스 버스트를 전송한 다음 일시 정지하며, 그 길이로 비트값을 정합니다.

### 에어컨

다른 리모컨과 달리 **에어컨은 누른 버튼의 코드만 전송하지 않습니다**. 버튼을 누를 때마다 **모든 정보도 함께 전송**해 **에어컨과 리모컨이 동기화된 상태를 유지**합니다.\
이렇게 하면 한 리모컨으로 20ºC에서 21ºC로 올린 뒤, 여전히 온도가 20ºC로 설정된 다른 리모컨을 사용했을 때 온도가 22ºC가 아니라 21ºC로 "올라가는" 문제를 방지할 수 있습니다. <sup>[[1]](#references)</sup>

---

## 공격 및 Offensive Research <a href="#attacks" id="attacks"></a>

Flipper Zero로 Infrared를 공격할 수 있습니다:


{{#ref}}
flipper-zero/fz-infrared.md
{{#endref}}

### Smart-TV / 셋톱박스 탈취(EvilScreen)

최근 학술 연구(EvilScreen, 2022)는 Infrared와 Bluetooth 또는 Wi-Fi를 결합한 **멀티채널 리모컨을 악용해 최신 smart-TV를 완전히 탈취할 수 있음**을 입증했습니다. 이 공격은 높은 권한의 IR 서비스 코드와 인증된 Bluetooth 패킷을 연쇄적으로 사용해 채널 격리를 우회하고, 물리적 접근 없이 임의 앱 실행, 마이크 활성화 또는 공장 초기화를 가능하게 합니다. ISO/IEC 27001 준수를 내세운 Samsung 모델을 포함해 여러 제조업체의 주요 TV 8종이 취약한 것으로 확인됐습니다. 대응하려면 제조업체의 firmware 수정이 필요하거나 사용하지 않는 IR 수신기를 완전히 비활성화해야 합니다.<sup>[[2]](#references)</sup>

### IR LED를 통한 Air-Gapped 데이터 유출(aIR-Jumper 계열)

보안 카메라에는 **야간 투시용 IR LED**가 흔히 포함되어 있습니다. aIR-Jumper 프로토타입은 해당 LED를 제어하는 malware가 창문을 통해 외부 카메라로 비밀 정보를 **카메라당 최대 20 bit/s 속도로 유출**할 수 있음을 보였습니다. 반대 방향으로는 수백 미터에서 수 킬로미터에 이르는 거리에서 **100 bit/s가 넘는 속도로 침투**할 수 있음을 연구자들이 입증했습니다.<sup>[[3]](#references)</sup> 빛이 가시광선 영역 밖에 있어 운영자가 알아차리지 못할 수 있습니다. 대응책은 다음과 같습니다.

* 민감한 구역의 IR LED를 물리적으로 가리거나 제거
* 카메라 LED의 듀티 사이클과 firmware 무결성을 모니터링
* 창문과 보안 카메라에 IR 차단 필터 설치

공격자는 강력한 IR 프로젝터를 사용해 데이터를 취약한 카메라로 다시 깜박여 네트워크에 명령을 **침투**시킬 수도 있습니다.

### Flipper Zero 1.0을 사용한 장거리 Brute-Force 및 확장 Protocol

Firmware 1.0(2024년 9월)은 범용 리모컨 라이브러리를 확장하고 microSD에서 IR asset 파일을 동적으로 불러오는 기능을 추가했습니다.<sup>[[4]](#references)</sup> 학습 및 범용 리모컨 기능으로 주변 TV와 에어컨에 알려진 명령을 재생하거나 시도할 수 있습니다. 작동 거리는 송신기, 광학 장치, 주변광, 수신기에 크게 좌우됩니다. 외부 IR 하드웨어를 사용해 거리를 늘릴 수 있지만, 고정된 거리를 가정해서는 안 됩니다.

---

## 도구 및 실용 예시 <a href="#tooling" id="tooling"></a>

### 하드웨어

* **Flipper Zero** – 학습, 재생, 사전 기반 brute-force 모드를 지원하는 휴대용 송수신기(위 내용 참조).
* **Arduino / ESP32** + IR LED / TSOP38xx 수신기 – 저렴한 DIY 분석기/송신기. `Arduino-IRremote` 라이브러리와 함께 사용합니다(v4.x는 40개가 넘는 protocol 지원).
* **Logic analyzer**(Saleae/FX2) – protocol을 모를 때 원시 타이밍을 캡처합니다.
* **IR blaster가 있는 스마트폰**(예: Xiaomi) – 현장에서 빠르게 테스트할 수 있지만 거리는 제한적입니다.

### 소프트웨어

* **`Arduino-IRremote`** – 활발히 유지 관리되는 C++ 라이브러리:<sup>[[5]](#references)</sup>
  ```cpp
  #include <IRremote.hpp>
  void setup(){ IrSender.begin(3); }
  void loop(){
    IrSender.sendNEC(0x00, 0x10, 0); // address, command, repeats
    delay(5000);
  }
  ```
* **IRscrutinizer / AnalysIR** – raw 캡처를 가져와 protocol을 자동 식별하고 Pronto/Arduino 코드를 생성하는 GUI 디코더.
* **LIRC / ir-keytable (Linux)** – 명령줄에서 IR 신호를 수신하고 전송:
  ```bash
  sudo ir-keytable -p nec,rc5 -t   # live-dump decoded scancodes
  irsend SEND_ONCE samsung KEY_POWER
  ```

---

## 방어 조치 <a href="#defense" id="defense"></a>

* 공공장소에 설치된 기기에서 IR 수신기가 필요하지 않을 때는 비활성화하거나 가립니다.
* smart-TV와 리모컨 간의 *pairing* 또는 암호화 검증을 적용하고, 권한이 높은 “서비스” 코드는 격리합니다.
* 기밀 구역 주변에 IR-cut 필터 또는 연속파 탐지기를 설치해 광학 은밀 채널을 차단합니다.
* 제어 가능한 IR LED를 노출하는 카메라/IoT 기기의 펌웨어 무결성을 모니터링합니다.

## References

- [1] [Flipper Zero 적외선 블로그 게시물](https://blog.flipperzero.one/infrared/)
- [2] [EvilScreen 공격: 다중 채널 리모컨 모방을 통한 smart-TV 탈취 (arXiv:2210.03014)](https://arxiv.org/abs/2210.03014)
- [3] [aIR-Jumper: 보안 카메라 및 적외선(IR)을 통한 은밀한 에어갭 데이터 반출/유입 (arXiv:1709.05742)](https://arxiv.org/abs/1709.05742)
- [4] [Flipper Zero 블로그 - 펌웨어 1.0 출시](https://blog.flipper.net/released-firmware-1/)
- [5] [Arduino-IRremote - 사용법 및 프로토콜 문서](https://github.com/Arduino-IRremote/Arduino-IRremote)
{{#include ../../banners/hacktricks-training.md}}
