# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 **300-928 MHz 범위의 라디오 주파수를 수신하고 전송**할 수 있는 내장 모듈을 가지고 있으며, 원격 제어 장치를 읽고 저장하며 에뮬레이트할 수 있습니다. 이러한 제어 장치는 게이트, 장벽, 라디오 잠금 장치, 원격 제어 스위치, 무선 초인종, 스마트 조명 등과의 상호작용에 사용됩니다. Flipper Zero는 보안이 침해되었는지 여부를 학습하는 데 도움을 줄 수 있습니다.

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 칩](https://www.ti.com/lit/ds/symlink/cc1101.pdf)을 기반으로 한 내장 서브 1 GHz 모듈과 라디오 안테나를 가지고 있으며 (최대 범위는 50미터입니다). CC1101 칩과 안테나는 300-348 MHz, 387-464 MHz 및 779-928 MHz 대역의 주파수에서 작동하도록 설계되었습니다.

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 작업

### 주파수 분석기

> [!NOTE]
> 원격 제어가 사용하는 주파수를 찾는 방법

분석할 때 Flipper Zero는 주파수 구성에서 사용 가능한 모든 주파수에서 신호 강도(RSSI)를 스캔합니다. Flipper Zero는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높은 신호 강도를 가진 주파수 중 가장 높은 RSSI 값을 표시합니다.

원격 제어의 주파수를 확인하려면 다음을 수행하십시오:

1. 원격 제어를 Flipper Zero의 왼쪽에 매우 가깝게 놓습니다.
2. **메인 메뉴** **→ Sub-GHz**로 이동합니다.
3. **주파수 분석기**를 선택한 다음 분석할 원격 제어의 버튼을 누르고 유지합니다.
4. 화면에서 주파수 값을 검토합니다.

### 읽기

> [!NOTE]
> 사용 중인 주파수에 대한 정보를 찾기 (또한 사용 중인 주파수를 찾는 또 다른 방법)

**읽기** 옵션은 **지정된 변조에서 구성된 주파수를 청취**합니다: 기본값은 433.92 AM입니다. 읽기 중 **무언가가 발견되면**, **정보가** 화면에 표시됩니다. 이 정보는 미래에 신호를 복제하는 데 사용할 수 있습니다.

읽기 중에는 **왼쪽 버튼**을 눌러 **구성할 수 있습니다**.\
현재 **4개의 변조**(AM270, AM650, FM328 및 FM476)와 **여러 관련 주파수**가 저장되어 있습니다:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**관심 있는 주파수**를 설정할 수 있지만, 원격 제어가 사용하는 주파수가 **확실하지 않은 경우**, **호핑을 켜기로 설정**(기본값은 꺼짐)하고 버튼을 여러 번 눌러 Flipper가 이를 캡처하고 주파수를 설정하는 데 필요한 정보를 제공하도록 합니다.

> [!CAUTION]
> 주파수 간 전환에는 시간이 걸리므로 전환 시 전송된 신호가 누락될 수 있습니다. 더 나은 신호 수신을 위해 주파수 분석기에 의해 결정된 고정 주파수를 설정하십시오.

### **원시 읽기**

> [!NOTE]
> 구성된 주파수에서 신호를 훔치고 (재생)하기

**원시 읽기** 옵션은 **청취 주파수에서 전송된 신호를 기록**합니다. 이는 신호를 **훔치고** **반복**하는 데 사용할 수 있습니다.

기본적으로 **원시 읽기는 AM650에서 433.92로 설정되어 있지만**, 읽기 옵션으로 관심 있는 신호가 **다른 주파수/변조에 있는 경우**, 원시 읽기 옵션 내에서 왼쪽 버튼을 눌러 수정할 수 있습니다.

### 무차별 대입

예를 들어 차고 문에 사용되는 프로토콜을 알고 있다면 **모든 코드를 생성하고 Flipper Zero로 전송할 수 있습니다.** 이는 일반적인 차고 유형을 지원하는 예입니다: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 수동 추가

> [!NOTE]
> 구성된 프로토콜 목록에서 신호 추가

#### [지원되는 프로토콜 목록](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (대부분의 정적 코드 시스템과 작동) | 433.92 | 정적  |
| --------------------------------------------------- | ------ | ----- |
| Nice Flo 12bit_433                                  | 433.92 | 정적  |
| Nice Flo 24bit_433                                  | 433.92 | 정적  |
| CAME 12bit_433                                      | 433.92 | 정적  |
| CAME 24bit_433                                      | 433.92 | 정적  |
| Linear_300                                          | 300.00 | 정적  |
| CAME TWEE                                           | 433.92 | 정적  |
| Gate TX_433                                         | 433.92 | 정적  |
| DoorHan_315                                         | 315.00 | 동적  |
| DoorHan_433                                         | 433.92 | 동적  |
| LiftMaster_315                                      | 315.00 | 동적  |
| LiftMaster_390                                      | 390.00 | 동적  |
| Security+2.0_310                                    | 310.00 | 동적  |
| Security+2.0_315                                    | 315.00 | 동적  |
| Security+2.0_390                                    | 390.00 | 동적  |

### 지원되는 Sub-GHz 공급업체

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)에서 목록을 확인하십시오.

### 지역별 지원되는 주파수

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)에서 목록을 확인하십시오.

### 테스트

> [!NOTE]
> 저장된 주파수의 dBms 가져오기

## 참조

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
