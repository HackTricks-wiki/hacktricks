# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#introduction" id="introduction"></a>

Flipper Zero는 내장 모듈을 사용해 **300~928 MHz 범위의 무선 주파수를 수신하고 송신할 수 있습니다**. 단, 설정된 지역의 주파수 제한이 적용됩니다. 게이트, 차단기, 무선 잠금장치, 스위치, 무선 초인종, 스마트 조명 및 기타 장치에 사용되는 호환 리모컨을 읽고, 저장하고, 에뮬레이션할 수 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero에는 CC1101 트랜시버와 무선 안테나를 기반으로 하는 내장 sub-1 GHz 모듈이 있습니다. 실제 작동 범위는 주파수, 안테나, 환경, 송신기에 따라 달라집니다. Flipper 문서에서는 유리한 조건에서 약 50미터까지 작동한다고 안내합니다. 하드웨어는 300~348 MHz, 387~464 MHz, 779~928 MHz 대역을 지원하지만, 펌웨어와 지역별 규정에 따라 송신이 추가로 제한됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 작업

### 주파수 분석기

> [!TIP]
> 리모컨이 사용하는 주파수를 찾는 방법

분석 중 Flipper Zero는 주파수 설정에서 사용할 수 있는 모든 주파수의 신호 세기(RSSI)를 스캔합니다. Flipper Zero는 RSSI 값이 가장 높은 주파수를 표시하며, 신호 세기는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높아야 합니다.<sup>[[1]](#references)</sup>

리모컨의 주파수를 확인하려면 다음 단계를 따르세요.

1. 리모컨을 Flipper Zero 왼쪽에 최대한 가까이 둡니다.
2. **메인 메뉴** **→ Sub-GHz**로 이동합니다.
3. **Frequency Analyzer**를 선택한 다음, 분석하려는 리모컨의 버튼을 길게 누릅니다.
4. 화면에 표시된 주파수 값을 확인합니다.

### 읽기

> [!TIP]
> 사용 주파수에 관한 정보를 확인하는 방법(주파수를 찾는 또 다른 방법)

**Read** 옵션은 설정된 주파수와 변조 방식(기본값은 433.92 MHz AM)으로 신호를 수신합니다. 지원되는 신호를 인식하면 화면에 정보가 표시되며, 이 정보를 저장해 나중에 다시 재생할 수 있습니다.<sup>[[1]](#references)</sup>

Read를 사용하는 동안 **왼쪽 버튼**을 눌러 **설정을 변경할 수 있습니다**.\
현재 **4가지 변조 방식**(AM270, AM650, FM328, FM476)과 저장된 **관련 주파수 여러 개**를 사용할 수 있습니다.

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

허용된 주파수를 선택할 수 있습니다. 리모컨이 사용하는 주파수를 모른다면 **Hopping을 ON**(기본값은 off)으로 설정한 다음, Flipper가 신호를 캡처하고 주파수를 표시할 때까지 리모컨 버튼을 여러 번 누르세요.

> [!CAUTION]
> 주파수를 전환하는 데 시간이 걸리므로 전환 중에 송신된 신호를 놓칠 수 있습니다. 신호를 더 잘 수신하려면 Frequency Analyzer로 확인한 고정 주파수를 설정하세요.

### **Raw 읽기**

> [!TIP]
> 설정된 주파수의 신호를 가로채기(및 다시 재생하기)

**Read Raw** 옵션은 선택한 주파수로 전송되는 신호를 기록합니다. 이를 사용해 승인된 테스트 중에 신호를 캡처하고 다시 재생할 수 있습니다.<sup>[[1]](#references)</sup>

기본적으로 **Read Raw도 AM650으로 433.92 MHz를 사용합니다**. Read 옵션에서 다른 주파수나 변조 방식의 신호를 찾았다면, Read Raw 화면에서 왼쪽 버튼을 눌러 설정을 변경하세요.

### 무차별 대입

차고 문과 같은 장치에서 사용하는 프로토콜을 알고 있다면, **후보 코드를 생성해 Flipper Zero로 송신할 수 있습니다**. `flipperzero-bruteforce` 프로젝트는 일반적인 여러 고정 코드 프로토콜을 지원합니다.<sup>[[3]](#references)</sup>

### 수동으로 추가

> [!TIP]
> 설정된 프로토콜 목록에서 신호 추가

#### 지원 프로토콜 목록 <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually 메뉴에는 Flipper Zero 문서에 설명된 프로토콜 프리셋이 표시됩니다.<sup>[[4]](#references)</sup>

| Princeton_433 (대부분의 고정 코드 시스템에서 작동) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### 지원되는 Sub-GHz 공급업체

Flipper Zero의 지원 공급업체 목록을 확인하세요.<sup>[[5]](#references)</sup>

### 지역별 지원 주파수

송신하기 전에 공식 지역별 주파수 목록을 확인하세요.<sup>[[6]](#references)</sup>

### 테스트

> [!TIP]
> 저장된 주파수의 dBm 확인

## References

- [1] [Sub-GHz - Flipper Zero 사용자 문서](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 데이터시트](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - 수동으로 만든 리모컨 추가](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - 지원되는 Sub-GHz 공급업체](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - 지역별 Sub-GHz 주파수](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
