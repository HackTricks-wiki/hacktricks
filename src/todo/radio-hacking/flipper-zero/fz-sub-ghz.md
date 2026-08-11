# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#introduction" id="introduction"></a>

Flipper Zero는 내장 모듈을 사용하여 **300-928 MHz 범위의 radio frequency를 수신 및 송신**할 수 있으며, 구성된 지역의 주파수 제한이 적용됩니다. 게이트, 차단기, radio lock, 스위치, wireless doorbell, smart light 및 기타 장치에 사용되는 호환 remote control을 읽고, 저장하고, 에뮬레이션할 수 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero에는 CC1101 transceiver와 radio antenna를 기반으로 하는 내장 sub-1 GHz module이 있습니다. 실제 range는 frequency, antenna, environment 및 transmitter에 따라 달라지며, Flipper 문서에는 유리한 조건에서 약 50미터까지 도달한다고 설명되어 있습니다. Hardware는 300-348 MHz, 387-464 MHz 및 779-928 MHz를 지원하지만, firmware 및 지역 규정에 따라 transmission이 추가로 제한됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> remote가 사용하는 frequency를 찾는 방법

분석 중 Flipper Zero는 frequency configuration에서 사용 가능한 모든 frequency의 signal strength (RSSI)를 scan합니다. Flipper Zero는 RSSI 값이 가장 높은 frequency를 표시하며, signal strength는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높아야 합니다.<sup>[[1]](#references)</sup>

remote의 frequency를 확인하려면 다음을 수행합니다:

1. remote control을 Flipper Zero의 왼쪽에 최대한 가까이 둡니다.
2. **Main Menu** **→ Sub-GHz**로 이동합니다.
3. **Frequency Analyzer**를 선택한 다음, 분석하려는 remote control의 button을 길게 누릅니다.
4. 화면에 표시된 frequency 값을 확인합니다.

### Read

> [!TIP]
> 사용 중인 frequency에 대한 정보를 확인하는 방법 (사용 중인 frequency를 찾는 또 다른 방법)

**Read** option은 구성된 frequency와 modulation(기본값: 433.92 MHz AM)으로 listen합니다. 지원되는 signal을 인식하면 화면에 나중에 저장하고 replay할 수 있는 정보가 표시됩니다.<sup>[[1]](#references)</sup>

Read를 사용하는 동안 **left button**을 누르고 **configure**할 수 있습니다.\
현재 **4개의 modulation**(AM270, AM650, FM328 및 FM476)과 **여러 관련 frequency**가 저장되어 있습니다:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

허용된 frequency를 선택할 수 있습니다. remote가 사용하는 frequency를 모르는 경우 **Hopping을 ON**(기본값은 off)으로 설정한 다음, Flipper가 signal을 capture하고 frequency를 보고할 때까지 remote button을 여러 번 누릅니다.

> [!CAUTION]
> frequency 간 switching에는 시간이 걸리므로 switching 중에 전송된 signal을 놓칠 수 있습니다. signal reception을 향상하려면 Frequency Analyzer로 확인한 고정 frequency를 설정하십시오.

### **Read Raw**

> [!TIP]
> 구성된 frequency의 signal을 탈취하고 replay하는 방법

**Read Raw** option은 선택한 frequency로 전송된 signal을 기록합니다. authorized testing 중 signal을 capture하고 replay하는 데 사용할 수 있습니다.<sup>[[1]](#references)</sup>

기본적으로 **Read Raw도 AM650을 사용하는 433.92 MHz를 사용합니다**. Read option이 다른 frequency 또는 modulation에서 signal을 찾은 경우, Read Raw 내부에서 Left를 눌러 해당 설정을 변경합니다.

### Brute-Force

garage door와 같은 device가 사용하는 protocol을 알고 있다면 **candidate code를 생성하고 Flipper Zero로 전송**할 수 있습니다. `flipperzero-bruteforce` project는 여러 일반적인 static-code protocol을 지원합니다.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> 구성된 protocol list에서 signal을 추가하는 방법

#### List of supported protocols <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually menu에는 Flipper Zero에 문서화된 protocol preset이 표시됩니다.<sup>[[4]](#references)</sup>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
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

### Supported Sub-GHz vendors

Flipper Zero의 supported-vendors list를 확인하십시오.<sup>[[5]](#references)</sup>

### Supported Frequencies by region

transmit하기 전에 공식 regional-frequency list를 확인하십시오.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> 저장된 frequency의 dBm을 확인하는 방법

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
