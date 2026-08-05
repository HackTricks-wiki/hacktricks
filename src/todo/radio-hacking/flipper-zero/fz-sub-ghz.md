# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero는 내장 모듈을 사용해 **300-928 MHz 범위의 radio frequencies를 수신하고 전송**할 수 있으며, remote control을 읽고 저장하고 emulate할 수 있습니다. 이러한 control은 gate, barrier, radio lock, remote control switch, wireless doorbell, smart light 등과 상호작용하는 데 사용됩니다. Flipper Zero를 사용하면 보안이 compromised되었는지 확인하는 데 도움이 됩니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 하드웨어 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero에는 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf)과 radio antenna(최대 range는 50 meters)를 기반으로 하는 내장 sub-1 GHz module이 있습니다. CC1101 chip과 antenna는 모두 300-348 MHz, 387-464 MHz, 779-928 MHz 대역의 frequencies에서 작동하도록 설계되었습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 작업

### Frequency Analyser

> [!TIP]
> remote가 사용하는 frequency를 확인하는 방법

분석하는 동안 Flipper Zero는 frequency configuration에서 사용 가능한 모든 frequencies의 signal strength(RSSI)를 scan합니다. Flipper Zero는 -90 [dBm](https://en.wikipedia.org/wiki/DBm)보다 높은 signal strength를 가진 가장 높은 RSSI 값을 표시합니다.<sup>[[1]](#references)</sup>

remote의 frequency를 확인하려면 다음을 수행합니다.

1. Flipper Zero의 왼쪽에 remote control을 매우 가까이 둡니다.
2. **Main Menu** **→ Sub-GHz**로 이동합니다.
3. **Frequency Analyzer**를 선택한 다음, 분석하려는 remote control의 button을 누른 채 유지합니다.
4. 화면에서 frequency 값을 확인합니다.

### Read

> [!TIP]
> 사용된 frequency에 대한 정보를 확인하는 방법(사용된 frequency를 확인하는 또 다른 방법)

**Read** option은 지정된 modulation으로 **configured frequency를 listen**합니다. 기본값은 433.92 AM입니다. Read 중 **무언가 발견되면** 화면에 **정보가 표시**됩니다. 이 정보는 나중에 signal을 replicate하는 데 사용할 수 있습니다.<sup>[[1]](#references)</sup>

Read를 사용하는 동안 **left button**을 눌러 **configure**할 수 있습니다.\
현재 **4개의 modulations**(AM270, AM650, FM328, FM476)과 **여러 relevant frequencies**가 저장되어 있습니다.

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**관심 있는 항목을 무엇이든 설정할 수 있습니다.** 그러나 보유한 remote가 어떤 frequency를 사용하는지 **확실하지 않다면**, **Hopping을 ON**으로 설정하고(기본값은 Off), Flipper가 signal을 capture하여 frequency 설정에 필요한 정보를 제공할 때까지 button을 여러 번 누릅니다.

> [!CAUTION]
> frequencies 사이를 전환하는 데 시간이 걸리므로 전환하는 순간 전송된 signals를 놓칠 수 있습니다. 더 나은 signal reception을 위해 Frequency Analyzer로 확인한 fixed frequency를 설정하세요.

### **Read Raw**

> [!TIP]
> configured frequency의 signal을 steal하고 replay하기

**Read Raw** option은 listening frequency로 전송된 signals를 **record**합니다. 이를 사용해 signal을 **steal**하고 **repeat**할 수 있습니다.

기본적으로 **Read Raw도 AM650의 433.92로 설정**되어 있지만, Read option을 사용해 관심 있는 signal이 **다른 frequency/modulation에 있다는 것을 확인했다면**, Read Raw option 안에서 left를 눌러 이를 변경할 수 있습니다.

### Brute-Force

예를 들어 garage door가 사용하는 protocol을 알고 있다면 **모든 codes를 generate하여 Flipper Zero로 전송할 수 있습니다.** 다음은 일반적인 garage 유형을 지원하는 예시입니다: [**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 수동으로 추가

> [!TIP]
> configured list의 protocols에서 signals 추가

#### [지원되는 protocols 목록](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (대부분의 static code systems에서 작동) | 433.92 | Static  |
| ----------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                    | 433.92 | Static  |
| Nice Flo 24bit_433                                    | 433.92 | Static  |
| CAME 12bit_433                                        | 433.92 | Static  |
| CAME 24bit_433                                        | 433.92 | Static  |
| Linear_300                                            | 300.00 | Static  |
| CAME TWEE                                             | 433.92 | Static  |
| Gate TX_433                                           | 433.92 | Static  |
| DoorHan_315                                           | 315.00 | Dynamic |
| DoorHan_433                                           | 433.92 | Dynamic |
| LiftMaster_315                                        | 315.00 | Dynamic |
| LiftMaster_390                                        | 390.00 | Dynamic |
| Security+2.0_310                                      | 310.00 | Dynamic |
| Security+2.0_315                                      | 315.00 | Dynamic |
| Security+2.0_390                                      | 390.00 | Dynamic |

### 지원되는 Sub-GHz vendor

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)에서 목록을 확인하세요.

### 지역별 지원 Frequencies

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)에서 목록을 확인하세요.

### Test

> [!TIP]
> 저장된 frequencies의 dBms 확인

## References

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
