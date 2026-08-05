# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## 소개

125kHz 태그의 작동 방식에 대한 자세한 내용은 다음을 확인하세요:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 동작

이러한 유형의 태그에 대한 자세한 내용은 [**이 소개 문서**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)를 확인하세요.

### 읽기

카드 정보를 **읽기** 위해 시도합니다. 그런 다음 카드를 **에뮬레이트**할 수 있습니다.<sup>[[1]](#references)</sup>

> [!WARNING]
> 일부 인터콤은 읽기 전에 write command를 전송하여 key duplication을 방지하려고 합니다. write가 성공하면 해당 태그는 가짜로 간주됩니다. Flipper가 RFID를 에뮬레이트할 때 리더는 이를 원본 태그와 구분할 방법이 없으므로 이러한 문제가 발생하지 않습니다.

### 수동으로 추가

수동으로 입력한 **데이터를 나타내는 가짜 카드**를 Flipper Zero에서 생성한 다음 에뮬레이트할 수 있습니다.

#### 카드의 ID

카드를 받았을 때 카드에 ID 또는 ID의 일부가 눈에 보이게 적혀 있는 경우가 있습니다.

- **EM Marin**

예를 들어 이 EM-Marin 카드에서는 실제 카드에 있는 5바이트 중 마지막 3바이트를 **평문으로 읽을 수 있습니다**.\
카드에서 나머지 2바이트를 읽을 수 없다면 brute-force할 수 있습니다.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

이 HID 카드도 마찬가지로 3바이트 중 2바이트만 카드에 인쇄되어 있습니다.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### 에뮬레이트/쓰기

카드를 **복사**하거나 ID를 **수동으로 입력**한 후 Flipper Zero로 카드를 **에뮬레이트**하거나 실제 카드에 **쓸** 수 있습니다.<sup>[[1]](#references)</sup>

## 참고 자료

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
