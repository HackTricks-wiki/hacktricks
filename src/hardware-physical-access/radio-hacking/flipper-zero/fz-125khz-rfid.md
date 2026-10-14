# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## 소개

125 kHz 태그의 작동 방식에 대한 배경 정보는 다음을 참조하세요.

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[저주파 RFID 소개](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)에서 일반적인 태그 계열과 데이터 형식을 설명합니다.

## 동작

### 읽기

**Read**를 사용해 태그 데이터를 캡처하세요. 읽기에 성공하면 Flipper Zero가 저장된 태그를 에뮬레이션할 수 있습니다.<sup>[[1]](#references)</sup>

> [!WARNING]
> 일부 인터콤 리더는 읽기 전에 쓰기 명령을 전송해 쓰기 가능한 복제 태그인지 탐지하려고 합니다. Flipper Zero 에뮬레이션은 쓰기 가능한 태그 메모리를 동일한 방식으로 노출하지 않습니다.<sup>[[1]](#references)</sup>

### 수동으로 추가

Flipper Zero에 태그 데이터를 직접 입력하고 저장한 다음 에뮬레이션할 수 있습니다.<sup>[[1]](#references)</sup>

#### 카드에 표시된 ID

카드 외부에 ID의 전부 또는 일부가 인쇄되어 있는 경우도 있습니다.

- **EM Marin**

예를 들어, 사진의 EM-Marin 카드는 ID를 구성하는 5바이트 중 마지막 3바이트를 표시합니다. 태그를 읽을 수 없다면 누락된 2바이트를 brute-force로 찾을 수 있습니다.

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

마찬가지로, 사진의 HID 카드는 ID를 구성하는 3바이트 중 2바이트만 인쇄되어 있습니다.

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### 에뮬레이션/쓰기

태그를 읽거나 ID를 직접 입력한 후 Flipper Zero가 저장된 자격 증명을 에뮬레이션할 수 있습니다. 지원되는 쓰기 가능 태그의 경우 저장된 데이터를 호환되는 카드에 쓸 수도 있습니다.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFID 프로토콜 살펴보기](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
