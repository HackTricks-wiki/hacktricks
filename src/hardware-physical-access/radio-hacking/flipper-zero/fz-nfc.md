# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID와 NFC에 대한 정보는 다음 페이지를 확인하세요:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 지원되는 NFC 카드 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC 카드 외에도 Flipper Zero는 여러 **Mifare** Classic 및 Ultralight, **NTAG** 등 **다른 유형의 고주파 카드**를 지원합니다.

아래 기능 목록은 원문에 소개된 펌웨어를 설명하며, 현재 지원 범위를 완전히 정리한 목록으로 간주해서는 안 됩니다. Flipper 펌웨어는 시간이 지나면서 프로토콜을 추가하고 NFC 동작을 변경해 왔으므로, 설치된 펌웨어의 최신 공식 문서를 확인하세요.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **은행 카드(EMV)** — UID, SAK, ATQA만 저장하지 않고 읽습니다.
- **알 수 없는 카드** — UID, SAK, ATQA를 읽고 UID를 에뮬레이트합니다.

**NFC 카드 유형 B, F, V**의 경우, 문서에 소개된 펌웨어는 UID를 저장하지 않고 읽을 수 있었습니다.

### NFC 카드 유형 A <a href="#uvusf" id="uvusf"></a>

#### 은행 카드(EMV) <a href="#kzmrp" id="kzmrp"></a>

문서에 소개된 펌웨어는 은행 카드의 UID, SAK, ATQA 및 사용 가능한 애플리케이션 데이터를 **저장하지 않고** 읽을 수 있었습니다.

이러한 은행 카드의 경우, 펌웨어는 데이터를 표시하되 카드를 저장하거나 에뮬레이트하지 않았습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 알 수 없는 카드 <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero가 **NFC 카드 유형을 판별할 수 없는 경우**, **UID, SAK, ATQA**만 **읽고 저장할 수 있습니다**.

알 수 없는 NFC 카드의 경우, 이 모드에서는 UID만 에뮬레이트할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC 카드 유형 B, F, V <a href="#wyg51" id="wyg51"></a>

원문에 소개된 펌웨어에서는 NFC 카드 유형 B, F, V의 식별자만 저장하지 않고 읽어 표시할 수 있었습니다.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 동작

NFC 소개는 [**이 페이지를 읽어보세요**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### 읽기

Flipper Zero는 NFC 카드를 읽을 수 있지만 ISO 14443 기반의 모든 상위 수준 프로토콜을 구현하지는 않습니다. 따라서 하위 수준 UID, SAK, ATQA는 읽어 오면서 애플리케이션 프로토콜은 알 수 없는 상태로 남을 수 있습니다. UID만으로 인증하는 기본적인 출입 시스템에서는 도구로 해당 식별자를 읽고, 수동으로 입력하고, 에뮬레이트할 수 있습니다. 암호화 인증 시스템에는 UID 복제 이상의 작업이 필요합니다.<sup>[[1]](#references)</sup>

#### UID 읽기와 내부 데이터 읽기의 차이 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz 태그 읽기는 두 부분으로 나눌 수 있습니다.<sup>[[1]](#references)</sup>

- **하위 수준 읽기** — UID, SAK, ATQA만 읽습니다. Flipper는 카드에서 읽은 이 데이터를 바탕으로 상위 수준 프로토콜을 추측합니다. 특정 요소를 근거로 한 추정일 뿐이므로, 이 결과를 100% 확신할 수는 없습니다.
- **상위 수준 읽기** — 특정 상위 수준 프로토콜을 사용해 카드 메모리의 데이터를 읽습니다. Mifare Ultralight의 데이터를 읽거나, Mifare Classic의 섹터를 읽거나, PayPass/Apple Pay의 카드 속성을 읽는 작업이 이에 해당합니다.

### 특정 카드 읽기

Flipper Zero가 하위 수준 데이터를 바탕으로 카드 유형을 식별하지 못하는 경우, `Extra Actions`에서 `Read Specific Card Type`을 선택하고 **읽으려는 카드 유형을 직접 지정**할 수 있습니다.

#### EMV 은행 카드(PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

구형 Flipper 펌웨어와 호환되는 EMV 카드에서는 UID 외에 PAN, 만료일, 카드 소유자 이름 또는 거래 로그까지 노출될 수 있었습니다. 단, 해당 기록이 카드에 제공되어 있어야 합니다. 제공되는 정보는 카드, 애플리케이션, 펌웨어에 따라 다릅니다. 카드에 인쇄된 마그네틱 스트라이프 CVV는 이 방법으로 노출되지 않으며, 이러한 기록을 읽어도 비접촉 결제에 필요한 암호화된 거래 기능이 복제되는 것은 아닙니다.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero로 RFID 프로토콜 살펴보기](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero 문서 - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
