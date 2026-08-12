# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID와 NFC에 대한 정보는 다음 페이지를 참고하세요:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 지원되는 NFC 카드 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC 카드 외에도 Flipper Zero는 여러 **Mifare** Classic 및 Ultralight와 **NTAG** 같은 **기타 유형의 High-frequency cards**를 지원합니다.

아래 기능 목록은 원문에서 설명한 firmware를 기준으로 하며, 현재의 전체 지원 매트릭스로 간주해서는 안 됩니다. Flipper firmware는 시간이 지나면서 프로토콜이 추가되고 NFC 동작이 변경되었으므로, 설치된 firmware에 대한 최신 공식 문서를 확인하세요.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — 저장하지 않고 UID, SAK, ATQA만 읽습니다.
- **Unknown cards** — UID, SAK, ATQA를 읽고 UID를 emulate합니다.

**NFC card types B, F, and V**의 경우, 문서화된 firmware는 저장하지 않고 UID를 읽을 수 있었습니다.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

문서화된 firmware는 bank card에서 UID, SAK, ATQA 및 사용 가능한 애플리케이션 데이터를 **저장하지 않고** 읽을 수 있었습니다.

이러한 bank card의 경우 firmware는 카드를 저장하거나 emulate하지 않고 데이터를 표시했습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero가 **NFC card의 type을 확인할 수 없는 경우**, **UID, SAK, ATQA**만 **읽고 저장할 수 있습니다**.

Unknown NFC card의 경우 이 모드에서는 UID만 emulate할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

원문에서 설명한 firmware에서는 NFC card types B, F, and V의 identifier를 저장하지 않고 읽어 표시하는 것만 가능했습니다.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 작업

NFC에 대한 소개는 [**이 페이지를 읽어보세요**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### 읽기

Flipper Zero는 NFC cards를 읽을 수 있지만 ISO 14443 기반의 모든 higher-level protocol을 구현하지는 않습니다. 따라서 application protocol을 확인할 수 없는 상태에서 low-level UID, SAK, ATQA만 복구할 수 있습니다. UID만으로 인증하는 primitive access system에서는 tool로 해당 identifier를 읽고 수동으로 입력하여 emulate할 수 있지만, cryptographically authenticated system에는 복사한 UID 이상의 정보가 필요합니다.<sup>[[1]](#references)</sup>

#### UID 읽기 VS 내부 데이터 읽기 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz tags를 읽는 작업은 두 부분으로 나눌 수 있습니다:<sup>[[1]](#references)</sup>

- **Low-level read** — UID, SAK, ATQA만 읽습니다. Flipper는 카드에서 읽은 이 데이터를 기반으로 high-level protocol을 추측합니다. 이는 특정 요소에 기반한 추정일 뿐이므로 100% 확신할 수 없습니다.
- **High-level read** — 특정 high-level protocol을 사용하여 카드 memory에서 데이터를 읽습니다. Mifare Ultralight의 데이터를 읽거나, Mifare Classic의 sectors를 읽거나, PayPass/Apple Pay에서 카드 attributes를 읽는 작업이 이에 해당합니다.

### 특정 항목 읽기

Flipper Zero가 low level data에서 카드 type을 확인하지 못하는 경우, `Extra Actions`에서 `Read Specific Card Type`을 선택하고 **읽으려는 카드 type을 수동으로** **지정할 수 있습니다**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

이전 Flipper firmware와 호환되는 EMV cards에서는 UID 외에도 PAN, expiration date, cardholder name 또는 transaction log가 카드에서 제공되는 경우 해당 정보를 노출할 수 있었습니다. 사용 가능 여부는 card, application 및 firmware에 따라 다릅니다. 카드에 인쇄된 magnetic-stripe CVV는 이러한 방식으로 노출되지 않으며, 이러한 records를 읽는다고 해서 contactless payment에 필요한 cryptographic transaction capability가 clone되는 것은 아닙니다.<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero로 RFID Protocol深入 탐구](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
