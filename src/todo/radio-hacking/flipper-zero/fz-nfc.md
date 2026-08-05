# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 소개 <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID 및 NFC에 대한 정보는 다음 페이지를 확인하세요:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 지원되는 NFC 카드 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC 카드 외에도 Flipper Zero는 여러 **Mifare** Classic 및 Ultralight, **NTAG**와 같은 **기타 유형의 고주파 카드**를 지원합니다.

새로운 유형의 NFC 카드가 지원 카드 목록에 추가될 예정입니다. Flipper Zero는 다음 **NFC type A 카드**(ISO 14443A)를 지원합니다:

- **Bank cards (EMV)** — 저장하지 않고 UID, SAK 및 ATQA만 읽습니다.
- **Unknown cards** — (UID, SAK, ATQA)를 읽고 UID를 emulate합니다.

**NFC type B, type F 및 type V 카드**의 경우 Flipper Zero는 저장하지 않고 UID를 읽을 수 있습니다.

### NFC type A 카드 <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero는 **저장하지 않고** Bank card에서 UID, SAK, ATQA 및 저장된 데이터만 읽을 수 있습니다.

Bank card reading screenBank card의 경우 Flipper Zero는 데이터를 **저장하거나 emulate하지 않고** 읽기만 할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero가 **NFC 카드의 유형을 확인할 수 없는 경우**, **UID, SAK 및 ATQA**만 **읽고 저장할 수 있습니다**.

Unknown card reading screenUnknown NFC 카드의 경우 Flipper Zero는 UID만 emulate할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC type B, F 및 V 카드 <a href="#wyg51" id="wyg51"></a>

**NFC type B, type F 및 type V 카드**의 경우 Flipper Zero는 저장하지 않고 **UID를 읽어 표시**하기만 할 수 있습니다.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 동작

NFC에 대한 소개는 [**이 페이지를 읽어보세요**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### 읽기

Flipper Zero는 **NFC 카드를 읽을 수 있지만**, ISO 14443를 기반으로 하는 **모든 프로토콜을 이해하지는 못합니다**. 그러나 **UID는 low-level attribute**이므로, **UID는 이미 읽었지만 high-level data transfer protocol은 아직 알려지지 않은** 상황이 발생할 수 있습니다. UID를 인증에 사용하는 단순한 reader의 경우 Flipper를 사용하여 UID를 읽고, emulate하고, 수동으로 입력할 수 있습니다.<sup>[[1]](#references)</sup>

#### UID 읽기 VS 내부 데이터 읽기 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz 태그 읽기는 두 부분으로 나눌 수 있습니다:<sup>[[1]](#references)</sup>

- **Low-level read** — UID, SAK 및 ATQA만 읽습니다. Flipper는 카드에서 읽은 이 데이터를 기반으로 high-level protocol을 추측합니다. 이는 특정 요소를 기반으로 한 가정일 뿐이므로 100% 확신할 수는 없습니다.
- **High-level read** — 특정 high-level protocol을 사용하여 카드 memory의 데이터를 읽습니다. 이는 Mifare Ultralight의 데이터를 읽거나, Mifare Classic의 sector를 읽거나, PayPass/Apple Pay에서 카드 attribute를 읽는 작업입니다.

### 특정 항목 읽기

Flipper Zero가 low-level data에서 카드 유형을 확인하지 못하는 경우, `Extra Actions`에서 `Read Specific Card Type`을 선택하고 **읽고 싶은 카드 유형을** **수동으로** **지정할 수 있습니다**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

단순히 UID를 읽는 것 외에도 Bank card에서 훨씬 더 많은 데이터를 추출할 수 있습니다. **전체 카드 번호**(카드 앞면의 16자리), **유효기간**, 경우에 따라 **소유자의 이름**과 **최근 거래 내역**까지 가져올 수 있습니다.\
그러나 이 방법으로 **CVV는 읽을 수 없습니다**(카드 뒷면의 3자리 숫자). 또한 **Bank card는 replay attack으로부터 보호**되므로, Flipper로 카드를 복사한 다음 결제에 사용하도록 emulate하려 해도 작동하지 않습니다.<sup>[[1]](#references)</sup>

## 참고 자료

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
