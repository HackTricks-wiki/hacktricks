# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID 및 NFC에 대한 정보는 다음 페이지를 확인하세요:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 지원되는 NFC 카드 <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC 카드를 제외하고 Flipper Zero는 여러 **Mifare** Classic 및 Ultralight와 **NTAG**와 같은 **다른 유형의 고주파 카드**를 지원합니다.

새로운 유형의 NFC 카드가 지원 카드 목록에 추가될 것입니다. Flipper Zero는 다음 **NFC 카드 유형 A** (ISO 14443A)를 지원합니다:

- **은행 카드 (EMV)** — UID, SAK 및 ATQA만 읽고 저장하지 않습니다.
- **알 수 없는 카드** — UID를 읽고 에뮬레이트합니다.

**NFC 카드 유형 B, F 및 V**의 경우, Flipper Zero는 UID를 읽을 수 있지만 저장하지 않습니다.

### NFC 카드 유형 A <a href="#uvusf" id="uvusf"></a>

#### 은행 카드 (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero는 은행 카드에서 UID, SAK, ATQA 및 저장된 데이터를 **저장하지 않고** 읽을 수 있습니다.

은행 카드 읽기 화면 은행 카드의 경우, Flipper Zero는 데이터를 **저장하지 않고 에뮬레이트하지 않고** 읽을 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 알 수 없는 카드 <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero가 **NFC 카드의 유형을 결정할 수 없을 때**, **UID, SAK 및 ATQA**만 **읽고 저장할 수 있습니다**.

알 수 없는 카드 읽기 화면 알 수 없는 NFC 카드의 경우, Flipper Zero는 UID만 에뮬레이트할 수 있습니다.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC 카드 유형 B, F 및 V <a href="#wyg51" id="wyg51"></a>

**NFC 카드 유형 B, F 및 V**의 경우, Flipper Zero는 UID를 **읽고 표시할 수 있지만** 저장하지 않습니다.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 작업

NFC에 대한 소개는 [**이 페이지를 읽어보세요**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### 읽기

Flipper Zero는 **NFC 카드를 읽을 수 있지만**, ISO 14443를 기반으로 한 모든 프로토콜을 **이해하지는 못합니다**. 그러나 **UID는 저수준 속성**이기 때문에, **UID가 이미 읽혔지만 고수준 데이터 전송 프로토콜은 여전히 알 수 없는 상황**에 처할 수 있습니다. Flipper를 사용하여 UID를 읽고 에뮬레이트하며 수동으로 입력할 수 있습니다.

#### UID 읽기 VS 내부 데이터 읽기 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper에서 13.56 MHz 태그 읽기는 두 부분으로 나눌 수 있습니다:

- **저수준 읽기** — UID, SAK 및 ATQA만 읽습니다. Flipper는 카드에서 읽은 이 데이터를 기반으로 고수준 프로토콜을 추측하려고 합니다. 이는 특정 요인을 기반으로 한 추정일 뿐이므로 100% 확신할 수는 없습니다.
- **고수준 읽기** — 특정 고수준 프로토콜을 사용하여 카드의 메모리에서 데이터를 읽습니다. 이는 Mifare Ultralight의 데이터를 읽거나 Mifare Classic의 섹터를 읽거나 PayPass/Apple Pay의 카드 속성을 읽는 것입니다.

### 특정 읽기

Flipper Zero가 저수준 데이터에서 카드 유형을 찾을 수 없는 경우, `Extra Actions`에서 `Read Specific Card Type`을 선택하고 **수동으로 읽고자 하는 카드 유형을 지정할 수 있습니다**.

#### EMV 은행 카드 (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UID를 단순히 읽는 것 외에도 은행 카드에서 더 많은 데이터를 추출할 수 있습니다. **전체 카드 번호**(카드 앞면의 16자리 숫자), **유효 기간**, 그리고 경우에 따라 **소유자의 이름**과 **가장 최근 거래 목록**을 **얻을 수 있습니다**.\
그러나 이 방법으로 **CVV를 읽을 수는 없습니다**(카드 뒷면의 3자리 숫자). 또한 **은행 카드는 재전송 공격으로부터 보호됩니다**, 따라서 Flipper로 복사한 후 이를 에뮬레이트하여 무언가를 결제하는 것은 작동하지 않습니다.

## 참고 문헌

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
