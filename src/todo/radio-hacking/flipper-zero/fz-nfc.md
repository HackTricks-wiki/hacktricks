# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

Для інформації про RFID та NFC перегляньте наступну сторінку:

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Окрім NFC карт, Flipper Zero підтримує **інші типи високочастотних карт**, такі як кілька **Mifare** Classic та Ultralight і **NTAG**.

Нові типи NFC карт будуть додані до списку підтримуваних карт. Flipper Zero підтримує наступні **NFC картки типу A** (ISO 14443A):

- **Банківські картки (EMV)** — лише читання UID, SAK та ATQA без збереження.
- **Невідомі картки** — читання (UID, SAK, ATQA) та емуляція UID.

Для **NFC карток типу B, типу F та типу V**, Flipper Zero може читати UID без збереження.

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero може лише читати UID, SAK, ATQA та збережені дані на банківських картках **без збереження**.

Екран читання банківської картки. Для банківських карток Flipper Zero може лише читати дані **без збереження та емуляції**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Коли Flipper Zero **не може визначити тип NFC картки**, тоді можна лише **читати та зберігати UID, SAK та ATQA**.

Екран читання невідомої картки. Для невідомих NFC карток Flipper Zero може емуляціювати лише UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

Для **NFC карток типів B, F та V**, Flipper Zero може лише **читати та відображати UID** без збереження.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

Для вступу про NFC [**прочитайте цю сторінку**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zero може **читати NFC картки**, однак він **не розуміє всі протоколи**, що базуються на ISO 14443. Однак, оскільки **UID є атрибутом низького рівня**, ви можете опинитися в ситуації, коли **UID вже прочитано, але протокол передачі даних високого рівня все ще невідомий**. Ви можете читати, емуляціювати та вручну вводити UID, використовуючи Flipper для примітивних зчитувачів, які використовують UID для авторизації.

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

У Flipper читання міток 13.56 МГц можна поділити на дві частини:

- **Читання низького рівня** — читає лише UID, SAK та ATQA. Flipper намагається вгадати протокол високого рівня на основі цих даних, прочитаних з картки. Ви не можете бути на 100% впевненими в цьому, оскільки це лише припущення на основі певних факторів.
- **Читання високого рівня** — читає дані з пам'яті картки, використовуючи специфічний протокол високого рівня. Це буде читання даних на Mifare Ultralight, читання секторів з Mifare Classic або читання атрибутів картки з PayPass/Apple Pay.

### Read Specific

У разі, якщо Flipper Zero не може визначити тип картки з даних низького рівня, у `Extra Actions` ви можете вибрати `Read Specific Card Type` та **вручну** **вказати тип картки, яку ви хочете прочитати**.

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Окрім простого читання UID, ви можете витягти набагато більше даних з банківської картки. Можливо **отримати повний номер картки** (16 цифр на лицьовій стороні картки), **дату дії**, а в деяких випадках навіть **ім'я власника** разом зі списком **найбільш останніх транзакцій**.\
Однак, ви **не можете прочитати CVV таким чином** (3 цифри на звороті картки). Також **банківські картки захищені від атак повторного відтворення**, тому копіювання їх за допомогою Flipper і спроба емуляції для оплати чогось не спрацює.

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
