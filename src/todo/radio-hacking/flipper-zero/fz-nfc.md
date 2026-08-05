# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#id-9wrzi" id="id-9wrzi"></a>

Інформацію про RFID і NFC наведено на цій сторінці:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Підтримувані NFC-карти <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Окрім NFC-карт, Flipper Zero підтримує **інші типи високочастотних карт**, зокрема деякі карти **Mifare** Classic і Ultralight та **NTAG**.

До списку підтримуваних карт будуть додаватися нові типи NFC-карт. Flipper Zero підтримує такі **NFC-карти типу A** (ISO 14443A):

- **Банківські картки (EMV)** — лише зчитування UID, SAK і ATQA без збереження.
- **Невідомі карти** — зчитування (UID, SAK, ATQA) та емуляція UID.

Для **NFC-карт типу B, типу F і типу V** Flipper Zero може зчитувати UID без його збереження.

### NFC-карти типу A <a href="#uvusf" id="uvusf"></a>

#### Банківська картка (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zero може лише зчитувати UID, SAK, ATQA та збережені дані банківських карток **без збереження**.

Екран зчитування банківської карткиДля банківських карток Flipper Zero може лише зчитувати дані **без їх збереження та емуляції**.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Невідомі карти <a href="#id-37eo8" id="id-37eo8"></a>

Коли Flipper Zero **не може визначити тип NFC-карти**, можна **зчитати та зберегти** лише **UID, SAK і ATQA**.

Екран зчитування невідомої картиДля невідомих NFC-карт Flipper Zero може емулювати лише UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-карти типів B, F і V <a href="#wyg51" id="wyg51"></a>

Для **NFC-карт типів B, F і V** Flipper Zero може лише **зчитувати та відображати UID** без його збереження.

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Дії

Вступну інформацію про NFC дивіться на [**цій сторінці**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Зчитування

Flipper Zero може **зчитувати NFC-карти**, однак він **не розуміє всіх протоколів**, що базуються на ISO 14443. Оскільки **UID є низькорівневим атрибутом**, ви можете опинитися в ситуації, коли **UID уже зчитано, але протокол передавання даних високого рівня все ще невідомий**. За допомогою Flipper можна зчитувати, емулювати та вводити UID вручну для примітивних зчитувачів, які використовують UID для авторизації.<sup>[[1]](#references)</sup>

#### Зчитування UID VS зчитування даних усередині <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

У Flipper зчитування карт на частоті 13,56 МГц можна розділити на дві частини:<sup>[[1]](#references)</sup>

- **Зчитування низького рівня** — зчитує лише UID, SAK і ATQA. Flipper намагається визначити протокол високого рівня на основі цих даних, зчитаних із карти. Неможливо бути на 100% упевненим у цьому, оскільки це лише припущення, засноване на певних факторах.
- **Зчитування високого рівня** — зчитує дані з пам’яті карти за допомогою певного протоколу високого рівня. Це може бути зчитування даних із Mifare Ultralight, зчитування секторів із Mifare Classic або зчитування атрибутів карти з PayPass/Apple Pay.

### Спеціальне зчитування

Якщо Flipper Zero не може визначити тип карти з даних низького рівня, у `Extra Actions` можна вибрати `Read Specific Card Type` і **вручну** **вказати тип карти, яку потрібно зчитати**.

#### Банківські картки EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Окрім простого зчитування UID, із банківської картки можна отримати набагато більше даних. Можна **отримати повний номер картки** (16 цифр на лицьовому боці картки), **термін дії**, а в деяких випадках навіть **ім’я власника** разом зі списком **останніх транзакцій**.\
Однак у такий спосіб **неможливо зчитати CVV** (3 цифри на зворотному боці картки). Крім того, **банківські картки захищені від replay attacks**, тому копіювання картки за допомогою Flipper із подальшою спробою емулювати її для оплати не спрацює.<sup>[[1]](#references)</sup>

## Посилання

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
