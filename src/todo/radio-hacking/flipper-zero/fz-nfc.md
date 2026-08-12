# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#id-9wrzi" id="id-9wrzi"></a>

Докладніше про RFID і NFC дивіться на цій сторінці:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Підтримувані NFC-карти <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Окрім NFC-карт, Flipper Zero підтримує **інші типи високочастотних карт**, зокрема деякі карти **Mifare** Classic і Ultralight, а також **NTAG**.

Наведений нижче список можливостей описує firmware, задокументовану в оригінальній статті, і не повинен вважатися актуальною вичерпною матрицею підтримки. Firmware Flipper з часом отримувала нові протоколи, а поведінка NFC змінювалася; перевіряйте поточну офіційну документацію для встановленої firmware.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Банківські карти (EMV)** — лише зчитування UID, SAK і ATQA без збереження.
- **Невідомі карти** — зчитування UID, SAK і ATQA та емуляція UID.

Для **типів NFC-карт B, F і V** задокументована firmware могла зчитувати UID без його збереження.

### NFC-карти типу A <a href="#uvusf" id="uvusf"></a>

#### Банківська карта (EMV) <a href="#kzmrp" id="kzmrp"></a>

Задокументована firmware могла зчитувати UID, SAK, ATQA та доступні дані застосунків із банківської карти **без їх збереження**.

Для цих банківських карт firmware відображала дані, не зберігаючи та не емулюючи карту.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Невідомі карти <a href="#id-37eo8" id="id-37eo8"></a>

Якщо Flipper Zero **не може визначити тип NFC-карти**, можна **зчитати та зберегти** лише **UID, SAK і ATQA**.

Для невідомої NFC-карти цей режим може емулювати лише її UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC-карти типів B, F і V <a href="#wyg51" id="wyg51"></a>

У firmware, описаній в оригінальній статті, для NFC-карт типів B, F і V можна було лише зчитати та відобразити ідентифікатор без його збереження.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Дії

Вступну інформацію про NFC дивіться на [**цій сторінці**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Зчитування

Flipper Zero може зчитувати NFC-карти, але не реалізує кожен протокол вищого рівня, побудований на ISO 14443. Тому він може отримати низькорівневі UID, SAK і ATQA, залишивши протокол застосунку невідомим. Для примітивних систем доступу, які авторизують лише за UID, інструмент може зчитати, ввести вручну та емулювати цей ідентифікатор; системи з криптографічною автентифікацією потребують більшого, ніж скопійований UID.<sup>[[1]](#references)</sup>

#### Зчитування UID VS зчитування даних усередині <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

У Flipper зчитування карт на частоті 13,56 МГц можна розділити на дві частини:<sup>[[1]](#references)</sup>

- **Низькорівневе зчитування** — зчитує лише UID, SAK і ATQA. Flipper намагається визначити протокол вищого рівня на основі цих даних, зчитаних із карти. Неможливо бути впевненим на 100%, оскільки це лише припущення, засноване на певних факторах.
- **Високорівневе зчитування** — зчитує дані з пам’яті карти за допомогою певного протоколу вищого рівня. Це може бути зчитування даних із Mifare Ultralight, зчитування секторів із Mifare Classic або зчитування атрибутів карти з PayPass/Apple Pay.

### Спеціальне зчитування

Якщо Flipper Zero не може визначити тип карти за низькорівневими даними, у `Extra Actions` можна вибрати `Read Specific Card Type` і **вручну** **вказати тип карти, яку потрібно зчитати**.

#### Банківські карти EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Старі версії firmware Flipper і сумісні EMV-карти могли надавати більше, ніж UID, зокрема PAN, термін дії, ім’я власника карти або журнал транзакцій, якщо ці записи були доступні на карті. Доступність залежить від карти, застосунку та firmware. CVV магнітної смуги, надрукований на карті, у такий спосіб не розкривається, а зчитування цих записів не клонує криптографічну функціональність транзакцій, необхідну для здійснення безконтактного платежу.<sup>[[1]](#references)</sup>

## References

- [1] [Занурення в протоколи RFID за допомогою Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Документація Flipper Zero - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
