# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#id-9wrzi" id="id-9wrzi"></a>

Інформацію про RFID та NFC дивіться на цій сторінці:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Підтримувані NFC-картки <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Окрім NFC-карток, Flipper Zero підтримує **інші типи високочастотних карток**, зокрема деякі картки **Mifare** Classic та Ultralight, а також **NTAG**.

Наведений нижче список можливостей описує прошивку, задокументовану в оригінальній статті, і не має вважатися повною актуальною матрицею підтримки. Прошивки Flipper з часом додавали протоколи та змінювали поведінку NFC; перевіряйте актуальну офіційну документацію для встановленої прошивки.<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Банківські картки (EMV)** — лише зчитування UID, SAK і ATQA без збереження.
- **Невідомі картки** — зчитування UID, SAK і ATQA та емуляція UID.

Для **карток NFC типів B, F і V** задокументована прошивка могла зчитати UID без його збереження.

### Картки NFC типу A <a href="#uvusf" id="uvusf"></a>

#### Банківська картка (EMV) <a href="#kzmrp" id="kzmrp"></a>

Задокументована прошивка могла зчитувати UID, SAK, ATQA та доступні дані застосунку з банківської картки **без збереження**.

Для цих банківських карток прошивка відображала дані, не зберігаючи й не емулюючи картку.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Невідомі картки <a href="#id-37eo8" id="id-37eo8"></a>

Якщо Flipper Zero **не може визначити тип NFC-картки**, тоді можна **зчитати та зберегти** лише **UID, SAK і ATQA**.

Для невідомої NFC-картки цей режим може емулювати лише її UID.

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### Картки NFC типів B, F і V <a href="#wyg51" id="wyg51"></a>

У прошивці, задокументованій в оригінальній статті, для карток NFC типів B, F і V можна було лише зчитати й відобразити ідентифікатор без його збереження.<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Дії

Вступ про NFC — [**читайте на цій сторінці**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1).

### Зчитування

Flipper Zero може зчитувати NFC-картки, але не реалізує всі протоколи вищого рівня, побудовані на ISO 14443. Тому він може отримати UID, SAK і ATQA на низькому рівні, не визначивши протокол застосунку. Для простих систем контролю доступу, які авторизують лише за UID, пристрій може зчитати, дозволити вручну ввести й емулювати цей ідентифікатор; для систем із криптографічною автентифікацією недостатньо скопіювати UID.<sup>[[1]](#references)</sup>

#### Зчитування UID VS зчитування даних усередині картки <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

У Flipper зчитування міток 13,56 MHz можна розділити на дві частини:<sup>[[1]](#references)</sup>

- **Зчитування низького рівня** — зчитуються лише UID, SAK і ATQA. Flipper намагається визначити протокол вищого рівня на основі зчитаних із картки даних. Це не дає стовідсоткової впевненості, оскільки є лише припущенням на основі певних чинників.
- **Зчитування високого рівня** — зчитуються дані з пам’яті картки за допомогою певного протоколу вищого рівня. Наприклад, зчитування даних із Mifare Ultralight, секторів із Mifare Classic або атрибутів картки з PayPass/Apple Pay.

### Вибір типу картки для зчитування

Якщо Flipper Zero не може визначити тип картки за даними низького рівня, у розділі `Extra Actions` можна вибрати `Read Specific Card Type` і **вручну** **вказати тип картки, яку потрібно зчитати**.

#### Банківські картки EMV (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

Старіші прошивки Flipper та сумісні картки EMV могли розкривати більше, ніж UID, потенційно включно з PAN, терміном дії, ім’ям власника картки або журналом транзакцій, якщо картка надавала ці записи. Доступність залежить від картки, застосунку та прошивки. CVV магнітної смуги, надрукований на картці, таким способом не розкривається, а зчитування цих записів не клонує криптографічні можливості для транзакцій, необхідні для безконтактної оплати.<sup>[[1]](#references)</sup>

## References

- [1] [Занурення у протоколи RFID з Flipper Zero](https://blog.flipperzero.one/rfid/)
- [2] [Документація Flipper Zero — NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
