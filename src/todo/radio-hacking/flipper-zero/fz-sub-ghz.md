# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Вступ <a href="#introduction" id="introduction"></a>

Flipper Zero може **приймати та передавати радіочастоти в діапазоні 300-928 MHz** за допомогою вбудованого модуля з урахуванням частотних обмежень для налаштованого регіону. Він може зчитувати, зберігати та емулювати сумісні пульти дистанційного керування, що використовуються для воріт, шлагбаумів, радіозамків, перемикачів, бездротових дверних дзвінків, розумних ламп та інших пристроїв.<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Апаратне забезпечення Sub-GHz <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero має вбудований модуль частотою до 1 GHz на базі трансивера CC1101 і радіоантени. Фактична дальність залежить від частоти, антени, навколишнього середовища та передавача; документація Flipper вказує дальність до приблизно 50 метрів за сприятливих умов. Апаратне забезпечення охоплює діапазони 300-348 MHz, 387-464 MHz і 779-928 MHz, тоді як firmware та регіональні правила додатково обмежують передачу.<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Дії

### Frequency Analyser

> [!TIP]
> Як визначити, яку частоту використовує пульт

Під час аналізу Flipper Zero сканує рівень сигналу (RSSI) на всіх частотах, доступних у конфігурації частот. Flipper Zero відображає частоту з найвищим значенням RSSI, якщо рівень сигналу перевищує -90 [dBm](https://en.wikipedia.org/wiki/DBm).<sup>[[1]](#references)</sup>

Щоб визначити частоту пульта, виконайте такі дії:

1. Розмістіть пульт дуже близько ліворуч від Flipper Zero.
2. Перейдіть до **Main Menu** **→ Sub-GHz**.
3. Виберіть **Frequency Analyzer**, потім натисніть і утримуйте кнопку на пульті, який потрібно проаналізувати.
4. Перевірте значення частоти на екрані.

### Read

> [!TIP]
> Знайдіть інформацію про використовувану частоту (також інший спосіб визначити, яка частота використовується)

Опція **Read** прослуховує налаштовані частоту та modulation (за замовчуванням 433.92 MHz AM). Коли вона розпізнає підтримуваний сигнал, на екрані відображається інформація, яку можна зберегти та відтворити пізніше.<sup>[[1]](#references)</sup>

Під час використання Read можна натиснути **ліву кнопку** та **налаштувати його**.\
На цей момент доступні **4 modulations** (AM270, AM650, FM328 і FM476), а також **кілька відповідних частот**, що зберігаються:

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

Можна вибрати будь-яку дозволену частоту. Якщо ви не впевнені, яку частоту використовує пульт, увімкніть **Hopping** (за замовчуванням вимкнено), потім кілька разів натисніть кнопку пульта, доки Flipper не захопить сигнал і не повідомить частоту.

> [!CAUTION]
> Перемикання між частотами займає певний час, тому сигнали, передані під час перемикання, можуть бути пропущені. Для кращого приймання сигналу встановіть фіксовану частоту, визначену за допомогою Frequency Analyzer.

### **Read Raw**

> [!TIP]
> Викрасти (і відтворити) сигнал на налаштованій частоті

Опція **Read Raw** записує сигнали, надіслані на вибраній частоті. Це можна використовувати для захоплення та відтворення сигналу під час authorized testing.<sup>[[1]](#references)</sup>

За замовчуванням **Read Raw також використовує 433.92 MHz з AM650**. Якщо опція Read знайшла сигнал на іншій частоті або modulation, натисніть Left у Read Raw, щоб змінити ці налаштування.

### Brute-Force

Якщо ви знаєте протокол, який використовує такий пристрій, як гаражні ворота, може бути можливо **генерувати candidate codes і передавати їх за допомогою Flipper Zero**. Проєкт `flipperzero-bruteforce` підтримує кілька поширених протоколів зі статичними кодами.<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> Додайте сигнали зі списку налаштованих протоколів

#### List of supported protocols <a href="#id-3iglu" id="id-3iglu"></a>

Меню Add Manually містить попередні налаштування протоколів, задокументовані Flipper Zero.<sup>[[4]](#references)</sup>

| Princeton_433 (працює з більшістю систем зі статичними кодами) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### Підтримувані виробники Sub-GHz

Перегляньте список supported-vendors для Flipper Zero.<sup>[[5]](#references)</sup>

### Підтримувані частоти за регіонами

Перед передаванням перевірте офіційний список regional-frequency.<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> Отримайте значення dBm для збережених частот

## References

- [1] [Sub-GHz - Документація користувача Flipper Zero](https://docs.flipperzero.one/sub-ghz)
- [2] [Технічний опис Texas Instruments CC1101](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Додати вручну створений пульт](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Підтримувані виробники Sub-GHz](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Регіональні частоти Sub-GHz](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
