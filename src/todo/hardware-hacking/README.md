# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG (IEEE 1149.1) підтримує тестування boundary-scan за допомогою комірок, розміщених навколо I/O-контактів пристрою. Багато процесорів також надають vendor-specific функції налагодження через той самий Test Access Port (TAP); boundary scan і налагодження CPU є пов’язаними способами використання JTAG, але не синонімами.<sup>[[1]](#references)</sup>

Стандарт JTAG визначає **спеціальні команди для виконання boundary scan**, зокрема:

- **BYPASS** вибирає однобітний bypass register, щоб отримати доступ до інших пристроїв у scan chain із мінімальними накладними витратами.
- **SAMPLE/PRELOAD** зчитує значення контактів під час нормальної роботи та може попередньо завантажувати boundary-scan register перед виконанням іншої інструкції.
- **EXTEST** встановлює та зчитує стани контактів.

Також він може підтримувати інші команди, наприклад:

- **IDCODE** для ідентифікації пристрою
- **INTEST** для внутрішнього тестування пристрою

Ви можете зустріти ці інструкції під час використання такого інструмента, як JTAGulator.

### Test Access Port

**Test Access Port (TAP)** надає доступ до логіки JTAG-тестування компонента. Потрібні чотири сигнали, а `TRST` є необов’язковим:<sup>[[1]](#references)</sup>

- Вхід тактового сигналу тестування (**TCK**) TCK — це **clock**, який визначає, як часто TAP controller виконуватиме одну дію (іншими словами, переходитиме до наступного стану state machine).
- Вхід вибору тестового режиму (**TMS**) TMS керує **finite state machine**. На кожному такті clock JTAG TAP controller пристрою перевіряє напругу на контакті TMS. Якщо напруга нижча за певний поріг, сигнал вважається низьким і інтерпретується як 0; якщо напруга вища за певний поріг, сигнал вважається високим і інтерпретується як 1.
- Вхід тестових даних (**TDI**) послідовно передає інструкцію або тестові дані до вибраного TAP register. IEEE 1149.1 визначає поведінку передавання TAP, тоді як vendor визначають optional instructions і debug registers.
- Вихід тестових даних (**TDO**) — це контакт, який надсилає **data out of the chip**.
- Вхід скидання тестування (**TRST**) Необов’язковий TRST скидає finite state machine **до відомого робочого стану**. Як альтернативу, якщо утримувати TMS у стані 1 протягом п’яти послідовних тактів, виконується reset так само, як і через контакт TRST, тому TRST є необов’язковим.

Іноді ці контакти можна знайти з відповідними позначеннями на PCB. В інших випадках їх може знадобитися **знайти**.

### Визначення контактів JTAG

Швидким, спеціально призначеним для цього, але порівняно дорогим варіантом виявлення JTAG-портів є **JTAGulator**, який також може визначати pinout UART.<sup>[[2]](#references)</sup>

Він має **24 канали**, які можна під’єднати до тестових точок плати. Він перебирає можливі комбінації контактів за допомогою **IDCODE** і **BYPASS** scans та повідомляє канали, що відповідають виявленим JTAG-сигналам.

Дешевший, але значно повільніший спосіб визначення pinout JTAG — використання [**JTAGenum**](https://github.com/cyphunk/JTAGenum/), завантаженого на Arduino-compatible microcontroller.

За допомогою **JTAGenum** спочатку визначте контакти probing microcontroller, які використовуються для enumeration. Ознайомтеся з його pinout, а потім під’єднайте ці контакти до можливих тестових точок на цільовій платі.<sup>[[3]](#references)</sup>

**Третій спосіб** визначення контактів JTAG — **огляд PCB** на наявність відомого footprint. Деякі плати мають footprint **Tag-Connect**, хоча Tag-Connect — це connector system, який може передавати JTAG, SWD, UART або інший інтерфейс; сам по собі він не доводить, що контакти є JTAG. Потім datasheets компонентів і вимірювання continuity можуть допомогти визначити фактичні сигнали.<sup>[[5]](#references)</sup>

## SDW

SWD — це двоконтактний packet-based debug interface від Arm.<sup>[[4]](#references)</sup>

Інтерфейс використовує двонапрямний **SWDIO** для data та **SWCLK** для clock. Багато пристроїв реалізують **Serial Wire/JTAG Debug Port (SWJ-DP)**, який дає змогу вибирати між SWD і JTAG на спільних контактах.<sup>[[4]](#references)</sup>

## References

- [1] [Робоча група IEEE 1149.1 — JTAG і boundary scan](https://sagroups.ieee.org/1149/1/)
- [2] [Документація JTAGulator](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum — enumeration контактів JTAG для Arduino](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm — Debug interfaces з малою кількістю контактів для multi-device systems](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect — footprint кабелів для debug і programming](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
