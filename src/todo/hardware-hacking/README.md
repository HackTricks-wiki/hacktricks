# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG дозволяє виконувати boundary scan. Boundary scan аналізує певні схеми, зокрема вбудовані boundary-scan cells і регістри для кожного піна.

Стандарт JTAG визначає **specific commands for conducting boundary scans**, зокрема такі:

- **BYPASS** дозволяє тестувати конкретний чип без накладних витрат на проходження через інші чипи.
- **SAMPLE/PRELOAD** знімає зразок даних, що надходять до пристрою та виходять із нього, коли він перебуває у звичайному режимі роботи.
- **EXTEST** встановлює та зчитує стани пінів.

Він також може підтримувати інші команди, як-от:

- **IDCODE** для ідентифікації пристрою
- **INTEST** для внутрішнього тестування пристрою

Ви можете зустріти ці інструкції під час використання такого інструмента, як JTAGulator.

### The Test Access Port

Boundary scans включають тестування чотирипровідного **Test Access Port (TAP)** — порту загального призначення, який забезпечує **access to the JTAG test support** functions, вбудованих у компонент. TAP використовує такі п’ять сигналів:

- Вхід тактового сигналу тестування (**TCK**) TCK — це **clock**, який визначає, як часто TAP controller виконуватиме одну дію (іншими словами, переходити до наступного стану в state machine).
- Вхід вибору режиму тестування (**TMS**) TMS керує **finite state machine**. На кожному такті clock JTAG TAP controller пристрою перевіряє напругу на піні TMS. Якщо напруга нижча за певний поріг, сигнал вважається низьким і інтерпретується як 0, тоді як якщо напруга вища за певний поріг, сигнал вважається високим і інтерпретується як 1.
- Вхід тестових даних (**TDI**) TDI — це пін, який надсилає **data into the chip through the scan cells**. Кожен vendor відповідає за визначення протоколу комунікації через цей пін, оскільки JTAG цього не визначає.
- Вихід тестових даних (**TDO**) TDO — це пін, який надсилає **data out of the chip**.
- Вхід скидання тестування (**TRST**) Необов’язковий TRST скидає finite state machine **to a known good state**. Альтернативно, якщо TMS утримується на рівні 1 протягом п’яти послідовних тактів clock, це викликає reset так само, як і пін TRST, тому TRST є необов’язковим.

Іноді ви зможете знайти позначення цих пінів на PCB. В інших випадках вам може знадобитися **find them**.

### Identifying JTAG pins

Найшвидший, але найдорожчий спосіб виявити JTAG ports — використати **JTAGulator**, пристрій, спеціально створений для цієї мети (хоча він **also detect UART pinouts**).

Він має **24 channels**, які можна під’єднати до пінів плати. Потім він виконує **BF attack** усіх можливих комбінацій, надсилаючи boundary scan commands **IDCODE** і **BYPASS**. Якщо він отримує відповідь, то відображає channel, що відповідає кожному JTAG signal

Дешевший, але значно повільніший спосіб визначити JTAG pinouts — використати [**JTAGenum**](https://github.com/cyphunk/JTAGenum/), завантажений на Arduino-compatible microcontroller.

Використовуючи **JTAGenum**, спочатку потрібно **define the pins of the probing** device, який ви використовуватимете для enumeration. Вам потрібно звернутися до pinout diagram пристрою, а потім з’єднати ці піни з test points на target device.

**Третій спосіб** ідентифікувати JTAG pins — **inspecting the PCB** на наявність одного з pinouts. У деяких випадках PCBs можуть зручно містити **Tag-Connect interface**, що є чіткою ознакою того, що плата також має JTAG connector. Ви можете побачити, який вигляд має цей interface, за адресою [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/). Крім того, перевірка **datasheets of the chipsets on the PCB** може виявити pinout diagrams, які вказують на JTAG interfaces.

## SDW

SWD — це ARM-specific protocol, розроблений для debugging.

Для SWD interface потрібні **two pins**: двонапрямний signal **SWDIO**, який є еквівалентом **TDI and TDO pins and a clock** у JTAG, і **SWCLK**, який є еквівалентом **TCK** у JTAG. Багато пристроїв підтримують **Serial Wire or JTAG Debug Port (SWJ-DP)** — комбінований JTAG і SWD interface, що дає змогу під’єднати до target або SWD, або JTAG probe.

{{#include ../../banners/hacktricks-training.md}}
