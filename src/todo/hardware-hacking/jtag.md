# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** — це інструмент, який можна завантажити на MCU, сумісний з Arduino, або експериментально на Raspberry Pi, щоб перебором визначати невідомі розкладки контактів JTAG та перераховувати регістри інструкцій.<sup>[[3]](#references)</sup>

- Arduino: підключіть цифрові контакти D2–D11 максимум до 10 передбачуваних JTAG-площадок/тестових точок, а GND Arduino — до GND цільового пристрою. Живіть цільовий пристрій окремо, якщо не впевнені, що ця шина безпечна. Надавайте перевагу логіці 3.3 V (наприклад, Arduino Due) або використовуйте перетворювач рівнів/послідовні резистори під час перевірки цілей із напругою 1.8–3.3 V.
- Raspberry Pi: збірка для Pi надає менше придатних GPIO (тому сканування відбувається повільніше); перевірте репозиторій, щоб дізнатися поточну карту контактів та обмеження.

Після прошивання відкрийте serial monitor зі швидкістю 115200 бод і надішліть `h` для отримання довідки. Типовий порядок дій:

- `l` пошук loopback-з'єднань, щоб уникнути хибних спрацьовувань
- `r` перемикання внутрішніх pull-up, якщо потрібно
- `s` сканування TCK/TMS/TDI/TDO (а іноді TRST/SRST)
- `y` перебір IR для виявлення недокументованих opcode
- `x` знімок станів контактів boundary-scan

![JTAG - JTAGenum: x знімок станів контактів boundary-scan](<../../images/image (939).png>)

![JTAG - JTAGenum: x знімок станів контактів boundary-scan](<../../images/image (578).png>)

![JTAG - JTAGenum: x знімок станів контактів boundary-scan](<../../images/image (774).png>)



Якщо знайдено дійсний TAP, ви побачите рядки, що починаються з `FOUND!` і вказують на виявлені контакти.

### Поради з безпеки JTAGenum

- Завжди використовуйте спільну землю та ніколи не подавайте на невідомі контакти напругу, вищу за Vtref цільового пристрою. Якщо є сумніви, додайте послідовні резистори 100–470 Ω до контактів-кандидатів.
- Якщо пристрій використовує SWD/SWJ замість 4-провідного JTAG, JTAGenum може його не виявити; спробуйте інструменти SWD або адаптер із підтримкою SWJ-DP.

## Безпечніший пошук контактів і налаштування обладнання

- Спочатку визначте Vtref і GND за допомогою мультиметра. Багатьом адаптерам потрібен Vtref для встановлення напруги I/O.
- Перетворення рівнів: надавайте перевагу двонапрямним перетворювачам рівнів, призначеним для push-pull-сигналів (лінії JTAG не є open-drain). Уникайте I2C-перетворювачів з автоматичним визначенням напрямку для JTAG.
- Корисні адаптери: плати FT2232H/FT232H (наприклад, Tigard), CMSIS-DAP, J-Link, ST-LINK (специфічні для виробника), ESP-USB-JTAG (на ESP32-Sx). Мінімально підключіть TCK, TMS, TDI, TDO, GND і Vtref; додатково можна підключити TRST і SRST.

## Перше підключення до OpenOCD (сканування та IDCODE)

OpenOCD — фактичний стандарт OSS для JTAG/SWD. За допомогою підтримуваного адаптера можна просканувати ланцюг і прочитати IDCODE:<sup>[[1]](#references)</sup>

- Загальний приклад із J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Вбудований USB-JTAG ESP32‑S3 (зовнішній probe не потрібен):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Примітки

- Якщо ви отримуєте IDCODE, що складається лише з одиниць/нулів, перевірте підключення, живлення, Vtref і переконайтеся, що порт не заблокований fuse/option bytes.
- Для ручної взаємодії з TAP під час запуску невідомих ланцюжків див. низькорівневі `irscan`/`drscan` в OpenOCD.<sup>[[1]](#references)</sup>

## Зупинка CPU і створення дампу пам’яті/flash

Після розпізнавання TAP і вибору target script можна зупинити core і створити дамп областей пам’яті або внутрішньої flash-пам’яті. Приклади (змініть target, базові адреси та розміри):<sup>[[1]](#references)</sup>

- Generic target після init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (бажано SBA, якщо доступний):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, програмування або зчитування за допомогою OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Поради щодо дампінгу пам’яті

- Використовуйте `mdw/mdh/mdb`, щоб перевірити пам’ять перед створенням довгих дампів.
- Для ланцюжків із кількома пристроями встановлюйте BYPASS на пристроях, які не є цілями, або використовуйте файл плати, що визначає всі TAP.

## Прийоми boundary-scan (EXTEST/SAMPLE)

Навіть коли доступ до налагодження CPU заблоковано, boundary-scan може залишатися доступним. За допомогою UrJTAG/OpenOCD можна:<sup>[[1]](#references)</sup>
- Використовувати SAMPLE для знімка станів контактів під час роботи системи (знаходити активність шини, підтверджувати відповідність контактів).
- Використовувати EXTEST для керування контактами (наприклад, виконувати bit-bang ліній зовнішньої SPI flash через MCU, щоб прочитати її offline, якщо розводка плати це дозволяє).

Мінімальний процес UrJTAG з адаптером FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Потрібен BSDL пристрою, щоб знати порядок бітів boundary register. Враховуйте, що деякі vendors блокують boundary-scan cells у production.

## Сучасні targets і примітки

- ESP32‑S3/C3 містять native USB‑JTAG bridge; OpenOCD може напряму працювати через USB без зовнішнього probe. Дуже зручно для triage і dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) широко підтримується OpenOCD; надавайте перевагу SBA для доступу до пам’яті, коли core не можна безпечно зупинити.
- Багато MCU реалізують debug authentication і lifecycle states. Якщо JTAG не працює, але живлення правильне, пристрій може бути переведений fuse-ами у closed state або вимагати authenticated probe.

## Захист і hardening (чого очікувати на реальних пристроях)

- Назавжди вимикайте або блокуйте JTAG/SWD у production (наприклад, STM32 RDP level 2, ESP eFuses, що вимикають PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Вимагайте authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, challenge-response під керуванням OEM), зберігаючи доступ для manufacturing.
- Не виводьте легкодоступні test pads; ховайте test vias, видаляйте або встановлюйте resistors для ізоляції TAP, використовуйте connectors із keying або pogo-pin fixtures.
- Power-on debug lock: блокуйте TAP через early ROM, яка забезпечує secure boot.

## References

- [1] [Посібник користувача OpenOCD – команди JTAG і конфігурація](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Налагодження JTAG Espressif ESP32‑S3 (USB‑JTAG, використання OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – сканер розпіновки JTAG на базі Arduino](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
