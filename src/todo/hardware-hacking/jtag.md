# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) — це інструмент, який можна завантажити на MCU, сумісний з Arduino, або (експериментально) на Raspberry Pi, щоб виконати brute-force невідомої розводки контактів JTAG і навіть перерахувати регістри інструкцій.

- Arduino: підключіть цифрові піни D2–D11 максимум до 10 підозрюваних JTAG-падів/тестових точок, а GND Arduino — до GND цільового пристрою. Живіть цільовий пристрій окремо, якщо ви не впевнені в безпечності цієї шини живлення. Надавайте перевагу логіці 3.3 V (наприклад, Arduino Due) або використовуйте level shifter/послідовні резистори під час probing цільових пристроїв із напругою 1.8–3.3 V.
- Raspberry Pi: збірка для Pi має менше доступних GPIO (тому сканування повільніше); перевірте репозиторій, щоб дізнатися актуальну карту пінів та обмеження.

Після прошивання відкрийте serial monitor на швидкості 115200 бод і надішліть `h`, щоб отримати довідку. Типовий порядок дій:

- `l` — знайти loopback-з'єднання, щоб уникнути false positive
- `r` — за потреби перемкнути внутрішні pull-up
- `s` — просканувати TCK/TMS/TDI/TDO (а іноді TRST/SRST)
- `y` — виконати brute-force IR, щоб виявити недокументовані opcode
- `x` — зробити boundary-scan знімок станів пінів

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



Якщо знайдено валідний TAP, ви побачите рядки, що починаються з `FOUND!` і вказують на виявлені піни.

Поради
- Завжди підключайте спільну землю й ніколи не подавайте на невідомі піни напругу, вищу за Vtref цільового пристрою. Якщо сумніваєтеся, додайте послідовні резистори 100–470 Ω на піни-кандидати.
- Якщо пристрій використовує SWD/SWJ замість 4-провідного JTAG, JTAGenum може його не виявити; спробуйте інструменти для SWD або адаптер із підтримкою SWJ-DP.

## Безпечніший пошук пінів і налаштування hardware

- Спочатку визначте Vtref і GND за допомогою мультиметра. Багатьом адаптерам потрібен Vtref для налаштування I/O voltage.
- Level shifting: надавайте перевагу двонапрямним level shifter, розробленим для push-pull сигналів (лінії JTAG не є open-drain). Не використовуйте I2C shifter з автоматичним визначенням напрямку для JTAG.
- Корисні адаптери: плати FT2232H/FT232H (наприклад, Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (на ESP32-Sx). Підключіть щонайменше TCK, TMS, TDI, TDO, GND і Vtref; опційно TRST і SRST.

## Перший контакт з OpenOCD (сканування та IDCODE)

OpenOCD — de-facto OSS для JTAG/SWD. За допомогою сумісного адаптера можна просканувати chain і прочитати IDCODE:

- Загальний приклад із J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Вбудований USB-JTAG ESP32-S3 (зовнішній probe не потрібен):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Нотатки
- Якщо ви отримуєте IDCODE, що складається лише з одиниць/нулів, перевірте підключення, живлення, Vtref і те, що порт не заблокований fuse/option bytes.
- Див. низькорівневі `irscan`/`drscan` в OpenOCD для ручної взаємодії з TAP під час запуску невідомих ланцюгів.<sup>[[1]](#references)</sup>

## Зупинка CPU і дамп пам’яті/flash

Після розпізнавання TAP і вибору target script можна зупинити core та створити дамп областей пам’яті або внутрішньої flash-пам’яті. Приклади (відкоригуйте target, базові адреси та розміри):

- Generic target після init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (за можливості надавайте перевагу SBA):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, програмування або читання через OpenOCD helper:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Поради
- Використовуйте `mdw/mdh/mdb`, щоб перевірити узгодженість памʼяті перед тривалими дампами.
- Для multi-device ланцюжків установлюйте BYPASS на нетаргетних пристроях або використовуйте board file, що визначає всі TAPs.

## Трюки boundary-scan (EXTEST/SAMPLE)

Навіть якщо debug-доступ до CPU заблоковано, boundary-scan усе ще може бути доступним. За допомогою UrJTAG/OpenOCD можна:
- SAMPLE — знімати стан контактів під час роботи системи (знаходити активність шини, підтверджувати відповідність контактів).
- EXTEST — керувати контактами (наприклад, виконувати bit-bang ліній зовнішньої SPI flash через MCU, щоб зчитати її offline, якщо це дозволяє wiring плати).

Мінімальний UrJTAG flow з адаптером FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Вам потрібен BSDL пристрою, щоб знати порядок бітів boundary register. Зверніть увагу, що деякі vendors блокують boundary-scan cells у production.

## Сучасні targets і примітки

- ESP32‑S3/C3 містять native USB‑JTAG bridge; OpenOCD може напряму працювати через USB без external probe. Дуже зручно для triage і dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) широко підтримується OpenOCD; надавайте перевагу SBA для доступу до пам’яті, коли core не можна безпечно зупинити.
- Багато MCUs реалізують debug authentication і lifecycle states. Якщо JTAG не працює, хоча живлення в нормі, пристрій може бути переведений fuse-ами у closed state або вимагати authenticated probe.

## Захист і hardening (чого очікувати на реальних пристроях)

- Назавжди вимикайте або блокуйте JTAG/SWD у production (наприклад, STM32 RDP level 2, ESP eFuses, які вимикають PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Вимагайте authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM-managed challenge-response), зберігаючи manufacturing access.
- Не виводьте прості test pads; ховайте test vias, видаляйте або встановлюйте resistors для ізоляції TAP, використовуйте connectors із keying або pogo-pin fixtures.
- Power-on debug lock: блокуйте TAP через early ROM, яка забезпечує secure boot.

## References

- [1] [Посібник користувача OpenOCD – JTAG Commands і конфігурація](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Налагодження JTAG на Espressif ESP32‑S3 (USB‑JTAG, використання OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
