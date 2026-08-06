# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) — це інструмент, який можна завантажити на MCU, сумісний з Arduino, або (експериментально) на Raspberry Pi, щоб методом brute-force визначити невідоме розташування виводів JTAG і навіть перелічити instruction registers.

- Arduino: підключіть цифрові виводи D2–D11 до 10 підозрюваних JTAG-площадок/testpoint максимум, а GND Arduino — до GND цільового пристрою. Живіть цільовий пристрій окремо, якщо ви не впевнені в безпечності цієї лінії живлення. Надавайте перевагу логіці 3.3 V (наприклад, Arduino Due) або використовуйте level shifter/послідовні резистори під час перевірки цілей з напругою 1.8–3.3 V.
- Raspberry Pi: збірка для Pi має менше доступних GPIO (тому сканування повільніше); перевірте репозиторій, щоб дізнатися актуальну карту виводів і обмеження.

Після прошивання відкрийте serial monitor на швидкості 115200 baud і надішліть `h`, щоб отримати довідку. Типовий процес:

- `l` — пошук loopback, щоб уникнути false positives
- `r` — перемикання внутрішніх pull-up за потреби
- `s` — сканування TCK/TMS/TDI/TDO (а іноді TRST/SRST)
- `y` — brute-force IR для виявлення undocumented opcodes
- `x` — boundary-scan знімок станів виводів

![JTAG - JTAGenum: x boundary-scan знімок станів виводів](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary-scan знімок станів виводів](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary-scan знімок станів виводів](<../../images/image (774).png>)



Якщо знайдено коректний TAP, ви побачите рядки, що починаються з `FOUND!` і вказують на виявлені виводи.

Поради
- Завжди з'єднуйте GND і ніколи не подавайте на невідомі виводи напругу, вищу за Vtref цільового пристрою. Якщо сумніваєтеся, додайте послідовні резистори 100–470 Ω на кандидатні виводи.
- Якщо пристрій використовує SWD/SWJ замість 4-провідного JTAG, JTAGenum може його не виявити; спробуйте SWD tools або адаптер із підтримкою SWJ-DP.

## Безпечніший пошук виводів і налаштування hardware

- Спочатку визначте Vtref і GND за допомогою мультиметра. Багатьом адаптерам потрібен Vtref для встановлення напруги I/O.
- Level shifting: надавайте перевагу двонапрямним level shifters, призначеним для push-pull signals (лінії JTAG не є open-drain). Уникайте I2C shifters з автоматичним визначенням напрямку для JTAG.
- Корисні адаптери: плати FT2232H/FT232H (наприклад, Tigard), CMSIS-DAP, J-Link, ST-LINK (vendor-specific), ESP-USB-JTAG (на ESP32-Sx). Мінімально підключіть TCK, TMS, TDI, TDO, GND і Vtref; за потреби також TRST і SRST.

## Перший контакт з OpenOCD (сканування та IDCODE)

OpenOCD — de-facto OSS для JTAG/SWD. За допомогою сумісного адаптера можна просканувати chain і прочитати IDCODE:<sup>[[1]](#references)</sup>

- Загальний приклад із J-Link:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- Вбудований USB-JTAG ESP32-S3 (зовнішній програматор не потрібен):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Примітки
- Якщо ви отримуєте IDCODE, що складається лише з одиниць/нулів, перевірте wiring, живлення, Vtref, а також переконайтеся, що порт не заблокований fuse/option bytes.
- Див. низькорівневі `irscan`/`drscan` в OpenOCD для ручної взаємодії з TAP під час налаштування невідомих ланцюжків.<sup>[[1]](#references)</sup>

## Зупинка CPU і зняття дампу пам’яті/flash

Після розпізнавання TAP і вибору target script можна зупинити core та зняти дамп регіонів пам’яті або внутрішньої flash-пам’яті. Приклади (змініть target, базові адреси та розміри відповідно до потреб):<sup>[[1]](#references)</sup>

- Generic target після init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (надавайте перевагу SBA, якщо доступний):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, програмування або читання через OpenOCD helper:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Поради
- Використовуйте `mdw/mdh/mdb`, щоб перевірити пам’ять перед тривалими дампами.
- Для ланцюгів із кількома пристроями установіть BYPASS для нецільових пристроїв або використовуйте файл плати, у якому визначені всі TAP.

## Прийоми boundary-scan (EXTEST/SAMPLE)

Навіть якщо доступ до налагодження CPU заблоковано, boundary-scan усе ще може бути доступним. За допомогою UrJTAG/OpenOCD можна:<sup>[[1]](#references)</sup>
- Використовувати SAMPLE для знімання станів виводів під час роботи системи (виявлення активності шини, підтвердження відповідності виводів).
- Використовувати EXTEST для керування виводами (наприклад, виконувати bit-bang ліній зовнішньої SPI flash через MCU, щоб зчитати її офлайн, якщо це дозволяє розводка плати).

Мінімальний робочий процес UrJTAG з адаптером FT2232x:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
Щоб знати порядок бітів boundary register, потрібен BSDL пристрою. Враховуйте, що деякі vendors блокують boundary-scan cells у production.

## Сучасні targets і примітки

- ESP32‑S3/C3 містять native USB‑JTAG bridge; OpenOCD може напряму взаємодіяти через USB без external probe. Дуже зручно для triage і dumps.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) широко підтримується OpenOCD; надавайте перевагу SBA для доступу до пам’яті, коли core не можна безпечно зупинити.
- Багато MCU реалізують debug authentication і lifecycle states. Якщо JTAG не працює, але живлення коректне, пристрій може бути заф’юзований у closed state або вимагати authenticated probe.

## Захист і hardening (чого очікувати на реальних пристроях)

- Назавжди вимикайте або блокуйте JTAG/SWD у production (наприклад, STM32 RDP level 2, ESP eFuses, що вимикають PAD JTAG, NXP/Nordic APPROTECT/DPAP).
- Вимагайте authenticated debug (ARMv8.2‑A ADIv6 Debug Authentication, OEM‑керований challenge‑response), зберігаючи manufacturing access.
- Не виводьте зручні test pads; ховайте test vias, видаляйте або встановлюйте resistors для ізоляції TAP, використовуйте connectors із keying або pogo‑pin fixtures.
- Power‑on debug lock: блокуйте TAP через early ROM, що забезпечує secure boot.

## Посилання

- [1] [Посібник користувача OpenOCD – команди та конфігурація JTAG](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Налагодження JTAG ESP32‑S3 від Espressif (USB‑JTAG, використання OpenOCD)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
