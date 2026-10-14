# I2C

{{#include ../../banners/hacktricks-training.md}}

## Bus Pirate

> [!CAUTION]
> Перед підключенням Bus Pirate перевірте напругу цільового пристрою, розпіновку, схему підтягування та спільне заземлення. Не вмикайте джерела живлення Bus Pirate на шині, яка вже перебуває під напругою цільового пристрою, лише для її прослуховування: два джерела живлення можуть конфліктувати та пошкодити обладнання. Наведений нижче запис — це приклад для конкретного пристрою Bus Pirate v3 із community firmware, а не універсальна схема підключення.<sup>[[1]](#references)[[2]](#references)</sup>

Щоб перевірити, чи працює Bus Pirate, підключіть +5V до VPU, а 3.3V до ADC, відкрийте доступ до Bus Pirate (наприклад, за допомогою Tera Term) і введіть команду `~`:

```bash
# Use command
HiZ>~
Disconnect any devices
Connect (Vpu to +5V) and (ADC to +3.3V)
Space to continue
# Press space
Ctrl
AUX OK
MODE LED OK
PULLUP H OK
PULLUP L OK
VREG OK
ADC and supply
5V(4.96) OK
VPU(4.96) OK
3.3V(3.26) OK
ADC(3.27) OK
Bus high
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 0
MOSI OK
CLK OK
MISO OK
CS OK
Bus Hi-Z 1
MOSI OK
CLK OK
MISO OK
CS OK
MODE and VREG LEDs should be on!
Any key to exit
#Press space
Found 0 errors.
```

Як видно з попереднього командного рядка, помилок не знайдено. Це дуже корисно знати, щоб переконатися, що пристрій працює після придбання або прошивання firmware.

Щоб під’єднатися до Bus Pirate, можна скористатися документацією:

![Виконайте команду — натисніть пробіл: щоб під’єднатися до Bus Pirate, можна скористатися документацією](<../../images/image (484).png>)

У цьому випадку цільовий пристрій — I²C EEPROM сімейства 24C256. Перевірте точний суфікс і технічну документацію, оскільки підтримувана напруга живлення залежить від конкретної мікросхеми.<sup>[[3]](#references)</sup>

![Виконайте команду — натисніть пробіл: у цьому випадку я під’єднаюся до EPROM: ATMEL901 24C256 PU27](<../../images/image (964).png>)

Для взаємодії з Bus Pirate я використовував Tera Term, під’єднавшись до COM-порту Bus Pirate і задавши швидкість 115200 у меню Setup --> Serial Port --> Speed.\
У наведеному нижче обміні даними показано, як налаштувати Bus Pirate для роботи з I2C, а також як записувати дані в пам’ять і зчитувати їх (коментарі позначені символом "#"; не очікуйте побачити їх у самому обміні даними):

```bash
# Check communication with buspirate
i
Bus Pirate v3.5
Community Firmware v7.1 - goo.gl/gCzQnW [HiZ 1-WIRE UART I2C SPI 2WIRE 3WIRE KEYB LCD PIC DIO] Bootloader v4.5
DEVID:0x0447 REVID:0x3046 (24FJ64GA00 2 B8)
http://dangerousprototypes.com

# Check voltages
I2C>v
Pinstates:
1.(BR)  2.(RD)  3.(OR)  4.(YW)  5.(GN)  6.(BL)  7.(PU)  8.(GR)  9.(WT)  0.(Blk)
GND     3.3V    5.0V    ADC     VPU     AUX     SCL     SDA     -       -
P       P       P       I       I       I       I       I       I       I
GND     3.27V   4.96V   0.00V   4.96V   L       H       H       L       L

# This particular setup used 5 V pull-ups; do not generalize it to every 24C256 variant or board

# Get mode options
HiZ>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select I2C
(1)>4
I2C mode:
 1. Software
 2. Hardware

# Select Software mode
(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

# Select communication speed
(1)> 2
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start communication
I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Get macros
I2C>(0)
 0.Macro menu
 1.7bit address search
 2.I2C sniffer

#Get addresses of slaves connected
I2C>(1)
Searching I2C address space. Found devices at:
0xA0(0x50 W) 0xA1(0x50 R)

# Bus Pirate displays the 8-bit address bytes 0xA0 (write) and 0xA1 (read)
# Both correspond to the same 7-bit I2C target address, 0x50

# Write "BBB" in address 0x69
I2C>[0xA0 0x00 0x69 0x42 0x42 0x42]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
WRITE: 0x42 ACK
I2C STOP BIT

# Prepare to read from address 0x69
I2C>[0xA0 0x00 0x69]
I2C START BIT
WRITE: 0xA0 ACK
WRITE: 0x00 ACK
WRITE: 0x69 ACK
I2C STOP BIT

# Read 20B from address 0x69 configured before
I2C>[0xA1 r:20]
I2C START BIT
WRITE: 0xA1 ACK
READ: 0x42  ACK 0x42  ACK 0x42  ACK 0x20  ACK 0x48  ACK 0x69  ACK 0x20  ACK 0x44  ACK 0x72  ACK 0x65  ACK 0x67  ACK 0x21  ACK 0x20  ACK 0x41  ACK 0x41  ACK 0x41  ACK 0x00  ACK 0xFF  ACK 0xFF  ACK 0xFF
NACK
```

### Сніфер

У цьому сценарії ми перехоплюватимемо I2C-комунікацію між Arduino та попередньою EPROM. Потрібно лише встановити зв’язок між обома пристроями, а потім під’єднати Bus Pirate до контактів SCL, SDA та GND:

![Зчитування 20B з адреси 0x69, налаштованої раніше — Сніфер: У цьому сценарії ми перехоплюватимемо I2C-комунікацію між Arduino та попередньою EPROM. Потрібно лише...](<../../images/image (166).png>)

```bash
I2C>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

(1)>4
I2C mode:
 1. Software
 2. Hardware

(1)>1
Set speed:
 1. ~5kHz
 2. ~50kHz
 3. ~100kHz
 4. ~240kHz

(1)>1
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Historical transcript powered this bench setup. On a live target-powered bus, leave Bus Pirate power OFF.

I2C>W
POWER SUPPLIES ON
Clutch engaged!!!

# Start sniffing, you can see we sniffed a write command

I2C>(2)
Sniffer
Any key to exit
[0xA0+0x00+0x69+0x41+0x41+0x41+0x20+0x48+0x69+0x20+0x44+0x72+0x65+0x67+0x21+0x20+0x41+0x41+0x41+0x00+]
```

## Реконструкція протоколу I2C методом чорної скриньки

### Визначення шини за активними контактами

Якщо для периферійного пристрою немає розпіновки чи datasheet, почніть із пасивного спостереження за допомогою логічного аналізатора з високим вхідним опором, поки працює початковий хост. Забезпечивши спільне заземлення та безпечний логічний рівень, класифікуйте постійні сигнали як імовірні лінії живлення, землю або лінії з підтягуванням, а тоді порівняйте активні лінії з поширеними шинами: UART використовує асинхронні TX/RX з незалежними напрямками передавання; традиційний SPI зазвичай має тактову лінію, вибір мікросхеми та окремі лінії даних для кожного напрямку; I2C має регулярний тактовий сигнал і одну двонапрямлену лінію даних. Декодування I2C має виявити 7-бітні адреси цільових пристроїв, напрямок читання/запису, ACK/NACK і повторювані корисні навантаження.<sup>[[2]](#references)[[4]](#references)</sup>

Захопіть кілька легітимних обмінів і збережіть як декодовані байти, так і вихідні часові дані. Повторювані кадри стануть корисними тестами з відомими відповідями для подальших серіалізаторів, а відмінності між запитами можуть вказати на ймовірні поля коду операції, індексу, зсуву, довжини, послідовності або контрольної суми.<sup>[[4]](#references)</sup>

### Відновлення формату кадрів із firmware хоста

Якщо firmware периферійного пристрою недоступна, витягніть firmware **хоста** й знайдіть компонент, який відкриває пристрій I2C. Шукайте рядки та символи з назвою периферійного пристрою, `/dev/i2c-`, побудовниками команд, парсерами відповідей, процедурами скидання/ініціалізації та функціями контрольних сум. Для кожного побудовника запишіть точні зсуви полів, константи, допустимі розміри аргументів, довжину корисного навантаження, охоплення контрольної суми, порядок байтів контрольної суми й довжину поверненого кадру, а не вгадуйте формат за назвами функцій.<sup>[[4]](#references)</sup>

Назви функції контрольної суми `crc16_ccitt` недостатньо, щоб вибрати пресет. Визначте напрямок зсуву, байт індексу таблиці, поліном, представлений таблицею, початковий регістр, відображення вхідних/вихідних даних, фінальне XOR/інвертування та порядок байтів у серіалізаторі для передавання. Наприклад, таблиця молодших байтів зі зсувом праворуч, побудована на оберненому поліномі `0x8408`, з ініціалізацією `0xFFFF` і доповненням наприкінці відповідає **CRC-16/X-25 (IBM-SDLC)**. Правильна контрольна сума часто потрібна, щоб тестові приклади пройшли перевірку цілісності й дійшли до парсера команд.<sup>[[4]](#references)</sup>

Відновивши формат, пошукайте характерні назви символів і константи у відкритому коді. У випадку MJA1 знайдений незалежно SDK wrapper підтвердив ідентифікатори команд, перевірку аргументів, визначення відповідей і дзеркальну реалізацію CRC; використовуйте такий код для перевірки, а не замість аналізу точного бінарного файла цільового пристрою та порядку байтів у переданих даних.<sup>[[4]](#references)[[5]](#references)</sup>

### Надсилання кадрів із хоста Linux із root-доступом

Скомпрометований хост із вбудованою Linux може взаємодіяти з периферійним пристроєм без додавання іншого контролера шини. Відкрийте потрібний адаптер, виберіть 7-бітну адресу за допомогою `I2C_SLAVE` і надішліть кадр, сформований спеціальним серіалізатором; для модифікації та fuzzing збережіть режим роботи із сирими кадрами.<sup>[[4]](#references)</sup>

```c
int fd = open("/dev/i2c-0", O_RDWR);
if (fd < 0 || ioctl(fd, I2C_SLAVE, target_addr) < 0)
    err(1, "I2C setup");
if (write(fd, cmd, cmd_len) != cmd_len)
    err(1, "I2C write");
ssize_t n = read(fd, resp, resp_size);
if (n < 0)
    err(1, "I2C read");
```

Крос-компілюйте за допомогою toolchain, сумісного з цільовими CPU та libc, і порівняйте трасування аналізатора тестового клієнта з легітимним трафіком. Межі транзакцій, порядок запису/читання, затримки та стан периферійного пристрою можуть мати значення, навіть якщо видимі байти збігаються.<sup>[[4]](#references)</sup>

### Перелічення opcode на основі відповідей

Щойно найкоротший коректний кадр і контрольна сума відомі, переберіть повний діапазон opcode та використовуйте явну відповідь протоколу **«непідтримувана команда»** як базовий негативний результат. Інший результат — наприклад, недійсні аргументи, недійсний стан або недокументований статус — вказує на те, що декодування дійшло до реалізованого або частково реалізованого обробника. Це **не** підтверджує можливість експлуатації; визначте пріоритет цього кандидата для структурованого fuzzing довжин, аргументів, станів і послідовностей команд.<sup>[[4]](#references)</sup>

Якщо тест зависає на периферійному пристрої, автоматизуйте запуск одного ізольованого випадку на кожне завантаження із зовнішнього контролера: під’єднайтеся через SSH, виконайте тестовий випадок, збережіть необроблені запит і відповідь, а також часові характеристики, перезавантажте пристрій або вимкніть і знову подайте живлення, дочекайтеся відновлення перевірок працездатності та продовжте. Пізніше перенесення компонента на керовану мікроконтролером тестову платформу може забезпечити детерміноване скидання, пряме керування живленням і швидший fuzzing.<sup>[[4]](#references)</sup>

## References

- [1] [Документація Bus Pirate — I²C](https://docs.buspirate.com/docs/devices/i2c-eeprom/)
- [2] [NXP — специфікація шини I²C та посібник користувача](https://www.nxp.com/docs/en/user-guide/UM10204.pdf)
- [3] [Microchip — опис мікросхеми послідовної EEPROM AT24C256C з інтерфейсом I²C](https://ww1.microchip.com/downloads/en/DeviceDoc/AT24C256C-I2C-Compatible-Two-Wire-Serial-EEPROM-256-Kbit-32,768-x-8-20005915A.pdf)
- [4] [Quarkslab — Black Box Probing: аналіз безпеки захищеного чипа MJA1 від Xiaomi](https://blog.quarkslab.com/black-box-probing-a-security-analysis-of-xiaomis-mja1-secure-chip.html)
- [5] [Обгортка криптографії MJA1 для Mijia BLE SDK](https://github.com/iomonad/handshow-firmware/tree/master/components/vendor/common/mijia_ble/libs/cryptography/mja1)
{{#include ../../banners/hacktricks-training.md}}
