# UART

{{#include ../../banners/hacktricks-training.md}}

## Основна інформація

UART — це serial protocol, тобто він передає дані між компонентами по одному біту за раз. На відміну від цього, parallel communication protocols передають дані одночасно через кілька каналів. До поширених serial protocols належать RS-232, I2C, SPI, CAN, Ethernet, HDMI, PCI Express і USB.

Зазвичай лінія має високий рівень (логічне значення 1), коли UART перебуває в стані очікування. Потім, щоб сигналізувати про початок передавання даних, передавач надсилає приймачу start bit, під час якого сигнал має низький рівень (логічне значення 0). Далі передавач надсилає від п’яти до восьми data bits, що містять фактичне повідомлення, після чого — необов’язковий parity bit і один або два stop bits (із логічним значенням 1), залежно від конфігурації. Parity bit, який використовується для перевірки помилок, на практиці трапляється рідко. Stop bit (або біти) позначає кінець передавання.

Найпоширенішу конфігурацію називають 8N1: вісім data bits, без parity і один stop bit. Наприклад, якщо потрібно надіслати символ C, або 0x43 в ASCII, у конфігурації 8N1 UART, ми надішлемо такі біти: 0 (start bit); 0, 1, 0, 0, 0, 0, 1, 1 (значення 0x43 у двійковому форматі) і 0 (stop bit).

![UART: Найпоширенішу конфігурацію називають 8N1: вісім data bits, без parity і один stop bit. Наприклад, якщо потрібно надіслати символ C, або 0x43 в ASCII, у конфігурації 8N1 UART](<../../images/image (764).png>)

Hardware tools для роботи з UART:

- USB-to-serial adapter
- Адаптери з чипами CP2102 або PL2303
- Multipurpose tool, наприклад Bus Pirate, Adafruit FT232H, Shikra або Attify Badge

### Визначення UART Ports

UART має 4 ports: **TX**(Transmit), **RX**(Receive), **Vcc**(Voltage) і **GND**(Ground). Можливо, вам вдасться знайти 4 ports із **`TX`** і **`RX`**, **написаними** на PCB. Але якщо позначень немає, можливо, їх доведеться шукати самостійно за допомогою **мультиметра** або **logic analyzer**.

За допомогою **мультиметра**, коли пристрій вимкнено:

- Щоб визначити pin **GND**, використайте режим **Continuity Test**, під’єднайте чорний щуп до ground і перевіряйте червоним щупом контакти, доки не почуєте звуковий сигнал мультиметра. На PCB можна знайти кілька pins GND, тому знайдений pin може належати або не належати UART.
- Щоб визначити **VCC port**, встановіть режим **DC voltage** і діапазон до 20 V. Під’єднайте чорний щуп до ground, а червоний — до pin. Увімкніть пристрій. Якщо мультиметр вимірює стабільну напругу 3.3 V або 5 V, ви знайшли pin Vcc. Якщо отримуєте інші значення напруги, спробуйте інші ports.
- Щоб визначити **TX** **port**, встановіть режим **DC voltage** з діапазоном до 20 V, під’єднайте чорний щуп до ground, а червоний — до pin, після чого увімкніть пристрій. Якщо напруга коливається протягом кількох секунд, а потім стабілізується на рівні Vcc, найімовірніше, ви знайшли TX port. Це відбувається тому, що під час увімкнення пристрій надсилає debug data.
- **RX port** зазвичай розташований найближче до інших 3, має найменші коливання напруги та найнижче загальне значення серед усіх UART pins.

Ви можете переплутати TX і RX ports — нічого не станеться, але якщо переплутати GND і VCC port, можна пошкодити circuit.

У деяких target devices виробник вимикає UART port, деактивуючи RX або TX, або обидва. У такому разі може бути корисно простежити з’єднання на circuit board і знайти breakout point. Важливою підказкою для підтвердження відсутності UART і розриву circuit є перевірка гарантії пристрою. Якщо пристрій постачався з гарантією, виробник залишає деякі debug interfaces (у цьому випадку UART), а отже, повинен був від’єднати UART і під’єднати його знову під час debugging. Ці breakout pins можна з’єднати за допомогою пайки або jumper wires.

### Визначення UART Baud Rate

Найпростіший спосіб визначити правильний baud rate — переглянути **вивід TX pin і спробувати прочитати data**. Якщо отримані data нечитабельні, переходьте до наступного можливого baud rate, доки data не стануть читабельними. Для цього можна використати USB-to-serial adapter або multipurpose device на кшталт Bus Pirate у поєднанні з helper script, наприклад [baudrate.py](https://github.com/devttys0/baudrate/). Найпоширеніші baud rates: 9600, 38400, 19200, 57600 і 115200.

> [!CAUTION]
> Важливо зазначити, що в цьому protocol потрібно під’єднати TX одного пристрою до RX іншого!

## CP210X UART to TTY Adapter

Chip CP210X використовується в багатьох prototyping boards, таких як NodeMCU (з esp8266), для Serial Communication. Ці adapters відносно недорогі, їх можна використовувати для підключення до UART interface target. Пристрій має 5 pins: 5V, GND, RXD, TXD, 3.3V. Переконайтеся, що під’єднуєте voltage, який підтримується target, щоб уникнути пошкоджень. Нарешті, під’єднайте RXD pin Adapter до TXD target, а TXD pin Adapter — до RXD target.

Якщо adapter не визначається, переконайтеся, що в host system встановлені CP210X drivers. Після визначення та підключення adapter можна використовувати такі tools, як picocom, minicom або screen.

Щоб переглянути список devices, підключених до Linux/MacOS systems:
```
ls /dev/
```
Для базової взаємодії з інтерфейсом UART використовуйте таку команду:
```
picocom /dev/<adapter> --baud <baudrate>
```
Для minicom використовуйте наведену нижче команду для його налаштування:
```
minicom -s
```
Налаштуйте такі параметри, як baudrate і назва пристрою, в опції `Serial port setup`.

Після налаштування використайте команду `minicom`, щоб запустити UART Console.

## UART Via Arduino UNO R3 (Removable Atmel 328p Chip Boards)

Якщо UART Serial to USB adapters недоступні, Arduino UNO R3 можна використати за допомогою швидкого hack. Оскільки Arduino UNO R3 зазвичай доступний усюди, це може заощадити багато часу.

Arduino UNO R3 має вбудований у саму плату USB to Serial adapter. Щоб отримати UART connection, просто витягніть мікроконтролерний chip Atmel 328p із плати. Цей hack працює з варіантами Arduino UNO R3, у яких Atmel 328p не припаяний до плати (у ньому використовується SMD version). Під’єднайте RX pin Arduino (Digital Pin 0) до TX pin UART Interface, а TX pin Arduino (Digital Pin 1) — до RX pin UART interface.

Нарешті, рекомендується використовувати Arduino IDE для доступу до Serial Console. У розділі `tools` меню виберіть опцію `Serial Console` і встановіть baud rate відповідно до UART interface.

## Bus Pirate

У цьому сценарії ми перехоплюватимемо UART communication Arduino, яка надсилає всі program prints до Serial Monitor.
```bash
# Check the modes
UART>m
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

# Select UART
(1)>3
Set serial port speed: (bps)
1. 300
2. 1200
3. 2400
4. 4800
5. 9600
6. 19200
7. 38400
8. 57600
9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
1. 8, NONE *default
2. 8, EVEN
3. 8, ODD
4. 9, NONE

# From now on pulse enter for default
(1)>
Stop bits:
1. 1 *default
2. 2
(1)>
Receive polarity:
1. Idle 1 *default
2. Idle 0
(1)>
Select output type:
1. Open drain (H=Hi-Z, L=GND)
2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```
## Dumping Firmware with UART Console

UART Console надає чудову можливість працювати з базовою прошивкою в середовищі виконання. Однак коли доступ до UART Console доступний лише для читання, це може створити чимало обмежень. У багатьох вбудованих пристроях прошивка зберігається в EEPROM і виконується процесорами, що мають енергозалежну пам'ять. Тому прошивка залишається доступною лише для читання, оскільки оригінальна прошивка під час виробництва міститься безпосередньо в EEPROM, а всі нові файли будуть втрачені через енергозалежну пам'ять. Отже, дамп прошивки є важливим завданням під час роботи з вбудованими прошивками.

Існує багато способів зробити це, а в розділі SPI описано методи вилучення прошивки безпосередньо з EEPROM за допомогою різних пристроїв. Однак спочатку рекомендується спробувати створити дамп прошивки через UART, оскільки вилучення прошивки за допомогою фізичних пристроїв і зовнішньої взаємодії може бути ризикованим.

Створення дампа прошивки через UART Console спочатку потребує отримання доступу до bootloader. Багато популярних виробників використовують uboot (Universal Bootloader) як bootloader для завантаження Linux. Отже, необхідно отримати доступ до uboot.

Щоб отримати доступ до bootloader, підключіть UART-порт до комп'ютера, скористайтеся будь-яким інструментом Serial Console і залиште живлення пристрою від'єднаним. Після завершення налаштування натисніть і утримуйте клавішу Enter. Нарешті підключіть живлення до пристрою та дозвольте йому завантажитися.

Це перерве завантаження uboot і відкриє меню. Рекомендується ознайомитися з командами uboot і скористатися меню help, щоб переглянути їхній список. Це може бути команда `help`. Оскільки різні виробники використовують різні конфігурації, необхідно окремо розібратися з кожною з них.

Зазвичай команда для створення дампа прошивки має такий вигляд:
```
md
```
що означає «memory dump». Це виведе пам’ять (вміст EEPROM) на екран. Перед початком процедури рекомендується зберегти в log output Serial Console, щоб захопити memory dump.

Насамкінець просто видаліть усі непотрібні дані з log file, збережіть файл як `filename.rom` і використайте binwalk для вилучення вмісту:
```
binwalk -e <filename.rom>
```
Це перелічить можливий вміст EEPROM відповідно до сигнатур, знайдених у hex-файлі.

Однак важливо зазначити, що uboot не завжди розблокований, навіть якщо він використовується. Якщо клавіша Enter нічого не робить, перевірте інші клавіші, наприклад пробіл тощо. Якщо bootloader заблокований і його не вдається перервати, цей метод не працюватиме. Щоб перевірити, чи є uboot bootloader пристрою, перевірте вивід у UART Console під час завантаження пристрою. Під час завантаження там може згадуватися uboot.

{{#include ../../banners/hacktricks-training.md}}
