# Натискання клавіш через USB

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap із записом обміну даними через USB клавіатури, як у наведеному нижче прикладі:

![Натискання клавіш через USB: якщо у вас є pcap із записом обміну даними через USB клавіатури, як у наведеному нижче прикладі](<../../../images/image (962).png>)

У клавіатурі, що використовує HID **boot protocol**, кожен звіт Interrupt IN має фіксований формат із 8 байтів: один байт модифікаторів, один зарезервований байт і шість байтів кодів клавіш. Хост порівнює послідовні звіти й зіставляє коди клавіш із HID usage, щоб відновити події натискання клавіш.<sup>[[8]](#references)</sup>

Загальні відомості про первинний аналіз захоплень див. у розділі [Pcap Inspection](./).

## Основи звітів USB HID

Стандартний вхідний звіт клавіатури в boot-форматі має таку структуру.<sup>[[8]](#references)[[9]](#references)</sup>

| Байт | Значення |
| --- | --- |
| 0 | Бітова маска модифікаторів (`0x02` = лівий Shift, `0x20` = правий Shift, `0x40` = правий Alt тощо). Одночасно можуть бути встановлені кілька бітів. |
| 1 | Зарезервований байт; зазвичай у невикористовуваних звітах він має дорівнювати нулю. Використання OEM або конкретної системи не є переносним. |
| 2-7 | До шести одночасно натиснутих кодів клавіш у форматі USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` означає «клавішу не натиснуто». | 

У boot-форматі usage ID `0x01` (`Keyboard ErrorRollOver`) передається в усіх слотах клавіш, якщо натиснуто більше шести клавіш, що не є модифікаторами; він також може вказувати на комбінацію, яку неможливо розпізнати.<sup>[[8]](#references)[[9]](#references)</sup> Розуміння цього формату стане в пригоді, якщо у вас є лише необроблені байти `usb.capdata`.

## Вилучення HID-даних із PCAP

### Спершу визначте інтерфейс клавіатури

У захопленнях із великим обсягом трафіку визначте HID-клавіатуру, перш ніж вивантажувати звіти. Надійною відправною точкою є відповідь із дескриптором інтерфейсу:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Клас HID визначає такі значення інтерфейсу:<sup>[[8]](#references)</sup>

- `subclass == 1` — це підклас Boot Interface; разом із `protocol == 1` він визначає клавіатуру boot
- `protocol == 2` визначає мишу boot
- `protocol == 0` означає відсутність boot protocol; перевірте дескриптор звіту HID, а не припускайте, що використовується 8-байтовий формат

Інтерфейс із підтримкою boot **не є доказом того, що boot protocol активний**. Пристрої HID ініціалізуються в report protocol. Хост вибирає режим boot за допомогою `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); значення `wValue = 1` вибирає report protocol. Якщо у захопленні є процес перелічення пристроїв, перевірте запит для інтерфейсу клавіатури (`wIndex`), перш ніж використовувати восьмибайтовий декодер boot. Якщо його немає, перевірте спостережуваний формат звіту, а не визначайте режим за дескриптором інтерфейсу.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Щойно інтерфейс буде відомий, зафіксуйте фільтри на `usb.bus_id`, `usb.device_address` і, якщо можливо, `usb.bInterfaceNumber` перед експортом.

### Процес роботи у Wireshark

1. **Ізолюйте пристрій**: відфільтруйте вхідний трафік переривань від клавіатури, наприклад, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Додайте корисні стовпці**: клацніть правою кнопкою миші поле `Leftover Capture Data` (`usb.capdata`) і вибрані вами поля `usbhid.*` (наприклад, `usbhid.boot_report.keyboard.keycode_1`), щоб відстежувати натискання клавіш, не відкриваючи кожен кадр.<sup>[[11]](#references)</sup>
3. **Приховайте порожні звіти**: застосуйте `!(usb.capdata == 00:00:00:00:00:00:00:00)`, щоб відкинути неактивні кадри.
4. **Експортуйте дані для подальшої обробки**: `File -> Export Packet Dissections -> As CSV`; додайте `frame.number`, `usb.src`, `usb.capdata` і декодовані поля модифікаторів, як-от `usbhid.boot_report.keyboard.modifier.left_shift` та `usbhid.boot_report.keyboard.modifier.right_alt`, щоб пізніше написати скрипт для реконструкції.<sup>[[10]](#references)[[11]](#references)</sup>

### Робота з командного рядка

Класичний спосіб витягування даних — вивести `usb.capdata`, відкинути неактивні звіти й зіставити ID використання — наведено в оригінальному аналізі 2017 року та супровідному посібнику.<sup>[[1]](#references)[[2]](#references)</sup>

Репозиторій `ctf-usb-keyboard-parser` автоматизує класичний конвеєр tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

У новіших захопленнях трафіку надавайте перевагу декодованому полю `usbhid.data` у Wireshark, а якщо його немає — використовуйте `usb.capdata`; записуйте один payload на звіт у файл для кожного пристрою:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Ці файли для окремих пристроїв можна передати декодеру після нормалізації формату hex, якого він очікує. Якщо захоплення отримано з клавіатур BLE, тунельованих через GATT, відфільтруйте пакети за `btatt.value && frame.len == 20` і перед декодуванням вивантажте payload у форматі hex.<sup>[[7]](#references)</sup>

### Коли звіт не є класичним 8-байтовим boot-звітом

Інтерфейс, відмінний від boot, або ID звіту може змінити структуру payload, тож не припускайте, що кожен звіт клавіатури має вигляд `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Віддавайте перевагу `usbhid.data` замість `usb.capdata`, якщо Wireshark уже розібрав рівень HID.
- Якщо кожен рядок починається з постійного префікса або ID звіту, видаліть його за допомогою декодера з урахуванням зсуву, а не припускайте, що байт 0 завжди є модифікатором.<sup>[[7]](#references)</sup>
- У деяких експортах USBPcap пропущено зарезервований байт, тому декодери з підтримкою `--no-reserved` або власний зсув заощадять час.<sup>[[7]](#references)</sup>
- Якщо в захопленні є дескриптор звіту HID або карта звітів BLE HOGP, використайте їх, щоб відновити фактичну структуру полів, перш ніж писати парсер.

### Декодування бітової карти клавіш у протоколі звітів

Для клавіатури, вхідний звіт якої є бітовою картою, а не містить шість слотів клавіш boot, знайдіть її **дескриптор звіту HID** у трафіку переліку пристроїв. Цей фільтр знаходить кадри, у яких Wireshark декодував елемент Report Size; відкрийте один із них і перегляньте повний дескриптор. Якщо дескриптора немає, почніть нове захоплення перед підключенням клавіатури.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Для кожного звіту `Input` клавіатури зафіксуйте його `Report ID` (якщо є), `Usage Page` (`0x07` для клавіш клавіатури), `Usage Minimum/Maximum`, `Report Size`, `Report Count` і те, чи є кожен елемент `Input` типом **Variable** або **Array**. Щоб знайти бітове зміщення поля клавіш, порахуйте всі попередні поля `Input` і біти доповнення-константи; поля звіту не обов’язково вирівняні за байтами. Однобітове поле `Variable` з послідовними usage клавіатури — це бітова карта стану клавіш: біт 0 цього поля відповідає першому оголошеному usage, біт 1 — наступному тощо. Натомість `Array` містить значення, які визначаються за діапазоном usage дескриптора, а не по одному значенню на кожну натиснуту клавішу. Якщо оголошено `Report ID`, спочатку виберіть звіти з таким префіксом і пропустіть його байт під час обчислення зміщень полів. Порівнюйте набори утримуваних usage у послідовних звітах з **того самого інтерфейсу та Report ID**, щоб фіксувати лише нові натискання.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Автоматизація декодування

- **ctf-usb-keyboard-parser** зручний для швидкого розв’язання CTF-завдань і вже є в репозиторії.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) обробляє файли `pcap` і `pcapng` безпосередньо, розуміє `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` і не потребує tshark чи інших зовнішніх залежностей, тож підходить для ізольованих середовищ.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** додає візуалізатори клавіатури, миші та планшета. Можна запустити допоміжний скрипт `extract_hid_data.sh` (бекенд tshark) або `extract_hid_data.py` (бекенд scapy), а потім передати отриманий текстовий файл декодеру або модулям відтворення, щоб побачити, як відтворюються натискання клавіш.<sup>[[7]](#references)</sup>

### Важливість декодування зі збереженням стану

USB-клавіатури в режимі boot надсилають звіти з інтервалом очікування, навіть якщо нових подій клавіш немає, тому захоплення може містити повторні звіти до події відпускання клавіші. Практичний декодер має:<sup>[[3]](#references)[[8]](#references)</sup>

- фіксувати лише нові натискання клавіш порівняно з попереднім звітом
- зберігати стан модифікаторів (`Shift`, `Ctrl`, `AltGr`) з байта 0 або розібраних полів, як-от `usbhid.boot_report.keyboard.modifier.left_shift` і `usbhid.boot_report.keyboard.modifier.right_alt`
- відстежувати клавіші-перемикачі, як-от `Caps Lock`, оскільки для введення великих літер недостатньо лише `Shift`
- пам’ятати, що ідентифікатори usage HID не залежать від розкладки: `0x1d` відповідає фізичній клавіші `z` або `y` залежно від розкладки клавіатури на хості.<sup>[[9]](#references)</sup>

## Простий декодер на Python

```python
#!/usr/bin/env python3
import sys
NORMAL = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n',0x2d:'-',0x2e:'=',0x2f:'[',0x30:']',0x33:';',0x34:"'",0x36:',',0x37:'.'}
SHIFTED = {0x2d:'_',0x2e:'+',0x2f:'{',0x30:'}',0x33:':',0x34:'"',0x36:'<',0x37:'>'}
prev = set()
caps = False
for raw in sys.stdin:
    raw = raw.strip().replace(':', '')
    if len(raw) != 16:
        continue
    modifier = int(raw[0:2], 16)
    keycodes = [int(raw[i:i+2], 16) for i in range(4, 16, 2)]
    current = {k for k in keycodes if k}
    newly_pressed = [k for k in keycodes if k and k not in prev]
    shift = bool(modifier & 0x22)
    for keycode in newly_pressed:
        if keycode == 0x39:
            caps = not caps
            continue
        char = SHIFTED.get(keycode) if shift else None
        if char is None:
            char = NORMAL.get(keycode, '?')
            if char.isalpha() and (shift ^ caps):
                char = char.upper()
        sys.stdout.write(char)
    prev = current
```

Подайте йому звичайні рядки hex, виведені раніше, щоб миттєво отримати приблизну реконструкцію, не додаючи повноцінний parser до середовища. Для розкладок, відмінних від американської, це все одно відновлює фізичне розташування клавіші, але не обов’язково кінцевий символ, який відображався на хості жертви.

## Поради з усунення несправностей

- Якщо Wireshark не заповнює поля `usbhid.*`, імовірно, дескриптор звіту HID не було захоплено. Перепід’єднайте клавіатуру під час захоплення або використайте сирі дані `usb.capdata`.
- У програмних захопленнях на Linux зазвичай використовують `usbmon`; у Windows Wireshark для перегляду сирих USB URB залежить від extcap **USBPcap**.<sup>[[4]](#references)</sup>
- Якщо клавіатуру під’єднано через hub або док-станцію, спочатку перевірте дескриптор інтерфейсу, а потім декодуйте лише відповідну пару пристрою та інтерфейсу. У складених HID-захопленнях часто перемішуються звіти клавіатури та миші.
- Для захоплень у Windows потрібен інтерфейс extcap **USBPcap**; переконайтеся, що він залишився після оновлення Wireshark, оскільки через відсутні extcap списки пристроїв будуть порожніми.<sup>[[4]](#references)</sup>
- Перш ніж щось декодувати, завжди звіряйте кортеж шини, пристрою та інтерфейсу (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; наприклад, `1.9.1`) — змішування кількох клавіатур або пристроїв зберігання призведе до безглуздих натискань клавіш.<sup>[[10]](#references)</sup>



## References

- [1] [Звіт про розв’язання HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Аналіз захоплення пакетів USB-клавіатури](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [Звіт про розв’язання ACSC Quals 2023 — pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Налаштування захоплення USB у Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Визначення класу пристроїв для пристроїв взаємодії з людиною (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Таблиці використання HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Довідник фільтрів відображення Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Довідник фільтрів відображення Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Ядро Linux: вступ до дескрипторів звітів HID](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: звіт про розв’язання ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
