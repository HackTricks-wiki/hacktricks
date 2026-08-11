# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap із комунікацією через USB клавіатури, як у наведеному прикладі:

![USB Keystrokes: Якщо у вас є pcap із комунікацією через USB клавіатури, як у наведеному прикладі](<../../../images/image (962).png>)

Для клавіатури, що використовує **boot protocol** HID, кожен Interrupt IN report має фіксовану 8-байтову структуру: один байт модифікаторів, один зарезервований байт і шість байтів keycode. Хост порівнює послідовні reports і зіставляє keycode з HID usages, щоб відновити key events.<sup>[[8]](#references)</sup>

## Основи HID report

Стандартний input report boot-клавіатури має таку структуру.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Значення |
| --- | --- |
| 0 | Bitmap модифікаторів (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt тощо). Одночасно можуть бути встановлені кілька бітів. |
| 1 | Зарезервований байт; невикористовувані reports зазвичай мають встановлювати його в нуль. Використання OEM або системами-specific не є портативним. |
| 2-7 | До шести одночасних keycode у форматі USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` означає "no key". |

У boot layout usage ID `0x01` (`Keyboard ErrorRollOver`) передається в усіх key slots, коли натиснуто понад шість клавіш, що не є модифікаторами; він також може сигналізувати про нерозпізнавану комбінацію.<sup>[[8]](#references)[[9]](#references)</sup> Розуміння цієї структури допомагає, коли у вас є лише необроблені байти `usb.capdata`.

## Вилучення HID data з PCAP

### Спочатку ідентифікуйте інтерфейс клавіатури

У великих captures спочатку ідентифікуйте HID-клавіатуру, перш ніж вивантажувати reports. Надійною відправною точкою є відповідь на interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Клас HID визначає такі значення інтерфейсу:<sup>[[8]](#references)</sup>

- `subclass == 1` — Boot Interface Subclass; у поєднанні з `protocol == 1` ідентифікує boot keyboard
- `protocol == 2` ідентифікує boot mouse
- `protocol == 0` означає відсутність boot protocol; замість припущення про 8-байтову структуру слід перевірити HID report descriptor

Після визначення інтерфейсу прив’яжіть фільтри до `usb.bus_id`, `usb.device_address` і, якщо можливо, до `usb.bInterfaceNumber` перед експортом будь-яких даних.

### Робочий процес у Wireshark

1. **Ізолюйте пристрій**: фільтруйте interrupt IN-трафік від keyboard, наприклад `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Додайте корисні колонки**: клацніть правою кнопкою миші поле `Leftover Capture Data` (`usb.capdata`) і потрібні поля `usbhid.*` (наприклад, `usbhid.boot_report.keyboard.keycode_1`), щоб відстежувати натискання клавіш без відкриття кожного кадру.<sup>[[11]](#references)</sup>
3. **Приховайте порожні звіти**: застосуйте `!(usb.capdata == 00:00:00:00:00:00:00:00)`, щоб вилучити idle frames.
4. **Експортуйте дані для post-processing**: `File -> Export Packet Dissections -> As CSV`, додавши `frame.number`, `usb.src`, `usb.capdata` і декодовані поля модифікаторів, такі як `usbhid.boot_report.keyboard.modifier.left_shift` та `usbhid.boot_report.keyboard.modifier.right_alt`, щоб пізніше виконати реконструкцію за допомогою скрипта.<sup>[[10]](#references)[[11]](#references)</sup>

### Робочий процес через командний рядок

Класичний шаблон extraction — вивантажити `usb.capdata`, вилучити idle reports і зіставити usage IDs — наведено в оригінальному аналізі 2017 року та його walkthrough.<sup>[[1]](#references)[[2]](#references)</sup>

Репозиторій `ctf-usb-keyboard-parser` автоматизує класичний pipeline на основі tshark + sed:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
У новіших захопленнях надавайте перевагу декодованому полю Wireshark `usbhid.data`, а за його відсутності використовуйте `usb.capdata`; записуйте один payload на кожен report в окремий файл для кожного пристрою:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Ці файли для окремих пристроїв можна передати декодеру після нормалізації формату hex, якого він очікує. Якщо capture отримано з BLE-клавіатур, тунельованих через GATT, фільтруйте за `btatt.value && frame.len == 20` і збережіть hex payloads перед декодуванням.<sup>[[7]](#references)</sup>

### Коли звіт не є класичним 8-байтовим boot report

Не-boot interface або report ID можуть змінити layout payload, тому не припускайте, що кожен keyboard report відповідає `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Віддавайте перевагу `usbhid.data` замість `usb.capdata`, якщо Wireshark уже розібрав HID layer.
- Якщо кожен рядок починається зі сталого prefix або report ID, видаляйте його за допомогою offset-aware декодера, а не припускайте, що byte 0 завжди є modifier.<sup>[[7]](#references)</sup>
- Деякі USBPcap exports не містять reserved byte, тому декодери з підтримкою `--no-reserved` або custom offset заощадять час.<sup>[[7]](#references)</sup>
- Якщо HID report descriptor або BLE HOGP report map присутній у capture, використайте його для відновлення фактичного field layout перед написанням parser.

## Автоматизація декодування

- **ctf-usb-keyboard-parser** залишається зручним для швидких CTF challenges і вже входить до repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) нативно розбирає файли `pcap` і `pcapng`, розуміє `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` і не потребує tshark або іншої external dependency, тому підходить для ізольованих sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** додає visualizers для keyboard, mouse і tablet. Можна запустити helper `extract_hid_data.sh` (tshark backend) або `extract_hid_data.py` (scapy backend), а потім передати отриманий text file decoder або replay modules, щоб спостерігати за відтворенням keystrokes.<sup>[[7]](#references)</sup>

### Важливість stateful decoding

USB boot keyboards надсилають reports з idle rate, навіть коли немає нової key event, тому captures можуть містити повторювані reports до події release. Практичний декодер має:<sup>[[3]](#references)[[8]](#references)</sup>

- виводити лише нові натиснуті keycodes порівняно з попереднім report
- зберігати modifier state (`Shift`, `Ctrl`, `AltGr`) з byte 0 або parsed fields, таких як `usbhid.boot_report.keyboard.modifier.left_shift` і `usbhid.boot_report.keyboard.modifier.right_alt`
- відстежувати toggle keys, такі як `Caps Lock`, оскільки uppercase output не контролюється лише Shift
- пам’ятати, що HID usage IDs не залежать від layout: `0x1d` — це фізична позиція клавіші `z`/`y` залежно від host keyboard layout.<sup>[[9]](#references)</sup>

## Швидкий Python decoder
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
Подайте йому звичайні hex-рядки, виведені раніше, щоб миттєво отримати приблизну реконструкцію без завантаження повного parser в середовище. Для розкладок, відмінних від US, це все одно реконструює фізичну позицію клавіші, але не обов'язково фінальний glyph, показаний на host жертви.

## Поради щодо усунення несправностей

- Якщо Wireshark не заповнює поля `usbhid.*`, імовірно, дескриптор HID report не було захоплено. Перепід'єднайте клавіатуру під час захоплення або перейдіть до raw `usb.capdata`.
- У software captures на Linux стандартним джерелом є `usbmon`; у Windows Wireshark залежить від extcap **USBPcap**, щоб взагалі бачити raw USB URBs.<sup>[[4]](#references)</sup>
- Якщо клавіатуру під'єднано через hub або dock, спочатку підтвердьте interface descriptor, а потім декодуйте лише цю пару device/interface. Composite HID captures часто змішують reports клавіатури та миші.
- Для captures у Windows потрібен extcap interface **USBPcap**; переконайтеся, що він зберігся після оновлень Wireshark, оскільки відсутні extcaps залишають вас із порожніми списками пристроїв.<sup>[[4]](#references)</sup>
- Перед декодуванням завжди зіставляйте tuple bus, device та interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; наприклад, `1.9.1`) — змішування кількох клавіатур або storage devices призводить до безглуздих keystrokes.<sup>[[10]](#references)</sup>

## References

- [1] [Звіт HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Аналіз захоплення пакетів USB Keyboard](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 — write-up для pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Налаштування захоплення USB у Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Визначення класу пристроїв для Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Таблиці використання HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Довідник display filters Wireshark: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Довідник display filters Wireshark: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
