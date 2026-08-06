# Keystrokes USB

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap, що містить комунікацію через USB клавіатури, як у наведеному нижче прикладі:

![Keystrokes USB: Якщо у вас є pcap, що містить комунікацію через USB клавіатури, як у наведеному нижче прикладі](<../../../images/image (962).png>)

USB-клавіатури зазвичай використовують **boot protocol** HID, тому кожна interrupt transfer до хоста має довжину лише 8 байтів: один байт бітів модифікаторів (Ctrl/Shift/Alt/Super), один зарезервований байт і до шести keycodes у кожному report. Декодування цих байтів достатнє для відновлення всього введеного тексту.

## Основи USB HID report

Типовий IN report має такий вигляд:

| Byte | Значення |
| --- | --- |
| 0 | Bitmap модифікаторів (`0x02` = Left Shift, `0x20` = Right Alt тощо). Одночасно може бути встановлено кілька бітів. |
| 1 | Зарезервований байт або padding, але gaming keyboards часто повторно використовують його для vendor data. |
| 2-7 | До шести одночасних keycodes у форматі USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` означає "no key". |

Клавіатури без NKRO зазвичай надсилають `0x01` у byte 2, коли натиснуто понад шість клавіш, щоб сигналізувати про "rollover". Розуміння цієї структури допомагає, коли у вас є лише необроблені байти `usb.capdata`.

## Витягування HID data з PCAP

### Спочатку ідентифікуйте інтерфейс клавіатури

У великих capture спочатку ідентифікуйте HID-клавіатуру, перш ніж вивантажувати reports. Надійною відправною точкою є відповідь із описом інтерфейсу:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Перевірте `usb.bInterfaceSubClass` і `usb.bInterfaceProtocol`:

- `subclass == 1` і `protocol == 1` зазвичай означають boot-клавіатуру
- `protocol == 2` зазвичай означає мишу
- `protocol == 0` часто означає HID-інтерфейс, визначений виробником, або інтерфейс у стилі NKRO, який усе ще передає дані клавіатури, але не у простому 8-байтовому boot-форматі

Після визначення інтерфейсу прив'яжіть фільтри до `usb.bus_id`, `usb.device_address` і, якщо можливо, `usb.interface_number`, перш ніж щось експортувати.

### Робочий процес у Wireshark

1. **Ізолюйте пристрій**: фільтруйте interrupt IN-трафік від клавіатури, наприклад `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Додайте корисні стовпці**: клацніть правою кнопкою миші поле `Leftover Capture Data` (`usb.capdata`) і потрібні поля `usbhid.*` (наприклад, `usbhid.boot_report.keyboard.keycode_1`), щоб відстежувати натискання клавіш без відкриття кожного фрейму.
3. **Приховайте порожні звіти**: застосуйте `!(usb.capdata == 00:00:00:00:00:00:00:00)`, щоб відфільтрувати неактивні фрейми.
4. **Експортуйте для подальшої обробки**: `File -> Export Packet Dissections -> As CSV`, додавши `frame.number`, `usb.src`, `usb.capdata` і `usbhid.modifiers`, щоб пізніше написати скрипт для реконструкції.

### Робочий процес у командному рядку

`ctf-usb-keyboard-parser` уже автоматизує класичний конвеєр tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
У новіших захопленнях можна зберігати і `usb.capdata`, і більш інформативне поле `usbhid.data`, групуючи дані за пристроєм:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ці файли для окремих пристроїв можна безпосередньо передати в будь-який decoder. Якщо захоплення отримано з BLE keyboards, тунельованих через GATT, фільтруйте за `btatt.value && frame.len == 20` і збережіть hex payloads перед decoding.

### Коли звіт не є класичним 8-байтовим boot report

Сучасні gaming keyboards, split keyboards і composite HID devices часто надають non-boot keyboard interface, у якому payload більше не відповідає формату `modifier,reserved,key1..key6`.

- Надавайте перевагу `usbhid.data` перед `usb.capdata`, якщо Wireshark уже розібрав HID layer.
- Якщо кожен рядок починається з постійного prefix або report ID, видаляйте його за допомогою offset-aware decoder, а не припускайте, що byte 0 завжди є modifier.
- Деякі USBPcap exports не містять reserved byte, тому decoders із підтримкою `--no-reserved` або custom offset заощадять час.
- Якщо HID report descriptor або BLE HOGP report map присутній у capture, використайте його для відновлення фактичної структури полів перед написанням parser.

## Автоматизація decoding

- **ctf-usb-keyboard-parser** залишається зручним для швидких CTF challenges і вже постачається в repository.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) нативно обробляє файли `pcap` і `pcapng`, розуміє `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` і не потребує tshark, тому добре працює в ізольованих sandboxes.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** додає visualizers для keyboard, mouse і tablet. Можна запустити helper `extract_hid_data.sh` (tshark backend) або `extract_hid_data.py` (scapy backend), а потім передати отриманий text file у decoder або replay modules, щоб спостерігати за відтворенням натискань клавіш.<sup>[[5]](#references)</sup>

### Важливість stateful decoding

USB interrupt captures зазвичай містять як натискання клавіші, так і одну або кілька повторних копій того самого report до надходження event відпускання. Практичний decoder має:<sup>[[2]](#references)</sup>

- виводити лише нові keycodes порівняно з попереднім report
- зберігати стан modifier (`Shift`, `Ctrl`, `AltGr`) із byte 0 або розібраного поля `usbhid.boot_report.keyboard.modifier`
- відстежувати toggle keys, наприклад `Caps Lock`, оскільки виведення великих літер залежить не лише від Shift
- пам’ятати, що HID usage IDs не залежать від розкладки: `0x1d` відповідає фізичній позиції клавіші `z`/`y` залежно від розкладки keyboard на host

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
Подайте йому звичайні hex-рядки, збережені раніше, щоб миттєво отримати приблизну реконструкцію без підключення повного parser до середовища. Для не-US розкладок це все одно відновлює фізичну позицію клавіші, але не обов’язково кінцевий glyph, показаний на host жертви.

## Поради з усунення несправностей

- Якщо Wireshark не заповнює поля `usbhid.*`, імовірно, HID report descriptor не було захоплено. Перепід’єднайте клавіатуру під час захоплення або перейдіть до raw `usb.capdata`.
- У software captures на Linux звичайним джерелом є `usbmon`; у Windows Wireshark залежить від extcap **USBPcap**, щоб узагалі бачити raw USB URBs.<sup>[[1]](#references)</sup>
- Якщо клавіатуру підключено через hub або dock, спочатку перевірте interface descriptor, а потім декодуйте лише цю пару device/interface. Composite HID captures часто змішують keyboard і mouse reports.
- Для Windows captures потрібен extcap interface **USBPcap**; переконайтеся, що він зберігся після оновлень Wireshark, оскільки відсутні extcaps залишають порожні списки пристроїв.<sup>[[1]](#references)</sup>
- Завжди зіставляйте `usb.bus_id:device:interface` (наприклад, `1.9.1`) перед декодуванням — змішування кількох клавіатур або storage devices призводить до безглуздих keystrokes.

## References

- [1] [Налаштування захоплення USB у Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
