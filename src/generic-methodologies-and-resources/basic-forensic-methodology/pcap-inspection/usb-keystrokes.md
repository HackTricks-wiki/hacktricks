# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap, що містить USB-communication клавіатури, як-от така:

![](<../../../images/image (962).png>)

USB keyboards зазвичай використовують HID **boot protocol**, тож кожен interrupt transfer до host має лише 8 bytes: один byte модифікаторів (Ctrl/Shift/Alt/Super), один reserved byte і до шести keycodes на кожен report. Декодування цих bytes достатньо, щоб відновити все, що було введено.

## USB HID report basics

Типовий IN report виглядає так:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

Keyboards without NKRO usually send `0x01` in byte 2 when more than six keys are pressed to signal "rollover". Understanding this layout helps when you only have the raw `usb.capdata` bytes.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

On busy captures, identify the HID keyboard before dumping any reports. A reliable starting point is the interface descriptor response:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Подивіться на `usb.bInterfaceSubClass` і `usb.bInterfaceProtocol`:

- `subclass == 1` і `protocol == 1` зазвичай означає boot keyboard
- `protocol == 2` зазвичай означає mouse
- `protocol == 0` часто означає vendor-defined або NKRO-style HID interface, яка все ще передає keyboard data, але не в простому 8-byte boot layout

Після того як interface визначено, прив’яжіть свої filters до `usb.bus_id`, `usb.device_address` і, якщо можливо, `usb.interface_number` перед тим, як щось експортувати.

### Wireshark workflow

1. **Ізолюйте device**: відфільтруйте interrupt IN traffic від keyboard, наприклад `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Додайте корисні columns**: клацніть правою кнопкою на полі `Leftover Capture Data` (`usb.capdata`) і на ваших prefered `usbhid.*` fields (наприклад, `usbhid.boot_report.keyboard.keycode_1`), щоб відстежувати keystrokes без відкривання кожного frame.
3. **Приховайте empty reports**: застосуйте `!(usb.capdata == 00:00:00:00:00:00:00:00)`, щоб прибрати idle frames.
4. **Експортуйте для post-processing**: `File -> Export Packet Dissections -> As CSV`, включіть `frame.number`, `usb.src`, `usb.capdata` і `usbhid.modifiers`, щоб потім автоматизувати reconstruction за допомогою script.

### Command-line workflow

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
У новіших captures можна зберігати і `usb.capdata`, і більш багате поле `usbhid.data`, групуючи за device:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ті файли для кожного пристрою можна напряму подавати в будь-який decoder. Якщо capture був з BLE keyboards, тунельованих через GATT, відфільтруйте `btatt.value && frame.len == 20` і вивантажте hex payloads перед декодуванням.

### Коли report не є класичним 8-byte boot report

Сучасні gaming keyboards, split keyboards і composite HID devices часто мають non-boot keyboard interface, де payload уже не відповідає `modifier,reserved,key1..key6`.

- Краще використовувати `usbhid.data`, а не `usb.capdata`, коли Wireshark уже розібрав HID layer.
- Якщо кожен рядок починається з постійного prefix або report ID, відсікайте його декодером, який враховує offset, а не припускайте, що byte 0 завжди є modifier.
- Деякі USBPcap exports не містять reserved byte, тож decoders з підтримкою `--no-reserved` або custom offset економлять час.
- Якщо в capture є HID report descriptor або BLE HOGP report map, використайте їх, щоб відновити реальну структуру полів ще до написання parser.

## Автоматизація decoding

- **ctf-usb-keyboard-parser** досі корисний для швидких CTF challenges і вже є в repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) нативно parse-ить як `pcap`, так і `pcapng`, розуміє `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` і не потребує tshark, тож добре працює в ізольованих sandboxes.
- **USB-HID-decoders** додає visualizers для keyboard, mouse і tablet. Ви можете або запустити helper `extract_hid_data.sh` (tshark backend), або `extract_hid_data.py` (scapy backend), а потім передати отриманий text file у decoder чи replay modules, щоб побачити, як розгортаються keystrokes.

### Stateful decoding має значення

USB interrupt captures зазвичай містять і key press, і одну або кілька повторних копій того самого report до надходження release event. Практичний decoder має:

- виводити лише нові keycodes порівняно з попереднім report
- зберігати modifier state (`Shift`, `Ctrl`, `AltGr`) з byte 0 або з розібраного поля `usbhid.boot_report.keyboard.modifier`
- відстежувати toggle keys на кшталт `Caps Lock`, бо uppercase output не контролюється лише Shift
- пам’ятати, що HID usage IDs не залежать від layout: `0x1d` — це фізична позиція клавіші `z`/`y` залежно від keyboard layout на host

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
Подавайте їм прості hex-рядки, скинуті раніше, щоб одразу отримати приблизну реконструкцію без підключення повного parser до середовища. Для non-US layouts це все ще відновлює physical key position, а не обов’язково final glyph, який бачився на host жертви.

## Troubleshooting tips

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- On Linux software captures, `usbmon` is the normal source; on Windows, Wireshark depends on the **USBPcap** extcap to see raw USB URBs at all.
- If the keyboard was attached through a hub or dock, confirm the interface descriptor first and then decode only that device/interface pair. Composite HID captures frequently mix keyboard and mouse reports.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
