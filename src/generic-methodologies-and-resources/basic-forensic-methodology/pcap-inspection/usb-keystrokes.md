# USB натискання клавіш

{{#include ../../../banners/hacktricks-training.md}}

Якщо у вас є pcap, що містить USB‑комунікацію клавіатури, як на наступному прикладі:

![](<../../../images/image (962).png>)

USB-клавіатури зазвичай використовують HID **boot protocol**, тож кожен interrupt transfer до хоста має довжину лише 8 байтів: один байт бітів-модифікаторів (Ctrl/Shift/Alt/Super), один зарезервований байт і до шести keycodes у звіті. Декодування цих байтів достатнє, щоб відтворити все, що було введено.

## Основи USB HID звіту

Типовий IN-звіт виглядає так:

| Byte | Meaning |
| --- | --- |
| 0 | Бітова маска модифікаторів (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Може бути встановлено кілька бітів одночасно. |
| 1 | Зарезервовано/паддінг, але часто використовується ігровими клавіатурами для даних виробника. |
| 2-7 | До шести одночасних keycodes у форматі USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` означає «немає клавіші». |

Клавіатури без NKRO зазвичай надсилають `0x01` в байті 2, коли натиснуто більше шести клавіш, щоб сигналізувати про "rollover". Розуміння цього формату допомагає, коли у вас є лише сирі байти `usb.capdata`.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Ізолюйте пристрій**: відфільтруйте interrupt IN traffic від клавіатури, наприклад `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Додайте корисні колонки**: клікніть правою кнопкою на полі `Leftover Capture Data` (`usb.capdata`) та обраних полях `usbhid.*` (наприклад `usbhid.boot_report.keyboard.keycode_1`), щоб відстежувати натискання клавіш без відкриття кожного кадру.
3. **Приховати порожні звіти**: застосуйте `!(usb.capdata == 00:00:00:00:00:00:00:00)`, щоб відкинути idle кадри.
4. **Експорт для подальшої обробки**: `File -> Export Packet Dissections -> As CSV`, включіть `frame.number`, `usb.src`, `usb.capdata`, та `usbhid.modifiers` для скриптової реконструкції пізніше.

### Command-line workflow

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
У новіших захопленнях ви можете зберегти як `usb.capdata`, так і більш насичене поле `usbhid.data`, групуючи за пристроєм:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ці файли для кожного пристрою можна відразу підвантажити в будь-який декодер. Якщо захоплення зроблене з BLE-клавіатур, тунельованих через GATT, відфільтруйте за `btatt.value && frame.len == 20` і перед декодуванням виведіть hex payloads.

## Автоматизація декодування

- **ctf-usb-keyboard-parser** залишається корисним для швидких CTF-завдань і вже входить у репозиторій.
- **CTF-Usb_Keyboard_Parser** (`main.py`) нативно парсить як `pcap`, так і `pcapng` файли, розуміє `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` і не потребує tshark, тому добре працює в ізольованих пісочницях.
- **USB-HID-decoders** додає візуалізатори для клавіатури, миші та планшета. Ви можете запустити допоміжний скрипт `extract_hid_data.sh` (tshark backend) або `extract_hid_data.py` (scapy backend), а потім передати отриманий текстовий файл у модулі decoder або replay, щоб переглянути відтворення натискань клавіш.

## Швидкий Python-декодер
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
Надайте йому прості hex-рядки, виведені раніше, щоб миттєво отримати грубу реконструкцію без підключення повного парсера до середовища.

## Поради з усунення неполадок

- Якщо Wireshark не заповнює поля `usbhid.*`, ймовірно, HID report descriptor не був зафіксований. Перепідключіть клавіатуру під час захоплення або використайте raw `usb.capdata`.
- Захоплення з Windows потребують інтерфейсу **USBPcap** extcap; переконайтеся, що він працює після оновлень Wireshark, оскільки відсутні extcap-и залишають порожні списки пристроїв.
- Завжди корелюйте `usb.bus_id:device:interface` (наприклад `1.9.1`) перед декодуванням — змішування декількох клавіатур або накопичувачів призводить до безглуздих натискань клавіш.

## Посилання

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
