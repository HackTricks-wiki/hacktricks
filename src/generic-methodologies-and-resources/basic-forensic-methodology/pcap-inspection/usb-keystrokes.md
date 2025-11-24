# Naciśnięcia klawiszy USB

{{#include ../../../banners/hacktricks-training.md}}

Jeśli masz pcap zawierający komunikację przez USB klawiatury podobnej do poniższej:

![](<../../../images/image (962).png>)

Klawiatury USB zazwyczaj używają HID **boot protocol**, więc każde przerwanie IN do hosta ma tylko 8 bajtów: jeden bajt bitów modyfikujących (Ctrl/Shift/Alt/Super), jeden bajt zarezerwowany oraz do sześciu keycode'ów na raport. Dekodowanie tych bajtów wystarcza, aby odtworzyć wszystko, co zostało wpisane.

## Podstawy raportu USB HID

Typowy raport IN wygląda tak:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

Klawiatury bez NKRO zwykle wysyłają `0x01` w bajcie 2, gdy wciśnięto więcej niż sześć klawiszy, aby zasygnalizować "rollover". Zrozumienie tego układu pomaga, gdy masz tylko surowe bajty z `usb.capdata`.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Izoluj urządzenie**: filtruj ruch interrupt IN z klawiatury, np. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodaj przydatne kolumny**: kliknij prawym przyciskiem pole `Leftover Capture Data` (`usb.capdata`) i swoje preferowane pola `usbhid.*` (np. `usbhid.boot_report.keyboard.keycode_1`), aby śledzić naciśnięcia bez otwierania każdego frame'a.
3. **Ukryj puste raporty**: zastosuj `!(usb.capdata == 00:00:00:00:00:00:00:00)`, aby odfiltrować nieaktywne ramki.
4. **Eksport do dalszego przetwarzania**: `File -> Export Packet Dissections -> As CSV`, dołącz `frame.number`, `usb.src`, `usb.capdata` i `usbhid.modifiers`, aby później zautomatyzować rekonstrukcję.

### Praca z linii poleceń

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
W nowszych przechwyceniach możesz zachować zarówno `usb.capdata`, jak i bogatsze pole `usbhid.data`, grupując według urządzenia:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Te pliki przypisane do poszczególnych urządzeń można bezpośrednio wczytać do dowolnego decodera. Jeśli zrzut pochodzi z klawiatur BLE tunelowanych przez GATT, przefiltruj po `btatt.value && frame.len == 20` i zrzutuj hex payloads przed dekodowaniem.

## Automating the decoding

- **ctf-usb-keyboard-parser** pozostaje przydatny do szybkich wyzwań CTF i jest już dołączony do repozytorium.
- **CTF-Usb_Keyboard_Parser** (`main.py`) natywnie parsuje zarówno `pcap`, jak i `pcapng`, rozumie `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i nie wymaga tshark, więc działa ładnie w izolowanych sandboxach.
- **USB-HID-decoders** dodaje wizualizery dla klawiatury, myszy i tabletu. Możesz uruchomić pomocnik `extract_hid_data.sh` (tshark backend) lub `extract_hid_data.py` (scapy backend), a następnie podać powstały plik tekstowy do modułów decoder lub replay, aby obserwować unfolding keystrokes.

## Szybki dekoder w Pythonie
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
Podaj to za pomocą zwykłych linii heksadecymalnych zrzutowanych wcześniej, aby szybko uzyskać przybliżoną rekonstrukcję bez potrzeby ładowania pełnego parsera do środowiska.

## Porady dotyczące rozwiązywania problemów

- Jeśli Wireshark nie wypełnia pól `usbhid.*`, to prawdopodobnie nie przechwycono deskryptora raportu HID. Odłącz i ponownie podłącz klawiaturę podczas przechwytywania albo użyj surowych danych z `usb.capdata`.
- Przechwytywanie na Windows wymaga interfejsu extcap **USBPcap**; upewnij się, że przetrwał aktualizacje Wireshark, ponieważ brakujące extcaps pozostawiają puste listy urządzeń.
- Zawsze skoreluj `usb.bus_id:device:interface` (np. `1.9.1`) przed dekodowaniem czegokolwiek — mieszanie wielu klawiatur lub urządzeń pamięci masowej prowadzi do nonsensownych sekwencji naciśnięć klawiszy.

## Referencje

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
