# USB-Tastatureingaben

{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie ein pcap haben, das die USB-Kommunikation einer Tastatur wie die folgende enthält:

![](<../../../images/image (962).png>)

USB-Tastaturen sprechen normalerweise das HID **boot protocol**, daher ist jeder Interrupt-Transfer zum Host nur 8 Bytes lang: ein Byte mit Modifier-Bits (Ctrl/Shift/Alt/Super), ein reserviertes Byte und bis zu sechs Keycodes pro Report. Das Dekodieren dieser Bytes reicht aus, um alles zu rekonstruieren, was getippt wurde.

## Grundlagen des USB HID-Reports

Das typische IN-Report sieht so aus:

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Mehrere Bits können gleichzeitig gesetzt sein. |
| 1 | Reserviert/Padding, wird aber oft von Gaming-Tastaturen für Vendor-Daten wiederverwendet. |
| 2-7 | Bis zu sechs gleichzeitige Keycodes im USB usage ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet "keine Taste". |

Tastaturen ohne NKRO senden normalerweise `0x01` in Byte 2, wenn mehr als sechs Tasten gedrückt werden, um "rollover" zu signalisieren. Das Verständnis dieses Layouts hilft, wenn Sie nur die rohen `usb.capdata`-Bytes haben.

## Extrahieren von HID-Daten aus einem PCAP

### Wireshark-Workflow

1. **Gerät isolieren**: Filter auf Interrupt-IN-Traffic der Tastatur anwenden, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Nützliche Spalten hinzufügen**: Rechtsklick auf das Feld `Leftover Capture Data` (`usb.capdata`) und Ihre bevorzugten `usbhid.*`-Felder (z. B. `usbhid.boot_report.keyboard.keycode_1`) um Tastendrücke zu verfolgen, ohne jeden Frame zu öffnen.
3. **Leere Reports ausblenden**: `!(usb.capdata == 00:00:00:00:00:00:00:00)` anwenden, um Idle-Frames zu entfernen.
4. **Für Post-Processing exportieren**: `File -> Export Packet Dissections -> As CSV`, fügen Sie `frame.number`, `usb.src`, `usb.capdata` und `usbhid.modifiers` hinzu, um die Rekonstruktion später per Skript durchzuführen.

### Kommandozeilen-Workflow

`ctf-usb-keyboard-parser` automatisiert bereits die klassische tshark + sed-Pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Bei neueren Captures kannst du sowohl `usb.capdata` als auch das umfangreichere Feld `usbhid.data` beibehalten, indem du pro Gerät in Batches arbeitest:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Diese per-Gerät-Dateien lassen sich direkt in jeden Decoder einfügen. Wenn die Aufzeichnung von BLE-Tastaturen stammt, die über GATT getunnelt wurden, filtere nach `btatt.value && frame.len == 20` und dump die Hex-Payloads vor dem Decoding.

## Automatisierung der Dekodierung

- **ctf-usb-keyboard-parser** bleibt praktisch für schnelle CTF-Challenges und ist bereits im Repository enthalten.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parst sowohl `pcap`- als auch `pcapng`-Dateien nativ, versteht `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt kein tshark, sodass es sich gut in isolierten Sandboxes einsetzen lässt.
- **USB-HID-decoders** fügt Visualisierungen für Tastatur, Maus und Tablet hinzu. Du kannst entweder das Hilfsprogramm `extract_hid_data.sh` (tshark-Backend) oder `extract_hid_data.py` (scapy-Backend) ausführen und die resultierende Textdatei anschließend an die Decoder- oder Replay-Module übergeben, um die Tastenanschläge abspielen zu lassen.

## Schneller Python-Decoder
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
Füttere es mit den zuvor ausgegebenen reinen Hex-Zeilen, um eine sofortige grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung ziehen zu müssen.

## Tipps zur Fehlerbehebung

- Wenn Wireshark die `usbhid.*`-Felder nicht befüllt, wurde der HID report descriptor wahrscheinlich nicht aufgezeichnet. Stecke die Tastatur während der Aufzeichnung erneut ein oder wechsle auf das rohe `usb.capdata`.
- Windows-Aufnahmen erfordern die **USBPcap** extcap-Schnittstelle; stelle sicher, dass sie Upgrades von Wireshark überlebt hat, da fehlende extcaps zu leeren Gerätelisten führen.
- Stelle vor dem Dekodieren immer eine Korrelation des `usb.bus_id:device:interface` (z. B. `1.9.1`) her — das Mischen mehrerer Tastaturen oder Speichermedien führt zu unsinnigen Tastenanschlägen.

## Referenzen

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
