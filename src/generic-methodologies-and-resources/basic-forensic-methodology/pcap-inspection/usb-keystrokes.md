# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Wenn du einen pcap hast, der die Kommunikation via USB einer Tastatur wie der folgenden enthält:

![](<../../../images/image (962).png>)

USB-Tastaturen sprechen normalerweise das HID **boot protocol**, daher ist jeder Interrupt-Transfer zum Host nur 8 Bytes lang: ein Byte mit Modifier-Bits (Ctrl/Shift/Alt/Super), ein reserviertes Byte und bis zu sechs Keycodes pro Report. Das Dekodieren dieser Bytes reicht aus, um alles wiederherzustellen, was getippt wurde.

## USB HID report basics

Der typische IN-Report sieht so aus:

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = Left Shift, `0x20` = Right Alt, usw.). Mehrere Bits können gleichzeitig gesetzt sein. |
| 1 | Reserviert/Padding, wird aber oft von Gaming-Keyboards für Vendor-Daten wiederverwendet. |
| 2-7 | Bis zu sechs gleichzeitige Keycodes im USB usage ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet "kein Key". |

Keyboards ohne NKRO senden normalerweise `0x01` in Byte 2, wenn mehr als sechs Tasten gedrückt werden, um "rollover" zu signalisieren. Dieses Layout zu verstehen hilft, wenn du nur die rohen `usb.capdata`-Bytes hast.

## Extrahieren von HID-Daten aus einem PCAP

### Identifiziere zuerst die Keyboard-Schnittstelle

Bei großen Captures solltest du zuerst die HID-Tastatur identifizieren, bevor du irgendwelche Reports ausgibst. Ein zuverlässiger Ausgangspunkt ist die Antwort des Interface-Descriptors:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Schau auf `usb.bInterfaceSubClass` und `usb.bInterfaceProtocol`:

- `subclass == 1` und `protocol == 1` bedeutet meist eine boot keyboard
- `protocol == 2` ist typischerweise eine mouse
- `protocol == 0` bedeutet oft eine vendor-defined oder NKRO-style HID interface, die trotzdem keyboard data trägt, aber nicht im einfachen 8-byte boot layout

Sobald das interface bekannt ist, setze deine Filter auf `usb.bus_id`, `usb.device_address` und, wenn möglich, `usb.interface_number`, bevor du etwas exportierst.

### Wireshark workflow

1. **Isoliere das device**: filtere auf interrupt IN traffic von der keyboard, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Füge nützliche columns hinzu**: Rechtsklick auf das Feld `Leftover Capture Data` (`usb.capdata`) und deine bevorzugten `usbhid.*` fields (z. B. `usbhid.boot_report.keyboard.keycode_1`), um keystrokes zu verfolgen, ohne jeden frame zu öffnen.
3. **Verstecke leere reports**: wende `!(usb.capdata == 00:00:00:00:00:00:00:00)` an, um idle frames zu entfernen.
4. **Export für post-processing**: `File -> Export Packet Dissections -> As CSV`, nimm `frame.number`, `usb.src`, `usb.capdata` und `usbhid.modifiers` auf, um die reconstruction später per script zu machen.

### Command-line workflow

`ctf-usb-keyboard-parser` automatisiert bereits die klassische tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Bei neueren Mitschnitten kannst du sowohl `usb.capdata` als auch das umfangreichere Feld `usbhid.data` behalten, indem du pro Gerät batchst:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Diese per-device-Dateien lassen sich direkt in jeden Decoder einfügen. Wenn die Capture von BLE-Keyboards kam, die über GATT getunnelt wurden, filtere auf `btatt.value && frame.len == 20` und gib die Hex-Payloads vor dem Decoding aus.

### Wenn der Report nicht der klassische 8-Byte-Boot-Report ist

Neuere Gaming-Keyboards, Split-Keyboards und Composite-HID-Devices stellen oft eine non-boot keyboard interface bereit, bei der die Payload nicht mehr `modifier,reserved,key1..key6` entspricht.

- Bevorzuge `usbhid.data` gegenüber `usb.capdata`, wenn Wireshark die HID-Layer bereits geparst hat.
- Wenn jede Zeile mit einem konstanten Prefix oder Report-ID beginnt, entferne ihn mit einem offset-aware decoder, statt anzunehmen, dass Byte 0 immer der Modifier ist.
- Manche USBPcap-Exports lassen das Reserved-Byte weg, daher sparen Decoder mit `--no-reserved` oder einem custom offset Zeit.
- Wenn der HID Report Descriptor oder die BLE HOGP Report Map im Capture vorhanden ist, nutze ihn, um das tatsächliche Field Layout zu rekonstruieren, bevor du einen Parser schreibst.

## Automating the decoding

- **ctf-usb-keyboard-parser** bleibt praktisch für schnelle CTF-Challenges und ist bereits im Repository enthalten.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parst sowohl `pcap`- als auch `pcapng`-Dateien nativ, versteht `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt kein tshark, daher funktioniert es gut in isolierten Sandboxes.
- **USB-HID-decoders** ergänzt Visualizer für Keyboard, Mouse und Tablet. Du kannst entweder den `extract_hid_data.sh`-Helper (`tshark`-Backend) oder `extract_hid_data.py` (`scapy`-Backend) ausführen und dann die resultierende Textdatei an den Decoder oder die Replay-Module übergeben, um die Keystrokes ablaufen zu sehen.

### Stateful decoding matters

USB-Interrupt-Captures enthalten normalerweise sowohl den Key-Press als auch eine oder mehrere wiederholte Kopien desselben Reports, bevor das Release-Event eintrifft. Ein praktischer Decoder sollte:

- nur neu gedrückte Keycodes im Vergleich zum vorherigen Report ausgeben
- den Modifier-Status (`Shift`, `Ctrl`, `AltGr`) aus Byte 0 oder dem geparsten `usbhid.boot_report.keyboard.modifier`-Field behalten
- Toggle-Keys wie `Caps Lock` verfolgen, weil Großschreibung nicht nur von Shift gesteuert wird
- daran denken, dass HID Usage IDs layout-agnostisch sind: `0x1d` ist je nach Host-Keyboard-Layout die physische `z`/`y`-Key-Position

## Quick Python decoder
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
Füttere es mit den reinen Hex-Zeilen, die zuvor gedumpt wurden, um sofort eine grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung zu ziehen. Für Nicht-US-Layouts rekonstruiert das weiterhin die physische Tastenposition, nicht unbedingt das endgültige Glyph, das auf dem Zielhost angezeigt wird.

## Troubleshooting tips

- Wenn Wireshark die `usbhid.*` Felder nicht auffüllt, wurde der HID-Report-Descriptor wahrscheinlich nicht mitgeschnitten. Verbinde die Tastatur während der Aufnahme erneut oder weiche auf das rohe `usb.capdata` aus.
- Bei Software-Captures unter Linux ist `usbmon` die normale Quelle; unter Windows ist Wireshark auf das **USBPcap** extcap angewiesen, um rohe USB-URBs überhaupt zu sehen.
- Wenn die Tastatur über einen Hub oder Dock angeschlossen war, prüfe zuerst den Interface-Descriptor und dekodiere dann nur dieses Gerät-/Interface-Paar. Composite HID-Captures vermischen häufig Tastatur- und Maus-Reports.
- Windows-Captures erfordern die **USBPcap** extcap-Interface; stelle sicher, dass sie Wireshark-Upgrades überstanden hat, da fehlende extcaps zu leeren Gerätelisten führen.
- Korrigiere immer `usb.bus_id:device:interface` (z. B. `1.9.1`) bevor du etwas dekodierst — das Vermischen mehrerer Tastaturen oder Storage-Devices führt zu unsinnigen Tastendrücken.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
