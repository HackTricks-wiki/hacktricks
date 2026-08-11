# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Wenn Sie eine pcap-Datei mit der USB-Kommunikation einer Tastatur wie der folgenden haben:

![USB Keystrokes: Wenn Sie eine pcap-Datei mit der USB-Kommunikation einer Tastatur wie der folgenden haben](<../../../images/image (962).png>)

Bei einer Tastatur, die das HID-**boot protocol** verwendet, besitzt jeder Interrupt-IN-Report ein festes Layout von 8 Bytes: ein Modifier-Byte, ein reserviertes Byte und sechs Keycode-Bytes. Der Host vergleicht aufeinanderfolgende Reports und ordnet die Keycodes HID usages zu, um Tastaturereignisse zu rekonstruieren.<sup>[[8]](#references)</sup>

## Grundlagen von USB-HID-Reports

Der standardmäßige Eingabe-Report einer Boot-Tastatur ist wie folgt strukturiert.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt usw.). Mehrere Bits können gleichzeitig gesetzt sein. |
| 1 | Reserviertes Byte; ungenutzte Reports sollten normalerweise auf null gesetzt werden. Die Verwendung durch OEMs oder systemspezifische Verwendung ist nicht portabel. |
| 2-7 | Bis zu sechs gleichzeitig gedrückte Keycodes im USB-Usage-ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet „keine Taste“. |

Im Boot-Layout wird die Usage-ID `0x01` (`Keyboard ErrorRollOver`) in allen Tastenfeldern gemeldet, wenn mehr als sechs Nicht-Modifier-Tasten gedrückt werden; sie kann auch eine nicht erkennbare Kombination signalisieren.<sup>[[8]](#references)[[9]](#references)</sup> Das Verständnis dieses Layouts ist hilfreich, wenn Sie nur die rohen `usb.capdata`-Bytes haben.

## HID-Daten aus einer PCAP extrahieren

### Zuerst das Tastatur-Interface identifizieren

Identifizieren Sie bei umfangreichen Captures die HID-Tastatur, bevor Sie Reports ausgeben. Ein zuverlässiger Ausgangspunkt ist die Antwort des Interface-Descriptors:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Die HID-Klasse definiert diese Interface-Werte:<sup>[[8]](#references)</sup>

- `subclass == 1` ist die Boot Interface Subclass; zusammen mit `protocol == 1` identifiziert sie eine Boot-Tastatur
- `protocol == 2` identifiziert eine Boot-Maus
- `protocol == 0` bedeutet, dass kein Boot-Protokoll verwendet wird; untersuche stattdessen den HID-Report-Deskriptor, anstatt ein 8-Byte-Layout anzunehmen

Sobald das Interface bekannt ist, schränke deine Filter vor dem Export auf `usb.bus_id`, `usb.device_address` und, sofern möglich, `usb.bInterfaceNumber` ein.

### Wireshark-Workflow

1. **Gerät isolieren**: Filtere den Interrupt-IN-Datenverkehr der Tastatur, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Nützliche Spalten hinzufügen**: Klicke mit der rechten Maustaste auf das Feld `Leftover Capture Data` (`usb.capdata`) und deine bevorzugten `usbhid.*`-Felder (z. B. `usbhid.boot_report.keyboard.keycode_1`), um Tastatureingaben zu verfolgen, ohne jeden Frame öffnen zu müssen.<sup>[[11]](#references)</sup>
3. **Leere Reports ausblenden**: Wende `!(usb.capdata == 00:00:00:00:00:00:00:00)` an, um inaktive Frames zu entfernen.
4. **Für die Nachbearbeitung exportieren**: `File -> Export Packet Dissections -> As CSV`; füge `frame.number`, `usb.src`, `usb.capdata` sowie dekodierte Modifier-Felder wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt` ein, um die Rekonstruktion später per Script durchzuführen.<sup>[[10]](#references)[[11]](#references)</sup>

### Kommandozeilen-Workflow

Das klassische Extraktionsmuster – `usb.capdata` ausgeben, inaktive Reports entfernen und Usage-IDs zuordnen – erscheint in der ursprünglichen Analyse von 2017 und in deren Anleitung.<sup>[[1]](#references)[[2]](#references)</sup>

Das Repository `ctf-usb-keyboard-parser` automatisiert die klassische `tshark`- und `sed`-Pipeline:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Bei neueren Mitschnitten sollte das von Wireshark dekodierte Feld `usbhid.data` bevorzugt und auf `usb.capdata` zurückgegriffen werden, wenn es nicht verfügbar ist; schreibe ein Payload pro Report in eine gerätespezifische Datei:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Diese gerätespezifischen Dateien können nach der Normalisierung des von ihm erwarteten Hex-Formats einem Decoder zugeführt werden. Wenn der Capture von über GATT getunnelten BLE keyboards stammt, filtere mit `btatt.value && frame.len == 20` und gib die Hex-Payloads vor dem Decoding aus.<sup>[[7]](#references)</sup>

### Wenn der Report nicht dem klassischen 8-Byte-Boot-Report entspricht

Ein Nicht-Boot-Interface oder eine Report-ID kann das Payload-Layout verändern. Gehe daher nicht davon aus, dass jeder Keyboard-Report dem Format `modifier,reserved,key1..key6` entspricht.<sup>[[8]](#references)[[11]](#references)</sup>

- Bevorzuge `usbhid.data` gegenüber `usb.capdata`, wenn Wireshark die HID-Schicht bereits geparst hat.
- Wenn jede Zeile mit einem konstanten Präfix oder einer Report-ID beginnt, entferne dieses mit einem offset-bewussten Decoder, anstatt anzunehmen, dass Byte 0 immer der Modifier ist.<sup>[[7]](#references)</sup>
- Einige USBPcap-Exporte lassen das reservierte Byte aus. Decoder, die `--no-reserved` oder einen benutzerdefinierten Offset unterstützen, sparen daher Zeit.<sup>[[7]](#references)</sup>
- Wenn der HID-Report-Descriptor oder die BLE-HOGP-Report-Map im Capture vorhanden ist, verwende sie, um das tatsächliche Feld-Layout zu ermitteln, bevor du einen Parser schreibst.

## Decoding automatisieren

- **ctf-usb-keyboard-parser** bleibt für schnelle CTF-Challenges praktisch und ist bereits im Repository enthalten.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parst sowohl `pcap`- als auch `pcapng`-Dateien nativ, versteht `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt weder tshark noch eine andere externe Dependency. Damit eignet es sich für isolierte Sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** ergänzt Visualizer für Keyboard, Maus und Tablet. Du kannst entweder das Hilfsprogramm `extract_hid_data.sh` (tshark-Backend) oder `extract_hid_data.py` (scapy-Backend) ausführen und die resultierende Textdatei anschließend dem Decoder oder den Replay-Modulen zuführen, um die einzelnen Keystrokes zu verfolgen.<sup>[[7]](#references)</sup>

### Stateful Decoding ist wichtig

USB-Boot-Keyboards senden Reports mit der Idle-Rate, selbst wenn kein neues Key-Event vorliegt. Daher können Captures wiederholte Reports enthalten, bevor das Release-Event eintritt. Ein praktischer Decoder sollte:<sup>[[3]](#references)[[8]](#references)</sup>

- nur die neu gedrückten Keycodes im Vergleich zum vorherigen Report ausgeben
- den Modifier-Status (`Shift`, `Ctrl`, `AltGr`) aus Byte 0 oder aus geparsten Feldern wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt` beibehalten
- Toggle-Tasten wie `Caps Lock` verfolgen, da die Großschreibung nicht allein durch Shift gesteuert wird
- beachten, dass HID-Usage-IDs layoutunabhängig sind: `0x1d` bezeichnet abhängig vom Keyboard-Layout des Hosts die physische Tastenposition `z`/`y`.<sup>[[9]](#references)</sup>

## Schneller Python-Decoder
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
Füttere es mit den zuvor ausgegebenen reinen Hex-Zeilen, um sofort eine grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung einzubinden. Bei nicht-US-Layouts wird damit weiterhin die physische Tastenposition rekonstruiert, nicht unbedingt das endgültige auf dem Opfer-Host angezeigte Zeichen.

## Tipps zur Fehlerbehebung

- Wenn Wireshark keine `usbhid.*`-Felder befüllt, wurde der HID report descriptor wahrscheinlich nicht erfasst. Schließe die Tastatur während der Aufzeichnung erneut an oder weiche auf rohes `usb.capdata` aus.
- Bei Software-Captures unter Linux ist `usbmon` die übliche Quelle; unter Windows benötigt Wireshark das **USBPcap** extcap, um überhaupt rohe USB-URBs zu sehen.<sup>[[4]](#references)</sup>
- Wenn die Tastatur über einen Hub oder eine Dockingstation angeschlossen war, bestätige zuerst den interface descriptor und dekodiere anschließend nur dieses Geräte-/Interface-Paar. Composite-HID-Captures enthalten häufig gemischte Tastatur- und Maus-Reports.
- Windows-Captures benötigen das **USBPcap**-extcap-Interface. Stelle sicher, dass es Wireshark-Upgrades überstanden hat, da fehlende extcaps zu leeren Gerätelisten führen.<sup>[[4]](#references)</sup>
- Gleiche vor der Decodierung immer das Bus-, Geräte- und Interface-Tupel ab (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; z. B. `1.9.1`) — das Vermischen mehrerer Tastaturen oder Speichergeräte führt zu unsinnigen Tastenanschlägen.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB-Tastatur-Paketanalyse](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB-Capture-Einrichtung](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-Decoder](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Geräteklassendefinition für Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
