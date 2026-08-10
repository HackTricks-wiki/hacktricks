# USB-Tastatureingaben

Wenn du einen pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast:

![USB-Tastatureingaben: Wenn du einen pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast](<../../../images/image (962).png>)

Bei einer Tastatur, die das HID-**boot protocol** verwendet, hat jeder Interrupt-IN-Report ein festes Layout von 8 Bytes: ein Modifier-Byte, ein reserviertes Byte und sechs Keycode-Bytes. Der Host vergleicht aufeinanderfolgende Reports und ordnet die Keycodes HID usages zu, um Tastaturereignisse zu rekonstruieren.<sup>[[8]](#references)</sup>

## Grundlagen von USB-HID-Reports

Der standardmäßige Input-Report einer Boot-Tastatur ist wie folgt strukturiert.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt usw.). Mehrere Bits können gleichzeitig gesetzt sein. |
| 1 | Reserviertes Byte; ungenutzte Reports sollten normalerweise auf null gesetzt werden. Die Verwendung durch OEMs oder systemspezifische Verwendung ist nicht portierbar. |
| 2-7 | Bis zu sechs gleichzeitig gedrückte Keycodes im USB-Usage-ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet `"no key"`. |

Im Boot-Layout wird die Usage-ID `0x01` (`Keyboard ErrorRollOver`) in allen Key-Slots gemeldet, wenn mehr als sechs Nicht-Modifier-Tasten gedrückt werden; sie kann auch eine nicht erkennbare Kombination signalisieren.<sup>[[8]](#references)[[9]](#references)</sup> Das Verständnis dieses Layouts ist hilfreich, wenn nur die rohen `usb.capdata`-Bytes vorliegen.

## HID-Daten aus einem PCAP extrahieren

### Zuerst die Tastaturschnittstelle identifizieren

Bei stark ausgelasteten Captures solltest du die HID-Tastatur identifizieren, bevor du Reports ausgibst. Ein zuverlässiger Ausgangspunkt ist die Antwort auf den Interface-Descriptor:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Die HID-Klasse definiert diese Interface-Werte:<sup>[[8]](#references)</sup>

- `subclass == 1` ist die Boot Interface Subclass; mit `protocol == 1` identifiziert sie eine boot keyboard
- `protocol == 2` identifiziert eine boot mouse
- `protocol == 0` bedeutet kein Boot-Protokoll; untersuche stattdessen den HID report descriptor, anstatt ein 8-Byte-Layout anzunehmen

Sobald das Interface bekannt ist, beschränke deine Filter vor dem Export auf `usb.bus_id`, `usb.device_address` und, falls möglich, `usb.bInterfaceNumber`.

### Wireshark-Workflow

1. **Gerät isolieren**: Filtere den Interrupt-IN-Traffic der Tastatur, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Nützliche Spalten hinzufügen**: Klicke mit der rechten Maustaste auf das Feld `Leftover Capture Data` (`usb.capdata`) und deine bevorzugten `usbhid.*`-Felder (z. B. `usbhid.boot_report.keyboard.keycode_1`), um Tastatureingaben zu verfolgen, ohne jedes Frame zu öffnen.<sup>[[11]](#references)</sup>
3. **Leere Reports ausblenden**: Wende `!(usb.capdata == 00:00:00:00:00:00:00:00)` an, um Idle-Frames zu entfernen.
4. **Für die Nachbearbeitung exportieren**: `File -> Export Packet Dissections -> As CSV`, einschließlich `frame.number`, `usb.src`, `usb.capdata` und dekodierter Modifier-Felder wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt`, damit die Rekonstruktion später per Script erfolgen kann.<sup>[[10]](#references)[[11]](#references)</sup>

### Kommandozeilen-Workflow

Das klassische Extraktionsmuster — `usb.capdata` ausgeben, Idle-Reports entfernen und Usage-IDs zuordnen — erscheint in der ursprünglichen Analyse von 2017 und ihrer Anleitung.<sup>[[1]](#references)[[2]](#references)</sup>

Das Repository `ctf-usb-keyboard-parser` automatisiert die klassische tshark- + sed-Pipeline:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Bei neueren Mitschnitten sollte das von Wireshark dekodierte Feld `usbhid.data` bevorzugt und auf `usb.capdata` zurückgegriffen werden, wenn es nicht verfügbar ist; schreibe pro Report einen Payload in eine gerätespezifische Datei:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Diese gerätespezifischen Dateien können nach einer Normalisierung des von ihnen erwarteten Hex-Formats an einen Decoder übergeben werden. Wenn der Mitschnitt von über GATT getunnelten BLE-Tastaturen stammt, filtere mit `btatt.value && frame.len == 20` und gib die Hex-Payloads vor dem Decoding aus.<sup>[[7]](#references)</sup>

### Wenn der Report nicht dem klassischen 8-Byte-Boot-Report entspricht

Eine Nicht-Boot-Schnittstelle oder eine Report-ID kann das Payload-Layout ändern. Gehe daher nicht davon aus, dass jeder Tastatur-Report dem Schema `modifier,reserved,key1..key6` entspricht.<sup>[[8]](#references)[[11]](#references)</sup>

- Bevorzuge `usbhid.data` gegenüber `usb.capdata`, wenn Wireshark die HID-Schicht bereits geparst hat.
- Wenn jede Zeile mit einem konstanten Präfix oder einer Report-ID beginnt, entferne dieses mit einem offset-bewussten Decoder, anstatt anzunehmen, dass Byte 0 immer den Modifier enthält.<sup>[[7]](#references)</sup>
- Einige USBPcap-Exporte lassen das reservierte Byte aus. Decoder mit Unterstützung für `--no-reserved` oder einen benutzerdefinierten Offset sparen daher Zeit.<sup>[[7]](#references)</sup>
- Wenn der HID-Report-Descriptor oder die BLE-HOGP-Report-Map im Mitschnitt vorhanden ist, verwende sie, um vor dem Schreiben eines Parsers das tatsächliche Feld-Layout zu ermitteln.

## Decoding automatisieren

- **ctf-usb-keyboard-parser** bleibt für schnelle CTF-Challenges praktisch und ist bereits im Repository enthalten.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parst `pcap`- und `pcapng`-Dateien nativ, versteht `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt weder tshark noch eine andere externe Abhängigkeit. Dadurch eignet es sich für isolierte Sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** fügt Visualisierer für Tastaturen, Mäuse und Tablets hinzu. Du kannst entweder das Hilfsskript `extract_hid_data.sh` (tshark-Backend) oder `extract_hid_data.py` (scapy-Backend) ausführen und anschließend die resultierende Textdatei an die Decoder- oder Replay-Module übergeben, um zu beobachten, wie die Tastatureingaben sichtbar werden.<sup>[[7]](#references)</sup>

### Zustandsbehaftetes Decoding ist wichtig

USB-Boot-Tastaturen senden Reports mit der Idle-Rate, auch wenn kein neues Tastenereignis vorliegt. Daher können Mitschnitte wiederholte Reports enthalten, bevor das Loslassen der Taste erfasst wird. Ein praxisnaher Decoder sollte:<sup>[[3]](#references)[[8]](#references)</sup>

- nur neu gedrückte Keycodes im Vergleich zum vorherigen Report ausgeben
- den Modifier-Zustand (`Shift`, `Ctrl`, `AltGr`) aus Byte 0 oder geparsten Feldern wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt` beibehalten
- Umschalttasten wie `Caps Lock` verfolgen, da die Ausgabe von Großbuchstaben nicht allein durch Shift gesteuert wird
- beachten, dass HID-Usage-IDs layoutunabhängig sind: `0x1d` bezeichnet abhängig vom Tastaturlayout des Hosts die physische Position der Taste `z` bzw. `y`.<sup>[[9]](#references)</sup>

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
Füttere es mit den zuvor ausgegebenen reinen Hex-Zeilen, um sofort eine grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung einzubinden. Bei nicht-US-Tastaturlayouts wird dadurch weiterhin die physische Tastenposition rekonstruiert, nicht unbedingt das endgültige auf dem Opfer-Host angezeigte Zeichen.

## Tipps zur Fehlerbehebung

- Wenn Wireshark keine `usbhid.*`-Felder auffüllt, wurde der HID report descriptor wahrscheinlich nicht erfasst. Schließe die Tastatur während der Erfassung erneut an oder greife auf rohes `usb.capdata` zurück.
- Bei Software-Erfassungen unter Linux ist `usbmon` die normale Quelle; unter Windows hängt Wireshark vom **USBPcap**-extcap ab, um überhaupt rohe USB-URBs zu sehen.<sup>[[4]](#references)</sup>
- Wenn die Tastatur über einen Hub oder ein Dock angeschlossen war, überprüfe zuerst den interface descriptor und dekodiere anschließend nur dieses Geräte-/Interface-Paar. Composite-HID-Erfassungen mischen häufig Tastatur- und Maus-Reports.
- Windows-Erfassungen erfordern das **USBPcap**-extcap-Interface. Stelle sicher, dass es Wireshark-Upgrades überstanden hat, da fehlende extcaps zu leeren Gerätelisten führen.<sup>[[4]](#references)</sup>
- Gleiche immer das Bus-, Geräte- und Interface-Tupel (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; z. B. `1.9.1`) ab, bevor du etwas dekodierst — das Vermischen mehrerer Tastaturen oder Speichergeräte führt zu unsinnigen Tastenanschlägen.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analyse eines USB-Tastatur-Packet-Captures](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 Write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Einrichtung von Wireshark für USB-Captures](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-Decoder](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Geräteklassendefinition für Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referenz für Wireshark Display Filter: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referenz für Wireshark Display Filter: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
