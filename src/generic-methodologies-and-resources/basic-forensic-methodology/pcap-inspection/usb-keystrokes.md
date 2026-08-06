# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Wenn du ein pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast:

![USB Keystrokes: Wenn du ein pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast](<../../../images/image (962).png>)

USB-Tastaturen verwenden normalerweise das HID-**boot protocol**, daher ist jeder Interrupt-Transfer zum Host nur 8 Bytes lang: ein Byte für Modifier-Bits (Ctrl/Shift/Alt/Super), ein reserviertes Byte und bis zu sechs Keycodes pro Report. Das Decodieren dieser Bytes reicht aus, um alles, was eingegeben wurde, wiederherzustellen.

## Grundlagen von USB-HID-Reports

Der typische IN-Report sieht folgendermaßen aus:

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = Left Shift, `0x20` = Right Alt usw.). Mehrere Bits können gleichzeitig gesetzt sein. |
| 1 | Reserviert/Padding, wird von Gaming-Tastaturen jedoch häufig für Vendor-Daten wiederverwendet. |
| 2-7 | Bis zu sechs gleichzeitige Keycodes im USB-Usage-ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet „keine Taste“. |

Tastaturen ohne NKRO senden normalerweise `0x01` in Byte 2, wenn mehr als sechs Tasten gedrückt werden, um einen „rollover“ zu signalisieren. Das Verständnis dieses Aufbaus hilft, wenn du nur die rohen `usb.capdata`-Bytes hast.

## HID-Daten aus einem PCAP extrahieren

### Zuerst das Tastatur-Interface identifizieren

Identifiziere bei umfangreichen Captures zunächst die HID-Tastatur, bevor du Reports ausgibst. Ein zuverlässiger Ausgangspunkt ist die Antwort auf den Interface-Descriptor:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Betrachte `usb.bInterfaceSubClass` und `usb.bInterfaceProtocol`:

- `subclass == 1` und `protocol == 1` bedeuten normalerweise eine Boot-Tastatur
- `protocol == 2` bedeutet typischerweise eine Maus
- `protocol == 0` bedeutet häufig ein herstellerdefiniertes oder NKRO-style HID-Interface, das weiterhin Tastaturdaten überträgt, jedoch nicht im einfachen 8-Byte-Boot-Layout

Sobald das Interface bekannt ist, beschränke deine Filter vor dem Export auf `usb.bus_id`, `usb.device_address` und, falls möglich, `usb.interface_number`.

### Wireshark-Workflow

1. **Gerät isolieren**: Filtere den Interrupt-IN-Datenverkehr der Tastatur, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Nützliche Spalten hinzufügen**: Klicke mit der rechten Maustaste auf das Feld `Leftover Capture Data` (`usb.capdata`) und deine bevorzugten `usbhid.*`-Felder (z. B. `usbhid.boot_report.keyboard.keycode_1`), um die Tastenanschläge zu verfolgen, ohne jeden Frame zu öffnen.
3. **Leere Reports ausblenden**: Verwende `!(usb.capdata == 00:00:00:00:00:00:00:00)`, um Idle-Frames zu entfernen.
4. **Für die Nachbearbeitung exportieren**: `File -> Export Packet Dissections -> As CSV`, und füge `frame.number`, `usb.src`, `usb.capdata` sowie `usbhid.modifiers` hinzu, um die Rekonstruktion später zu skripten.

### Command-Line-Workflow

`ctf-usb-keyboard-parser` automatisiert bereits die klassische tshark- + sed-Pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Bei neueren Captures kannst du sowohl das Feld `usb.capdata` als auch das umfassendere Feld `usbhid.data` beibehalten, indem du die Daten pro Gerät stapelweise verarbeitest:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Diese gerätespezifischen Dateien können direkt in jeden Decoder eingespeist werden. Wenn der Mitschnitt von über GATT getunnelten BLE-Tastaturen stammt, filtere mit `btatt.value && frame.len == 20` und gib die Hex-Payloads vor dem Decoding aus.

### Wenn der Report nicht der klassische 8-Byte-Boot-Report ist

Moderne Gaming-Tastaturen, Split-Tastaturen und zusammengesetzte HID-Geräte stellen häufig eine Nicht-Boot-Tastaturschnittstelle bereit, bei der die Payload nicht mehr dem Format `modifier,reserved,key1..key6` entspricht.

- Bevorzuge `usbhid.data` gegenüber `usb.capdata`, wenn Wireshark die HID-Schicht bereits geparst hat.
- Wenn jede Zeile mit einem konstanten Präfix oder einer Report-ID beginnt, entferne diese mit einem offset-bewussten Decoder, anstatt anzunehmen, dass Byte 0 immer das Modifier-Byte ist.
- Einige USBPcap-Exporte lassen das reservierte Byte weg. Decoder, die `--no-reserved` oder einen benutzerdefinierten Offset unterstützen, sparen daher Zeit.
- Wenn der HID-Report-Descriptor oder die BLE-HOGP-Report-Map im Mitschnitt vorhanden ist, verwende sie, um das tatsächliche Feldlayout zu rekonstruieren, bevor du einen Parser schreibst.

## Decoding automatisieren

- **ctf-usb-keyboard-parser** bleibt für schnelle CTF-Herausforderungen praktisch und ist bereits im Repository enthalten.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parst sowohl `pcap`- als auch `pcapng`-Dateien nativ, versteht `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt kein tshark. Dadurch funktioniert es gut in isolierten Sandboxes.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** fügt Visualisierungen für Tastaturen, Mäuse und Tablets hinzu. Du kannst entweder das Hilfsskript `extract_hid_data.sh` (tshark-Backend) oder `extract_hid_data.py` (scapy-Backend) ausführen und anschließend die resultierende Textdatei an den Decoder oder die Replay-Module übergeben, um zu beobachten, wie sich die Tastatureingaben entfalten.<sup>[[5]](#references)</sup>

### Zustandsbehaftetes Decoding ist wichtig

USB-Interrupt-Mitschnitte enthalten normalerweise sowohl den Tastendruck als auch eine oder mehrere wiederholte Kopien desselben Reports, bevor das Loslassereignis eintrifft. Ein praktischer Decoder sollte:<sup>[[2]](#references)</sup>

- nur neu gedrückte Keycodes im Vergleich zum vorherigen Report ausgeben
- den Modifier-Zustand (`Shift`, `Ctrl`, `AltGr`) aus Byte 0 oder dem geparsten Feld `usbhid.boot_report.keyboard.modifier` beibehalten
- Umschalttasten wie `Caps Lock` verfolgen, da die Großschreibung nicht allein durch Shift gesteuert wird
- berücksichtigen, dass HID-Usage-IDs layoutunabhängig sind: `0x1d` bezeichnet je nach Tastaturlayout des Hosts die physische Position der `z`-/`y`-Taste

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
Füttere es mit den zuvor ausgegebenen reinen Hex-Zeilen, um sofort eine grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung zu laden. Bei nicht-US-Layouts wird damit weiterhin die physische Tastenposition rekonstruiert, nicht unbedingt das auf dem Opfer-Host angezeigte endgültige Zeichen.

## Tipps zur Fehlerbehebung

- Wenn Wireshark keine `usbhid.*`-Felder befüllt, wurde der HID-Report-Deskriptor wahrscheinlich nicht erfasst. Schließe die Tastatur während der Aufzeichnung erneut an oder greife auf rohe `usb.capdata` zurück.
- Bei Software-Aufzeichnungen unter Linux ist `usbmon` die normale Quelle; unter Windows benötigt Wireshark das **USBPcap**-extcap, um überhaupt rohe USB-URBs zu sehen.<sup>[[1]](#references)</sup>
- Wenn die Tastatur über einen Hub oder ein Dock angeschlossen war, bestätige zuerst den Interface-Deskriptor und dekodiere anschließend nur dieses Geräte-/Interface-Paar. Composite-HID-Aufzeichnungen mischen häufig Tastatur- und Maus-Reports.
- Windows-Aufzeichnungen benötigen das **USBPcap**-extcap-Interface. Stelle sicher, dass es Wireshark-Upgrades überstanden hat, da fehlende extcaps zu leeren Gerätelisten führen.<sup>[[1]](#references)</sup>
- Gleiche `usb.bus_id:device:interface` (z. B. `1.9.1`) immer ab, bevor du etwas dekodierst — das Vermischen mehrerer Tastaturen oder Speichergeräte führt zu unsinnigen Tastenanschlägen.

## Referenzen

- [1] [Wireshark-Einrichtung für USB-Aufzeichnungen](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 – Write-up zu pcap 1 und 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
