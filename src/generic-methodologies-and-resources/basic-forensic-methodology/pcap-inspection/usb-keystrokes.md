# USB-Tastatureingaben

{{#include ../../../banners/hacktricks-training.md}}

Wenn du einen pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast:

![USB-Tastatureingaben: Wenn du einen pcap mit der USB-Kommunikation einer Tastatur wie der folgenden hast](<../../../images/image (962).png>)

Bei einer Tastatur, die das HID **boot protocol** verwendet, hat jeder Interrupt-IN-Report ein festes Layout von 8 Byte: ein Modifier-Byte, ein reserviertes Byte und sechs Tastencode-Bytes. Der Host vergleicht aufeinanderfolgende Reports und ordnet die Tastencodes HID-Usages zu, um Tastaturereignisse zu rekonstruieren.<sup>[[8]](#references)</sup>

Für eine allgemeine Analyse des Captures siehe [Pcap Inspection](./).

## Grundlagen von USB-HID-Reports

Der standardmäßige Eingabe-Report einer Boot-Tastatur ist wie folgt aufgebaut.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Bedeutung |
| --- | --- |
| 0 | Modifier-Bitmap (`0x02` = linke Umschalttaste, `0x20` = rechte Umschalttaste, `0x40` = rechte Alt-Taste usw.). Es können mehrere Bits gleichzeitig gesetzt sein. |
| 1 | Reserviertes Byte; in ungenutzten Reports sollte es normalerweise auf null gesetzt sein. Die Verwendung durch OEMs oder bestimmte Systeme ist nicht portabel. |
| 2-7 | Bis zu sechs gleichzeitig gedrückte Tastencodes im USB-Usage-ID-Format (`0x04 = a`, `0x1E = 1`). `0x00` bedeutet „keine Taste“. | 

Im Boot-Layout wird die Usage-ID `0x01` (`Keyboard ErrorRollOver`) in allen Tasten-Slots gemeldet, wenn mehr als sechs Nicht-Modifier-Tasten gedrückt werden; sie kann auch auf eine nicht erkennbare Kombination hinweisen.<sup>[[8]](#references)[[9]](#references)</sup> Das Verständnis dieses Layouts ist hilfreich, wenn dir nur die rohen `usb.capdata`-Bytes vorliegen.

## HID-Daten aus einem PCAP extrahieren

### Zuerst die Tastaturschnittstelle identifizieren

Bei umfangreichen Captures solltest du die HID-Tastatur identifizieren, bevor du Reports ausgibst. Ein zuverlässiger Ausgangspunkt ist die Antwort auf die Schnittstellenbeschreibung:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Die HID-Klasse definiert diese Interface-Werte:<sup>[[8]](#references)</sup>

- `subclass == 1` ist die Boot-Interface-Subclass; mit `protocol == 1` kennzeichnet sie eine Boot-Tastatur
- `protocol == 2` kennzeichnet eine Boot-Maus
- `protocol == 0` bedeutet, dass kein Boot-Protokoll verwendet wird; untersuche stattdessen den HID-Report-Descriptor, anstatt ein 8-Byte-Layout anzunehmen

Ein bootfähiges Interface ist **kein Beweis dafür, dass das Boot-Protokoll aktiv ist**. HID-Geräte werden im Report-Protokoll initialisiert. Der Host wählt den Boot-Modus mit `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); mit `wValue = 1` wird das Report-Protokoll ausgewählt. Wenn die Enumeration in der Aufzeichnung enthalten ist, prüfe die Anfrage für das Tastatur-Interface (`wIndex`), bevor du einen 8-Byte-Boot-Decoder verwendest. Fehlt sie, verifiziere das beobachtete Report-Layout, anstatt den Modus aus dem Interface-Descriptor abzuleiten.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Sobald die Schnittstelle bekannt ist, beschränke deine Filter auf `usb.bus_id`, `usb.device_address` und nach Möglichkeit `usb.bInterfaceNumber`, bevor du etwas exportierst.

### Wireshark-Workflow

1. **Gerät isolieren**: Filtere den Interrupt-IN-Verkehr der Tastatur, z. B. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Nützliche Spalten hinzufügen**: Klicke mit der rechten Maustaste auf das Feld `Leftover Capture Data` (`usb.capdata`) und deine bevorzugten `usbhid.*`-Felder (z. B. `usbhid.boot_report.keyboard.keycode_1`), um Tastenanschläge nachzuverfolgen, ohne jeden Frame einzeln zu öffnen.<sup>[[11]](#references)</sup>
3. **Leere Reports ausblenden**: Wende `!(usb.capdata == 00:00:00:00:00:00:00:00)` an, um inaktive Frames auszublenden.
4. **Zum Post-Processing exportieren**: `File -> Export Packet Dissections -> As CSV`, und füge `frame.number`, `usb.src`, `usb.capdata` sowie dekodierte Modifier-Felder wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt` hinzu, um die Rekonstruktion später zu skripten.<sup>[[10]](#references)[[11]](#references)</sup>

### Kommandozeilen-Workflow

Das klassische Extraktionsmuster – `usb.capdata` ausgeben, inaktive Reports verwerfen und Usage-IDs zuordnen – wird in der ursprünglichen Analyse von 2017 und ihrer Schritt-für-Schritt-Anleitung beschrieben.<sup>[[1]](#references)[[2]](#references)</sup>

Das Repository `ctf-usb-keyboard-parser` automatisiert die klassische tshark- + sed-Pipeline:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Bei neueren Mitschnitten sollte bevorzugt Wiresharks dekodiertes Feld `usbhid.data` verwendet und auf `usb.capdata` zurückgegriffen werden, falls es nicht verfügbar ist; schreiben Sie eine Payload pro Report in eine Datei pro Gerät:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Diese gerätespezifischen Dateien können nach einer Normalisierung des erwarteten Hexformats an einen Decoder übergeben werden. Wenn die Aufzeichnung von BLE-Tastaturen stammt, deren Daten über GATT getunnelt werden, filtere mit `btatt.value && frame.len == 20` und gib die Hex-Payloads vor dem Decodieren aus.<sup>[[7]](#references)</sup>

### Wenn der Report nicht dem klassischen 8-Byte-Boot-Report entspricht

Ein Nicht-Boot-Interface oder eine Report-ID kann das Payload-Layout ändern. Gehe daher nicht davon aus, dass jeder Tastaturreport dem Schema `modifier,reserved,key1..key6` entspricht.<sup>[[8]](#references)[[11]](#references)</sup>

- Bevorzuge `usbhid.data` gegenüber `usb.capdata`, wenn Wireshark die HID-Schicht bereits geparst hat.
- Wenn jede Zeile mit einem konstanten Präfix oder einer Report-ID beginnt, entferne diese mit einem offset-bewussten Decoder, statt anzunehmen, dass Byte 0 immer der Modifier ist.<sup>[[7]](#references)</sup>
- Bei manchen USBPcap-Exporten fehlt das reservierte Byte. Decoder mit Unterstützung für `--no-reserved` oder ein benutzerdefinierter Offset sparen Zeit.<sup>[[7]](#references)</sup>
- Wenn der HID-Reportdeskriptor oder die BLE-HOGP-Report-Map in der Aufzeichnung enthalten ist, verwende sie, um das tatsächliche Feldlayout zu ermitteln, bevor du einen Parser schreibst.

### Eine Key-Bitmap des Report-Protokolls decodieren

Bei einer Tastatur, deren Eingabereport eine Bitmap statt sechs Boot-Tasten-Slots enthält, suche den **HID-Reportdeskriptor** im Enumerierungsverkehr. Dieser Filter findet Frames, in denen Wireshark ein Report-Size-Element decodiert hat. Öffne einen davon und untersuche den vollständigen Deskriptor. Starte eine neue Aufzeichnung, bevor du die Tastatur anschließt, wenn der Deskriptor fehlt.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Für jeden Keyboard-Input-Report sollten Sie dessen `Report ID` (falls vorhanden), `Usage Page` (`0x07` für Tastaturtasten), `Usage Minimum/Maximum`, `Report Size`, `Report Count` und ob jedes `Input`-Element **Variable** oder **Array** ist, notieren. Zählen Sie alle vorhergehenden Input-Felder und konstantes Padding, um den Bit-Offset des Tastenfelds zu ermitteln; Report-Felder müssen nicht an Byte-Grenzen ausgerichtet sein. Ein Ein-Bit-Variable-Feld mit aufeinanderfolgenden Keyboard-Usages ist eine Tastenstatus-Bitmap: Bit 0 dieses Felds entspricht dem ersten deklarierten Usage, Bit 1 dem nächsten und so weiter. Ein Array enthält dagegen Werte, die anhand des Usage-Bereichs des Deskriptors aufgelöst werden, und nicht ein gedrücktes Tastensignal pro Bit. Wenn eine Report ID deklariert ist, wählen Sie zuerst Reports mit diesem Präfix aus und überspringen Sie das Byte bei der Berechnung der Feld-Offsets. Vergleichen Sie die Mengen der gehaltenen Usages zwischen aufeinanderfolgenden Reports derselben Schnittstelle und Report ID, um nur neu gedrückte Tasten auszugeben.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Decodierung automatisieren

- **ctf-usb-keyboard-parser** ist weiterhin praktisch für schnelle CTF-Challenges und ist bereits im Repository enthalten.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) verarbeitet sowohl `pcap`- als auch `pcapng`-Dateien nativ, unterstützt `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` und benötigt weder tshark noch andere externe Abhängigkeiten. Daher eignet es sich für isolierte Sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** bietet Visualisierungen für Tastatur, Maus und Tablet. Sie können entweder das Hilfsprogramm `extract_hid_data.sh` (tshark-Backend) oder `extract_hid_data.py` (scapy-Backend) ausführen und anschließend die resultierende Textdatei an den Decoder oder die Replay-Module übergeben, um die Tastenanschläge zu verfolgen.<sup>[[7]](#references)</sup>

### Zustandsbehaftete Decodierung ist wichtig

USB-Boot-Tastaturen senden im Ruhezustand Reports, auch wenn kein neues Tastenereignis vorliegt. Daher können Mitschnitte wiederholte Reports enthalten, bevor das Loslassereignis eintritt. Ein praxistauglicher Decoder sollte:<sup>[[3]](#references)[[8]](#references)</sup>

- nur neu gedrückte Keycodes im Vergleich zum vorherigen Report ausgeben
- den Modifikatorstatus (`Shift`, `Ctrl`, `AltGr`) aus Byte 0 oder geparsten Feldern wie `usbhid.boot_report.keyboard.modifier.left_shift` und `usbhid.boot_report.keyboard.modifier.right_alt` beibehalten
- Umschalttasten wie `Caps Lock` nachverfolgen, da die Ausgabe von Großbuchstaben nicht allein durch Shift gesteuert wird
- berücksichtigen, dass HID-Usage-IDs unabhängig vom Tastaturlayout sind: `0x1d` bezeichnet abhängig vom Tastaturlayout des Hosts die physische `z`- oder `y`-Tastenposition.<sup>[[9]](#references)</sup>

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

Füttere es mit den zuvor ausgegebenen einfachen Hex-Zeilen, um sofort eine grobe Rekonstruktion zu erhalten, ohne einen vollständigen Parser in die Umgebung einzubinden. Bei Nicht-US-Tastaturlayouts wird dabei weiterhin die physische Tastenposition rekonstruiert, nicht unbedingt das endgültige Zeichen, das auf dem Host des Opfers angezeigt wird.

## Tipps zur Fehlerbehebung

- Wenn Wireshark keine `usbhid.*`-Felder befüllt, wurde wahrscheinlich der HID-Report-Deskriptor nicht erfasst. Schließe die Tastatur während der Aufzeichnung erneut an oder verwende ersatzweise das rohe `usb.capdata`.
- Bei Software-Aufzeichnungen unter Linux ist `usbmon` die übliche Quelle; unter Windows benötigt Wireshark das **USBPcap**-extcap, um rohe USB-URBs überhaupt zu sehen.<sup>[[4]](#references)</sup>
- Wenn die Tastatur über einen Hub oder eine Dockingstation angeschlossen war, überprüfe zuerst den Interface-Deskriptor und dekodiere dann nur das betreffende Geräte-/Interface-Paar. Composite-HID-Aufzeichnungen vermischen häufig Tastatur- und Mausberichte.
- Für Windows-Aufzeichnungen ist das **USBPcap**-extcap-Interface erforderlich. Stelle sicher, dass es Wireshark-Upgrades überstanden hat, da fehlende extcaps zu leeren Gerätelisten führen.<sup>[[4]](#references)</sup>
- Gleiche vor dem Dekodieren immer das Tupel aus Bus, Gerät und Interface ab (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; z. B. `1.9.1`) — das Vermischen mehrerer Tastaturen oder Speichergeräte führt zu unsinnigen Tastenanschlägen.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Write-up: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analyse eines USB-Tastatur-Paketmitschnitts](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 – Write-up zu pcap 1 und 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Einrichtung der USB-Aufzeichnung in Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Geräteklassendefinition für Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID-Usage-Tabellen 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Referenz zu Wireshark-Anzeigefiltern: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Referenz zu Wireshark-Anzeigefiltern: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux-Kernel: Einführung in HID-Report-Deskriptoren](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: Write-up zu ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
