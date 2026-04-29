# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

As jy 'n pcap het wat die kommunikasie via USB van 'n keyboard bevat soos die volgende een:

![](<../../../images/image (962).png>)

USB keyboards praat gewoonlik die HID **boot protocol**, so elke interrupt transfer na die host toe is net 8 bytes lank: een byte van modifier bits (Ctrl/Shift/Alt/Super), een gereserveerde byte, en tot ses keycodes per report. Om daardie bytes te dekodeer is genoeg om alles wat getik is, te herbou.

## USB HID report basics

Die tipiese IN report lyk soos:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, ens.). Veelvuldige bits kan gelyktydig gestel wees. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Tot ses gelyktydige keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` beteken "no key". |

Keyboards sonder NKRO stuur gewoonlik `0x01` in byte 2 wanneer meer as ses keys gedruk word om "rollover" aan te dui. Om hierdie uitleg te verstaan help wanneer jy net die rou `usb.capdata` bytes het.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

Op besige captures, identifiseer eers die HID keyboard voordat jy enige reports dump. 'n Betroubare beginpunt is die interface descriptor response:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Kyk na `usb.bInterfaceSubClass` en `usb.bInterfaceProtocol`:

- `subclass == 1` en `protocol == 1` beteken gewoonlik ’n boot keyboard
- `protocol == 2` is tipies ’n mouse
- `protocol == 0` beteken dikwels ’n vendor-defined of NKRO-style HID interface wat steeds keyboard data dra, maar nie in die eenvoudige 8-byte boot layout nie

Sodra die interface bekend is, pin jou filters aan `usb.bus_id`, `usb.device_address`, en indien moontlik `usb.interface_number` voordat jy enigiets export.

### Wireshark workflow

1. **Isoleer die device**: filter op interrupt IN traffic vanaf die keyboard, bv. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Voeg nuttige columns by**: right-click die `Leftover Capture Data` field (`usb.capdata`) en jou voorkeur `usbhid.*` fields (bv. `usbhid.boot_report.keyboard.keycode_1`) om keystrokes te volg sonder om elke frame oop te maak.
3. **Versteek leë reports**: pas `!(usb.capdata == 00:00:00:00:00:00:00:00)` toe om idle frames uit te haal.
4. **Export vir post-processing**: `File -> Export Packet Dissections -> As CSV`, sluit `frame.number`, `usb.src`, `usb.capdata`, en `usbhid.modifiers` in om later die reconstruction te script.

### Command-line workflow

`ctf-usb-keyboard-parser` automateer reeds die classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Op nuwer captures kan jy beide `usb.capdata` en die ryker `usbhid.data` veld behou deur per toestel te batch:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Daardie per-toestel-lêers val reg in enige decoder in. As die capture van BLE keyboards gekom het wat oor GATT getunnel is, filter op `btatt.value && frame.len == 20` en dump die hex payloads voor decoding.

### Wanneer die report nie die klassieke 8-byte boot report is nie

Onlangse gaming keyboards, split keyboards, en composite HID devices stel dikwels 'n non-boot keyboard interface bloot waar die payload nie meer ooreenstem met `modifier,reserved,key1..key6` nie.

- Verkies `usbhid.data` bo `usb.capdata` wanneer Wireshark reeds die HID layer geparse het.
- As elke reël met 'n konstante prefix of report ID begin, stroop dit met 'n offset-aware decoder eerder as om aan te neem byte 0 is altyd die modifier.
- Sommige USBPcap exports laat die reserved byte weg, so decoders wat `--no-reserved` of 'n custom offset ondersteun, spaar tyd.
- As die HID report descriptor of BLE HOGP report map in die capture teenwoordig is, gebruik dit om die werklike field layout te herstel voordat jy 'n parser skryf.

## Automating the decoding

- **ctf-usb-keyboard-parser** bly handig vir vinnige CTF challenges en kom reeds saam in die repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parse beide `pcap` en `pcapng` files natively, verstaan `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, en vereis nie tshark nie, so dit werk mooi binne geïsoleerde sandboxes.
- **USB-HID-decoders** voeg keyboard-, mouse-, en tablet-visualizers by. Jy kan óf die `extract_hid_data.sh` helper (tshark backend) of `extract_hid_data.py` (scapy backend) laat loop en dan die resulterende tekslêer na die decoder of replay modules voer om die keystrokes te sien ontvou.

### Stateful decoding matters

USB interrupt captures bevat gewoonlik beide die key press en een of meer herhaalde kopieë van dieselfde report voordat die release event aankom. 'n Praktiese decoder behoort:

- slegs nuutgedrukte keycodes uit te voer in vergelyking met die vorige report
- modifier state (`Shift`, `Ctrl`, `AltGr`) te behou vanaf byte 0 of die geparsde `usbhid.boot_report.keyboard.modifier` field
- toggle keys soos `Caps Lock` te volg, omdat hoofletters nie net deur Shift alleen beheer word nie
- te onthou dat HID usage IDs layout-agnosties is: `0x1d` is die fisiese `z`/`y` key position afhangend van die host keyboard layout

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
Voer dit met die rou hex-lyne wat vroeër gedump is om ’n onmiddellike rowwe rekonstruering te kry sonder om ’n volle parser in die omgewing in te trek. Vir nie-VS uitlegte rekonstrueer dit steeds die fisiese sleutelposisie, nie noodwendig die finale glyph wat op die slagoffer se host gewys word nie.

## Troubleshooting tips

- As Wireshark nie `usbhid.*` velde vul nie, is die HID report descriptor waarskynlik nie vasgevang nie. Koppel die keyboard weer in terwyl jy capture of val terug na rou `usb.capdata`.
- Op Linux software captures is `usbmon` die normale bron; op Windows is Wireshark afhanklik van die **USBPcap** extcap om enigsins rou USB URBs te sien.
- As die keyboard deur ’n hub of dock gekoppel was, bevestig eers die interface descriptor en decode dan net daardie device/interface-paar. Composite HID captures meng dikwels keyboard- en mouse reports.
- Windows captures vereis die **USBPcap** extcap interface; maak seker dit het Wireshark upgrades oorleef, aangesien ontbrekende extcaps jou met leë device lists laat.
- Correlate altyd `usb.bus_id:device:interface` (bv. `1.9.1`) voordat jy enigiets decode — om multiple keyboards of storage devices te meng lei tot onsin keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
