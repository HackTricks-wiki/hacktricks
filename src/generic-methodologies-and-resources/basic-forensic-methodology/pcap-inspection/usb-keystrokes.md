# USB-toetsaanslae

{{#include ../../../banners/hacktricks-training.md}}

As jy 'n pcap het wat die kommunikasie via USB van 'n sleutelbord soos die volgende een bevat:

![USB-toetsaanslae: As jy 'n pcap het wat die kommunikasie via USB van 'n sleutelbord soos die volgende een bevat](<../../../images/image (962).png>)

USB-sleutelborde gebruik gewoonlik die HID **boot protocol**, dus is elke interrupt-oordrag na die host slegs 8 grepe lank: een greep met modifier-bisse (Ctrl/Shift/Alt/Super), een gereserveerde greep, en tot ses keycodes per report. Deur hierdie grepe te dekodeer, is dit genoeg om alles wat ingetik is, te rekonstrueer.

## USB HID report-basiese beginsels

Die tipiese IN-report lyk soos volg:

| Greep | Betekenis |
| --- | --- |
| 0 | Modifier-bitmap (`0x02` = Left Shift, `0x20` = Right Alt, ens.). Veelvuldige bisse kan gelyktydig gestel wees. |
| 1 | Gereserveer/vulsel, maar word dikwels deur gaming-sleutelborde vir vendor-data hergebruik. |
| 2-7 | Tot ses gelyktydige keycodes in USB usage ID-formaat (`0x04 = a`, `0x1E = 1`). `0x00` beteken "geen sleutel". |

Sleutelborde sonder NKRO stuur gewoonlik `0x01` in greep 2 wanneer meer as ses sleutels gedruk word, om "rollover" aan te dui. Deur hierdie uitleg te verstaan, kan jy die rou `usb.capdata`-grepe interpreteer wanneer dit al is wat jy het.

## Onttrekking van HID-data uit 'n PCAP

### Identifiseer eers die sleutelbord-koppelvlak

In besige captures, identifiseer die HID-sleutelbord voordat jy enige reports dump. 'n Betroubare beginpunt is die interface descriptor response:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Kyk na `usb.bInterfaceSubClass` en `usb.bInterfaceProtocol`:

- `subclass == 1` en `protocol == 1` beteken gewoonlik 'n boot keyboard
- `protocol == 2` is tipies 'n mouse
- `protocol == 0` beteken dikwels 'n vendor-defined of NKRO-style HID-interface wat steeds keyboard-data dra, maar nie in die eenvoudige 8-byte boot-uitleg nie

Sodra die interface geïdentifiseer is, beperk jou filters tot `usb.bus_id`, `usb.device_address` en, indien moontlik, `usb.interface_number` voordat jy enigiets uitvoer.

### Wireshark-werkvloei

1. **Isoleer die toestel**: filter op interrupt IN-verkeer vanaf die keyboard, byvoorbeeld `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Voeg nuttige kolomme by**: klik met die regtermuisknoppie op die `Leftover Capture Data`-veld (`usb.capdata`) en jou voorkeur-`usbhid.*`-velde (byvoorbeeld `usbhid.boot_report.keyboard.keycode_1`) om keypresses te volg sonder om elke frame oop te maak.
3. **Versteek leë reports**: pas `!(usb.capdata == 00:00:00:00:00:00:00:00)` toe om idle frames te verwyder.
4. **Voer uit vir post-processing**: `File -> Export Packet Dissections -> As CSV`, en sluit `frame.number`, `usb.src`, `usb.capdata` en `usbhid.modifiers` in om die reconstruction later te script.

### Command-line-werkvloei

`ctf-usb-keyboard-parser` outomatiseer reeds die klassieke tshark + sed-pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
In nuwer captures kan jy beide `usb.capdata` en die ryker `usbhid.data`-veld behou deur per toestel te bondel:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Daardie per-toestel-lêers kan direk in enige decoder ingelees word. As die capture van BLE keyboards gekom het wat oor GATT getunnel is, filter op `btatt.value && frame.len == 20` en dump die hex-payloads voordat jy dit decodeer.

### Wanneer die report nie die klassieke 8-byte boot report is nie

Onlangse gaming keyboards, split keyboards en composite HID-devices stel dikwels ’n nie-boot keyboard-interface bloot waar die payload nie meer met `modifier,reserved,key1..key6` ooreenstem nie.

- Verkies `usbhid.data` bo `usb.capdata` wanneer Wireshark reeds die HID-laag geparse het.
- As elke lyn met ’n konstante prefix of report ID begin, strip dit met ’n offset-bewuste decoder eerder as om aan te neem dat byte 0 altyd die modifier is.
- Sommige USBPcap-exports laat die reserved-byte weg, dus bespaar decoders wat `--no-reserved` of ’n custom offset ondersteun tyd.
- As die HID report descriptor of BLE HOGP report map in die capture teenwoordig is, gebruik dit om die werklike velduitleg te herstel voordat jy ’n parser skryf.

## Die decoding outomatiseer

- **ctf-usb-keyboard-parser** bly handig vir vinnige CTF-challenges en word reeds in die repository verskaf.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) parseer beide `pcap`- en `pcapng`-lêers natively, verstaan `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` en vereis nie tshark nie, dus werk dit goed binne geïsoleerde sandboxes.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** voeg keyboard-, mouse- en tablet-visualizers by. Jy kan óf die `extract_hid_data.sh`-helper (tshark-backend) óf `extract_hid_data.py` (scapy-backend) uitvoer en dan die gevolglike tekslêer aan die decoder- of replay-modules voer om te kyk hoe die keystrokes ontvou.<sup>[[5]](#references)</sup>

### Stateful decoding is belangrik

USB interrupt-captures bevat gewoonlik beide die key press en een of meer herhaalde kopieë van dieselfde report voordat die release event arriveer. ’n Praktiese decoder behoort:<sup>[[2]](#references)</sup>

- slegs nuut-gedrukte keycodes uit te stuur in vergelyking met die vorige report
- modifier-state (`Shift`, `Ctrl`, `AltGr`) vanaf byte 0 of die geparseerde `usbhid.boot_report.keyboard.modifier`-veld te behou
- toggle keys soos `Caps Lock` na te spoor, omdat uppercase output nie slegs deur Shift beheer word nie
- te onthou dat HID usage IDs layout-agnosties is: `0x1d` is die fisiese `z`/`y`-sleutelposisie, afhangend van die host se keyboard-layout

## Vinnige Python-decoder
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
Voer dit met die gewone hex-reëls wat vroeër gedump is, om onmiddellik ’n rowwe rekonstruksie te kry sonder om ’n volledige parser in die omgewing in te trek. Vir nie-US-uitlegte rekonstrueer dit steeds die fisiese sleutelposisie, nie noodwendig die finale glyph wat op die slagofferhost vertoon word nie.

## Wenke vir probleemoplossing

- As Wireshark nie `usbhid.*`-velde invul nie, is die HID report descriptor waarskynlik nie vasgelê nie. Koppel die sleutelbord weer in terwyl jy vaslê, of val terug na rou `usb.capdata`.
- Op Linux-sagtewarevasleggings is `usbmon` die normale bron; op Windows is Wireshark afhanklik van die **USBPcap** extcap om enigsins rou USB URBs te sien.<sup>[[1]](#references)</sup>
- As die sleutelbord deur ’n hub of dock gekoppel is, bevestig eers die interface descriptor en dekodeer dan slegs daardie device/interface-paar. Composite HID-vasleggings meng dikwels sleutelbord- en muisverslae.
- Windows-vasleggings vereis die **USBPcap** extcap-interface; maak seker dit het Wireshark-opgraderings oorleef, aangesien ontbrekende extcaps jou met leë toestellyste laat.<sup>[[1]](#references)</sup>
- Korrelleer altyd `usb.bus_id:device:interface` (byvoorbeeld `1.9.1`) voordat jy enigiets dekodeer — die vermenging van verskeie sleutelborde of stoortoestelle lei tot onsinnige sleuteldrukke.

## Verwysings

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
