# USB Keystrokes

As jy 'n pcap het wat die kommunikasie via USB van 'n sleutelbord soos die volgende bevat:

![USB Keystrokes: As jy 'n pcap het wat die kommunikasie via USB van 'n sleutelbord soos die volgende bevat](<../../../images/image (962).png>)

Vir 'n sleutelbord wat die HID **boot protocol** gebruik, het elke Interrupt IN report 'n vaste uitleg van 8 grepe: een modifier-greep, een gereserveerde greep en ses keycode-grepe. Die gasheer vergelyk opeenvolgende reports en karteer keycodes na HID usages om sleutelgebeurtenisse te rekonstrueer.<sup>[[8]](#references)</sup>

## USB HID-report-beginsels

Die standaard boot-sleutelbord-invoerreport is soos volg gestruktureer.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Betekenis |
| --- | --- |
| 0 | Modifier-bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, ens.). Veelvuldige bisse kan gelyktydig gestel wees. |
| 1 | Gereserveerde greep; ongebruikte reports behoort dit normaalweg op nul te stel. OEM- of stelselspesifieke gebruik is nie draagbaar nie. |
| 2-7 | Tot ses gelyktydige keycodes in USB usage ID-formaat (`0x04 = a`, `0x1E = 1`). `0x00` beteken "geen sleutel". |

In die boot-uitleg word usage ID `0x01` (`Keyboard ErrorRollOver`) in alle sleutelgleuwe gerapporteer wanneer meer as ses nie-modifier-sleutels gedruk word; dit kan ook 'n onherkenbare kombinasie aandui.<sup>[[8]](#references)[[9]](#references)</sup> As jy hierdie uitleg verstaan, help dit wanneer jy slegs die rou `usb.capdata`-grepe het.

## Onttrekking van HID-data uit 'n PCAP

### Identifiseer eers die sleutelbordinterface

In besige captures, identifiseer die HID-sleutelbord voordat jy enige reports dump. 'n Betroubare beginpunt is die interface descriptor-response:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Die HID-klas definieer hierdie koppelvlakwaardes:<sup>[[8]](#references)</sup>

- `subclass == 1` is die Boot Interface Subclass; met `protocol == 1` identifiseer dit ’n boot-sleutelbord
- `protocol == 2` identifiseer ’n boot-muis
- `protocol == 0` beteken geen boot-protokol nie; inspekteer eerder die HID report descriptor as om ’n 8-grepe-uitleg te aanvaar

Sodra die koppelvlak bekend is, bind jou filters aan `usb.bus_id`, `usb.device_address` en, indien moontlik, `usb.bInterfaceNumber` voordat jy enigiets uitvoer.

### Wireshark-werksvloei

1. **Isoleer die toestel**: filter op interrupt IN-verkeer vanaf die sleutelbord, byvoorbeeld `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Voeg nuttige kolomme by**: klik met die regtermuisknoppie op die `Leftover Capture Data`-veld (`usb.capdata`) en jou voorkeur-`usbhid.*`-velde (byvoorbeeld `usbhid.boot_report.keyboard.keycode_1`) om sleuteldrukke te volg sonder om elke raam oop te maak.<sup>[[11]](#references)</sup>
3. **Versteek leë reports**: pas `!(usb.capdata == 00:00:00:00:00:00:00:00)` toe om idle-rame te verwyder.
4. **Voer uit vir naverwerking**: `File -> Export Packet Dissections -> As CSV`, sluit `frame.number`, `usb.src`, `usb.capdata` en gedekodeerde wysiger-velde soos `usbhid.boot_report.keyboard.modifier.left_shift` en `usbhid.boot_report.keyboard.modifier.right_alt` in om die rekonstruksie later te script.<sup>[[10]](#references)[[11]](#references)</sup>

### Opdragreël-werksvloei

Die klassieke ekstraksiepatroon—dump `usb.capdata`, verwyder idle reports en karteer usage IDs—verskyn in die oorspronklike 2017-analise en sy deurloop.<sup>[[1]](#references)[[2]](#references)</sup>

Die `ctf-usb-keyboard-parser`-repository outomatiseer die klassieke tshark + sed-pyplyn:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Op nuwer opnames, verkies Wireshark se gedekodeerde `usbhid.data`-veld en gebruik `usb.capdata` as terugval; skryf een payload per report na ’n lêer per toestel:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Daardie per-toestel-lêers kan aan ’n decoder gevoer word nadat die hex-formaat wat dit verwag, genormaliseer is. As die capture van BLE-sleutelborde gekom het wat oor GATT getonnel is, filter op `btatt.value && frame.len == 20` en skryf die hex-ladings uit voordat jy dit decodeer.<sup>[[7]](#references)</sup>

### Wanneer die verslag nie die klassieke 8-grepe boot report is nie

’n Nie-boot-koppelvlak of ’n report ID kan die uitleg van die lading verander, dus moenie aanvaar dat elke sleutelbordverslag by `modifier,reserved,key1..key6` pas nie.<sup>[[8]](#references)[[11]](#references)</sup>

- Verkies `usbhid.data` bo `usb.capdata` wanneer Wireshark reeds die HID-laag ontleed het.
- As elke lyn met ’n konstante voorvoegsel of report ID begin, verwyder dit met ’n decoder wat offsets in ag neem, eerder as om aan te neem dat byte 0 altyd die modifier is.<sup>[[7]](#references)</sup>
- Sommige USBPcap-uitvoere laat die reserved-byte weg, dus spaar decoders wat `--no-reserved` of ’n pasgemaakte offset ondersteun tyd.<sup>[[7]](#references)</sup>
- As die HID report descriptor of BLE HOGP report map in die capture teenwoordig is, gebruik dit om die werklike veld-uitleg te herstel voordat jy ’n parser skryf.

## Die decoding outomatiseer

- **ctf-usb-keyboard-parser** bly handig vir vinnige CTF-uitdagings en is reeds in die repository ingesluit.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) ontleed beide `pcap`- en `pcapng`-lêers inheems, verstaan `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, en vereis nie tshark of ’n ander eksterne dependency nie, dus is dit geskik vir geïsoleerde sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** voeg visualiseerders vir sleutelborde, muise en tablette by. Jy kan óf die `extract_hid_data.sh`-helper (tshark-backend) óf `extract_hid_data.py` (scapy-backend) uitvoer en dan die resulterende tekslêer aan die decoder- of replay-modules voer om te sien hoe die sleuteldrukke ontvou.<sup>[[7]](#references)</sup>

### Stateful decoding is belangrik

USB boot-sleutelborde stuur reports teen die idle rate, selfs wanneer daar geen nuwe sleutelgebeurtenis is nie, dus kan captures herhaalde reports bevat voordat die release event plaasvind. ’n Praktiese decoder behoort:<sup>[[3]](#references)[[8]](#references)</sup>

- slegs nuutgedrukte keycodes uit te stuur in vergelyking met die vorige report
- modifier-state (`Shift`, `Ctrl`, `AltGr`) vanaf byte 0 of geparseerde velde soos `usbhid.boot_report.keyboard.modifier.left_shift` en `usbhid.boot_report.keyboard.modifier.right_alt` te behou
- toggle keys soos `Caps Lock` dop te hou, omdat hoofletters nie slegs deur Shift beheer word nie
- te onthou dat HID usage IDs uitleg-onafhanklik is: `0x1d` is die fisiese `z`/`y`-sleutelposisie, afhangend van die host-sleutelborduitleg.<sup>[[9]](#references)</sup>

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
Voer dit met die gewone heksadesimale lyne wat vroeër gedump is om onmiddellik ’n rowwe rekonstruksie te kry sonder om ’n volledige parser in die omgewing in te trek. Vir nie-US-uitlegte rekonstrueer dit steeds die fisiese sleutelposisie, nie noodwendig die finale glyph wat op die slagofferhost vertoon word nie.

## Foutsporingswenke

- As Wireshark nie `usbhid.*`-velde invul nie, is die HID report descriptor waarskynlik nie vasgelê nie. Koppel die sleutelbord weer in terwyl jy vaslê, of val terug na rou `usb.capdata`.
- Op Linux-sagtewarevasleggings is `usbmon` die normale bron; op Windows is Wireshark afhanklik van die **USBPcap** extcap om hoegenaamd rou USB URBs te sien.<sup>[[4]](#references)</sup>
- As die sleutelbord deur ’n hub of dock gekoppel was, bevestig eers die interface descriptor en decodeer dan slegs daardie device/interface-paar. Saamgestelde HID-vasleggings meng dikwels sleutelbord- en muisverslae.
- Windows-vasleggings vereis die **USBPcap** extcap-interface; maak seker dit het Wireshark-opgraderings oorleef, aangesien ontbrekende extcaps jou met leë toestelyste laat.<sup>[[4]](#references)</sup>
- Korrelleer altyd die bus-, device- en interface-tupel (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; byvoorbeeld `1.9.1`) voordat jy enigiets decodeer — die vermenging van verskeie sleutelborde of stoortoestelle lei tot onsinnige sleuteldrukke.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Ontleding van USB-sleutelbordpakketvaslegging](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB-vasstellingsopstelling](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Device Class Definition for Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
