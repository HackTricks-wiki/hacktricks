# USB Toetsaanslae

{{#include ../../../banners/hacktricks-training.md}}

As jy 'n pcap het wat die kommunikasie via USB van 'n sleutelbord bevat soos die volgende een:

![](<../../../images/image (962).png>)

USB keyboards praat gewoonlik die HID **boot protocol**, so elke interrupt transfer na die host is net 8 bytes lank: een byte van modifier-bits (Ctrl/Shift/Alt/Super), een gereserveerde byte, en tot ses keycodes per report. Die dekodeer van daardie bytes is genoeg om alles wat getik is te herbou.

## USB HID-rapport basies

Die tipiese IN report lyk soos:

| Byte | Betekenis |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, ens.). Meerdere bits kan terselfdertyd gestel wees. |
| 1 | Gereserveerd/padding maar word dikwels deur gaming-sleutelborde hergebruik vir vendor data. |
| 2-7 | Tot ses gelyktydige keycodes in USB usage ID-formaat (`0x04 = a`, `0x1E = 1`). `0x00` beteken "no key". |

Sleutelborde sonder NKRO stuur gewoonlik `0x01` in byte 2 wanneer meer as ses sleutels gedruk word om "rollover" te signaleer. Om hierdie uitleg te verstaan help wanneer jy slegs die rou `usb.capdata` bytes het.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Isolate the device**: filter op interrupt IN traffic vanaf die sleutelbord, bv. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Add useful columns**: regsklik die `Leftover Capture Data` veld (`usb.capdata`) en jou voorkeur `usbhid.*` velde (bv. `usbhid.boot_report.keyboard.keycode_1`) om toetsaanslae te volg sonder om elke frame oop te maak.
3. **Hide empty reports**: pas `!(usb.capdata == 00:00:00:00:00:00:00:00)` toe om idle frames te verwyder.
4. **Export for post-processing**: `File -> Export Packet Dissections -> As CSV`, sluit `frame.number`, `usb.src`, `usb.capdata`, en `usbhid.modifiers` in om die rekonstruksie later te skryf.

### Command-line workflow

`ctf-usb-keyboard-parser` automaties al die klassieke tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Op nuwer opnames kan jy beide `usb.capdata` en die ryker `usbhid.data` veld behou deur per toestel te groepeer:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Daardie per-toestel-lêers val regstreeks in enige decoder. As die capture van BLE keyboards gekom het wat oor GATT getunnel is, filter op `btatt.value && frame.len == 20` en dump die hex payloads voordat jy dit dekodeer.

## Automatisering van die dekodering

- **ctf-usb-keyboard-parser** bly handig vir vinnige CTF-uitdagings en word reeds in die repository ingesluit.
- **CTF-Usb_Keyboard_Parser** (`main.py`) ontleed beide `pcap` en `pcapng` lêers natief, verstaan `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, en benodig nie tshark nie, so dit werk goed binne geïsoleerde sandboxes.
- **USB-HID-decoders** voeg toetsbord-, muis- en tablet-visualiseerders by. Jy kan óf die `extract_hid_data.sh` hulpprogram (tshark backend) óf `extract_hid_data.py` (scapy backend) hardloop en dan die resulterende tekslêer na die decoder of replay-modules voer om die toetsaanslae te sien ontvou.

## Vinnige Python-dekoder
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
Voer dit met die platte hex-lyne wat vroeër gedump is om 'n onmiddellike, ru-rekonstruksie te kry sonder om 'n volledige parser in die omgewing in te laai.

## Foutoplossingswenke

- As Wireshark nie die `usbhid.*` velde invul nie, is die HID report descriptor waarskynlik nie vasgelê nie. Steek die sleutelbord weer in terwyl jy capture, of val terug op die rou `usb.capdata`.
- Windows captures vereis die **USBPcap** extcap-interface; maak seker dit het Wireshark-opgraderings oorleef, aangesien ontbrekende extcaps jou met leë apparaatlyste laat.
- Korreleer altyd `usb.bus_id:device:interface` (bv. `1.9.1`) voordat jy enigiets dekodeer — die meng van verskeie sleutelborde of bergingsapparaatte lei tot onsin-toetsaanslae.

## Verwysings

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
