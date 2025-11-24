# Mabofya ya USB

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap inayojumuisha mawasiliano kupitia USB ya kibodi kama ifuatayo:

![](<../../../images/image (962).png>)

USB keyboards kawaida huzungumza HID **boot protocol**, kwa hivyo kila interrupt transfer kuelekea host ni ndefu kwa 8 bait tu: bait moja ya modifier bits (Ctrl/Shift/Alt/Super), bait moja iliyo reserved, na hadi keycode sita kwa ripoti. Kutoa maana ya bait hizo inatosha kujenga upya kila kilichoandikwa.

## Misingi ya ripoti za USB HID

Ripoti ya kawaida ya IN inaonekana kama ifuatavyo:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

Kibodi ambazo hazina NKRO kawaida hutuma `0x01` katika byte 2 wakati vitufe zaidi ya sita vinabofuliwa ili kuashiria "rollover". Kuelewa mpangilio huu kunasaidia wakati una tu bait za raw `usb.capdata`.

## Kutoa data za HID kutoka kwa PCAP

### Mtiririko wa Wireshark

1. **Tenga kifaa**: filter kwenye trafiki ya interrupt IN kutoka kwa kibodi, mf. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ongeza safu muhimu**: bofya-kulia uwanja wa `Leftover Capture Data` (`usb.capdata`) na uwanja unaopendelea wa `usbhid.*` (mf. `usbhid.boot_report.keyboard.keycode_1`) ili kufuatilia mabofya bila kufungua fremu zote.
3. **Ficha ripoti tupu**: tumia `!(usb.capdata == 00:00:00:00:00:00:00:00)` kuondoa fremu za utulivu.
4. **Export kwa uchakataji wa baadaye**: `File -> Export Packet Dissections -> As CSV`, jumuisha `frame.number`, `usb.src`, `usb.capdata`, na `usbhid.modifiers` ili kuandika script ya ujenzi upya baadaye.

### Mtiririko wa mstari wa amri

`ctf-usb-keyboard-parser` tayari hufanya otomatiki pipeline ya classic tshark + sed:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Katika captures za hivi karibuni unaweza kuhifadhi zote mbili `usb.capdata` na uwanja wenye taarifa zaidi `usbhid.data` kwa kuzipanga kwa kila kifaa:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Hizo per-device files huingizwa moja kwa moja kwenye decoder yoyote. Ikiwa capture ilitoka kwa vibodi vya BLE vilivyo tunneling kupitia GATT, chuja kwa `btatt.value && frame.len == 20` na toa payloads za hex kabla ya ku-decode.

## Ku-otomatisha ku-decode

- **ctf-usb-keyboard-parser** inabaki muhimu kwa changamoto za CTF za haraka na tayari inajumuishwa kwenye repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) huchambua faili za `pcap` na `pcapng` moja kwa moja, inatambua `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, na haitegemei `tshark`, hivyo inafanya kazi vizuri ndani ya sandboxes zilizo pekee.
- **USB-HID-decoders** inaongeza vionyeshi vya keyboard, mouse, na tablet. Unaweza kuendesha msaada wa `extract_hid_data.sh` (tshark backend) au `extract_hid_data.py` (scapy backend) kisha uwasilishe faili la maandishi lililotengenezwa kwa decoder au moduli za replay ili kutazama keystrokes zikifunguka.

## Decoder ya Python ya haraka
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
Weka mistari rahisi za hex zilizotolewa hapo awali ili kupata ujenzi wa haraka bila kuleta parser kamili ndani ya mazingira.

## Vidokezo vya kutatua matatizo

- Kama Wireshark haitajaza viwanja vya `usbhid.*`, inawezekana HID report descriptor haikushikiliwa. Unganisha tena kibodi wakati wa kunasa au tumia `usb.capdata` ghafi.
- Kunanasa kwenye Windows kunahitaji kiolesura cha extcap cha **USBPcap**; hakikisha kilidumu baada ya masasisho ya Wireshark, kwa kuwa ukosefu wa extcap utakufanya uwe na orodha za vifaa tupu.
- Daima linganisha `usb.bus_id:device:interface` (kwa mfano `1.9.1`) kabla ya kutafsiri chochote — kuchanganya vibodi nyingi au vifaa vya uhifadhi kunaweza kusababisha vibofyo vya kibodi visivyo na maana.

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
