# USB pritisci tastera

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži USB komunikaciju tastature kao na sledećoj slici:

![](<../../../images/image (962).png>)

USB tastature obično koriste HID **boot protocol**, tako da je svaki interrupt transfer ka hostu dugačak samo 8 bajtova: jedan bajt bitmapa modifikatora (Ctrl/Shift/Alt/Super), jedan rezervisani bajt, i do šest keycode-ova po reportu. Dekodiranje tih bajtova je dovoljno da se rekonstruiše sve što je otkucano.

## Osnove USB HID izveštaja

Tipičan IN report izgleda ovako:

| Bajt | Značenje |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, itd.). Više bitova može biti postavljeno istovremeno. |
| 1 | Reserved/padding ali često se ponovo koristi na gaming tastaturama za vendor podatke. |
| 2-7 | Do šest istovremenih keycode-ova u USB usage ID formatu (`0x04 = a`, `0x1E = 1`). `0x00` znači "no key". |

Tastature bez NKRO obično pošalju `0x01` u bajtu 2 kada je pritisnuto više od šest tastera da signaliziraju "rollover". Razumevanje ovog rasporeda pomaže kada imate samo raw `usb.capdata` bajtove.

## Ekstrakcija HID podataka iz PCAP-a

### Wireshark radni tok

1. **Isolujte uređaj**: filtrirajte interrupt IN saobraćaj od tastature, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodajte korisne kolone**: kliknite desnim tasterom na `Leftover Capture Data` polje (`usb.capdata`) i na željena `usbhid.*` polja (npr. `usbhid.boot_report.keyboard.keycode_1`) da pratite pritiske bez otvaranja svakog frejma.
3. **Sakrijte prazne izveštaje**: primenite `!(usb.capdata == 00:00:00:00:00:00:00:00)` da izbacite idle frejmove.
4. **Eksport za post-processing**: `File -> Export Packet Dissections -> As CSV`, uključite `frame.number`, `usb.src`, `usb.capdata`, i `usbhid.modifiers` da kasnije skriptujete rekonstrukciju.

### Radni tok komandne linije

`ctf-usb-keyboard-parser` već automatizuje klasični tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Na novijim captures možete sačuvati i `usb.capdata` i bogatije polje `usbhid.data` tako što ćete batchovati po device:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ti fajlovi po uređaju se mogu direktno ubaciti u bilo koji dekoder. Ako je capture potekao sa BLE tastatura tunelovanih preko GATT, filtrirajte po `btatt.value && frame.len == 20` i ispišite hex payloads pre dekodiranja.

## Automatizacija dekodiranja

- **ctf-usb-keyboard-parser** ostaje koristan za brze CTF izazove i već se isporučuje u repozitorijumu.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parsira i `pcap` i `pcapng` fajlove nativno, razume `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, i ne zahteva tshark, pa lepo radi u izolovanim sandbox-ovima.
- **USB-HID-decoders** dodaje vizualizere za keyboard, mouse i tablet. Možete ili pokrenuti helper `extract_hid_data.sh` (tshark backend) ili `extract_hid_data.py` (scapy backend) i zatim proslediti dobijeni tekst fajl decoderu ili replay modulima da biste gledali kako se keystrokes odvijaju.

## Brzi Python dekoder
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
Prosledi mu obične hex linije izdumpane ranije da dobiješ brzu grubu rekonstrukciju bez potrebe da ubacuješ kompletan parser u okruženje.

## Saveti za rešavanje problema

- Ako Wireshark ne popuni `usbhid.*` polja, HID report descriptor verovatno nije snimljen. Ponovo priključite tastaturu dok vršite capture ili se vratite na raw `usb.capdata`.
- Windows captures zahtevaju **USBPcap** extcap interfejs; proverite da li je preživeo nadogradnje Wireshark-a, jer nedostajući extcap-ovi ostavljaju prazne liste uređaja.
- Uvek uskladite `usb.bus_id:device:interface` (npr. `1.9.1`) pre dekodiranja bilo čega — mešanje više tastatura ili uređaja za skladištenje dovodi do besmislenih keystrokes.

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
