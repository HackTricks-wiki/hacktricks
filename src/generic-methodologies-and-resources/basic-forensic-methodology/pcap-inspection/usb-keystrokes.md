# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži komunikaciju preko USB-a za tastaturu kao što je sledeća:

![](<../../../images/image (962).png>)

USB tastature obično koriste HID **boot protocol**, pa je svaki interrupt transfer ka hostu dug samo 8 bajtova: jedan bajt bitova modifikatora (Ctrl/Shift/Alt/Super), jedan rezervisani bajt, i do šest keycode-ova po reportu. Dekodiranje tih bajtova je dovoljno da se rekonstruiše sve što je ukucano.

## Osnove USB HID reporta

Tipičan IN report izgleda ovako:

| Byte | Meaning |
| --- | --- |
| 0 | Bit mapa modifikatora (`0x02` = Left Shift, `0x20` = Right Alt, itd.). Više bitova može biti postavljeno istovremeno. |
| 1 | Rezervisano/padding, ali ga gaming tastature često ponovo koriste za vendor data. |
| 2-7 | Do šest istovremenih keycode-ova u USB usage ID formatu (`0x04 = a`, `0x1E = 1`). `0x00` znači "nema tastera". |

Tastature bez NKRO obično šalju `0x01` u bajtu 2 kada je pritisnuto više od šest tastera, da signaliziraju "rollover". Razumevanje ovog rasporeda pomaže kada imate samo sirove `usb.capdata` bajtove.

## Ekstrakcija HID podataka iz PCAP-a

### Prvo identifikujte interfejs tastature

Na zauzetim capture-ima, identifikujte HID tastaturu pre nego što dump-ujete bilo koje report-e. Pouzdana početna tačka je odgovor interface descriptor-a:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Pogledaj `usb.bInterfaceSubClass` i `usb.bInterfaceProtocol`:

- `subclass == 1` i `protocol == 1` obično znači boot keyboard
- `protocol == 2` je tipično mouse
- `protocol == 0` često znači vendor-defined ili NKRO-style HID interface koji i dalje nosi keyboard podatke, ali ne u jednostavnom 8-byte boot layoutu

Kada je interface poznat, ograniči filtre na `usb.bus_id`, `usb.device_address` i, ako je moguće, `usb.interface_number` pre nego što išta eksportuješ.

### Wireshark workflow

1. **Izoluj uređaj**: filtriraj interrupt IN traffic sa keyboarda, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodaj korisne kolone**: desni klik na polje `Leftover Capture Data` (`usb.capdata`) i željena `usbhid.*` polja (npr. `usbhid.boot_report.keyboard.keycode_1`) da pratiš keystrokes bez otvaranja svakog frame-a.
3. **Sakrij prazne reportove**: primeni `!(usb.capdata == 00:00:00:00:00:00:00:00)` da izbaciš idle frame-ove.
4. **Eksport za naknadnu obradu**: `File -> Export Packet Dissections -> As CSV`, uključi `frame.number`, `usb.src`, `usb.capdata` i `usbhid.modifiers` da kasnije skriptom rekonstruišeš podatke.

### Command-line workflow

`ctf-usb-keyboard-parser` već automatizuje klasični tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Na novijim capture-ovima možete zadržati i `usb.capdata` i bogatije `usbhid.data` polje tako što ćete grupisati po uređaju:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Ti fajlovi po uređaju se direktno ubacuju u bilo koji decoder. Ako je capture došao sa BLE tastatura tuneliranih preko GATT, filtriraj na `btatt.value && frame.len == 20` i izvezi hex payload-e pre dekodiranja.

### Kada report nije klasični 8-byte boot report

Savremene gaming tastature, split tastature i composite HID uređaji često izlažu non-boot keyboard interface gde payload više ne odgovara `modifier,reserved,key1..key6`.

- Preferiraj `usbhid.data` umesto `usb.capdata` kada je Wireshark već parsirao HID layer.
- Ako svaka linija počinje konstantnim prefixom ili report ID-jem, ukloni ga offset-aware decoderom umesto da pretpostaviš da je byte 0 uvek modifier.
- Neki USBPcap exporti izostavljaju reserved byte, pa decoderi koji podržavaju `--no-reserved` ili custom offset štede vreme.
- Ako su u capture-u prisutni HID report descriptor ili BLE HOGP report map, iskoristi ih da obnoviš stvarni field layout pre pisanja parsera.

## Automatizacija dekodiranja

- **ctf-usb-keyboard-parser** i dalje je koristan za brze CTF izazove i već se nalazi u repozitorijumu.
- **CTF-Usb_Keyboard_Parser** (`main.py`) nativno parsira i `pcap` i `pcapng` fajlove, razume `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, i ne zahteva tshark, pa dobro radi unutar izolovanih sandbox-eva.
- **USB-HID-decoders** dodaje vizuelizatore za tastaturu, miš i tablet. Možeš da pokreneš `extract_hid_data.sh` helper (tshark backend) ili `extract_hid_data.py` (scapy backend), a zatim da rezultujući text file proslediš decoderu ili replay modulima da posmatraš kako se keystrokes odvijaju.

### Stateful decoding je važan

USB interrupt captures obično sadrže i key press i jednu ili više ponovljenih kopija istog reporta pre nego što stigne release event. Praktičan decoder bi trebalo da:

- emituje samo novopritisnute keycode-ove u odnosu na prethodni report
- čuva modifier state (`Shift`, `Ctrl`, `AltGr`) iz byte 0 ili iz parsiranog `usbhid.boot_report.keyboard.modifier` polja
- prati toggle keys kao što je `Caps Lock`, jer uppercase output ne kontroliše samo Shift
- zapamti da su HID usage ID-jevi layout-agnostični: `0x1d` je fizička `z`/`y` key pozicija u zavisnosti od host keyboard layout-a

## Brzi Python decoder
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
Feed it with the plain hex lines dumped earlier to get an instant rough reconstruction without pulling a full parser into the environment. For non-US layouts this still reconstructs the physical key position, not necessarily the final glyph shown on the victim host.

## Troubleshooting tips

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- On Linux software captures, `usbmon` is the normal source; on Windows, Wireshark depends on the **USBPcap** extcap to see raw USB URBs at all.
- If the keyboard was attached through a hub or dock, confirm the interface descriptor first and then decode only that device/interface pair. Composite HID captures frequently mix keyboard and mouse reports.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
