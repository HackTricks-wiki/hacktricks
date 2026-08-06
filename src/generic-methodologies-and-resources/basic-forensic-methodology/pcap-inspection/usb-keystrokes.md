# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži komunikaciju putem USB-a sa tastature poput sledeće:

![USB Keystrokes: Ako imate pcap koji sadrži komunikaciju putem USB-a sa tastature poput sledeće](<../../../images/image (962).png>)

USB tastature obično koriste HID **boot protocol**, tako da je svaki interrupt transfer ka hostu dugačak samo 8 bajtova: jedan bajt modifikatorskih bitova (Ctrl/Shift/Alt/Super), jedan rezervisani bajt i do šest keycode-ova po izveštaju. Dekodiranje ovih bajtova dovoljno je za rekonstrukciju svega što je otkucano.

## Osnove USB HID izveštaja

Tipični IN izveštaj izgleda ovako:

| Bajt | Značenje |
| --- | --- |
| 0 | Bitmapa modifikatora (`0x02` = Left Shift, `0x20` = Right Alt itd.). Istovremeno može biti postavljeno više bitova. |
| 1 | Rezervisan/padding, ali ga gaming tastature često ponovo koriste za vendor podatke. |
| 2-7 | Do šest istovremenih keycode-ova u USB usage ID formatu (`0x04 = a`, `0x1E = 1`). `0x00` znači „nema tastera“. |

Tastature bez NKRO obično šalju `0x01` u bajtu 2 kada je pritisnuto više od šest tastera, kako bi signalizovale „rollover“. Razumevanje ovog rasporeda pomaže kada imate samo sirove `usb.capdata` bajtove.

## Izdvajanje HID podataka iz PCAP-a

### Najpre identifikujte interfejs tastature

Kod zauzetih capture-a, identifikujte HID tastaturu pre izlistavanja izveštaja. Pouzdana početna tačka je odgovor deskriptora interfejsa:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Pogledajte `usb.bInterfaceSubClass` i `usb.bInterfaceProtocol`:

- `subclass == 1` i `protocol == 1` obično označavaju boot keyboard
- `protocol == 2` obično označava miš
- `protocol == 0` često označava vendor-defined ili NKRO-style HID interfejs koji i dalje prenosi podatke sa tastature, ali ne u jednostavnom 8-byte boot rasporedu

Kada identifikujete interfejs, ograničite filtere na `usb.bus_id`, `usb.device_address` i, ako je moguće, `usb.interface_number` pre bilo kakvog exportovanja.

### Wireshark workflow

1. **Izolujte uređaj**: filtrirajte interrupt IN saobraćaj sa tastature, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Dodajte korisne kolone**: kliknite desnim tasterom na polje `Leftover Capture Data` (`usb.capdata`) i željena `usbhid.*` polja (npr. `usbhid.boot_report.keyboard.keycode_1`) da biste pratili pritiske tastera bez otvaranja svakog frame-a.
3. **Sakrijte prazne report-e**: primenite `!(usb.capdata == 00:00:00:00:00:00:00:00)` da biste uklonili idle frame-ove.
4. **Exportujte za post-processing**: `File -> Export Packet Dissections -> As CSV`, uključite `frame.number`, `usb.src`, `usb.capdata` i `usbhid.modifiers` kako biste kasnije mogli da skriptujete rekonstrukciju.

### Command-line workflow

`ctf-usb-keyboard-parser` već automatizuje klasični tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Na novijim snimcima možete zadržati i `usb.capdata` i bogatije polje `usbhid.data` grupisanjem po uređaju:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Te datoteke po uređaju mogu direktno da se proslede bilo kom decoder-u. Ako je snimak došao sa BLE tastatura tunelovanih preko GATT-a, filtrirajte po `btatt.value && frame.len == 20` i sačuvajte heksadecimalne payload-e pre dekodiranja.

### Kada report nije klasični 8-bajtni boot report

Novije gaming tastature, podeljene tastature i kompozitni HID uređaji često izlažu tastaturni interfejs koji nije boot interfejs, pa payload više ne odgovara formatu `modifier,reserved,key1..key6`.

- Dajte prednost `usbhid.data` u odnosu na `usb.capdata` kada je Wireshark već parsirao HID sloj.
- Ako svaki red počinje konstantnim prefiksom ili report ID-jem, uklonite ga pomoću decoder-a koji podržava offset, umesto da pretpostavite da je bajt 0 uvek modifier.
- Neki USBPcap export-i izostavljaju reserved bajt, pa decoder-i koji podržavaju `--no-reserved` ili prilagođeni offset štede vreme.
- Ako su HID report descriptor ili BLE HOGP report map prisutni u snimku, upotrebite ih da utvrdite stvarni raspored polja pre pisanja parser-a.

## Automatizacija dekodiranja

- **ctf-usb-keyboard-parser** je i dalje koristan za brze CTF izazove i već se nalazi u repository-ju.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) izvorno parsira i `pcap` i `pcapng` datoteke, podržava `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i ne zahteva tshark, pa dobro funkcioniše unutar izolovanih sandbox-a.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** dodaje vizualizatore za tastaturu, miš i tablet. Možete pokrenuti pomoćni alat `extract_hid_data.sh` (tshark backend) ili `extract_hid_data.py` (scapy backend), a zatim proslediti dobijenu tekstualnu datoteku decoder-u ili replay modulima da biste pratili kako se pritisci tastera pojavljuju.<sup>[[5]](#references)</sup>

### Stateful dekodiranje je važno

USB interrupt snimci obično sadrže i pritisak tastera i jednu ili više ponovljenih kopija istog report-a pre nego što stigne događaj otpuštanja. Praktičan decoder treba da:<sup>[[2]](#references)</sup>

- emituje samo novopritisnute keycode-ove u odnosu na prethodni report
- čuva stanje modifier-a (`Shift`, `Ctrl`, `AltGr`) iz bajta 0 ili parsiranog polja `usbhid.boot_report.keyboard.modifier`
- prati toggle tastere kao što je `Caps Lock`, jer se ispis velikih slova ne kontroliše samo pomoću Shift-a
- uzme u obzir da su HID usage ID-jevi nezavisni od rasporeda: `0x1d` predstavlja fizičku poziciju tastera `z`/`y`, u zavisnosti od rasporeda tastature hosta

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
Prosledite mu obične hex linije izbačene ranije da biste odmah dobili grubu rekonstrukciju, bez ubacivanja celog parser-a u okruženje. Za rasporede koji nisu US, ovo i dalje rekonstruiše fizičku poziciju tastera, ali ne nužno i konačni glyph prikazan na victim host-u.

## Saveti za rešavanje problema

- Ako Wireshark ne popuni polja `usbhid.*`, HID report descriptor verovatno nije uhvaćen. Ponovo priključite tastaturu tokom capture-a ili pređite na raw `usb.capdata`.
- Na Linux software capture-ima, `usbmon` je uobičajeni izvor; na Windows-u, Wireshark zavisi od **USBPcap** extcap-a da bi uopšte video raw USB URB-ove.<sup>[[1]](#references)</sup>
- Ako je tastatura povezana preko hub-a ili dock-a, prvo potvrdite interface descriptor, a zatim dekodirajte samo taj device/interface pair. Composite HID capture-i često mešaju izveštaje tastature i miša.
- Windows capture-i zahtevaju **USBPcap** extcap interface; proverite da li je sačuvan nakon Wireshark upgrade-a, jer nedostajući extcap-ovi ostavljaju prazne liste uređaja.<sup>[[1]](#references)</sup>
- Uvek proverite korelaciju `usb.bus_id:device:interface` (npr. `1.9.1`) pre bilo kakvog dekodiranja — mešanje više tastatura ili storage uređaja dovodi do besmislenih keystroke-ova.

## Reference

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
