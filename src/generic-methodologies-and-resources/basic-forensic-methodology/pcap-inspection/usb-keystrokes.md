# USB pritisci tastera

Ako imate pcap koji sadrži USB komunikaciju tastature, kao u sledećem primeru:

![USB pritisci tastera: Ako imate pcap koji sadrži USB komunikaciju tastature, kao u sledećem primeru](<../../../images/image (962).png>)

Kod tastature koja koristi HID **boot protocol**, svaki Interrupt IN izveštaj ima fiksnu strukturu od 8 bajtova: jedan bajt modifikatora, jedan rezervisani bajt i šest bajtova kodova tastera. Host upoređuje uzastopne izveštaje i mapira kodove tastera na HID upotrebe kako bi rekonstruisao događaje tastera.<sup>[[8]](#references)</sup>

## Osnove USB HID izveštaja

Standardni boot keyboard input report strukturisan je na sledeći način.<sup>[[8]](#references)[[9]](#references)</sup>

| Bajt | Značenje |
| --- | --- |
| 0 | Bitmapa modifikatora (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt itd.). Više bitova može biti postavljeno istovremeno. |
| 1 | Rezervisani bajt; izveštaji koji ga ne koriste trebalo bi uobičajeno da ga postave na nulu. OEM ili upotreba specifična za sistem nije prenosiva. |
| 2-7 | Do šest istovremenih kodova tastera u formatu USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` znači "no key". |

U boot layout-u, usage ID `0x01` (`Keyboard ErrorRollOver`) prijavljuje se u svim slotovima za tastere kada je pritisnuto više od šest tastera koji nisu modifikatori; takođe može označavati neprepoznatljivu kombinaciju.<sup>[[8]](#references)[[9]](#references)</sup> Razumevanje ove strukture je korisno kada imate samo sirove `usb.capdata` bajtove.

## Izdvajanje HID podataka iz PCAP-a

### Najpre identifikujte interfejs tastature

Kod zauzetih capture-a, identifikujte HID tastaturu pre izbacivanja izveštaja. Pouzdana početna tačka je odgovor deskriptora interfejsa:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Klasa HID definiše sledeće vrednosti interfejsa:<sup>[[8]](#references)</sup>

- `subclass == 1` je Boot Interface Subclass; sa `protocol == 1` identifikuje boot keyboard
- `protocol == 2` identifikuje boot mouse
- `protocol == 0` znači da nema boot protocol-a; umesto pretpostavke o rasporedu od 8 bajtova, pregledajte HID report descriptor

Kada je interfejs poznat, ograničite filtere na `usb.bus_id`, `usb.device_address` i, ako je moguće, `usb.bInterfaceNumber` pre bilo kakvog izvoza.

### Tok rada u Wireshark-u

1. **Izolujte uređaj**: filtrirajte interrupt IN saobraćaj sa tastature, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Dodajte korisne kolone**: kliknite desnim tasterom miša na polje `Leftover Capture Data` (`usb.capdata`) i željena `usbhid.*` polja (npr. `usbhid.boot_report.keyboard.keycode_1`) da biste pratili pritiske tastera bez otvaranja svakog frame-a.<sup>[[11]](#references)</sup>
3. **Sakrijte prazne report-e**: primenite `!(usb.capdata == 00:00:00:00:00:00:00:00)` da biste uklonili idle frame-ove.
4. **Izvezite podatke za naknadnu obradu**: `File -> Export Packet Dissections -> As CSV`, uključujući `frame.number`, `usb.src`, `usb.capdata` i dekodirana polja modifikatora, kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`, kako biste kasnije skriptom rekonstruisali unos.<sup>[[10]](#references)[[11]](#references)</sup>

### Tok rada iz komandne linije

Klasični obrazac ekstrakcije — ispisivanje `usb.capdata`, uklanjanje idle report-a i mapiranje usage ID-jeva — pojavljuje se u originalnoj analizi iz 2017. godine i njenom vodiču.<sup>[[1]](#references)[[2]](#references)</sup>

Repository `ctf-usb-keyboard-parser` automatizuje klasični tshark + sed pipeline:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Kod novijih snimanja, prednost dajte Wireshark-ovom dekodiranom polju `usbhid.data`, a ako nije dostupno, koristite `usb.capdata`; upišite jedan payload po report-u u datoteku za svaki uređaj:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Te datoteke po uređajima mogu se proslediti decoder-u nakon normalizacije hex formata koji očekuje. Ako je capture potekao sa BLE keyboards tunelovanih preko GATT-a, filtrirajte pomoću `btatt.value && frame.len == 20` i izvezite hex payload-e pre decoding-a.<sup>[[7]](#references)</sup>

### Kada report nije klasični 8-byte boot report

Non-boot interface ili report ID mogu promeniti raspored payload-a, zato nemojte pretpostavljati da svaki keyboard report odgovara formatu `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Dajte prednost polju `usbhid.data` u odnosu na `usb.capdata` kada je Wireshark već parsirao HID layer.
- Ako svaki red počinje konstantnim prefix-om ili report ID-jem, uklonite ga pomoću offset-aware decoder-a umesto pretpostavke da je byte 0 uvek modifier.<sup>[[7]](#references)</sup>
- Neki USBPcap export-i izostavljaju reserved byte, pa decoder-i koji podržavaju `--no-reserved` ili custom offset štede vreme.<sup>[[7]](#references)</sup>
- Ako su HID report descriptor ili BLE HOGP report map prisutni u capture-u, koristite ih da utvrdite stvarni raspored polja pre pisanja parser-a.

## Automatizacija decoding-a

- **ctf-usb-keyboard-parser** je i dalje praktičan za brze CTF challenges i već se nalazi u repository-ju.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) nativno parsira i `pcap` i `pcapng` fajlove, podržava `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i ne zahteva tshark niti drugu eksternu dependency, zbog čega je pogodan za izolovane sandbox-e.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** dodaje visualizer-e za keyboard, mouse i tablet. Možete pokrenuti helper `extract_hid_data.sh` (tshark backend) ili `extract_hid_data.py` (scapy backend), a zatim proslediti dobijeni text file decoder-u ili replay modulima da biste pratili kako se keystrokes pojavljuju.<sup>[[7]](#references)</sup>

### Stateful decoding je važan

USB boot keyboards šalju report-e u idle rate-u čak i kada nema novog key event-a, pa capture-i mogu sadržati ponovljene report-e pre event-a otpuštanja tastera. Praktičan decoder treba da:<sup>[[3]](#references)[[8]](#references)</sup>

- emituje samo novo pritisnute keycode-ove u odnosu na prethodni report
- čuva stanje modifier-a (`Shift`, `Ctrl`, `AltGr`) iz byte 0 ili parsiranih polja kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`
- prati toggle tastere kao što je `Caps Lock`, jer izlaz velikih slova ne kontroliše samo Shift
- ima na umu da su HID usage ID-jevi nezavisni od layout-a: `0x1d` predstavlja fizičku poziciju tastera `z`/`y`, u zavisnosti od layout-a keyboard-a hosta.<sup>[[9]](#references)</sup>

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
Prosledite mu obične hex linije prethodno izbačene da biste dobili trenutnu grubu rekonstrukciju bez ubacivanja kompletnog parsera u okruženje. Za rasporede koji nisu US, ovo i dalje rekonstruiše fizičku poziciju tastera, a ne nužno konačni znak prikazan na hostu žrtve.

## Saveti za rešavanje problema

- Ako Wireshark ne popuni polja `usbhid.*`, descriptor HID report-a verovatno nije uhvaćen. Ponovo priključite tastaturu tokom snimanja ili pređite na sirovi `usb.capdata`.
- Na Linux software snimcima, `usbmon` je uobičajeni izvor; na Windows-u, Wireshark zavisi od **USBPcap** extcap-a da bi uopšte video sirove USB URB-ove.<sup>[[4]](#references)</sup>
- Ako je tastatura bila povezana preko hub-a ili dock-a, prvo potvrdite interface descriptor, a zatim dekodirajte samo taj par uređaja/interface-a. Composite HID snimci često mešaju izveštaje tastature i miša.
- Windows snimci zahtevaju **USBPcap** extcap interface; proverite da li je opstao nakon Wireshark nadogradnji, jer nedostajući extcap-ovi ostavljaju prazne liste uređaja.<sup>[[4]](#references)</sup>
- Uvek povežite tuple bus-a, uređaja i interface-a (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; npr. `1.9.1`) pre bilo kakvog dekodiranja — mešanje više tastatura ili storage uređaja dovodi do besmislenih pritisaka tastera.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analiza snimka paketa USB tastature](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Podešavanje USB snimanja u Wireshark-u](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definicija klase uređaja za Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
