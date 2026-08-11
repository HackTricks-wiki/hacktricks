# USB pritisci tastera

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži USB komunikaciju tastature, kao u sledećem primeru:

![USB pritisci tastera: Ako imate pcap koji sadrži USB komunikaciju tastature, kao u sledećem primeru](<../../../images/image (962).png>)

Kod tastature koja koristi HID **boot protocol**, svaki Interrupt IN report ima fiksni raspored od 8 bajtova: jedan bajt modifikatora, jedan rezervisani bajt i šest bajtova kodova tastera. Host upoređuje uzastopne report-ove i mapira kodove tastera na HID usage vrednosti kako bi rekonstruisao događaje pritiska tastera.<sup>[[8]](#references)</sup>

## Osnove USB HID report-a

Standardni boot keyboard input report strukturisan je na sledeći način.<sup>[[8]](#references)[[9]](#references)</sup>

| Bajt | Značenje |
| --- | --- |
| 0 | Bitmapa modifikatora (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt itd.). Istovremeno može biti postavljeno više bitova. |
| 1 | Rezervisani bajt; nekorišćeni report-ovi bi normalno trebalo da ga postave na nulu. OEM ili sistemski specifična upotreba nije prenosiva. |
| 2-7 | Do šest istovremenih kodova tastera u USB usage ID formatu (`0x04 = a`, `0x1E = 1`). `0x00` znači „nema tastera“. |

U boot rasporedu, usage ID `0x01` (`Keyboard ErrorRollOver`) prijavljuje se u svim slotovima za tastere kada je pritisnuto više od šest tastera koji nisu modifikatori; takođe može signalizirati neprepoznatljivu kombinaciju.<sup>[[8]](#references)[[9]](#references)</sup> Razumevanje ovog rasporeda je korisno kada imate samo sirove `usb.capdata` bajtove.

## Izdvajanje HID podataka iz PCAP-a

### Najpre identifikujte interfejs tastature

Kod zauzetih capture-a, najpre identifikujte HID tastaturu pre dumpovanja report-ova. Pouzdana početna tačka je odgovor deskriptora interfejsa:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID klasa definiše sledeće vrednosti interfejsa:<sup>[[8]](#references)</sup>

- `subclass == 1` je Boot Interface Subclass; sa `protocol == 1` identifikuje boot tastaturu
- `protocol == 2` identifikuje boot miša
- `protocol == 0` znači da nema boot protokola; pregledajte HID report descriptor umesto da pretpostavite raspored od 8 bajtova

Kada je interfejs poznat, ograničite filtere na `usb.bus_id`, `usb.device_address` i, ako je moguće, `usb.bInterfaceNumber` pre bilo kakvog eksportovanja.

### Wireshark workflow

1. **Izolujte uređaj**: filtrirajte interrupt IN saobraćaj sa tastature, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Dodajte korisne kolone**: kliknite desnim tasterom miša na polje `Leftover Capture Data` (`usb.capdata`) i željena `usbhid.*` polja (npr. `usbhid.boot_report.keyboard.keycode_1`) da biste pratili pritiske tastera bez otvaranja svakog frejma.<sup>[[11]](#references)</sup>
3. **Sakrijte prazne reportove**: primenite `!(usb.capdata == 00:00:00:00:00:00:00:00)` da biste uklonili idle frejmove.
4. **Eksportujte za naknadnu obradu**: `File -> Export Packet Dissections -> As CSV`, uključujući `frame.number`, `usb.src`, `usb.capdata` i dekodirana modifier polja kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`, kako biste kasnije mogli da skriptujete rekonstrukciju.<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

Klasični obrazac ekstrakcije — ispisivanje `usb.capdata`, uklanjanje idle reportova i mapiranje usage ID-jeva — pojavljuje se u originalnoj analizi iz 2017. godine i njenom vodiču.<sup>[[1]](#references)[[2]](#references)</sup>

Repository `ctf-usb-keyboard-parser` automatizuje klasični tshark + sed pipeline:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Kod novijih snimaka, prednost dajte Wireshark-ovom dekodiranom polju `usbhid.data`, a ako nije dostupno, koristite `usb.capdata`; upišite jedan payload po report-u u datoteku za svaki uređaj:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Ti fajlovi za svaki uređaj mogu se proslediti dekoderu nakon normalizovanja hex formata koji on očekuje. Ako je snimak došao sa BLE tastatura tunelovanih preko GATT-a, filtrirajte pomoću `btatt.value && frame.len == 20` i izvezite hex payload-e pre dekodiranja.<sup>[[7]](#references)</sup>

### Kada izveštaj nije klasični 8-bajtni boot izveštaj

Ne-boot interfejs ili ID izveštaja može promeniti raspored payload-a, zato nemojte pretpostaviti da svaki izveštaj tastature odgovara formatu `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Dajte prednost polju `usbhid.data` u odnosu na `usb.capdata` kada je Wireshark već raščlanio HID sloj.
- Ako svaki red počinje konstantnim prefiksom ili ID-jem izveštaja, uklonite ga pomoću dekodera koji uzima u obzir offset, umesto da pretpostavite da je bajt 0 uvek modifier.<sup>[[7]](#references)</sup>
- Neki USBPcap exporti izostavljaju reserved bajt, pa dekoderi koji podržavaju `--no-reserved` ili prilagođeni offset štede vreme.<sup>[[7]](#references)</sup>
- Ako su HID report descriptor ili BLE HOGP report map prisutni u snimku, upotrebite ih da utvrdite stvarni raspored polja pre pisanja parsera.

## Automatizacija dekodiranja

- **ctf-usb-keyboard-parser** je i dalje praktičan za brze CTF izazove i već se nalazi u repository-ju.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) izvorno parsira i `pcap` i `pcapng` fajlove, podržava `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i ne zahteva tshark niti drugu eksternu zavisnost, pa je pogodan za izolovane sandbox-e.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** dodaje vizualizatore za tastaturu, miš i tablet. Možete pokrenuti pomoćni alat `extract_hid_data.sh` (tshark backend) ili `extract_hid_data.py` (scapy backend), a zatim proslediti dobijeni tekstualni fajl dekoderu ili replay modulima da biste pratili kako se pritisci tastera pojavljuju.<sup>[[7]](#references)</sup>

### Stateful dekodiranje je važno

USB boot tastature šalju izveštaje brzinom mirovanja čak i kada nema novog događaja pritiska tastera, pa snimci mogu sadržati ponovljene izveštaje pre događaja otpuštanja tastera. Praktičan dekoder treba da:<sup>[[3]](#references)[[8]](#references)</sup>

- emituje samo novopritisnute keycode-ove u odnosu na prethodni izveštaj
- čuva stanje modifier-a (`Shift`, `Ctrl`, `AltGr`) iz bajta 0 ili raščlanjenih polja kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`
- prati toggle tastere kao što je `Caps Lock`, jer izlaz velikih slova ne kontroliše samo Shift
- ima na umu da su HID usage ID-jevi nezavisni od rasporeda: `0x1d` predstavlja fizičku poziciju tastera `z`/`y`, u zavisnosti od rasporeda tastature na hostu.<sup>[[9]](#references)</sup>

## Brzi Python dekoder
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
Napajajte ga običnim hex linijama prethodno izbačenim u dump da biste odmah dobili grubu rekonstrukciju, bez ubacivanja kompletnog parsera u environment. Za ne-US rasporede ovo i dalje rekonstruiše fizičku poziciju tastera, ali ne nužno i konačni glyph prikazan na victim hostu.

## Saveti za rešavanje problema

- Ako Wireshark ne popunjava polja `usbhid.*`, descriptor HID report-a verovatno nije uhvaćen. Ponovo priključite tastaturu tokom capture-a ili pređite na raw `usb.capdata`.
- Na Linux software capture-ima, `usbmon` je uobičajen source; na Windows-u, Wireshark zavisi od **USBPcap** extcap-a da bi uopšte video raw USB URB-ove.<sup>[[4]](#references)</sup>
- Ako je tastatura povezana preko hub-a ili dock-a, prvo potvrdite interface descriptor, a zatim dekodirajte samo taj par device/interface. Composite HID capture-i često mešaju report-e tastature i miša.
- Windows capture-i zahtevaju **USBPcap** extcap interface; proverite da li je ostao nakon Wireshark upgrade-a, jer nedostajući extcap-ovi ostavljaju prazne liste uređaja.<sup>[[4]](#references)</sup>
- Uvek povežite tuple bus-a, device-a i interface-a (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; npr. `1.9.1`) pre dekodiranja bilo čega — mešanje više tastatura ili storage uređaja dovodi do besmislenih keystroke-ova.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analiza capture-a paketa USB tastature](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Podešavanje Wireshark USB capture-a](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definicija klase uređaja za Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
