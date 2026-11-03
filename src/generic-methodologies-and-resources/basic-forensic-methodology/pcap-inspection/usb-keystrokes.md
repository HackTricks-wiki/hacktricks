# Pritisci tastera preko USB-a

{{#include ../../../banners/hacktricks-training.md}}

Ako imate pcap koji sadrži komunikaciju preko USB-a tastature poput sledeće:

![Pritisci tastera preko USB-a: Ako imate pcap koji sadrži komunikaciju preko USB-a tastature poput sledeće](<../../../images/image (962).png>)

Kod tastature koja koristi HID **boot protokol**, svaki Interrupt IN izveštaj ima fiksni raspored od 8 bajtova: jedan bajt za modifikatore, jedan rezervisani bajt i šest bajtova za kodove tastera. Host upoređuje uzastopne izveštaje i mapira kodove tastera na HID upotrebe kako bi rekonstruisao događaje tastera.<sup>[[8]](#references)</sup>

Za opštu početnu analizu capture-a pogledajte [Pcap Inspection](./).

## Osnove USB HID izveštaja

Standardni ulazni izveštaj boot tastature strukturiran je na sledeći način.<sup>[[8]](#references)[[9]](#references)</sup>

| Bajt | Značenje |
| --- | --- |
| 0 | Bitmaska modifikatora (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt itd.). Istovremeno može biti postavljeno više bitova. |
| 1 | Rezervisani bajt; u neupotrebljenim izveštajima bi obično trebalo da bude postavljen na nulu. Upotreba specifična za OEM ili sistem nije prenosiva. |
| 2-7 | Do šest istovremeno pritisnutih kodova tastera u formatu USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` znači „nijedan taster“. | 

U boot rasporedu, usage ID `0x01` (`Keyboard ErrorRollOver`) se prijavljuje u svim slotovima za tastere kada se pritisne više od šest tastera koji nisu modifikatori; može ukazivati i na kombinaciju koja ne može da se prepozna.<sup>[[8]](#references)[[9]](#references)</sup> Razumevanje ovog rasporeda pomaže kada imate samo sirove bajtove `usb.capdata`.

## Izdvajanje HID podataka iz PCAP-a

### Najpre identifikujte interfejs tastature

U capture-ima sa mnogo saobraćaja, identifikujte HID tastaturu pre nego što izdvojite izveštaje. Pouzdana početna tačka je odgovor deskriptora interfejsa:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID klasa definiše sledeće vrednosti interfejsa:<sup>[[8]](#references)</sup>

- `subclass == 1` je podklasa Boot interfejsa; uz `protocol == 1` označava boot tastaturu
- `protocol == 2` označava boot miš
- `protocol == 0` znači da nema boot protokola; pregledajte HID deskriptor izveštaja umesto da pretpostavite raspored od 8 bajtova

Interfejs koji podržava boot režim **ne dokazuje da je boot protokol aktivan**. HID uređaji se inicijalizuju u report protokolu. Host bira boot režim pomoću `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` bira report protokol. Ako snimak sadrži enumeraciju, proverite zahtev za interfejs tastature (`wIndex`) pre nego što upotrebite boot dekoder od osam bajtova. Ako zahtev nedostaje, proverite uočeni raspored izveštaja umesto da zaključujete o režimu na osnovu deskriptora interfejsa.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Kada utvrdite interfejs, podesite filtere za `usb.bus_id`, `usb.device_address` i, ako je moguće, `usb.bInterfaceNumber` pre izvoza.

### Wireshark tok rada

1. **Izolujte uređaj**: filtrirajte interrupt IN saobraćaj sa tastature, npr. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Dodajte korisne kolone**: kliknite desnim tasterom na polje `Leftover Capture Data` (`usb.capdata`) i željena polja `usbhid.*` (npr. `usbhid.boot_report.keyboard.keycode_1`) da biste pratili pritiske tastera bez otvaranja svakog frejma.<sup>[[11]](#references)</sup>
3. **Sakrijte prazne izveštaje**: primenite `!(usb.capdata == 00:00:00:00:00:00:00:00)` da biste izbacili neaktivne frejmove.
4. **Izvezite podatke za naknadnu obradu**: izaberite `File -> Export Packet Dissections -> As CSV`, uključite `frame.number`, `usb.src`, `usb.capdata` i dekodirana polja modifikatora, kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`, kako biste kasnije skriptom rekonstruisali unos.<sup>[[10]](#references)[[11]](#references)</sup>

### Tok rada iz komandne linije

Klasični obrazac izdvajanja — ispisivanje `usb.capdata`, izbacivanje neaktivnih izveštaja i mapiranje ID-jeva upotrebe — pojavljuje se u originalnoj analizi iz 2017. i njenom vodiču.<sup>[[1]](#references)[[2]](#references)</sup>

Repozitorijum `ctf-usb-keyboard-parser` automatizuje klasični tshark + sed cevovod:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

U novijim snimcima, prednost dajte Wiresharkovom dekodiranom polju `usbhid.data`, a ako ono nije dostupno, koristite `usb.capdata`; upišite jedan payload po izveštaju u datoteku za svaki uređaj:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Te datoteke za svaki uređaj mogu se proslediti dekoderu nakon normalizacije heksadecimalnog formata koji očekuje. Ako je snimak napravljen sa BLE tastatura tunelovanih preko GATT-a, filtrirajte po `btatt.value && frame.len == 20` i izdvojite heksadecimalne payload-e pre dekodiranja.<sup>[[7]](#references)</sup>

### Kada izveštaj nije klasični 8-bajtni boot report

Interfejs koji nije boot interfejs ili ID izveštaja mogu da promene raspored payloada, zato nemojte pretpostavljati da svaki izveštaj tastature odgovara formatu `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Prednost dajte polju `usbhid.data` u odnosu na `usb.capdata` kada je Wireshark već raščlanio HID sloj.
- Ako svaki red počinje konstantnim prefiksom ili ID-jem izveštaja, uklonite ga dekoderom koji uzima u obzir pomeraj, umesto da pretpostavite da je bajt 0 uvek modifikator.<sup>[[7]](#references)</sup>
- Neki USBPcap izvozi izostavljaju rezervisani bajt, pa dekoderi koji podržavaju `--no-reserved` ili prilagođeni pomeraj štede vreme.<sup>[[7]](#references)</sup>
- Ako su deskriptor HID izveštaja ili mapa izveštaja BLE HOGP prisutni u snimku, iskoristite ih da utvrdite stvarni raspored polja pre pisanja parsera.

### Dekodirajte bitmapu tastera u report-protocol formatu

Za tastaturu čiji je ulazni izveštaj bitmapa, a ne šest boot slotova za tastere, pronađite njen **deskriptor HID izveštaja** u saobraćaju tokom enumeracije. Ovaj filter pronalazi frejmove u kojima je Wireshark dekodirao stavku Report Size; otvorite jedan od njih i pregledajte ceo deskriptor. Započnite novo snimanje pre nego što priključite tastaturu ako deskriptor nedostaje.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Za svaki keyboard Input izveštaj zabeležite njegov `Report ID` (ako postoji), `Usage Page` (`0x07` za tastere tastature), `Usage Minimum/Maximum`, `Report Size`, `Report Count` i da li je svaka stavka `Input` tipa **Variable** ili **Array**. Prebrojite sva prethodna Input polja i konstantne dopunske bitove da biste pronašli bitni pomak polja tastera; polja izveštaja ne moraju biti poravnata po bajtovima. Jednobitno polje tipa Variable sa uzastopnim upotrebama tastature predstavlja bitmapu stanja tastera: bit 0 tog polja odgovara prvoj deklarisanoj upotrebi, bit 1 sledećoj, i tako dalje. Nasuprot tome, Array sadrži vrednosti koje se tumače preko opsega upotreba iz deskriptora, a ne po jedan pritisnuti taster za svaki bit. Ako je deklarisan `Report ID`, prvo izdvojite izveštaje sa tim prefiksom, a zatim zanemarite njegov bajt prilikom izračunavanja pomaka polja. Uporedite skupove zadržanih upotreba između uzastopnih izveštaja istог интерфејса и `Report ID`-ja da biste izdvojili samo nove pritiske.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Automatizacija dekodiranja

- **ctf-usb-keyboard-parser** je i dalje praktičan za brze CTF izazove i već je dostupan u repozitorijumu.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) izvorno parsira i `pcap` i `pcapng` datoteke, podržava `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` i ne zahteva tshark niti neku drugu spoljnu zavisnost, pa je pogodan za izolovana okruženja.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** dodaje vizualizatore za tastaturu, miš i tablet. Možete pokrenuti pomoćnu skriptu `extract_hid_data.sh` (pozadinski mehanizam tshark) ili `extract_hid_data.py` (pozadinski mehanizam scapy), pa zatim proslediti dobijenu tekstualnu datoteku dekoderu ili modulima za reprodukciju i pratiti kako se pritisci tastera odvijaju.<sup>[[7]](#references)</sup>

### Važno je dekodiranje sa očuvanjem stanja

USB boot tastature šalju izveštaje u intervalu mirovanja čak i kada nema novog događaja tastera, pa hvatanje saobraćaja može sadržati ponovljene izveštaje pre događaja otpuštanja tastera. Praktičan dekoder treba da:<sup>[[3]](#references)[[8]](#references)</sup>

- emituje samo novopritisnute kodove tastera u odnosu na prethodni izveštaj
- čuva stanje modifikatora (`Shift`, `Ctrl`, `AltGr`) iz bajta 0 ili parsiranih polja kao što su `usbhid.boot_report.keyboard.modifier.left_shift` i `usbhid.boot_report.keyboard.modifier.right_alt`
- prati prekidačke tastere kao što je `Caps Lock`, jer izlaz velikih slova ne zavisi samo od tastera Shift
- uzima u obzir da su HID ID-jevi upotreba nezavisni od rasporeda: `0x1d` predstavlja fizički položaj tastera `z`/`y`, u zavisnosti od rasporeda tastature na računaru.<sup>[[9]](#references)</sup>

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

Prosledite mu obične hex linije iz prethodnog ispisa da biste odmah dobili grubu rekonstrukciju, bez potrebe da u okruženje dodajete pun parser. Kod rasporeda tastature koji nisu američki, ovim se i dalje rekonstruiše fizički položaj tastera, ali ne nužno i konačni znak prikazan na hostu žrtve.

## Saveti za rešavanje problema

- Ako Wireshark ne popunjava polja `usbhid.*`, verovatno nije uhvaćen HID deskriptor izveštaja. Ponovo priključite tastaturu tokom snimanja ili koristite sirovi `usb.capdata`.
- Kod softverskog snimanja na Linuxu, uobičajeni izvor je `usbmon`; na Windowsu, Wireshark zavisi od extcap-a **USBPcap** da bi uopšte mogao da vidi sirove USB URB-ove.<sup>[[4]](#references)</sup>
- Ako je tastatura povezana preko huba ili dock-a, prvo proverite deskriptor interfejsa, a zatim dekodirajte samo taj par uređaja i interfejsa. U snimcima kompozitnog HID-a često su pomešani izveštaji tastature i miša.
- Za snimanje na Windowsu potreban je extcap interfejs **USBPcap**; proverite da li je ostao dostupan posle nadogradnje Wireshark-a, jer nedostajući extcap-ovi ostavljaju prazne liste uređaja.<sup>[[4]](#references)</sup>
- Uvek proverite kombinaciju magistrale, uređaja i interfejsa (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; npr. `1.9.1`) pre dekodiranja bilo čega — mešanje više tastatura ili uređaja za skladištenje podataka dovodi do besmislenih pritisaka tastera.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Analiza snimka paketa USB tastature](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Podešavanje USB snimanja u Wireshark-u](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Definicija klase uređaja za uređaje za ljudski interfejs (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID tabele upotrebe 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux kernel: Uvod u HID deskriptore izveštaja](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboard writeup](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
