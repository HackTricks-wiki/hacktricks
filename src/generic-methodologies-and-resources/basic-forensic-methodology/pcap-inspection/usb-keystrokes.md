# USB-sleuteldrukke

{{#include ../../../banners/hacktricks-training.md}}

As jy ’n pcap het wat die kommunikasie via USB van ’n sleutelbord soos die volgende een bevat:

![USB-sleuteldrukke: As jy ’n pcap het wat die kommunikasie via USB van ’n sleutelbord soos die volgende een bevat](<../../../images/image (962).png>)

Vir ’n sleutelbord wat die HID **boot protocol** gebruik, het elke Interrupt IN-verslag ’n vaste uitleg van 8 grepe: een wysiger-greep, een gereserveerde greep en ses sleutelkodegrepe. Die gasheer vergelyk opeenvolgende verslae en karteer sleutelkodes na HID-gebruike om sleutelgebeurtenisse te rekonstrueer.<sup>[[8]](#references)</sup>

Vir algemene pcap-aanvanklike ontleding, sien [Pcap-inspeksie](./).

## Basiese beginsels van USB HID-verslae

Die standaardinvoerverslag vir ’n boot-sleutelbord is soos volg gestruktureer.<sup>[[8]](#references)[[9]](#references)</sup>

| Greep | Betekenis |
| --- | --- |
| 0 | Wysiger-bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, ens.). Verskeie bisse kan gelyktydig gestel wees. |
| 1 | Gereserveerde greep; ongebruikte verslae behoort dit gewoonlik op nul te stel. OEM- of stelselspesifieke gebruik is nie draagbaar nie. |
| 2-7 | Tot ses gelyktydige sleutelkodes in USB-gebruik-ID-formaat (`0x04 = a`, `0x1E = 1`). `0x00` beteken "geen sleutel". | 

In die boot-uitleg word gebruik-ID `0x01` (`Keyboard ErrorRollOver`) in al die sleutelgleuwe gerapporteer wanneer meer as ses nie-wysigersleutels gedruk word; dit kan ook ’n onherkenbare kombinasie aandui.<sup>[[8]](#references)[[9]](#references)</sup> As jy net die rou `usb.capdata`-grepe het, help dit om hierdie uitleg te verstaan.

## Onttrekking van HID-data uit ’n PCAP

### Identifiseer eers die sleutelbordkoppelvlak

Identifiseer die HID-sleutelbord voordat jy enige verslae uit ’n besige opname aflaai. ’n Betroubare beginpunt is die koppelvlakbeskrywerantwoord:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Die HID-klas definieer hierdie koppelvlakwaardes:<sup>[[8]](#references)</sup>

- `subclass == 1` is die Boot Interface Subclass; met `protocol == 1` identifiseer dit ’n boot-keyboard
- `protocol == 2` identifiseer ’n boot-muis
- `protocol == 0` beteken geen boot-protokol nie; inspekteer eerder die HID report descriptor as om ’n 8-greep-uitleg te aanvaar

’n Boot-bekwame koppelvlak is **nie bewys dat boot-protokol aktief is nie**. HID-toestelle inisialiseer in report-protokol. Die host kies boot-modus met `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` kies report-protokol. As die opname enumerasie bevat, kyk na die versoek vir die keyboard-koppelvlak (`wIndex`) voordat jy ’n agt-greep-boot-decoder gebruik. As dit ontbreek, verifieer eerder die waargenome report-uitleg as om die modus uit die koppelvlakbeskrywing af te lei.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Sodra die koppelvlak bekend is, beperk jou filters tot `usb.bus_id`, `usb.device_address` en, indien moontlik, `usb.bInterfaceNumber` voordat jy enigiets uitvoer.

### Wireshark-werkvloei

1. **Isoleer die toestel**: filter vir interrupt IN-verkeer vanaf die sleutelbord, bv. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Voeg nuttige kolomme by**: regskliek op die `Leftover Capture Data`-veld (`usb.capdata`) en jou voorkeur-`usbhid.*`-velde (bv. `usbhid.boot_report.keyboard.keycode_1`) om toetsaanslae te volg sonder om elke raam oop te maak.<sup>[[11]](#references)</sup>
3. **Versteek leë verslae**: pas `!(usb.capdata == 00:00:00:00:00:00:00:00)` toe om onaktiewe rame te verwyder.
4. **Voer uit vir naverwerking**: `File -> Export Packet Dissections -> As CSV`; sluit `frame.number`, `usb.src`, `usb.capdata` en gedekodeerde wysiger-velde soos `usbhid.boot_report.keyboard.modifier.left_shift` en `usbhid.boot_report.keyboard.modifier.right_alt` in om die rekonstruksie later te skrip.<sup>[[10]](#references)[[11]](#references)</sup>

### Opdragreël-werkvloei

Die klassieke onttrekkingspatroon—dump `usb.capdata`, verwyder onaktiewe verslae en koppel gebruiks-ID's—verskyn in die oorspronklike ontleding van 2017 en die deurbraak daarvan.<sup>[[1]](#references)[[2]](#references)</sup>

Die `ctf-usb-keyboard-parser`-bewaarplek outomatiseer die klassieke tshark + sed-pyplyn:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Op nuwer opnames, verkies Wireshark se gedekodeerde `usbhid.data`-veld en gebruik `usb.capdata` as terugval; skryf een loonvrag per verslag na ’n lêer per toestel:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Daardie lêers per toestel kan aan ’n decoder gevoer word nadat die heksformaat genormaliseer is soos die decoder dit verwag. As die capture afkomstig is van BLE-sleutelborde wat oor GATT getonnel word, filter op `btatt.value && frame.len == 20` en stoor die heks-payloads voordat jy dit decodeer.<sup>[[7]](#references)</sup>

### Wanneer die report nie die klassieke 8-grepe-bootreport is nie

’n Nie-boot-koppelvlak of ’n report-ID kan die payload-uitleg verander, dus moet jy nie aanvaar dat elke sleutelbordreport ooreenstem met `modifier,reserved,key1..key6` nie.<sup>[[8]](#references)[[11]](#references)</sup>

- Verkies `usbhid.data` bo `usb.capdata` wanneer Wireshark reeds die HID-laag ontleed het.
- As elke reël met ’n konstante voorvoegsel of report-ID begin, verwyder dit met ’n decoder wat die offset in ag neem, eerder as om aan te neem dat greep 0 altyd die modifier is.<sup>[[7]](#references)</sup>
- Sommige USBPcap-uitvoere laat die gereserveerde greep weg, dus bespaar decoders wat `--no-reserved` of ’n pasgemaakte offset ondersteun tyd.<sup>[[7]](#references)</sup>
- As die HID-reportdescriptor of BLE HOGP-reportmap in die capture voorkom, gebruik dit om die werklike velduitleg vas te stel voordat jy ’n parser skryf.

### Decodeer ’n sleutelbordinvoer se bitmap in report-protokol

Vir ’n sleutelbord waarvan die invoerreport ’n bitmap is eerder as ses boot-sleutelgleuwe, soek die **HID-reportdescriptor** in die enumerasieverkeer. Hierdie filter vind rame waarin Wireshark ’n Report Size-item gedecodeer het; maak een oop en ondersoek die volledige descriptor. Begin ’n nuwe capture voordat jy die sleutelbord inprop as die descriptor ontbreek.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Vir elke sleutelbord-Input-verslag, teken die `Report ID` (indien enige), `Usage Page` (`0x07` vir sleutelbordtoetse), `Usage Minimum/Maximum`, `Report Size`, `Report Count` en of elke `Input`-item **Variable** of **Array** is aan. Tel alle voorafgaande Input-velde en konstante opvulling om die sleutelveld se bit-offset te bepaal; verslagvelde hoef nie op greepgrense te val nie. ’n Eenbis-Variable-veld met opeenvolgende sleutelbord-usages is ’n sleutelstatus-bitmap: bit 0 van daardie veld stem ooreen met die eerste gedeclareerde usage, bit 1 met die volgende, ensovoorts. ’n Array bevat daarenteen waardes wat volgens die descriptor se usage-reeks opgelos word, nie een ingedrukte sleutel per bit nie. As ’n `Report ID` gedeclareer is, kies eers verslae met daardie voorvoegsel en slaan die byte daarvan oor wanneer jy veld-offsets bereken. Vergelyk stelle van ingedrukte usages tussen opeenvolgende verslae van dieselfde koppelvlak en `Report ID` om slegs nuwe drukke uit te voer.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Outomatisering van dekodering

- **ctf-usb-keyboard-parser** is steeds handig vir vinnige CTF-uitdagings en is reeds in die repository ingesluit.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) ontleed beide `pcap`- en `pcapng`-lêers direk, verstaan `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` en vereis nie tshark of ’n ander eksterne afhanklikheid nie, dus is dit geskik vir geïsoleerde sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** voeg visualiseerders vir sleutelborde, muise en tablette by. Jy kan óf die `extract_hid_data.sh`-helper (tshark-backend) óf `extract_hid_data.py` (scapy-backend) uitvoer en dan die resulterende tekslêer aan die decoder- of replay-modules voer om te sien hoe die toetsaanslae ontvou.<sup>[[7]](#references)</sup>

### Toestandbewuste dekodering is belangrik

USB-boot-sleutelborde stuur verslae teen die luitydtempo, selfs wanneer daar geen nuwe sleutelgebeurtenis is nie; daarom kan opnames herhaalde verslae bevat voordat die loslaatgebeurtenis plaasvind. ’n Praktiese decoder behoort:<sup>[[3]](#references)[[8]](#references)</sup>

- slegs nuut ingedrukte sleutelko de uit te voer in vergelyking met die vorige verslag
- wysigerstatus (`Shift`, `Ctrl`, `AltGr`) vanaf byte 0 of ontlede velde soos `usbhid.boot_report.keyboard.modifier.left_shift` en `usbhid.boot_report.keyboard.modifier.right_alt` by te hou
- wisseltoetse soos `Caps Lock` na te spoor, omdat hoofletters nie net deur Shift beheer word nie
- te onthou dat HID-usage-ID’s uitleg-onafhanklik is: `0x1d` is die fisiese `z`-/`y`-sleutelposisie, afhangend van die gasheersleutelborduitleg.<sup>[[9]](#references)</sup>

## Vinnige Python-dekodeerder

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

Voer dit met die gewone heksadesimale reëls wat vroeër uitgevoer is om onmiddellik ’n rowwe rekonstruksie te kry, sonder om ’n volledige parser in die omgewing in te bring. Vir nie-Amerikaanse sleutelborduitlegte rekonstrueer dit steeds die fisiese sleutelposisie, nie noodwendig die finale glyph wat op die slagoffer se gasheer vertoon word nie.

## Wenke vir probleemoplossing

- As Wireshark nie `usbhid.*`-velde invul nie, is die HID-verslagbeskrywer waarskynlik nie vasgelê nie. Ontkoppel en koppel die sleutelbord weer aan terwyl jy vaslê, of gebruik rou `usb.capdata` as alternatief.
- Op Linux-sagtewarevasleggings is `usbmon` die gewone bron; op Windows maak Wireshark staat op die **USBPcap**-extcap om enigsins rou USB URBs te sien.<sup>[[4]](#references)</sup>
- As die sleutelbord via ’n hub of dok gekoppel was, bevestig eers die koppelvlakbeskrywer en dekodeer dan slegs daardie toestel-/koppelvlakpaar. Saamgestelde HID-vasleggings meng dikwels sleutelbord- en muisverslae.
- Windows-vasleggings vereis die **USBPcap**-extcap-koppelvlak; maak seker dit het Wireshark-opgraderings oorleef, aangesien ontbrekende extcaps leë toestellyste tot gevolg het.<sup>[[4]](#references)</sup>
- Kontroleer altyd die bus-, toestel- en koppelvlaktupel (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; bv. `1.9.1`) voordat jy enigiets dekodeer — as verskeie sleutelborde of stoortoestelle deurmekaar gehaal word, lewer dit onsinnige sleuteldrukke op.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017-verslag: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Ontleding van USB-sleutelbordpakkievaslegging](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2-verslag](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Opstelling vir USB-vaslegging in Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Toestelklasdefinisie vir menslike koppelvlaktoestelle (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID-gebruikstabelle 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark-vertoonfilterverwysing: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark-vertoonfilterverwysing: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux-kern: Inleiding tot HID-verslagbeskrywers](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboard-verslag](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
