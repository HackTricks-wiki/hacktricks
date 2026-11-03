# Mibonyezo ya Vitufe vya USB

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap iliyo na mawasiliano kupitia USB ya kibodi kama hii:

![Mibonyezo ya Vitufe vya USB: Ikiwa una pcap iliyo na mawasiliano kupitia USB ya kibodi kama hii](<../../../images/image (962).png>)

Kwa kibodi inayotumia **boot protocol** ya HID, kila ripoti ya Interrupt IN ina mpangilio usiobadilika wa baiti 8: baiti moja ya modifier, baiti moja iliyohifadhiwa, na baiti sita za keycode. Kompyuta mwenyeji hulinganisha ripoti zinazofuatana na kupanga keycode kulingana na matumizi ya HID ili kuunda upya matukio ya vitufe.<sup>[[8]](#references)</sup>

Kwa uchunguzi wa jumla wa capture, tazama [Pcap Inspection](./).

## Misingi ya ripoti za USB HID

Ripoti ya kawaida ya ingizo ya kibodi ya boot imepangwa kama ifuatavyo.<sup>[[8]](#references)[[9]](#references)</sup>

| Baiti | Maana |
| --- | --- |
| 0 | Bitmap ya modifier (`0x02` = Shift ya Kushoto, `0x20` = Shift ya Kulia, `0x40` = Alt ya Kulia, n.k.). Biti nyingi zinaweza kuwekwa kwa wakati mmoja. |
| 1 | Baiti iliyohifadhiwa; kwa kawaida ripoti zisizotumika zinapaswa kuiweka kuwa sifuri. Matumizi maalum ya OEM au mfumo hayatumiki kwa mifumo yote. |
| 2-7 | Hadi keycode sita zinazotumika kwa wakati mmoja katika muundo wa USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` humaanisha "hakuna kitufe". |

Katika mpangilio wa boot, usage ID `0x01` (`Keyboard ErrorRollOver`) huripotiwa katika nafasi zote za vitufe wakati vitufe zaidi ya sita visivyo vya modifier vimebonyezwa; pia inaweza kuashiria mchanganyiko usiotambulika.<sup>[[8]](#references)[[9]](#references)</sup> Kuelewa mpangilio huu husaidia unapokuwa na baiti ghafi za `usb.capdata` pekee.

## Kutoa data ya HID kutoka kwenye PCAP

### Tambua kiolesura cha kibodi kwanza

Katika capture zenye shughuli nyingi, tambua kibodi ya HID kabla ya kutoa ripoti zozote. Mwanzo mzuri ni jibu la interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

Darasa la HID hufafanua thamani hizi za interface:<sup>[[8]](#references)</sup>

- `subclass == 1` ni Boot Interface Subclass; ikiwa `protocol == 1`, hutambua boot keyboard
- `protocol == 2` hutambua boot mouse
- `protocol == 0` humaanisha hakuna boot protocol; kagua HID report descriptor badala ya kudhani mpangilio wa baiti 8

Interface yenye uwezo wa kutumia boot protocol **si uthibitisho kwamba boot protocol inatumika**. Vifaa vya HID huanzishwa katika report protocol. Host huchagua boot mode kwa kutumia `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`); `wValue = 1` huchagua report protocol. Ikiwa enumeration ipo kwenye capture, kagua ombi la keyboard interface (`wIndex`) kabla ya kutumia boot decoder ya baiti nane. Ikiwa halipo, thibitisha mpangilio wa report ulioonekana badala ya kukisia mode kutokana na interface descriptor.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

Mara tu kiolesura kinapojulikana, weka vichujio vyako kwenye `usb.bus_id`, `usb.device_address`, na ikiwezekana `usb.bInterfaceNumber` kabla ya kuhamisha data yoyote.

### Mtiririko wa kazi wa Wireshark

1. **Tenga kifaa**: chuja trafiki ya interrupt IN kutoka kwenye kibodi, kwa mfano, `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Ongeza safu wima muhimu**: bofya kulia sehemu ya `Leftover Capture Data` (`usb.capdata`) na sehemu za `usbhid.*` unazopendelea (kwa mfano, `usbhid.boot_report.keyboard.keycode_1`) ili kufuatilia mibofyo ya vitufe bila kufungua kila fremu.<sup>[[11]](#references)</sup>
3. **Ficha ripoti tupu**: tumia `!(usb.capdata == 00:00:00:00:00:00:00:00)` kuondoa fremu zisizotumika.
4. **Hamisha kwa uchakataji wa baadaye**: `File -> Export Packet Dissections -> As CSV`, jumuisha `frame.number`, `usb.src`, `usb.capdata`, na sehemu za modifier zilizochambuliwa kama `usbhid.boot_report.keyboard.modifier.left_shift` na `usbhid.boot_report.keyboard.modifier.right_alt` ili uandike script ya kuunda upya baadaye.<sup>[[10]](#references)[[11]](#references)</sup>

### Mtiririko wa kazi wa mstari wa amri

Mbinu ya kawaida ya uchimbaji—kutupa `usb.capdata`, kuondoa ripoti zisizotumika, na kuweka ramani ya usage IDs—inaonekana katika uchanganuzi wa awali wa 2017 na mwongozo wake.<sup>[[1]](#references)[[2]](#references)</sup>

Hifadhi ya `ctf-usb-keyboard-parser` hujiendesha kiotomatiki mchakato wa kawaida wa tshark + sed:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

Katika captures mpya zaidi, pendelea uga wa `usbhid.data` uliotafsiriwa na Wireshark, na utumie `usb.capdata` kama mbadala; andika payload moja kwa kila report kwenye faili ya kila kifaa:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

Faili hizo za kila kifaa zinaweza kuingizwa kwenye decoder baada ya kusawazisha umbizo la hex linalotarajiwa. Ikiwa capture ilitoka kwa kibodi za BLE zilizopitishwa kupitia GATT, chuja kwa `btatt.value && frame.len == 20` na utoe payload za hex kabla ya kuzidecode.<sup>[[7]](#references)</sup>

### Wakati report si boot report ya kawaida ya baiti 8

Kiolesura kisicho cha boot au report ID inaweza kubadilisha mpangilio wa payload, kwa hivyo usidhani kwamba kila report ya kibodi inalingana na `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Pendelea `usbhid.data` badala ya `usb.capdata` wakati Wireshark tayari imechanganua safu ya HID.
- Ikiwa kila mstari unaanza na kiambishi awali kisichobadilika au report ID, kiondoe kwa kutumia decoder inayozingatia offset badala ya kudhani kwamba baiti ya 0 huwa modifier kila wakati.<sup>[[7]](#references)</sup>
- Baadhi ya export za USBPcap huacha baiti iliyohifadhiwa, kwa hivyo decoder zinazotumia `--no-reserved` au offset maalum huokoa muda.<sup>[[7]](#references)</sup>
- Ikiwa HID report descriptor au BLE HOGP report map ipo kwenye capture, itumie kubaini mpangilio halisi wa sehemu kabla ya kuandika parser.

### Decode bitmap ya vitufe ya report-protocol

Kwa kibodi ambayo input report yake ni bitmap badala ya nafasi sita za vitufe vya boot, tafuta **HID report descriptor** kwenye trafiki ya enumeration. Kichujio hiki hupata fremu ambazo Wireshark imechanganua kipengee cha Report Size; fungua mojawapo na ukague descriptor nzima. Anzisha capture mpya kabla ya kuchomeka kibodi ikiwa descriptor haipo.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

Kwa kila ripoti ya Input ya kibodi, andika `Report ID` (ikiwa ipo), `Usage Page` (`0x07` kwa vitufe vya kibodi), `Usage Minimum/Maximum`, `Report Size`, `Report Count`, na ikiwa kila kipengee cha `Input` ni **Variable** au **Array**. Hesabu sehemu zote za Input na padding ya constant zilizotangulia ili kupata bit offset ya uga wa vitufe; sehemu za ripoti hazihitaji kuanza kwenye mipaka ya byte. Uga wa Variable wa bit moja wenye usages za kibodi zinazofuatana ni bitmap ya hali ya vitufe: bit 0 ya uga huo inalingana na usage yake ya kwanza iliyotangazwa, bit 1 na inayofuata, na kuendelea hivyo. Kinyume chake, Array huwa na thamani zinazotatuliwa kupitia usage range ya descriptor, si kitufe kimoja kilichobonyezwa kwa kila bit. Ikiwa `Report ID` imetangazwa, chagua kwanza ripoti zenye kiambishi awali hicho na uruke byte yake unapokokotoa field offset. Linganisha seti za usages zilizoshikiliwa kati ya ripoti zinazofuatana za **kiolesura na Report ID sawa** ili kutoa mibofyo mipya pekee.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Kuendesha decoding kiotomatiki

- **ctf-usb-keyboard-parser** bado ni zana rahisi kwa changamoto za haraka za CTF na tayari imo kwenye repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) huchanganua faili za `pcap` na `pcapng` moja kwa moja, huelewa `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, na haihitaji tshark au dependency nyingine ya nje, kwa hiyo inafaa kwa sandbox zilizotengwa.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** huongeza visualizer za kibodi, kipanya na tablet. Unaweza kuendesha helper ya `extract_hid_data.sh` (tshark backend) au `extract_hid_data.py` (scapy backend), kisha uipe decoder au replay modules faili ya maandishi iliyotokana nayo ili kutazama mibofyo ya vitufe ikijitokeza.<sup>[[7]](#references)</sup>

### Decoding yenye hali ni muhimu

Kibodi za USB boot hutuma ripoti kwa idle rate hata kama hakuna tukio jipya la kitufe, kwa hiyo captures zinaweza kuwa na ripoti zinazorudiwa kabla ya tukio la kuachia kitufe. Decoder inayofaa inapaswa:<sup>[[3]](#references)[[8]](#references)</sup>

- kutoa keycodes mpya zilizobonyezwa pekee ikilinganishwa na ripoti iliyotangulia
- kuhifadhi hali ya modifier (`Shift`, `Ctrl`, `AltGr`) kutoka byte 0 au sehemu zilizochanganuliwa kama `usbhid.boot_report.keyboard.modifier.left_shift` na `usbhid.boot_report.keyboard.modifier.right_alt`
- kufuatilia vitufe vya kubadilisha hali kama `Caps Lock`, kwa sababu herufi kubwa hazidhibitiwi na Shift pekee
- kukumbuka kuwa HID usage IDs hazitegemei mpangilio wa kibodi: `0x1d` ni nafasi halisi ya kitufe cha `z`/`y`, kutegemea mpangilio wa kibodi wa host.<sup>[[9]](#references)</sup>

## Python decoder ya haraka

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

Ipekele mistari ya hex ya kawaida iliyotupwa awali ili upate mara moja ujenzi upya wa kadiri, bila kuhitaji kuingiza parser kamili kwenye mazingira. Kwa layouts zisizo za US, hii bado huonyesha nafasi halisi ya kitufe, si lazima glyph ya mwisho inayoonyeshwa kwenye host ya mwathiriwa.

## Vidokezo vya utatuzi

- Ikiwa Wireshark haijazi sehemu za `usbhid.*`, huenda HID report descriptor haikunakiliwa. Chomoa na uunganishe tena kibodi wakati wa kunasa trafiki, au tumia `usb.capdata` ghafi badala yake.
- Kwenye kunasa trafiki kwa software ya Linux, `usbmon` ndiyo chanzo cha kawaida; kwenye Windows, Wireshark hutegemea extcap ya **USBPcap** ili kuona USB URBs ghafi kabisa.<sup>[[4]](#references)</sup>
- Ikiwa kibodi iliunganishwa kupitia hub au dock, hakikisha descriptor ya interface kwanza, kisha decode jozi ya kifaa/interface hiyo pekee. Kunasa trafiki ya Composite HID mara nyingi huchanganya ripoti za kibodi na kipanya.
- Kunasa trafiki kwenye Windows kunahitaji interface ya extcap ya **USBPcap**; hakikisha bado inapatikana baada ya kusasisha Wireshark, kwa kuwa extcap zinazokosekana huacha orodha za vifaa zikiwa tupu.<sup>[[4]](#references)</sup>
- Linganisha kila mara tuple ya basi, kifaa na interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; kwa mfano, `1.9.1`) kabla ya kufanya decode — kuchanganya kibodi au vifaa vingi vya hifadhi husababisha mibofyo ya vitufe isiyo na maana.<sup>[[10]](#references)</sup>



## References

- [1] [Maelezo ya HackIT CTF 2017: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Uchambuzi wa packet capture za Kibodi ya USB](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - maelezo ya pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Usanidi wa USB capture wa Wireshark](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Ufafanuzi wa Darasa la Kifaa kwa Vifaa vya Kiolesura cha Binadamu (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Majedwali ya Matumizi ya HID 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Rejeleo la Wireshark Display Filter: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Rejeleo la Wireshark Display Filter: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Kernel ya Linux: Utangulizi wa HID report descriptors](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: maelezo ya ordinary-keyboard](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
