# Mibofyo ya USB

Ikiwa una pcap yenye mawasiliano kupitia USB ya keyboard kama ilivyo hapa chini:

![Mibofyo ya USB: Ikiwa una pcap yenye mawasiliano kupitia USB ya keyboard kama ilivyo hapa chini](<../../../images/image (962).png>)

Kwa keyboard inayotumia **boot protocol** ya HID, kila Interrupt IN report ina muundo thabiti wa baiti 8: baiti moja ya modifier, baiti moja iliyohifadhiwa, na baiti sita za keycode. Host hulinganisha reports zinazofuatana na kuhusisha keycodes na matumizi ya HID ili kuunda upya matukio ya mibofyo ya vitufe.<sup>[[8]](#references)</sup>

## Misingi ya HID report ya USB

Standard boot keyboard input report imeundwa kama ifuatavyo.<sup>[[8]](#references)[[9]](#references)</sup>

| Baiti | Maana |
| --- | --- |
| 0 | Bitmap ya modifier (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, n.k.). Bits nyingi zinaweza kuwekwa kwa wakati mmoja. |
| 1 | Baiti iliyohifadhiwa; reports zisizotumika kwa kawaida zinapaswa kuiweka kuwa sifuri. Matumizi ya OEM au maalum kwa mfumo si portable. |
| 2-7 | Hadi keycodes sita zinazotumika kwa wakati mmoja katika muundo wa USB usage ID (`0x04 = a`, `0x1E = 1`). `0x00` humaanisha "hakuna kitufe". |

Katika boot layout, usage ID `0x01` (`Keyboard ErrorRollOver`) huripotiwa katika nafasi zote za vitufe wakati zaidi ya vitufe sita visivyo modifiers vimebonyezwa; pia inaweza kuashiria mchanganyiko usiotambulika.<sup>[[8]](#references)[[9]](#references)</sup> Kuelewa layout hii husaidia unapokuwa na baiti ghafi za `usb.capdata` pekee.

## Kutoa data ya HID kutoka kwenye PCAP

### Tambua interface ya keyboard kwanza

Kwenye captures zenye shughuli nyingi, tambua HID keyboard kabla ya kutupa reports. Mwanzo unaotegemeka ni jibu la interface descriptor:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Darasa la HID linafafanua thamani hizi za interface:<sup>[[8]](#references)</sup>

- `subclass == 1` ni Boot Interface Subclass; ikiwa na `protocol == 1`, hutambulisha boot keyboard
- `protocol == 2` hutambulisha boot mouse
- `protocol == 0` humaanisha hakuna boot protocol; kagua HID report descriptor badala ya kudhani mpangilio wa baiti 8

Baada ya interface kujulikana, weka filters zako kwenye `usb.bus_id`, `usb.device_address`, na ikiwezekana `usb.bInterfaceNumber` kabla ya ku-export chochote.

### Wireshark workflow

1. **Tenga device**: filter kwenye interrupt IN traffic kutoka kwa keyboard, kwa mfano `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **Ongeza columns muhimu**: bofya-kulia field ya `Leftover Capture Data` (`usb.capdata`) na fields unazopendelea za `usbhid.*` (kwa mfano `usbhid.boot_report.keyboard.keycode_1`) ili kufuatilia keystrokes bila kufungua kila frame.<sup>[[11]](#references)</sup>
3. **Ficha reports tupu**: tumia `!(usb.capdata == 00:00:00:00:00:00:00:00)` kuondoa idle frames.
4. **Export kwa post-processing**: `File -> Export Packet Dissections -> As CSV`, jumuisha `frame.number`, `usb.src`, `usb.capdata`, na modifier fields zilizotafsiriwa kama `usbhid.boot_report.keyboard.modifier.left_shift` na `usbhid.boot_report.keyboard.modifier.right_alt` ili kuandika script ya kufanya reconstruction baadaye.<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

Muundo wa kawaida wa extraction—dump `usb.capdata`, ondoa idle reports, na map usage IDs—unaonekana katika analysis ya awali ya 2017 na walkthrough yake.<sup>[[1]](#references)[[2]](#references)</sup>

Repository ya `ctf-usb-keyboard-parser` hu-automate classic tshark + sed pipeline:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Kwenye captures mpya, pendelea sehemu iliyotafsiriwa ya Wireshark `usbhid.data` na utumie `usb.capdata` kama mbadala; andika payload moja kwa kila report kwenye faili maalum kwa kila kifaa:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
Faili hizo za kila kifaa zinaweza kupewa decoder baada ya kusawazisha muundo wa hex unaotarajiwa. Ikiwa capture ilitoka kwenye keyboards za BLE zilizopitishwa kupitia GATT, chuja kwa `btatt.value && frame.len == 20` na dump payload za hex kabla ya ku-decode.<sup>[[7]](#references)</sup>

### Wakati report si classic 8-byte boot report

Interface isiyo ya boot au report ID inaweza kubadilisha mpangilio wa payload, kwa hivyo usidhanie kwamba kila keyboard report inalingana na `modifier,reserved,key1..key6`.<sup>[[8]](#references)[[11]](#references)</sup>

- Pendelea `usbhid.data` badala ya `usb.capdata` wakati Wireshark tayari ime-parse HID layer.
- Ikiwa kila mstari unaanza na prefix au report ID isiyobadilika, iondoe kwa decoder inayozingatia offset badala ya kudhania kwamba byte 0 daima ni modifier.<sup>[[7]](#references)</sup>
- Baadhi ya USBPcap exports huacha reserved byte, kwa hivyo decoders zinazotumia `--no-reserved` au custom offset huokoa muda.<sup>[[7]](#references)</sup>
- Ikiwa HID report descriptor au BLE HOGP report map ipo kwenye capture, itumie kurejesha mpangilio halisi wa fields kabla ya kuandika parser.

## Ku-automate decoding

- **ctf-usb-keyboard-parser** bado ni muhimu kwa CTF challenges za haraka na tayari imejumuishwa kwenye repository.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) hu-parse faili za `pcap` na `pcapng` moja kwa moja, inaelewa `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, na haihitaji tshark au external dependency nyingine, hivyo inafaa kwa isolated sandboxes.<sup>[[6]](#references)</sup>
- **USB-HID-decoders** huongeza visualizers za keyboard, mouse na tablet. Unaweza kuendesha helper ya `extract_hid_data.sh` (tshark backend) au `extract_hid_data.py` (scapy backend), kisha upe decoder au replay modules text file inayotokana ili kutazama keystrokes zikifuatana.<sup>[[7]](#references)</sup>

### Stateful decoding ni muhimu

USB boot keyboards hutuma reports kwa idle rate hata wakati hakuna key event mpya, kwa hivyo captures zinaweza kuwa na reports zinazorudiwa kabla ya release event. Decoder ya vitendo inapaswa:<sup>[[3]](#references)[[8]](#references)</sup>

- kutoa keycodes mpya tu zilizobanwa ikilinganishwa na report iliyotangulia
- kuhifadhi modifier state (`Shift`, `Ctrl`, `AltGr`) kutoka byte 0 au fields zilizoparse kama `usbhid.boot_report.keyboard.modifier.left_shift` na `usbhid.boot_report.keyboard.modifier.right_alt`
- kufuatilia toggle keys kama `Caps Lock`, kwa sababu output ya uppercase haidhibitiwi na Shift pekee
- kukumbuka kwamba HID usage IDs hazitegemei layout: `0x1d` ni physical `z`/`y` key position kulingana na keyboard layout ya host.<sup>[[9]](#references)</sup>

## Decoder ya haraka ya Python
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
Ipe mistari ya hex wazi iliyotolewa awali ili kupata uundaji wa awali wa haraka bila kuingiza parser kamili kwenye mazingira. Kwa layouts zisizo za Marekani, hii bado huunda upya nafasi halisi ya key, si lazima glyph ya mwisho iliyoonyeshwa kwenye host ya victim.

## Vidokezo vya troubleshooting

- Ikiwa Wireshark haijazi fields za `usbhid.*`, huenda HID report descriptor haikunaswa. Unganisha tena keyboard wakati wa kunasa au tumia `usb.capdata` ghafi.
- Kwenye software captures za Linux, `usbmon` ndiyo source ya kawaida; kwenye Windows, Wireshark hutegemea extcap ya **USBPcap** ili kuona raw USB URBs kabisa.<sup>[[4]](#references)</sup>
- Ikiwa keyboard iliunganishwa kupitia hub au dock, thibitisha interface descriptor kwanza, kisha decode device/interface pair hiyo pekee. Composite HID captures mara nyingi huchanganya keyboard na mouse reports.
- Windows captures zinahitaji interface ya **USBPcap** extcap; hakikisha iliendelea kuwepo baada ya Wireshark upgrades, kwa kuwa extcaps zinazokosekana hukuachia device lists tupu.<sup>[[4]](#references)</sup>
- Kila mara correlate tuple ya bus, device na interface (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; kwa mfano `1.9.1`) kabla ya ku-decode chochote — kuchanganya keyboards au storage devices nyingi husababisha keystrokes zisizo na maana.<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Maelezo ya suluhisho: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [Uchambuzi wa packet capture ya USB Keyboard](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - maelezo ya suluhisho ya pcap 1, 2](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Usanidi wa Wireshark USB capture](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Ufafanuzi wa Device Class wa Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [Jedwali za HID Usage 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Marejeo ya Wireshark Display Filter: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Marejeo ya Wireshark Display Filter: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
