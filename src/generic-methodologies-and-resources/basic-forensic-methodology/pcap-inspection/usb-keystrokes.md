# Vibonyezo vya USB

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap iliyo na mawasiliano kupitia USB ya keyboard kama iliyo hapa chini:

![Vibonyezo vya USB: Ikiwa una pcap iliyo na mawasiliano kupitia USB ya keyboard kama iliyo hapa chini](<../../../images/image (962).png>)

USB keyboards kwa kawaida hutumia **boot protocol** ya HID, kwa hiyo kila interrupt transfer kuelekea host huwa na urefu wa bytes 8 pekee: byte moja ya modifier bits (Ctrl/Shift/Alt/Super), byte moja iliyotengwa, na hadi keycodes sita kwa kila report. Ku-decode bytes hizo kunatosha kujenga upya kila kitu kilichoandikwa.

## Misingi ya USB HID report

IN report ya kawaida huonekana kama:

| Byte | Maana |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, n.k.). Bits nyingi zinaweza kuwekwa kwa wakati mmoja. |
| 1 | Iliyotengwa/padding, lakini mara nyingi hutumiwa tena na gaming keyboards kwa vendor data. |
| 2-7 | Hadi keycodes sita zinazoingizwa kwa wakati mmoja katika USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` inamaanisha "hakuna key". |

Keyboards zisizo na NKRO kwa kawaida hutuma `0x01` katika byte 2 wakati keys zaidi ya sita zimebonyezwa ili kuashiria "rollover". Kuelewa mpangilio huu husaidia unapokuwa na bytes ghafi za `usb.capdata` pekee.

## Kutoa HID data kutoka kwenye PCAP

### Tambua keyboard interface kwanza

Katika captures zilizo na shughuli nyingi, tambua HID keyboard kabla ya kutoa reports. Mwanzo unaotegemewa ni interface descriptor response:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Angalia `usb.bInterfaceSubClass` na `usb.bInterfaceProtocol`:

- `subclass == 1` na `protocol == 1` kwa kawaida humaanisha boot keyboard
- `protocol == 2` kwa kawaida ni mouse
- `protocol == 0` mara nyingi humaanisha vendor-defined au NKRO-style HID interface ambayo bado hubeba data ya keyboard, lakini si katika mpangilio rahisi wa boot wa byte 8

Baada ya kujua interface, weka filters zako kwenye `usb.bus_id`, `usb.device_address`, na ikiwezekana `usb.interface_number` kabla ya ku-export chochote.

### Workflow ya Wireshark

1. **Tenga kifaa**: filter kwenye interrupt IN traffic kutoka kwa keyboard, kwa mfano `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ongeza columns muhimu**: bofya-kulia field ya `Leftover Capture Data` (`usb.capdata`) na fields za `usbhid.*` unazopendelea (kwa mfano `usbhid.boot_report.keyboard.keycode_1`) ili kufuatilia keystrokes bila kufungua kila frame.
3. **Ficha reports tupu**: tumia `!(usb.capdata == 00:00:00:00:00:00:00:00)` kuondoa idle frames.
4. **Export kwa post-processing**: `File -> Export Packet Dissections -> As CSV`, jumuisha `frame.number`, `usb.src`, `usb.capdata`, na `usbhid.modifiers` ili ku-script reconstruction baadaye.

### Workflow ya command-line

`ctf-usb-keyboard-parser` tayari ina-automate classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Katika captures mpya, unaweza kuhifadhi sehemu zote mbili za `usb.capdata` na sehemu yenye taarifa zaidi ya `usbhid.data` kwa kuziweka kwenye batches kulingana na kifaa:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Hizo faili za kila kifaa huingizwa moja kwa moja kwenye decoder yoyote. Ikiwa capture ilitoka kwenye keyboards za BLE zilizotunnel kupitia GATT, tumia filter kwenye `btatt.value && frame.len == 20` na toa hex payloads kabla ya kuzi-decode.

### Wakati report si classic 8-byte boot report

Keyboards za kisasa za gaming, split keyboards, na HID devices za composite mara nyingi hutoa keyboard interface isiyo ya boot, ambapo payload hailingani tena na `modifier,reserved,key1..key6`.

- Pendelea `usbhid.data` kuliko `usb.capdata` wakati Wireshark tayari ime-parse HID layer.
- Ikiwa kila mstari unaanza na constant prefix au report ID, iondoe kwa kutumia decoder inayotambua offset badala ya kudhani kuwa byte 0 daima ni modifier.
- Baadhi ya exports za USBPcap huacha reserved byte, hivyo decoders zinazounga mkono `--no-reserved` au custom offset huokoa muda.
- Ikiwa HID report descriptor au BLE HOGP report map ipo kwenye capture, itumie kurejesha field layout halisi kabla ya kuandika parser.

## Ku-automate decoding

- **ctf-usb-keyboard-parser** bado ni muhimu kwa CTF challenges za haraka na tayari ipo kwenye repository.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) hu-parse faili za `pcap` na `pcapng` natively, inaelewa `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, na haihitaji tshark, hivyo hufanya kazi vizuri ndani ya isolated sandboxes.<sup>[[4]](#references)</sup>
- **USB-HID-decoders** huongeza visualizers za keyboard, mouse, na tablet. Unaweza kuendesha helper ya `extract_hid_data.sh` (tshark backend) au `extract_hid_data.py` (scapy backend), kisha uipe decoder au replay modules faili ya text inayotokana ili kutazama keystrokes zikijitokeza.<sup>[[5]](#references)</sup>

### Stateful decoding ni muhimu

USB interrupt captures kwa kawaida huwa na key press na nakala moja au zaidi zinazorudiwa za report hiyo kabla release event haijafika. Decoder ya kivitendo inapaswa:<sup>[[2]](#references)</sup>

- kutoa keycodes mpya pekee ikilinganishwa na report iliyotangulia
- kuhifadhi modifier state (`Shift`, `Ctrl`, `AltGr`) kutoka byte 0 au field iliyo-parse ya `usbhid.boot_report.keyboard.modifier`
- kufuatilia toggle keys kama `Caps Lock`, kwa sababu uppercase output haidhibitiwi na Shift pekee
- kukumbuka kuwa HID usage IDs hazitegemei layout: `0x1d` ni physical key position ya `z`/`y`, kutegemea keyboard layout ya host

## Quick Python decoder
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
Ipenye mistari tambarare ya hex iliyotupwa awali ili kupata reconstruction ya haraka bila kuingiza parser kamili kwenye mazingira. Kwa layouts zisizo za Marekani, hii bado huonyesha nafasi halisi ya kitufe, si lazima glyph ya mwisho iliyoonyeshwa kwenye host ya victim.

## Vidokezo vya utatuzi

- Ikiwa Wireshark haijazi fields za `usbhid.*`, huenda HID report descriptor haikunaswa. Chomoa na uunganishe tena keyboard wakati wa kunasa, au tumia `usb.capdata` ghafi.
- Kwenye software captures za Linux, `usbmon` ndiyo chanzo cha kawaida; kwenye Windows, Wireshark hutegemea extcap ya **USBPcap** ili kuona raw USB URBs kabisa.<sup>[[1]](#references)</sup>
- Ikiwa keyboard iliunganishwa kupitia hub au dock, thibitisha interface descriptor kwanza, kisha decode device/interface pair hiyo pekee. Composite HID captures mara nyingi huchanganya reports za keyboard na mouse.
- Windows captures zinahitaji interface ya **USBPcap** extcap; hakikisha iliendelea kuwepo baada ya Wireshark upgrades, kwa kuwa extcaps zinazokosekana huacha device lists zikiwa tupu.<sup>[[1]](#references)</sup>
- Kila mara correlate `usb.bus_id:device:interface` (kwa mfano `1.9.1`) kabla ya kuanza decoding — kuchanganya keyboards au storage devices nyingi husababisha keystrokes zisizo na maana.

## Marejeleo

- [1] [Usanidi wa Wireshark USB capture](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
