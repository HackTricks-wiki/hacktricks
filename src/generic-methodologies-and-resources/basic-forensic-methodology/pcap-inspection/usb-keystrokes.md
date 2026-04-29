# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

Ikiwa una pcap yenye mawasiliano kupitia USB ya keyboard kama ifuatayo:

![](<../../../images/image (962).png>)

USB keyboards kawaida huzungumza HID **boot protocol**, kwa hiyo kila interrupt transfer kuelekea host huwa na urefu wa bytes 8 pekee: byte moja ya modifier bits (Ctrl/Shift/Alt/Super), byte moja ya reserved, na hadi keycodes sita kwa kila report. Kusimbua bytes hizo kunatosha kujenga upya kila kitu kilichoandikwa.

## USB HID report basics

Report ya kawaida ya IN inaonekana kama hii:

| Byte | Maana |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, n.k.). Bits nyingi zinaweza kuwekwa kwa wakati mmoja. |
| 1 | Reserved/padding lakini mara nyingi hutumiwa tena na gaming keyboards kwa vendor data. |
| 2-7 | Hadi keycodes sita za wakati mmoja katika USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` inamaanisha "hakuna key". |

Keyboards zisizo na NKRO kawaida hutuma `0x01` katika byte 2 wakati zaidi ya keys sita zimeshinikizwa ili kuashiria "rollover". Kuelewa mpangilio huu husaidia unapokuwa na tu `usb.capdata` bytes ghafi.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

Kwenye captures zilizo na shughuli nyingi, tambua kwanza HID keyboard kabla ya kutupa report yoyote. Sehemu ya kuanzia iliyoaminika ni interface descriptor response:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
Angalia `usb.bInterfaceSubClass` na `usb.bInterfaceProtocol`:

- `subclass == 1` na `protocol == 1` kwa kawaida humaanisha boot keyboard
- `protocol == 2` kwa kawaida ni mouse
- `protocol == 0` mara nyingi humaanisha vendor-defined au NKRO-style HID interface ambayo bado hubeba keyboard data, lakini si katika simple 8-byte boot layout

Mara interface inapojulikana, weka filters zako kwa `usb.bus_id`, `usb.device_address`, na ikiwezekana `usb.interface_number` kabla ya ku-export chochote.

### Wireshark workflow

1. **Tenga device**: filter traffic ya interrupt IN kutoka keyboard, mfano `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Ongeza useful columns**: right-click field ya `Leftover Capture Data` (`usb.capdata`) na `usbhid.*` fields unazopendelea (mfano `usbhid.boot_report.keyboard.keycode_1`) ili kufuatilia keystrokes bila kufungua kila frame.
3. **Ficha empty reports**: tumia `!(usb.capdata == 00:00:00:00:00:00:00:00)` kuondoa idle frames.
4. **Export kwa post-processing**: `File -> Export Packet Dissections -> As CSV`, jumuisha `frame.number`, `usb.src`, `usb.capdata`, na `usbhid.modifiers` ili kuandaa script ya reconstruction baadaye.

### Command-line workflow

`ctf-usb-keyboard-parser` tayari hu-automate classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
Kwenye captures mpya zaidi unaweza kuhifadhi zote mbili `usb.capdata` na field tajiri zaidi `usbhid.data` kwa ku-batch kulingana na device:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
Hizo faili maalum kwa kila kifaa huingia moja kwa moja kwenye decoder yoyote. Ikiwa capture ilitoka kwenye keyboard za BLE zilizopitishwa kupitia GATT, fanya filter kwa `btatt.value && frame.len == 20` na dumisha hex payloads kabla ya decoding.

### Wakati report si ile ya kawaida ya boot ya bytes 8

Recent gaming keyboards, split keyboards, na composite HID devices mara nyingi huonyesha non-boot keyboard interface ambapo payload haifanani tena na `modifier,reserved,key1..key6`.

- Pendelea `usbhid.data` badala ya `usb.capdata` wakati Wireshark tayari imeparse HID layer.
- Ikiwa kila line inaanza na constant prefix au report ID, iondoe kwa offset-aware decoder badala ya kudhani byte 0 ni modifier kila mara.
- Baadhi ya USBPcap exports huacha out byte ya reserved, hivyo decoders zinazo-support `--no-reserved` au custom offset huokoa muda.
- Ikiwa HID report descriptor au BLE HOGP report map ipo kwenye capture, itumie kurecover actual field layout kabla ya kuandika parser.

## Kufanya decoding kiotomatiki

- **ctf-usb-keyboard-parser** bado ni muhimu kwa quick CTF challenges na tayari imejumuishwa kwenye repository.
- **CTF-Usb_Keyboard_Parser** (`main.py`) parser both `pcap` and `pcapng` files natively, inaelewa `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`, na haihitaji tshark, kwa hivyo inafanya kazi vizuri ndani ya isolated sandboxes.
- **USB-HID-decoders** inaongeza keyboard, mouse, na tablet visualizers. Unaweza kuendesha `extract_hid_data.sh` helper (tshark backend) au `extract_hid_data.py` (scapy backend) na kisha kuingiza text file inayotokana kwenye decoder au replay modules ili kutazama keystrokes zikijitokeza.

### Stateful decoding ni muhimu

USB interrupt captures kawaida huwa na key press na nakala moja au zaidi za report hiyo hiyo kabla ya release event kufika. Decoder ya vitendo inapaswa:

- kutoa tu keycodes mpya zilizoandikwa ikilinganishwa na report iliyotangulia
- kuhifadhi modifier state (`Shift`, `Ctrl`, `AltGr`) kutoka byte 0 au field iliyoparse ya `usbhid.boot_report.keyboard.modifier`
- kufuatilia toggle keys kama `Caps Lock`, kwa sababu uppercase output haidhibitiwi na Shift pekee
- kukumbuka kwamba HID usage IDs hazitegemei layout: `0x1d` ni nafasi ya key ya kimwili ya `z`/`y` kutegemea host keyboard layout

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
Lisha kwa `hex` lines zilizodumpiwa awali ili upate reconstruction ya haraka ya awali bila kuleta full parser ndani ya environment. Kwa non-US layouts hii bado hujenga upya physical key position, si lazima glyph ya mwisho iliyoonekana kwenye victim host.

## Troubleshooting tips

- Ikiwa Wireshark haijazi fields za `usbhid.*`, HID report descriptor huenda haikunasa. Chomoa na uunganishe tena keyboard wakati unacapture au tumia `usb.capdata` ya raw kama fallback.
- Kwenye Linux software captures, `usbmon` ndiyo source ya kawaida; kwenye Windows, Wireshark hutegemea **USBPcap** extcap ili kuona raw USB URBs kabisa.
- Ikiwa keyboard iliunganishwa kupitia hub au dock, thibitisha interface descriptor kwanza kisha decode tu ile device/interface pair. Composite HID captures mara nyingi huchanganya keyboard na mouse reports.
- Windows captures zinahitaji **USBPcap** extcap interface; hakikisha bado ipo baada ya Wireshark upgrades, kwa kuwa missing extcaps hukupa empty device lists.
- Daima linganisha `usb.bus_id:device:interface` (mf. `1.9.1`) kabla ya decoding chochote — kuchanganya keyboards au storage devices nyingi husababisha keystrokes zisizo na maana.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
