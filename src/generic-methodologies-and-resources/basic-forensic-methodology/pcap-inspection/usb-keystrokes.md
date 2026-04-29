# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

अगर आपके पास ऐसा pcap है जिसमें USB के जरिए एक keyboard की communication हो, जैसा कि नीचे दिखाया गया है:

![](<../../../images/image (962).png>)

USB keyboards आमतौर पर HID **boot protocol** बोलती हैं, इसलिए host की तरफ हर interrupt transfer सिर्फ 8 bytes लंबा होता है: एक byte modifier bits (Ctrl/Shift/Alt/Super) का, एक reserved byte, और हर report में अधिकतम छह keycodes। इन bytes को decode करना typed चीज़ों को फिर से rebuild करने के लिए काफी है।

## USB HID report basics

Typical IN report इस तरह दिखता है:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits एक साथ set हो सकते हैं। |
| 1 | Reserved/padding लेकिन अक्सर gaming keyboards में vendor data के लिए reuse किया जाता है। |
| 2-7 | USB usage ID format में एक साथ अधिकतम छह keycodes (`0x04 = a`, `0x1E = 1`). `0x00` का मतलब "no key" है। |

NKRO बिना वाले keyboards आमतौर पर byte 2 में `0x01` भेजती हैं जब छह से ज्यादा keys दबाई जाती हैं, ताकि "rollover" signal हो। इस layout को समझना तब मदद करता है जब आपके पास सिर्फ raw `usb.capdata` bytes हों।

## Extracting HID data from a PCAP

### पहले keyboard interface की पहचान करें

Busy captures में, किसी भी report को dump करने से पहले HID keyboard की पहचान करें। एक भरोसेमंद starting point interface descriptor response है:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` और `usb.bInterfaceProtocol` देखें:

- `subclass == 1` और `protocol == 1` आमतौर पर boot keyboard का मतलब है
- `protocol == 2` आमतौर पर mouse होता है
- `protocol == 0` अक्सर vendor-defined या NKRO-style HID interface का मतलब होता है, जो अभी भी keyboard data carry करता है, लेकिन simple 8-byte boot layout में नहीं

जब interface पता चल जाए, तो export करने से पहले अपने filters को `usb.bus_id`, `usb.device_address`, और अगर संभव हो तो `usb.interface_number` पर pin करें।

### Wireshark workflow

1. **Device isolate करें**: keyboard से आने वाले interrupt IN traffic पर filter लगाएं, जैसे `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Useful columns जोड़ें**: `Leftover Capture Data` field (`usb.capdata`) और अपने preferred `usbhid.*` fields (जैसे `usbhid.boot_report.keyboard.keycode_1`) पर right-click करें ताकि हर frame खोलने की जरूरत बिना keystrokes follow कर सकें।
3. **Empty reports hide करें**: idle frames हटाने के लिए `!(usb.capdata == 00:00:00:00:00:00:00:00)` लागू करें।
4. **Post-processing के लिए export करें**: `File -> Export Packet Dissections -> As CSV`, `frame.number`, `usb.src`, `usb.capdata`, और `usbhid.modifiers` शामिल करें ताकि बाद में reconstruction script किया जा सके।

### Command-line workflow

`ctf-usb-keyboard-parser` पहले से ही classic tshark + sed pipeline को automate करता है:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
नए captures पर आप दोनों `usb.capdata` और अधिक समृद्ध `usbhid.data` field को per device batching करके रख सकते हैं:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
वे per-device files सीधे किसी भी decoder में drop हो जाते हैं। अगर capture BLE keyboards से आया है जो GATT के over tunneled हैं, तो `btatt.value && frame.len == 20` पर filter करें और decode करने से पहले hex payloads dump करें।

### जब report classic 8-byte boot report नहीं होता

Recent gaming keyboards, split keyboards, और composite HID devices अक्सर एक non-boot keyboard interface expose करते हैं जहाँ payload अब `modifier,reserved,key1..key6` से match नहीं करता।

- जब Wireshark पहले ही HID layer parse कर चुका हो, तो `usb.capdata` की बजाय `usbhid.data` prefer करें।
- अगर हर line एक constant prefix या report ID से शुरू होती है, तो byte 0 हमेशा modifier मानने की बजाय offset-aware decoder से उसे strip करें।
- कुछ USBPcap exports reserved byte omit करते हैं, इसलिए `--no-reserved` या custom offset support करने वाले decoders समय बचाते हैं।
- अगर capture में HID report descriptor या BLE HOGP report map मौजूद हो, तो parser लिखने से पहले actual field layout recover करने के लिए उसका उपयोग करें।

## Decoding को automate करना

- **ctf-usb-keyboard-parser** quick CTF challenges के लिए अभी भी उपयोगी है और repository में already ships होता है।
- **CTF-Usb_Keyboard_Parser** (`main.py`) native रूप से `pcap` और `pcapng` दोनों files parse करता है, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` समझता है, और tshark की आवश्यकता नहीं होती, इसलिए यह isolated sandboxes में अच्छी तरह काम करता है।
- **USB-HID-decoders** keyboard, mouse, और tablet visualizers जोड़ता है। आप या तो `extract_hid_data.sh` helper (tshark backend) या `extract_hid_data.py` (scapy backend) चला सकते हैं, और फिर resulting text file को decoder या replay modules में feed करके keystrokes को unfold होते देख सकते हैं।

### Stateful decoding matters

USB interrupt captures में आमतौर पर key press और उसी report की एक या अधिक repeated copies दोनों होती हैं, इससे पहले कि release event arrive हो। एक practical decoder को चाहिए:

- पिछले report की तुलना में केवल newly pressed keycodes emit करना
- modifier state (`Shift`, `Ctrl`, `AltGr`) को byte 0 या parsed `usbhid.boot_report.keyboard.modifier` field से keep करना
- `Caps Lock` जैसी toggle keys track करना, क्योंकि uppercase output सिर्फ Shift से control नहीं होता
- याद रखना कि HID usage IDs layout-agnostic हैं: `0x1d` host keyboard layout के अनुसार physical `z`/`y` key position है

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
इसे पहले डंप की गई plain hex lines के साथ feed करें ताकि full parser को environment में लाए बिना तुरंत एक rough reconstruction मिल जाए। गैर-US layouts के लिए भी यह physical key position reconstruct करता है, victim host पर दिखने वाले final glyph को नहीं।

## Troubleshooting tips

- अगर Wireshark `usbhid.*` fields populate नहीं करता, तो संभव है HID report descriptor capture नहीं हुआ हो। capture करते समय keyboard को फिर से plug करें या raw `usb.capdata` पर fall back करें।
- Linux software captures में, `usbmon` normal source है; Windows पर, Wireshark को raw USB URBs देखने के लिए **USBPcap** extcap पर निर्भर रहना पड़ता है।
- अगर keyboard किसी hub या dock के through attached था, पहले interface descriptor confirm करें और फिर सिर्फ उसी device/interface pair को decode करें। Composite HID captures अक्सर keyboard और mouse reports को mix कर देते हैं।
- Windows captures के लिए **USBPcap** extcap interface चाहिए; सुनिश्चित करें कि Wireshark upgrades के दौरान यह intact रहा हो, क्योंकि missing extcaps से device lists खाली रह जाती हैं।
- कोई भी decoding शुरू करने से पहले हमेशा `usb.bus_id:device:interface` (e.g. `1.9.1`) को correlate करें — multiple keyboards या storage devices को mix करने से meaningless keystrokes मिलती हैं।

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
