# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास निम्नलिखित जैसे keyboard के USB communication वाला pcap है:

![USB Keystrokes: यदि आपके पास निम्नलिखित जैसे keyboard के USB communication वाला pcap है](<../../../images/image (962).png>)

**boot protocol** का उपयोग करने वाले keyboard के लिए, प्रत्येक Interrupt IN report का layout निश्चित 8-byte का होता है: एक modifier byte, एक reserved byte और छह keycode bytes। Host लगातार आने वाली reports की तुलना करता है और key events को फिर से बनाने के लिए keycodes को HID usages से map करता है।<sup>[[8]](#references)</sup>

## USB HID report की मूल बातें

Standard boot keyboard input report की संरचना इस प्रकार होती है।<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | अर्थ |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, आदि)। एक साथ कई bits set हो सकते हैं। |
| 1 | Reserved byte; unused reports में सामान्यतः इसे zero पर set किया जाना चाहिए। OEM या system-specific उपयोग portable नहीं होता। |
| 2-7 | USB usage ID format में अधिकतम छह concurrent keycodes (`0x04 = a`, `0x1E = 1`)। `0x00` का अर्थ है "कोई key नहीं"। |

Boot layout में, जब छह से अधिक non-modifier keys दबाई जाती हैं, तो usage ID `0x01` (`Keyboard ErrorRollOver`) सभी key slots में report किया जाता है; यह किसी unrecognizable combination का संकेत भी दे सकता है।<sup>[[8]](#references)[[9]](#references)</sup> इस layout को समझना तब उपयोगी होता है जब आपके पास केवल raw `usb.capdata` bytes हों।

## PCAP से HID data extract करना

### पहले keyboard interface की पहचान करें

व्यस्त captures में reports dump करने से पहले HID keyboard की पहचान करें। एक reliable starting point interface descriptor response है:<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class इन interface values को define करता है:<sup>[[8]](#references)</sup>

- `subclass == 1` Boot Interface Subclass है; `protocol == 1` के साथ यह boot keyboard की पहचान करता है
- `protocol == 2` boot mouse की पहचान करता है
- `protocol == 0` का अर्थ है कि कोई boot protocol नहीं है; 8-byte layout मानने के बजाय HID report descriptor का निरीक्षण करें

Interface ज्ञात हो जाने के बाद, कुछ भी export करने से पहले अपने filters को `usb.bus_id`, `usb.device_address`, और यदि संभव हो तो `usb.bInterfaceNumber` पर पिन करें।

### Wireshark workflow

1. **Device को isolate करें**: keyboard से आने वाले interrupt IN traffic पर filter लगाएँ, जैसे `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`।
2. **उपयोगी columns जोड़ें**: `Leftover Capture Data` field (`usb.capdata`) और अपने पसंदीदा `usbhid.*` fields (जैसे `usbhid.boot_report.keyboard.keycode_1`) पर right-click करके उन्हें जोड़ें, ताकि हर frame खोले बिना keystrokes को follow किया जा सके।<sup>[[11]](#references)</sup>
3. **Empty reports छिपाएँ**: idle frames हटाने के लिए `!(usb.capdata == 00:00:00:00:00:00:00:00)` लागू करें।
4. **Post-processing के लिए export करें**: `File -> Export Packet Dissections -> As CSV` चुनें और `frame.number`, `usb.src`, `usb.capdata`, तथा decoded modifier fields जैसे `usbhid.boot_report.keyboard.modifier.left_shift` और `usbhid.boot_report.keyboard.modifier.right_alt` शामिल करें, ताकि बाद में reconstruction को script किया जा सके।<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

Classic extraction pattern—`usb.capdata` को dump करना, idle reports हटाना और usage IDs map करना—मूल 2017 analysis और उसके walkthrough में दिखाई देता है।<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository classic tshark + sed pipeline को automate करता है:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
नए captures में Wireshark के decoded `usbhid.data` field को प्राथमिकता दें और `usb.capdata` पर fallback करें; प्रत्येक report के लिए एक payload को per-device file में लिखें:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
इन per-device files को अपेक्षित hex format को normalize करने के बाद decoder में feed किया जा सकता है। यदि capture BLE keyboards से आया है जिन्हें GATT के माध्यम से tunneled किया गया था, तो `btatt.value && frame.len == 20` पर filter करें और decoding से पहले hex payloads dump करें।<sup>[[7]](#references)</sup>

### जब report classic 8-byte boot report न हो

एक non-boot interface या report ID payload layout बदल सकता है, इसलिए यह assume न करें कि हर keyboard report `modifier,reserved,key1..key6` से मेल खाता है।<sup>[[8]](#references)[[11]](#references)</sup>

- जब Wireshark ने HID layer को पहले ही parse कर लिया हो, तो `usb.capdata` के बजाय `usbhid.data` को प्राथमिकता दें।
- यदि हर line एक constant prefix या report ID से शुरू होती है, तो यह assume करने के बजाय कि byte 0 हमेशा modifier है, उसे offset-aware decoder से strip करें।<sup>[[7]](#references)</sup>
- कुछ USBPcap exports reserved byte को omit करते हैं, इसलिए `--no-reserved` या custom offset support करने वाले decoders समय बचाते हैं।<sup>[[7]](#references)</sup>
- यदि capture में HID report descriptor या BLE HOGP report map मौजूद है, तो parser लिखने से पहले वास्तविक field layout recover करने के लिए उसका उपयोग करें।

## Decoding को automate करना

- **ctf-usb-keyboard-parser** quick CTF challenges के लिए अभी भी उपयोगी है और repository में पहले से शामिल है।<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) `pcap` और `pcapng` files को natively parse करता है, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` को समझता है, और इसके लिए tshark या किसी अन्य external dependency की आवश्यकता नहीं होती, इसलिए यह isolated sandboxes के लिए उपयुक्त है।<sup>[[6]](#references)</sup>
- **USB-HID-decoders** keyboard, mouse और tablet visualizers जोड़ता है। आप या तो `extract_hid_data.sh` helper (tshark backend) या `extract_hid_data.py` (scapy backend) चला सकते हैं और फिर keystrokes को unfold होते देखने के लिए resulting text file को decoder या replay modules में feed कर सकते हैं।<sup>[[7]](#references)</sup>

### Stateful decoding महत्वपूर्ण है

USB boot keyboards idle rate पर reports भेजते हैं, भले ही कोई नया key event न हो, इसलिए captures में release event से पहले repeated reports हो सकती हैं। एक practical decoder को यह करना चाहिए:<sup>[[3]](#references)[[8]](#references)</sup>

- पिछले report की तुलना में केवल newly pressed keycodes emit करे
- byte 0 या `usbhid.boot_report.keyboard.modifier.left_shift` और `usbhid.boot_report.keyboard.modifier.right_alt` जैसे parsed fields से modifier state (`Shift`, `Ctrl`, `AltGr`) बनाए रखे
- `Caps Lock` जैसी toggle keys को track करे, क्योंकि uppercase output केवल Shift से नियंत्रित नहीं होता
- याद रखें कि HID usage IDs layout-agnostic होते हैं: host keyboard layout के आधार पर `0x1d` physical `z`/`y` key position होता है।<sup>[[9]](#references)</sup>

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
पहले dump की गई plain hex lines से इसे feed करें ताकि environment में full parser लाए बिना तुरंत rough reconstruction मिल सके। Non-US layouts के लिए यह अभी भी physical key position को reconstruct करता है, जरूरी नहीं कि victim host पर दिखने वाला final glyph ही reconstruct हो।

## Troubleshooting tips

- यदि Wireshark `usbhid.*` fields को populate नहीं करता है, तो संभवतः HID report descriptor capture नहीं हुआ। Capture करते समय keyboard को replug करें या raw `usb.capdata` पर fallback करें।
- Linux software captures में `usbmon` सामान्य source है; Windows पर raw USB URBs देखने के लिए Wireshark हर स्थिति में **USBPcap** extcap पर निर्भर करता है।<sup>[[4]](#references)</sup>
- यदि keyboard किसी hub या dock के माध्यम से जुड़ा था, तो पहले interface descriptor की पुष्टि करें और उसके बाद केवल उसी device/interface pair को decode करें। Composite HID captures में keyboard और mouse reports अक्सर mix हो जाती हैं।
- Windows captures के लिए **USBPcap** extcap interface आवश्यक है; सुनिश्चित करें कि Wireshark upgrades के बाद भी यह मौजूद रहे, क्योंकि missing extcaps के कारण device lists खाली रह जाती हैं।<sup>[[4]](#references)</sup>
- किसी भी चीज़ को decode करने से पहले bus, device और interface tuple (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; जैसे `1.9.1`) को हमेशा correlate करें — multiple keyboards या storage devices को mix करने पर nonsense keystrokes मिलते हैं।<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Keyboard packet capture analysis](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Device Class Definition for Human Interface Devices (HID) 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
