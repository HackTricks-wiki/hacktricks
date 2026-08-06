# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास किसी keyboard के USB के माध्यम से होने वाले communication का pcap हो, जैसा कि नीचे दिया गया है:

![USB Keystrokes: यदि आपके पास किसी keyboard के USB के माध्यम से होने वाले communication का pcap हो, जैसा कि नीचे दिया गया है](<../../../images/image (962).png>)

USB keyboards आमतौर पर HID **boot protocol** का उपयोग करते हैं, इसलिए host की ओर होने वाला प्रत्येक interrupt transfer केवल 8 bytes लंबा होता है: modifier bits (Ctrl/Shift/Alt/Super) का एक byte, एक reserved byte और प्रत्येक report में अधिकतम छह keycodes। इन bytes को decode करना typed किए गए पूरे text को दोबारा बनाने के लिए पर्याप्त है।

## USB HID report की मूल बातें

Typical IN report इस प्रकार दिखती है:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, आदि)। एक साथ कई bits set हो सकती हैं। |
| 1 | Reserved/padding, लेकिन gaming keyboards में vendor data के लिए अक्सर reused होता है। |
| 2-7 | USB usage ID format में अधिकतम छह concurrent keycodes (`0x04 = a`, `0x1E = 1`)। `0x00` का अर्थ है "कोई key नहीं"। |

NKRO के बिना वाले keyboards byte 2 में आमतौर पर `0x01` भेजते हैं, जब छह से अधिक keys press की जाती हैं, ताकि "rollover" signal किया जा सके। इस layout को समझना तब उपयोगी होता है जब आपके पास केवल raw `usb.capdata` bytes हों।

## PCAP से HID data निकालना

### पहले keyboard interface की पहचान करें

Busy captures में reports dump करने से पहले HID keyboard की पहचान करें। शुरुआत करने का एक reliable तरीका interface descriptor response है:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass` और `usb.bInterfaceProtocol` देखें:

- `subclass == 1` और `protocol == 1` का सामान्य अर्थ boot keyboard होता है
- `protocol == 2` आमतौर पर mouse होता है
- `protocol == 0` का अक्सर अर्थ vendor-defined या NKRO-style HID interface होता है, जो keyboard data अभी भी carry करता है, लेकिन simple 8-byte boot layout में नहीं

Interface ज्ञात हो जाने के बाद, कुछ भी export करने से पहले अपने filters को `usb.bus_id`, `usb.device_address`, और यदि संभव हो तो `usb.interface_number` पर pin करें।

### Wireshark workflow

1. **Device को isolate करें**: keyboard से आने वाले interrupt IN traffic पर filter लगाएँ, जैसे `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`।
2. **उपयोगी columns जोड़ें**: हर frame खोले बिना keystrokes को follow करने के लिए `Leftover Capture Data` field (`usb.capdata`) और अपने पसंदीदा `usbhid.*` fields (जैसे `usbhid.boot_report.keyboard.keycode_1`) पर right-click करें।
3. **Empty reports छिपाएँ**: idle frames हटाने के लिए `!(usb.capdata == 00:00:00:00:00:00:00:00)` लागू करें।
4. **Post-processing के लिए export करें**: `File -> Export Packet Dissections -> As CSV` चुनें और बाद में reconstruction को script करने के लिए `frame.number`, `usb.src`, `usb.capdata`, और `usbhid.modifiers` शामिल करें।

### Command-line workflow

`ctf-usb-keyboard-parser` classic tshark + sed pipeline को पहले से automate करता है:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
नए captures में आप प्रति device बैच बनाकर `usb.capdata` और अधिक विस्तृत `usbhid.data` field दोनों रख सकते हैं:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
वे per-device files सीधे किसी भी decoder में डाले जा सकते हैं। यदि capture BLE keyboards से आया है जिन्हें GATT पर tunneled किया गया था, तो `btatt.value && frame.len == 20` पर filter करें और decoding से पहले hex payloads dump करें।

### जब report classic 8-byte boot report न हो

Recent gaming keyboards, split keyboards और composite HID devices अक्सर ऐसा non-boot keyboard interface expose करते हैं, जिसमें payload अब `modifier,reserved,key1..key6` से match नहीं करता।

- जब Wireshark ने HID layer को पहले ही parse कर लिया हो, तो `usb.capdata` की जगह `usbhid.data` को प्राथमिकता दें।
- यदि हर line constant prefix या report ID से शुरू होती है, तो byte 0 को हमेशा modifier मानने के बजाय offset-aware decoder का उपयोग करके उसे strip करें।
- कुछ USBPcap exports reserved byte को omit कर देते हैं, इसलिए `--no-reserved` या custom offset support करने वाले decoders समय बचाते हैं।
- यदि HID report descriptor या BLE HOGP report map capture में मौजूद है, तो parser लिखने से पहले actual field layout recover करने के लिए उसका उपयोग करें।

## Decoding को automate करना

- **ctf-usb-keyboard-parser** quick CTF challenges के लिए अब भी उपयोगी है और repository में पहले से शामिल है।<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) `pcap` और `pcapng` files को natively parse करता है, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` को समझता है और tshark की आवश्यकता नहीं होती, इसलिए यह isolated sandboxes में अच्छी तरह काम करता है।<sup>[[4]](#references)</sup>
- **USB-HID-decoders** keyboard, mouse और tablet visualizers जोड़ता है। आप `extract_hid_data.sh` helper (tshark backend) या `extract_hid_data.py` (scapy backend) चला सकते हैं और फिर resulting text file को decoder या replay modules में feed करके keystrokes को unfold होते हुए देख सकते हैं।<sup>[[5]](#references)</sup>

### Stateful decoding महत्वपूर्ण है

USB interrupt captures में आमतौर पर key press और release event आने से पहले उसी report की एक या अधिक repeated copies दोनों मौजूद होती हैं। एक practical decoder को यह करना चाहिए:<sup>[[2]](#references)</sup>

- previous report की तुलना में केवल newly pressed keycodes emit करना
- byte 0 या parsed `usbhid.boot_report.keyboard.modifier` field से modifier state (`Shift`, `Ctrl`, `AltGr`) बनाए रखना
- `Caps Lock` जैसी toggle keys को track करना, क्योंकि uppercase output केवल Shift से नियंत्रित नहीं होता
- यह याद रखना कि HID usage IDs layout-agnostic होते हैं: host keyboard layout के आधार पर `0x1d` physical `z`/`y` key position होती है

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
पहले dump की गई plain hex lines को इसमें feed करें, ताकि environment में full parser लाए बिना तुरंत एक rough reconstruction मिल सके। Non-US layouts के लिए यह अभी भी physical key position को reconstruct करता है, victim host पर दिखने वाला final glyph आवश्यक रूप से नहीं।

## Troubleshooting tips

- यदि Wireshark `usbhid.*` fields populate नहीं करता है, तो संभवतः HID report descriptor capture नहीं हुआ। Capture के दौरान keyboard को replug करें या raw `usb.capdata` पर fallback करें।
- Linux software captures में `usbmon` सामान्य source है; Windows पर raw USB URBs देखने के लिए Wireshark पूरी तरह **USBPcap** extcap पर निर्भर करता है।<sup>[[1]](#references)</sup>
- यदि keyboard किसी hub या dock के माध्यम से attached था, तो पहले interface descriptor की पुष्टि करें और फिर केवल उस device/interface pair को decode करें। Composite HID captures में keyboard और mouse reports अक्सर mix हो जाते हैं।
- Windows captures के लिए **USBPcap** extcap interface आवश्यक है; सुनिश्चित करें कि Wireshark upgrades के बाद यह मौजूद रहे, क्योंकि missing extcaps के कारण device lists खाली दिखाई देती हैं।<sup>[[1]](#references)</sup>
- किसी भी चीज़ को decode करने से पहले हमेशा `usb.bus_id:device:interface` (जैसे `1.9.1`) correlate करें — कई keyboards या storage devices को mix करने से nonsense keystrokes मिलते हैं।

## References

- [1] [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
