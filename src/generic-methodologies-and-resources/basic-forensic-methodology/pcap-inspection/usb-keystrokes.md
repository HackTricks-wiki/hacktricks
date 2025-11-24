# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

यदि आपके पास किसी keyboard के USB संचार वाला pcap है जो नीचे दिखाए गए जैसा है:

![](<../../../images/image (962).png>)

USB keyboards आमतौर पर HID **boot protocol** बोलते हैं, इसलिए host की तरफ हर interrupt transfer केवल 8 bytes लंबा होता है: एक byte modifier बिट्स के लिए (Ctrl/Shift/Alt/Super), एक reserved byte, और हर report में अधिकतम छह keycodes। इन bytes को डिकोड करना टाइप की गई सभी चीज़ों को पुनर्निर्मित करने के लिए काफी होता है।

## USB HID रिपोर्ट मूल बातें

टिपिकल IN रिपोर्ट कुछ ऐसी दिखती है:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

NKRO के बिना keyboards आमतौर पर तब byte 2 में `0x01` भेजते हैं जब छह से अधिक कीज़ दबाई जाती हैं ताकि "rollover" संकेतित किया जा सके। जब आपके पास केवल raw `usb.capdata` bytes हों तो इस लेआउट को समझना मददगार होता है।

## PCAP से HID डेटा निकालना

### Wireshark workflow

1. **डिवाइस को अलग करें**: keyboard से आने वाले interrupt IN ट्रैफ़िक पर फ़िल्टर लगाएँ, जैसे `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **उपयोगी कॉलम जोड़ें**: `Leftover Capture Data` फ़ील्ड (`usb.capdata`) और अपनी पसंदीदा `usbhid.*` फ़ील्ड्स (जैसे `usbhid.boot_report.keyboard.keycode_1`) पर right-click करके हर frame खोले बिना keystrokes को फॉलो करें।
3. **खाली रिपोर्ट छुपाएँ**: idle frames हटाने के लिए `!(usb.capdata == 00:00:00:00:00:00:00:00)` लागू करें।
4. **पोस्ट-प्रोसेसिंग के लिए एक्सपोर्ट करें**: `File -> Export Packet Dissections -> As CSV`, और बाद में reconstruction स्क्रिप्टिंग के लिए `frame.number`, `usb.src`, `usb.capdata`, और `usbhid.modifiers` शामिल करें।

### Command-line workflow

`ctf-usb-keyboard-parser` पहले से classic tshark + sed pipeline को automate कर देता है:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
नए कैप्चर में आप प्रति डिवाइस बैचिंग करके दोनों `usb.capdata` और अधिक समृद्ध `usbhid.data` फ़ील्ड रख सकते हैं:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
वे per-device फ़ाइलें सीधे किसी भी decoder में डाल दी जाती हैं। यदि capture BLE keyboards से आया है जो GATT पर tunneled हैं, तो `btatt.value && frame.len == 20` पर filter करें और decoding से पहले hex payloads को dump करें।

## Decoding को स्वचालित करना

- **ctf-usb-keyboard-parser** तेज़ CTF चुनौतियों के लिए उपयोगी रहता है और पहले से ही repository में शामिल आता है।
- **CTF-Usb_Keyboard_Parser** (`main.py`) मूल रूप से दोनों `pcap` और `pcapng` फाइलों को parse करता है, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` को समझता है, और tshark की आवश्यकता नहीं है, इसलिए यह isolated sandboxes के अंदर अच्छी तरह काम करता है।
- **USB-HID-decoders** keyboard, mouse, और tablet visualizers जोड़ता है। आप या तो `extract_hid_data.sh` helper (tshark backend) या `extract_hid_data.py` (scapy backend) चला सकते हैं और फिर resulting text file को decoder या replay modules को feed करके keystrokes unfold होते हुए देख सकते हैं।

## तेज़ Python decoder
```python
#!/usr/bin/env python3
import sys
HID = {0x04:'a',0x05:'b',0x06:'c',0x07:'d',0x08:'e',0x09:'f',0x0a:'g',0x1c:'y',0x1d:'z',0x28:'\n'}
for raw in sys.stdin:
raw = raw.strip().replace(':', '')
if len(raw) != 16:
continue
keycode = int(raw[4:6], 16)
modifier = int(raw[0:2], 16)
if keycode:
char = HID.get(keycode, '?')
if modifier & 0x02:
char = char.upper()
sys.stdout.write(char)
```
इसे पहले डंप की गई साधारण hex लाइनों से फीड करें ताकि पूरे parser को environment में लाए बिना आप तुरंत एक मोटा पुनर्निर्माण प्राप्त कर सकें।

## Troubleshooting tips

- यदि Wireshark `usbhid.*` फील्ड भर नहीं रहा है, तो संभवतः HID report descriptor कैप्चर नहीं हुआ था। कैप्चर करते समय कीबोर्ड को फिर से प्लग करें या raw `usb.capdata` पर वापस लौटें।
- Windows captures के लिए **USBPcap** extcap interface चाहिए; सुनिश्चित करें कि यह Wireshark अपग्रेड्स के बाद भी मौजूद है, क्योंकि extcaps गायब होने पर डिवाइस सूचियाँ खाली रह जाती हैं।
- किसी भी चीज़ को डिकोड करने से पहले हमेशा `usb.bus_id:device:interface` (उदा. `1.9.1`) को correlate करें — एक से अधिक कीबोर्ड या स्टोरेज डिवाइस को मिलाने से बेतुके कीस्ट्रोक्स मिलते हैं।

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
