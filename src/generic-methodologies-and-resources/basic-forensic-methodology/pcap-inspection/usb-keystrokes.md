# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

अगर आपके पास ऐसा pcap है जिसमें किसी keyboard का USB के ज़रिए हुआ communication शामिल है:

![USB Keystrokes: अगर आपके पास ऐसा pcap है जिसमें किसी keyboard का USB के ज़रिए हुआ communication शामिल है](<../../../images/image (962).png>)

HID **boot protocol** का इस्तेमाल करने वाले keyboard में, हर Interrupt IN report का layout तयशुदा 8-byte का होता है: एक modifier byte, एक reserved byte और छह keycode bytes। Host लगातार आने वाली reports की तुलना करता है और key events को फिर से बनाने के लिए keycodes को HID usages से मैप करता है।<sup>[[8]](#references)</sup>

सामान्य capture triage के लिए, [Pcap Inspection](./) देखें।

## USB HID report की मूल बातें

Standard boot keyboard input report की संरचना इस प्रकार होती है।<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | अर्थ |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt, आदि)। एक साथ कई bits सेट हो सकते हैं। |
| 1 | Reserved byte; आम तौर पर, इस्तेमाल न होने वाली reports में इसे zero पर सेट किया जाना चाहिए। OEM या system-specific इस्तेमाल portable नहीं होता। |
| 2-7 | USB usage ID format में अधिकतम छह एक साथ दबाए गए keycodes (`0x04 = a`, `0x1E = 1`)। `0x00` का अर्थ है "कोई key नहीं"। | 

Boot layout में, जब छह से अधिक non-modifier keys दबाई जाती हैं, तो usage ID `0x01` (`Keyboard ErrorRollOver`) सभी key slots में report होता है; यह किसी ऐसी combination का संकेत भी दे सकता है जिसे पहचाना न जा सके।<sup>[[8]](#references)[[9]](#references)</sup> जब आपके पास केवल raw `usb.capdata` bytes हों, तब इस layout को समझना मददगार होता है।

## PCAP से HID data निकालना

### पहले keyboard interface पहचानें

व्यस्त captures में, कोई भी reports dump करने से पहले HID keyboard की पहचान करें। शुरुआत के लिए interface descriptor response एक भरोसेमंद तरीका है:<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID class इन interface values को परिभाषित करती है:<sup>[[8]](#references)</sup>

- `subclass == 1` Boot Interface Subclass है; `protocol == 1` के साथ यह boot keyboard की पहचान करता है
- `protocol == 2` boot mouse की पहचान करता है
- `protocol == 0` का अर्थ है कि boot protocol नहीं है; 8-byte layout मानने के बजाय HID report descriptor की जाँच करें

Boot-capable interface होना **इस बात का प्रमाण नहीं है कि boot protocol सक्रिय है**। HID devices report protocol में initialize होते हैं। Host, `SET_PROTOCOL` (`bRequest = 0x0b`, `wValue = 0`) से boot mode चुनता है; `wValue = 1` से report protocol चुना जाता है। यदि capture में enumeration शामिल है, तो eight-byte boot decoder का उपयोग करने से पहले keyboard interface (`wIndex`) के लिए request जाँचें। यदि वह मौजूद नहीं है, तो interface descriptor से mode का अनुमान लगाने के बजाय देखे गए report layout की पुष्टि करें।<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

इंटरफ़ेस की जानकारी मिल जाने के बाद, कुछ भी export करने से पहले अपने filters को `usb.bus_id`, `usb.device_address`, और यदि संभव हो तो `usb.bInterfaceNumber` पर सेट करें।

### Wireshark workflow

1. **डिवाइस को अलग करें**: keyboard से आने वाले interrupt IN traffic पर filter लगाएँ, जैसे `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`।
2. **उपयोगी columns जोड़ें**: हर frame खोले बिना keystrokes देखने के लिए `Leftover Capture Data` field (`usb.capdata`) और अपने पसंदीदा `usbhid.*` fields (जैसे `usbhid.boot_report.keyboard.keycode_1`) पर right-click करें।<sup>[[11]](#references)</sup>
3. **खाली reports छिपाएँ**: idle frames हटाने के लिए `!(usb.capdata == 00:00:00:00:00:00:00:00)` लागू करें।
4. **Post-processing के लिए export करें**: बाद में reconstruction को script करने के लिए `File -> Export Packet Dissections -> As CSV` चुनें और `frame.number`, `usb.src`, `usb.capdata`, तथा decoded modifier fields, जैसे `usbhid.boot_report.keyboard.modifier.left_shift` और `usbhid.boot_report.keyboard.modifier.right_alt`, शामिल करें।<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

`usb.capdata` dump करने, idle reports हटाने और usage IDs map करने वाला पारंपरिक extraction pattern मूल 2017 analysis और उसके walkthrough में दिखाई देता है।<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository पारंपरिक tshark + sed pipeline को automate करता है:<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

नए captures में, Wireshark के decoded `usbhid.data` field को प्राथमिकता दें और उपलब्ध न होने पर `usb.capdata` का उपयोग करें; हर report का एक payload प्रति-device file में लिखें:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

इन per-device files को अपेक्षित hex format में normalize करने के बाद decoder में दिया जा सकता है। अगर capture BLE keyboards से आया है, जिनका traffic GATT के ज़रिए tunnel किया गया है, तो `btatt.value && frame.len == 20` से filter करें और decoding से पहले hex payloads dump करें।<sup>[[7]](#references)</sup>

### जब report सामान्य 8-byte boot report न हो

Non-boot interface या report ID payload layout बदल सकता है, इसलिए यह न मानें कि हर keyboard report का format `modifier,reserved,key1..key6` से मेल खाता है।<sup>[[8]](#references)[[11]](#references)</sup>

- अगर Wireshark ने HID layer को पहले ही parse कर लिया है, तो `usb.capdata` के बजाय `usbhid.data` को प्राथमिकता दें।
- अगर हर line किसी constant prefix या report ID से शुरू होती है, तो byte 0 को हमेशा modifier मानने के बजाय offset-aware decoder से उसे हटाएँ।<sup>[[7]](#references)</sup>
- कुछ USBPcap exports में reserved byte शामिल नहीं होता, इसलिए `--no-reserved` या custom offset को support करने वाले decoders से समय बचता है।<sup>[[7]](#references)</sup>
- अगर capture में HID report descriptor या BLE HOGP report map मौजूद है, तो parser लिखने से पहले उससे actual field layout पता करें।

### Report-protocol key bitmap को decode करें

ऐसे keyboard के लिए जिसका input report छह boot key slots के बजाय bitmap हो, enumeration traffic में उसका **HID report descriptor** ढूँढें। यह filter वे frames खोजता है जिनमें Wireshark ने Report Size item decode किया हो; उनमें से किसी एक को खोलें और पूरा descriptor देखें। अगर descriptor मौजूद न हो, तो keyboard plug in करने से पहले नया capture शुरू करें।<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

हर keyboard Input report के लिए उसका `Report ID` (यदि हो), `Usage Page` (keyboard keys के लिए `0x07`), `Usage Minimum/Maximum`, `Report Size`, `Report Count`, और यह नोट करें कि प्रत्येक `Input` item **Variable** है या **Array**। Key field का bit offset पता करने के लिए उससे पहले के सभी Input fields और constant padding को गिनें; report fields का byte-aligned होना ज़रूरी नहीं है। लगातार keyboard usages वाला one-bit Variable field, key-state bitmap होता है: उस field का bit 0 उसके पहले घोषित usage से, bit 1 अगले usage से, और इसी तरह आगे के usages से मेल खाता है। इसके बजाय, Array में ऐसे values होते हैं जिन्हें descriptor की usage range के ज़रिए resolve किया जाता है; इसमें हर bit एक दबाई हुई key को नहीं दर्शाता। यदि `Report ID` घोषित है, तो पहले उस prefix वाले reports चुनें और field offsets की गणना करते समय उसका byte छोड़ दें। केवल नई presses निकालने के लिए, एक ही interface और `Report ID` वाले लगातार reports के held-usage sets की तुलना करें।<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## Decoding को स्वचालित करना

- **ctf-usb-keyboard-parser** त्वरित CTF challenges के लिए अब भी उपयोगी है और repository में पहले से शामिल है।<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) `pcap` और `pcapng` files—दोनों को native रूप से parse करता है, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap` को समझता है और इसे tshark या किसी अन्य external dependency की ज़रूरत नहीं होती, इसलिए यह isolated sandboxes के लिए उपयुक्त है।<sup>[[6]](#references)</sup>
- **USB-HID-decoders** में keyboard, mouse और tablet visualizers शामिल हैं। आप `extract_hid_data.sh` helper (tshark backend) या `extract_hid_data.py` (scapy backend) चला सकते हैं, फिर परिणामी text file को decoder या replay modules में देकर keystrokes को unfold होते हुए देख सकते हैं।<sup>[[7]](#references)</sup>

### Stateful decoding महत्वपूर्ण है

USB boot keyboards, idle rate पर reports भेजते हैं, भले ही कोई नया key event न हो। इसलिए captures में release event से पहले बार-बार भेजे गए reports हो सकते हैं। एक व्यावहारिक decoder को चाहिए कि वह:<sup>[[3]](#references)[[8]](#references)</sup>

- पिछले report की तुलना में केवल नए दबाए गए keycodes emit करे
- byte 0 या `usbhid.boot_report.keyboard.modifier.left_shift` और `usbhid.boot_report.keyboard.modifier.right_alt` जैसे parsed fields से modifier state (`Shift`, `Ctrl`, `AltGr`) बनाए रखे
- `Caps Lock` जैसी toggle keys को track करे, क्योंकि uppercase output केवल Shift से नियंत्रित नहीं होता
- याद रखे कि HID usage IDs keyboard layout से स्वतंत्र होते हैं: host keyboard layout के अनुसार `0x1d` भौतिक `z`/`y` key position को दर्शाता है।<sup>[[9]](#references)</sup>

## त्वरित Python decoder

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

पहले dump की गई plain hex lines को इसमें feed करें, ताकि पूरा parser environment में लाए बिना तुरंत एक मोटा reconstruction मिल जाए। गैर-US layouts के लिए यह victim host पर दिखने वाले अंतिम glyph के बजाय physical key position का reconstruction करता है।

## Troubleshooting tips

- अगर Wireshark `usbhid.*` fields नहीं भरता, तो संभवतः HID report descriptor capture नहीं हुआ था। Capture के दौरान keyboard को फिर से plug करें या raw `usb.capdata` पर जाएँ।
- Linux software captures में `usbmon` सामान्य source है; Windows पर raw USB URBs देखने के लिए Wireshark को **USBPcap** extcap की ज़रूरत होती है।<sup>[[4]](#references)</sup>
- अगर keyboard किसी hub या dock के ज़रिए जुड़ा था, तो पहले interface descriptor की पुष्टि करें और फिर केवल उस device/interface pair को decode करें। Composite HID captures में अक्सर keyboard और mouse reports आपस में मिल जाते हैं।
- Windows captures के लिए **USBPcap** extcap interface आवश्यक है; सुनिश्चित करें कि Wireshark upgrades के बाद भी यह मौजूद हो, क्योंकि extcaps गायब होने पर device lists खाली रह जाती हैं।<sup>[[4]](#references)</sup>
- कुछ भी decode करने से पहले bus, device और interface tuple (`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; जैसे `1.9.1`) का हमेशा मिलान करें — कई keyboards या storage devices को मिलाने से बेतुके keystrokes मिलते हैं।<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB Keyboard पैकेट कैप्चर विश्लेषण](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB capture सेटअप](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Human Interface Devices (HID) 1.11 के लिए Device Class Definition](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux kernel: HID report descriptors का परिचय](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboard writeup](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
