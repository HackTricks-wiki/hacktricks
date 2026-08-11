# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

다음과 같이 keyboard의 USB 통신이 포함된 pcap이 있다면:

![USB Keystrokes: 다음과 같이 keyboard의 USB 통신이 포함된 pcap이 있다면](<../../../images/image (962).png>)

**boot protocol**을 사용하는 keyboard에서 각 Interrupt IN report는 고정된 8바이트 구조를 갖습니다. 하나의 modifier byte, 하나의 reserved byte, 6개의 keycode byte로 구성됩니다. host는 연속된 report를 비교하고 keycode를 HID usage에 매핑하여 key event를 재구성합니다.<sup>[[8]](#references)</sup>

## USB HID report basics

표준 boot keyboard input report는 다음과 같이 구성됩니다.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt 등). 여러 bit를 동시에 설정할 수 있습니다. |
| 1 | Reserved byte. 사용하지 않는 report에서는 일반적으로 0으로 설정해야 합니다. OEM 또는 system별 용도는 이식성이 없습니다. |
| 2-7 | USB usage ID 형식의 최대 6개 동시 keycode (`0x04 = a`, `0x1E = 1`). `0x00`은 "키 없음"을 의미합니다. |

boot layout에서는 6개를 초과하는 non-modifier key가 눌리면 모든 key slot에 usage ID `0x01` (`Keyboard ErrorRollOver`)이 report됩니다. 또한 인식할 수 없는 조합을 나타낼 수도 있습니다.<sup>[[8]](#references)[[9]](#references)</sup> 이 layout을 이해하면 raw `usb.capdata` bytes만 가지고 있을 때 유용합니다.

## PCAP에서 HID data 추출

### 먼저 keyboard interface 식별

busy capture에서는 report를 dump하기 전에 HID keyboard를 식별해야 합니다. 신뢰할 수 있는 시작점은 interface descriptor response입니다.<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class는 다음 interface 값을 정의합니다:<sup>[[8]](#references)</sup>

- `subclass == 1`은 Boot Interface Subclass입니다. `protocol == 1`이면 boot keyboard를 식별합니다.
- `protocol == 2`는 boot mouse를 식별합니다.
- `protocol == 0`은 boot protocol이 없음을 의미합니다. 8바이트 레이아웃이라고 가정하지 말고 HID report descriptor를 확인하세요.

interface를 확인한 후에는 무언가를 export하기 전에 `usb.bus_id`, `usb.device_address`, 그리고 가능하다면 `usb.bInterfaceNumber`에 필터를 고정하세요.

### Wireshark workflow

1. **device 격리**: keyboard에서 발생한 interrupt IN traffic을 필터링합니다. 예: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **유용한 column 추가**: `Leftover Capture Data` field(`usb.capdata`)와 원하는 `usbhid.*` fields(예: `usbhid.boot_report.keyboard.keycode_1`)를 마우스 오른쪽 버튼으로 클릭해 column으로 추가하면 모든 frame을 열지 않고도 keystroke를 추적할 수 있습니다.<sup>[[11]](#references)</sup>
3. **비어 있는 report 숨기기**: `!(usb.capdata == 00:00:00:00:00:00:00:00)`을 적용해 idle frame을 제거합니다.
4. **post-processing을 위해 export**: `File -> Export Packet Dissections -> As CSV`를 선택하고 `frame.number`, `usb.src`, `usb.capdata`, 그리고 `usbhid.boot_report.keyboard.modifier.left_shift`, `usbhid.boot_report.keyboard.modifier.right_alt`와 같은 decoded modifier fields를 포함하세요. 그러면 나중에 script로 reconstruction을 수행할 수 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

### Command-line workflow

`usb.capdata`를 dump하고, idle report를 제거한 다음, usage ID를 매핑하는 고전적인 extraction pattern은 2017년 원본 analysis와 그 walkthrough에 나와 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository는 고전적인 tshark + sed pipeline을 자동화합니다:<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
최신 캡처에서는 Wireshark의 디코딩된 `usbhid.data` 필드를 우선 사용하고, `usb.capdata`로 대체합니다. 장치별 파일에 리포트당 하나의 payload를 기록합니다.<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
이러한 디바이스별 파일은 예상되는 hex 형식으로 정규화한 후 decoder에 전달할 수 있습니다. 캡처가 GATT를 통해 터널링된 BLE keyboards에서 생성된 것이라면, `btatt.value && frame.len == 20`으로 필터링하고 디코딩하기 전에 hex payload를 덤프하세요.<sup>[[7]](#references)</sup>

### report가 일반적인 8바이트 boot report가 아닌 경우

non-boot 인터페이스나 report ID에 따라 payload layout이 변경될 수 있으므로, 모든 keyboard report가 `modifier,reserved,key1..key6` 형식이라고 가정하지 마세요.<sup>[[8]](#references)[[11]](#references)</sup>

- Wireshark가 이미 HID layer를 파싱한 경우에는 `usb.capdata`보다 `usbhid.data`를 우선 사용하세요.
- 모든 줄이 일정한 prefix 또는 report ID로 시작한다면, 항상 byte 0이 modifier라고 가정하지 말고 offset을 인식하는 decoder로 해당 부분을 제거하세요.<sup>[[7]](#references)</sup>
- 일부 USBPcap export에서는 reserved byte가 누락되므로, `--no-reserved`를 지원하는 decoder나 custom offset을 사용하면 시간을 절약할 수 있습니다.<sup>[[7]](#references)</sup>
- 캡처에 HID report descriptor 또는 BLE HOGP report map이 포함되어 있다면, parser를 작성하기 전에 이를 사용해 실제 field layout을 복원하세요.

## decoding 자동화

- **ctf-usb-keyboard-parser**는 빠른 CTF challenges에 여전히 유용하며 repository에 이미 포함되어 있습니다.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`)는 `pcap` 및 `pcapng` 파일을 native로 파싱하고, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`을 이해하며, tshark나 다른 external dependency를 요구하지 않으므로 isolated sandbox에 적합합니다.<sup>[[6]](#references)</sup>
- **USB-HID-decoders**는 keyboard, mouse, tablet visualizer를 추가합니다. `extract_hid_data.sh` helper(tshark backend) 또는 `extract_hid_data.py`(scapy backend)를 실행한 다음, 결과 text file을 decoder 또는 replay module에 전달하여 keystroke가 입력되는 과정을 확인할 수 있습니다.<sup>[[7]](#references)</sup>

### Stateful decoding의 중요성

USB boot keyboard는 새로운 key event가 없을 때에도 idle rate에 따라 report를 전송하므로, 캡처에는 release event가 발생하기 전에 동일한 report가 반복되어 포함될 수 있습니다. 실용적인 decoder는 다음을 수행해야 합니다.<sup>[[3]](#references)[[8]](#references)</sup>

- 이전 report와 비교하여 새로 눌린 keycode만 출력
- byte 0 또는 `usbhid.boot_report.keyboard.modifier.left_shift`, `usbhid.boot_report.keyboard.modifier.right_alt`와 같이 파싱된 field에서 modifier state(`Shift`, `Ctrl`, `AltGr`) 유지
- `Caps Lock`과 같은 toggle key 추적: 대문자 출력은 Shift만으로 제어되지 않기 때문
- HID usage ID는 layout과 무관하다는 점을 기억: `0x1d`는 host keyboard layout에 따라 물리적인 `z`/`y` key 위치를 나타냅니다.<sup>[[9]](#references)</sup>

## 간단한 Python decoder
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
이전에 덤프한 일반 hex 줄을 입력하면 전체 parser를 환경에 가져오지 않고도 즉시 대략적인 재구성을 수행할 수 있습니다. US 이외의 레이아웃에서는 victim host에 최종적으로 표시된 glyph가 아니라 물리적인 키 위치가 재구성됩니다.

## Troubleshooting tips

- Wireshark가 `usbhid.*` 필드를 채우지 않는다면 HID report descriptor가 캡처되지 않았을 가능성이 높습니다. 캡처 중 keyboard를 다시 연결하거나 raw `usb.capdata`로 대체하세요.
- Linux software capture에서는 `usbmon`이 일반적인 source입니다. Windows에서는 raw USB URB를 확인하려면 Wireshark가 **USBPcap** extcap에 의존합니다.<sup>[[4]](#references)</sup>
- keyboard가 hub 또는 dock을 통해 연결된 경우 먼저 interface descriptor를 확인한 다음 해당 device/interface pair만 decode하세요. Composite HID capture에는 keyboard와 mouse report가 자주 섞입니다.
- Windows capture에는 **USBPcap** extcap interface가 필요합니다. Wireshark upgrade 후에도 해당 interface가 유지되었는지 확인하세요. extcap이 없으면 device list가 비어 있게 됩니다.<sup>[[4]](#references)</sup>
- 무엇이든 decode하기 전에 항상 bus, device, interface tuple(`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; 예: `1.9.1`)을 대조하세요. 여러 keyboard 또는 storage device를 섞으면 의미 없는 keystroke가 발생합니다.<sup>[[10]](#references)</sup>

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
