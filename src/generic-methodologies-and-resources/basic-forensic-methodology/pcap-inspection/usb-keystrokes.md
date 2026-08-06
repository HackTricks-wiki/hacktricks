# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

다음과 같이 USB를 통한 키보드 통신이 포함된 pcap이 있는 경우:

![USB Keystrokes: USB를 통한 키보드 통신이 포함된 pcap이 있는 경우](<../../../images/image (962).png>)

USB 키보드는 일반적으로 HID **boot protocol**을 사용하므로, 호스트로 향하는 모든 interrupt transfer는 길이가 8바이트뿐입니다. 여기에는 modifier 비트(Ctrl/Shift/Alt/Super) 1바이트, 예약된 바이트 1개, 그리고 report마다 최대 6개의 keycode가 포함됩니다. 이 바이트들을 디코딩하면 입력된 모든 내용을 재구성할 수 있습니다.

## USB HID report basics

일반적인 IN report는 다음과 같습니다.

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt 등). 여러 비트가 동시에 설정될 수 있습니다. |
| 1 | 예약된/padding 바이트이지만 gaming keyboard에서는 vendor data로 재사용되는 경우가 많습니다. |
| 2-7 | USB usage ID 형식의 동시 keycode 최대 6개 (`0x04 = a`, `0x1E = 1`). `0x00`은 "no key"를 의미합니다. |

NKRO를 지원하지 않는 키보드는 일반적으로 6개보다 많은 키가 눌렸을 때 byte 2에 `0x01`을 전송하여 "rollover"를 나타냅니다. 이 구조를 이해하면 raw `usb.capdata` 바이트만 있는 경우에도 분석할 수 있습니다.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

busy capture에서는 report를 덤프하기 전에 HID keyboard를 식별해야 합니다. 신뢰할 수 있는 시작점은 interface descriptor response입니다:<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass`와 `usb.bInterfaceProtocol`을 확인합니다.

- `subclass == 1` 및 `protocol == 1`은 일반적으로 boot keyboard를 의미합니다.
- `protocol == 2`는 일반적으로 mouse입니다.
- `protocol == 0`은 단순한 8바이트 boot 레이아웃이 아닌 방식으로도 keyboard data를 전달하는 vendor-defined 또는 NKRO-style HID interface를 의미하는 경우가 많습니다.

interface를 확인한 후에는 무언가를 export하기 전에 가능한 경우 `usb.bus_id`, `usb.device_address`, `usb.interface_number`를 기준으로 filter를 고정합니다.

### Wireshark workflow

1. **device 격리**: keyboard의 interrupt IN traffic을 filter합니다. 예: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`
2. **유용한 column 추가**: `Leftover Capture Data` field(`usb.capdata`)와 원하는 `usbhid.*` field(예: `usbhid.boot_report.keyboard.keycode_1`)를 마우스 오른쪽 버튼으로 클릭하여 추가하면 모든 frame을 열지 않고도 keystroke를 추적할 수 있습니다.
3. **빈 report 숨기기**: `!(usb.capdata == 00:00:00:00:00:00:00:00)`를 적용하여 idle frame을 제거합니다.
4. **post-processing을 위해 export**: `File -> Export Packet Dissections -> As CSV`를 사용하고, 나중에 reconstruction을 script로 처리할 수 있도록 `frame.number`, `usb.src`, `usb.capdata`, `usbhid.modifiers`를 포함합니다.

### Command-line workflow

`ctf-usb-keyboard-parser`는 기존의 tshark + sed pipeline을 이미 자동화합니다:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
최신 캡처에서는 장치별로 일괄 처리하여 `usb.capdata`와 더 풍부한 `usbhid.data` 필드를 모두 유지할 수 있습니다:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
이러한 장치별 파일은 어떤 decoder에도 바로 입력할 수 있습니다. 캡처가 GATT를 통해 터널링된 BLE keyboards에서 생성된 것이라면, `btatt.value && frame.len == 20`으로 필터링한 다음 hex payload를 추출하고 decoding하세요.

### report가 classic 8-byte boot report가 아닌 경우

최근 gaming keyboards, split keyboards 및 composite HID devices는 payload가 더 이상 `modifier,reserved,key1..key6`과 일치하지 않는 non-boot keyboard interface를 제공하는 경우가 많습니다.

- Wireshark가 이미 HID layer를 parsing했다면 `usb.capdata`보다 `usbhid.data`를 우선 사용하세요.
- 모든 줄이 constant prefix 또는 report ID로 시작한다면 byte 0이 항상 modifier라고 가정하지 말고 offset-aware decoder로 이를 제거하세요.
- 일부 USBPcap exports는 reserved byte를 생략하므로, `--no-reserved`를 지원하는 decoder나 custom offset을 사용하면 시간을 절약할 수 있습니다.
- HID report descriptor 또는 BLE HOGP report map이 capture에 포함되어 있다면, parser를 작성하기 전에 이를 사용해 실제 field layout을 복원하세요.

## decoding 자동화

- **ctf-usb-keyboard-parser**는 빠른 CTF challenges에 여전히 유용하며 repository에 이미 포함되어 있습니다.<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`)는 `pcap` 및 `pcapng` files를 native parsing하고, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`을 이해하며, tshark가 필요하지 않으므로 isolated sandboxes 내부에서 사용하기 좋습니다.<sup>[[4]](#references)</sup>
- **USB-HID-decoders**는 keyboard, mouse 및 tablet visualizers를 추가합니다. `extract_hid_data.sh` helper (tshark backend) 또는 `extract_hid_data.py` (scapy backend)를 실행한 다음, 생성된 text file을 decoder 또는 replay modules에 입력하여 keystrokes가 전개되는 과정을 확인할 수 있습니다.<sup>[[5]](#references)</sup>

### Stateful decoding이 중요한 이유

USB interrupt captures에는 일반적으로 key press와 release event가 도착하기 전까지 동일한 report가 한 번 이상 반복된 복사본이 모두 포함됩니다. 실용적인 decoder는 다음을 수행해야 합니다:<sup>[[2]](#references)</sup>

- 이전 report와 비교하여 새로 눌린 keycodes만 emit
- byte 0 또는 parsing된 `usbhid.boot_report.keyboard.modifier` field에서 modifier state (`Shift`, `Ctrl`, `AltGr`) 유지
- `Caps Lock`과 같은 toggle keys를 추적. 대문자 output은 Shift만으로 제어되지 않기 때문
- HID usage IDs는 layout-agnostic이라는 점을 기억: `0x1d`는 host keyboard layout에 따라 물리적인 `z`/`y` key position

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
앞서 덤프한 일반 hex 줄을 입력하면 전체 parser를 환경에 추가하지 않고도 즉시 대략적인 재구성을 수행할 수 있습니다. US 레이아웃이 아닌 경우에도 이는 victim host에 표시되는 최종 glyph가 아니라 물리적인 key position을 재구성합니다.

## 문제 해결 팁

- Wireshark에 `usbhid.*` 필드가 채워지지 않는다면 HID report descriptor가 캡처되지 않았을 가능성이 높습니다. 캡처 중 keyboard를 다시 연결하거나 raw `usb.capdata`로 대체하세요.
- Linux software capture에서는 `usbmon`이 일반적인 source입니다. Windows에서는 raw USB URB를 확인하려면 Wireshark가 **USBPcap** extcap에 의존합니다.<sup>[[1]](#references)</sup>
- keyboard가 hub 또는 dock을 통해 연결되었다면 먼저 interface descriptor를 확인한 다음 해당 device/interface pair만 decode하세요. Composite HID capture에는 keyboard와 mouse report가 자주 섞입니다.
- Windows capture에는 **USBPcap** extcap interface가 필요합니다. Wireshark upgrade 후에도 이것이 유지되었는지 확인하세요. extcap이 없으면 device list가 비어 있게 됩니다.<sup>[[1]](#references)</sup>
- 무엇이든 decode하기 전에 항상 `usb.bus_id:device:interface`(예: `1.9.1`)를 correlate하세요 — 여러 keyboard 또는 storage device를 섞으면 잘못된 keystroke가 발생합니다.

## 참고 자료

- [1] [Wireshark USB capture 설정](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
