# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

키보드의 USB 통신이 포함된 pcap이 있다면, 아래와 같은 경우를 생각해볼 수 있습니다:

![](<../../../images/image (962).png>)

USB 키보드는 보통 HID **boot protocol**을 사용하므로, host로 향하는 모든 interrupt transfer는 길이가 8 bytes뿐입니다: modifier bits(Ctrl/Shift/Alt/Super) 1 byte, reserved byte 1 byte, 그리고 report당 최대 6개의 keycode입니다. 이 bytes를 디코딩하면 입력된 모든 내용을 재구성할 수 있습니다.

## USB HID report basics

일반적인 IN report는 다음과 같습니다:

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

NKRO가 없는 키보드는 보통 6개를 초과하는 키가 눌리면 byte 2에 `0x01`을 보내 "rollover"를 알립니다. 이 레이아웃을 이해하면 raw `usb.capdata` bytes만 있어도 내용을 복원하는 데 도움이 됩니다.

## Extracting HID data from a PCAP

### Identify the keyboard interface first

바쁜 capture에서는 어떤 report도 덤프하기 전에 먼저 HID keyboard를 식별하세요. 신뢰할 수 있는 시작점은 interface descriptor response입니다:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
`usb.bInterfaceSubClass`와 `usb.bInterfaceProtocol`을 확인하세요:

- `subclass == 1` 그리고 `protocol == 1`은 보통 boot keyboard를 의미합니다
- `protocol == 2`는 일반적으로 mouse입니다
- `protocol == 0`은 종종 vendor-defined 또는 NKRO-style HID interface를 의미하며, 여전히 keyboard data를 담고 있지만 단순한 8-byte boot layout은 아닙니다

interface를 알게 되면, 무엇인가를 export하기 전에 필터를 `usb.bus_id`, `usb.device_address`, 가능하면 `usb.interface_number`에 고정하세요.

### Wireshark workflow

1. **device를 분리**: keyboard에서 오는 interrupt IN traffic만 필터링합니다. 예: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **유용한 columns 추가**: `Leftover Capture Data` field (`usb.capdata`)와 선호하는 `usbhid.*` fields(예: `usbhid.boot_report.keyboard.keycode_1`)를 right-click하여 모든 frame을 열지 않고도 keystrokes를 따라가세요.
3. **빈 reports 숨기기**: idle frames를 제거하려면 `!(usb.capdata == 00:00:00:00:00:00:00:00)`를 적용하세요.
4. **post-processing용 export**: `File -> Export Packet Dissections -> As CSV`를 사용하고, 나중에 reconstruction을 script로 처리할 수 있도록 `frame.number`, `usb.src`, `usb.capdata`, `usbhid.modifiers`를 포함하세요.

### Command-line workflow

`ctf-usb-keyboard-parser`는 이미 전형적인 tshark + sed pipeline을 자동화합니다:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
새로운 캡처에서는 장치별로 배치하여 `usb.capdata`와 더 풍부한 `usbhid.data` 필드를 모두 유지할 수 있습니다:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
그런 per-device 파일은 어떤 decoder에도 바로 넣을 수 있습니다. capture가 GATT를 통해 터널링된 BLE keyboard에서 나온 것이라면 `btatt.value && frame.len == 20`로 filter한 뒤 decoding 전에 hex payload를 dump하세요.

### report가 classic 8-byte boot report가 아닐 때

최근 gaming keyboard, split keyboard, composite HID device는 종종 payload가 더 이상 `modifier,reserved,key1..key6`와 일치하지 않는 non-boot keyboard interface를 노출합니다.

- Wireshark가 이미 HID layer를 parsed했다면 `usb.capdata`보다 `usbhid.data`를 우선하세요.
- 모든 line이 constant prefix나 report ID로 시작한다면, byte 0이 항상 modifier라고 가정하지 말고 offset-aware decoder로 strip하세요.
- 일부 USBPcap export는 reserved byte를 생략하므로 `--no-reserved`를 지원하는 decoder나 custom offset이 시간을 절약해 줍니다.
- capture에 HID report descriptor나 BLE HOGP report map이 있으면, parser를 작성하기 전에 그것을 사용해 실제 field layout을 복구하세요.

## decoding 자동화

- **ctf-usb-keyboard-parser**는 빠른 CTF challenge에 여전히 유용하며 이미 repository에 포함되어 있습니다.
- **CTF-Usb_Keyboard_Parser** (`main.py`)는 `pcap`과 `pcapng` 파일을 모두 native하게 parse하고, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`을 이해하며, tshark가 필요하지 않아서 isolated sandbox 안에서도 잘 동작합니다.
- **USB-HID-decoders**는 keyboard, mouse, tablet visualizer를 추가합니다. `extract_hid_data.sh` helper(tshark backend) 또는 `extract_hid_data.py`(scapy backend)를 실행한 뒤, 생성된 text file을 decoder나 replay module에 넣어 keystroke가 펼쳐지는 모습을 볼 수 있습니다.

### Stateful decoding이 중요합니다

USB interrupt capture에는 보통 key press와 release event가 도착하기 전까지 같은 report의 repeated copy가 하나 이상 함께 들어 있습니다. 실용적인 decoder는 다음을 해야 합니다.

- 이전 report와 비교해서 새로 눌린 keycode만 출력
- byte 0 또는 parsed `usbhid.boot_report.keyboard.modifier` field에서 modifier state(`Shift`, `Ctrl`, `AltGr`) 유지
- `Caps Lock` 같은 toggle key 추적, 왜냐하면 uppercase output은 Shift만으로 제어되지 않기 때문
- HID usage ID는 layout-agnostic이라는 점을 기억: `0x1d`는 host keyboard layout에 따라 물리적인 `z`/`y` key position입니다

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
평문 hex lines를 이전에 덤프한 것에 넣으면 전체 parser를 환경에 끌어오지 않고도 즉시 대략적인 복원을 할 수 있습니다. non-US layout의 경우 이것은 여전히 물리적인 key position을 복원할 뿐이며, 반드시 victim host에 표시된 최종 glyph를 의미하지는 않습니다.

## Troubleshooting tips

- Wireshark가 `usbhid.*` fields를 채우지 않는다면, HID report descriptor가 아마도 캡처되지 않은 것입니다. 캡처 중에 keyboard를 다시 꽂거나 raw `usb.capdata`로 fallback 하세요.
- Linux software captures에서는 `usbmon`이 일반적인 source입니다. Windows에서는 Wireshark가 raw USB URBs를 보기 위해 **USBPcap** extcap에 의존합니다.
- keyboard가 hub나 dock을 통해 연결되었다면, 먼저 interface descriptor를 확인한 다음 그 device/interface pair만 decode 하세요. Composite HID captures는 keyboard와 mouse reports를 자주 섞습니다.
- Windows captures는 **USBPcap** extcap interface가 필요합니다. Wireshark upgrades 후에도 살아남았는지 확인하세요. extcap이 없으면 device lists가 비어 있게 됩니다.
- 어떤 것도 decode하기 전에 항상 `usb.bus_id:device:interface`(예: `1.9.1`)를 상관시켜야 합니다. 여러 keyboard나 storage devices를 섞으면 의미 없는 keystrokes가 나옵니다.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
