# USB 키스트로크

{{#include ../../../banners/hacktricks-training.md}}

If you have a pcap containing the communication via USB of a keyboard like the following one:

![](<../../../images/image (962).png>)

USB keyboards usually speak the HID **boot protocol**, so every interrupt transfer towards the host is only 8 bytes long: one byte of modifier bits (Ctrl/Shift/Alt/Super), one reserved byte, and up to six keycodes per report. Decoding those bytes is enough to rebuild everything that was typed.

## USB HID report basics

The typical IN report looks like:

| Byte | 의미 |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

Keyboards without NKRO usually send `0x01` in byte 2 when more than six keys are pressed to signal "rollover". Understanding this layout helps when you only have the raw `usb.capdata` bytes.

## Extracting HID data from a PCAP

### Wireshark workflow

1. **Isolate the device**: filter on interrupt IN traffic from the keyboard, e.g. `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`.
2. **Add useful columns**: right-click the `Leftover Capture Data` field (`usb.capdata`) and your preferred `usbhid.*` fields (e.g. `usbhid.boot_report.keyboard.keycode_1`) to follow keystrokes without opening every frame.
3. **Hide empty reports**: apply `!(usb.capdata == 00:00:00:00:00:00:00:00)` to drop idle frames.
4. **Export for post-processing**: `File -> Export Packet Dissections -> As CSV`, include `frame.number`, `usb.src`, `usb.capdata`, and `usbhid.modifiers` to script the reconstruction later.

### Command-line workflow

`ctf-usb-keyboard-parser` already automates the classic tshark + sed pipeline:
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
최신 캡처에서는 장치별로 배치 처리하여 `usb.capdata`와 더 풍부한 `usbhid.data` 필드 둘 다 유지할 수 있습니다:
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
그 장치별 파일들은 어떤 decoder에도 바로 넣을 수 있습니다. 캡처가 GATT로 터널링된 BLE 키보드에서 왔다면, `btatt.value && frame.len == 20`로 필터링하고 디코딩하기 전에 hex payloads를 덤프하세요.

## 디코딩 자동화

- **ctf-usb-keyboard-parser**는 빠른 CTF 과제에 유용하며 이미 리포지토리에 포함되어 있습니다.
- **CTF-Usb_Keyboard_Parser** (`main.py`)는 `pcap`과 `pcapng` 파일을 네이티브로 파싱하고 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`을 이해하며 tshark가 필요 없어서 격리된 샌드박스에서도 잘 작동합니다.
- **USB-HID-decoders**는 키보드, 마우스, 태블릿용 시각화기를 추가합니다. `extract_hid_data.sh` 헬퍼(tshark 백엔드)나 `extract_hid_data.py`(scapy 백엔드)를 실행한 다음 생성된 텍스트 파일을 decoder 또는 replay 모듈에 넣어 키 입력이 재생되는 것을 볼 수 있습니다.

## 빠른 Python decoder
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
이전에 덤프한 16진수(hex) 라인들을 입력하면 전체 파서를 환경에 불러오지 않고도 즉시 대략적인 복원을 얻을 수 있습니다.

## 문제 해결 팁

- Wireshark이 `usbhid.*` 필드를 채우지 않는다면, HID report descriptor가 아마 캡처되지 않았습니다. 캡처 중에 키보드를 재연결하거나 원시 `usb.capdata`로 되돌아가세요.
- Windows 캡처는 **USBPcap** extcap 인터페이스를 필요로 합니다; Wireshark 업그레이드 후에도 해당 인터페이스가 유지되었는지 확인하세요. extcap이 없으면 장치 목록이 비어 있게 됩니다.
- 디코딩을 하기 전에 항상 `usb.bus_id:device:interface` (예: `1.9.1`)를 상호 연관시켜 확인하세요 — 여러 키보드나 스토리지 장치를 섞어 분석하면 무의미한 키스트로크가 발생합니다.

## 참고자료

- https://github.com/TeamRocketIst/ctf-usb-keyboard-parser
- https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup
- https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser
- https://github.com/Nissen96/USB-HID-decoders

{{#include ../../../banners/hacktricks-training.md}}
