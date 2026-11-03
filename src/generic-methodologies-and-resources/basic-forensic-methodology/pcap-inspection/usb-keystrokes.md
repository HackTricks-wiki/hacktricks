# USB 키 입력

{{#include ../../../banners/hacktricks-training.md}}

다음과 같이 키보드의 USB 통신이 담긴 pcap이 있다면:

![USB 키 입력: 다음과 같이 키보드의 USB 통신이 담긴 pcap이 있다면](<../../../images/image (962).png>)

HID **boot protocol**을 사용하는 키보드의 각 Interrupt IN 보고서는 고정된 8바이트 레이아웃을 따릅니다. modifier 바이트 하나, 예약 바이트 하나, 키코드 바이트 여섯 개로 구성됩니다. 호스트는 연속된 보고서를 비교하고 키코드를 HID usage에 대응시켜 키 이벤트를 재구성합니다.<sup>[[8]](#references)</sup>

일반적인 캡처 초기 분석은 [Pcap Inspection](./)을 참조하세요.

## USB HID 보고서 기본 사항

표준 boot 키보드 입력 보고서는 다음과 같은 구조입니다.<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | Meaning |
| --- | --- |
| 0 | Modifier 비트맵 (`0x02` = Left Shift, `0x20` = Right Shift, `0x40` = Right Alt 등). 여러 비트를 동시에 설정할 수 있습니다. |
| 1 | 예약 바이트입니다. 사용하지 않는 보고서는 일반적으로 이 값을 0으로 설정해야 합니다. OEM 또는 시스템별 용도로 사용되는 경우 호환성이 보장되지 않습니다. |
| 2-7 | USB usage ID 형식의 동시 키코드 최대 여섯 개 (`0x04 = a`, `0x1E = 1`). `0x00`은 "키 없음"을 의미합니다. |

boot 레이아웃에서는 비 modifier 키를 여섯 개 넘게 누르면 모든 키 슬롯에 usage ID `0x01`(`Keyboard ErrorRollOver`)이 보고됩니다. 인식할 수 없는 키 조합을 나타내는 경우도 있습니다.<sup>[[8]](#references)[[9]](#references)</sup> 이 레이아웃을 이해하면 원시 `usb.capdata` 바이트만 있는 경우에도 분석에 도움이 됩니다.

## PCAP에서 HID 데이터 추출하기

### 먼저 키보드 인터페이스 식별하기

트래픽이 많은 캡처에서는 보고서를 덤프하기 전에 HID 키보드를 식별하세요. 인터페이스 descriptor 응답부터 확인하는 것이 효과적입니다.<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID class는 다음 인터페이스 값을 정의합니다:<sup>[[8]](#references)</sup>

- `subclass == 1`은 Boot Interface Subclass입니다. `protocol == 1`이면 boot keyboard를 나타냅니다.
- `protocol == 2`이면 boot mouse를 나타냅니다.
- `protocol == 0`이면 boot protocol을 사용하지 않는다는 뜻입니다. 8바이트 레이아웃이라고 가정하지 말고 HID report descriptor를 확인하세요.

Boot를 지원하는 인터페이스라고 해서 **boot protocol이 활성화되어 있다는 증거는 아닙니다**. HID 장치는 report protocol로 초기화됩니다. 호스트는 `SET_PROTOCOL`(`bRequest = 0x0b`, `wValue = 0`)으로 boot mode를 선택하며, `wValue = 1`은 report protocol을 선택합니다. 캡처에 enumeration이 포함되어 있다면 8바이트 boot decoder를 사용하기 전에 keyboard 인터페이스에 대한 요청(`wIndex`)을 확인하세요. 해당 요청이 없다면 인터페이스 descriptor만으로 mode를 추론하지 말고, 관찰된 report 레이아웃을 확인하세요.<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

인터페이스를 확인한 후, 무엇이든 내보내기 전에 필터를 `usb.bus_id`, `usb.device_address` 및 가능한 경우 `usb.bInterfaceNumber`로 고정하세요.

### Wireshark 워크플로

1. **장치 분리**: 키보드의 interrupt IN 트래픽을 필터링합니다. 예: `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`.
2. **유용한 열 추가**: `Leftover Capture Data` 필드(`usb.capdata`)와 원하는 `usbhid.*` 필드(예: `usbhid.boot_report.keyboard.keycode_1`)를 마우스 오른쪽 버튼으로 클릭해 열로 추가하면, 모든 프레임을 열지 않고도 키 입력을 추적할 수 있습니다.<sup>[[11]](#references)</sup>
3. **빈 보고서 숨기기**: `!(usb.capdata == 00:00:00:00:00:00:00:00)`를 적용해 유휴 프레임을 제외합니다.
4. **후처리를 위해 내보내기**: `File -> Export Packet Dissections -> As CSV`를 선택하고 `frame.number`, `usb.src`, `usb.capdata`, 그리고 `usbhid.boot_report.keyboard.modifier.left_shift`, `usbhid.boot_report.keyboard.modifier.right_alt`와 같은 디코딩된 modifier 필드를 포함해 나중에 스크립트로 재구성합니다.<sup>[[10]](#references)[[11]](#references)</sup>

### 명령줄 워크플로

`usb.capdata`를 덤프하고, 유휴 보고서를 제외한 다음, usage ID를 매핑하는 고전적인 추출 패턴은 2017년 원본 분석과 그 단계별 설명에 나와 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` 저장소는 고전적인 tshark + sed 파이프라인을 자동화합니다.<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

최신 캡처에서는 Wireshark가 디코딩한 `usbhid.data` 필드를 우선 사용하고, 사용할 수 없으면 `usb.capdata`로 대체하세요. 각 report의 payload를 장치별 파일에 하나씩 기록합니다:<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

장치별 파일은 예상하는 hex 형식으로 정규화한 뒤 decoder에 입력할 수 있습니다. 캡처가 GATT를 통해 터널링된 BLE 키보드에서 온 경우, `btatt.value && frame.len == 20`으로 필터링하고 디코딩하기 전에 hex payload를 덤프하세요.<sup>[[7]](#references)</sup>

### report가 일반적인 8바이트 boot report가 아닌 경우

boot 인터페이스가 아니거나 report ID가 있으면 payload 레이아웃이 달라질 수 있으므로, 모든 키보드 report가 `modifier,reserved,key1..key6` 형식이라고 가정하지 마세요.<sup>[[8]](#references)[[11]](#references)</sup>

- Wireshark가 이미 HID 레이어를 파싱한 경우 `usb.capdata`보다 `usbhid.data`를 우선 사용하세요.
- 모든 행이 일정한 prefix 또는 report ID로 시작한다면, 항상 byte 0이 modifier라고 가정하지 말고 offset을 고려하는 decoder로 해당 부분을 제거하세요.<sup>[[7]](#references)</sup>
- 일부 USBPcap export에는 reserved byte가 빠져 있으므로, `--no-reserved`를 지원하는 decoder나 사용자 지정 offset을 사용하면 시간을 절약할 수 있습니다.<sup>[[7]](#references)</sup>
- 캡처에 HID report descriptor 또는 BLE HOGP report map이 있으면, parser를 작성하기 전에 이를 사용해 실제 필드 레이아웃을 확인하세요.

### report-protocol 키 bitmap 디코딩

입력 report가 여섯 개의 boot key 슬롯이 아닌 bitmap인 키보드라면, enumeration 트래픽에서 **HID report descriptor**를 찾으세요. 이 필터는 Wireshark가 Report Size 항목을 디코딩한 프레임을 찾습니다. 해당 프레임을 열어 전체 descriptor를 확인하세요. descriptor가 없다면 키보드를 연결하기 전에 새 캡처를 시작하세요.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

각 키보드 Input report에서 `Report ID`(있는 경우), `Usage Page`(키보드 키는 `0x07`), `Usage Minimum/Maximum`, `Report Size`, `Report Count`, 그리고 각 `Input` 항목이 **Variable**인지 **Array**인지 기록하세요. 앞에 오는 모든 Input 필드와 상수 패딩을 세어 키 필드의 비트 오프셋을 찾으세요. report 필드가 바이트 경계에 정렬되어 있을 필요는 없습니다. 연속된 키보드 usage를 갖는 1비트 Variable 필드는 키 상태 비트맵입니다. 이 필드의 비트 0은 처음 선언된 usage에, 비트 1은 그다음 usage에 대응하는 식입니다. 반면 Array에는 비트마다 눌린 키 하나가 들어 있는 것이 아니라, descriptor의 usage 범위에 따라 해석되는 값이 들어 있습니다. `Report ID`가 선언되어 있다면 먼저 해당 접두부가 있는 report를 선택하고, 필드 오프셋을 계산할 때 해당 바이트를 건너뛰세요. 연속된 report끼리 눌린 usage 집합을 비교할 때는 **동일한 인터페이스와 Report ID**끼리 비교해 새로 눌린 키만 출력하세요.<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## 디코딩 자동화

- **ctf-usb-keyboard-parser**는 빠른 CTF 문제 풀이에 여전히 유용하며, 이미 저장소에 포함되어 있습니다.<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`)는 `pcap` 및 `pcapng` 파일을 기본적으로 파싱하고, `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`을 이해하며, tshark나 다른 외부 종속성을 필요로 하지 않으므로 격리된 샌드박스에 적합합니다.<sup>[[6]](#references)</sup>
- **USB-HID-decoders**는 키보드, 마우스, 태블릿 시각화 기능을 제공합니다. `extract_hid_data.sh` 헬퍼(tshark 백엔드) 또는 `extract_hid_data.py`(scapy 백엔드)를 실행한 다음, 결과 텍스트 파일을 디코더 또는 재생 모듈에 전달해 키 입력이 나타나는 과정을 볼 수 있습니다.<sup>[[7]](#references)</sup>

### 상태 기반 디코딩이 중요한 이유

USB 부트 키보드는 새 키 이벤트가 없어도 유휴 속도에 맞춰 report를 전송하므로, 캡처에는 키 해제 이벤트가 발생하기 전까지 반복되는 report가 포함될 수 있습니다. 실용적인 디코더는 다음을 수행해야 합니다.<sup>[[3]](#references)[[8]](#references)</sup>

- 이전 report와 비교해 새로 눌린 키코드만 출력
- 바이트 0 또는 `usbhid.boot_report.keyboard.modifier.left_shift` 및 `usbhid.boot_report.keyboard.modifier.right_alt`와 같은 파싱된 필드에서 modifier 상태(`Shift`, `Ctrl`, `AltGr`) 유지
- `Caps Lock`과 같은 토글 키를 추적. 대문자 출력은 Shift만으로 결정되지 않기 때문입니다.
- HID usage ID는 키보드 레이아웃에 종속되지 않는다는 점을 기억하세요. 호스트 키보드 레이아웃에 따라 `0x1d`는 물리적 `z`/`y` 키 위치를 나타냅니다.<sup>[[9]](#references)</sup>

## 빠른 Python 디코더

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

이전에 덤프한 일반 hex 줄을 입력하면 전체 parser를 환경에 가져오지 않고도 즉시 대략적으로 재구성할 수 있습니다. US 이외의 레이아웃에서는 최종적으로 피해자 호스트에 표시된 글자가 아니라 물리적인 키 위치를 재구성합니다.

## 문제 해결 팁

- Wireshark에 `usbhid.*` 필드가 표시되지 않는다면 HID report descriptor가 캡처되지 않았을 가능성이 큽니다. 캡처를 시작한 상태에서 키보드를 다시 연결하거나 원시 `usb.capdata`를 사용하세요.
- Linux 소프트웨어 캡처에서는 `usbmon`을 일반적으로 사용하며, Windows에서는 원시 USB URB를 확인하려면 Wireshark에 **USBPcap** extcap이 필요합니다.<sup>[[4]](#references)</sup>
- 키보드가 허브나 도크를 통해 연결되었다면 먼저 interface descriptor를 확인한 다음 해당 device/interface 쌍만 디코딩하세요. Composite HID 캡처에는 키보드와 마우스 report가 함께 섞이는 경우가 많습니다.
- Windows 캡처에는 **USBPcap** extcap 인터페이스가 필요합니다. Wireshark 업그레이드 후에도 유지되었는지 확인하세요. extcap이 없으면 장치 목록이 비어 있을 수 있습니다.<sup>[[4]](#references)</sup>
- 무엇이든 디코딩하기 전에 bus, device, interface 튜플(`usb.bus_id`, `usb.device_address`, `usb.bInterfaceNumber`; 예: `1.9.1`)이 서로 일치하는지 항상 확인하세요. 여러 키보드나 저장 장치가 섞이면 의미 없는 keystroke가 나옵니다.<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 Writeup: foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB 키보드 packet 캡처 분석](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB 캡처 설정](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [Human Interface Devices(HID) 1.11을 위한 Device Class Definition](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID Usage Tables 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark Display Filter Reference: USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark Display Filter Reference: USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux kernel: HID report descriptor 소개](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024: ordinary-keyboard writeup](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
