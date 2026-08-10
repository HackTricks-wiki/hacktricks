# USB 按键记录

如果你有一个包含如下键盘 USB 通信的 pcap：

![USB 按键记录：如果你有一个包含如下键盘 USB 通信的 pcap](<../../../images/image (962).png>)

对于使用 HID **boot protocol** 的键盘，每个 Interrupt IN report 都具有固定的 8 字节布局：一个 modifier 字节、一个 reserved 字节和六个 keycode 字节。主机会比较连续的 reports，并将 keycodes 映射到 HID usages，以重建按键事件。<sup>[[8]](#references)</sup>

## USB HID report 基础

标准的 boot keyboard input report 结构如下。<sup>[[8]](#references)[[9]](#references)</sup>

| 字节 | 含义 |
| --- | --- |
| 0 | Modifier bitmap（`0x02` = Left Shift，`0x20` = Right Shift，`0x40` = Right Alt 等）。多个 bits 可以同时设置。 |
| 1 | Reserved 字节；未使用的 reports 通常应将其设为零。OEM 或特定系统的用途不具备可移植性。 |
| 2-7 | USB usage ID 格式的最多六个并发 keycodes（`0x04 = a`，`0x1E = 1`）。`0x00` 表示“无按键”。 |

在 boot layout 中，当按下超过六个非 modifier 按键时，usage ID `0x01`（`Keyboard ErrorRollOver`）会被报告到所有 key slots 中；它也可以表示无法识别的组合。<sup>[[8]](#references)[[9]](#references)</sup> 了解这一 layout 有助于分析仅包含原始 `usb.capdata` 字节的情况。

## 从 PCAP 中提取 HID 数据

### 首先识别键盘 interface

在繁忙的 captures 中，dump reports 之前应先识别 HID keyboard。interface descriptor response 是一个可靠的起点：<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class 定义了以下 interface values：<sup>[[8]](#references)</sup>

- `subclass == 1` 是 Boot Interface Subclass；与 `protocol == 1` 一起表示 boot keyboard
- `protocol == 2` 表示 boot mouse
- `protocol == 0` 表示没有 boot protocol；应检查 HID report descriptor，而不是假设其采用 8 字节布局

确定 interface 后，在导出任何内容前，将过滤器限定到 `usb.bus_id`、`usb.device_address`，并尽可能加入 `usb.bInterfaceNumber`。

### Wireshark 工作流程

1. **隔离设备**：过滤来自键盘的 interrupt IN 流量，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`。
2. **添加有用列**：右键点击 `Leftover Capture Data` 字段（`usb.capdata`）以及首选的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），即可跟踪 keystrokes，而无需打开每个 frame。<sup>[[11]](#references)</sup>
3. **隐藏空 report**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)` 以排除 idle frames。
4. **导出以进行后处理**：`File -> Export Packet Dissections -> As CSV`，包含 `frame.number`、`usb.src`、`usb.capdata`，以及解码后的 modifier 字段，例如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt`，以便稍后通过 script 重建。<sup>[[10]](#references)[[11]](#references)</sup>

### 命令行工作流程

经典的提取模式——导出 `usb.capdata`、删除 idle reports 并映射 usage IDs——出现在 2017 年的原始分析及其 walkthrough 中。<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository 自动化了经典的 tshark + sed pipeline：<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
对于较新的捕获文件，优先使用 Wireshark 解码后的 `usbhid.data` 字段，并在不可用时回退到 `usb.capdata`；将每个 report 的一个 payload 写入对应设备的独立文件：<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
这些按设备划分的文件在按 decoder 所需的格式规范化 hex 后，可以交给 decoder 处理。如果 capture 来自通过 GATT 隧道传输的 BLE keyboards，请使用 `btatt.value && frame.len == 20` 进行过滤，并在 decoding 前导出 hex payloads。<sup>[[7]](#references)</sup>

### 当 report 不是经典的 8-byte boot report 时

非 boot interface 或 report ID 可能会改变 payload layout，因此不要假设每个 keyboard report 都符合 `modifier,reserved,key1..key6`。<sup>[[8]](#references)[[11]](#references)</sup>

- 当 Wireshark 已经解析 HID layer 时，优先使用 `usbhid.data`，而不是 `usb.capdata`。
- 如果每一行都以固定 prefix 或 report ID 开头，请使用支持 offset 的 decoder 去除它，而不要假设 byte 0 始终是 modifier。<sup>[[7]](#references)</sup>
- 某些 USBPcap exports 会省略 reserved byte，因此支持 `--no-reserved` 或 custom offset 的 decoders 可以节省时间。<sup>[[7]](#references)</sup>
- 如果 capture 中存在 HID report descriptor 或 BLE HOGP report map，请先利用它恢复实际的 field layout，再编写 parser。

## 自动化 decoding

- **ctf-usb-keyboard-parser** 仍然适合快速解决 CTF challenges，并且已包含在 repository 中。<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser** (`main.py`) 原生解析 `pcap` 和 `pcapng` 文件，理解 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，且不需要 tshark 或其他 external dependency，因此适合 isolated sandboxes。<sup>[[6]](#references)</sup>
- **USB-HID-decoders** 增加了 keyboard、mouse 和 tablet visualizers。你可以运行 `extract_hid_data.sh` helper（tshark backend）或 `extract_hid_data.py`（scapy backend），然后将生成的 text file 交给 decoder 或 replay modules，以观察 keystrokes 展开。<sup>[[7]](#references)</sup>

### 有状态的 decoding 很重要

USB boot keyboards 会按照 idle rate 发送 reports，即使没有新的 key event，因此 capture 中可能会在 release event 之前包含重复 reports。实用的 decoder 应当：<sup>[[3]](#references)[[8]](#references)</sup>

- 仅输出与 previous report 相比新按下的 keycodes
- 从 byte 0 或诸如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt` 等 parsed fields 中保留 modifier state（`Shift`、`Ctrl`、`AltGr`）
- 跟踪 `Caps Lock` 等 toggle keys，因为 uppercase output 不仅由 Shift 控制
- 记住 HID usage IDs 与 keyboard layout 无关：根据 host keyboard layout，`0x1d` 是物理上的 `z`/`y` key position。<sup>[[9]](#references)</sup>

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
将之前导出的纯十六进制行输入其中，即可立即获得粗略重建，而无需将完整 parser 引入环境。对于非 US 键盘布局，这仍会重建物理按键位置，但不一定是受害主机上最终显示的字符。

## 故障排除提示

- 如果 Wireshark 没有填充 `usbhid.*` 字段，可能是未捕获 HID report descriptor。捕获时重新插拔键盘，或退回使用原始的 `usb.capdata`。
- 在 Linux 软件捕获中，`usbmon` 是常规来源；在 Windows 上，Wireshark 依赖 **USBPcap** extcap 才能查看原始 USB URB。<sup>[[4]](#references)</sup>
- 如果键盘通过 hub 或 dock 连接，请先确认 interface descriptor，然后仅解码该 device/interface 对。Composite HID 捕获经常会混入键盘和鼠标 report。
- Windows 捕获需要 **USBPcap** extcap interface；请确保其在 Wireshark 升级后仍然存在，因为缺少 extcap 会导致设备列表为空。<sup>[[4]](#references)</sup>
- 在解码任何内容之前，始终确认 bus、device 和 interface tuple（`usb.bus_id`、`usb.device_address`、`usb.bInterfaceNumber`；例如 `1.9.1`）之间的对应关系——混入多个键盘或存储设备会导致按键结果毫无意义。<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup：foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
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
