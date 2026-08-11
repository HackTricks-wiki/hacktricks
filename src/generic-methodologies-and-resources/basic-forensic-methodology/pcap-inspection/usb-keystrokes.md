# USB 按键记录

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个包含键盘 USB 通信数据的 pcap 文件，例如下面这个：

![USB 按键记录：如果你有一个包含如下键盘 USB 通信数据的 pcap 文件](<../../../images/image (962).png>)

对于使用 HID **boot protocol** 的键盘，每个 Interrupt IN report 都具有固定的 8 字节布局：1 个 modifier 字节、1 个保留字节以及 6 个 keycode 字节。主机会比较连续的 reports，并将 keycode 映射到 HID usage，以重建按键事件。<sup>[[8]](#references)</sup>

## USB HID report 基础

标准的 boot keyboard input report 结构如下。<sup>[[8]](#references)[[9]](#references)</sup>

| Byte | 含义 |
| --- | --- |
| 0 | Modifier 位图（`0x02` = Left Shift，`0x20` = Right Shift，`0x40` = Right Alt 等）。多个 bit 可以同时设置。 |
| 1 | 保留字节；未使用的 reports 通常应将其设置为零。OEM 或系统特定用途不具备可移植性。 |
| 2-7 | USB usage ID 格式的最多 6 个并发 keycode（`0x04 = a`，`0x1E = 1`）。`0x00` 表示“无按键”。 |

在 boot layout 中，当按下超过 6 个非 modifier 按键时，所有 key slot 都会报告 usage ID `0x01`（`Keyboard ErrorRollOver`）；它也可以表示无法识别的组合。<sup>[[8]](#references)[[9]](#references)</sup> 了解该布局有助于分析原始的 `usb.capdata` 字节。

## 从 PCAP 中提取 HID 数据

### 首先识别键盘接口

在繁忙的 captures 中，转储 reports 之前应先识别 HID 键盘。一个可靠的起点是接口描述符响应：<sup>[[3]](#references)[[8]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
HID class 定义了以下接口值：<sup>[[8]](#references)</sup>

- `subclass == 1` 表示 Boot Interface Subclass；结合 `protocol == 1` 时，表示 boot keyboard
- `protocol == 2` 表示 boot mouse
- `protocol == 0` 表示没有 boot protocol；应检查 HID report descriptor，而不是假设使用 8 字节布局

确定接口后，在导出任何内容之前，将过滤器固定到 `usb.bus_id`、`usb.device_address`，并尽可能加入 `usb.bInterfaceNumber`。

### Wireshark 工作流程

1. **隔离设备**：过滤来自键盘的 interrupt IN 流量，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`。
2. **添加有用的列**：右键单击 `Leftover Capture Data` 字段（`usb.capdata`）以及你需要的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），这样无需打开每个帧即可跟踪按键输入。<sup>[[11]](#references)</sup>
3. **隐藏空报告**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)`，以排除 idle 帧。
4. **导出以进行后处理**：选择 `File -> Export Packet Dissections -> As CSV`，包含 `frame.number`、`usb.src`、`usb.capdata` 以及已解码的 modifier 字段，例如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt`，之后通过脚本重建按键输入。<sup>[[10]](#references)[[11]](#references)</sup>

### 命令行工作流程

经典的提取模式——导出 `usb.capdata`、删除 idle 报告并映射 usage IDs——出现在最初的 2017 年分析及其演示中。<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` repository 自动化了经典的 tshark + sed pipeline：<sup>[[5]](#references)</sup>
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
对于较新的捕获，优先使用 Wireshark 解码的 `usbhid.data` 字段，并回退到 `usb.capdata`；将每个 report 的一个 payload 写入每个设备对应的文件：<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```
这些按设备分离的文件可以在将十六进制格式规范化为解码器所需的格式后，交给解码器处理。如果捕获内容来自通过 GATT 隧道传输的 BLE keyboards，请使用 `btatt.value && frame.len == 20` 进行过滤，并在解码前导出十六进制 payloads。<sup>[[7]](#references)</sup>

### 报告不是经典的 8 字节 boot report 时

非 boot interface 或 report ID 可能会改变 payload 布局，因此不要假设每个 keyboard report 都符合 `modifier,reserved,key1..key6`。<sup>[[8]](#references)[[11]](#references)</sup>

- 如果 Wireshark 已经解析 HID layer，优先使用 `usbhid.data` 而不是 `usb.capdata`。
- 如果每一行都以固定 prefix 或 report ID 开头，请使用能够识别 offset 的 decoder 将其去除，不要假设 byte 0 始终是 modifier。<sup>[[7]](#references)</sup>
- 某些 USBPcap exports 会省略 reserved byte，因此使用支持 `--no-reserved` 的 decoder 或自定义 offset 可以节省时间。<sup>[[7]](#references)</sup>
- 如果 capture 中包含 HID report descriptor 或 BLE HOGP report map，请先使用它恢复实际的 field layout，再编写 parser。

## 自动化解码

- **ctf-usb-keyboard-parser** 仍然适用于快速 CTF challenges，并且已经包含在 repository 中。<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser**（`main.py`）原生解析 `pcap` 和 `pcapng` files，理解 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，且不需要 tshark 或其他 external dependency，因此适合在 isolated sandboxes 中使用。<sup>[[6]](#references)</sup>
- **USB-HID-decoders** 添加了 keyboard、mouse 和 tablet visualizers。你可以运行 `extract_hid_data.sh` helper（tshark backend）或 `extract_hid_data.py`（scapy backend），然后将生成的 text file 交给 decoder 或 replay modules，以观察 keystrokes 逐步还原。<sup>[[7]](#references)</sup>

### 有状态解码很重要

USB boot keyboards 即使没有新的 key event，也会按照 idle rate 发送 reports，因此 capture 中可能会在 release event 之前包含重复 reports。一个实用的 decoder 应该：<sup>[[3]](#references)[[8]](#references)</sup>

- 仅输出与上一条 report 相比新按下的 keycodes
- 保留 modifier state（`Shift`、`Ctrl`、`AltGr`），其来源可以是 byte 0，也可以是诸如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt` 等 parsed fields
- 跟踪 `Caps Lock` 等 toggle keys，因为 uppercase output 并不只由 Shift 控制
- 记住 HID usage IDs 与 keyboard layout 无关：根据 host keyboard layout，`0x1d` 表示物理上的 `z`/`y` key position。<sup>[[9]](#references)</sup>

## 快速 Python decoder
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
将之前导出的纯十六进制行输入其中，即可立即获得粗略重建，无需将完整解析器引入环境。对于非 US 键盘布局，这仍会重建物理按键位置，但不一定是受害主机上最终显示的字符。

## Troubleshooting tips

- 如果 Wireshark 没有填充 `usbhid.*` 字段，可能是未捕获 HID 报告描述符。请在捕获过程中重新插拔键盘，或退回使用原始的 `usb.capdata`。
- 在 Linux 软件捕获中，`usbmon` 是常规来源；在 Windows 上，Wireshark 依赖 **USBPcap** extcap 才能查看原始 USB URB。<sup>[[4]](#references)</sup>
- 如果键盘通过集线器或扩展坞连接，请先确认接口描述符，然后仅解码该设备/接口对。复合 HID 捕获经常会混入键盘和鼠标报告。
- Windows 捕获需要 **USBPcap** extcap 接口；请确保它在 Wireshark 升级后仍然存在，因为缺少 extcap 会导致设备列表为空。<sup>[[4]](#references)</sup>
- 在解码任何内容之前，始终确认总线、设备和接口元组（`usb.bus_id`、`usb.device_address`、`usb.bInterfaceNumber`；例如 `1.9.1`），因为混合多个键盘或存储设备会产生无意义的按键输入。<sup>[[10]](#references)</sup>

## References

- [1] [HackIT CTF 2017 Writeup：foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB 键盘数据包捕获分析](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1、2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB 捕获设置](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [人机接口设备（HID）设备类定义 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID 使用表 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark 显示过滤器参考：USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark 显示过滤器参考：USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
{{#include ../../../banners/hacktricks-training.md}}
