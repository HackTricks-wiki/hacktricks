# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个包含如下所示键盘 USB 通信的 pcap：

![USB Keystrokes：如果你有一个包含如下所示键盘 USB 通信的 pcap](<../../../images/image (962).png>)

USB 键盘通常使用 HID **boot protocol**，因此每个发往主机的 interrupt transfer 只有 8 个字节：1 个修饰键位字节（Ctrl/Shift/Alt/Super）、1 个保留字节，以及每个 report 中最多 6 个 keycode。解析这些字节就足以还原输入的全部内容。

## USB HID report basics

典型的 IN report 如下：

| Byte | Meaning |
| --- | --- |
| 0 | 修饰键位图（`0x02` = Left Shift，`0x20` = Right Alt，等等）。多个位可以同时设置。 |
| 1 | 保留字节/填充字节，但 gaming keyboards 经常将其重新用于传输 vendor data。 |
| 2-7 | USB usage ID 格式的最多 6 个并发 keycode（`0x04` = a，`0x1E` = 1）。`0x00` 表示“无按键”。 |

不支持 NKRO 的键盘通常会在按下超过 6 个按键时，将字节 2 设置为 `0x01`，以表示“rollover”。了解这一布局有助于你仅拥有原始 `usb.capdata` 字节时进行分析。

## Extracting HID data from a PCAP

### Identify the keyboard interface first

在繁忙的 capture 中，dump report 之前应先识别 HID 键盘。一个可靠的起点是 interface descriptor response：<sup>[[2]](#references)</sup>
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
查看 `usb.bInterfaceSubClass` 和 `usb.bInterfaceProtocol`：

- `subclass == 1` 且 `protocol == 1` 通常表示 boot keyboard
- `protocol == 2` 通常表示鼠标
- `protocol == 0` 通常表示 vendor-defined 或 NKRO-style HID interface，它仍然携带键盘数据，但不采用简单的 8-byte boot layout

确定 interface 后，在导出任何内容之前，将过滤器固定到 `usb.bus_id`、`usb.device_address`，并尽可能加上 `usb.interface_number`。

### Wireshark workflow

1. **隔离设备**：过滤来自键盘的 interrupt IN 流量，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`。
2. **添加有用的列**：右键点击 `Leftover Capture Data` 字段（`usb.capdata`）以及你所需的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），无需打开每个 frame 即可跟踪按键输入。
3. **隐藏空 reports**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)`，以排除 idle frames。
4. **导出以便 post-processing**：`File -> Export Packet Dissections -> As CSV`，加入 `frame.number`、`usb.src`、`usb.capdata` 和 `usbhid.modifiers`，之后通过 script 重建数据。

### Command-line workflow

`ctf-usb-keyboard-parser` 已经自动化了经典的 tshark + sed pipeline：
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
在较新的捕获文件中，你可以通过按设备批处理，同时保留 `usb.capdata` 和信息更丰富的 `usbhid.data` 字段：
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
这些按设备划分的文件可以直接输入到任意解码器中。如果捕获内容来自通过 GATT 隧道传输的 BLE keyboards，请使用 `btatt.value && frame.len == 20` 进行过滤，并在解码前导出十六进制 payload。

### 当 report 不是经典的 8-byte boot report 时

近期的 gaming keyboards、split keyboards 和 composite HID devices 通常会暴露一个非 boot keyboard interface，其 payload 不再匹配 `modifier,reserved,key1..key6`。

- 当 Wireshark 已经解析 HID layer 时，优先使用 `usbhid.data` 而不是 `usb.capdata`。
- 如果每一行都以固定 prefix 或 report ID 开头，请使用支持 offset 的 decoder 将其剥离，不要假设 byte 0 始终是 modifier。
- 某些 USBPcap exports 会省略 reserved byte，因此支持 `--no-reserved` 或自定义 offset 的 decoders 可以节省时间。
- 如果 capture 中存在 HID report descriptor 或 BLE HOGP report map，请先利用它恢复实际的 field layout，再编写 parser。

## 自动化 decoding

- **ctf-usb-keyboard-parser** 仍然适用于快速 CTF challenges，并且已经包含在 repository 中。<sup>[[3]](#references)</sup>
- **CTF-Usb_Keyboard_Parser**（`main.py`）原生解析 `pcap` 和 `pcapng` files，支持 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，且不需要 tshark，因此非常适合在隔离的 sandboxes 中运行。<sup>[[4]](#references)</sup>
- **USB-HID-decoders** 增加了 keyboard、mouse 和 tablet visualizers。你可以运行 `extract_hid_data.sh` helper（tshark backend）或 `extract_hid_data.py`（scapy backend），然后将生成的 text file 输入 decoder 或 replay modules，以观察 keystrokes 展开。<sup>[[5]](#references)</sup>

### Stateful decoding 很重要

USB interrupt captures 通常同时包含 key press，以及在 release event 到达前同一 report 的一个或多个重复副本。实用的 decoder 应该：<sup>[[2]](#references)</sup>

- 仅输出与 previous report 相比 newly pressed 的 keycodes
- 从 byte 0 或已解析的 `usbhid.boot_report.keyboard.modifier` field 中维护 modifier state（`Shift`、`Ctrl`、`AltGr`）
- 跟踪 `Caps Lock` 等 toggle keys，因为 uppercase output 并不只由 Shift 控制
- 记住 HID usage IDs 与 layout 无关：根据 host keyboard layout，`0x1d` 是物理上的 `z`/`y` key position

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
将之前导出的纯十六进制行输入其中，即可立即获得粗略重建结果，而无需将完整 parser 引入环境。对于非 US 布局，这仍然重建的是物理按键位置，不一定是受害主机上显示的最终字符。

## 故障排除提示

- 如果 Wireshark 没有填充 `usbhid.*` 字段，可能是未捕获 HID report descriptor。请在捕获过程中重新插拔键盘，或退回使用原始 `usb.capdata`。
- 在 Linux 软件捕获中，`usbmon` 是标准来源；在 Windows 上，Wireshark 依赖 **USBPcap** extcap 才能查看原始 USB URB。<sup>[[1]](#references)</sup>
- 如果键盘通过 hub 或 dock 连接，请先确认 interface descriptor，然后仅解码对应的 device/interface pair。Composite HID 捕获经常会混入键盘和鼠标 report。
- Windows 捕获需要 **USBPcap** extcap interface；请确保它在 Wireshark 升级后仍然存在，因为缺失的 extcap 会导致设备列表为空。<sup>[[1]](#references)</sup>
- 在进行任何解码前，始终关联 `usb.bus_id:device:interface`（例如 `1.9.1`）——混合多个键盘或存储设备会导致按键结果毫无意义。

## 参考资料

- [1] [Wireshark USB 捕获设置](https://wiki.wireshark.org/CaptureSetup/USB)
- [2] [ACSC Quals 2023 - pcap 1、2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [3] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [4] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [5] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
