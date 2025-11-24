# USB 键击

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个包含如下键盘通过 USB 通信的 pcap：

![](<../../../images/image (962).png>)

USB 键盘通常使用 HID **boot protocol**，所以每个向主机的中断传输只有 8 字节长：一个字节的 modifier 位（Ctrl/Shift/Alt/Super），一个保留字节，以及每个报告最多六个键码。解码这些字节就足够重建所有被输入的内容。

## USB HID 报告基础

典型的 IN 报告如下：

| 字节 | 含义 |
| --- | --- |
| 0 | Modifier 位图 (`0x02` = Left Shift, `0x20` = Right Alt, etc.). 可以同时设置多个位。 |
| 1 | 保留/填充，但常被游戏键盘用于厂商数据。 |
| 2-7 | 最多六个并发的键码，采用 USB usage ID 格式 (`0x04 = a`, `0x1E = 1`)。`0x00` 表示 "no key"。 |

不支持 NKRO 的键盘在同时按下超过六个键时通常会在字节 2 发送 `0x01` 来表示 "rollover"。当你只有原始的 `usb.capdata` 字节时，理解这个布局很有帮助。

## 从 PCAP 提取 HID 数据

### Wireshark 工作流程

1. **隔离设备**：对来自键盘的中断 IN 流量进行过滤，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`。
2. **添加有用的列**：右键 `Leftover Capture Data` 字段 (`usb.capdata`) 和你偏好的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），以便在不打开每个帧的情况下跟踪按键。
3. **隐藏空报告**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)` 来丢弃空闲帧。
4. **导出以便后处理**：`File -> Export Packet Dissections -> As CSV`，包含 `frame.number`, `usb.src`, `usb.capdata`, 和 `usbhid.modifiers`，以便之后脚本化重建。

### 命令行工作流程

`ctf-usb-keyboard-parser` 已经自动化了经典的 tshark + sed 流水线：
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
在较新的抓包中，你可以通过按设备分批处理同时保留 `usb.capdata` 和更丰富的 `usbhid.data` 字段：
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
这些按设备生成的文件可以直接导入任意解码器。如果捕获来自通过 GATT 隧道的 BLE 键盘，请对 `btatt.value && frame.len == 20` 进行过滤，并在解码前转储 hex payloads。

## 自动化解码

- **ctf-usb-keyboard-parser** 对于快速 CTF 挑战仍然很有用，并且已经随仓库一起提供。
- **CTF-Usb_Keyboard_Parser** (`main.py`) 本地解析 `pcap` 和 `pcapng` 文件，支持 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，且不依赖 tshark，因此可以很好地在隔离的沙箱中运行。
- **USB-HID-decoders** 增加了键盘、鼠标和平板的可视化工具。你可以运行 `extract_hid_data.sh`（tshark 后端）或 `extract_hid_data.py`（scapy 后端）辅助脚本，然后将生成的文本文件喂给解码器或 replay 模块以观察按键展开。

## 快速 Python 解码器
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
使用之前转储的纯十六进制行喂给它，可以立即得到一个粗略重构，而无需将完整的解析器引入环境。

## 故障排查提示

- 如果 Wireshark 未填充 `usbhid.*` 字段，HID 报告描述符很可能未被捕获。在捕获时重新插拔键盘，或退回使用原始的 `usb.capdata`。
- Windows 的捕获需要 **USBPcap** extcap 接口；确保它在 Wireshark 升级后仍然存在，因为缺失的 extcaps 会导致设备列表为空。
- 在解码任何内容之前始终关联 `usb.bus_id:device:interface`（例如 `1.9.1`）——混合多个键盘或存储设备会导致无意义的按键。

## References

- [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [HackTheBox Deadly Arthropod write-up](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)
- [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)

{{#include ../../../banners/hacktricks-training.md}}
