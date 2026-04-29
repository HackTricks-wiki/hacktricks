# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个包含通过 USB 传输的键盘通信的 pcap，比如下面这个：

![](<../../../images/image (962).png>)

USB 键盘通常使用 HID **boot protocol**，所以每次发送到主机的 interrupt transfer 只有 8 字节：一个字节的修饰键位（Ctrl/Shift/Alt/Super），一个保留字节，以及每个 report 最多六个 keycodes。只要解码这些字节，就能重建所有输入内容。

## USB HID report basics

典型的 IN report 看起来像这样：

| Byte | Meaning |
| --- | --- |
| 0 | Modifier bitmap (`0x02` = Left Shift, `0x20` = Right Alt, etc.). Multiple bits can be set simultaneously. |
| 1 | Reserved/padding but often reused by gaming keyboards for vendor data. |
| 2-7 | Up to six concurrent keycodes in USB usage ID format (`0x04 = a`, `0x1E = 1`). `0x00` means "no key". |

没有 NKRO 的键盘在按下超过六个键时，通常会在 byte 2 发送 `0x01` 来表示 "rollover"。了解这个布局后，即使你只有原始的 `usb.capdata` 字节，也能还原按键内容。

## Extracting HID data from a PCAP

### Identify the keyboard interface first

在繁忙的抓包中，在导出任何 report 之前，先识别 HID 键盘。一个可靠的起点是 interface descriptor response:
```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```
查看 `usb.bInterfaceSubClass` 和 `usb.bInterfaceProtocol`：

- `subclass == 1` 且 `protocol == 1` 通常表示 boot keyboard
- `protocol == 2` 通常是 mouse
- `protocol == 0` 往往表示 vendor-defined 或 NKRO-style HID interface，但仍然携带 keyboard 数据，只是不是简单的 8-byte boot 布局

一旦确认了 interface，就把过滤器固定到 `usb.bus_id`、`usb.device_address`，如果可能再加上 `usb.interface_number`，然后再导出任何内容。

### Wireshark workflow

1. **隔离设备**：对来自 keyboard 的 interrupt IN 流量加过滤器，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == "IN" && usb.device_address == 3`。
2. **添加有用列**：右键点击 `Leftover Capture Data` 字段（`usb.capdata`）以及你偏好的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），这样就能跟踪 keystrokes，而不必打开每一帧。
3. **隐藏空报告**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)` 来去掉 idle frames。
4. **导出以便后处理**：`File -> Export Packet Dissections -> As CSV`，包含 `frame.number`、`usb.src`、`usb.capdata` 和 `usbhid.modifiers`，之后可以用脚本重建。

### Command-line workflow

`ctf-usb-keyboard-parser` 已经自动化了经典的 tshark + sed pipeline：
```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```
在较新的捕获中，你可以通过按设备批处理，同时保留 `usb.capdata` 和更丰富的 `usbhid.data` 字段：
```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -e usb.src -e usb.capdata -e usbhid.data | \
sort -s -k1,1 | \
awk '{ printf "%s", (NR==1 ? $1 : pre!=$1 ? "\n" $1 : "") " " $2; pre=$1 }' | \
awk '{ for (i=2; i<=NF; i++) print $i > "usbdata-" $1 ".txt" }'
```
那些按设备分别生成的文件可以直接丢进任何解码器。如果抓包来自通过 GATT 隧道传输的 BLE 键盘，就过滤 `btatt.value && frame.len == 20`，并在解码前把十六进制 payload 导出来。

### 当报告不是经典的 8 字节 boot report 时

最近的 gaming keyboards、split keyboards 和 composite HID devices 往往暴露的是非-boot keyboard interface，此时 payload 不再符合 `modifier,reserved,key1..key6`。

- 当 Wireshark 已经解析了 HID layer 时，优先使用 `usbhid.data` 而不是 `usb.capdata`。
- 如果每一行都以固定前缀或 report ID 开头，就用支持 offset 的 decoder 把它去掉，而不要假设 byte 0 永远是 modifier。
- 一些 USBPcap 导出会省略 reserved byte，所以支持 `--no-reserved` 或自定义 offset 的 decoder 可以节省时间。
- 如果抓包里有 HID report descriptor 或 BLE HOGP report map，就先用它恢复实际字段布局，再写 parser。

## 自动化解码

- **ctf-usb-keyboard-parser** 仍然很适合快速 CTF challenges，并且已经包含在 repository 中。
- **CTF-Usb_Keyboard_Parser**（`main.py`）原生支持解析 `pcap` 和 `pcapng` 文件，理解 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，并且不需要 tshark，所以在隔离 sandbox 中也能很好工作。
- **USB-HID-decoders** 增加了 keyboard、mouse 和 tablet visualizers。你可以运行 `extract_hid_data.sh` helper（tshark backend）或 `extract_hid_data.py`（scapy backend），然后把得到的 text file 喂给 decoder 或 replay modules，观察 keystrokes 展开。

### 有状态解码很重要

USB interrupt captures 通常同时包含 key press 以及在 release event 到来之前同一 report 的一个或多个重复副本。实用的 decoder 应该：

- 只输出相对于上一条 report 新按下的 keycodes
- 从 byte 0 或解析后的 `usbhid.boot_report.keyboard.modifier` field 中保留 modifier state（`Shift`、`Ctrl`、`AltGr`）
- 跟踪 `Caps Lock` 之类的 toggle keys，因为大写输出并不只由 Shift 控制
- 记住 HID usage IDs 与 layout 无关：`0x1d` 是物理上的 `z`/`y` key position，具体取决于主机 keyboard layout

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
用之前转储的纯 hex 行直接喂给它，就能立即得到一个粗略重建，而不需要在环境里引入完整 parser。对于非 US 布局，这仍然重建的是物理按键位置，而不一定是受害主机上显示的最终 glyph。

## Troubleshooting tips

- If Wireshark does not populate `usbhid.*` fields, the HID report descriptor was probably not captured. Replug the keyboard while capturing or fall back to raw `usb.capdata`.
- On Linux software captures, `usbmon` is the normal source; on Windows, Wireshark depends on the **USBPcap** extcap to see raw USB URBs at all.
- If the keyboard was attached through a hub or dock, confirm the interface descriptor first and then decode only that device/interface pair. Composite HID captures frequently mix keyboard and mouse reports.
- Windows captures require the **USBPcap** extcap interface; make sure it survived Wireshark upgrades, as missing extcaps leave you with empty device lists.
- Always correlate `usb.bus_id:device:interface` (e.g. `1.9.1`) before decoding anything — mixing multiple keyboards or storage devices leads to nonsense keystrokes.

## References

- [Wireshark USB capture setup](https://wiki.wireshark.org/CaptureSetup/USB)
- [ACSC Quals 2023 - pcap 1, 2 write-up](https://hackmd.io/@t510599/acsc-2023-quals-pcap)

{{#include ../../../banners/hacktricks-training.md}}
