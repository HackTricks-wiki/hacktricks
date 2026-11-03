# USB Keystrokes

{{#include ../../../banners/hacktricks-training.md}}

如果你有一个 pcap，其中包含键盘通过 USB 进行通信的数据，如下所示：

![USB Keystrokes：如果你有一个 pcap，其中包含键盘通过 USB 进行通信的数据，如下所示](<../../../images/image (962).png>)

对于使用 HID **boot protocol** 的键盘，每个 Interrupt IN 报告都采用固定的 8 字节布局：一个修饰键字节、一个保留字节，以及六个键码字节。主机会比较连续的报告，并将键码映射到 HID usage，以重建按键事件。<sup>[[8]](#references)</sup>

有关一般的捕获数据初步检查，请参阅 [Pcap 检查](./)。

## USB HID 报告基础

标准 boot 键盘输入报告的结构如下。<sup>[[8]](#references)[[9]](#references)</sup>

| 字节 | 含义 |
| --- | --- |
| 0 | 修饰键位图（`0x02` = 左 Shift，`0x20` = 右 Shift，`0x40` = 右 Alt 等）。可以同时设置多个位。 |
| 1 | 保留字节；未使用时通常应设为零。OEM 或系统特定用途不具备可移植性。 |
| 2-7 | 最多六个并发键码，采用 USB usage ID 格式（`0x04 = a`，`0x1E = 1`）。`0x00` 表示“无按键”。 | 

在 boot 布局中，如果同时按下超过六个非修饰键，所有键槽都会报告 usage ID `0x01`（`Keyboard ErrorRollOver`）；它也可能表示无法识别的组合。<sup>[[8]](#references)[[9]](#references)</sup> 了解此布局有助于分析仅包含原始 `usb.capdata` 字节的情况。

## 从 PCAP 中提取 HID 数据

### 先识别键盘接口

在流量繁忙的捕获数据中，转储报告前应先识别 HID 键盘。一个可靠的起点是接口描述符响应：<sup>[[3]](#references)[[8]](#references)</sup>

```text
usb.transfer_type == 0x02 && usb.endpoint_address.direction == 1 && usb.bDescriptorType == 4 && usb.bInterfaceClass == 3
```

HID 类定义了以下接口值：<sup>[[8]](#references)</sup>

- `subclass == 1` 表示 Boot Interface Subclass；当 `protocol == 1` 时，表示 boot keyboard
- `protocol == 2` 表示 boot mouse
- `protocol == 0` 表示没有 boot protocol；应检查 HID report descriptor，而不是假定采用 8 字节布局

接口支持 boot mode **并不能证明当前已启用 boot protocol**。HID 设备初始化时使用 report protocol。主机通过 `SET_PROTOCOL`（`bRequest = 0x0b`，`wValue = 0`）选择 boot mode；`wValue = 1` 则选择 report protocol。如果抓包包含枚举过程，请检查发往键盘接口（`wIndex`）的请求，然后再使用 8 字节 boot decoder。如果抓包中没有该请求，请验证实际观察到的 report 布局，而不要根据接口描述符推断当前模式。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usb.setup.bRequest == 0x0b' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address \
  -e usb.setup.wIndex -e usb.setup.wValue
```

一旦确认接口，在导出任何内容之前，将过滤条件限定为 `usb.bus_id`、`usb.device_address`，以及（如果可能）`usb.bInterfaceNumber`。

### Wireshark 工作流程

1. **隔离设备**：过滤来自键盘的 interrupt IN 流量，例如 `usb.transfer_type == 0x01 && usb.endpoint_address.direction == 1 && usb.device_address == 3`。
2. **添加实用列**：右键单击 `Leftover Capture Data` 字段（`usb.capdata`）以及你偏好的 `usbhid.*` 字段（例如 `usbhid.boot_report.keyboard.keycode_1`），这样无需打开每个帧也能跟踪按键。<sup>[[11]](#references)</sup>
3. **隐藏空报告**：应用 `!(usb.capdata == 00:00:00:00:00:00:00:00)` 以过滤掉空闲帧。
4. **导出以供后续处理**：选择 `File -> Export Packet Dissections -> As CSV`，包含 `frame.number`、`usb.src`、`usb.capdata` 以及解码后的修饰键字段，例如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt`，以便稍后编写脚本进行重建。<sup>[[10]](#references)[[11]](#references)</sup>

### 命令行工作流程

经典的提取方法——转储 `usb.capdata`、过滤掉空闲报告，并映射 usage ID——见于 2017 年的原始分析及其操作指南。<sup>[[1]](#references)[[2]](#references)</sup>

`ctf-usb-keyboard-parser` 仓库自动化了经典的 tshark + sed 流程：<sup>[[5]](#references)</sup>

```bash
tshark -r ./usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keystrokes.txt
python3 usbkeyboard.py ./keystrokes.txt
```

在较新的捕获文件中，优先使用 Wireshark 解码后的 `usbhid.data` 字段，并在不可用时回退到 `usb.capdata`；将每个报告中的一个 payload 写入对应设备的文件：<sup>[[7]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
tshark -r usb.pcapng -Y "usb.capdata || usbhid.data" -T fields -E separator=$'\t' -e usb.src -e usb.capdata -e usbhid.data | \
  awk -F '\t' '{ payload = ($3 != "" ? $3 : $2); if (payload != "") print payload > "usbdata-" $1 ".txt" }'
```

这些按设备拆分的文件在按解码器要求的格式规范化十六进制数据后，即可输入解码器。如果捕获的数据来自通过 GATT 隧道传输的 BLE 键盘，请使用 `btatt.value && frame.len == 20` 进行筛选，并在解码前导出十六进制 payload。<sup>[[7]](#references)</sup>

### 当报告不是经典的 8 字节 boot report 时

非 boot 接口或 report ID 可能会改变 payload 布局，因此不要假设每个键盘报告都符合 `modifier,reserved,key1..key6` 格式。<sup>[[8]](#references)[[11]](#references)</sup>

- 如果 Wireshark 已解析 HID 层，优先使用 `usbhid.data`，而不是 `usb.capdata`。
- 如果每行都以固定前缀或 report ID 开头，请使用能识别偏移量的解码器将其剥离，而不要假设第 0 个字节始终是 modifier。<sup>[[7]](#references)</sup>
- 一些 USBPcap 导出数据会省略 reserved 字节，因此使用支持 `--no-reserved` 的解码器或自定义偏移量可以节省时间。<sup>[[7]](#references)</sup>
- 如果捕获数据中包含 HID report descriptor 或 BLE HOGP report map，请先用它还原实际字段布局，再编写解析器。

### 解码 report protocol 的按键位图

对于输入报告采用位图而非六个 boot key 槽位的键盘，请在枚举流量中找到其 **HID report descriptor**。此筛选器会查找 Wireshark 已解析出 Report Size 项目的帧；打开其中一帧并检查完整 descriptor。如果 descriptor 缺失，请在插入键盘前重新开始捕获。<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>

```bash
tshark -r usb.pcapng -Y 'usbhid.item.global.report_size' -T fields \
  -e frame.number -e usb.bus_id -e usb.device_address
```

对于每个键盘 Input 报告，记录其 `Report ID`（如果有）、`Usage Page`（键盘按键为 `0x07`）、`Usage Minimum/Maximum`、`Report Size`、`Report Count`，以及每个 `Input` 项是 **Variable** 还是 **Array**。累加前面的所有 Input 字段和常量填充位，确定按键字段的位偏移；报告字段不一定按字节对齐。具有连续键盘 usage 的单个位 Variable 字段是按键状态位图：该字段的第 0 位对应其声明的第一个 usage，第 1 位对应下一个，以此类推。Array 则包含根据描述符的 usage 范围解析出的值，而不是每一位对应一个按下的键。如果声明了 Report ID，先选择带有该前缀的报告，并在计算字段偏移时跳过该字节。比较**同一接口和 Report ID**的连续报告中的按住 usage 集合，只输出新按下的按键。<sup>[[8]](#references)[[12]](#references)[[13]](#references)</sup>

## 自动化解码

- **ctf-usb-keyboard-parser** 仍然适用于快速解决 CTF 挑战，并且已包含在仓库中。<sup>[[5]](#references)</sup>
- **CTF-Usb_Keyboard_Parser**（`main.py`）可原生解析 `pcap` 和 `pcapng` 文件，支持 `LinkTypeUsbLinuxMmapped`/`LinkTypeUsbPcap`，且不需要 tshark 或其他外部依赖，因此适用于隔离沙箱。<sup>[[6]](#references)</sup>
- **USB-HID-decoders** 提供键盘、鼠标和平板电脑可视化工具。你可以运行 `extract_hid_data.sh` 辅助脚本（tshark 后端）或 `extract_hid_data.py`（scapy 后端），然后将生成的文本文件交给解码器或回放模块，观察按键输入逐步还原。<sup>[[7]](#references)</sup>

### 有状态解码很重要

USB boot 键盘会按照空闲速率发送报告，即使没有新的按键事件也会如此，因此抓包中可能会在释放事件之前包含重复报告。实用的解码器应当：<sup>[[3]](#references)[[8]](#references)</sup>

- 仅输出与前一份报告相比新按下的按键码
- 根据字节 0 或解析出的字段（例如 `usbhid.boot_report.keyboard.modifier.left_shift` 和 `usbhid.boot_report.keyboard.modifier.right_alt`）保留修饰键状态（`Shift`、`Ctrl`、`AltGr`）
- 跟踪 `Caps Lock` 等切换键，因为大小写输出并非仅由 Shift 控制
- 记住 HID usage ID 与键盘布局无关：根据主机键盘布局，`0x1d` 对应物理键位 `z` 或 `y`。<sup>[[9]](#references)</sup>

## 快速 Python 解码器

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

将之前转储的纯十六进制行输入其中，即可快速粗略重建按键记录，无需在环境中引入完整解析器。对于非美式键盘布局，这仍会重建物理按键位置，但不一定是受害者主机上最终显示的字符。

## 故障排除提示

- 如果 Wireshark 没有填充 `usbhid.*` 字段，可能是未捕获 HID 报告描述符。开始捕获后重新插拔键盘，或者退而使用原始 `usb.capdata`。
- 在 Linux 软件抓包中，通常使用 `usbmon`；在 Windows 上，Wireshark 需要 **USBPcap** extcap 才能查看原始 USB URB。<sup>[[4]](#references)</sup>
- 如果键盘通过集线器或扩展坞连接，请先确认接口描述符，然后仅解码对应的设备/接口组合。复合 HID 抓包经常会混杂键盘和鼠标报告。
- Windows 抓包需要 **USBPcap** extcap 接口；请确认 Wireshark 升级后它仍然可用，因为 extcap 缺失会导致设备列表为空。<sup>[[4]](#references)</sup>
- 解码前务必核对总线、设备和接口的三元组（`usb.bus_id`、`usb.device_address`、`usb.bInterfaceNumber`；例如 `1.9.1`）——混入多个键盘或存储设备的数据会导致按键记录毫无意义。<sup>[[10]](#references)</sup>



## References

- [1] [HackIT CTF 2017 题解：foren100](https://0xd13a.github.io/ctfs/hackit2017/foren100/)
- [2] [USB 键盘数据包捕获分析](https://naykisec.github.io/USB-Keyboard-packet-capture-analysis/)
- [3] [ACSC Quals 2023 - pcap 1、2 题解](https://hackmd.io/@t510599/acsc-2023-quals-pcap)
- [4] [Wireshark USB 捕获设置](https://wiki.wireshark.org/CaptureSetup/USB)
- [5] [ctf-usb-keyboard-parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser)
- [6] [CTF-Usb_Keyboard_Parser](https://github.com/5h4rrk/CTF-Usb_Keyboard_Parser)
- [7] [USB-HID-decoders](https://github.com/Nissen96/USB-HID-decoders)
- [8] [人机接口设备（HID）设备类定义 1.11](https://www.usb.org/sites/default/files/documents/hid1_11.pdf)
- [9] [HID 用法表 1.2](https://usb.org/sites/default/files/hut1_2.pdf)
- [10] [Wireshark 显示过滤器参考：USB](https://www.wireshark.org/docs/dfref/u/usb.html)
- [11] [Wireshark 显示过滤器参考：USB HID](https://www.wireshark.org/docs/dfref/u/usbhid.html)
- [12] [Linux 内核：HID 报告描述符简介](https://docs.kernel.org/hid/hidintro.html)
- [13] [snakeCTF 2024：ordinary-keyboard 题解](https://snakectf.org/writeups/2024-quals/misc/ordinary-keyboard)
{{#include ../../../banners/hacktricks-training.md}}
