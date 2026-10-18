# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

SPI（Serial Peripheral Interface，串行外设接口）是一种同步串行总线，常用于集成电路之间的短距离通信。控制器提供时钟，并使用片选信号选择 EEPROM、传感器或控制设备等外设。<sup>[[1]](#references)</sup>

多个外设可以共用时钟线和数据线，通常每个外设都有独立的片选线。传输由控制器协调；外设通常不会通过 SPI 总线彼此直接通信。片选信号的有效电平和时序因设备而异；低电平有效很常见，但并非总是如此。SPI 不规定设备发现、寻址、命令或统一的最大传输长度，因此务必查阅目标设备的数据手册。<sup>[[1]](#references)</sup>

MOSI/COPI 用于传输从控制器到外设的数据，MISO/CIPO 用于传输从外设到控制器的数据。两个方向可以同时移位传输。命令、地址、空周期与返回数据之间的关系由外设定义，而不是由 SPI 定义，并且取决于时钟极性和相位（模式 0–3）。不要假设输入结束后恰好一个时钟周期就会开始输出。<sup>[[1]](#references)</sup>

## 从 EEPROM 中提取固件

提取固件有助于分析固件并查找漏洞。网上可能找不到正确的固件映像，或者映像可能因型号、硬件修订版或版本而异，因此直接从实体设备中提取固件，可以获得与评估目标完全一致的映像。

串行控制台会有所帮助，但其文件系统可能是只读的，目标设备也可能缺少分析工具，包括发送/接收测试流量或方便地提取二进制文件所需的工具。离线映像可以保留完整的闪存布局，让你无需修改正在运行的目标设备，就能提取文件系统并进行逆向工程。

在经过授权的实体评估期间，经过验证的转储还可用于受控修改和重新刷写测试。这包括修改文件或注入测试 payload/backdoor，以演示固件级持久化。在进行任何写入之前，应保存多份内容一致的读取结果和原始映像：电压、芯片选择、布局或映像不正确都可能导致设备变砖。

### CH341A EEPROM 编程器和读取器

这款廉价的 USB 工具可以提取和重新刷写兼容的串行 EEPROM 和 SPI flash 设备。它常用于存储 PC BIOS/UEFI 固件的 SPI NOR flash 芯片，在实体访问时间有限时也很方便。

![图示](../../images/board_image_ch341a.jpg)

将 flash 存储器连接到 CH341A，然后将编程器连接到电脑。如果系统无法检测到编程器本身，请在排查目标芯片问题之前，先检查 USB 线缆、操作系统权限以及适用的 CH341A 驱动程序。请根据数据手册或使用万用表确认芯片电压、1 脚位置、适配器接线和编程器输出——**不要**依赖“将 VCC 放在 USB 接口对面”之类的规则。方向错误，或将 5 V 电压施加到 3.3/1.8 V 芯片上，都可能损坏芯片。在电路板上直接读取也可能失败，因为电路板的其他部分会加载总线或为总线供电。<sup>[[2]](#references)</sup>

![图示](../../images/connect_wires_ch341a.jpg) ![图示](../../images/eeprom_plugged_ch341a.jpg)

使用 `flashrom` 或 G-Flash 等软件读取芯片。G-Flash 是一款精简的 GUI 工具，可能会自动检测兼容设备，在快速采集时很方便，但仍应自行确认检测到的型号和电压。指定准确的编程器，并在必要时指定准确的芯片型号；至少读取两次并比较哈希值，再将转储视为可靠结果。<sup>[[2]](#references)</sup>

![图示](../../images/connected_status_ch341a.jpg)

提取固件后，就可以分析二进制文件。可以使用 strings、hexdump、xxd、binwalk 等工具，从固件和整个文件系统中提取大量信息。

在初步检查时，可以使用 Binwalk 扫描已知签名并提取受支持的嵌入内容：

```
binwalk -e <filename>
```

输出文件可能使用 `.bin`、`.rom` 或其他扩展名；扩展名并不能确定文件格式。

> [!CAUTION]
> 请注意，固件提取是一个精细的过程，需要很大的耐心。任何操作不当都可能损坏固件，甚至将其彻底擦除，导致设备无法使用。建议先研究特定设备，再尝试提取固件。

### Bus Pirate + flashrom

![CH341A EEPROM 编程器和读取器 - Bus Pirate + flashrom：Bus Pirate + flashrom](<../../images/image (910).png>)

某些数据手册将目标引脚标记为 `DI` 和 `DO`：对于常规的单数据线 flash 连接，控制器的 **MOSI/COPI 连接到 DI**，控制器的 **MISO/CIPO 连接到 DO**。请查阅目标器件的数据手册进行确认，因为双路/四路 I/O 器件在其他模式下会复用这些引脚。

![CH341A EEPROM 编程器和读取器 - Bus Pirate + flashrom：请注意，即使 Pirate Bus 的引脚定义图标出了用于连接 SPI 的 MOSI 和 MISO 引脚，某些 SPI 也可能……](<../../images/image (360).png>)

在 Windows 或 Linux 中，可以使用程序 [**`flashrom`**](https://www.flashrom.org/Flashrom) 转储 flash memory 的内容，例如运行以下命令：

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

近期的 Bus Pirate 文档还展示了可选的 `serialspeed` 和 `spispeed` 参数。如果线缆较长或电路内负载导致读取不稳定，请从较低速度开始。<sup>[[3]](#references)</sup>

### 控制器与闪存共用总线时的电路内读取

SOIC 夹可能会将闪存电源接入 PCB 的其余部分。如果此时 MCU 已通电并访问同一芯片，其 SPI 传输可能会与外部编程器的传输冲突。因此，出现 `No EEPROM/flash device found` 并不能证明闪存不存在或不受支持。请先检查引脚排列、电压和接触情况，然后确认板载控制器是否也处于活动状态。<sup>[[4]](#references)</sup>

如果有复位测试焊盘，请先用万用表确认其极性和电压，再将其置为有效状态。让 MCU 保持复位状态，可能使闪存仍可访问，同时阻止发生冲突的 SPI 主机工作。其他方法包括拆焊芯片或被动记录 MCU 的读取操作；后者无法访问尚未读取的区域，也无法写入芯片，而且额外的探针接线可能会干扰高速总线。对振荡器或启动模式进行干预取决于具体目标，不能替代对原理图和信号的检查。<sup>[[4]](#references)</sup>

在 MCU 保持非活动状态时，可使用启用了 `spidev` 接口的 Raspberry Pi，通过 flashrom 的 `linux_spi` programmer 读取。使用其他适配器时，请更改 `-p` 参数。重复读取并比较哈希值后再信任结果；SFDP 自动检测和成功读取**并不能**证明擦除、写入或写保护操作适用于其他方面不受支持的芯片。<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### 使用 logic analyzer 重建 SPI flash 读取数据

无法主动读取时，可在启动期间或执行特定 UI 操作时，捕获片选、时钟、控制器到 flash 的数据以及 flash 到控制器的数据。在 PulseView 中，先识别有效的片选区间和时钟，然后根据 flash 引脚定义配置 SPI 解码器的数据通道，并确认能解出合理的命令/地址及其后返回的字节。使用 Binary Decoder Output View 导出 **MISO/flash 输出**字节，并保留解码出的读取地址，以便将每个响应放到对应的 flash 偏移处。只捕获由菜单操作触发的读取，只会得到请求的区域，而非完整的 flash 镜像；未核对地址前，不要把响应拼接起来并视为连续数据。<sup>[[4]](#references)</sup>

如果转储看起来包含的是图形而非可执行代码，请继续进行 [raw display-asset triage](../firmware-analysis/#raw-display-assets-in-external-flash)。<sup>[[4]](#references)</sup>

#### Scapy 和混合 SPI/QSPI 捕获

对于未标记的探针，可通过判断哪条线路在响应数据之前传输了操作码来区分 MOSI 和 MISO，然后对照 flash 数据手册核实命令。短于时钟周期的脉冲可能是探针噪声，而非采样到的位；额外的夹线也可能导致高速捕获不可靠。<sup>[[5]](#references)</sup>

Saleae 的 SPI CSV 导出使用 `enable` 和 `disable` 标记片选区间，并在 `result` 行中记录 MOSI/MISO 字节。解码前应按区间对字节分组；拼接所有 MISO 数据会丢失事务地址。<sup>[[5]](#references)</sup> Scapy 的 `Packet` 可以用 `ByteEnumField` 操作码以及条件式地址和 dummy 字段来建模 MOSI 标头。对于 24 位 NOR 读取，`0x03` 包含一个操作码和三个地址字节，而 `0x0B` 还会增加一个 dummy 字节。`len(req.self_build())` 可得出建模后的标头长度：对于单 lane 读取，`miso[header_length:]` 是 flash 响应，而标头之后的 MOSI 数据属于控制器端的 don't-care 数据。<sup>[[5]](#references)</sup> 将响应放到 `0xFF` 填充的镜像中的解码地址处，并单独跟踪已覆盖的偏移。未观测到某个字节，并不能证明 flash 中该位置的值为 `0xFF`。<sup>[[5]](#references)[[6]](#references)</sup>

W25Q 风格的 `0x6B`（1-1-4）读取使用单 lane 传输操作码和地址，但使用 IO0–IO3 传输响应数据。原先的 `/WP` 和 `/HOLD` 引脚上出现活动，是切换到 quad 模式的更有力证据；仅凭时钟变快并不足以确认。单 lane analyzer 可能会错误解码 quad 响应。<sup>[[5]](#references)</sup> 使用针对该命令的 lane 宽度和 dummy 周期配置的 QSPI analyzer 导出该阶段的数据，然后按 flash 地址合并单 lane 和 quad lane 的读取数据。<sup>[[5]](#references)[[7]](#references)</sup> `spidump` 会自动检测这两种导出格式，丢弃按错误 lane 宽度解码的读取，并报告读取覆盖范围。<sup>[[6]](#references)</sup> 从其 repository 安装依赖后，可使用以下命令合并捕获数据：<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

结果仍然只是稀疏观测，并非完整的芯片转储。<sup>[[5]](#references)[[6]](#references)</sup> 若要单独检查写入操作，可关联 `0x06` 写使能、`0x05` 状态轮询、擦除操作码以及 `0x02` 页编程命令。页编程数据会在地址之后通过 MOSI 传输，仅读取重建不会包含这些数据。<sup>[[5]](#references)</sup> 使用 [固件分析](../firmware-analysis/) 分析生成的映像，同时保留读取覆盖信息。

## References

- [1] [Analog Devices — SPI 接口简介](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 手册 — CH341A SPI 编程器及读写选项](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 文档 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — 硬件黑客技术进阶，第 2 部分](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — 扩展 Scapy 以进行硬件逆向工程](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI 轨迹捕获与重建](https://github.com/wrongbaud/spidump)
- [7] [适用于 Saleae Logic/KingstVIS 的 QSPI 分析器](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
