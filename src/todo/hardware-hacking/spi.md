# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

SPI（Serial Peripheral Interface，串行外设接口）是一种同步串行总线，通常用于集成电路之间的短距离通信。控制器提供时钟，并使用片选信号选择某个外设，例如 EEPROM、传感器或控制设备。<sup>[[1]](#references)</sup>

多个外设可以共享时钟线和数据线，通常每个外设对应一个独立的片选信号。控制器负责协调传输；外设通常不会通过 SPI 总线直接相互通信。片选的极性和时序取决于具体设备；低电平有效很常见，但并非普遍适用。SPI 不规定发现、寻址、命令或单次传输的最大长度，因此务必查阅目标设备的数据手册。<sup>[[1]](#references)</sup>

MOSI/COPI 携带从控制器到外设的数据，MISO/CIPO 携带从外设到控制器的数据。两个方向可以同时进行移位传输。命令、地址、dummy cycles 与返回数据之间的关系由外设定义，而不是由 SPI 定义，并且取决于时钟极性和相位（模式 0–3）。不要假设输入结束后恰好一个时钟周期输出就会开始。<sup>[[1]](#references)</sup>

## 从 EEPROM 中转储固件

转储固件有助于对其进行分析并发现漏洞。网上可能找不到正确的镜像，或者镜像可能因型号、硬件修订版本或软件版本而有所不同，因此直接从物理设备中提取固件可以获得精确的评估目标。

串行控制台可能会有所帮助，但其文件系统可能是只读的，且目标设备可能缺少分析工具，包括用于发送/接收测试流量或方便地提取二进制文件所需的实用程序。离线镜像可以保留完整的闪存布局，并允许在不修改运行中目标的情况下提取文件系统和进行逆向工程。

在经过授权的物理评估期间，经过验证的转储还可以支持受控修改和重新刷写测试。这包括修改文件或注入测试 payload/backdoor，以证明固件级持久化。在进行任何写入操作前，应保留多个相互匹配的读取结果以及原始镜像：错误的电压、芯片选择、布局或镜像可能会导致设备变砖。

### CH341A EEPROM Programmer and Reader

这个价格低廉的 USB 工具可以转储和重新刷写兼容的串行 EEPROM 与 SPI flash 设备。它通常用于处理存储 PC BIOS/UEFI 固件的 SPI NOR flash 芯片，在时间受限的物理访问期间非常方便。

![drawing](../../images/board_image_ch341a.jpg)

将 flash memory 连接到 CH341A，然后将 programmer 连接到计算机。如果 programmer 本身未被检测到，请先检查 USB 线缆、操作系统权限以及适用的 CH341A driver，再排查目标芯片。根据数据手册或使用万用表确认芯片电压、引脚 1、适配器接线和 programmer 输出——**不要**依赖诸如将 VCC 放在 USB 接口对面之类的规则。方向错误，或将 5 V 施加到 3.3/1.8 V 器件上，可能会将其损坏。电路内读取也可能失败，因为电路板的其余部分会对总线产生负载或供电。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

使用 `flashrom` 或 G-Flash 等软件读取芯片。G-Flash 是一个简易 GUI，可能会自动检测兼容设备；在快速获取期间这很方便，但仍需自行确认检测到的型号和电压。指定确切的 programmer，并在必要时指定确切的芯片型号；至少执行两次读取，并在将转储视为可靠之前比较它们的哈希值。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

转储固件后，可以对二进制文件进行分析。可以使用 strings、hexdump、xxd、binwalk 等工具提取有关固件以及整个文件系统的大量信息。

在初步筛查阶段，Binwalk 可以扫描已知签名，并提取受支持的嵌入式内容：
```
binwalk -e <filename>
```
输出文件可能使用 `.bin`、`.rom` 或其他扩展名；扩展名并不能确定其格式。

> [!CAUTION]
> 请注意，firmware 提取是一个需要谨慎处理的过程，并且需要大量耐心。任何操作不当都可能损坏 firmware，甚至将其完全擦除，导致设备无法使用。建议在尝试提取 firmware 之前，先研究特定设备。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom：Bus Pirate + flashrom](<../../images/image (910).png>)

一些 datasheet 将目标引脚标记为 `DI` 和 `DO`：对于传统的单数据线 flash 连接，控制器的 **MOSI/COPI 连接到 DI**，控制器的 **MISO/CIPO 连接到 DO**。请确认目标 datasheet，因为双路/四路 I/O 器件会在其他模式下复用这些引脚。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom：请注意，即使 Pirate Bus 的 PINOUT 指示了用于连接 SPI 的 MOSI 和 MISO 引脚，某些 SPI 可能……](<../../images/image (360).png>)

在 Windows 或 Linux 中，可以使用程序 [**`flashrom`**](https://www.flashrom.org/Flashrom) 转储 flash memory 的内容，运行类似以下命令：
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
Recent Bus Pirate 文档还显示了可选的 `serialspeed` 和 `spispeed` 参数。如果长线或电路内负载导致读取不稳定，请从较保守的设置开始。<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI 接口简介](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 手册 — CH341A SPI programmer 及读写选项](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 文档 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
