# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

SPI（Serial Peripheral Interface，串行外设接口）是一种同步串行总线，常用于集成电路之间的短距离通信。控制器提供时钟，并使用片选信号选择外设，例如 EEPROM、传感器或控制设备。<sup>[[1]](#references)</sup>

多个外设可以共用时钟线和数据线，通常每个外设都有单独的片选线。传输由控制器协调；外设通常不会通过 SPI 总线彼此直接通信。片选的极性和时序因设备而异；低电平有效很常见，但并非所有设备都如此。SPI 不定义设备发现、寻址、命令或统一的最大传输长度，因此务必查阅目标设备的数据手册。<sup>[[1]](#references)</sup>

MOSI/COPI 传输从控制器到外设的数据，MISO/CIPO 传输从外设到控制器的数据。两个方向可以同时移位传输。命令、地址、空周期与返回数据之间的关系由外设定义，而非 SPI 定义，并且取决于时钟极性和相位（模式 0–3）。不要假设输入结束后恰好一个时钟周期就会开始输出。<sup>[[1]](#references)</sup>

## 从 EEPROM 中转储固件

转储固件有助于分析固件并发现漏洞。正确的固件映像可能无法在线获取，也可能因型号、硬件修订版或版本而异，因此直接从实体设备提取固件，可以确保评估对象准确无误。

串行控制台会很有帮助，但其文件系统可能是只读的，而且目标设备可能缺少分析工具，包括发送/接收测试流量或便捷提取二进制文件所需的实用程序。离线映像保留了完整的闪存布局，便于提取文件系统和进行逆向工程，且无需修改正在运行的目标设备。

在获得授权的实体评估期间，经过验证的转储也可用于受控修改和重新刷写测试。这包括修改文件或注入测试 payload/backdoor，以演示固件级持久性。在进行任何写入之前，应保留多份一致的读取结果和原始映像：电压、芯片选择、布局或映像有误都可能导致设备变砖。

### CH341A EEPROM 编程器和读取器

这款廉价的 USB 工具可以转储并重新刷写兼容的串行 EEPROM 和 SPI 闪存设备。它常用于存储 PC BIOS/UEFI 固件的 SPI NOR 闪存芯片，在实体访问时间有限时非常方便。

![drawing](../../images/board_image_ch341a.jpg)

将闪存连接到 CH341A，再将编程器连接到计算机。如果未检测到编程器本身，请先检查 USB 线缆、操作系统权限以及相应的 CH341A 驱动程序，再排查目标芯片。请根据数据手册或使用万用表确认芯片电压、1 脚位置、转接板接线和编程器输出——**不要**依赖诸如将 VCC 放在 USB 接口对侧之类的规则。方向错误，或向 3.3/1.8 V 器件施加 5 V，都可能将其损坏。在电路板上读取也可能失败，因为板上其他部分会对总线产生负载或供电。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

使用 `flashrom` 或 G-Flash 等软件读取芯片。G-Flash 是一款精简的 GUI，可能会自动检测兼容设备，在快速采集时很方便，但仍应自行确认检测到的型号和电压。指定准确的编程器，必要时还要指定准确的芯片型号；至少读取两次，并比较哈希值，确认转储可靠后再使用。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

转储固件后，可以分析二进制文件。可以使用 strings、hexdump、xxd、binwalk 等工具提取固件及整个文件系统中的大量信息。

初步检查时，可以使用 Binwalk 扫描已知签名并提取受支持的嵌入内容：

```
binwalk -e <filename>
```

输出文件可能使用 `.bin`、`.rom` 或其他扩展名；扩展名并不能确定文件格式。

> [!CAUTION]
> 请注意，固件提取是一个精细的过程，需要极大的耐心。任何不当操作都可能损坏固件，甚至将其彻底擦除，导致设备无法使用。建议在尝试提取固件之前，先研究特定设备。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

有些数据手册会将目标引脚标记为 `DI` 和 `DO`：对于常规的单数据线 flash 连接，控制器的 **MOSI/COPI 连接到 DI**，控制器的 **MISO/CIPO 连接到 DO**。请查阅目标设备的数据手册进行确认，因为双路/四路 I/O 器件会在其他模式下复用这些引脚。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: 请注意，即使 Pirate Bus 的 PINOUT 标注了用于连接 SPI 的 MOSI 和 MISO 引脚，一些 SPI 设备也可能……](<../../images/image (360).png>)

在 Windows 或 Linux 中，你可以使用 [**`flashrom`**](https://www.flashrom.org/Flashrom) 程序，通过运行类似以下命令来转储 flash memory 的内容：

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

近期的 Bus Pirate 文档还展示了可选的 `serialspeed` 和 `spispeed` 参数。如果长导线或电路内负载导致读取不稳定，请从较低速度开始。<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI 接口简介](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 手册 — CH341A SPI 编程器及读写选项](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 文档 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
