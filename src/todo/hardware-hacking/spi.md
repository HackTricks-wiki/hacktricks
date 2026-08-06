# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

SPI（Serial Peripheral Interface）是一种同步串行通信协议，用于嵌入式系统中 IC（集成电路）之间的短距离通信。SPI 通信协议采用由 Clock 和 Chip Select Signal 协调的 master-slave 架构。master-slave 架构由一个 master（通常是微处理器）管理外部外围设备，例如 EEPROM、传感器、控制设备等，这些设备被视为 slaves。

一个 master 可以连接多个 slaves，但 slaves 之间无法相互通信。Slaves 由两个引脚管理：clock 和 chip select。由于 SPI 是一种同步通信协议，输入和输出引脚会遵循 clock 信号。Chip select 由 master 用于选择某个 slave 并与其交互。当 chip select 为高电平时，slave 设备未被选中；当其为低电平时，芯片已被选中，master 会与该 slave 进行交互。

MOSI（Master Out, Slave In）和 MISO（Master In, Slave Out）负责数据发送和接收。数据会通过 MOSI 引脚发送到 slave 设备，同时 chip select 保持低电平。输入数据包含指令、内存地址或数据，具体取决于 slave 设备厂商提供的 datasheet。收到有效输入后，MISO 引脚负责向 master 传输数据。输出数据会在输入结束后的下一个 clock cycle 中准确发送。MISO 引脚会持续传输数据，直到数据全部发送完毕，或 master 将 chip select 引脚置为高电平（在这种情况下，slave 会停止传输，master 也不会在该 clock cycle 之后继续监听）。

## 从 EEPROM 中 Dump Firmware

Dump firmware 有助于分析 firmware 并发现其中的漏洞。很多时候，firmware 在互联网上不可用，或者由于型号、版本等因素的差异而不适用。因此，直接从物理设备中提取 firmware，有助于在 threat hunting 时确保目标的准确性。

获取 Serial Console 可能会有所帮助，但很多时候文件是只读的。这会由于各种原因限制分析。例如，firmware 中可能不存在用于发送和接收数据包的工具。因此，提取二进制文件并对其进行 reverse engineering 并不可行。所以，将完整的 firmware dump 到系统中，再提取二进制文件进行分析，会非常有帮助。

此外，在 red teaming 和获得设备的物理访问权限期间，dump firmware 可以帮助修改文件或注入恶意文件，然后将其重新刷写到内存中，从而有助于在设备中植入 backdoor。因此，firmware dumping 可以解锁许多可能性。

### CH341A EEPROM Programmer and Reader

该设备是一种价格低廉的工具，可用于从 EEPROM 中 dump firmware，也可以使用 firmware 文件对其进行重新刷写。它一直是处理计算机 BIOS 芯片（本质上也是 EEPROM）的热门选择。该设备通过 USB 连接，只需极少的工具即可开始使用。此外，它通常能够快速完成任务，因此在对物理设备进行访问时也很有帮助。

![drawing](../../images/board_image_ch341a.jpg)

将 EEPROM 内存连接到 CH341a Programmer，然后将设备插入计算机。如果设备未被检测到，请尝试在计算机中安装 drivers。此外，请确保 EEPROM 的方向正确（通常需要将 VCC Pin 以与 USB connector 相反的方向放置），否则软件将无法检测到芯片。如有需要，请参考下图：

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

最后，可以使用 flashrom、G-Flash（GUI）等 software 来 dump firmware。G-Flash 是一个简洁的 GUI tool，运行速度快，并且能够自动检测 EEPROM。当需要快速提取 firmware，且不想过多查阅 documentation 时，它会非常有帮助。

![drawing](../../images/connected_status_ch341a.jpg)

Dump firmware 后，可以对 binary files 进行分析。可以使用 strings、hexdump、xxd、binwalk 等 tools 提取大量 firmware 信息以及整个 file system 的信息。

要从 firmware 中提取内容，可以使用 binwalk。Binwalk 会分析 hex signatures，识别 binary file 中的文件，并能够将其提取出来。
```
binwalk -e <filename>
```
可以是 `.bin` 或 `.rom`，具体取决于所使用的工具和配置。

> [!CAUTION]
> 请注意，固件提取是一个需要耐心的精细过程。任何操作不当都可能损坏固件，甚至将其完全擦除，导致设备无法使用。建议在尝试提取固件之前，先研究特定设备。

### Bus Pirate + flashrom

![CH341A EEPROM 编程器和读取器 - Bus Pirate + flashrom：Bus Pirate + flashrom](<../../images/image (910).png>)

请注意，即使 Pirate Bus 的 PINOUT 标示了用于连接 SPI 的 **MOSI** 和 **MISO** 引脚，某些 SPI 也可能将引脚标示为 DI 和 DO。**MOSI -> DI，MISO -> DO**

![CH341A EEPROM 编程器和读取器 - Bus Pirate + flashrom：请注意，即使 Pirate Bus 的 PINOUT 标示了用于连接 SPI 的 MOSI 和 MISO 引脚，某些 SPI 也可能将引脚标示为 DI 和 DO](<../../images/image (360).png>)

在 Windows 或 Linux 中，可以使用 [**`flashrom`**](https://www.flashrom.org/Flashrom) 程序，通过运行类似以下的命令来 dump flash memory 的内容：
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
