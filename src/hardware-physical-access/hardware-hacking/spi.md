# SPI

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

SPI（Serial Peripheral Interface，串行外设接口）是一种同步串行总线，常用于集成电路之间的短距离通信。控制器提供时钟，并通过片选信号选择 EEPROM、传感器或控制设备等外设。<sup>[[1]](#references)</sup>

多个外设可以共用时钟线和数据线，通常每个外设都有独立的片选信号。传输由控制器协调；外设通常不会通过 SPI 总线直接相互通信。片选信号的有效电平和时序因设备而异；低电平有效很常见，但并非通用。SPI 未定义设备发现、寻址、命令或统一的最大传输长度，因此务必查阅目标设备的数据手册。<sup>[[1]](#references)</sup>

MOSI/COPI 传输从控制器到外设的数据，MISO/CIPO 传输从外设到控制器的数据。两个方向可以同时移位传输。命令、地址、虚拟时钟周期和返回数据之间的关系由外设定义，而非 SPI；具体关系取决于时钟极性和相位（模式 0–3）。不要假设输入结束后恰好一个时钟周期，输出就会开始。<sup>[[1]](#references)</sup>

## 从 EEPROM 中转储固件

转储固件有助于分析固件并发现漏洞。网上可能找不到正确的镜像，或镜像与设备型号、硬件版本或软件版本不符，因此直接从实体设备中提取固件，可以获得与评估目标完全一致的镜像。

串口控制台可能会有帮助，但其文件系统可能是只读的，而且目标设备可能缺少分析工具，包括用于发送/接收测试流量或便捷提取二进制文件的实用程序。离线镜像会保留完整的闪存布局，便于提取文件系统和进行逆向工程，而无需修改运行中的目标设备。

在获得授权的实体设备评估期间，经过验证的转储也可用于受控修改和重新刷写测试。这包括修改文件或注入测试载荷/后门，以证明固件级持久性。在写入任何内容之前，应保留多个一致的读取结果和原始镜像：电压、芯片选择、布局或镜像有误，都可能导致设备变砖。

### CH341A EEPROM Programmer and Reader

这款廉价的 USB 工具可以转储和重新刷写兼容的串行 EEPROM 和 SPI flash 器件。它常用于读写存储 PC BIOS/UEFI 固件的 SPI NOR flash 芯片，在时间有限的实体设备访问期间也很方便。

![drawing](../../images/board_image_ch341a.jpg)

将 flash memory 连接到 CH341A，然后将编程器连接到计算机。如果系统未检测到编程器，请先检查 USB 线缆、OS 权限以及对应的 CH341A 驱动，再排查目标芯片。使用数据手册或万用表确认芯片电压、1 脚位置、适配器接线和编程器输出——**不要**依赖“将 VCC 放在 USB 接口对侧”之类的规则。方向错误，或向 3.3/1.8 V 器件施加 5 V，都可能将其损坏。在电路板上直接读取也可能失败，因为电路板上的其他部分会对总线施加负载或供电。<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

使用 `flashrom` 或 G-Flash 等软件读取芯片。G-Flash 是一款精简的 GUI，可能会自动检测兼容设备，在快速采集时很方便，但请自行确认检测到的型号和电压。指定准确的编程器，并在必要时指定准确的芯片型号；至少读取两次，并在将转储视为可靠数据前比较其哈希值。<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

转储固件后，可以分析二进制文件。可以使用 strings、hexdump、xxd、binwalk 等工具，从固件乃至整个文件系统中提取大量信息。

初步排查时，可以使用 Binwalk 扫描已知签名并提取其支持的嵌入内容：

```
binwalk -e <filename>
```

输出文件可能使用 `.bin`、`.rom` 或其他扩展名；扩展名并不能确定文件格式。

> [!CAUTION]
> 请注意，固件提取是一个精细的过程，需要极大的耐心。任何操作不当都可能损坏固件，甚至将其完全擦除，导致设备无法使用。建议先研究具体设备，再尝试提取固件。

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

一些数据手册会将目标引脚标为 `DI` 和 `DO`：对于常规的单数据线 flash 连接，控制器的 **MOSI/COPI 连接到 DI**，控制器的 **MISO/CIPO 连接到 DO**。请查阅目标器件的数据手册进行确认，因为双路/四路 I/O 器件在其他模式下会复用这些引脚。

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: 请注意，即使 Bus Pirate 的引脚定义图标出了用于连接 SPI 的 MOSI 和 MISO 引脚，某些 SPI 也可能……](<../../images/image (360).png>)

在 Windows 或 Linux 中，可以使用 [**`flashrom`**](https://www.flashrom.org/Flashrom) 程序，通过运行类似以下命令来转储 flash memory 的内容：

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

近期的 Bus Pirate 文档还列出了可选的 `serialspeed` 和 `spispeed` 参数。如果长导线或电路内负载导致读取不稳定，请从较低速度开始。<sup>[[3]](#references)</sup>

### 控制器与 flash 共用总线时的电路内读取

SOIC 夹可能会将 flash 的电源馈入 PCB 的其余部分。如果 MCU 此时上电并访问同一芯片，其 SPI 传输可能会与外部编程器的传输发生冲突。因此，出现 `No EEPROM/flash device found` 并不能证明 flash 不存在或不受支持。请先检查引脚排列、电压和接触情况，然后确认板载控制器是否也处于活动状态。<sup>[[4]](#references)</sup>

如果有复位测试焊盘，请先用万用表确认其有效电平和电压，再将其置为有效状态。让 MCU 保持在复位状态，可以在停止竞争中的 SPI 主机的同时，让 flash 仍可访问。其他方法包括拆焊芯片或被动记录 MCU 的读取操作；后者无法访问未读取的区域，也无法写入芯片，而且额外的探针接线可能会干扰高速总线。对振荡器或启动模式进行干预取决于具体目标，不能替代对原理图和信号的检查。<sup>[[4]](#references)</sup>

在 MCU 保持非活动状态时，可以使用启用了 `spidev` 接口的 Raspberry Pi，通过 flashrom 的 `linux_spi` 编程器进行读取。使用其他适配器时，请更改 `-p` 参数。重复读取并比较哈希值后再予以信任；SFDP 自动检测和成功读取**并不能**证明擦除、写入或写保护操作在其他不受支持的器件上也能正常工作。<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### 使用逻辑分析仪重建 SPI flash 读取数据

无法主动读取时，可在启动期间或执行指定 UI 操作时，捕获片选、时钟、控制器到 flash 的数据以及 flash 到控制器的数据。在 PulseView 中，先识别有效的片选区间和时钟，然后根据 flash 引脚定义配置 SPI 解码器的数据通道，并验证是否存在合理的命令/地址及其后返回的字节。使用 Binary Decoder Output View 导出 **MISO/flash 输出**字节，并保留解码出的读取地址，以便将每个响应放到对应的 flash 偏移处。仅捕获由菜单操作触发的读取，只会得到请求的区域，而非完整的 flash 镜像；未经地址核对，不要将响应直接拼接成连续数据。<sup>[[4]](#references)</sup>

如果转储内容看起来是图形而非可执行代码，请继续查看[原始显示资源初步分析](../firmware-analysis/#raw-display-assets-in-external-flash)。<sup>[[4]](#references)</sup>

## References

- [1] [Analog Devices — SPI 接口简介](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 手册 — CH341A SPI 编程器及读写选项](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 文档 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — 硬件 hacking 入门复习，第 2 部分](https://voidstarsec.com/blog/brushing-up-part-2)
{{#include ../../banners/hacktricks-training.md}}
