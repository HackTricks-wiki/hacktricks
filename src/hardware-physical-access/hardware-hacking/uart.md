# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

UART 是一种异步串行接口，无需共享时钟即可传输带帧的比特流。不要将逻辑电平 UART 与 RS-232 混淆：RS-232 使用不同的电压电平（通常为负电压），并且需要收发器。<sup>[[1]](#references)[[3]](#references)</sup>

通常，UART 处于空闲状态时，线路保持高电平（逻辑值 1）。随后，为了通知接收器数据传输开始，发送器会发送一个起始位，此时信号保持低电平（逻辑值 0）。接着，发送器发送五到八个包含实际消息的数据位，之后根据配置发送一个可选的奇偶校验位和一个或两个停止位（逻辑值为 1）。奇偶校验位用于错误检查，在实际应用中很少见。停止位表示传输结束。

最常见的配置是 8N1：八个数据位、无奇偶校验位和一个停止位。UART 先发送数据的最低有效位，因此 ASCII 字符 `C`（`0x43`）的传输内容为：起始位 `0`；数据位 `1, 1, 0, 0, 0, 0, 1, 0`；停止位 `1`。<sup>[[1]](#references)</sup>

![UART：最常见的配置称为 8N1：八个数据位、无奇偶校验位和一个停止位。例如，如果要通过 8N1 UART 发送字符 C（ASCII 编码为 0x43）](<../../images/image (764).png>)

用于与 UART 通信的硬件工具：

- USB 转串口适配器
- 使用 CP2102 或 PL2303 芯片的适配器
- 多用途工具，例如：Bus Pirate、Adafruit FT232H、Shikra 或 Attify Badge

### 识别 UART 端口

典型的调试排针会引出 **TX**、**RX** 和 **GND**；也可能引出 **Vcc/Vref** 引脚、复位引脚或流控引脚。Vcc 不是 UART 信号，通常只能用作电压参考，不应连接为电源，除非已确认电路板原理图和电流要求。<sup>[[2]](#references)[[3]](#references)</sup>

开始前，请先**关闭设备电源**并断开连接：

- 使用通断档，将 **GND** 与已知的接地平面、连接器屏蔽层或电源地进行比对。请勿在通电的电路板上使用通断档或电阻档。
- 给目标设备通电前，先切换到直流电压档。测量候选引脚相对于地的电压，以确定逻辑电压。稳定的电压轨可能是 Vcc/Vref；不要假设连接它是安全的。
- 在启动期间，使用逻辑分析仪或示波器观察候选引脚。**TX** 通常空闲时为高电平，并会出现成帧数据突发。万用表可能会显示平均电压变化，但无法验证帧格式或波特率。
- **RX** 可能一直处于空闲状态，不能仅凭它与 TX 相邻就安全地判断其身份。可追踪 PCB 走线、查阅 SoC 数据手册，或使用高阻抗分析仪后再驱动该引脚。

交换 TX 和 RX 通常只会导致无法通信；混淆电源、地或信号电平则可能永久损坏目标设备或适配器。先连接地线，并从**仅接收**开始（目标设备 TX 接适配器 RX）。

制造商可能会省略排针、未焊接串联电阻、在固件中禁用控制台，或只引出 TX。追踪附近的测试焊盘和电阻焊盘至 SoC，并仅在确认电气电平后添加临时高阻抗连接。设备有保修并不意味着它一定有可访问的 UART。

### 识别 UART 波特率

识别正确波特率最简单的方法是查看 **TX 引脚的输出并尝试读取数据**。如果收到的数据不可读，就切换到下一个可能的波特率，直到数据变得可读。你可以使用 USB 转串口适配器或 Bus Pirate 之类的多用途设备，并配合辅助脚本，例如 [baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率是 9600、38400、19200、57600 和 115200。

> [!CAUTION]
> 请注意，在此协议中，必须将一个设备的 TX 连接到另一个设备的 RX！

## CP210X UART 转 TTY 适配器

CP210x USB 转 UART 桥接器常见于许多原型板和廉价适配器上。常见模块会在 GND、RXD 和 TXD 之外引出电源引脚，但其排针配置和 I/O 电平各不相同。请根据电路板设计或数据手册确认实际电压。通常只连接 GND、将适配器 RX 接到目标设备 TX；在仅接收验证通过后，再将适配器 TX 接到目标设备 RX。除非有意为已确认能够承受该电压的目标设备供电，否则不要连接适配器的 5 V/3.3 V 电源引脚。<sup>[[3]](#references)</sup>

如果未检测到适配器，请确认主机系统已安装 CP210X 驱动程序。检测到并连接适配器后，可以使用 picocom、minicom 或 screen 等工具。

列出连接到 Linux/MacOS 系统的设备：

```
ls /dev/
```

要与 UART 接口进行基本交互，请使用以下命令：

```
picocom /dev/<adapter> --baud <baudrate>
```

对于 minicom，请使用以下命令进行配置：

```
minicom -s
```

在 `Serial port setup` 选项中配置波特率、设备名称等设置。

配置完成后，运行 `minicom` 打开 UART 控制台。

## 通过 Arduino UNO R3 使用 UART（可拆卸 Atmel 328p 芯片的开发板）

如果没有 UART 转 USB 适配器，可以通过一个快速 hack 使用 Arduino UNO R3。Arduino UNO R3 通常随处可见，因此这样能节省大量时间。

Arduino UNO R3 板载 USB 转 Serial 适配器。要建立 UART 连接，只需从板上拔下 Atmel 328p 微控制器芯片。此 hack 适用于 Atmel 328p 未焊接在板上的 Arduino UNO R3 变体（这类板使用 SMD 版本）。将 Arduino 的 RX 引脚（数字引脚 0）连接到 UART 接口的 TX 引脚，并将 Arduino 的 TX 引脚（数字引脚 1）连接到 UART 接口的 RX 引脚。

使用 Arduino IDE 的 **Serial Monitor**，或使用专用终端并设置目标波特率。经典 Uno R3 的串行信号采用 5 V 逻辑电平，因此连接到 3.3 V 或更低电压的目标设备之前，请使用电平转换器或分压器。

## Bus Pirate

以下记录使用旧版 Bus Pirate 固件接口监控 UART 输出。较新版的 Bus Pirate 固件使用 `m uart`、`{`/`}`、`monitor` 或 `bridge` 等命令；请查阅对应安装版本的文档。<sup>[[2]](#references)</sup>

```bash
# Check the modes
UART>m
1. HiZ
2. 1-WIRE
3. UART
4. I2C
5. SPI
6. 2WIRE
7. 3WIRE
8. KEYB
9. LCD
10. PIC
11. DIO
x. exit(without change)

# Select UART
(1)>3
Set serial port speed: (bps)
 1. 300
 2. 1200
 3. 2400
 4. 4800
 5. 9600
 6. 19200
 7. 38400
 8. 57600
 9. 115200
10. BRG raw value

# Select the speed the communication is occurring on (you BF all this until you find readable things)
# Or you could later use the macro (4) to try to find the speed
(1)>5
Data bits and parity:
 1. 8, NONE *default
 2. 8, EVEN
 3. 8, ODD
 4. 9, NONE

 # From now on pulse enter for default
(1)>
Stop bits:
 1. 1 *default
 2. 2
(1)>
Receive polarity:
 1. Idle 1 *default
 2. Idle 0
(1)>
Select output type:
 1. Open drain (H=Hi-Z, L=GND)
 2. Normal (H=3.3V, L=GND)

(1)>
Clutch disengaged!!!
To finish setup, start up the power supplies with command 'W'
Ready

# Start
UART>W
POWER SUPPLIES ON
Clutch engaged!!!

# Use macro (2) to read the data of the bus (live monitor)
UART>(2)
Raw UART input
Any key to exit
Escritura inicial completada:
AAA Hi Dreg! AAA
waiting a few secs to repeat....
```

## 使用 UART 控制台转储固件

UART 控制台可在运行时访问启动日志，有时还能访问 bootloader 或操作系统 shell。即使是只读控制台，也能显示内存映射、flash 驱动程序、启动参数、分区布局和固件版本。固件可能存储在 SPI NOR/NAND、eMMC 或其他设备中；通常不会从 EEPROM 执行，而且写入已挂载持久文件系统的文件不一定会在重启后消失。

固件采集有多种途径，SPI 一节介绍了直接从外部 flash 读取。若 bootloader 已提供安全的读取命令，通过控制台辅助采集可能侵入性更低；但中断启动或执行 flash 命令可能影响设备可用性，因此应记录原始状态，并避免写入或擦除操作。

通过控制台辅助转储固件，通常要先中断 bootloader。许多嵌入式 Linux 设备使用 **Das U-Boot**，但也有设备使用专有 bootloader，或禁用了交互式控制台。

要测试是否存在交互式 bootloader，请在目标设备断电时连接 UART 接收线路和终端，开始记录，然后给设备通电。按照屏幕显示的自动启动提示操作；具体取决于固件构建方式，中断启动可能需要按下某个键、输入一段简短按键序列，也可能完全不可用。

如果成功中断启动，请先使用 `help`、`printenv` 和只读探测命令，了解该厂商的内存和存储布局，然后再访问地址。

在 U-Boot 中，`md` 显示的是**可寻址内存**，并不会自动指向“EEPROM”。首先使用特定于板子的命令（如 `mtd list`、`sf probe`、`mmc info`、`part list`）、环境变量和启动日志，确定正确的映射地址，或将 flash 区域加载到 RAM 中。然后逐字节显示已知范围：<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

开始前先记录串口输出。`md.b` 的输出包含地址列和 ASCII 列，因此它是文本表示形式，而非原始 ROM 映像。

剥离地址列和 ASCII 列，只拼接十六进制字节字段，并将其解码为二进制（例如使用 `xxd -r -p`）。分析前，请核对预期字节数并记录哈希值：

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk 随后会在重构出的二进制文件中识别已知签名。当控制台无法可靠传输数据时，通过合适的 SPI/eMMC/NAND 接口直接读取闪存通常更快，也更不容易出错。

U-Boot 可能会禁用中断、要求特定厂商的按键序列，或锁定内存/闪存命令。请根据自动启动提示和启动日志操作，不要盲目发送字符。如果无法中断控制台，请保留启动日志，并改用非侵入式固件获取方式。

## References

- [1] [Microchip PIC32 系列参考手册 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate 文档 - UART 模式和电气限制](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C 数据手册](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot 文档 - `md` 内存显示命令](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
