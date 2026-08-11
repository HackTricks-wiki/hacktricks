# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

UART 是一种异步串行接口，用于传输没有共享时钟的成帧比特流。不要将逻辑电平 UART 与 RS-232 混淆：RS-232 使用不同且通常为负的电压电平，并且需要收发器。<sup>[[1]](#references)[[3]](#references)</sup>

通常，在 UART 处于空闲状态时，线路保持高电平（逻辑值为 1）。随后，为了表示数据传输开始，发送器向接收器发送一个起始位，此时信号保持低电平（逻辑值为 0）。接下来，发送器发送五到八个包含实际消息的数据位，之后根据配置发送一个可选的奇偶校验位以及一个或两个停止位（逻辑值为 1）。奇偶校验位用于错误检查，但在实际应用中很少见。停止位表示传输结束。

最常见的配置是 8N1：八个数据位、无奇偶校验位和一个停止位。UART 首先发送最低有效数据位，因此 ASCII `C`（`0x43`）的传输形式为：起始位 `0`；数据位 `1, 1, 0, 0, 0, 0, 1, 0`；停止位 `1`。<sup>[[1]](#references)</sup>

![UART：我们将最常见的配置称为 8N1：八个数据位、无奇偶校验位和一个停止位。例如，如果我们要发送字符 C，即 ASCII 中的 0x43，那么在 8N1 UART 中](<../../images/image (764).png>)

用于与 UART 通信的硬件工具：

- USB 转串口适配器
- 使用 CP2102 或 PL2303 芯片的适配器
- 多用途工具，例如：Bus Pirate、Adafruit FT232H、Shikra 或 Attify Badge

### 识别 UART 端口

典型的调试接口会引出 **TX**、**RX** 和 **GND**；也可能引出 **Vcc/Vref** 引脚、复位引脚或流控制引脚。Vcc 不是 UART 信号，通常只能用作电压参考，而不应连接为电源，除非已知电路板的原理图和电流要求。<sup>[[2]](#references)[[3]](#references)</sup>

从设备**断电**且未连接的状态开始：

- 使用通断模式，将 **GND** 与已知的接地平面、连接器屏蔽层或电源地进行比对来识别。切勿在通电电路板上使用通断/电阻模式。
- 在为目标设备通电前，切换到直流电压模式。测量候选引脚相对于地的电压，以识别逻辑电压。稳定的电源轨可能是 Vcc/Vref；不要假设连接它是安全的。
- 在启动期间，使用逻辑分析仪或示波器观察候选引脚。**TX** 通常处于高电平空闲状态，并显示成帧数据的突发信号。万用表可能显示平均波动，但无法验证成帧方式或波特率。
- **RX** 可能保持空闲状态，不能仅因其位于 TX 旁边就安全地将其识别出来。在驱动该引脚之前，应追踪 PCB 走线、查阅 SoC 数据表，或使用高阻抗分析仪。

交换 TX 和 RX 通常不会产生通信；混淆电源、地线或信号电平可能永久损坏目标设备或适配器。先连接地线，并从**仅接收**开始（目标设备 TX 连接适配器 RX）。

制造商可能省略接口、未装配串联电阻、在固件中禁用控制台，或仅引出 TX。追踪附近的测试焊盘和电阻焊盘至 SoC，并且只有在确认电气电平后，才添加临时高阻抗连接。存在保修并不意味着一定存在可访问的 UART。

### 识别 UART 波特率

识别正确波特率的最简单方法是查看 **TX 引脚的输出并尝试读取数据**。如果收到的数据不可读，则切换到下一个可能的波特率，直到数据变得可读。可以使用 USB 转串口适配器，或使用 Bus Pirate 等多用途设备来完成此操作，并配合辅助脚本，例如 [baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率为 9600、38400、19200、57600 和 115200。

> [!CAUTION]
> 需要注意的是，在此协议中，必须将一个设备的 TX 连接到另一个设备的 RX！

## CP210X UART 转 TTY 适配器

CP210x USB 转 UART 桥接器常见于许多原型开发板和廉价适配器中。常见模块会在 GND、RXD 和 TXD 旁边引出电源引脚，但其接口和 I/O 电平各不相同。请根据电路板设计或数据表确认实际电压。通常只连接 GND、将适配器 RX 连接到目标设备 TX，并在完成仅接收验证后，将适配器 TX 连接到目标设备 RX。除非明确要为已知能够承受该电压的目标设备供电，否则不要连接适配器的 5 V/3.3 V 电源引脚。<sup>[[3]](#references)</sup>

如果未检测到适配器，请确保主机系统已安装 CP210X 驱动程序。检测到并连接适配器后，可以使用 picocom、minicom 或 screen 等工具。

列出连接到 Linux/MacOS 系统的设备：
```
ls /dev/
```
进行 UART 接口基本交互时，使用以下命令：
```
picocom /dev/<adapter> --baud <baudrate>
```
对于 minicom，使用以下命令进行配置：
```
minicom -s
```
在 `Serial port setup` 选项中配置 baudrate、设备名称等设置。

配置完成后，运行 `minicom` 打开 UART console。

## 通过 Arduino UNO R3（可拆卸 Atmel 328p 芯片的开发板）使用 UART

如果没有 UART Serial to USB adapters，可以通过一个简单的 hack 使用 Arduino UNO R3。由于 Arduino UNO R3 通常随处可见，这可以节省大量时间。

Arduino UNO R3 的板载 USB to Serial adapter。要建立 UART connection，只需将 Atmel 328p microcontroller chip 从开发板上拔下即可。此 hack 适用于 Atmel 328p 未焊接在开发板上的 Arduino UNO R3 variants（使用 SMD version 的型号）。将 Arduino 的 RX pin（Digital Pin 0）连接到 UART Interface 的 TX pin，并将 Arduino 的 TX pin（Digital Pin 1）连接到 UART interface 的 RX pin。

使用 Arduino IDE 的 **Serial Monitor** 或专用 terminal，并设置为目标 baud rate。经典 Uno R3 的 serial signals 使用 5 V logic，因此在将其连接到 3.3 V 或更低电压的 target 前，请使用 level shifter 或 divider。

## Bus Pirate

以下 transcript 使用旧版 Bus Pirate firmware interface 监控 UART output。较新的 Bus Pirate firmware 使用 `m uart`、`{`/`}`、`monitor` 或 `bridge` 等 commands；请参阅已安装版本的 documentation。<sup>[[2]](#references)</sup>
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
## 使用 UART Console Dumping Firmware

UART Console 提供对 boot logs 的运行时访问，有时还可以访问 bootloader 或 operating-system shell。即使是只读 Console，也能泄露 memory maps、flash drivers、boot arguments、partition layouts 和 firmware versions。Firmware 可能存储在 SPI NOR/NAND、eMMC 或其他设备中；它通常并不是从 EEPROM 执行的，并且写入已挂载 persistent filesystem 的文件不一定会在 reboot 后消失。

有几种 acquisition 路径，SPI 部分介绍了从 external flash 直接读取的方法。当 bootloader 已提供安全的 read command 时，使用 Console 辅助 acquisition 的侵入性可能更低；但任何 boot interruption 或 flash command 都可能影响可用性，因此应记录原始状态，并避免 write/erase 操作。

使用 Console dump firmware 通常从中断 bootloader 开始。许多 embedded Linux 设备使用 **Das U-Boot**，但其他设备可能使用 proprietary bootloaders，或禁用 interactive Console。

要测试 interactive bootloader，请在 target 断电时连接 UART receive path 和 terminal，开始 logging，然后给设备上电。按照显示的 autoboot prompt 操作；根据 build 的不同，中断可能需要按下某个 key、输入一段短 sequence，或者可能完全被禁用。

如果中断成功，请使用 `help`、`printenv` 和 read-only discovery commands，先了解该 vendor 的 memory 和 storage layout，再访问地址。

在 U-Boot 中，`md` 显示的是 **addressable memory**，并不会自动显示 “EEPROM”。首先使用 board-specific commands，例如 `mtd list`、`sf probe`、`mmc info`、`part list`、environment variables 和 boot logs，确定正确的 mapped address，或将某个 flash region 加载到 RAM。然后逐字节显示一个已知范围：<sup>[[4]](#references)</sup>
```
md.b <address> <byte_count>
```
在开始前记录 serial 输出。`md.b` 输出包含地址和 ASCII 列，因此它是文本表示，而不是原始 ROM 镜像。

去除地址列和 ASCII 列，仅拼接十六进制字节字段，并将其解码为二进制（例如使用 `xxd -r -p`）。在分析前验证预期字节数并记录 hash：
```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```
Binwalk 随后会在重建的 binary 中识别已知签名。当 console 无法可靠传输数据时，通过适当的 SPI/eMMC/NAND interface 直接读取 flash 通常更快，也更不容易出错。

U-Boot 可能会禁用中断、要求使用 vendor-specific key sequence，或锁定 memory/flash commands。应根据 autoboot prompt 和 boot log 操作，而不是盲目发送字符。如果 console 无法被中断，请保留 boot log，并转而采用 non-invasive firmware acquisition 路径。

## References

- [1] [Microchip PIC32 Family Reference Manual - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate documentation - UART mode and electrical limits](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C data sheet](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot documentation - `md` memory-display command](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
{{#include ../../banners/hacktricks-training.md}}
