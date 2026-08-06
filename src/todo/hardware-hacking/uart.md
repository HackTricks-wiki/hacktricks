# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

UART 是一种串行协议，这意味着它在组件之间一次传输一位数据。相比之下，并行通信协议会通过多个通道同时传输数据。常见的串行协议包括 RS-232、I2C、SPI、CAN、Ethernet、HDMI、PCI Express 和 USB。

通常情况下，UART 处于空闲状态时，线路保持高电平（逻辑值为 1）。随后，为了向接收器指示数据传输开始，发送器会向接收器发送一个起始位，此时信号保持低电平（逻辑值为 0）。接下来，发送器会发送五到八个包含实际消息的数据位，然后根据配置发送一个可选的奇偶校验位，以及一个或两个停止位（逻辑值为 1）。奇偶校验位用于错误检查，但在实践中很少见。停止位表示传输结束。

最常见的配置称为 8N1：八个数据位、无奇偶校验位和一个停止位。例如，如果要发送字符 C（ASCII 中为 0x43），在 8N1 UART 配置下，需要发送以下位：0（起始位）；0、1、0、0、0、0、1、1（0x43 的二进制值）；以及 0（停止位）。

![UART：最常见的配置称为 8N1：八个数据位、无奇偶校验位和一个停止位。例如，如果要发送字符 C（ASCII 中为 0x43），在 8N1 UART 配置下](<../../images/image (764).png>)

用于与 UART 通信的硬件工具：

- USB-to-serial adapter
- 使用 CP2102 或 PL2303 芯片的适配器
- 多用途工具，例如：Bus Pirate、Adafruit FT232H、Shikra 或 Attify Badge

### 识别 UART 端口

UART 有 4 个端口：**TX**（Transmit，发送）、**RX**（Receive，接收）、**Vcc**（Voltage，电压）和 **GND**（Ground，接地）。你可能会在 PCB 上找到标有 **`TX`** 和 **`RX`** 字母的 4 个端口。但如果没有任何标识，则可能需要使用**万用表**或**逻辑分析仪**自行查找。

使用**万用表**并关闭设备电源：

- 要识别 **GND** 引脚，请使用**通断测试**模式，将黑色表笔接地，然后用红色表笔逐个测试，直到听到万用表发出声音。PCB 上可能有多个 GND 引脚，因此你找到的未必是 UART 对应的那个。
- 要识别 **VCC 端口**，设置为**直流电压模式**，并将量程设置为 20 V。黑色表笔接地，红色表笔接触引脚。打开设备电源。如果万用表测得稳定的 3.3 V 或 5 V 电压，则找到了 Vcc 引脚。如果测得其他电压，请使用其他端口重试。
- 要识别 **TX** **端口**，设置为**直流电压模式**，量程设置为 20 V，黑色表笔接地，红色表笔接触引脚，然后打开设备电源。如果发现电压在几秒内波动，随后稳定到 Vcc 电压值，那么你很可能找到了 TX 端口。这是因为设备开机时会发送一些调试数据。
- **RX 端口**通常是距离其他 3 个端口最近的一个，其电压波动最小，并且在所有 UART 引脚中总体电压值最低。

如果将 TX 和 RX 端口接反，不会发生任何事情；但如果将 GND 和 VCC 端口接反，可能会烧毁电路。

在某些目标设备中，制造商会通过禁用 RX、TX 或两者来禁用 UART 端口。在这种情况下，沿着电路板上的连接进行追踪并寻找某个 breakout point 可能会有所帮助。确认 UART 未被检测到以及电路被断开的一个重要线索，是检查设备保修情况。如果设备出厂时带有保修，制造商通常会保留一些调试接口（在本例中为 UART），因此必须在设备出厂前断开 UART，并在调试时重新连接。这些 breakout pins 可以通过焊接或 jumper wires 进行连接。

### 识别 UART 波特率

识别正确波特率最简单的方法，是查看 **TX 引脚的输出并尝试读取数据**。如果收到的数据不可读，则切换到下一个可能的波特率，直到数据变得可读。你可以使用 USB-to-serial adapter 或 Bus Pirate 等多用途设备，并配合辅助脚本，例如 [baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率包括 9600、38400、19200、57600 和 115200。

> [!CAUTION]
> 需要注意的是，在该协议中，你必须将一个设备的 TX 连接到另一个设备的 RX！

## CP210X UART to TTY Adapter

CP210X Chip 被广泛用于 NodeMCU（使用 esp8266）等原型开发板的 Serial Communication。这些适配器价格相对低廉，可用于连接目标设备的 UART 接口。该设备有 5 个引脚：5V、GND、RXD、TXD 和 3.3V。务必连接目标设备支持的电压，以避免造成损坏。最后，将 Adapter 的 RXD 引脚连接到目标设备的 TXD，将 Adapter 的 TXD 引脚连接到目标设备的 RXD。

如果未检测到适配器，请确保主机系统中已安装 CP210X drivers。检测到并连接适配器后，可以使用 picocom、minicom 或 screen 等工具。

列出连接到 Linux/MacOS 系统的设备：
```
ls /dev/
```
要与 UART 接口进行基本交互，请使用以下命令：
```
picocom /dev/<adapter> --baud <baudrate>
```
对于 minicom，使用以下命令进行配置：
```
minicom -s
```
在 `Serial port setup` 选项中配置 baudrate 和设备名称等设置。

配置完成后，使用命令 `minicom` 启动 UART Console。

## 通过 Arduino UNO R3（可拆卸 Atmel 328p 芯片板）使用 UART

如果没有 UART Serial to USB adapters，可以通过一个简单的 hack 使用 Arduino UNO R3。由于 Arduino UNO R3 通常随处可见，这可以节省大量时间。

Arduino UNO R3 的板载 USB to Serial adapter。要建立 UART 连接，只需将 Atmel 328p microcontroller chip 从板上拔出即可。此 hack 适用于 Atmel 328p 未焊接在板上的 Arduino UNO R3 变体（其中使用的是 SMD 版本）。将 Arduino 的 RX pin（Digital Pin 0）连接到 UART Interface 的 TX pin，并将 Arduino 的 TX pin（Digital Pin 1）连接到 UART interface 的 RX pin。

最后，建议使用 Arduino IDE 获取 Serial Console。在菜单的 `tools` 部分中，选择 `Serial Console` 选项，并根据 UART interface 设置 baud rate。

## Bus Pirate

在此场景中，我们将 sniff Arduino 的 UART communication；该 Arduino 会将程序的所有 prints 发送到 Serial Monitor。
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

UART Console 提供了一种在 runtime environment 中操作底层固件的有效方式。但是，当 UART Console access 为 read-only 时，可能会带来很多限制。在许多 embedded devices 中，固件存储在 EEPROM 中，并由使用 volatile memory 的处理器执行。因此，固件保持 read-only，因为制造过程中使用的原始固件本身位于 EEPROM 中，而任何新文件都会因 volatile memory 而丢失。因此，在操作 embedded firmwares 时，dumping firmware 是一项很有价值的工作。

有很多方法可以做到这一点，SPI 部分介绍了使用各种设备直接从 EEPROM 提取固件的方法。不过，建议首先尝试使用 UART dumping firmware，因为使用 physical devices 以及进行 external interactions 来 dumping firmware 可能存在风险。

从 UART Console dumping firmware 首先需要获取对 bootloaders 的访问权限。许多 popular vendors 使用 uboot（Universal Bootloader）作为加载 Linux 的 bootloader。因此，获取 uboot 的访问权限是必要的。

要访问 boot bootloader，请将 UART port 连接到 computer，并使用任意 Serial Console tools，同时保持设备的 power supply 断开。设置完成后，按下 Enter Key 并保持按住。最后，将 power supply 连接到设备并让其启动。

这样会中断 uboot 的加载并提供一个 menu。建议了解 uboot commands，并使用 help menu 列出这些命令。命令可能是 `help`。由于不同 vendors 使用不同的 configurations，因此有必要分别理解每种 configuration。

通常，dumping firmware 的 command 是：
```
md
```
它代表“memory dump”。这会将内存（EEPROM Content）转储并显示在屏幕上。建议在开始此过程之前记录 Serial Console 的输出，以捕获内存转储。

最后，只需从日志文件中删除所有不必要的数据，将文件保存为 `filename.rom`，然后使用 binwalk 提取其内容：
```
binwalk -e <filename.rom>
```
这将根据 hex 文件中找到的签名，列出 EEPROM 可能包含的内容。

不过需要注意的是，即使设备正在使用 uboot，也不一定意味着 uboot 是解锁的。如果按下 Enter Key 没有任何反应，请尝试其他按键，例如 Space Key 等。如果 bootloader 已锁定且无法被中断，此方法将无法工作。要检查 uboot 是否是设备的 bootloader，请在设备启动时查看 UART Console 的输出。启动过程中可能会提到 uboot。

{{#include ../../banners/hacktricks-training.md}}
