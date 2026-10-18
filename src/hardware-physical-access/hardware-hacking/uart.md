# UART

{{#include ../../banners/hacktricks-training.md}}

## 基本信息

UART 是一种异步串行接口，可传输带帧的比特流，且不需要共享时钟。不要将逻辑电平 UART 与 RS-232 混淆：RS-232 使用不同的电压电平，通常为负电压，因此需要收发器。<sup>[[1]](#references)[[3]](#references)</sup>

通常，UART 处于空闲状态时，线路保持高电平（逻辑值为 1）。随后，发送器向接收器发送一个起始位以指示数据传输开始，此时信号保持低电平（逻辑值为 0）。接下来，发送器发送五到八个包含实际消息的数据位，然后根据配置发送一个可选的奇偶校验位和一到两个停止位（逻辑值为 1）。奇偶校验位用于错误检查，但在实际应用中很少见。停止位表示传输结束。

最常见的配置是 8N1：八个数据位、无奇偶校验位和一个停止位。UART 先发送数据的最低有效位，因此 ASCII 字符 `C`（`0x43`）的传输内容为：起始位 `0`；数据位 `1, 1, 0, 0, 0, 0, 1, 0`；停止位 `1`。<sup>[[1]](#references)</sup>

![UART：最常见的配置称为 8N1，即八个数据位、无奇偶校验位和一个停止位。例如，如果要通过 8N1 UART 发送字符 C（ASCII 编码为 0x43）](<../../images/image (764).png>)

用于与 UART 通信的硬件工具：

- USB 转串口适配器
- 使用 CP2102 或 PL2303 芯片的适配器
- 多功能工具，例如 Bus Pirate、Adafruit FT232H、Shikra 或 Attify Badge

### 识别 UART 端口

典型的调试接口会引出 **TX**、**RX** 和 **GND**；也可能引出 **Vcc/Vref** 引脚、复位引脚或流控引脚。Vcc 不是 UART 信号，通常只能用作电压参考，不应连接为电源，除非已确认电路板原理图和电流要求。<sup>[[2]](#references)[[3]](#references)</sup>

先关闭设备电源并断开连接：

- 使用通断档，将 **GND** 与已知的接地平面、连接器屏蔽层或电源地进行比对。切勿在电路板通电时使用通断档或电阻档。
- 给目标设备通电前，切换到直流电压档。测量候选引脚相对于地的电压，以确定逻辑电压。稳定的电源轨可能是 Vcc/Vref；不要假设连接它是安全的。
- 启动设备时，使用逻辑分析仪或示波器观察候选引脚。**TX** 通常空闲时为高电平，并会出现成帧数据突发。万用表可能显示平均电压变化，但无法验证帧格式或波特率。
- **RX** 可能一直处于空闲状态，不能仅因它紧邻 TX 就认定其身份。应追踪 PCB 走线、查阅 SoC 数据手册，或先使用高阻抗分析仪，再向其驱动信号。

交换 TX 和 RX 通常不会产生通信；混淆电源、地或信号电平则可能永久损坏目标设备或适配器。先连接地线，并从**仅接收**开始（目标设备 TX 接适配器 RX）。

制造商可能不安装接口、未焊接串联电阻、在固件中禁用控制台，或只引出 TX。追踪附近的测试焊盘和电阻焊盘到 SoC，并仅在确认电气电平后添加临时高阻抗连接。设备有保修并不意味着一定存在可访问的 UART。

### 识别 UART 波特率

识别正确波特率最简单的方法是查看 **TX 引脚的输出并尝试读取数据**。如果收到的数据无法读取，就依次尝试其他可能的波特率，直到数据变得可读。可以使用 USB 转串口适配器或 Bus Pirate 等多功能设备，并配合辅助脚本，例如 [baudrate.py](https://github.com/devttys0/baudrate/)。最常见的波特率为 9600、38400、19200、57600 和 115200。

> [!CAUTION]
> 请注意，在此协议中，需要将一个设备的 TX 连接到另一个设备的 RX！

### 使用 SCPI 自动捕获启动时的 UART 数据

如果启动输出很短，或尚未确定 TX 焊盘的位置，可以自动重复启动，而不是手动操作电源和示波器。将限流可编程电源连接到已确认的目标设备电源输入。使用共地的高阻抗示波器输入探测每个候选 TX 焊盘；不要驱动该焊盘。<sup>[[5]](#references)</sup>

VISA 用于打开串口或以太网仪器会话，而 SCPI 用于控制输出、触发和波形读取。<sup>[[5]](#references)[[6]](#references)</sup> 安装 `pyvisa` 和 `pyvisa-py`（串口 VISA 资源还需安装 `pyserial`）；`ResourceManager('@py')` 会明确选择 Python 后端。<sup>[[5]](#references)[[7]](#references)</sup> 根据所用仪器支持的内容，替换资源字符串和命令。<sup>[[5]](#references)</sup>

以 Rigol MSO5000 为例，在给电路板通电前，先设置单次下降沿触发：空闲时为高电平的 UART TX 会在起始位到来时首次变为低电平。<sup>[[5]](#references)</sup> 将触发阈值设在测得的空闲电平和低电平之间，并将时基设置为覆盖所需的启动时间段。<sup>[[5]](#references)[[6]](#references)</sup> 在连续捕获模式下，`:TRIG:HOLD` 可以抑制重复边沿，但不能代替对单次捕获是否实际完成的检查。<sup>[[5]](#references)</sup> 以下脚本捕获一次启动过程，并同时保存无符号字节样本及其缩放元数据；超时后会关闭目标设备电源，而不是无限期等待。<sup>[[5]](#references)[[6]](#references)</sup>

<details>
<summary>使用 PyVISA 上电并单次捕获 UART 波形</summary>

```python
import time
from pathlib import Path
import pyvisa

rm = pyvisa.ResourceManager('@py')
psu = rm.open_resource('ASRL/dev/ttyUSB0::INSTR')
scope = rm.open_resource('TCPIP::192.0.2.10::INSTR')
psu.baud_rate = 115200
scope.timeout = 5000
try:
    print(psu.query('*IDN?').strip(), scope.query('*IDN?').strip())
    psu.write('OUTP OFF')
    psu.write('SOUR:VOLT 3.3')
    psu.write('SOUR:CURR 0.5')
    for cmd in (':CHAN1:DISP ON', ':CHAN1:SCAL 0.5',
                ':TIM:MAIN:SCAL 0.05', ':TRIG:MODE EDGE',
                ':TRIG:EDGE:SOUR CHAN1', ':TRIG:EDGE:LEV 1.5',
                ':TRIG:EDGE:SLOP NEG'):
        scope.write(cmd)
    scope.write(':SING')
    psu.write('OUTP ON')
    deadline = time.monotonic() + 30
    while scope.query(':TRIG:STAT?').strip() != 'STOP':
        if time.monotonic() >= deadline:
            raise TimeoutError('No single-shot trigger')
        time.sleep(0.5)
    scope.write(':WAV:SOUR CHAN1')
    scope.write(':WAV:MODE RAW')
    scope.write(':WAV:FORM BYTE')
    preamble = scope.query(':WAV:PRE?').strip()
    points = int(preamble.split(',')[2])
    scope.write(f':WAV:POIN {points}')
    scope.write(':WAV:STAR 1')
    scope.write(f':WAV:STOP {points}')
    scope.timeout = 120000
    raw = scope.query_binary_values(':WAV:DATA?', datatype='B', container=bytes)
    if len(raw) != points:
        raise ValueError('Incomplete waveform; use instrument-specific batch reads')
    Path('capture.bin').write_bytes(raw)
    Path('capture_preamble.txt').write_text(preamble + '\n')
finally:
    psu.write('OUTP OFF')
    scope.close()
    psu.close()
    rm.close()
```

</details>

对于焊盘勘测，移动探针后重复单次捕获，或者保持电源会话开启，并通过设置启动保持时间和关闭间隔来循环电源输出。每次上电前都重新布防示波器，确保每个文件对应一次启动和一个焊盘。<sup>[[5]](#references)</sup>

Rigol 前导码格式为 `<format>,<type>,<points>,<count>,<xincrement>,...`。<sup>[[6]](#references)</sup> **第三个**值是采样点数，而不是文章中所说的采样率。<sup>[[5]](#references)[[6]](#references)</sup> 在示例中，`25,000,000` 个采样点和 `xincrement = 2e-8` 秒意味着 `1 / xincrement = 50,000,000` 个采样/秒，而不是 25 MSa/s。<sup>[[5]](#references)[[6]](#references)</sup> 将前导码与二进制文件一并保存，并检查读取长度是否与 `<points>` 相符；该指南介绍了针对大型记录的分段/批量读取方法。<sup>[[6]](#references)</sup>

要解码捕获的信号，请在 PulseView 中以 **Raw Analog Data Without Header** 格式导入 `capture.bin`，选择无符号 8 位（`U8`）数值，并输入根据 `xincrement` 计算出的采样率。<sup>[[5]](#references)[[6]](#references)</sup> 对模拟通道应用 **Logic via Threshold**，并选择介于低、高采样值之间的阈值。<sup>[[5]](#references)</sup> 测量干净起始位的宽度以估算波特率（57,600 baud 时约为 17.36 µs），然后应用 PulseView 的 UART 解码器，并确认多个帧都能稳定解码。<sup>[[5]](#references)</sup> 仅凭下降沿并不能证明某个焊盘是 UART。

## CP210X UART 转 TTY 适配器

CP210x USB-to-UART 桥接器常见于许多原型板和低价适配器上。常见模块除了 GND、RXD 和 TXD 外，还会引出电源引脚，但其排针布局和 I/O 电平各不相同。请根据电路板设计或数据手册确认实际电压。通常只连接 GND、适配器 RX 到目标 TX；在完成仅接收验证后，再连接适配器 TX 到目标 RX。除非有意为已确认能够承受该电压的目标设备供电，否则不要连接适配器的 5 V/3.3 V 电源引脚。<sup>[[3]](#references)</sup>

如果未检测到适配器，请确保主机系统已安装 CP210X 驱动程序。检测到适配器并完成连接后，可以使用 picocom、minicom 或 screen 等工具。

列出连接到 Linux/MacOS 系统的设备：

```
ls /dev/
```

要与 UART 接口进行基本交互，请使用以下命令：

```
picocom /dev/<adapter> --baud <baudrate>
```

对于 minicom，使用以下命令对其进行配置：

```
minicom -s
```

在 `Serial port setup` 选项中配置波特率和设备名称等设置。

配置完成后，运行 `minicom` 打开 UART 控制台。

## 通过 Arduino UNO R3 连接 UART（可拆卸 Atmel 328p 芯片的开发板）

如果没有 UART Serial to USB 适配器，可以通过一个快速技巧使用 Arduino UNO R3。由于 Arduino UNO R3 通常随处可见，这样可以节省很多时间。

Arduino UNO R3 板载了 USB 转 Serial 适配器。要建立 UART 连接，只需拔下板上的 Atmel 328p 微控制器芯片。此技巧适用于 Atmel 328p 未焊接在板上的 Arduino UNO R3 变体（使用 SMD 版本）。将 Arduino 的 RX 引脚（数字引脚 0）连接到 UART 接口的 TX 引脚，并将 Arduino 的 TX 引脚（数字引脚 1）连接到 UART 接口的 RX 引脚。

使用 Arduino IDE 的 **Serial Monitor**，或将专用终端设置为目标波特率。经典的 Uno R3 Serial 信号采用 5 V 逻辑电平，因此连接到 3.3 V 或更低电压的目标设备前，请使用电平转换器或分压器。

## Bus Pirate

以下记录使用旧版 Bus Pirate firmware 接口监控 UART 输出。较新的 Bus Pirate firmware 使用 `m uart`、`{`/`}`、`monitor` 或 `bridge` 等命令；请参阅所安装版本的文档。<sup>[[2]](#references)</sup>

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

## 使用 UART Console 转储 Firmware

UART console 提供对启动日志的运行时访问，有时还能访问 bootloader 或操作系统 shell。即使是只读 console，也会泄露内存映射、flash 驱动、启动参数、分区布局和 firmware 版本。Firmware 可能存储在 SPI NOR/NAND、eMMC 或其他设备中；它通常不会从 EEPROM 执行，而且写入已挂载持久文件系统的文件不一定会在重启后消失。

有几种获取方式，SPI 部分介绍了直接从外部 flash 读取。若 bootloader 已提供安全的读取命令，借助 console 获取数据的侵入性可能较低，但任何中断启动或 flash 命令都可能影响设备可用性，因此应记录原始状态，并避免写入或擦除操作。

借助 console 转储 firmware，通常需要先中断 bootloader。许多嵌入式 Linux 设备使用 **Das U-Boot**，但也有设备使用专有 bootloader，或禁用了交互式 console。

要测试是否存在交互式 bootloader，请在目标设备断电时连接 UART 接收线路和终端，开始记录，然后为设备通电。按照屏幕显示的 autoboot 提示操作；具体取决于构建版本，中断启动可能需要按下某个键、输入一段短序列，也可能完全被禁用。

如果成功中断启动，请使用 `help`、`printenv` 和只读探测命令，先了解该厂商的内存和存储布局，再访问地址。

在 U-Boot 中，`md` 显示的是**可寻址内存**，并非自动指向“EEPROM”。首先使用 `mtd list`、`sf probe`、`mmc info`、`part list` 等板级命令、环境变量和启动日志，确定正确的映射地址，或将 flash 区域加载到 RAM。然后逐字节显示已知范围：<sup>[[4]](#references)</sup>

```
md.b <address> <byte_count>
```

开始前先记录串口输出。`md.b` 输出包含地址列和 ASCII 列，因此它是文本表示，而不是原始 ROM 映像。

去掉地址列和 ASCII 列，仅拼接十六进制字节字段，并将其解码为二进制（例如使用 `xxd -r -p`）。分析前，验证预期字节数并记录哈希值：

```
xxd -r -p firmware.hex > firmware.bin
sha256sum firmware.bin
binwalk -e firmware.bin
```

Binwalk 随后会在重建的二进制文件中识别已知签名。如果控制台无法可靠传输数据，通过合适的 SPI/eMMC/NAND 接口直接读取闪存通常更快，也更不容易出错。

U-Boot 可能会禁用中断、要求特定于厂商的按键序列，或锁定内存/闪存命令。请根据自动启动提示和启动日志操作，不要盲目发送字符。如果无法中断控制台启动，请保留启动日志，并改用非侵入式固件获取方式。

## References

- [1] [Microchip PIC32 系列参考手册 - UART](https://ww1.microchip.com/downloads/en/DeviceDoc/60001107H.pdf)
- [2] [Bus Pirate 文档 - UART 模式和电气限制](https://docs.buspirate.com/docs/command-reference/#uart)
- [3] [Silicon Labs - CP2102C 数据手册](https://www.silabs.com/documents/public/data-sheets/cp2102c-datasheet.pdf)
- [4] [U-Boot 文档 - `md` 内存显示命令](https://docs.u-boot.org/en/latest/usage/cmd/md.html)
- [5] [VoidStar Security — 面向逆向工程师的 SCPI 和硬件仪器，第 1 部分](https://voidstarsec.com/blog/scpi-and-hardware-instrumentation-for-reverse-engineers-part-1)
- [6] [Rigol MSO5000 编程指南](https://www.batronix.com/files/Rigol/Oszilloskope/MSO5000/MSO5000_ProgrammingGuide_EN-V2.0.pdf)
- [7] [PyVISA — 配置后端](https://pyvisa.readthedocs.io/en/latest/introduction/configuring.html)
{{#include ../../banners/hacktricks-training.md}}
