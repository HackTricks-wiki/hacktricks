# 硬件 Hacking

{{#include ../../banners/hacktricks-training.md}}

对于能够物理接触的设备，首先检查其电路板或信号所暴露的接口：[UART 串行控制台](uart.md)、[JTAG/SWD 调试接口](jtag.md)、[I²C](i2c.md) 和 [SPI flash](spi.md) 总线。[Side-channel analysis](side_channel_analysis.md) 和 [fault injection](fault_injection_attacks.md) 用于不同的测量和 glitching 任务；[无线电信号分析](radio.md)则涵盖一种无线入口点。在连接工具前，请先查看目标的电气电平，以及相关章节中说明的限制。

## JTAG

JTAG（IEEE 1149.1）通过放置在设备 I/O 引脚周围的单元支持边界扫描测试。许多处理器还会通过同一个测试访问端口（TAP）暴露厂商专属的调试功能；边界扫描和 CPU 调试是 JTAG 的相关用途，但二者并非同义词。<sup>[[1]](#references)</sup>

JTAG 标准定义了**用于执行边界扫描的特定命令**，包括：

- **BYPASS** 选择一个 1 位旁路寄存器，使扫描链中的其他设备能够以最小开销被访问。
- **SAMPLE/PRELOAD** 在正常运行期间捕获引脚值，并可在执行另一条指令前预加载边界扫描寄存器。
- **EXTEST** 设置并读取引脚状态。

它还支持其他命令，例如：

- 用于识别设备的 **IDCODE**
- 用于设备内部测试的 **INTEST**

使用 JTAGulator 等工具时，你可能会遇到这些指令。

### 测试访问端口

**测试访问端口（TAP）**提供对组件 JTAG 测试逻辑的访问。需要四个信号，`TRST` 则为可选信号：<sup>[[1]](#references)</sup>

- 测试时钟输入（**TCK**）TCK 是**时钟**，用于定义 TAP 控制器执行单个操作的频率（换句话说，就是在状态机中跳转到下一个状态）。
- 测试模式选择（**TMS**）输入 TMS 控制**有限状态机**。每个时钟周期到来时，设备的 JTAG TAP 控制器都会检查 TMS 引脚上的电压。如果电压低于某个阈值，信号就会被视为低电平并解释为 0；如果电压高于某个阈值，信号就会被视为高电平并解释为 1。
- 测试数据输入（**TDI**）将串行指令或测试数据移入选定的 TAP 寄存器。IEEE 1149.1 定义了 TAP 的传输行为，而厂商则定义可选指令和调试寄存器。
- 测试数据输出（**TDO**）TDO 是用于将**芯片内的数据发送出来**的引脚。
- 测试复位（**TRST**）输入 可选的 TRST 会将有限状态机复位到**已知的正常状态**。或者，如果 TMS 连续五个时钟周期保持为 1，也会触发复位，效果与 TRST 引脚相同，因此 TRST 是可选的。

有时，PCB 上会标出这些引脚；有时则需要你**找到它们**。

### 识别 JTAG 引脚

用于检测 JTAG 端口的快速专用方案是 **JTAGulator**，但它的价格相对较高；它也能识别 UART 引脚排列。<sup>[[2]](#references)</sup>

它有 **24 个通道**，可连接到电路板测试点。它会使用 **IDCODE** 和 **BYPASS** 扫描枚举候选引脚组合，并报告与检测到的 JTAG 信号对应的通道。

一种更便宜但速度慢得多的识别 JTAG 引脚排列的方法，是在兼容 Arduino 的微控制器上运行 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)。

使用 **JTAGenum** 时，首先要定义用于枚举的探测微控制器引脚。查看其引脚布局，然后将这些引脚连接到目标电路板上的候选测试点。<sup>[[3]](#references)</sup>

识别 JTAG 引脚的**第三种方法**是**检查 PCB**，寻找已知的焊盘布局。有些电路板会暴露 **Tag-Connect** 焊盘布局，但 Tag-Connect 是一种可承载 JTAG、SWD、UART 或其他接口的连接器系统；仅凭它本身不能证明这些引脚就是 JTAG。之后可以通过元件数据手册和通断测量来识别实际信号。<sup>[[5]](#references)</sup>

## SDW

SWD 是 Arm 的双引脚、基于数据包的调试接口。<sup>[[4]](#references)</sup>

该接口使用双向的 **SWDIO** 传输数据，并使用 **SWCLK** 作为时钟。许多设备实现了 **串行线/JTAG 调试端口（SWJ-DP）**，允许在共用引脚上选择 SWD 或 JTAG。<sup>[[4]](#references)</sup>

## References

- [1] [IEEE 1149.1 工作组——JTAG 与边界扫描](https://sagroups.ieee.org/1149/1/)
- [2] [JTAGulator 文档](https://github.com/grandideastudio/jtagulator/wiki)
- [3] [JTAGenum——Arduino JTAG 引脚枚举](https://github.com/cyphunk/JTAGenum/)
- [4] [Arm——面向多设备系统的低引脚数调试接口](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Low_Pin-Count_Debug_Interfaces_for_Multi-device_Systems.pdf)
- [5] [Tag-Connect——调试与编程线缆焊盘布局](https://www.tag-connect.com/info/)
{{#include ../../banners/hacktricks-training.md}}
