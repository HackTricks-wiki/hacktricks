# Hardware Hacking

{{#include ../../banners/hacktricks-training.md}}

## JTAG

JTAG 可以执行 boundary scan。Boundary scan 会分析特定电路，包括嵌入式 boundary-scan cells，以及每个引脚对应的 registers。

JTAG standard 定义了**用于执行 boundary scans 的特定 commands**，包括：

- **BYPASS** 允许你在不经过其他芯片所产生额外开销的情况下测试特定芯片。
- **SAMPLE/PRELOAD** 在设备处于正常工作模式时，对进入和离开设备的数据进行采样。
- **EXTEST** 设置并读取引脚状态。

它还支持其他 commands，例如：

- **IDCODE** 用于识别设备
- **INTEST** 用于对设备进行内部测试

使用 JTAGulator 等工具时，可能会遇到这些 instructions。

### The Test Access Port

Boundary scans 包括对四线 **Test Access Port (TAP)** 的测试。TAP 是一种通用端口，用于访问组件内置的 **JTAG test support** functions。TAP 使用以下五种 signals：

- Test clock input (**TCK**) TCK 是定义 TAP controller 多久执行一次操作的 **clock**（换句话说，就是多久跳转到 state machine 的下一个 state）。
- Test mode select (**TMS**) input TMS 控制 **finite state machine**。在 clock 的每个 beat 上，设备的 JTAG TAP controller 都会检查 TMS 引脚上的电压。如果电压低于某个 threshold，则该 signal 被视为 low，并解释为 0；如果电压高于某个 threshold，则该 signal 被视为 high，并解释为 1。
- Test data input (**TDI**) TDI 是通过 **scan cells 将 data 送入芯片**的引脚。每个 vendor 负责定义通过该引脚进行通信的 protocol，因为 JTAG 并未对此进行定义。
- Test data output (**TDO**) TDO 是将 **data 从芯片送出**的引脚。
- Test reset (**TRST**) input 可选的 TRST 会将 finite state machine 重置**到已知的良好状态**。另外，如果将 TMS 保持为 1 并持续五个 clock cycles，也会触发 reset，效果与 TRST 引脚相同，因此 TRST 是可选的。

有时你可以在 PCB 上找到标记出的这些 pins。在其他情况下，你可能需要**找到它们**。

### Identifying JTAG pins

检测 JTAG ports 最快但最昂贵的方法，是使用专门为此目的创建的 **JTAGulator**（不过它**也能检测 UART pinouts**）。

它有 **24 个 channels**，你可以将其连接到 board 的 pins。然后它会对所有可能的 combinations 执行 **BF attack**，发送 **IDCODE** 和 **BYPASS** boundary scan commands。如果收到 response，它会显示每个 JTAG signal 对应的 channel。

一种更便宜但慢得多的识别 JTAG pinouts 方法，是在 Arduino-compatible microcontroller 上加载 [**JTAGenum**](https://github.com/cyphunk/JTAGenum/)。

使用 **JTAGenum** 时，你首先需要**定义用于 enumeration 的 probing device 的 pins**。你需要参考该 device 的 pinout diagram，然后将这些 pins 与 target device 上的 test points 连接起来。

识别 JTAG pins 的**第三种方法**，是**检查 PCB** 是否存在某种 pinout。在某些情况下，PCB 可能会方便地提供 **Tag-Connect interface**，这清楚表明该 board 也有一个 JTAG connector。你可以在 [https://www.tag-connect.com/info/](https://www.tag-connect.com/info/) 查看该 interface 的外观。此外，检查 **PCB 上 chipset 的 datasheets** 也可能找到指向 JTAG interfaces 的 pinout diagrams。

## SDW

SWD 是一种专为 ARM 设计的 debugging protocol。

SWD interface 需要 **两个 pins**：双向的 **SWDIO** signal，它相当于 JTAG 的 **TDI 和 TDO pins 以及一个 clock**；以及 **SWCLK**，它相当于 JTAG 中的 **TCK**。许多 devices 支持 **Serial Wire or JTAG Debug Port (SWJ-DP)**，这是一种组合式 JTAG 和 SWD interface，允许你将 SWD 或 JTAG probe 连接到 target。

{{#include ../../banners/hacktricks-training.md}}
