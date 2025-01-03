# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 可以 **接收和发送 300-928 MHz 范围内的无线电频率**，其内置模块可以读取、保存和模拟遥控器。这些遥控器用于与门、障碍物、无线电锁、遥控开关、无线门铃、智能灯等进行交互。Flipper Zero 可以帮助您了解您的安全性是否受到威胁。

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 具有基于 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf) 的内置 sub-1 GHz 模块和一根无线电天线（最大范围为 50 米）。CC1101 芯片和天线均设计用于在 300-348 MHz、387-464 MHz 和 779-928 MHz 频段内工作。

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!NOTE]
> 如何找到遥控器使用的频率

在分析时，Flipper Zero 正在扫描频率配置中所有可用频率的信号强度 (RSSI)。Flipper Zero 显示 RSSI 值最高的频率，信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm)。

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放置在 Flipper Zero 左侧非常靠近的位置。
2. 转到 **主菜单** **→ Sub-GHz**。
3. 选择 **频率分析仪**，然后按住您想要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### Read

> [!NOTE]
> 查找使用的频率信息（也是查找使用频率的另一种方法）

**读取**选项 **在配置的频率上监听**，默认调制为 433.92 AM。如果在读取时 **发现了某些内容**，则 **屏幕上会提供信息**。这些信息可以用于将来复制信号。

在使用读取时，可以按 **左按钮** 并 **进行配置**。\
此时它有 **4 种调制方式**（AM270、AM650、FM328 和 FM476），并存储了 **几个相关频率**：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

您可以设置 **任何您感兴趣的频率**，但是，如果您 **不确定遥控器使用的频率**，请 **将跳频设置为开启**（默认关闭），并多次按下按钮，直到 Flipper 捕获到它并提供您设置频率所需的信息。

> [!CAUTION]
> 在频率之间切换需要一些时间，因此在切换时传输的信号可能会丢失。为了更好的信号接收，请设置由频率分析仪确定的固定频率。

### **Read Raw**

> [!NOTE]
> 在配置的频率上窃取（并重放）信号

**读取原始**选项 **记录在监听频率上发送的信号**。这可以用于 **窃取** 信号并 **重复** 它。

默认情况下 **读取原始也在 433.92 AM650**，但如果通过读取选项发现您感兴趣的信号在 **不同的频率/调制中，您也可以通过按左键进行修改**（在读取原始选项内）。

### Brute-Force

如果您知道例如车库门使用的协议，可以 **生成所有代码并通过 Flipper Zero 发送它们。** 这是一个支持一般常见类型车库的示例：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!NOTE]
> 从配置的协议列表中添加信号

#### [支持的协议](https://docs.flipperzero.one/sub-ghz/add-new-remote) 列表 <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (适用于大多数静态代码系统) | 433.92 | 静态  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | 静态  |
| Nice Flo 24bit_433                                             | 433.92 | 静态  |
| CAME 12bit_433                                                 | 433.92 | 静态  |
| CAME 24bit_433                                                 | 433.92 | 静态  |
| Linear_300                                                     | 300.00 | 静态  |
| CAME TWEE                                                      | 433.92 | 静态  |
| Gate TX_433                                                    | 433.92 | 静态  |
| DoorHan_315                                                    | 315.00 | 动态 |
| DoorHan_433                                                    | 433.92 | 动态 |
| LiftMaster_315                                                 | 315.00 | 动态 |
| LiftMaster_390                                                 | 390.00 | 动态 |
| Security+2.0_310                                               | 310.00 | 动态 |
| Security+2.0_315                                               | 315.00 | 动态 |
| Security+2.0_390                                               | 390.00 | 动态 |

### 支持的 Sub-GHz 供应商

查看 [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) 中的列表

### 按地区支持的频率

查看 [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) 中的列表

### Test

> [!NOTE]
> 获取保存频率的 dBms

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
