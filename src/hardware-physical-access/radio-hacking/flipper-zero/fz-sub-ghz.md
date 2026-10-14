# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#introduction" id="introduction"></a>

Flipper Zero 内置模块可**接收和发射 300-928 MHz 范围内的无线电频率**，但需遵守所配置区域的频率限制。它可以读取、保存和模拟兼容的遥控器，这些遥控器可用于大门、闸门、无线电锁、开关、无线门铃、智能灯及其他设备。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 硬件 <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero 内置基于 CC1101 收发器和无线电天线的 sub-1 GHz 模块。实际范围取决于频率、天线、环境和发射器；Flipper 文档指出，在条件理想时，距离最高约为 50 米。硬件覆盖 300-348 MHz、387-464 MHz 和 779-928 MHz，而固件和区域规定会进一步限制发射。<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> 如何查找遥控器使用的频率

分析时，Flipper Zero 会扫描频率配置中所有可用频率的信号强度（RSSI）。Flipper Zero 会显示 RSSI 值最高且信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm) 的频率。<sup>[[1]](#references)</sup>

要确定遥控器的频率，请按以下步骤操作：

1. 将遥控器紧贴 Flipper Zero 左侧放置。
2. 前往 **主菜单** **→ Sub-GHz**。
3. 选择 **Frequency Analyzer**，然后按住要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### Read

> [!TIP]
> 查找所用频率的信息（也可以用其他方法查找所用频率）

**Read** 选项会监听已配置的频率和调制方式（默认为 433.92 MHz AM）。识别到受支持的信号后，屏幕会显示相关信息，可供保存并在之后重放。<sup>[[1]](#references)</sup>

使用 Read 时，可以按下**左侧按钮**进行**配置**。\
目前支持 **4 种调制方式**（AM270、AM650、FM328 和 FM476），并存储了**若干相关频率**：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

你可以选择任何允许使用的频率。如果不确定遥控器使用的频率，请将 **Hopping 设为 ON**（默认关闭），然后多次按下遥控器按钮，直到 Flipper 捕获信号并报告频率。

> [!CAUTION]
> 切换频率需要一些时间，因此切换期间发射的信号可能会漏掉。要更好地接收信号，请使用 Frequency Analyzer 确定频率后将其设为固定频率。

### **Read Raw**

> [!TIP]
> 窃取（并重放）配置频率上的信号

**Read Raw** 选项会记录在所选频率上发送的信号。可在授权测试期间用它捕获并重放信号。<sup>[[1]](#references)</sup>

默认情况下，**Read Raw 也使用 433.92 MHz 和 AM650**。如果 Read 在其他频率或调制方式上发现信号，请在 Read Raw 中按 Left 更改这些设置。

### Brute-Force

如果你知道某设备（例如车库门）使用的协议，就可能**生成候选代码并使用 Flipper Zero 发射**。`flipperzero-bruteforce` 项目支持几种常见的静态码协议。<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> 从已配置的协议列表中添加信号

#### 支持的协议列表 <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually 菜单提供 Flipper Zero 文档中列出的协议预设。<sup>[[4]](#references)</sup>

| Princeton_433 (适用于大多数静态码系统) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### 支持的 Sub-GHz 厂商

查看 Flipper Zero 支持的厂商列表。<sup>[[5]](#references)</sup>

### 各地区支持的频率

发射前请查看官方地区频率列表。<sup>[[6]](#references)</sup>

### 测试

> [!TIP]
> 获取已保存频率的 dBm 值

## References

- [1] [Sub-GHz - Flipper Zero 用户文档](https://docs.flipperzero.one/sub-ghz)
- [2] [德州仪器 CC1101 数据手册](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - 添加手动创建的遥控器](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - 支持的 Sub-GHz 厂商](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - 各地区 Sub-GHz 频率](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
