# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 介绍 <a href="#introduction" id="introduction"></a>

Flipper Zero 可通过内置模块**接收和传输 300-928 MHz 范围内的无线电频率**，但会受到已配置区域的频率限制。它可以读取、保存并模拟用于大门、道闸、无线电锁、开关、无线门铃、智能灯及其他设备的兼容遥控器。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 硬件 <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero 内置基于 CC1101 transceiver 和无线电天线的 sub-1 GHz 模块。实际范围取决于频率、天线、环境和发射器；Flipper 文档显示，在有利条件下最远约为 50 米。硬件覆盖 300-348 MHz、387-464 MHz 和 779-928 MHz，而 firmware 和区域规则会进一步限制传输。<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> 如何查找遥控器使用的频率

分析时，Flipper Zero 会扫描频率配置中所有可用频率的信号强度（RSSI）。Flipper Zero 会显示 RSSI 值最高且信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm) 的频率。<sup>[[1]](#references)</sup>

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放置在 Flipper Zero 左侧，并尽量靠近设备。
2. 进入 **Main Menu** **→ Sub-GHz**。
3. 选择 **Frequency Analyzer**，然后按住要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### Read

> [!TIP]
> 查找所使用频率的信息（也是查找所用频率的另一种方法）

**Read** 选项会监听配置的频率和 modulation（默认为 433.92 MHz AM）。识别到受支持的信号后，屏幕会显示相关信息，之后可以保存并重放该信号。<sup>[[1]](#references)</sup>

使用 Read 时，可以按下**左侧按钮**并**进行配置**。\
目前它有 **4 种 modulations**（AM270、AM650、FM328 和 FM476），并存储了**多种相关频率**：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

你可以选择任何允许的频率。如果不确定遥控器使用的频率，请将 **Hopping 设置为 ON**（默认关闭），然后多次按下遥控器按钮，直到 Flipper 捕获信号并报告频率。

> [!CAUTION]
> 切换频率需要一定时间，因此在切换期间传输的信号可能会丢失。为了获得更好的信号接收效果，请设置由 Frequency Analyzer 确定的固定频率。

### **Read Raw**

> [!TIP]
> 窃取（并重放）配置频率上的信号

**Read Raw** 选项会记录在所选频率上发送的信号。可以在经过授权的测试期间使用该功能捕获并重放信号。<sup>[[1]](#references)</sup>

默认情况下，**Read Raw 也使用 433.92 MHz 和 AM650**。如果 Read 在其他频率或 modulation 上发现了信号，请在 Read Raw 中按 Left 更改这些设置。

### Brute-Force

如果你知道某个设备（例如车库门）所使用的 protocol，则可能可以**生成候选 code，并通过 Flipper Zero 传输这些 code**。`flipperzero-bruteforce` 项目支持多种常见的 static-code protocols。<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> 从已配置的 protocols 列表中添加信号

#### 支持的 protocols 列表 <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually 菜单提供了 Flipper Zero 文档中记录的 protocol presets。<sup>[[4]](#references)</sup>

| Princeton_433 (适用于大多数 static code systems) | 433.92 | Static  |
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

### 受支持的 Sub-GHz vendors

查看 Flipper Zero 的 supported-vendors 列表。<sup>[[5]](#references)</sup>

### 各区域支持的频率

在传输之前查看官方 regional-frequency 列表。<sup>[[6]](#references)</sup>

### 测试

> [!TIP]
> 获取已保存频率的 dBm 值

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
