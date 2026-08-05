# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 通过其内置模块可以**接收和发射 300-928 MHz 范围内的无线电频率**，能够读取、保存和模拟遥控器。这些遥控器用于操作大门、道闸、无线电锁、遥控开关、无线门铃、智能灯等设备。Flipper Zero 可以帮助你了解自己的安全性是否已遭到破坏。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 内置了基于 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf)的 sub-1 GHz 模块和无线电天线（最大范围为 50 米）。CC1101 芯片和天线均设计用于 300-348 MHz、387-464 MHz 和 779-928 MHz 频段。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> 如何查找遥控器使用的频率

分析时，Flipper Zero 会扫描频率配置中所有可用频率的信号强度（RSSI）。Flipper Zero 会显示 RSSI 值最高且信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm) 的频率。<sup>[[1]](#references)</sup>

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放置在 Flipper Zero 左侧，并尽量靠近设备。
2. 前往 **Main Menu** **→ Sub-GHz**。
3. 选择 **Frequency Analyzer**，然后按住要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### Read

> [!TIP]
> 查找所使用频率的信息（也是查找所用频率的另一种方法）

**Read** 选项会在指定的 modulation 上监听**已配置的频率**：默认为 433.92 AM。如果读取时**发现了某些内容**，屏幕上会显示**相关信息**。这些信息将来可用于复制该信号。<sup>[[1]](#references)</sup>

使用 Read 时，可以按下**左键**并对其进行**配置**。\
目前它有 **4 种 modulation**（AM270、AM650、FM328 和 FM476），并存储了**多个相关频率**：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

你可以设置**任何感兴趣的频率**。但是，如果你**不确定遥控器使用的是哪个频率**，请将 Hopping 设置为 ON（默认为 Off），然后多次按下按钮，直到 Flipper 捕获到信号并提供设置频率所需的信息。

> [!CAUTION]
> 在不同频率之间切换需要一定时间，因此切换期间发射的信号可能会丢失。为了获得更好的信号接收效果，请使用 Frequency Analyzer 确定的固定频率。

### **Read Raw**

> [!TIP]
> 窃取（并重放）指定频率上的信号

**Read Raw** 选项会**记录**监听频率上的信号。可以利用它**窃取**并**重复发送**信号。

默认情况下，**Read Raw 也使用 433.92 AM650**；但如果你通过 Read 选项发现感兴趣的信号使用的是**不同的频率/modulation，也可以在 Read Raw 选项中按左键进行修改**。

### Brute-Force

如果你知道车库门等设备使用的协议，就可以**生成所有 code 并通过 Flipper Zero 发送它们。**以下示例支持常见的车库门类型：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 手动添加

> [!TIP]
> 从已配置的协议列表中添加信号

#### [受支持的协议](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433（适用于大多数 static code 系统） | 433.92 | Static  |
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

### 受支持的 Sub-GHz 厂商

请查看 [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) 中的列表。

### 各地区支持的频率

请查看 [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) 中的列表。

### 测试

> [!TIP]
> 获取已保存频率的 dBm 值

## 参考资料

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
