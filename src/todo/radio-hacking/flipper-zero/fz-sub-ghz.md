# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 通过内置模块可以**接收和发射 300-928 MHz 范围内的无线电频率**，能够读取、保存和模拟遥控器。这些遥控器用于与大门、道闸、无线电锁、遥控开关、无线门铃、智能灯等设备进行交互。Flipper Zero 可以帮助你了解自己的安全性是否已被攻破。

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz 硬件 <a href="#kfpn7" id="kfpn7"></a>

Flipper Zero 内置了一个基于 [﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 芯片](https://www.ti.com/lit/ds/symlink/cc1101.pdf) 的低于 1 GHz 模块和一个无线电天线（最大范围为 50 米）。CC1101 芯片和天线均设计用于 300-348 MHz、387-464 MHz 和 779-928 MHz 频段。

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyzer

> [!TIP]
> 如何查找遥控器使用的频率

分析时，Flipper Zero 会扫描频率配置中所有可用频率的信号强度（RSSI）。Flipper Zero 会显示 RSSI 值最高且信号强度高于 -90 [dBm](https://en.wikipedia.org/wiki/DBm) 的频率。<sup>[[1]](#references)</sup>

要确定遥控器的频率，请执行以下操作：

1. 将遥控器放在 Flipper Zero 左侧，并尽量靠近设备。
2. 进入**主菜单** **→ Sub-GHz**。
3. 选择 **Frequency Analyzer**，然后按住要分析的遥控器上的按钮。
4. 查看屏幕上的频率值。

### Read

> [!TIP]
> 查找所使用频率的信息（也是查找所用频率的另一种方式）

**Read** 选项会在指定的调制方式下**监听已配置的频率**：默认使用 433.92 AM。如果在读取时**发现了某些内容**，屏幕上会显示**相关信息**。这些信息将来可用于复制该信号。<sup>[[1]](#references)</sup>

使用 Read 时，可以按下**左键**并对其进行**配置**。\
目前它包含 **4 种调制方式**（AM270、AM650、FM328 和 FM476），并存储了**多个相关频率**：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

你可以设置**任意感兴趣的频率**；但是，如果你**不确定遥控器所使用的频率**，请将 Hopping 设置为 ON（默认为 Off），然后多次按下按钮，直到 Flipper 捕获信号并提供设置频率所需的信息。

> [!CAUTION]
> 切换频率需要一定时间，因此在切换期间发射的信号可能会被遗漏。为了获得更好的信号接收效果，请使用 Frequency Analyzer 确定频率后设置固定频率。

### **Read Raw**

> [!TIP]
> 窃取（并重放）指定频率上的信号

**Read Raw** 选项会**记录**监听频率上发送的信号。这可用于**窃取**信号并将其**重放**。<sup>[[1]](#references)</sup>

默认情况下，**Read Raw 也使用 433.92 AM650**；但是，如果通过 Read 选项发现感兴趣的信号使用的是**其他频率/调制方式，也可以在 Read Raw 选项中按下左键进行修改**。

### Brute-Force

如果你知道车库门等设备使用的协议，就可以**生成所有代码并通过 Flipper Zero 发送这些代码**。以下示例支持常见的车库门类型：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> 从已配置的协议列表中添加信号

#### [支持的协议](https://docs.flipperzero.one/sub-ghz/add-new-remote) 列表 <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433（适用于大多数静态代码系统） | 433.92 | 静态 |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | 静态 |
| Nice Flo 24bit_433                                             | 433.92 | 静态 |
| CAME 12bit_433                                                 | 433.92 | 静态 |
| CAME 24bit_433                                                 | 433.92 | 静态 |
| Linear_300                                                     | 300.00 | 静态 |
| CAME TWEE                                                      | 433.92 | 静态 |
| Gate TX_433                                                    | 433.92 | 静态 |
| DoorHan_315                                                    | 315.00 | 动态 |
| DoorHan_433                                                    | 433.92 | 动态 |
| LiftMaster_315                                                 | 315.00 | 动态 |
| LiftMaster_390                                                 | 390.00 | 动态 |
| Security+2.0_310                                               | 310.00 | 动态 |
| Security+2.0_315                                               | 315.00 | 动态 |
| Security+2.0_390                                               | 390.00 | 动态 |

### 支持的 Sub-GHz 厂商

请查看 [https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors) 中的列表。

### 按地区划分的支持频率

请查看 [https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies) 中的列表。

### Test

> [!TIP]
> 获取已保存频率的 dBm 值

## 参考资料

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
