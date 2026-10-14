# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## 简介

有关 125 kHz 标签工作原理的背景信息，请参阅：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[低频 RFID 简介](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)介绍了常见的标签系列及其数据格式。

## 操作

### 读取

使用 **读取** 来采集标签数据。成功读取后，Flipper Zero 可以模拟保存的标签。<sup>[[1]](#references)</sup>

> [!WARNING]
> 一些对讲机读卡器会在读取前发送写入命令，试图检测可写的重复标签。Flipper Zero 模拟时无法像可写标签那样访问标签内存。<sup>[[1]](#references)</sup>

### 手动添加

你可以在 Flipper Zero 中手动输入标签数据、保存，然后模拟该标签。<sup>[[1]](#references)</sup>

#### 卡片上的 ID

有时卡片的 ID 全部或部分印在卡片表面。

- **EM Marin**

例如，图中所示的 EM-Marin 卡片露出了其五个 ID 字节中的最后三个。如果无法读取标签，可以对缺失的两个字节进行暴力破解。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

类似地，图中所示的 HID 卡片只印出了三个 ID 字节中的两个。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### 模拟/写入

读取标签或手动输入其 ID 后，Flipper Zero 可以模拟保存的凭证。对于支持写入的标签，它还可以将保存的数据写入兼容卡片。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero：深入了解 RFID 协议](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
