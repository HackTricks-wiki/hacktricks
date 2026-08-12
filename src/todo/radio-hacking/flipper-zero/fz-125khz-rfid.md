# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Intro

有关 125 kHz 标签工作原理的背景信息，请参阅：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[低频 RFID 简介](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)介绍了常见的标签系列及其数据格式。

## Actions

### Read

使用 **Read** 捕获标签数据。成功读取后，Flipper Zero 可以模拟保存的标签。<sup>[[1]](#references)</sup>

> [!WARNING]
> 某些对讲机读卡器会在读取前发送写入命令，以尝试检测可写的复制标签。Flipper Zero 的模拟不会以相同方式暴露可写标签存储器。<sup>[[1]](#references)</sup>

### Add manually

你可以在 Flipper Zero 中手动输入标签数据、保存数据，然后进行模拟。<sup>[[1]](#references)</sup>

#### IDs on cards

有时，卡片会将其全部或部分 ID 印刷在外部。

- **EM Marin**

例如，图示的 EM-Marin 卡片显示了其五个 ID 字节中的最后三个。如果无法读取标签，可以对缺失的两个字节进行 brute-force。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

类似地，图示的 HID 卡片只印刷了三个 ID 字节中的两个。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

读取标签或手动输入其 ID 后，Flipper Zero 可以模拟保存的凭据。对于受支持的可写标签，它还可以将保存的数据写入兼容卡片。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero：深入了解 RFID 协议](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
