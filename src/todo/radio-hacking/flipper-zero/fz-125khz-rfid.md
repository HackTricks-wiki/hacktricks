# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## 简介

有关 125kHz tags 工作方式的更多信息，请查看：


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 操作

有关这类 tags 的更多信息，请[**阅读此简介**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)。

### 读取

尝试**读取**卡片信息。然后可以对其进行**模拟**。<sup>[[1]](#references)</sup>

> [!WARNING]
> 请注意，某些对讲机在读取前会发送写入命令，以防止密钥复制。如果写入成功，该 tag 就会被视为伪造。当 Flipper 模拟 RFID 时，读取器无法将其与原始 tag 区分开来，因此不会出现此类问题。

### 手动添加

你可以在 Flipper Zero 中创建**伪造卡片**，手动填写数据，然后对其进行模拟。

#### 卡片上的 ID

有时，当你拿到一张卡片时，会发现卡片上以可见方式写有其 ID（或其中一部分）。

- **EM Marin**

例如，在这张 EM-Marin 卡片上，可以从实体卡片中**明文读取 5 个字节中的最后 3 个**。\
如果无法从卡片上读取另外 2 个字节，则可以对其进行 **brute-force**。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

这张 HID 卡片也是如此，卡片上印出的 3 个字节中只有 2 个可以找到。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### 模拟/写入

**复制**卡片或**手动输入** ID 后，可以使用 Flipper Zero 对其进行**模拟**，或将其**写入**真实卡片。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [使用 Flipper Zero 深入了解 RFID 协议](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
