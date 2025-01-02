# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## 介绍

有关125kHz标签工作原理的更多信息，请查看：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 操作

有关这些类型标签的更多信息 [**请阅读此介绍**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)。

### 读取

尝试**读取**卡片信息。然后可以**模拟**它们。

> [!WARNING]
> 请注意，一些对讲机试图通过在读取之前发送写入命令来保护自己免受密钥复制。如果写入成功，则该标签被视为假标签。当Flipper模拟RFID时，读卡器无法将其与原始标签区分开，因此不会出现此类问题。

### 手动添加

您可以在Flipper Zero中创建**指示您手动输入数据的假卡**，然后模拟它。

#### 卡片上的ID

有时，当您获得一张卡时，您会发现卡片上可见的ID（或部分ID）。

- **EM Marin**

例如，在这张EM-Marin卡中，可以**清晰地读取最后3个字节中的5个字节**。\
如果您无法从卡片上读取其他2个字节，可以通过暴力破解来获取。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

在这张HID卡中也是如此，只有3个字节中的2个可以在卡片上找到。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### 模拟/写入

在**复制**一张卡或**手动输入**ID后，可以使用Flipper Zero**模拟**它或在真实卡片上**写入**它。

## 参考

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
