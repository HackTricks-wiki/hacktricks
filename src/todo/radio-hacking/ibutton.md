# iButton

{{#include ../../banners/hacktricks-training.md}}

## Intro

iButton 是一种电子识别密钥的通用名称，装在一个 **硬币形状的金属容器** 中。它也被称为 **Dallas Touch** Memory 或接触式存储器。尽管它常常被错误地称为“磁性”密钥，但里面 **没有任何磁性**。实际上，里面隐藏着一个完整的 **微芯片**，它在数字协议上运行。

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### What is iButton? <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是密钥和读卡器的物理形式 - 一个带有两个接触点的圆形硬币。对于其周围的框架，有许多变体，从最常见的带孔塑料支架到戒指、挂件等。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

当密钥接触到读卡器时，**接触点接触**，密钥被供电以 **传输** 其 ID。有时密钥 **不会立即被读取**，因为 **对讲机的接触 PSD 较大**。因此，密钥和读卡器的外轮廓无法接触。如果是这种情况，您需要将密钥按在读卡器的一个侧面上。

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 密钥使用 1-wire 协议交换数据。仅用一个接触点进行数据传输 (!!)，双向传输，从主设备到从设备，反之亦然。1-wire 协议按照主从模型工作。在这种拓扑中，主设备始终发起通信，从设备遵循其指令。

当密钥（从设备）接触到对讲机（主设备）时，密钥内部的芯片开启，由对讲机供电，密钥被初始化。随后，对讲机请求密钥 ID。接下来，我们将更详细地查看这个过程。

Flipper 可以在主模式和从模式下工作。在密钥读取模式下，Flipper 充当读卡器，也就是说它作为主设备工作。而在密钥仿真模式下，Flipper 假装是一个密钥，处于从模式。

### Dallas, Cyfral & Metakom keys

有关这些密钥如何工作的更多信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### Attacks

iButtons 可以通过 Flipper Zero 进行攻击：

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
