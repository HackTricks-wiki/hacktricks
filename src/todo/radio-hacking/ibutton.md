# iButton

{{#include ../../banners/hacktricks-training.md}}

## 介绍

iButton 是一种电子识别钥匙的通用名称，装在一个 **硬币形状的金属容器** 中。它也被称为 **Dallas Touch** Memory 或接触式存储器。尽管它常常被错误地称为“磁性”钥匙，但里面 **没有任何磁性**。实际上，里面隐藏着一个完整的 **微芯片**，它在数字协议上运行。

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是钥匙和读卡器的物理形态 - 一个带有两个接触点的圆形硬币。围绕它的框架有很多变体，从最常见的带孔塑料支架到戒指、挂件等。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

当钥匙接触到读卡器时，**接触点接触**，钥匙被供电以 **传输** 其 ID。有时钥匙 **不会立即被读取**，因为 **对讲机的接触 PSD 较大**。因此，钥匙和读卡器的外部轮廓无法接触。如果是这种情况，您需要将钥匙按在读卡器的一个墙面上。

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas 钥匙使用 1-wire 协议交换数据。仅用一个接触点进行数据传输 (!!)，双向传输，从主设备到从设备，反之亦然。1-wire 协议按照主从模型工作。在这种拓扑中，主设备始终发起通信，从设备遵循其指令。

当钥匙（从设备）接触到对讲机（主设备）时，钥匙内部的芯片开启，由对讲机供电，钥匙被初始化。随后，对讲机请求钥匙 ID。接下来，我们将更详细地查看这个过程。

Flipper 可以在主模式和从模式下工作。在钥匙读取模式下，Flipper 充当读卡器，也就是说它作为主设备工作。而在钥匙仿真模式下，Flipper 假装是钥匙，处于从模式。

### Dallas、Cyfral 和 Metakom 钥匙

有关这些钥匙如何工作的更多信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

### 攻击

iButtons 可以通过 Flipper Zero 进行攻击：

{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## 参考

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
