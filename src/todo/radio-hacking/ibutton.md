# iButton

{{#include ../../banners/hacktricks-training.md}}

## 简介

iButton 是一种通用名称，指封装在**硬币形金属容器**中的电子识别钥匙。它也被称为 **Dallas Touch** Memory 或 contact memory。尽管它经常被错误地称为“磁性”钥匙，但其中**没有任何磁性元件**。事实上，内部隐藏着一枚通过数字协议运行的完整**微芯片**。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是钥匙和读取器的物理形态——一个带有两个触点的圆形硬币。用于包裹它的外框有很多种，从最常见的带孔塑料外壳，到环形、吊坠等形式。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

当钥匙接触读取器时，**触点会相互接触**，钥匙通电并**传输**其 ID。有时钥匙不会被**立即读取**，因为对讲机的**接触 PSD 大于应有尺寸**，导致钥匙和读取器的外部轮廓无法接触。如果出现这种情况，你需要将钥匙按在读取器的一侧边缘上。

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire protocol** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keys 使用 1-wire protocol 交换数据。在两个方向上，即从 master 到 slave 以及反向传输时，都只使用一个数据传输触点 (!!)。1-wire protocol 遵循 Master-Slave 模型。在这种拓扑中，Master 始终发起通信，Slave 则按照其指令执行。

当钥匙（Slave）接触对讲机（Master）时，钥匙内部的芯片由对讲机供电并启动，随后钥匙完成初始化。接着，对讲机请求钥匙 ID。下面我们将更详细地了解这一过程。

Flipper 可以工作在 Master 和 Slave 两种模式下。在钥匙读取模式中，Flipper 充当读取器，也就是说它工作在 Master 模式。在钥匙仿真模式中，Flipper 假装成一把钥匙，处于 Slave 模式。

### Dallas、Cyfral 和 Metakom keys

有关这些钥匙工作方式的信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 攻击

可以使用 Flipper Zero 对 iButtons 发起攻击：


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## 参考资料

- [1] [Taming iButton](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
