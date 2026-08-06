# iButton

{{#include ../../banners/hacktricks-training.md}}

## 简介

iButton 是一种通用名称，指封装在**硬币形金属容器**中的电子身份识别钥匙。它也被称为 **Dallas Touch** Memory 或接触式存储器。尽管它经常被错误地称为“磁性”钥匙，但其中**没有任何磁性元件**。事实上，内部隐藏着一枚基于数字协议运行的完整**微芯片**。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

通常，iButton 指的是钥匙和读卡器的物理形态——带有两个触点的圆形硬币。用于固定它的外框有许多不同形式，从最常见的带孔塑料外壳，到环形、吊坠形等。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

当钥匙接触读卡器时，**触点相互接触**，钥匙获得供电并**传输**其 ID。有时钥匙**无法立即读取**，因为对讲机的**接触式 PSD 大于应有尺寸**。因此，钥匙和读卡器的外部轮廓可能无法相互接触。如果出现这种情况，则必须将钥匙按在读卡器的某一侧壁上。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas keys 使用 1-wire 协议交换数据。数据传输在两个方向上都只使用一个数据触点 (!!)，既可以从主设备传输到从设备，也可以反向传输。1-wire 协议遵循主从模型。在这种拓扑结构中，主设备始终发起通信，而从设备遵循其指令。

当钥匙（从设备）接触对讲机（主设备）时，钥匙内部的芯片由对讲机供电并启动，随后钥匙完成初始化。接着，对讲机请求钥匙 ID。下面我们将更详细地了解这一过程。

Flipper 既可以工作在主设备模式，也可以工作在从设备模式。在钥匙读取模式下，Flipper 充当读卡器，也就是说它工作在主设备模式。在钥匙仿真模式下，Flipper 模拟一把钥匙，处于从设备模式。<sup>[[1]](#references)</sup>

### Dallas、Cyfral 与 Metakom keys

有关这些 keys 工作方式的信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 攻击

可以使用 Flipper Zero 对 iButton 发起攻击：


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## 参考资料

- [1] [Taming iButton with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../banners/hacktricks-training.md}}
