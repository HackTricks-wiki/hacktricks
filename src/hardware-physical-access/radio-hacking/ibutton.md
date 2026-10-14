# iButton

{{#include ../../banners/hacktricks-training.md}}

## 简介

iButton 是一种通用名称，指封装在**硬币形金属外壳**中的电子识别钥匙。它也称为 Dallas Touch Memory 或接触式存储器。尽管它常被误称为“磁性”钥匙，但其中**没有任何磁性元件**。实际上，内部隐藏着一枚通过数字协议运行的完整**微芯片**。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton 这个名称描述的是耐用的硬币形封装及其触点布局。外壳形式包括塑料钥匙扣、戒指和吊坠。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

两个触点都与读卡器接触时，设备便会获得电源并交换数据。如果凹陷的触点结构导致外侧接地触点无法接触，沿读卡器侧壁倾斜钥匙可能有助于恢复接触。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim 钥匙使用 1-Wire 协议：一个数据触点承载双向通信，也可能提供寄生供电，而金属外壳则作为回流触点。控制器发起事务，设备进行响应。<sup>[[2]](#references)</sup>

当钥匙（Slave）与对讲机（Master）接触时，钥匙内部的芯片会由对讲机供电并启动，钥匙随即完成初始化。之后，对讲机会请求钥匙 ID。下面我们将更详细地了解这一过程。

Flipper 在读取钥匙时可以充当控制器，也可以在向读卡器提供已存储的标识符时充当模拟设备。<sup>[[1]](#references)</sup>

### Dallas、Cyfral 和 Metakom 钥匙

有关这些钥匙工作原理的信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 攻击

可以使用 Flipper Zero 攻击 iButton：


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [使用 Flipper Zero 驯服 iButton](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 通过软件实现 1-Wire 通信](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
