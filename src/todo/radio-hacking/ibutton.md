# iButton

{{#include ../../banners/hacktricks-training.md}}

## 简介

iButton 是一种电子识别钥匙的通用名称，其封装在**硬币形金属容器**中。它也被称为 **Dallas Touch** Memory 或接触式存储器。尽管它经常被错误地称为“磁性”钥匙，但其中**完全没有磁性元件**。实际上，内部隐藏着一个运行数字协议的完整**微芯片**。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (915).png" alt=""><figcaption></figcaption></figure>

### 什么是 iButton？ <a href="#what-is-ibutton" id="what-is-ibutton"></a>

iButton 这一名称描述的是其耐用的硬币形封装和触点排列方式。其载体包括塑料钥匙扣、戒指和吊坠。

<figure><img src="../../images/image (1078).png" alt=""><figcaption></figcaption></figure>

当两个触点与读卡器接触时，设备会获得电力并交换数据。如果凹陷的触点结构导致外部接地触点无法接触，将钥匙抵在读卡器侧壁上倾斜，可以恢复接触。<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (290).png" alt=""><figcaption></figcaption></figure>

### **1-Wire 协议** <a href="#id-1-wire-protocol" id="id-1-wire-protocol"></a>

Dallas/Maxim keys 使用 1-Wire 协议：一个数据触点承载双向通信，也可以提供寄生供电，而金属外壳则作为回路触点。控制器发起事务，设备进行响应。<sup>[[2]](#references)</sup>

当钥匙（从设备）与对讲机（主设备）接触时，钥匙内部的芯片由对讲机供电并启动，随后钥匙完成初始化。接着，对讲机会请求钥匙 ID。下面我们将更详细地了解这一过程。

Flipper 在读取钥匙时可以充当控制器，在向读卡器提供已存储的标识符时，也可以充当模拟设备。<sup>[[1]](#references)</sup>

### Dallas、Cyfral 和 Metakom keys

有关这些 keys 工作方式的信息，请查看页面 [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)<sup>[[1]](#references)</sup>

### 攻击

可以使用 Flipper Zero 对 iButtons 发起攻击：


{{#ref}}
flipper-zero/fz-ibutton.md
{{#endref}}

## References

- [1] [使用 Flipper Zero 驯服 iButton](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Analog Devices — 通过软件进行 1-Wire 通信](https://www.analog.com/en/resources/technical-articles/1wire-communication-through-software.html)
{{#include ../../banners/hacktricks-training.md}}
