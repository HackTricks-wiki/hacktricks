# FZ - 红外线

{{#include ../../../banners/hacktricks-training.md}}

## 介绍 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线工作原理的更多信息，请查看：

{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero 中的 IR 信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper 使用数字 IR 信号接收器 TSOP，这 **允许拦截来自 IR 遥控器的信号**。有一些 **智能手机**，如小米，也有 IR 端口，但请记住，**大多数只能发送** 信号，**无法接收**。

Flipper 的红外线 **接收器非常灵敏**。您甚至可以在 **遥控器和电视之间的某个地方** 捕捉信号。将遥控器直接指向 Flipper 的 IR 端口并不是必需的。当有人在电视旁边换频道时，这非常方便，而您和 Flipper 都在一定距离之外。

由于 **红外线信号的解码** 在 **软件** 端进行，Flipper Zero 潜在支持 **接收和发送任何 IR 遥控代码**。在 **未知** 协议无法识别的情况下，它 **记录并回放** 原始信号，完全按照接收到的方式。

## 操作

### 通用遥控器

Flipper Zero 可以用作 **通用遥控器来控制任何电视、空调或媒体中心**。在此模式下，Flipper **暴力破解** 所有支持制造商的 **已知代码**，**根据 SD 卡中的字典**。您无需选择特定的遥控器来关闭餐厅的电视。

只需在通用遥控器模式下按下电源按钮，Flipper 将 **依次发送所有已知电视的“关机”** 命令：索尼、三星、松下……等等。当电视接收到信号时，它将做出反应并关闭。

这种暴力破解需要时间。字典越大，完成所需的时间就越长。无法确定电视确切识别了哪个信号，因为电视没有反馈。

### 学习新遥控器

可以使用 Flipper Zero **捕捉红外线信号**。如果它 **在数据库中找到信号**，Flipper 将自动 **知道这是什么设备** 并允许您与之交互。\
如果没有，Flipper 可以 **存储** 该 **信号** 并允许您 **重播** 它。

## 参考

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
