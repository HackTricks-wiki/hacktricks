# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外线工作原理的更多信息，请查看：

{{#ref}}
../infrared.md
{{#endref}}

## IR Signal Receiver in Flipper Zero <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper使用数字IR信号接收器TSOP，这**允许拦截来自IR遥控器的信号**。有一些**智能手机**如小米，也有IR端口，但请记住，**大多数只能发送**信号，**无法接收**信号。

Flipper的红外线**接收器相当敏感**。您甚至可以在**遥控器和电视之间的某个地方**捕捉到信号。将遥控器直接指向Flipper的IR端口并不是必要的。这在某人站在电视附近切换频道时非常方便，而您和Flipper都在一定距离之外。

由于**红外线信号的解码**发生在**软件**端，Flipper Zero潜在地支持**接收和发送任何IR遥控代码**。在无法识别的**未知**协议的情况下，它**记录并回放**接收到的原始信号。

## Actions

### Universal Remotes

Flipper Zero可以用作**通用遥控器来控制任何电视、空调或媒体中心**。在此模式下，Flipper会**暴力破解**所有支持制造商的**已知代码**，**根据SD卡中的字典**。您无需选择特定的遥控器来关闭餐厅的电视。

只需在通用遥控模式下按下电源按钮，Flipper将**依次发送所有已知电视的“关机”**命令：索尼、三星、松下……等等。当电视接收到信号时，它将做出反应并关闭。

这种暴力破解需要时间。字典越大，完成所需的时间就越长。无法确定电视确切识别了哪个信号，因为电视没有反馈。

### Learn New Remote

可以使用Flipper Zero**捕获红外信号**。如果它**在数据库中找到信号**，Flipper将自动**知道这是哪个设备**并允许您与之交互。\
如果没有，Flipper可以**存储**该**信号**并允许您**重播**它。

## References

- [https://blog.flipperzero.one/infrared/](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
