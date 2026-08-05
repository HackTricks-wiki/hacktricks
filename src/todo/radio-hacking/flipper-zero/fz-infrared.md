# FZ - Infrared

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关 Infrared 工作原理的更多信息，请查看：


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero 中的 IR 信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper 使用 TSOP 数字 IR 信号接收器，**可以拦截来自 IR 遥控器的信号**。有一些**智能手机**（例如 Xiaomi）也配备了 IR 接口，但请注意，**大多数手机只能发送**信号，**无法接收**信号。<sup>[[1]](#references)</sup>

Flipper 的 Infrared **接收器非常灵敏**。即使你位于遥控器和电视之间的**某处位置**，也能**捕获信号**。无需将遥控器直接对准 Flipper 的 IR 接口。当有人站在电视旁切换频道，而你和 Flipper 都距离电视较远时，这一功能非常实用。

由于红外信号的**解码**发生在**软件**侧，Flipper Zero 理论上支持**接收和发送任意 IR 遥控器代码**。对于无法识别的**未知**协议，它会准确地**记录并回放**接收到的原始信号。<sup>[[1]](#references)</sup>

## 操作

### Universal Remotes

Flipper Zero 可作为**通用遥控器，用于控制任何电视、空调或媒体中心**。在此模式下，Flipper 会根据 SD 卡中的字典，对所有受支持制造商的所有**已知代码**进行 **bruteforces**。你无需选择特定遥控器即可关闭餐厅里的电视。<sup>[[1]](#references)</sup>

在 Universal Remote 模式下，只需按下电源按钮，Flipper 就会**依次发送所有已知电视的“Power Off”**命令：Sony、Samsung、Panasonic……等等。当电视接收到对应信号后，就会作出反应并关闭。

这种 brute-force 需要一定时间。字典越大，完成所需的时间越长。由于电视不会提供反馈，因此无法得知电视究竟识别了哪个信号。

### 学习新遥控器

Flipper Zero 可以**捕获红外信号**。如果它在数据库中**找到该信号**，Flipper 将自动**识别对应设备**，并允许你与其交互。\
如果找不到，Flipper 可以**存储**该**信号**，并允许你**重放该信号**。<sup>[[1]](#references)</sup>

## 参考资料

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
