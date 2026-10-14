# FZ - 红外

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关红外工作原理的更多信息，请参阅：


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero 中的红外信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero 使用解调型红外接收器来捕获常见红外遥控器发出的信号。一些手机（包括某些 Xiaomi 型号）配有红外发射器，但大多数手机无法接收并解码遥控器信号。<sup>[[1]](#references)</sup>

Flipper 的红外**接收器相当灵敏**。即使你待在遥控器和电视之间的**某个位置**，也能**捕获信号**。无需将遥控器直接对准 Flipper 的红外端口。如果有人站在电视旁切换频道，而你和 Flipper 都在一定距离之外，这项功能就很实用。

协议解码由软件完成。识别出的协议可以存储为解码后的命令；不支持的协议则可以捕获为原始时序数据并重放，但会受硬件载波频率和时序限制。<sup>[[1]](#references)</sup>

## 操作

### 通用遥控器

Flipper Zero 的通用遥控器模式会从其红外数据库中循环发送已知命令，适用于受支持的电视、音频设备、投影仪和空调。它不保证能控制所有设备，只能用于你拥有或获准测试的设备。<sup>[[1]](#references)</sup>

在通用遥控器模式下，只需按下电源按钮，Flipper 就会**依次发送所有已知电视的“关机”命令**：Sony、Samsung、Panasonic……等等。电视收到信号后，就会响应并关机。

这种暴力尝试需要时间。字典越大，完成所需的时间就越长。由于电视不会反馈，因此无法确定电视具体识别了哪个信号。

### 学习新遥控器

Flipper Zero 可以**捕获红外信号**。如果它能识别协议和命令，就会存储解码后的表示形式；否则，它可以存储原始时序数据，以便稍后重放。<sup>[[1]](#references)</sup>

## References

- [1] [使用 Flipper Zero 红外端口控制电视](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
