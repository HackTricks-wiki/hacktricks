# FZ - 红外

{{#include ../../../banners/hacktricks-training.md}}

## 简介 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

有关 Infrared 工作原理的更多信息，请查看：


{{#ref}}
../infrared.md
{{#endref}}

## Flipper Zero 中的 IR 信号接收器 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zero 使用解调型 IR 接收器来捕获常见 IR 遥控器发出的信号。部分手机（包括某些 Xiaomi 型号）配备了 IR 发射器，但大多数手机无法接收和解码遥控信号。<sup>[[1]](#references)</sup>

Flipper 的 Infrared **接收器非常灵敏**。即使你位于遥控器和电视之间的**某个位置**，也可以**捕获信号**。无需将遥控器直接对准 Flipper 的 IR 接口。当有人站在电视附近切换频道，而你和 Flipper 都距离电视较远时，这一特性非常实用。

Protocol decoding 在软件中完成。已识别的 protocols 可以保存为 decoded commands；不支持的 protocols 则可以作为 raw timing data 捕获并重放，但受硬件载波频率和 timing 限制。<sup>[[1]](#references)</sup>

## 操作

### Universal Remotes

Flipper Zero 的 universal-remote 模式会针对受支持的电视、音频设备、投影仪和空调，从其 infrared database 中循环发送已知 commands。它不保证能够控制所有设备，并且只能用于你拥有或获授权测试的设备。<sup>[[1]](#references)</sup>

在 Universal Remote 模式下，只需按下电源按钮，Flipper 就会**依次发送**它所知的所有电视的“Power Off” commands：Sony、Samsung、Panasonic……等等。当电视接收到相应信号后，就会做出响应并关机。

这种 brute-force 需要一定时间。dictionary 越大，完成所需的时间就越长。由于电视不会返回反馈，因此无法确定电视究竟识别了哪个信号。

### Learn New Remote

Flipper Zero 可以**捕获 infrared signal**。如果它识别出 protocol 和 command，就会保存 decoded representation；否则，可以保存 raw timing data 以便之后重放。<sup>[[1]](#references)</sup>

## References

- [1] [使用 Flipper Zero Infrared Port 控制电视](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
