# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

无线电安全测试会检查设备如何发射、接收和解读无线信号。软件定义无线电（SDR）可以帮助定位信号、记录同相/正交（I/Q）采样，并测试解调和解码，而无需专门使用特定协议的硬件。<sup>[[1]](#references)</sup>

实用的工作流程是：确定频段和信道带宽，捕获设备执行几种已知操作时的信号，对比所得信号，然后判断调制方式和数据包结构。仅在隔离环境中，并且仅使用你获准操作的频率和设备进行重放或发射测试。本节页面涵盖 RFID、NFC、sub-GHz 无线电、红外、BLE 及相关工具。<sup>[[1]](#references)</sup>

## 查找相关接口

- 对于门禁卡或接触式钥匙，可从 [RFID/NFC 标签类型与攻击](pentesting-rfid.md)、[Proxmark3 工作流程](proxmark-3.md)或 [iButton 和 1-Wire 钥匙](ibutton.md)开始。[Flipper Zero 指南](flipper-zero/README.md)链接到针对其接口的操作。
- 对于遥控信号，可使用 [sub-GHz RF 和滚动码](sub-ghz-rf.md)或[红外协议与攻击](infrared.md)。
- 对于附近的设备和传感器，可使用 [BLE 广播、GATT 和 mesh 测试](pentesting-ble-bluetooth-low-energy.md)或 [LPWAN/LoRaWAN 安全](low-power-wide-area-network.md)。
- 对于捕获到的或未知的 RF 信号，可使用 [SigDigger 信号分析](../hardware-hacking/radio.md#sigdigger)或 [FISSURE 框架](fissure-the-rf-framework.md)。

## References

- [1] [Great Scott Gadgets - 使用 HackRF 的软件定义无线电](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
