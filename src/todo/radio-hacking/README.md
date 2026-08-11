# Radio Hacking

{{#include ../../banners/hacktricks-training.md}}

无线电安全测试用于检查设备如何传输、接收和解析无线信号。软件定义无线电（SDR）可以帮助定位信号、记录同相/正交（I/Q）采样，并在不依赖特定协议硬件的情况下测试解调和解码。<sup>[[1]](#references)</sup>

一种实用的工作流程是确定频段和信道宽度，捕获设备执行多个已知操作时产生的信号，比较所得信号，然后确定调制方式和数据包结构。仅在隔离环境中，并且仅使用你获得授权的频率和设备进行 replay 或传输测试。本节涵盖 RFID、NFC、sub-GHz radio、infrared、BLE 及相关工具。<sup>[[1]](#references)</sup>

## References

- [1] [Great Scott Gadgets - 使用 HackRF 的软件定义无线电](https://greatscottgadgets.com/sdr/1/)
{{#include ../../banners/hacktricks-training.md}}
