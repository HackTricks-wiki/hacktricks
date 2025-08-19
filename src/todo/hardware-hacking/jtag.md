# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) 是一个可以加载到兼容Arduino的MCU或（实验性地）Raspberry Pi上的工具，用于暴力破解未知的JTAG引脚排列，甚至枚举指令寄存器。

- Arduino：将数字引脚D2–D11连接到最多10个可疑的JTAG垫/测试点，并将Arduino GND连接到目标GND。除非你知道电源轨是安全的，否则单独为目标供电。优先使用3.3 V逻辑（例如，Arduino Due），或者在探测1.8–3.3 V目标时使用电平转换器/串联电阻。
- Raspberry Pi：Pi构建暴露的可用GPIO较少（因此扫描速度较慢）；请查看repo以获取当前引脚图和限制。

一旦刷写完成，打开115200波特率的串口监视器并发送`h`以获取帮助。典型流程：

- `l` 查找环回以避免误报
- `r` 如有需要，切换内部上拉电阻
- `s` 扫描TCK/TMS/TDI/TDO（有时还包括TRST/SRST）
- `y` 暴力破解IR以发现未记录的操作码
- `x` 引脚状态的边界扫描快照

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)

如果找到有效的TAP，你将看到以`FOUND!`开头的行，表示发现的引脚。

提示
- 始终共享接地，切勿将未知引脚驱动到高于目标Vtref的电压。如果有疑问，请在候选引脚上添加100–470 Ω的串联电阻。
- 如果设备使用SWD/SWJ而不是4线JTAG，JTAGenum可能无法检测到；尝试SWD工具或支持SWJ-DP的适配器。

## 更安全的引脚探测和硬件设置

- 首先使用万用表识别Vtref和GND。许多适配器需要Vtref来设置I/O电压。
- 电平转换：优先使用为推挽信号设计的双向电平转换器（JTAG线路不是开漏）。避免为JTAG使用自动方向的I2C转换器。
- 有用的适配器：FT2232H/FT232H板（例如，Tigard）、CMSIS-DAP、J-Link、ST-LINK（特定于供应商）、ESP-USB-JTAG（在ESP32-Sx上）。至少连接TCK、TMS、TDI、TDO、GND和Vtref；可选连接TRST和SRST。

## 与OpenOCD的首次接触（扫描和IDCODE）

OpenOCD是JTAG/SWD的事实上的开源软件。使用支持的适配器，你可以扫描链并读取IDCODE：

- 使用J-Link的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部探头）：
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
笔记
- 如果您得到“全为1/0”的IDCODE，请检查接线、电源、Vtref，以及端口是否被保险丝/选项字节锁定。
- 请参阅OpenOCD低级`irscan`/`drscan`，以便在启动未知链时手动进行TAP交互。

## 停止CPU并转储内存/闪存

一旦识别了TAP并选择了目标脚本，您可以停止核心并转储内存区域或内部闪存。示例（调整目标、基地址和大小）：

- 初始化后的通用目标：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（优先使用SBA，如果可用）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，通过 OpenOCD 辅助程序进行编程或读取：
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- 使用 `mdw/mdh/mdb` 在长时间转储之前检查内存的完整性。
- 对于多设备链，在非目标设备上设置 BYPASS 或使用定义所有 TAP 的板文件。

## 边界扫描技巧 (EXTEST/SAMPLE)

即使 CPU 调试访问被锁定，边界扫描仍可能被暴露。使用 UrJTAG/OpenOCD 你可以：
- SAMPLE 在系统运行时快照引脚状态（查找总线活动，确认引脚映射）。
- EXTEST 驱动引脚（例如，通过 MCU 位翻转外部 SPI 闪存线路，如果板子接线允许的话，可以离线读取）。

使用 FT2232x 适配器的最小 UrJTAG 流程：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
您需要设备 BSDL 以了解边界寄存器位的顺序。请注意，一些供应商在生产中锁定边界扫描单元。

## 现代目标和注意事项

- ESP32‑S3/C3 包含原生 USB‑JTAG 桥接器；OpenOCD 可以直接通过 USB 进行通信，无需外部探头。这对于初步检查和转储非常方便。
- RISC‑V 调试（v0.13+）得到 OpenOCD 的广泛支持；当核心无法安全停止时，优先使用 SBA 进行内存访问。
- 许多 MCU 实现了调试认证和生命周期状态。如果 JTAG 看起来无响应但电源正常，设备可能被熔断为封闭状态或需要经过认证的探头。

## 防御和加固（在真实设备上预期的内容）

- 在生产中永久禁用或锁定 JTAG/SWD（例如，STM32 RDP 级别 2，禁用 PAD JTAG 的 ESP eFuses，NXP/Nordic APPROTECT/DPAP）。
- 在保持制造访问的同时，要求经过认证的调试（ARMv8.2‑A ADIv6 调试认证，OEM 管理的挑战-响应）。
- 不要布置容易测试的测试垫；埋藏测试通孔，移除/填充电阻以隔离 TAP，使用带键控或弹簧针夹具的连接器。
- 上电调试锁：在早期 ROM 后面设置 TAP，以强制执行安全启动。

## 参考文献

- OpenOCD 用户指南 – JTAG 命令和配置。 https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG 调试（USB‑JTAG，OpenOCD 使用）。 https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
