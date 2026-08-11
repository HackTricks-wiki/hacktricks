# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** 是一个工具，可加载到兼容 Arduino 的 MCU 上，或实验性地加载到 Raspberry Pi 上，用于对未知的 JTAG 引脚布局进行 brute-force，并枚举指令寄存器。<sup>[[3]](#references)</sup>

- Arduino：将数字引脚 D2–D11 连接到最多 10 个疑似 JTAG 焊盘/测试点，并将 Arduino GND 连接到目标设备的 GND。除非确认目标设备的电源轨安全，否则应单独为目标设备供电。优先使用 3.3 V 逻辑电平（例如 Arduino Due）；探测 1.8–3.3 V 目标设备时，应使用电平转换器或串联电阻。
- Raspberry Pi：Pi 版本可用的 GPIO 更少（因此扫描速度更慢）；请查看 repo 以获取当前的引脚映射和限制。

烧录完成后，以 115200 波特率打开串口监视器，并发送 `h` 获取帮助。典型流程如下：

- `l` 查找 loopback，以避免 false positive
- `r` 根据需要切换内部上拉电阻
- `s` 扫描 TCK/TMS/TDI/TDO（有时还包括 TRST/SRST）
- `y` 对 IR 进行 brute-force，以发现未公开的 opcode
- `x` 对引脚状态进行 boundary-scan 快照

![JTAG - JTAGenum：x 对引脚状态进行 boundary-scan 快照](<../../images/image (939).png>)

![JTAG - JTAGenum：x 对引脚状态进行 boundary-scan 快照](<../../images/image (578).png>)

![JTAG - JTAGenum：x 对引脚状态进行 boundary-scan 快照](<../../images/image (774).png>)



如果发现有效的 TAP，你会看到以 `FOUND!` 开头的行，其中会显示已发现的引脚。

### JTAGenum 安全提示

- 始终共用 GND，绝不要将未知引脚驱动到高于目标 Vtref 的电压。如果不确定，可在候选引脚上增加 100–470 Ω 的串联电阻。
- 如果设备使用 SWD/SWJ 而不是 4 线 JTAG，JTAGenum 可能无法检测到它；请尝试使用 SWD 工具，或支持 SWJ-DP 的适配器。

## 更安全的引脚查找和硬件设置

- 首先使用万用表识别 Vtref 和 GND。许多适配器需要 Vtref 来设置 I/O 电压。
- 电平转换：优先使用专为推挽信号设计的双向电平转换器（JTAG 线路不是开漏结构）。避免将自动方向 I2C 转换器用于 JTAG。
- 实用的适配器包括：FT2232H/FT232H 主板（例如 Tigard）、CMSIS-DAP、J-Link、ST-LINK（厂商专用）以及 ESP-USB-JTAG（用于 ESP32-Sx）。至少连接 TCK、TMS、TDI、TDO、GND 和 Vtref；也可以选择连接 TRST 和 SRST。

## 首次接触 OpenOCD（扫描和 IDCODE）

OpenOCD 是 JTAG/SWD 的事实标准 OSS。使用受支持的适配器后，你可以扫描链并读取 IDCODE：<sup>[[1]](#references)</sup>

- 使用 J-Link 的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部 probe）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### 注意

- 如果获得的是“全 1/全 0”的 IDCODE，请检查接线、电源、Vtref，以及端口是否被 fuse/option bytes 锁定。
- 在调试未知链路时，请参阅 OpenOCD 的底层 `irscan`/`drscan`，以进行手动 TAP 交互。<sup>[[1]](#references)</sup>

## 暂停 CPU 并转储内存/flash

识别 TAP 并选择 target script 后，即可暂停 core，并转储内存区域或内部 flash。示例（请根据 target、基地址和大小进行调整）：<sup>[[1]](#references)</sup>

- 初始化后的通用 target：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（可用时优先选择 SBA）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，通过 OpenOCD helper 进行编程或读取：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Memory-Dumping 技巧

- 使用 `mdw/mdh/mdb` 在进行长时间 dump 前检查内存是否正常。
- 对于多设备 chain，在非目标设备上设置 BYPASS，或使用定义所有 TAP 的 board file。

## Boundary-scan 技巧（EXTEST/SAMPLE）

即使 CPU debug access 已被锁定，boundary-scan 仍可能处于 exposed 状态。使用 UrJTAG/OpenOCD 可以：<sup>[[1]](#references)</sup>
- 使用 SAMPLE 在系统运行时 snapshot 引脚状态（查找总线活动、确认引脚映射）。
- 使用 EXTEST 驱动引脚（例如，如果 board wiring 允许，可通过 MCU 对外部 SPI flash 线路进行 bit-bang，以 offline 方式读取）。

使用 FT2232x adapter 的最小 UrJTAG 流程：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
需要设备的 BSDL 才能确定 boundary register 的位顺序。注意，某些厂商会在生产阶段锁定 boundary-scan cells。

## Modern targets and notes

- ESP32-S3/C3 内置原生 USB-JTAG bridge；OpenOCD 可以通过 USB 直接通信，无需外部 probe。非常适合进行 triage 和 dumps。<sup>[[2]](#references)</sup>
- RISC-V debug（v0.13+）已被 OpenOCD 广泛支持；当 core 无法安全暂停时，优先使用 SBA 进行内存访问。
- 许多 MCU 实现了 debug authentication 和生命周期状态。如果 JTAG 看似失效但供电正常，设备可能已被熔丝设置为 closed state，或需要经过认证的 probe。

## Defenses and hardening (what to expect on real devices)

- 在生产环境中永久禁用或锁定 JTAG/SWD（例如 STM32 RDP level 2、禁用 PAD JTAG 的 ESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 在保留制造访问能力的同时，要求 authenticated debug（ARMv8.2-A ADIv6 Debug Authentication、由 OEM 管理的 challenge-response）。
- 不要引出易于访问的 test pads；隐藏 test vias，通过移除或安装电阻来隔离 TAP，并使用带防呆设计的 connectors 或 pogo-pin fixtures。
- 上电 debug lock：通过早期 ROM 强制执行 secure boot，将 TAP 置于其保护之下。

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – 基于 Arduino 的 JTAG 引脚布局扫描器](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
