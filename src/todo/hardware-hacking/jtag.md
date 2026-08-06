# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) 是一种工具，可加载到 Arduino-compatible MCU 或（实验性地）Raspberry Pi 上，用于 brute-force 未知的 JTAG 引脚布局，甚至枚举 instruction registers。

- Arduino：将数字引脚 D2–D11 连接到最多 10 个疑似 JTAG 焊盘/测试点，并将 Arduino GND 连接到目标设备的 GND。除非确定电源轨安全，否则请单独为目标设备供电。优先使用 3.3 V 逻辑电平（例如 Arduino Due）；探测 1.8–3.3 V 目标设备时，请使用 level shifter 或串联电阻。
- Raspberry Pi：Pi 版本可用的 GPIO 更少（因此扫描速度更慢）；请查看 repo 了解当前的引脚映射和限制。

烧录完成后，以 115200 baud 打开 serial monitor，并发送 `h` 获取帮助。典型流程：

- `l` 查找 loopback，以避免 false positives
- `r` 根据需要切换 internal pull-up
- `s` 扫描 TCK/TMS/TDI/TDO（有时还包括 TRST/SRST）
- `y` 对 IR 进行 brute-force，以发现未公开的 opcodes
- `x` 获取 pin states 的 boundary-scan 快照

![JTAG - JTAGenum：x pin states 的 boundary-scan 快照](<../../images/image (939).png>)

![JTAG - JTAGenum：x pin states 的 boundary-scan 快照](<../../images/image (578).png>)

![JTAG - JTAGenum：x pin states 的 boundary-scan 快照](<../../images/image (774).png>)



如果找到有效的 TAP，你会看到以 `FOUND!` 开头的行，其中会显示已发现的引脚。

Tips
- 始终共地，绝不要驱动未知引脚使其电压高于目标设备的 Vtref。如有疑问，请在候选引脚上添加 100–470 Ω 的串联电阻。
- 如果设备使用 SWD/SWJ 而不是 4-wire JTAG，JTAGenum 可能无法检测到它；请尝试 SWD tools 或支持 SWJ-DP 的 adapter。

## 更安全的引脚探测和硬件设置

- 首先使用 multimeter 识别 Vtref 和 GND。许多 adapters 需要 Vtref 来设置 I/O 电压。
- Level shifting：优先使用为 push-pull signals 设计的 bidirectional level shifters（JTAG lines 并非 open-drain）。避免将 auto-direction I2C shifters 用于 JTAG。
- 有用的 adapters：FT2232H/FT232H boards（例如 Tigard）、CMSIS-DAP、J-Link、ST-LINK（vendor-specific）、ESP-USB-JTAG（用于 ESP32-Sx）。至少连接 TCK、TMS、TDI、TDO、GND 和 Vtref；也可选择连接 TRST 和 SRST。

## 首次接触 OpenOCD（扫描和 IDCODE）

OpenOCD 是 JTAG/SWD 的 de-facto OSS。使用受支持的 adapter，你可以扫描 chain 并读取 IDCODEs：<sup>[[1]](#references)</sup>

- 使用 J-Link 的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部 probe）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
说明
- 如果获取到“全 1/全 0”的 IDCODE，请检查接线、电源、Vtref，以及端口是否被 fuse/option bytes 锁定。
- 在调试未知 chain 时，可参考 OpenOCD 底层的 `irscan`/`drscan`，手动与 TAP 交互。<sup>[[1]](#references)</sup>

## Halt CPU 并 dump memory/flash

识别 TAP 并选择 target script 后，即可 halt core，并 dump memory 区域或 internal flash。示例（请根据实际情况调整 target、基地址和大小）：<sup>[[1]](#references)</sup>

- 初始化后的 Generic target：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（可用时优先使用 SBA）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，通过 OpenOCD helper 进行编程或读取：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
提示
- 在进行长时间 dump 前，使用 `mdw/mdh/mdb` 对内存进行基本检查。
- 对于多设备链，需在非目标设备上设置 BYPASS，或使用定义了所有 TAP 的 board file。

## Boundary-scan 技巧（EXTEST/SAMPLE）

即使 CPU debug access 已被锁定，boundary-scan 仍可能处于暴露状态。使用 UrJTAG/OpenOCD，你可以：<sup>[[1]](#references)</sup>
- 使用 SAMPLE 在系统运行时快照引脚状态（查找总线活动、确认引脚映射）。
- 使用 EXTEST 驱动引脚（例如，如果 board wiring 允许，可通过 MCU 对外部 SPI flash 线路进行 bit-bang，以离线读取它）。

使用 FT2232x adapter 的最简 UrJTAG 流程：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
你需要设备的 BSDL 才能了解 boundary register 的 bit ordering。注意，一些厂商会在生产环境中锁定 boundary-scan cells。

## Modern targets and notes

- ESP32‑S3/C3 包含原生 USB‑JTAG bridge；OpenOCD 可以通过 USB 直接通信，无需外部 probe。非常适合 triage 和 dumps。<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+) 得到 OpenOCD 的广泛支持；当 core 无法安全暂停时，优先使用 SBA 进行内存访问。
- 许多 MCU 实现了 debug authentication 和 lifecycle states。如果 JTAG 看起来失效但供电正常，设备可能已被 fuse 设置为 closed state，或需要经过认证的 probe。

## Defenses and hardening (what to expect on real devices)

- 在生产环境中永久禁用或锁定 JTAG/SWD（例如 STM32 RDP level 2、用于禁用 PAD JTAG 的 ESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 要求 authenticated debug（ARMv8.2‑A ADIv6 Debug Authentication、由 OEM 管理的 challenge-response），同时保留 manufacturing access。
- 不要布置易于接触的 test pads；将 test vias 埋入内部，通过移除/安装电阻来隔离 TAP，并使用带防呆设计的 connectors 或 pogo-pin fixtures。
- Power-on debug lock：通过早期 ROM 强制执行 secure boot，将 TAP 置于其控制之下。

## References

- [1] [OpenOCD User’s Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
