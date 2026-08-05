# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum) 是一个可以加载到 Arduino-compatible MCU，或（实验性地）Raspberry Pi 上的工具，用于 brute-force 未知的 JTAG pinout，甚至枚举 instruction register。

- Arduino：将数字引脚 D2–D11 连接到最多 10 个疑似 JTAG 焊盘/测试点，并将 Arduino GND 连接到目标设备的 GND。除非确定供电轨安全，否则应为目标设备单独供电。优先使用 3.3 V 逻辑电平（例如 Arduino Due）；探测 1.8–3.3 V 目标设备时，请使用电平转换器或串联电阻。
- Raspberry Pi：Pi 版本可用的 GPIO 更少（因此扫描速度更慢）；请查看 repo 以获取当前的引脚映射和限制。

烧录完成后，以 115200 波特率打开 serial monitor，并发送 `h` 获取帮助。典型流程：

- `l` 查找 loopback，以避免 false positive
- `r` 根据需要切换内部 pull-up
- `s` 扫描 TCK/TMS/TDI/TDO（有时还包括 TRST/SRST）
- `y` brute-force IR，以发现未公开的 opcode
- `x` 获取 pin state 的 boundary-scan snapshot

![JTAG - JTAGenum：x pin state 的 boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum：x pin state 的 boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum：x pin state 的 boundary-scan snapshot](<../../images/image (774).png>)



如果找到有效的 TAP，你将看到以 `FOUND!` 开头的行，其中会显示发现的引脚。

Tips
- 始终共用 ground，绝不要将未知引脚驱动到高于目标 Vtref 的电压。如果不确定，请在候选引脚上增加 100–470 Ω 的串联电阻。
- 如果设备使用 SWD/SWJ 而不是 4-wire JTAG，JTAGenum 可能无法检测到它；请尝试 SWD tools 或支持 SWJ-DP 的 adapter。

## 更安全的 pin hunting 和硬件设置

- 首先使用万用表识别 Vtref 和 GND。许多 adapter 需要 Vtref 来设置 I/O 电压。
- Level shifting：优先使用专为 push-pull signal 设计的 bidirectional level shifter（JTAG line 不是 open-drain）。避免将 auto-direction I2C shifter 用于 JTAG。
- 有用的 adapter：FT2232H/FT232H boards（例如 Tigard）、CMSIS-DAP、J-Link、ST-LINK（vendor-specific）、ESP-USB-JTAG（位于 ESP32-Sx 上）。至少连接 TCK、TMS、TDI、TDO、GND 和 Vtref；也可选择连接 TRST 和 SRST。

## 首次使用 OpenOCD（扫描和 IDCODE）

OpenOCD 是 JTAG/SWD 事实上的 OSS。使用受支持的 adapter 后，你可以扫描 chain 并读取 IDCODE：

- 使用 J-Link 的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部探针）：
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- 如果获得的是“全 1/全 0”的 IDCODE，请检查 wiring、power、Vtref，以及端口是否被 fuses/option bytes 锁定。
- 在启动未知 chain 时，可参考 OpenOCD 的低级 `irscan`/`drscan`，以手动进行 TAP 交互。<sup>[[1]](#references)</sup>

## Halt CPU 并 dump memory/flash

识别 TAP 并选择 target script 后，就可以 halt core，并 dump memory 区域或内部 flash。示例（请根据实际情况调整 target、base addresses 和 sizes）：

- Generic target after init:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（可用时优先使用 SBA）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，通过 OpenOCD helper 编程或读取：
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- 使用 `mdw/mdh/mdb` 在进行长时间 dump 前进行内存 sanity-check。
- 对于多设备链，须在非目标设备上设置 BYPASS，或使用定义了所有 TAP 的 board file。

## Boundary-scan tricks (EXTEST/SAMPLE)

即使 CPU debug access 已被锁定，boundary-scan 仍可能处于 exposed 状态。使用 UrJTAG/OpenOCD，你可以：
- 使用 SAMPLE 在系统运行时 snapshot 引脚状态（查找总线活动、确认引脚映射）。
- 使用 EXTEST 驱动引脚（例如，如果 board wiring 允许，可通过 MCU 对外部 SPI flash 线路进行 bit-bang，以 offline 方式读取）。

使用 FT2232x 适配器的最简 UrJTAG 流程：
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
你需要设备的 BSDL 才能确定 boundary register 的 bit ordering。注意，某些厂商会在量产设备中锁定 boundary-scan cells。

## Modern targets and notes

- ESP32-S3/C3 包含原生 USB-JTAG bridge；OpenOCD 可以直接通过 USB 通信，无需外部 probe。非常适合 triage 和 dumps。<sup>[[2]](#references)</sup>
- RISC-V debug（v0.13+）已获 OpenOCD 广泛支持；当 core 无法安全 halt 时，优先使用 SBA 进行 memory access。
- 许多 MCU 实现了 debug authentication 和 lifecycle states。如果 JTAG 看起来失效但供电正常，设备可能已被 fuse 设置为 closed state，或需要经过认证的 probe。

## Defenses and hardening (what to expect on real devices)

- 在量产中永久禁用或锁定 JTAG/SWD（例如 STM32 RDP level 2、禁用 PAD JTAG 的 ESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 在保留 manufacturing access 的同时，要求 authenticated debug（ARMv8.2-A ADIv6 Debug Authentication、由 OEM 管理的 challenge-response）。
- 不要布置容易访问的 test pads；将 test vias 埋入内部，移除或安装电阻以隔离 TAP，并使用带防呆设计的 connectors 或 pogo-pin fixtures。
- Power-on debug lock：通过在早期 ROM 中强制执行 secure boot，将 TAP 置于其后。

## References

- [1] [OpenOCD User's Guide - JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
