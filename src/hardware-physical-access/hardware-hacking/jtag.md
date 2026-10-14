# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum** 是一种工具，可加载到兼容 Arduino 的 MCU 上，或实验性地加载到 Raspberry Pi 上，用于暴力破解未知的 JTAG 引脚布局并枚举指令寄存器。<sup>[[3]](#references)</sup>

- Arduino：将数字引脚 D2–D11 连接到最多 10 个疑似 JTAG 焊盘/测试点，并将 Arduino GND 连接到目标设备 GND。除非确认供电轨安全，否则请为目标设备单独供电。优先使用 3.3 V 逻辑电平（例如 Arduino Due）；探测 1.8–3.3 V 的目标设备时，请使用电平转换器/串联电阻。
- Raspberry Pi：Pi 版本可用的 GPIO 更少（因此扫描速度较慢）；请查看 repo，了解当前引脚映射和限制。

烧录完成后，以 115200 波特率打开串口监视器，并发送 `h` 获取帮助。典型流程如下：

- `l` 查找回环，避免误报
- `r` 根据需要切换内部上拉电阻
- `s` 扫描 TCK/TMS/TDI/TDO（有时也包括 TRST/SRST）
- `y` 暴力破解 IR，以发现未公开的操作码
- `x` 对引脚状态进行边界扫描快照

![JTAG - JTAGenum: x 对引脚状态进行边界扫描快照](<../../images/image (939).png>)

![JTAG - JTAGenum: x 对引脚状态进行边界扫描快照](<../../images/image (578).png>)

![JTAG - JTAGenum: x 对引脚状态进行边界扫描快照](<../../images/image (774).png>)



如果找到有效的 TAP，你会看到以 `FOUND!` 开头的行，其中显示发现的引脚。

### JTAGenum 安全提示

- 始终共地，切勿驱动未知引脚，使其电压高于目标设备的 Vtref。如有疑虑，可在候选引脚上串联 100–470 Ω 电阻。
- 如果设备使用 SWD/SWJ 而非 4 线 JTAG，JTAGenum 可能无法检测到；请尝试使用 SWD 工具或支持 SWJ‑DP 的适配器。

## 更安全的引脚探测与硬件设置

- 首先用万用表识别 Vtref 和 GND。许多适配器需要 Vtref 来设置 I/O 电压。
- 电平转换：优先使用专为推挽信号设计的双向电平转换器（JTAG 线路不是开漏）。避免在 JTAG 上使用自动方向 I2C 电平转换器。
- 实用适配器：FT2232H/FT232H 板（例如 Tigard）、CMSIS‑DAP、J‑Link、ST‑LINK（厂商专用）、ESP‑USB‑JTAG（用于 ESP32‑Sx）。至少连接 TCK、TMS、TDI、TDO、GND 和 Vtref；也可连接 TRST 和 SRST。

## 初次使用 OpenOCD（扫描和 IDCODE）

OpenOCD 是事实上的 JTAG/SWD 开源软件。使用受支持的适配器，可以扫描链并读取 IDCODE：<sup>[[1]](#references)</sup>

- 使用 J‑Link 的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部探针）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### 注意事项

- 如果得到“全 1/全 0”的 IDCODE，请检查接线、电源、Vtref，以及端口是否被 fuse/option bytes 锁定。
- 在调试未知链时，可参考 OpenOCD 底层的 `irscan`/`drscan`，手动与 TAP 交互。<sup>[[1]](#references)</sup>

## 暂停 CPU 并转储内存/flash

识别出 TAP 并选择目标脚本后，即可暂停核心并转储内存区域或内部 flash。示例（请调整 target、基地址和大小）：<sup>[[1]](#references)</sup>

- 初始化后的通用 target：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（可用时优先使用 SBA）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，通过 OpenOCD helper 编程或读取：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### 内存转储技巧

- 长时间转储前，使用 `mdw/mdh/mdb` 对内存进行快速检查。
- 对于多设备链，将非目标设备设为 BYPASS，或使用定义了所有 TAP 的板级文件。

## Boundary-scan 技巧（EXTEST/SAMPLE）

即使 CPU 调试访问已锁定，boundary-scan 仍可能处于开放状态。使用 UrJTAG/OpenOCD 可以：<sup>[[1]](#references)</sup>
- 使用 SAMPLE 在系统运行时捕获引脚状态（查找总线活动、确认引脚映射）。
- 使用 EXTEST 驱动引脚（例如，在电路板布线允许的情况下，通过 MCU 对外部 SPI flash 引脚进行 bit-bang 操作，以便离线读取）。

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
你需要设备的 BSDL 才能了解边界寄存器的位顺序。注意，有些厂商会在量产时锁定 boundary-scan cells。

## 现代目标与注意事项

- ESP32‑S3/C3 内置 USB‑JTAG bridge；OpenOCD 无需外部探针即可直接通过 USB 通信。非常适合初步排查和转储。<sup>[[2]](#references)</sup>
- RISC‑V debug（v0.13+）已获 OpenOCD 广泛支持；如果无法安全地暂停核心，访问内存时优先使用 SBA。
- 许多 MCU 实现了 debug authentication 和生命周期状态。如果 JTAG 看似失效但供电正常，设备可能已熔丝配置为关闭状态，或需要经过认证的探针。

## 防御与加固（真实设备上的常见情况）

- 在量产时永久禁用或锁定 JTAG/SWD（例如 STM32 RDP level 2、禁用 PAD JTAG 的 ESP eFuse、NXP/Nordic APPROTECT/DPAP）。
- 要求经过认证的 debug（ARMv8.2‑A ADIv6 Debug Authentication、由 OEM 管理的 challenge-response），同时保留制造阶段的访问能力。
- 避免布置容易接触的测试焊盘；隐藏测试过孔，通过移除/焊接电阻隔离 TAP，并使用带防呆设计的连接器或 pogo-pin 测试夹具。
- 上电时锁定 debug：通过早期 ROM 在 secure boot 强制执行前限制 TAP。

## References

- [1] [OpenOCD 用户指南 – JTAG 命令与配置](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG 调试（USB‑JTAG、OpenOCD 用法）](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – 基于 Arduino 的 JTAG 引脚扫描器](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
