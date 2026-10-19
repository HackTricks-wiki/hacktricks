# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## 更安全的引脚查找与硬件设置

- 首先用万用表识别 Vtref 和 GND。许多适配器需要 Vtref 来设置 I/O 电压。
- 电平转换：优先使用为推挽信号设计的双向电平转换器（JTAG 线路不是开漏的）。避免将自动方向识别的 I2C 电平转换器用于 JTAG。
- 实用的适配器：FT2232H/FT232H 开发板（例如 Tigard）、CMSIS-DAP、J-Link、ST-LINK（厂商专用）、ESP-USB-JTAG（用于 ESP32-Sx）。至少连接 TCK、TMS、TDI、TDO、GND 和 Vtref；TRST 和 SRST 为可选项。

对于未标注的排针，在目标设备**断电时**，通过测量与已知接地平面的通断来识别 GND。切换到电压模式并给设备通电后，不要把所有高电平引脚都认作 Vtref：高电平数字输入在万用表上的读数可能很相似。追踪候选电源轨至附近的去耦电容，并用示波器比较它们上电和断电时的波形。电容形状的缓慢上升或下降可作为电源/参考网络的证据，但连接电平转换探针前，请确认电压和接线。在 PiFex 上，可通过 `VCCA_IN` 选择外部较低电压的目标参考电压，而不是使用默认的 3.3 V 设置。<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum** 是一款工具，可加载到兼容 Arduino 的 MCU 上，也可尝试加载到 Raspberry Pi 上，用于暴力枚举未知的 JTAG 引脚排列和指令寄存器。<sup>[[3]](#references)</sup>

- Arduino：将数字引脚 D2–D11 连接到最多 10 个疑似 JTAG 焊盘/测试点，并将 Arduino GND 连接到目标设备 GND。除非确认电源轨安全，否则请单独为目标设备供电。优先使用 3.3 V 逻辑电平（例如 Arduino Due）；探测 1.8–3.3 V 的目标设备时，使用电平转换器/串联电阻。
- Raspberry Pi：Pi 版本可用的 GPIO 较少（因此扫描速度较慢）；请查看代码仓库，了解当前的引脚映射和限制。

烧录后，以 115200 波特率打开串口监视器并发送 `h` 获取帮助。典型流程：

- `l` 查找环回，以避免误报
- `r` 根据需要切换内部上拉电阻
- `s` 扫描 TCK/TMS/TDI/TDO（有时也扫描 TRST/SRST）
- `y` 暴力枚举 IR，以发现未公开的操作码
- `x` 对引脚状态进行边界扫描快照

![JTAG - JTAGenum：x 对引脚状态进行边界扫描快照](<../../images/image (939).png>)

![JTAG - JTAGenum：x 对引脚状态进行边界扫描快照](<../../images/image (578).png>)

![JTAG - JTAGenum：x 对引脚状态进行边界扫描快照](<../../images/image (774).png>)



如果找到有效的 TAP，你会看到以 `FOUND!` 开头的行，显示已发现的引脚。

### JTAGenum 安全提示

- 始终共地，绝不要驱动未知引脚，使其电压高于目标设备的 Vtref。如有疑问，可在候选引脚上串联 100–470 Ω 电阻。
- 如果设备使用 SWD/SWJ 而不是 4 线 JTAG，JTAGenum 可能无法检测到；请尝试 SWD 工具或支持 SWJ-DP 的适配器。

## 使用 go-jtagenum 发现 GPIO 引脚

在已通电、确认共地且 I/O 电压兼容的目标设备上，`go-jtagenum` 可以从 Raspberry Pi GPIO 中枚举候选 JTAG 信号。`-pins` JSON 将标签映射到 **GPIO 编号**，而不是物理排针位置。<sup>[[5]](#references)</sup> 在 SSD 示例中，首次 IDCODE 扫描还报告了一条长得不合理且数值不断变化的链：仅有候选 TDO 线路数值变化，并不能证明存在有效的 TAP。请通过 BYPASS 扫描重新验证合理的结果；该扫描会将已知位模式从 TDI 移入 1 位旁路寄存器，再传到 TDO。<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

对于该板，BYPASS 确认了 `TCK=10`、`TMS=14`、`TDI=9` 和 `TDO=15`；额外的引脚只是**可能**的 nTRST 候选引脚。如果候选引脚返回全零或不一致的模式，在将其指定为某个信号前，请检查接触情况、目标设备供电、上拉电阻以及时钟/复位延迟。<sup>[[4]](#references)[[5]](#references)</sup> 该工具还支持将 `-known-pins` 与 `test_bypass` 配合使用，以重新测试已恢复的映射。<sup>[[5]](#references)</sup>

## 使用 UrJTAG 对未记录的 TAP 进行特征分析

发现引脚排列并不能确定调试所需的指令寄存器（IR）操作码或数据寄存器（DR）宽度。使用支持 Raspberry Pi GPIO cable 的 UrJTAG 构建版本，设置恢复出的映射，然后依次运行 `idcode`、`detect` 和 `discover`。SSD 示例检测到一个 TAP、一个四位 IR，以及不同 IR 值对应的不同 DR 宽度。DR 长度为 `-1` 或出现 “TDO stuck at 0” 都不能作为可用的寄存器定义；请检查时序、接线和所选指令，而不要擅自指定其宽度。<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

这是 TAP 探测，而不是自动识别 CPU：将得到的 IDCODE 与设备文档及受支持的 OpenOCD target 进行比较。UrJTAG 的本地制造商数据库可能会将一个有效 ID 标记为 unknown。<sup>[[4]](#references)</sup>

## 首次使用 OpenOCD（扫描并读取 IDCODE）

OpenOCD 是 JTAG/SWD 领域事实上的 OSS。使用受支持的适配器即可扫描链并读取 IDCODE：<sup>[[1]](#references)</sup>

- 使用 J-Link 的通用示例：
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 内置 USB‑JTAG（无需外部探针）：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### Notes

- 如果得到“全 1/全 0”的 IDCODE，请检查接线、电源、Vtref，以及端口是否被 fuse/option bytes 锁定。
- 在连接未知链时，可参考 OpenOCD 的底层 `irscan`/`drscan`，手动与 TAP 交互。<sup>[[1]](#references)</sup>

## Bring an undocumented target into OpenOCD

已知 TAP ID 和 IR 长度后，检查 OpenOCD 的 `cpu/`、`target/` 和 `board/` 脚本，寻找**匹配的 CPU 架构**，然后分别创建 adapter 和 target 配置。<sup>[[4]](#references)[[6]](#references)</sup> 以下 Pi GPIO 映射和 ARCv2 target 是经过测试的 SSD 示例，并非通用 JTAG 配置。ARC target 的选择和调试设置是针对该设备验证成功的假设；在其他板子上使用时，请替换为目标实际测得的 ID、IR 长度、架构和 GPIO 编号。<sup>[[4]](#references)</sup>

```tcl
# raspberrypi-io.cfg
source [find interface/raspberrypi-native.cfg]
transport select jtag
adapter gpio tck -chip 0 10
adapter gpio tms -chip 0 14
adapter gpio tdi -chip 0 9
adapter gpio tdo -chip 0 15
adapter speed 100
```

```tcl
# target.cfg: ARCv2 example only
source [find cpu/arc/hs.tcl]
set _CHIPNAME arc-em
set _TARGETNAME $_CHIPNAME.cpu
jtag newtap $_CHIPNAME cpu -irlen 4 -ircapture 0x1 -expected-id 0x100434b1
target create $_TARGETNAME arcv2 -chain-position $_TARGETNAME
$_TARGETNAME configure -coreid 0
$_TARGETNAME configure -dbgbase 0
$_TARGETNAME configure -event reset-assert "arc_hs_reset $_TARGETNAME"
arc_hs_init_regs
$_TARGETNAME arc cache l2 auto 1
```

运行 `openocd -f raspberrypi-io.cfg -f target.cfg`，并确认 TAP 检查成功后再读取内存。示例在端口 `4444` 上开启了 Telnet，并在 `3333` 上开启了 GDB server；仅识别出 IDCODE 并不能证明所选的 CPU target 可以接受检查或调试。<sup>[[4]](#references)</sup> 如果适配器支持通过 `adapter gpio` 重新映射，Raspberry Pi GPIO 未必需要连接到 breakout board 上标记为 JTAG 的引脚。<sup>[[4]](#references)[[6]](#references)</sup>

## 暂停 CPU 并转储内存/flash

识别出 TAP 并选择 target script 后，你可以暂停核心并转储内存区域或内部 flash。示例（请调整 target、基地址和大小）：<sup>[[1]](#references)</sup>

- init 后的通用 target：
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC（可用时优先使用 SBA）：
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3，可通过 OpenOCD 辅助程序进行编程或读取：<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### 内存转储技巧

- 使用 `mdw/mdh/mdb` 在进行长时间转储前对内存做合理性检查。
- 对于多设备链，需在非目标设备上设置 BYPASS，或使用定义了所有 TAP 的 board file。

对于未记录的内存映射，SSD 研究先检查了 1 MiB 转储，查找可识别的控制器字符串，然后通过 OpenOCD 使用支持该架构的 GDB 检查 `$pc`、反汇编和寄存器。这些实时地址为第二次区域转储提供了参考；随后又将其与支持 ARC 的 Ghidra 版本中匹配的指令进行核对。字符串只能用于初步判断，不能证明映像完整或映射正确。<sup>[[4]](#references)</sup> 更广泛的静态分析步骤，请参见 [firmware analysis](../firmware-analysis/)。

## 边界扫描技巧（EXTEST/SAMPLE）

即使 CPU 调试访问已锁定，边界扫描仍可能开放。使用 UrJTAG/OpenOCD 可以：<sup>[[1]](#references)</sup>
- 使用 SAMPLE 在系统运行时捕获引脚状态（查找总线活动、确认引脚映射）。
- 使用 EXTEST 驱动引脚（例如，若电路板布线允许，可通过 MCU 对外部 SPI flash 线路进行 bit-bang，以离线读取数据）。

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
需要设备的 BSDL 才能确定 boundary register 的位顺序。注意，有些厂商会在量产时锁定 boundary-scan cells。

## 现代目标和注意事项

- ESP32‑S3/C3 内置 USB‑JTAG bridge；OpenOCD 可通过 USB 直接通信，无需外部 probe。非常适合快速排查和转储。<sup>[[2]](#references)</sup>
- OpenOCD 广泛支持 RISC‑V debug（v0.13+）；如果无法安全地暂停核心，访问内存时优先使用 SBA。
- 许多 MCU 实现了 debug authentication 和生命周期状态。如果 JTAG 看起来没有响应，但供电正常，设备可能已熔丝配置为 closed 状态，或者需要经过身份验证的 probe。

## 防御和加固（真实设备上的常见情况）

- 在量产时永久禁用或锁定 JTAG/SWD（例如 STM32 RDP level 2、禁用 PAD JTAG 的 ESP eFuses、NXP/Nordic APPROTECT/DPAP）。
- 要求经过身份验证的 debug（ARMv8.2‑A ADIv6 Debug Authentication、OEM 管理的 challenge-response），同时保留制造阶段的访问权限。
- 不要布置容易接触的测试焊盘；将测试过孔埋入板内，移除或焊接电阻以隔离 TAP，并使用带防呆设计的连接器或 pogo-pin 测试夹具。
- 上电时锁定 debug：通过早期 ROM 控制 TAP，并强制执行 secure boot。

## References

- [1] [OpenOCD 用户指南 – JTAG 命令和配置](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG 调试（USB‑JTAG、OpenOCD 用法）](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – 基于 Arduino 的 JTAG 引脚布局扫描器](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — 使用 Raspberry Pi 进行 JTAG Hacking](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG 枚举](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD 用户指南 — Debug Adapter 配置](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
