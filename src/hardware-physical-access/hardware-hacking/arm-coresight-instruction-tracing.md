# ARM CoreSight 通过 SWO 进行指令跟踪

{{#include ../../banners/hacktricks-training.md}}

可访问的 [SWD/JTAG debug port](jtag.md) 可用于启用实时 Cortex-M 执行跟踪，无需对固件进行插桩。这需要 MCU 配备 ETM 和 TPIU、引出 SWO 信号、用于解码的精确固件副本，以及足以支持所选 SWO 位速率的逻辑分析仪。与[功耗或 EM 侧信道测量](side_channel_analysis.md)不同，ETM 是一种调试跟踪；同时记录这两类数据可以将观察到的 leak 与执行代码对齐。这种对齐也有助于确定 [fault injection](fault_injection_attacks.md) 的时机。<sup>[[1]](#references)</sup>

ETM 发出压缩的控制流事件，而非指令字节。解码器会根据匹配的固件映像重建执行过程。ITM 携带软件插桩数据，而 TPIU 会对跟踪源进行帧封装，并驱动串行线输出。在应用任何寄存器值之前，请查阅目标设备的参考手册，确认其 CoreSight 组件和引脚复用情况：以下示例针对 STM32F401，并非通用的 Cortex-M 配置。<sup>[[1]](#references)</sup>

## 查找跟踪输出

在 STM32F401 上，异步 SWO 使用 PB3。在研究的控制器上，PB3 连接到电阻 R15，因此可以在此处探测信号。如果封装或网络连接不可见，可暂时将支持 SWO 的候选引脚配置为 GPIO，并通过 SWD 内存写入使其翻转。探测板上的各个点，找到匹配的波形后，再恢复跟踪引脚配置。连接分析仪时，请使用共地，并确保逻辑电压兼容。<sup>[[1]](#references)</sup>

## 使用 OpenOCD 启用 TPIU 和 ETM

以下命令应在 OpenOCD 配置中使用，并且需要先选择合适的适配器和 `target/stm32f4x.cfg`。`setbits` 会保留控制寄存器中的其他位，而 `mww` 会覆盖整个字。首先由 TPIU 路由异步跟踪；然后解锁 ETM、将其配置为编程模式、分配跟踪源 ID `1`，并启动跟踪。这些值基于作者在 STM32F401 上验证可用的配置，因此请根据目标设备的寄存器映射和时钟树进行调整。<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCD 跟踪寄存器配置</summary>

```tcl
proc setbits {addr mask} {
    mem2array value 32 $addr 1
    set value(0) [expr {$value(0) | $mask}]
    array2mem value 32 $addr 1
}
init
reset halt
setbits 0xe0042004 0x20       ;# DBGMCU_CR: trace I/O, async SWO
setbits 0xe000edfc 0x1000000  ;# DEMCR: TRCENA
mww 0xe0040004 1              ;# TPIU_CPSR: port size
mww 0xe0040010 3              ;# TPIU_ACPR: 16 MHz / (3 + 1) = 4 Mbaud
mww 0xe00400f0 2              ;# TPIU_SPPR: async UART framing
mww 0xe0040304 0x102          ;# TPIU_FFCR: formatter
mww 0xe0041fb0 0xC5ACCE55     ;# ETM_LAR: unlock
mww 0xe0041000 0x00201d0e     ;# ETM_CR: programming mode
mww 0xe0041200 1              ;# ETM_TRACEIDR: source ID 1
mww 0xe0041008 0x0000406F     ;# ETM_TER: trigger event
mww 0xe0041020 0x0000006F     ;# ETM_TEE: trace-enable event
mww 0xe0041024 0x00000001     ;# ETM_TSSR: start trace
mww 0xe0041000 0x0000191E     ;# ETM_CR: leave programming mode
```

</details>

SWO 速率为 `HCLK / (TPIU_ACPR + 1)`。使用 16 MHz HCLK 和 `ACPR=3` 时，以 4 Mbaud 进行捕获。在 PulseView 中，将 ETM 解码器放在 SWO 分析器通道上的 UART 解码器上方，将 UART 设为实际线路速率，并使用上文配置的 ETM source ID。示例使用 24 MHz 采样率（每位采样六次）、下降沿触发和 25% 预触发捕获。配置完成后，暂停/复位目标设备，启动捕获，然后执行 `resume`；请根据固件检查 ETM 同步情况以及是否存在合理的 PC 路径，不要仅凭看起来像解码结果的输出就轻信。<sup>[[1]](#references)</sup>

## 从时钟和引脚复用变更中恢复

固件中的两种独立操作都可能导致有效 trace 中断。PLL 变更会提高 HCLK，因此在 `ACPR` 不变时也会提高 SWO 波特率；此时 UART 层会恢复出错误字节，ETM 重放结果也会变得毫无意义。请在 [firmware analysis](../firmware-analysis/) 中检查 RCC/PLL 设置；在 STM32F401 示例中，将 Cortex-M 镜像加载到 `0x08000000`，并在 Ghidra 中导入其 SVD，这样时钟寄存器写入操作就会显示名称。在时钟初始化之后的一条双字节 Thumb 指令上设置硬件断点。示例中，执行 `bp 0x080001fa 2 hw`，然后执行 `resume`，会在 PLL 设置完成后停止；暂停时，执行 `mww 0xe0040010 31` 设置新的分频值。计算并设置新的 UART 速率，启动捕获，然后再次执行 `resume`。这样可以捕获时钟切换后的路径，但无法恢复错过的时钟切换过程。<sup>[[1]](#references)</sup>

此外，固件可能会将 SWO 引脚重映射到其他外设。在示例中，GPIO 复用功能设置将 PB3 切换为 I2C2 SDA，因此无论如何设置解码器，都无法恢复该线路上的 trace。请在固件中找到相关的 GPIO 初始化，然后将其调用点替换为长度相同的 Thumb NOP（每个半字为 `0xBF00`），或者暂停内核并通过 SWD 恢复兼容 trace 的引脚配置。这两种方法都可能禁用被替代的外设；运行时恢复也可能再次被固件覆盖。在运行时恢复引脚时，请根据当前 HCLK 设置 SWO 分频值。<sup>[[1]](#references)</sup>

## References

- [1] [遵循指令：使用 ETM、ITM 和 TPIU 进行 ARM 实时跟踪](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples：STM32F4 OpenOCD ETM/TPIU 配置](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
