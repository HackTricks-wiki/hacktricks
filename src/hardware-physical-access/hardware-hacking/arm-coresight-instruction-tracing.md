# ARM CoreSight Instruction Tracing over SWO

{{#include ../../banners/hacktricks-training.md}}

An accessible [SWD/JTAG debug port](jtag.md) can be used to enable a live Cortex-M execution trace without firmware instrumentation. This requires an MCU with ETM and TPIU, an exposed SWO route, a copy of the exact firmware for decoding, and a logic analyzer fast enough for the selected SWO bit rate. Unlike [power or EM side-channel measurements](side_channel_analysis.md), ETM is a debug trace; recording both can align observed leakage with executed code. The same alignment can help time [fault injection](fault_injection_attacks.md).<sup>[[1]](#references)</sup>

ETM emits compressed control-flow events rather than instruction bytes. A decoder reconstructs execution against the matching firmware image. ITM carries software instrumentation, while TPIU frames trace sources and drives the serial-wire output. Check the target's CoreSight components and pin multiplexing in its reference manual before applying any register values: the example below is for an STM32F401, not a universal Cortex-M configuration.<sup>[[1]](#references)</sup>

## Find the trace output

On the STM32F401, asynchronous SWO uses PB3. On the researched controller, PB3 was connected to resistor R15, providing an accessible probe point. When the package or net is hidden, temporarily configure the candidate SWO-capable pin as a GPIO and toggle it through SWD memory writes. Probe board points for the matching waveform, then restore the trace pin configuration. Connect the analyzer with a common ground and a compatible logic voltage.<sup>[[1]](#references)</sup>

## Enable TPIU and ETM with OpenOCD

The following commands belong in an OpenOCD configuration after the appropriate adapter and `target/stm32f4x.cfg` are selected. `setbits` preserves unrelated bits in control registers, whereas `mww` overwrites the whole word. The TPIU routes asynchronous trace first; then the ETM is unlocked, configured in programming mode, assigned trace source ID `1`, and started. These values follow the author's working STM32F401 configuration, so adapt them to the target's register map and clock tree.<sup>[[1]](#references)[[2]](#references)</sup>

<details>
<summary>STM32F401 OpenOCD trace-register configuration</summary>

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

The SWO rate is `HCLK / (TPIU_ACPR + 1)`. With a 16 MHz HCLK and `ACPR=3`, capture at 4 Mbaud. In PulseView, place the ETM decoder above a UART decoder on the SWO analyzer channel, set UART to the actual wire rate, and use the ETM source ID configured above. The example used 24 MHz sampling (six samples per bit), a falling-edge trigger, and 25% pre-trigger capture. After configuration, halt/reset the target, arm capture, then `resume`; verify ETM synchronization and a plausible PC path against the firmware rather than trusting decoded-looking output alone.<sup>[[1]](#references)</sup>

## Recover from clock and pin-mux changes

Two independent firmware actions can stop a valid trace. A PLL change raises HCLK and therefore SWO baud while `ACPR` stays fixed; the UART layer then recovers incorrect bytes and ETM replay becomes nonsense. Inspect RCC/PLL setup in [firmware analysis](../firmware-analysis/) and, on the STM32F401 example, load the Cortex-M image at `0x08000000` and import its SVD in Ghidra so clock-register writes have names. Set a hardware breakpoint on a two-byte Thumb instruction *after* clock initialization. In the example, `bp 0x080001fa 2 hw` followed by `resume` stops after PLL setup; while halted, `mww 0xe0040010 31` sets the new divider. Calculate and set the new UART rate, arm capture, then `resume` again. This captures the post-transition path; it does not recover the missed transition.<sup>[[1]](#references)</sup>

Separately, firmware may remap the SWO pad to another peripheral. In the example, GPIO alternate-function setup switched PB3 to I2C2 SDA, so no decoder setting could restore trace on that wire. Find the relevant GPIO initialization in the firmware, then either replace its call sites with size-matched Thumb NOPs (`0xBF00` per halfword) or halt the core and restore the trace-compatible pin configuration through SWD. Both approaches can disable the displaced peripheral; a runtime restore may also be overwritten again by firmware. When restoring the pin at runtime, set the SWO divider for the current HCLK.<sup>[[1]](#references)</sup>

## References

- [1] [Following the Instructions: Live ARM Tracing with the ETM, ITM, and TPIU](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU configuration](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)

{{#include ../../banners/hacktricks-training.md}}
