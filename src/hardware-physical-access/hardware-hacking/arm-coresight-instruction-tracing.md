# ARM CoreSight Instruction Tracing over SWO

{{#include ../../banners/hacktricks-training.md}}

접근 가능한 [SWD/JTAG debug port](jtag.md)를 사용하면 firmware 계측 없이 Cortex-M 실행을 실시간으로 trace할 수 있습니다. 이를 위해서는 ETM과 TPIU가 있는 MCU, 외부로 연결된 SWO 경로, 디코딩에 사용할 정확한 firmware 사본, 그리고 선택한 SWO bit rate를 처리할 수 있을 만큼 빠른 logic analyzer가 필요합니다. [power or EM side-channel measurements](side_channel_analysis.md)와 달리 ETM은 debug trace입니다. 두 가지를 함께 기록하면 관찰된 leak과 실행 코드를 정렬할 수 있습니다. 이와 같은 정렬은 [fault injection](fault_injection_attacks.md) 타이밍을 맞추는 데도 도움이 됩니다.<sup>[[1]](#references)</sup>

ETM은 instruction byte 대신 압축된 control-flow event를 출력합니다. 디코더는 일치하는 firmware image를 기준으로 실행을 재구성합니다. ITM은 software 계측 정보를 전달하고, TPIU는 trace source를 프레이밍하여 serial-wire 출력을 구동합니다. register 값을 적용하기 전에 대상의 reference manual에서 CoreSight 구성 요소와 pin multiplexing을 확인하세요. 아래 예시는 STM32F401용이며, 모든 Cortex-M 설정에 적용되는 것은 아닙니다.<sup>[[1]](#references)</sup>

## trace 출력 찾기

STM32F401에서 비동기 SWO는 PB3을 사용합니다. 조사한 controller에서는 PB3이 저항 R15에 연결되어 있어 쉽게 probe할 수 있는 지점이었습니다. package나 net을 확인할 수 없는 경우, 후보 SWO 지원 pin을 GPIO로 임시 설정하고 SWD memory write를 통해 토글하세요. 일치하는 waveform이 나오는 board 지점을 probe한 다음 trace pin 설정을 복원합니다. 공통 ground와 호환되는 logic voltage를 사용해 analyzer를 연결하세요.<sup>[[1]](#references)</sup>

## OpenOCD로 TPIU 및 ETM 활성화

다음 명령은 적절한 adapter와 `target/stm32f4x.cfg`를 선택한 뒤 OpenOCD 설정에 추가해야 합니다. `setbits`는 control register의 관련 없는 bit를 보존하지만, `mww`는 전체 word를 덮어씁니다. 먼저 TPIU가 비동기 trace를 라우팅합니다. 이어서 ETM 잠금을 해제하고 programming mode로 설정한 뒤 trace source ID `1`을 지정하고 실행합니다. 이 값은 작성자가 STM32F401에서 사용한 설정을 기준으로 하므로 대상의 register map과 clock tree에 맞게 조정하세요.<sup>[[1]](#references)[[2]](#references)</sup>

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

SWO rate는 `HCLK / (TPIU_ACPR + 1)`입니다. HCLK가 16 MHz이고 `ACPR=3`이면 4 Mbaud로 캡처합니다. PulseView에서 SWO analyzer 채널의 UART decoder 위에 ETM decoder를 배치하고, UART를 실제 신호선 속도로 설정한 다음 위에서 설정한 ETM source ID를 사용합니다. 예제에서는 24 MHz 샘플링(비트당 6개 샘플), 하강 에지 트리거, 25% 프리트리거 캡처를 사용했습니다. 설정을 마친 뒤 타깃을 halt/reset하고 캡처를 arm한 다음 `resume`합니다. 디코딩된 출력만 믿지 말고 ETM 동기화와 펌웨어에 비추어 타당한 PC 경로인지 확인하세요.<sup>[[1]](#references)</sup>

## 클록 및 핀 멀티플렉싱 변경 대응

서로 독립적인 두 가지 펌웨어 동작으로 유효한 trace가 중단될 수 있습니다. PLL 변경으로 HCLK가 올라가고 `ACPR`가 그대로면 SWO baud도 높아집니다. 그러면 UART 계층이 잘못된 바이트를 복구하고 ETM 재생 결과는 엉망이 됩니다. [펌웨어 분석](../firmware-analysis/)에서 RCC/PLL 설정을 확인하세요. STM32F401 예제에서는 Cortex-M 이미지를 `0x08000000`에 로드하고 Ghidra에서 SVD를 가져와 클록 레지스터 쓰기를 이름으로 확인합니다. 클록 초기화 *후*에 있는 2바이트 Thumb 명령어에 하드웨어 breakpoint를 설정합니다. 예제에서는 `bp 0x080001fa 2 hw` 다음에 `resume`을 실행하면 PLL 설정 후에 멈춥니다. halt 상태에서 `mww 0xe0040010 31`을 실행해 새 분주값을 설정합니다. 새 UART 속도를 계산해 설정하고 캡처를 arm한 다음 다시 `resume`합니다. 이렇게 하면 클록 전환 이후 경로를 캡처할 수 있지만, 놓친 전환을 복구하지는 못합니다.<sup>[[1]](#references)</sup>

이와 별개로 펌웨어가 SWO 패드를 다른 주변 장치로 재매핑할 수 있습니다. 예제에서는 GPIO 대체 기능 설정으로 PB3이 I2C2 SDA로 전환되어, 어떤 decoder 설정으로도 해당 신호선에서 trace를 복구할 수 없었습니다. 펌웨어에서 관련 GPIO 초기화 코드를 찾아 호출 지점을 크기가 같은 Thumb NOP(`0xBF00`을 halfword마다)로 바꾸거나, 코어를 halt한 뒤 SWD를 통해 trace에 맞는 핀 설정으로 복구하세요. 두 방법 모두 해당 핀을 사용하던 주변 장치를 비활성화할 수 있습니다. 런타임에 복구해도 펌웨어가 다시 덮어쓸 수 있습니다. 런타임에 핀을 복구할 때는 현재 HCLK에 맞춰 SWO 분주값을 설정하세요.<sup>[[1]](#references)</sup>

## References

- [1] [명령어 따라가기: ETM, ITM, TPIU를 사용한 실시간 ARM 트레이싱](https://voidstarsec.com/blog/arm-tracing-etm-itm)
- [2] [wrongbaud/etm-examples: STM32F4 OpenOCD ETM/TPIU 설정](https://github.com/wrongbaud/etm-examples/blob/main/openocd-configs/prescaler.cfg)
{{#include ../../banners/hacktricks-training.md}}
