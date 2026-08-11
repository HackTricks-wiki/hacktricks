# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum**은 Arduino 호환 MCU 또는 실험적으로 Raspberry Pi에 로드하여 알려지지 않은 JTAG pinout을 brute-force하고 instruction register를 열거할 수 있는 tool입니다.<sup>[[3]](#references)</sup>

- Arduino: 디지털 핀 D2–D11을 최대 10개의 의심되는 JTAG pad/testpoint에 연결하고, Arduino GND를 target GND에 연결합니다. 해당 rail이 안전하다는 것을 알고 있지 않다면 target에 별도로 전원을 공급합니다. 3.3 V logic(예: Arduino Due)을 우선 사용하거나, 1.8–3.3 V target을 probe할 때 level shifter/series resistor를 사용합니다.
- Raspberry Pi: Pi build는 사용 가능한 GPIO 수가 더 적으므로(따라서 scan이 더 느림) 현재 pin map과 제약 사항은 repo에서 확인하세요.

flash한 후 serial monitor를 115200 baud로 열고 `h`를 입력하여 help를 표시합니다. 일반적인 흐름은 다음과 같습니다.

- `l` false positive를 피하기 위해 loopback 찾기
- `r` 필요한 경우 internal pull-up 전환
- `s` TCK/TMS/TDI/TDO(때로는 TRST/SRST도) scan
- `y` undocumented opcode를 발견하기 위해 IR brute-force
- `x` pin state의 boundary-scan snapshot 생성

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



유효한 TAP이 발견되면 발견된 pin을 나타내는 `FOUND!`로 시작하는 줄이 표시됩니다.

### JTAGenum Safety Tips

- 항상 ground를 공유하고, target Vtref보다 높은 전압을 알 수 없는 pin에 절대 인가하지 마세요. 확실하지 않다면 후보 pin에 100–470 Ω series resistor를 추가하세요.
- device가 4-wire JTAG 대신 SWD/SWJ를 사용하는 경우 JTAGenum이 이를 감지하지 못할 수 있습니다. SWD tool 또는 SWJ-DP를 지원하는 adapter를 사용해 보세요.

## 더 안전한 pin 탐색 및 hardware setup

- 먼저 multimeter로 Vtref와 GND를 식별합니다. 많은 adapter는 I/O voltage를 설정하기 위해 Vtref가 필요합니다.
- Level shifting: push-pull signal용으로 설계된 bidirectional level shifter를 우선 사용합니다(JTAG line은 open-drain이 아님). JTAG에는 auto-direction I2C shifter를 사용하지 마세요.
- 유용한 adapter: FT2232H/FT232H board(예: Tigard), CMSIS-DAP, J-Link, ST-LINK(vendor-specific), ESP-USB-JTAG(ESP32-Sx에서 사용). 최소한 TCK, TMS, TDI, TDO, GND 및 Vtref를 연결하고, 필요에 따라 TRST와 SRST도 연결합니다.

## OpenOCD와 첫 접촉(scan 및 IDCODE)

OpenOCD는 JTAG/SWD를 위한 de-facto OSS입니다. 지원되는 adapter를 사용하면 chain을 scan하고 IDCODE를 읽을 수 있습니다.<sup>[[1]](#references)</sup>

- J-Link를 사용하는 generic example:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 내장 USB‑JTAG (외부 probe 불필요):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### 참고

- "all ones/zeros" IDCODE가 표시되면 wiring, power, Vtref, 그리고 해당 port가 fuses/option bytes에 의해 locked되지 않았는지 확인하세요.
- 알 수 없는 chain을 bring up할 때 수동 TAP interaction을 수행하려면 OpenOCD low-level `irscan`/`drscan`을 참고하세요.<sup>[[1]](#references)</sup>

## CPU 중지 및 memory/flash 덤프

TAP가 인식되고 target script가 선택되면 core를 halt하고 memory regions 또는 internal flash를 덤프할 수 있습니다. 예시는 다음과 같습니다(target, base addresses 및 sizes를 조정하세요):<sup>[[1]](#references)</sup>

- init 이후 generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (가능한 경우 SBA 우선):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32-S3, OpenOCD helper를 통해 프로그래밍하거나 읽기:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
### Memory-Dumping 팁

- 긴 dump 전에 `mdw/mdh/mdb`를 사용해 memory를 sanity-check합니다.
- 여러 device chain에서는 target이 아닌 device에 BYPASS를 설정하거나 모든 TAP을 정의하는 board file을 사용합니다.

## Boundary-scan 트릭 (EXTEST/SAMPLE)

CPU debug access가 잠겨 있어도 boundary-scan이 여전히 노출되어 있을 수 있습니다. UrJTAG/OpenOCD를 사용하면:<sup>[[1]](#references)</sup>
- 시스템이 실행 중일 때 SAMPLE로 pin state를 snapshot합니다 (bus activity를 확인하고 pin mapping을 검증).
- EXTEST로 pin을 drive합니다 (예: board wiring이 허용하면 MCU를 통해 external SPI flash line을 bit-bang하여 오프라인으로 읽기).

FT2232x adapter를 사용하는 최소 UrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
장치의 boundary register bit ordering을 파악하려면 BSDL이 필요합니다. 일부 vendor는 production 과정에서 boundary-scan cell을 lock하므로 주의해야 합니다.

## 최신 대상 및 참고 사항

- ESP32-S3/C3에는 native USB-JTAG bridge가 포함되어 있습니다. OpenOCD는 external probe 없이 USB를 통해 직접 통신할 수 있습니다. triage와 dump에 매우 편리합니다.<sup>[[2]](#references)</sup>
- RISC-V debug (v0.13+)는 OpenOCD에서 폭넓게 지원됩니다. core를 안전하게 halt할 수 없는 경우 memory access에는 SBA를 우선 사용하세요.
- 많은 MCU는 debug authentication과 lifecycle state를 구현합니다. 전원이 정상인데 JTAG가 동작하지 않는다면 device가 closed state로 fuse되었거나 authenticated probe를 요구할 수 있습니다.

## 방어 및 hardening (실제 device에서 예상할 사항)

- production에서 JTAG/SWD를 영구적으로 disable하거나 lock합니다(예: STM32 RDP level 2, PAD JTAG를 disable하는 ESP eFuse, NXP/Nordic APPROTECT/DPAP).
- manufacturing access는 유지하면서 authenticated debug를 요구합니다(ARMv8.2-A ADIv6 Debug Authentication, OEM이 관리하는 challenge-response).
- 접근하기 쉬운 test pad를 배치하지 마세요. test via를 내부에 묻고, TAP을 격리하기 위해 resistor를 제거하거나 배치하며, keying이 적용된 connector 또는 pogo-pin fixture를 사용하세요.
- Power-on debug lock: secure boot을 강제하는 초기 ROM 뒤에 TAP을 배치합니다.

## References

- [1] [OpenOCD User’s Guide – JTAG Commands 및 configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32-S3 JTAG debugging (USB-JTAG, OpenOCD 사용법)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino 기반 JTAG pinout scanner](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
