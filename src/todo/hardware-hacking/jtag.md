# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum)은 Arduino 호환 MCU 또는 (실험적으로) Raspberry Pi에 로드하여 알려지지 않은 JTAG 핀 배열을 brute-force하고 instruction register도 열거할 수 있는 도구입니다.

- Arduino: 디지털 핀 D2–D11을 최대 10개의 JTAG 후보 패드/테스트포인트에 연결하고, Arduino GND를 대상 장치의 GND에 연결합니다. 전원 레일이 안전하다는 것을 알고 있지 않다면 대상 장치에 별도로 전원을 공급합니다. 3.3 V 로직(예: Arduino Due)을 우선 사용하거나, 1.8–3.3 V 대상 장치를 프로빙할 때는 level shifter/series resistor를 사용합니다.
- Raspberry Pi: Pi 빌드에서는 사용할 수 있는 GPIO가 더 적으므로 스캔이 느립니다. 현재 핀 매핑과 제약 사항은 repository에서 확인합니다.

플래시한 후 serial monitor를 115200 baud로 열고 `h`를 입력하면 도움말이 표시됩니다. 일반적인 흐름은 다음과 같습니다.

- `l` false positive를 피하기 위해 loopback 검색
- `r` 필요한 경우 internal pull-up 전환
- `s` TCK/TMS/TDI/TDO(때로는 TRST/SRST도 포함) 스캔
- `y` 문서화되지 않은 opcode를 찾기 위해 IR brute-force
- `x` 핀 상태의 boundary-scan snapshot

![JTAG - JTAGenum: x 핀 상태의 boundary-scan snapshot](<../../images/image (939).png>)

![JTAG - JTAGenum: x 핀 상태의 boundary-scan snapshot](<../../images/image (578).png>)

![JTAG - JTAGenum: x 핀 상태의 boundary-scan snapshot](<../../images/image (774).png>)



유효한 TAP가 발견되면 검색된 핀을 나타내는 `FOUND!`로 시작하는 줄이 표시됩니다.

팁
- 항상 ground를 공유하고, 알 수 없는 핀을 대상 장치의 Vtref보다 높은 전압으로 drive하지 마십시오. 확실하지 않다면 후보 핀에 100–470 Ω series resistor를 추가합니다.
- 장치가 4-wire JTAG 대신 SWD/SWJ를 사용하는 경우 JTAGenum이 이를 감지하지 못할 수 있습니다. SWD tools 또는 SWJ-DP를 지원하는 adapter를 사용해 보십시오.

## 더 안전한 핀 탐색 및 hardware setup

- 먼저 multimeter로 Vtref와 GND를 식별합니다. 많은 adapter는 I/O 전압을 설정하기 위해 Vtref가 필요합니다.
- Level shifting: push-pull signal용으로 설계된 bidirectional level shifter를 우선 사용합니다(JTAG line은 open-drain이 아님). JTAG에는 auto-direction I2C shifter를 사용하지 마십시오.
- 유용한 adapter: FT2232H/FT232H board(예: Tigard), CMSIS-DAP, J-Link, ST-LINK(vendor-specific), ESP-USB-JTAG(ESP32-Sx에서 사용). 최소한 TCK, TMS, TDI, TDO, GND 및 Vtref를 연결하고, 필요에 따라 TRST와 SRST도 연결합니다.

## OpenOCD와 첫 접촉(scan 및 IDCODE)

OpenOCD는 JTAG/SWD용 de-facto OSS입니다. 지원되는 adapter를 사용하면 chain을 스캔하고 IDCODE를 읽을 수 있습니다:<sup>[[1]](#references)</sup>

- J-Link를 사용하는 일반적인 예:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 내장 USB‑JTAG (외부 probe 불필요):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- "all ones/zeros" IDCODE가 표시되면 wiring, power, Vtref, 그리고 port가 fuses/option bytes로 잠겨 있지 않은지 확인하세요.
- 알 수 없는 chain을 bring up할 때 수동 TAP 상호작용을 수행하려면 OpenOCD low-level `irscan`/`drscan`을 참조하세요.<sup>[[1]](#references)</sup>

## CPU 중지 및 memory/flash 덤프

TAP가 인식되고 target script가 선택되면 core를 중지하고 memory 영역 또는 internal flash를 덤프할 수 있습니다. 예시( target, base addresses 및 sizes를 조정):<sup>[[1]](#references)</sup>

- init 후 generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (사용 가능한 경우 SBA 우선):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD helper를 통해 program하거나 read:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
팁
- 긴 dump 전에 `mdw/mdh/mdb`를 사용해 memory를 sanity-check하세요.
- 다중 device chain에서는 target이 아닌 장치에 BYPASS를 설정하거나 모든 TAP을 정의하는 board file을 사용하세요.

## Boundary-scan tricks (EXTEST/SAMPLE)

CPU debug access가 잠겨 있어도 boundary-scan이 여전히 노출되어 있을 수 있습니다. UrJTAG/OpenOCD를 사용하면 다음을 수행할 수 있습니다:<sup>[[1]](#references)</sup>
- 시스템이 실행되는 동안 SAMPLE로 pin 상태를 snapshot하여 bus activity를 확인하고 pin mapping을 검증합니다.
- EXTEST로 pin을 구동합니다. 예를 들어 board wiring이 허용한다면 MCU를 통해 외부 SPI flash line을 bit-bang하여 offline으로 읽을 수 있습니다.

FT2232x adapter를 사용하는 최소한의 UrJTAG flow:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
JTAG boundary register bit ordering을 알려면 device BSDL이 필요합니다. 일부 vendor는 production 단계에서 boundary-scan cells를 lock하므로 주의해야 합니다.

## 최신 target 및 참고 사항

- ESP32‑S3/C3에는 native USB‑JTAG bridge가 포함되어 있어 external probe 없이 OpenOCD가 USB를 통해 직접 통신할 수 있습니다. triage 및 dump에 매우 편리합니다.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+)는 OpenOCD에서 폭넓게 지원됩니다. core를 안전하게 halt할 수 없는 경우 memory access에는 SBA를 우선 사용하십시오.
- 많은 MCU는 debug authentication 및 lifecycle state를 구현합니다. 전원이 정상인데 JTAG가 동작하지 않는다면 device가 closed state로 fuse되었거나 authenticated probe를 요구하는 것일 수 있습니다.

## 방어 및 hardening (실제 device에서 예상되는 사항)

- production에서 JTAG/SWD를 영구적으로 disable하거나 lock합니다 (예: STM32 RDP level 2, PAD JTAG를 disable하는 ESP eFuse, NXP/Nordic APPROTECT/DPAP).
- manufacturing access를 유지하면서 authenticated debug를 요구합니다 (ARMv8.2‑A ADIv6 Debug Authentication, OEM이 관리하는 challenge-response).
- 쉽게 접근할 수 있는 test pad를 배치하지 마십시오. test via를 매립하고, TAP을 isolate하기 위해 resistor를 제거하거나 장착하며, keying이 적용된 connector 또는 pogo-pin fixture를 사용하십시오.
- Power-on debug lock: secure boot를 강제하는 early ROM 뒤에 TAP을 배치합니다.

## References

- [1] [OpenOCD User's Guide – JTAG Commands and configuration](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG debugging (USB‑JTAG, OpenOCD usage)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)

{{#include ../../banners/hacktricks-training.md}}
