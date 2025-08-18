# JTAG

{{#include ../../banners/hacktricks-training.md}}

{{#ref}}
README.md
{{#endref}}

## JTAGenum

[**JTAGenum**](https://github.com/cyphunk/JTAGenum)은 Arduino 호환 MCU 또는 (실험적으로) Raspberry Pi에 로드하여 알려지지 않은 JTAG 핀 배치를 무차별 대입하고 심지어 명령 레지스터를 열거할 수 있는 도구입니다.

- Arduino: 디지털 핀 D2–D11을 최대 10개의 의심되는 JTAG 패드/테스트 포인트에 연결하고, Arduino GND를 타겟 GND에 연결합니다. 레일이 안전하다는 것을 모르는 한 타겟에 별도로 전원을 공급하십시오. 3.3 V 로직을 선호하거나 (예: Arduino Due) 1.8–3.3 V 타겟을 프로빙할 때 레벨 시프터/직렬 저항기를 사용하십시오.
- Raspberry Pi: Pi 빌드는 사용 가능한 GPIO가 적어 (스캔 속도가 느림) 현재 핀 맵과 제약 사항은 레포를 확인하십시오.

플래시가 완료되면 115200 보드에서 시리얼 모니터를 열고 도움을 위해 `h`를 전송하십시오. 일반적인 흐름:

- `l` 루프백을 찾아 잘못된 긍정을 피합니다.
- `r` 필요시 내부 풀업을 전환합니다.
- `s` TCK/TMS/TDI/TDO (때때로 TRST/SRST)를 스캔합니다.
- `y` 문서화되지 않은 연산 코드를 발견하기 위해 IR을 무차별 대입합니다.
- `x` 핀 상태의 경계 스캔 스냅샷을 생성합니다.

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

![](<../../images/image (774).png>)

유효한 TAP이 발견되면 발견된 핀을 나타내는 `FOUND!`로 시작하는 줄이 표시됩니다.

팁
- 항상 접지를 공유하고, 알려지지 않은 핀을 타겟 Vtref 이상으로 구동하지 마십시오. 의심스러운 경우 후보 핀에 100–470 Ω 직렬 저항기를 추가하십시오.
- 장치가 4선 JTAG 대신 SWD/SWJ를 사용하는 경우 JTAGenum이 이를 감지하지 못할 수 있습니다. SWD 도구나 SWJ-DP를 지원하는 어댑터를 사용해 보십시오.

## Safer pin hunting and hardware setup

- 멀티미터로 먼저 Vtref와 GND를 식별하십시오. 많은 어댑터는 I/O 전압을 설정하기 위해 Vtref가 필요합니다.
- 레벨 시프팅: 푸시-풀 신호를 위해 설계된 양방향 레벨 시프터를 선호하십시오 (JTAG 라인은 오픈 드레인이 아닙니다). JTAG에 대해 자동 방향 I2C 시프터는 피하십시오.
- 유용한 어댑터: FT2232H/FT232H 보드 (예: Tigard), CMSIS-DAP, J-Link, ST-LINK (벤더 특정), ESP-USB-JTAG (ESP32-Sx에서). 최소한 TCK, TMS, TDI, TDO, GND 및 Vtref를 연결하십시오; 선택적으로 TRST 및 SRST를 추가하십시오.

## First contact with OpenOCD (scan and IDCODE)

OpenOCD는 JTAG/SWD에 대한 사실상의 OSS입니다. 지원되는 어댑터를 사용하면 체인을 스캔하고 IDCODE를 읽을 수 있습니다:

- J-Link를 사용한 일반적인 예:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
-c "init; scan_chain; shutdown"
```
- ESP32‑S3 내장 USB‑JTAG (외부 프로브 필요 없음):
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
Notes
- "모든 1/0" IDCODE를 받으면, 배선, 전원, Vtref를 확인하고 포트가 퓨즈/옵션 바이트에 의해 잠겨 있지 않은지 확인하세요.
- 알 수 없는 체인을 올릴 때 수동 TAP 상호작용을 위해 OpenOCD 저수준 `irscan`/`drscan`을 참조하세요.

## CPU 정지 및 메모리/플래시 덤프

TAP이 인식되고 대상 스크립트가 선택되면, 코어를 정지시키고 메모리 영역 또는 내부 플래시를 덤프할 수 있습니다. 예시 (대상, 기본 주소 및 크기를 조정하세요):

- 초기화 후 일반 대상:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
-c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (사용 가능한 경우 SBA를 선호):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
-c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD 헬퍼를 통해 프로그래밍하거나 읽기:
```
openocd -f board/esp32s3-builtin.cfg \
-c "program_esp app.bin 0x10000 verify exit"
```
Tips
- `mdw/mdh/mdb`를 사용하여 긴 덤프 전에 메모리를 점검하세요.
- 다중 장치 체인의 경우, 비대상 장치에서 BYPASS를 설정하거나 모든 TAP을 정의하는 보드 파일을 사용하세요.

## 경계 스캔 트릭 (EXTEST/SAMPLE)

CPU 디버그 접근이 잠겨 있어도 경계 스캔이 여전히 노출될 수 있습니다. UrJTAG/OpenOCD를 사용하여:
- 시스템이 실행되는 동안 핀 상태를 스냅샷하기 위해 SAMPLE을 사용하세요 (버스 활동 찾기, 핀 매핑 확인).
- EXTEST를 사용하여 핀을 구동하세요 (예: 보드 배선이 허용하는 경우 MCU를 통해 외부 SPI 플래시 라인을 비트 뱅킹하여 오프라인에서 읽기).

FT2232x 어댑터를 사용한 최소 UrJTAG 흐름:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
장치 BSDL이 필요하여 경계 레지스터 비트 순서를 알아야 합니다. 일부 공급업체는 생산 중에 경계 스캔 셀을 잠글 수 있으니 주의하세요.

## 현대의 타겟 및 주의사항

- ESP32‑S3/C3는 네이티브 USB‑JTAG 브리지를 포함하고 있으며, OpenOCD는 외부 프로브 없이 USB를 통해 직접 통신할 수 있습니다. 이는 긴급 대응 및 덤프에 매우 편리합니다.
- RISC‑V 디버그(v0.13+)는 OpenOCD에서 널리 지원되며, 코어를 안전하게 중단할 수 없는 경우 메모리 접근을 위해 SBA를 선호합니다.
- 많은 MCU가 디버그 인증 및 생애 주기 상태를 구현합니다. JTAG가 작동하지 않는 것처럼 보이지만 전원이 올바른 경우, 장치가 폐쇄 상태로 퓨즈되었거나 인증된 프로브가 필요할 수 있습니다.

## 방어 및 강화(실제 장치에서 기대할 수 있는 것)

- 생산 중 JTAG/SWD를 영구적으로 비활성화하거나 잠급니다(예: STM32 RDP 레벨 2, PAD JTAG를 비활성화하는 ESP eFuses, NXP/Nordic APPROTECT/DPAP).
- 제조 접근을 유지하면서 인증된 디버그를 요구합니다(ARMv8.2‑A ADIv6 디버그 인증, OEM 관리 챌린지-응답).
- 쉬운 테스트 패드를 배치하지 마세요; 테스트 비아를 숨기고, TAP을 격리하기 위해 저항기를 제거/배치하며, 키잉 또는 포고 핀 고정 장치가 있는 커넥터를 사용하세요.
- 전원 켜기 디버그 잠금: 초기 ROM 뒤에 TAP을 게이트하여 보안 부팅을 강제합니다.

## 참고자료

- OpenOCD 사용자 가이드 – JTAG 명령 및 구성. https://openocd.org/doc-release/html/JTAG-Commands.html
- Espressif ESP32‑S3 JTAG 디버깅(USB‑JTAG, OpenOCD 사용). https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/

{{#include ../../banners/hacktricks-training.md}}
