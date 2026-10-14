# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## JTAGenum

**JTAGenum**은 Arduino 호환 MCU 또는 실험적으로 Raspberry Pi에 로드해, 알 수 없는 JTAG 핀 배열을 brute-force하고 명령어 레지스터를 열거할 수 있는 도구입니다.<sup>[[3]](#references)</sup>

- Arduino: 디지털 핀 D2–D11을 최대 10개의 JTAG 후보 패드/테스트 포인트에 연결하고, Arduino GND를 대상 장치의 GND에 연결합니다. 전압이 안전한지 알지 못한다면 대상 장치에는 별도로 전원을 공급하세요. 3.3 V 로직(예: Arduino Due)을 사용하거나, 1.8–3.3 V 대상 장치를 프로빙할 때는 레벨 시프터/직렬 저항을 사용하세요.
- Raspberry Pi: Pi 빌드는 사용할 수 있는 GPIO가 더 적어 스캔이 느립니다. 현재 핀 매핑과 제약 사항은 저장소에서 확인하세요.

플래시한 후 시리얼 모니터를 115200 baud로 열고 `h`를 입력해 도움말을 확인하세요. 일반적인 사용 흐름은 다음과 같습니다.

- `l` 가짜 양성을 피하기 위한 루프백 찾기
- `r` 필요한 경우 내부 풀업 전환
- `s` TCK/TMS/TDI/TDO(때로는 TRST/SRST) 스캔
- `y` 문서화되지 않은 opcode를 찾기 위한 IR brute-force
- `x` 핀 상태의 boundary-scan 스냅샷

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (939).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (578).png>)

![JTAG - JTAGenum: x boundary‑scan snapshot of pin states](<../../images/image (774).png>)



유효한 TAP을 찾으면 발견된 핀을 나타내는 `FOUND!`로 시작하는 줄이 표시됩니다.

### JTAGenum 안전 팁

- 항상 접지를 공유하고, 알 수 없는 핀에 대상 장치의 Vtref보다 높은 전압을 인가하지 마세요. 확실하지 않다면 후보 핀에 100–470 Ω 직렬 저항을 추가하세요.
- 장치가 4선 JTAG 대신 SWD/SWJ를 사용한다면 JTAGenum이 감지하지 못할 수 있습니다. SWD 도구나 SWJ‑DP를 지원하는 어댑터를 사용해 보세요.

## 안전한 핀 탐색 및 하드웨어 설정

- 먼저 멀티미터로 Vtref와 GND를 확인하세요. 많은 어댑터는 I/O 전압 설정에 Vtref가 필요합니다.
- 레벨 시프팅: 푸시풀 신호용으로 설계된 양방향 레벨 시프터를 사용하세요(JTAG 라인은 오픈 드레인이 아닙니다). JTAG에는 자동 방향 감지 I2C 시프터를 사용하지 마세요.
- 유용한 어댑터: FT2232H/FT232H 보드(예: Tigard), CMSIS-DAP, J‑Link, ST‑LINK(벤더별), ESP‑USB‑JTAG(ESP32‑Sx용). 최소한 TCK, TMS, TDI, TDO, GND, Vtref를 연결하고, 필요하면 TRST와 SRST도 연결하세요.

## OpenOCD 시작하기 (스캔 및 IDCODE)

OpenOCD는 JTAG/SWD용 사실상의 OSS입니다. 지원되는 어댑터를 사용하면 체인을 스캔하고 IDCODE를 읽을 수 있습니다.<sup>[[1]](#references)</sup>

- J‑Link를 사용하는 일반적인 예시:
```
openocd -f interface/jlink.cfg -c "transport select jtag; adapter speed 1000" \
  -c "init; scan_chain; shutdown"
```
- ESP32‑S3 내장 USB‑JTAG (외부 프로브 불필요):<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg -c "init; scan_chain; shutdown"
```
### 참고 사항

- "all ones/zeros" IDCODE가 나오면 배선, 전원, Vtref, 그리고 포트가 fuse/option byte로 잠겨 있지 않은지 확인하세요.
- 알 수 없는 chain을 초기화할 때 수동으로 TAP과 상호작용하려면 OpenOCD의 low-level `irscan`/`drscan`을 참고하세요.<sup>[[1]](#references)</sup>

## CPU 중지 및 메모리/flash 덤프

TAP이 인식되고 target script를 선택하면 core를 중지하고 메모리 영역이나 internal flash를 덤프할 수 있습니다. 예시는 다음과 같습니다(target, base address 및 크기를 조정하세요).<sup>[[1]](#references)</sup>

- 초기화 후 generic target:
```
openocd -f interface/jlink.cfg -f target/stm32f1x.cfg \
  -c "init; reset halt; mdw 0x08000000 4; dump_image flash.bin 0x08000000 0x00100000; shutdown"
```
- RISC‑V SoC (사용 가능한 경우 SBA 우선):
```
openocd -f interface/ftdi/ft232h.cfg -f target/riscv.cfg \
  -c "init; riscv set_prefer_sba on; halt; dump_image sram.bin 0x80000000 0x20000; shutdown"
```
- ESP32‑S3, OpenOCD helper를 통해 프로그래밍하거나 읽기:<sup>[[2]](#references)</sup>
```
openocd -f board/esp32s3-builtin.cfg \
  -c "program_esp app.bin 0x10000 verify exit"
```

### Memory-Dumping 팁

- 긴 덤프를 수행하기 전에 `mdw/mdh/mdb`를 사용해 메모리가 정상인지 확인하세요.
- 여러 장치로 구성된 체인에서는 대상이 아닌 장치에 BYPASS를 설정하거나 모든 TAP을 정의하는 board file을 사용하세요.

## Boundary-scan 트릭 (EXTEST/SAMPLE)

CPU debug access가 잠겨 있어도 boundary-scan이 노출되어 있을 수 있습니다. UrJTAG/OpenOCD를 사용하면 다음을 수행할 수 있습니다:<sup>[[1]](#references)</sup>
- 시스템이 실행 중일 때 SAMPLE로 핀 상태를 스냅샷해 버스 활동을 찾고 핀 매핑을 확인합니다.
- EXTEST로 핀을 구동합니다(예: 보드 배선이 허용하면 MCU를 통해 외부 SPI flash 라인을 bit-bang해 오프라인으로 읽기).

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
디바이스 BSDL을 확인해야 boundary register의 비트 순서를 알 수 있습니다. 일부 vendor는 생산 단계에서 boundary-scan cell을 잠그므로 주의하세요.

## 최신 대상 및 참고 사항

- ESP32‑S3/C3에는 기본 USB‑JTAG bridge가 포함되어 있습니다. OpenOCD는 외부 probe 없이 USB를 통해 직접 통신할 수 있습니다. triage와 dump에 매우 편리합니다.<sup>[[2]](#references)</sup>
- RISC‑V debug(v0.13+)는 OpenOCD에서 폭넓게 지원됩니다. core를 안전하게 halt할 수 없는 경우 memory access에는 SBA를 우선 사용하세요.
- 많은 MCU는 debug authentication 및 lifecycle state를 구현합니다. 전원이 정상인데 JTAG가 작동하지 않는다면, 디바이스가 closed state로 fuse되었거나 인증된 probe가 필요할 수 있습니다.

## 방어 및 보안 강화 (실제 디바이스에서 예상되는 사항)

- 생산 단계에서 JTAG/SWD를 영구적으로 비활성화하거나 잠급니다(예: STM32 RDP level 2, PAD JTAG를 비활성화하는 ESP eFuse, NXP/Nordic APPROTECT/DPAP).
- 제조 접근 권한은 유지하면서 인증된 debug를 요구합니다(ARMv8.2‑A ADIv6 Debug Authentication, OEM 관리형 challenge-response).
- 쉽게 접근할 수 있는 test pad를 배치하지 않습니다. test via를 내부에 묻고, TAP을 분리하기 위해 저항을 제거하거나 실장하며, keying이 있는 connector 또는 pogo-pin fixture를 사용합니다.
- Power-on debug lock: secure boot를 적용하는 초기 ROM 뒤에 TAP을 둡니다.

## References

- [1] [OpenOCD 사용 설명서 – JTAG 명령 및 구성](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG 디버깅 (USB‑JTAG, OpenOCD 사용법)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino 기반 JTAG 핀아웃 스캐너](https://github.com/cyphunk/JTAGenum)
{{#include ../../banners/hacktricks-training.md}}
