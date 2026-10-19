# JTAG

{{#include ../../banners/hacktricks-training.md}}


{{#ref}}
README.md
{{#endref}}

## 더 안전한 핀 탐색 및 하드웨어 설정

- 먼저 멀티미터로 Vtref와 GND를 식별합니다. 많은 어댑터는 I/O 전압을 설정하기 위해 Vtref가 필요합니다.
- 레벨 시프팅: 푸시-풀 신호용으로 설계된 양방향 레벨 시프터를 사용합니다(JTAG 라인은 오픈 드레인이 아닙니다). JTAG에는 자동 방향 감지 I2C 시프터를 사용하지 마세요.
- 유용한 어댑터: FT2232H/FT232H 보드(예: Tigard), CMSIS-DAP, J-Link, ST-LINK(벤더별), ESP-USB-JTAG(ESP32-Sx). 최소한 TCK, TMS, TDI, TDO, GND, Vtref를 연결하고, 필요에 따라 TRST와 SRST도 연결합니다.

문서화되지 않은 헤더에서는 **대상 장치의 전원이 꺼진 상태에서** 알려진 접지면과의 연속성을 확인해 GND를 식별합니다. 전압 모드로 전환하고 전원을 켠 뒤에는 전압이 높은 모든 핀을 Vtref로 분류하지 마세요. 디지털 입력도 멀티미터에서 비슷하게 보일 수 있습니다. 후보 전원 레일을 인근 디커플링 커패시터까지 추적하고 오실로스코프로 전원 켜기/끄기 파형을 비교합니다. 커패시터처럼 서서히 상승하거나 하강하는 파형은 전원/레퍼런스 네트일 가능성을 보여주지만, 레벨 시프팅된 프로브를 연결하기 전에 전압과 배선을 확인하세요. PiFex에서는 기본 3.3 V 설정 대신 `VCCA_IN`을 통해 외부의 저전압 대상 장치 레퍼런스를 선택할 수 있습니다.<sup>[[4]](#references)</sup>

## JTAGenum

**JTAGenum**은 Arduino 호환 MCU 또는 실험적으로 Raspberry Pi에 올려 알 수 없는 JTAG 핀 배열을 무차별 대입하고 명령어 레지스터를 열거할 수 있는 도구입니다.<sup>[[3]](#references)</sup>

- Arduino: 디지털 핀 D2–D11을 의심되는 JTAG 패드/테스트 포인트 최대 10개에 연결하고, Arduino GND를 대상 장치의 GND에 연결합니다. 전원 레일이 안전하다고 확신할 수 없다면 대상 장치에는 별도로 전원을 공급하세요. 3.3 V 로직(예: Arduino Due)을 사용하거나 1.8–3.3 V 대상 장치를 프로빙할 때 레벨 시프터/직렬 저항을 사용하세요.
- Raspberry Pi: Pi 빌드는 사용할 수 있는 GPIO가 더 적어(따라서 스캔 속도가 느려) 현재 핀 맵과 제약 사항을 저장소에서 확인하세요.

펌웨어를 올린 뒤 115200 baud로 시리얼 모니터를 열고 `h`를 입력해 도움말을 확인합니다. 일반적인 사용 흐름은 다음과 같습니다.

- `l` 루프백을 찾아 오탐을 방지
- `r` 필요한 경우 내부 풀업을 전환
- `s` TCK/TMS/TDI/TDO(때로는 TRST/SRST도 포함)를 스캔
- `y` 문서화되지 않은 opcode를 찾기 위해 IR을 무차별 대입
- `x` 핀 상태의 boundary-scan 스냅샷을 생성

![JTAG - JTAGenum: x 핀 상태의 boundary-scan 스냅샷](<../../images/image (939).png>)

![JTAG - JTAGenum: x 핀 상태의 boundary-scan 스냅샷](<../../images/image (578).png>)

![JTAG - JTAGenum: x 핀 상태의 boundary-scan 스냅샷](<../../images/image (774).png>)



유효한 TAP을 찾으면 발견된 핀을 나타내는 `FOUND!`로 시작하는 줄이 표시됩니다.

### JTAGenum 안전 팁

- 항상 접지를 공유하고, 알 수 없는 핀에 대상 장치의 Vtref보다 높은 전압을 절대 인가하지 마세요. 확실하지 않다면 후보 핀에 100–470 Ω 직렬 저항을 추가하세요.
- 장치가 4선 JTAG 대신 SWD/SWJ를 사용하는 경우 JTAGenum이 이를 감지하지 못할 수 있습니다. SWD 도구나 SWJ-DP를 지원하는 어댑터를 사용해 보세요.

## go-jtagenum을 사용한 GPIO 핀 검색

전원이 켜진 대상 장치에 공통 접지가 확인되어 있고 I/O 전압이 호환되는 경우, `go-jtagenum`은 Raspberry Pi GPIO에서 후보 JTAG 신호를 열거할 수 있습니다. `-pins` JSON은 레이블을 **물리적 헤더 위치가 아닌 GPIO 번호**에 매핑합니다.<sup>[[5]](#references)</sup> SSD 예시에서 첫 IDCODE 스캔은 그럴듯하지 않게 길고 값이 계속 바뀌는 체인도 보고했습니다. 후보 TDO 라인의 값이 바뀐다는 것만으로는 유효한 TAP의 증거가 되지 않습니다. TDI에서 1비트 bypass 레지스터를 거쳐 TDO로 알려진 비트 패턴을 이동시키는 BYPASS 스캔으로 그럴듯한 결과를 다시 확인하세요.<sup>[[4]](#references)</sup>

```bash
PINS='{ "pin2": 2, "pin3": 3, "pin9": 9, "pin10": 10, "pin14": 14, "pin15": 15 }'
go-jtagenum -pins "$PINS" -command scan_idcode -delay-tck 50
go-jtagenum -pins "$PINS" -command scan_bypass -delay-tck 50
```

해당 보드에서 BYPASS로 확인된 핀은 `TCK=10`, `TMS=14`, `TDI=9`, `TDO=15`였으며, 추가 핀은 nTRST 후보일 가능성만 있었습니다. 후보 핀에서 모두 0이 반환되거나 일관되지 않은 패턴이 나타나면 해당 핀에 신호를 할당하기 전에 접촉 상태, 대상 장치의 전원, 풀업, 클록/리셋 지연을 확인하세요.<sup>[[4]](#references)[[5]](#references)</sup> 이 도구는 `test_bypass`와 함께 `-known-pins`를 사용해 복구된 매핑을 다시 테스트할 수도 있습니다.<sup>[[5]](#references)</sup>

## UrJTAG로 문서화되지 않은 TAP 특성 파악하기

핀 배치만 알아서는 디버깅에 필요한 명령 레지스터(IR) opcode나 데이터 레지스터(DR) 너비를 알 수 없습니다. Raspberry Pi GPIO cable을 지원하는 UrJTAG 빌드에서 복구한 매핑을 설정한 다음 `idcode`, `detect`, `discover`를 실행하세요. SSD 예제에서는 TAP 하나와 4비트 IR이 확인되었으며, IR 값에 따라 DR 너비가 달랐습니다. DR 길이가 `-1`이거나 “TDO stuck at 0”이 표시되면 유효한 레지스터 정의로 볼 수 없습니다. 너비를 지정하기보다는 타이밍, 배선, 선택된 명령어를 점검하세요.<sup>[[4]](#references)</sup>

```text
jtag> cable gpio tck=10 tdi=9 tms=14 tdo=15
jtag> idcode
jtag> detect
jtag> discover
```

This는 자동 CPU 식별이 아니라 TAP 정찰입니다. 결과로 얻은 IDCODE를 장치 문서 및 지원되는 OpenOCD 타깃과 비교하세요. UrJTAG의 로컬 제조업체 데이터베이스에서는 유효한 ID도 unknown으로 표시될 수 있습니다.<sup>[[4]](#references)</sup>

## OpenOCD와 첫 접촉 (scan 및 IDCODE)

OpenOCD는 JTAG/SWD용 사실상의 OSS입니다. 지원되는 어댑터를 사용하면 chain을 scan하고 IDCODE를 읽을 수 있습니다:<sup>[[1]](#references)</sup>

- J-Link를 사용하는 일반적인 예:
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
- 알 수 없는 chain을 bring up할 때 수동 TAP 상호작용을 위해 OpenOCD의 저수준 `irscan`/`drscan`을 참고하세요.<sup>[[1]](#references)</sup>

## 문서화되지 않은 타깃을 OpenOCD에 추가하기

TAP ID와 IR 길이를 확인한 후, OpenOCD의 `cpu/`, `target/`, `board/` 스크립트를 살펴 **일치하는 CPU architecture**를 찾고, adapter와 target 설정을 별도로 만드세요.<sup>[[4]](#references)[[6]](#references)</sup> 다음 Pi GPIO 매핑과 ARCv2 타깃은 테스트를 거친 SSD 예시이며, 보편적인 JTAG 설정은 아닙니다. ARC 타깃 선택과 debug 설정은 이 장치에서 성공한 가정이었습니다. 다른 보드에서는 타깃에서 측정한 ID, IR 길이, architecture, GPIO 번호를 사용하세요.<sup>[[4]](#references)</sup>

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

`openocd -f raspberrypi-io.cfg -f target.cfg`를 실행하고 메모리를 읽기 전에 TAP 검사가 성공하는지 확인하세요. 예시에서는 포트 `4444`에서 Telnet을, 포트 `3333`에서 GDB 서버를 열었습니다. 인식된 IDCODE만으로는 선택한 CPU target을 검사하거나 디버깅할 수 있다는 사실이 입증되지 않습니다.<sup>[[4]](#references)</sup> 어댑터에서 `adapter gpio` 재매핑을 지원한다면 Raspberry Pi GPIO가 브레이크아웃 보드에서 JTAG으로 표시된 핀일 필요는 없습니다.<sup>[[4]](#references)[[6]](#references)</sup>

## CPU 중지 및 메모리/flash 덤프

TAP이 인식되고 target 스크립트가 선택되면 코어를 중지하고 메모리 영역이나 내부 flash를 덤프할 수 있습니다. 예시(대상, 기본 주소 및 크기를 조정하세요):<sup>[[1]](#references)</sup>

- 초기화 후 일반 target:
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

- 긴 dump를 수행하기 전에 `mdw/mdh/mdb`를 사용해 메모리가 정상인지 확인합니다.
- 여러 디바이스가 연결된 체인에서는 대상이 아닌 디바이스에 BYPASS를 설정하거나 모든 TAP을 정의하는 board file을 사용합니다.

메모리 맵이 문서화되지 않은 경우, SSD 연구에서는 1 MiB dump에서 식별 가능한 컨트롤러 문자열을 확인한 다음 OpenOCD를 통해 아키텍처를 지원하는 GDB를 사용해 `$pc`, disassembly, registers를 검사했습니다. 이렇게 확인한 실시간 주소를 바탕으로 두 번째 영역을 dump하고, ARC를 지원하는 Ghidra 빌드에서 일치하는 명령어와 대조했습니다. 문자열은 그럴듯한지 확인하는 용도일 뿐, 이미지가 완전하거나 올바르게 매핑되었다는 증거는 아닙니다.<sup>[[4]](#references)</sup> 더 폭넓은 정적 분석 단계는 [firmware analysis](../firmware-analysis/)를 참고하세요.

## Boundary-scan 트릭 (EXTEST/SAMPLE)

CPU debug access가 잠겨 있어도 boundary-scan이 노출되어 있을 수 있습니다. UrJTAG/OpenOCD를 사용하면 다음을 할 수 있습니다.<sup>[[1]](#references)</sup>
- SAMPLE로 시스템이 실행 중일 때 핀 상태를 스냅샷으로 저장합니다(버스 활동을 찾고 핀 매핑을 확인).
- EXTEST로 핀을 구동합니다(예: 보드 배선이 허용하는 경우 MCU를 통해 외부 SPI flash 라인을 bit-bang하여 오프라인으로 읽기).

FT2232x adapter를 사용하는 최소 UrJTAG 흐름:
```
jtag> cable ft2232 vid=0x0403 pid=0x6010 interface=1
jtag> frequency 100000
jtag> detect
jtag> bsdl path /path/to/bsdl/files
jtag> instruction EXTEST
jtag> shift ir
jtag> dr  <bit pattern for boundary register>
```
장치의 BSDL이 있어야 boundary register의 비트 순서를 알 수 있습니다. 일부 벤더는 생산 단계에서 boundary-scan cell을 잠그므로 주의하세요.

## 최신 타깃 및 참고 사항

- ESP32‑S3/C3에는 native USB‑JTAG bridge가 포함되어 있습니다. OpenOCD는 외부 probe 없이 USB를 통해 직접 통신할 수 있어 triage 및 dump에 매우 편리합니다.<sup>[[2]](#references)</sup>
- RISC‑V debug (v0.13+)는 OpenOCD에서 폭넓게 지원됩니다. 코어를 안전하게 halt할 수 없는 경우 메모리 액세스에는 SBA를 우선 사용하세요.
- 많은 MCU가 debug authentication 및 lifecycle state를 구현합니다. 전원이 정상인데 JTAG가 동작하지 않는다면, 장치가 closed state로 fuse되었거나 인증된 probe가 필요할 수 있습니다.

## 방어 및 강화 (실제 장치에서 예상할 사항)

- 생산 단계에서 JTAG/SWD를 영구적으로 비활성화하거나 잠급니다(예: STM32 RDP level 2, PAD JTAG를 비활성화하는 ESP eFuse, NXP/Nordic APPROTECT/DPAP).
- 제조 단계의 액세스는 유지하면서 인증된 debug를 요구합니다(ARMv8.2‑A ADIv6 Debug Authentication, OEM 관리 challenge-response).
- 쉽게 접근할 수 있는 test pad를 배치하지 마세요. test via를 숨기고, TAP을 분리하기 위해 저항을 제거하거나 실장하며, 방향이 정해진 커넥터나 pogo-pin fixture를 사용하세요.
- 전원 인가 시 debug를 잠급니다. secure boot를 강제하는 초기 ROM 뒤에 TAP을 배치하세요.

## References

- [1] [OpenOCD 사용자 가이드 – JTAG 명령 및 설정](https://openocd.org/doc-release/html/JTAG-Commands.html)
- [2] [Espressif ESP32‑S3 JTAG 디버깅 (USB‑JTAG, OpenOCD 사용법)](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/jtag-debugging/)
- [3] [JTAGenum – Arduino 기반 JTAG 핀아웃 스캐너](https://github.com/cyphunk/JTAGenum)
- [4] [VoidStar Security — Raspberry Pi를 이용한 JTAG 해킹](https://voidstarsec.com/blog/jtag-pifex)
- [5] [gremwell/go-jtagenum — GPIO JTAG 열거](https://github.com/gremwell/go-jtagenum)
- [6] [OpenOCD 사용자 가이드 — Debug Adapter 설정](https://openocd.org/doc-release/html/Debug-Adapter-Configuration.html)
{{#include ../../banners/hacktricks-training.md}}
