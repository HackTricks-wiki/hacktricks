# SPI

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

SPI(Serial Peripheral Interface)는 집적 회로 간 단거리 통신에 흔히 사용되는 동기식 직렬 버스입니다. 컨트롤러는 클록을 공급하고 칩 선택 신호를 사용해 EEPROM, 센서 또는 제어 장치와 같은 주변 장치를 선택합니다.<sup>[[1]](#references)</sup>

여러 주변 장치가 클록 및 데이터 라인을 공유할 수 있으며, 일반적으로 주변 장치마다 별도의 칩 선택 신호를 사용합니다. 컨트롤러가 전송을 조정하며, 주변 장치는 보통 SPI 버스를 통해 서로 직접 통신하지 않습니다. 칩 선택 신호의 극성과 타이밍은 장치별로 다릅니다. 선택 시 로우 상태가 활성화되는 방식이 흔하지만, 항상 그런 것은 아닙니다. SPI는 장치 검색, 주소 지정, 명령 또는 단일 최대 전송 길이를 정의하지 않으므로, 항상 대상 장치의 데이터시트를 확인하세요.<sup>[[1]](#references)</sup>

MOSI/COPI는 컨트롤러에서 주변 장치로 데이터를 전달하고, MISO/CIPO는 주변 장치에서 컨트롤러로 데이터를 전달합니다. 양방향 데이터는 동시에 시프트될 수 있습니다. 명령, 주소, 더미 사이클 및 반환 데이터 간의 관계는 SPI가 아니라 주변 장치에서 정의하며, 클록 극성 및 위상(모드 0–3)에 따라 달라집니다. 입력이 끝난 직후 정확히 한 클록 뒤에 출력이 시작된다고 가정하지 마세요.<sup>[[1]](#references)</sup>

## EEPROM에서 펌웨어 덤프하기

펌웨어를 덤프하면 이를 분석하고 취약점을 찾는 데 유용합니다. 올바른 이미지가 온라인에 없거나 모델, 하드웨어 리비전 또는 버전에 따라 다를 수 있으므로, 물리 장치에서 직접 추출하면 평가 대상과 정확히 일치하는 이미지를 확보할 수 있습니다.

시리얼 콘솔이 도움이 될 수 있지만, 파일 시스템이 읽기 전용일 수 있고 대상 장치에 테스트 트래픽을 송수신하거나 바이너리를 편리하게 추출하는 데 필요한 유틸리티를 비롯한 분석 도구가 없을 수도 있습니다. 오프라인 이미지를 확보하면 플래시 레이아웃 전체를 보존하고, 실행 중인 대상을 변경하지 않고도 파일 시스템을 추출하고 리버스 엔지니어링할 수 있습니다.

승인된 물리 접근 평가 중에는 검증된 덤프를 사용해 통제된 수정 및 재플래시 테스트도 수행할 수 있습니다. 여기에는 파일을 변경하거나 테스트 페이로드/백도어를 삽입해 펌웨어 수준의 지속성을 입증하는 작업이 포함됩니다. 쓰기 작업을 하기 전에 일치하는 덤프를 여러 개 확보하고 원본 이미지를 보존하세요. 전압, 칩 선택, 레이아웃 또는 이미지가 잘못되면 장치가 벽돌이 될 수 있습니다.

### CH341A EEPROM 프로그래머 및 리더

이 저렴한 USB 도구는 호환되는 시리얼 EEPROM 및 SPI 플래시 장치를 덤프하고 다시 플래시할 수 있습니다. PC BIOS/UEFI 펌웨어를 저장하는 SPI NOR 플래시 칩에 흔히 사용되며, 시간이 제한된 물리 접근 상황에서 편리합니다.

![drawing](../../images/board_image_ch341a.jpg)

플래시 메모리를 CH341A에 연결한 다음 프로그래머를 컴퓨터에 연결하세요. 프로그래머가 감지되지 않으면 대상 칩을 점검하기 전에 USB 케이블, OS 권한 및 적절한 CH341A 드라이버를 확인하세요. 데이터시트나 측정기를 사용해 칩 전압, 1번 핀, 어댑터 배선 및 프로그래머 출력을 확인하세요. VCC를 USB 커넥터 반대쪽에 배치하는 것과 같은 규칙에 **의존하지 마세요**. 방향이 잘못되거나 3.3/1.8 V 부품에 5 V를 인가하면 부품이 손상될 수 있습니다. 회로 내에서 읽을 때는 보드의 나머지 부분이 버스에 부하를 걸거나 전원을 공급해 읽기에 실패할 수도 있습니다.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom` 또는 G-Flash와 같은 소프트웨어를 사용해 칩을 읽으세요. G-Flash는 최소한의 GUI를 제공하며 호환 장치를 자동 감지할 수 있어 빠르게 데이터를 확보할 때 편리하지만, 감지된 모델과 전압은 직접 확인하세요. 정확한 프로그래머를 지정하고, 필요한 경우 정확한 칩 모델도 지정하세요. 덤프를 신뢰할 수 있는 것으로 판단하기 전에 최소 두 번 읽고 해시를 비교하세요.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

펌웨어를 덤프한 뒤에는 바이너리 파일을 분석할 수 있습니다. strings, hexdump, xxd, binwalk 등의 도구를 사용하면 펌웨어와 전체 파일 시스템에 관한 많은 정보를 추출할 수 있습니다.

초기 분석에는 Binwalk를 사용해 알려진 시그니처를 검색하고 지원되는 내장 콘텐츠를 추출할 수 있습니다:

```
binwalk -e <filename>
```

출력 파일은 `.bin`, `.rom` 또는 다른 확장자를 사용할 수 있습니다. 확장자만으로 파일 형식을 알 수는 없습니다.

> [!CAUTION]
> 펌웨어 추출은 세심한 작업이며 많은 인내심이 필요합니다. 부주의하게 다루면 펌웨어가 손상되거나 완전히 지워져 장치를 사용할 수 없게 될 수도 있습니다. 펌웨어 추출을 시도하기 전에 해당 장치에 대해 충분히 알아보는 것이 좋습니다.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

일부 데이터시트에서는 대상 핀을 `DI`와 `DO`로 표기합니다. 일반적인 단일 데이터 라인 flash 연결에서는 컨트롤러의 **MOSI/COPI를 DI에 연결**하고 컨트롤러의 **MISO/CIPO를 DO에 연결**합니다. 듀얼/쿼드 I/O 부품에서는 다른 모드에서 핀을 재사용하므로 대상 데이터시트를 확인하세요.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Bus의 PINOUT에 SPI 연결용 MOSI 및 MISO 핀이 표시되어 있더라도 일부 SPI는...](<../../images/image (360).png>)

Windows 또는 Linux에서는 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용하여 다음과 같은 명령으로 flash memory의 내용을 덤프할 수 있습니다.

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

최근 Bus Pirate 문서에는 선택적 `serialspeed` 및 `spispeed` 매개변수도 나와 있습니다. 긴 전선이나 회로 내 부하로 읽기가 불안정하다면 낮은 속도부터 시작하세요.<sup>[[3]](#references)</sup>

### 컨트롤러가 flash 버스를 공유할 때의 회로 내 읽기

SOIC 클립은 flash 전원을 PCB의 나머지 부분에 공급할 수 있습니다. 이때 MCU에 전원이 공급되어 같은 칩에 접근하면 MCU의 SPI 전송과 외부 프로그래머의 전송이 충돌할 수 있습니다. 따라서 `No EEPROM/flash device found`라는 결과만으로 flash가 없거나 지원되지 않는다고 단정할 수는 없습니다. 먼저 핀 배열, 전압, 접촉 상태를 확인한 다음, 기판의 컨트롤러도 활성 상태인지 확인하세요.<sup>[[4]](#references)</sup>

리셋 테스트 패드를 사용할 수 있다면, 리셋을 걸기 전에 멀티미터로 극성과 전압을 확인하세요. MCU를 리셋 상태로 유지하면 경쟁하는 SPI 호스트를 중지하면서 flash에 접근할 수 있습니다. 다른 방법으로는 칩을 분리하거나 MCU의 읽기를 수동으로 기록할 수 있습니다. 후자의 방법으로는 아직 읽지 않은 영역에 접근하거나 칩에 쓸 수 없으며, 프로브 배선을 추가하면 빠른 버스 신호에 간섭이 생길 수 있습니다. 오실레이터 또는 부트 모드 개입은 대상별 방법이므로 회로도와 신호를 확인하는 일을 대신할 수 없습니다.<sup>[[4]](#references)</sup>

MCU를 비활성 상태로 유지한 채, `spidev` 인터페이스를 활성화한 Raspberry Pi로 flashrom의 `linux_spi` 프로그래머를 사용해 읽을 수 있습니다. 다른 어댑터를 사용한다면 `-p` 값을 변경하세요. 읽기를 반복하고 해시를 비교한 뒤에 결과를 신뢰하세요. SFDP 자동 감지와 읽기 성공만으로는, 지원되지 않는 부품에서 지우기, 쓰기 또는 쓰기 보호 작업이 작동한다고 볼 수 없습니다.<sup>[[4]](#references)[[2]](#references)</sup>

```bash
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-1.bin
sudo flashrom -p linux_spi:dev=/dev/spidev0.0 -r flash-2.bin
sha256sum flash-1.bin flash-2.bin
```

### 로직 분석기로 SPI 플래시 읽기 재구성하기

능동 읽기가 불가능하면 부팅 중이나 선택한 UI 동작을 수행할 때 칩 선택, 클록, 컨트롤러-플래시 데이터, 플래시-컨트롤러 데이터를 캡처합니다. PulseView에서 먼저 활성 칩 선택 구간과 클록을 식별한 다음, 플래시 핀 배치에 따라 SPI 디코더의 데이터 채널을 설정하고 그럴듯한 명령/주소 뒤에 데이터가 반환되는지 확인합니다. Binary Decoder Output View로 **MISO/플래시 출력** 바이트를 내보내고, 각 응답을 해당 플래시 오프셋에 배치할 수 있도록 디코딩된 읽기 주소를 보존합니다. 메뉴 조작으로 읽은 내용만 캡처하면 요청된 영역만 얻을 수 있으며, 완전한 플래시 이미지는 얻을 수 없습니다. 주소를 확인하지 않은 채 응답을 연속된 데이터처럼 이어 붙이지 마세요.<sup>[[4]](#references)</sup>

덤프에 실행 코드가 아닌 그래픽이 들어 있는 것처럼 보이면 [raw 디스플레이 에셋 1차 분석](../firmware-analysis/#raw-display-assets-in-external-flash)을 계속 진행합니다.<sup>[[4]](#references)</sup>

#### Scapy와 SPI/QSPI 혼합 캡처

레이블이 없는 프로브에서는 응답 데이터 전에 opcode가 나타나는 라인을 확인해 MOSI와 MISO를 구분한 다음, 플래시 데이터시트와 대조해 명령을 확인합니다. 클록 주기보다 짧은 펄스는 샘플링된 비트가 아니라 프로브 노이즈일 수 있으며, 클립 배선이 추가되면 고속 캡처의 신뢰도가 떨어질 수 있습니다.<sup>[[5]](#references)</sup>

Saleae의 SPI CSV 내보내기에서는 `enable`과 `disable`로 칩 선택 구간을 표시하고, `result` 행에 MOSI/MISO 바이트를 담습니다. 디코딩하기 전에 바이트를 구간별로 묶으세요. 모든 MISO 데이터를 이어 붙이면 트랜잭션 주소가 사라집니다.<sup>[[5]](#references)</sup> Scapy `Packet`은 `ByteEnumField` opcode와 조건부 주소 및 더미 필드를 사용해 MOSI 헤더를 모델링할 수 있습니다. 24비트 NOR 읽기의 경우 `0x03`은 opcode와 주소 바이트 세 개로 구성되며, `0x0B`는 더미 바이트를 추가합니다. `len(req.self_build())`는 모델링된 헤더 길이를 반환합니다. 단일 레인 읽기에서는 `miso[header_length:]`가 플래시 응답이며, 헤더 뒤의 MOSI는 컨트롤러 측의 don't-care 데이터입니다.<sup>[[5]](#references)</sup> 응답은 `0xFF`로 채운 이미지의 디코딩된 주소에 배치하고, 커버된 오프셋은 별도로 추적합니다. 관찰되지 않은 바이트는 플래시에 실제로 `0xFF`가 저장되어 있었다는 증거가 아닙니다.<sup>[[5]](#references)[[6]](#references)</sup>

W25Q 방식의 `0x6B` (1-1-4) 읽기는 opcode와 주소에 한 레인을 사용하지만, 응답 데이터에는 IO0–IO3을 사용합니다. 이전에 `/WP` 및 `/HOLD` 핀이었던 라인에서 활동이 나타나는 것은 클록만 빨라지는 것보다 쿼드 모드 전환의 더 강한 증거입니다. 단일 레인 분석기는 쿼드 응답을 잘못 디코딩할 수 있습니다.<sup>[[5]](#references)</sup> 명령의 레인 너비와 더미 사이클에 맞춰 QSPI 분석기를 설정해 해당 구간을 내보낸 다음, 플래시 주소를 기준으로 단일 레인 읽기와 쿼드 레인 읽기를 병합합니다.<sup>[[5]](#references)[[7]](#references)</sup> `spidump`는 두 내보내기 형식을 모두 자동 감지하고, 잘못된 레인 너비로 디코딩된 읽기를 버리며, 읽기 커버리지를 보고합니다.<sup>[[6]](#references)</sup> 저장소에서 의존성을 설치한 뒤 다음 명령으로 캡처를 병합합니다.<sup>[[6]](#references)</sup>

```bash
python main.py single_lane_boot.csv --merge quad_boot.txt -o recovered_flash.bin -v
```

결과는 완전한 칩 덤프가 아니라 여전히 일부만 관찰한 것입니다.<sup>[[5]](#references)[[6]](#references)</sup> 쓰기 동작을 별도로 확인하려면 `0x06` 쓰기 활성화, `0x05` 상태 폴링, 지우기 opcode, `0x02` 페이지 프로그램 명령을 연관 지어 분석합니다. 페이지 프로그램 데이터는 MOSI의 주소 뒤에 이어지며, 읽기 전용 재구성에는 포함되지 않습니다.<sup>[[5]](#references)</sup> 읽기 범위 정보를 유지하면서 [firmware analysis](../firmware-analysis/)로 결과 이미지를 분석합니다.

## References

- [1] [Analog Devices — SPI 인터페이스 소개](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 설명서 — CH341A SPI 프로그래머 및 읽기/쓰기 옵션](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 문서 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
- [4] [VoidStar Security — 하드웨어 해킹 기초 다지기 2부](https://voidstarsec.com/blog/brushing-up-part-2)
- [5] [VoidStar Security — 하드웨어 리버스 엔지니어링을 위한 Scapy 확장](https://voidstarsec.com/blog/scapy-spi-reconstruction)
- [6] [spidump — SPI/QSPI 트레이스 캡처 및 재구성](https://github.com/wrongbaud/spidump)
- [7] [Saleae Logic/KingstVIS용 QSPI Analyzer](https://github.com/AddioElectronics/QSPI-Analyzer)
{{#include ../../banners/hacktricks-training.md}}
