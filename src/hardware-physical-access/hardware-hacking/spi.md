# SPI

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

SPI(Serial Peripheral Interface)는 집적 회로 간 단거리 통신에 흔히 사용되는 동기식 직렬 버스입니다. 컨트롤러는 클록을 공급하고 칩 선택 신호를 사용해 EEPROM, 센서 또는 제어 장치와 같은 주변 장치를 선택합니다.<sup>[[1]](#references)</sup>

여러 주변 장치가 클록 및 데이터 라인을 공유할 수 있으며, 일반적으로 주변 장치마다 별도의 칩 선택 신호를 사용합니다. 전송은 컨트롤러가 조정하며, 주변 장치는 보통 SPI 버스를 통해 서로 직접 통신하지 않습니다. 칩 선택 신호의 극성과 타이밍은 장치마다 다릅니다. active-low 선택 방식이 흔하지만, 항상 그런 것은 아닙니다. SPI는 장치 검색, 주소 지정, 명령 또는 단일 최대 전송 길이를 정의하지 않으므로 대상 장치의 데이터시트를 항상 확인하세요.<sup>[[1]](#references)</sup>

MOSI/COPI는 컨트롤러에서 주변 장치로 데이터를 전달하고, MISO/CIPO는 주변 장치에서 컨트롤러로 데이터를 전달합니다. 두 방향의 데이터는 동시에 시프트될 수 있습니다. 명령, 주소, 더미 사이클, 반환 데이터 간의 관계는 SPI가 아니라 주변 장치에 따라 정의되며, 클록 극성 및 위상(모드 0–3)에 따라 달라집니다. 입력이 끝난 후 정확히 한 클록 주기 뒤에 출력이 시작된다고 가정하지 마세요.<sup>[[1]](#references)</sup>

## EEPROM에서 펌웨어 덤프하기

펌웨어 덤프는 분석 및 취약점 탐색에 유용할 수 있습니다. 올바른 이미지가 온라인에 없거나 모델, 하드웨어 리비전 또는 버전에 따라 다를 수 있으므로, 실제 장치에서 직접 추출하면 정확한 평가 대상을 확보할 수 있습니다.

시리얼 콘솔이 도움이 될 수 있지만, 파일 시스템이 읽기 전용일 수 있고 대상 장치에 테스트 트래픽 송수신이나 바이너리 추출에 필요한 유틸리티를 비롯한 분석 도구가 없을 수도 있습니다. 오프라인 이미지를 사용하면 전체 플래시 레이아웃을 보존할 수 있으며, 실행 중인 대상을 수정하지 않고도 파일 시스템을 추출하고 리버스 엔지니어링할 수 있습니다.

승인된 물리적 평가 중에는 검증된 덤프를 사용해 통제된 수정 및 재플래싱 테스트를 수행할 수도 있습니다. 여기에는 펌웨어 수준의 지속성을 입증하기 위해 파일을 변경하거나 테스트 페이로드/백도어를 삽입하는 작업이 포함됩니다. 쓰기 작업을 하기 전에 일치하는 덤프를 여러 번 보존하고 원본 이미지를 저장하세요. 전압, 칩 선택, 레이아웃 또는 이미지가 잘못되면 장치가 벽돌이 될 수 있습니다.

### CH341A EEPROM 프로그래머 및 리더

이 저렴한 USB 도구는 호환되는 시리얼 EEPROM 및 SPI 플래시 장치를 덤프하고 재플래싱할 수 있습니다. PC BIOS/UEFI 펌웨어를 저장하는 SPI NOR 플래시 칩에 흔히 사용되며, 제한된 시간 동안의 물리적 접근 상황에서 편리합니다.

![drawing](../../images/board_image_ch341a.jpg)

플래시 메모리를 CH341A에 연결한 다음 프로그래머를 컴퓨터에 연결합니다. 프로그래머가 감지되지 않으면 대상 칩을 점검하기 전에 USB 케이블, OS 권한 및 적절한 CH341A 드라이버를 확인하세요. 데이터시트나 측정기를 사용해 칩의 전압, 1번 핀, 어댑터 배선 및 프로그래머 출력을 확인하세요. VCC를 USB 커넥터 반대쪽에 놓는 것과 같은 규칙에 **의존하지 마세요**. 방향이 잘못되거나 3.3/1.8 V 부품에 5 V를 공급하면 부품이 손상될 수 있습니다. 회로 내에서 읽을 경우 보드의 나머지 부분이 버스에 부하를 주거나 전원을 공급해 읽기에 실패할 수도 있습니다.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom` 또는 G-Flash와 같은 소프트웨어를 사용해 칩을 읽으세요. G-Flash는 최소한의 기능을 갖춘 GUI이며 호환 장치를 자동으로 감지할 수 있어 빠른 획득 작업에 편리하지만, 감지된 모델과 전압을 직접 확인해야 합니다. 정확한 프로그래머를 지정하고, 필요한 경우 정확한 칩 모델도 지정하세요. 덤프를 신뢰할 수 있다고 판단하기 전에 최소 두 번 읽고 해시를 비교하세요.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

펌웨어를 덤프한 후에는 바이너리 파일을 분석할 수 있습니다. strings, hexdump, xxd, binwalk 등의 도구를 사용하면 펌웨어와 전체 파일 시스템에 대한 많은 정보를 추출할 수 있습니다.

초기 분류를 위해 Binwalk로 알려진 시그니처를 스캔하고 지원되는 내장 콘텐츠를 추출할 수 있습니다:

```
binwalk -e <filename>
```

출력 파일은 `.bin`, `.rom` 또는 다른 확장자를 사용할 수 있습니다. 확장자만으로 파일 형식을 알 수는 없습니다.

> [!CAUTION]
> 펌웨어 추출은 섬세한 작업이며 많은 인내심이 필요합니다. 잘못 다루면 펌웨어가 손상되거나 완전히 지워져 장치를 사용할 수 없게 될 수 있습니다. 펌웨어 추출을 시도하기 전에 해당 장치에 대해 충분히 알아보는 것이 좋습니다.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

일부 데이터시트에서는 대상 핀을 `DI`와 `DO`로 표기합니다. 일반적인 단일 데이터 라인 flash 연결에서는 컨트롤러의 **MOSI/COPI를 DI에 연결하고**, 컨트롤러의 **MISO/CIPO를 DO에 연결합니다**. 듀얼/쿼드 I/O 부품은 다른 모드에서 핀을 재사용하므로 대상 데이터시트를 확인하세요.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Bus의 PINOUT에 SPI 연결용 MOSI 및 MISO 핀이 표시되어 있더라도 일부 SPI는...](<../../images/image (360).png>)

Windows 또는 Linux에서는 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용해 다음과 같은 명령으로 flash 메모리의 내용을 덤프할 수 있습니다:

```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```

최근 Bus Pirate 문서에는 선택적 `serialspeed` 및 `spispeed` 매개변수도 나와 있습니다. 긴 전선이나 회로 내 부하로 인해 읽기가 불안정해지는 경우, 보수적인 설정부터 시작하세요.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI 인터페이스 소개](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 매뉴얼 — CH341A SPI 프로그래머 및 읽기/쓰기 옵션](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 문서 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
