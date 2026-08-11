# SPI

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

SPI(Serial Peripheral Interface)는 집적 회로 간 단거리 통신에 일반적으로 사용되는 동기식 serial bus입니다. controller는 clock을 공급하고 chip-select signal을 사용해 EEPROM, sensor 또는 control device와 같은 peripheral을 선택합니다.<sup>[[1]](#references)</sup>

여러 peripheral이 clock 및 data line을 공유할 수 있으며, 일반적으로 각 peripheral마다 별도의 chip-select가 사용됩니다. controller가 transfer를 조정하며, peripheral은 일반적으로 SPI bus를 통해 서로 직접 통신하지 않습니다. Chip-select polarity와 timing은 device마다 다르며, active-low selection이 일반적이지만 항상 그런 것은 아닙니다. SPI는 discovery, addressing, commands 또는 하나의 고정된 maximum transfer length를 정의하지 않으므로, 항상 대상 datasheet를 참조해야 합니다.<sup>[[1]](#references)</sup>

MOSI/COPI는 controller에서 peripheral로 향하는 data를 전달하고, MISO/CIPO는 peripheral에서 controller로 향하는 data를 전달합니다. 양방향은 동시에 shift될 수 있습니다. command, address, dummy cycles 및 반환되는 data 간의 관계는 SPI가 아니라 peripheral에 의해 정의되며, clock polarity와 phase(modes 0–3)에 따라 달라집니다. output이 input 종료 후 정확히 한 clock 뒤에 시작한다고 가정하지 마십시오.<sup>[[1]](#references)</sup>

## EEPROM에서 Firmware Dump하기

Firmware를 dump하면 이를 분석하고 vulnerability를 찾는 데 유용합니다. 올바른 image를 온라인에서 구할 수 없거나 model, hardware revision 또는 version에 따라 다를 수 있으므로, physical device에서 직접 추출하면 정확한 assessment target을 확보할 수 있습니다.

Serial console이 도움이 될 수 있지만, 해당 filesystem이 read-only일 수 있고 target에 test traffic을 송수신하거나 binary를 편리하게 추출하는 데 필요한 utility를 비롯한 analysis tool이 없을 수 있습니다. Offline image를 사용하면 전체 flash layout을 보존하고 실행 중인 target을 수정하지 않고 filesystem extraction 및 reverse engineering을 수행할 수 있습니다.

승인된 physical assessment 중에는 검증된 dump를 사용해 controlled modification 및 reflashing test를 지원할 수도 있습니다. 여기에는 firmware-level persistence를 입증하기 위해 file을 변경하거나 test payload/backdoor를 주입하는 작업이 포함됩니다. write를 수행하기 전에 서로 일치하는 read 결과를 여러 개 보존하고 original image를 저장하십시오. 잘못된 voltage, chip selection, layout 또는 image는 device를 brick할 수 있습니다.

### CH341A EEPROM Programmer 및 Reader

이 저렴한 USB tool은 호환되는 serial EEPROM 및 SPI flash device를 dump하고 reflash할 수 있습니다. PC BIOS/UEFI firmware를 저장하는 SPI NOR flash chip과 함께 흔히 사용되며, 시간이 제한된 physical access 상황에서 편리합니다.

![drawing](../../images/board_image_ch341a.jpg)

Flash memory를 CH341A에 연결한 다음 programmer를 computer에 연결합니다. Programmer 자체가 감지되지 않으면 target chip을 troubleshooting하기 전에 USB cable, OS permission 및 적절한 CH341A driver를 확인하십시오. Datasheet 또는 meter를 사용해 chip의 voltage, pin 1, adapter wiring 및 programmer output을 확인하십시오. USB connector의 반대편에 VCC를 배치하는 것과 같은 규칙에 **의존하지 마십시오**. 잘못된 orientation 또는 3.3/1.8 V 부품에 5 V를 인가하면 부품이 손상될 수 있습니다. In-circuit read는 나머지 board가 bus를 load하거나 power를 공급하기 때문에 실패할 수도 있습니다.<sup>[[2]](#references)</sup>

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

`flashrom` 또는 G-Flash와 같은 software를 사용해 chip을 read합니다. G-Flash는 최소한의 GUI이며 호환되는 device를 자동으로 감지할 수 있어 빠른 acquisition 중 편리할 수 있지만, 감지된 model과 voltage는 직접 확인하십시오. 정확한 programmer를 지정하고, 필요한 경우 정확한 chip model도 지정하십시오. Dump를 신뢰할 수 있는 것으로 간주하기 전에 최소 두 번 read하고 hash를 비교하십시오.<sup>[[2]](#references)</sup>

![drawing](../../images/connected_status_ch341a.jpg)

Firmware를 dump한 후에는 binary file에서 analysis를 수행할 수 있습니다. strings, hexdump, xxd, binwalk 등의 tool을 사용하면 firmware와 전체 filesystem에 관한 많은 정보를 추출할 수 있습니다.

Initial triage를 위해 Binwalk는 알려진 signature를 scan하고 지원되는 embedded content를 extract할 수 있습니다:
```
binwalk -e <filename>
```
출력 파일은 `.bin`, `.rom` 또는 다른 확장자를 사용할 수 있으며, 확장자가 형식을 결정하지는 않습니다.

> [!CAUTION]
> firmware 추출은 섬세한 과정이며 많은 인내심이 필요합니다. 잘못 취급하면 firmware가 손상되거나 완전히 지워져 장치를 사용할 수 없게 될 수 있습니다. firmware 추출을 시도하기 전에 해당 장치를 먼저 연구하는 것이 좋습니다.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

일부 datasheet에서는 대상 핀을 `DI` 및 `DO`로 표시합니다. 일반적인 단일 데이터 라인 flash 연결에서는 controller의 **MOSI/COPI가 DI에 연결되고**, controller의 **MISO/CIPO가 DO에 연결됩니다**. dual/quad I/O 부품은 다른 mode에서 핀을 재사용하므로 대상 datasheet를 확인하십시오.

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Pirate Bus의 PINOUT에 MOSI 및 MISO를 SPI에 연결하기 위한 핀이 표시되어 있더라도 일부 SPI는...](<../../images/image (360).png>)

Windows 또는 Linux에서는 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용하여 다음과 같은 명령으로 flash memory의 내용을 dump할 수 있습니다:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> Exact chip model (omit it to let flashrom probe candidates)
# -p <programmer> Programmer configuration; here, the Bus Pirate connection
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
최근 Bus Pirate 문서에는 선택적 `serialspeed` 및 `spispeed` 매개변수도 나와 있습니다. 긴 전선이나 회로 내 로딩으로 인해 read가 불안정해지는 경우에는 보수적으로 시작하세요.<sup>[[3]](#references)</sup>

## References

- [1] [Analog Devices — SPI 인터페이스 소개](https://www.analog.com/en/resources/analog-dialogue/articles/introduction-to-spi-interface.html)
- [2] [flashrom 매뉴얼 — CH341A SPI programmer 및 read/write 옵션](https://flashrom.org/classic_cli_manpage.html)
- [3] [Bus Pirate 문서 — flashrom](https://docs.buspirate.com/docs/software/flashrom/)
{{#include ../../banners/hacktricks-training.md}}
