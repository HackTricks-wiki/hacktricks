# SPI

{{#include ../../banners/hacktricks-training.md}}

## 기본 정보

SPI (Serial Peripheral Interface)는 임베디드 시스템에서 IC (Integrated Circuits) 간 단거리 통신에 사용되는 Synchronous Serial Communication Protocol입니다. SPI Communication Protocol은 Clock 및 Chip Select Signal에 의해 조정되는 master-slave architecture를 사용합니다. master-slave architecture는 EEPROM, 센서, 제어 장치 등 외부 주변 장치를 관리하는 master (일반적으로 microprocessor)와 slave로 간주되는 이러한 장치들로 구성됩니다.

여러 slave를 하나의 master에 연결할 수 있지만, slave끼리는 서로 통신할 수 없습니다. Slave는 clock과 chip select라는 두 개의 핀으로 관리됩니다. SPI는 synchronous communication protocol이므로 input 및 output 핀은 clock signal을 따릅니다. Chip select는 master가 slave를 선택하고 상호작용하는 데 사용됩니다. Chip select가 high이면 slave device가 선택되지 않은 상태이며, low이면 chip이 선택된 상태이고 master가 slave와 상호작용합니다.

MOSI (Master Out, Slave In)와 MISO (Master In, Slave Out)는 데이터 전송 및 수신을 담당합니다. Chip select가 low로 유지되는 동안 MOSI 핀을 통해 slave device로 데이터가 전송됩니다. Input data에는 slave device vendor의 datasheet에 따른 instruction, memory address 또는 data가 포함됩니다. 유효한 input이 수신되면 MISO 핀이 master로 데이터를 전송합니다. Output data는 input이 끝난 바로 다음 clock cycle에 정확히 전송됩니다. MISO 핀은 데이터가 완전히 전송되거나 master가 chip select 핀을 high로 설정할 때까지 데이터를 전송합니다. 후자의 경우 slave는 전송을 중지하며, master는 해당 clock cycle 이후의 데이터를 수신하지 않습니다.

## EEPROM에서 Firmware Dumping

Firmware dumping은 firmware를 분석하고 취약점을 찾는 데 유용할 수 있습니다. Firmware가 인터넷에 제공되지 않거나 model number, version 등의 요인에 따른 변형으로 인해 관련성이 없는 경우가 많습니다. 따라서 physical device에서 직접 firmware를 추출하면 threat hunting 시 특정 장치에 맞춰 분석하는 데 도움이 될 수 있습니다.

Serial Console을 확보하는 것이 도움이 될 수 있지만, 파일이 read-only인 경우가 많습니다. 이는 여러 이유로 분석을 제한합니다. 예를 들어, package를 전송하고 수신하는 데 필요한 tool이 firmware에 존재하지 않을 수 있습니다. 따라서 binary를 추출해 reverse engineer하는 것은 실행하기 어렵습니다. 그러므로 전체 firmware를 system에 dump하고 분석을 위해 binary를 추출할 수 있다면 매우 유용합니다.

또한 red teaming 및 device에 대한 physical access를 확보하는 과정에서 firmware dumping을 통해 파일을 수정하거나 malicious file을 주입한 후 memory에 다시 reflash할 수 있습니다. 이는 device에 backdoor를 implant하는 데 도움이 될 수 있습니다. 따라서 firmware dumping으로 다양한 가능성을 활용할 수 있습니다.

### CH341A EEPROM Programmer and Reader

이 device는 EEPROM에서 firmware를 dump하고 firmware file로 다시 reflash할 수 있는 저렴한 tool입니다. 컴퓨터 BIOS chip (단순한 EEPROM임)을 다루는 데 널리 사용되어 왔습니다. 이 device는 USB를 통해 연결되며 시작하는 데 필요한 tool이 거의 없습니다. 또한 일반적으로 작업을 빠르게 완료하므로 physical device access 상황에서도 유용할 수 있습니다.

![drawing](../../images/board_image_ch341a.jpg)

EEPROM memory를 CH341a Programmer에 연결하고 device를 computer에 연결합니다. Device가 감지되지 않으면 computer에 driver를 설치해 보세요. 또한 EEPROM이 올바른 방향으로 연결되어 있는지 확인하세요. 일반적으로 VCC Pin을 USB connector와 반대 방향으로 배치합니다. 그렇지 않으면 software가 chip을 감지하지 못합니다. 필요한 경우 diagram을 참조하세요.

![drawing](../../images/connect_wires_ch341a.jpg) ![drawing](../../images/eeprom_plugged_ch341a.jpg)

마지막으로 flashrom, G-Flash (GUI) 등의 software를 사용해 firmware를 dump합니다. G-Flash는 빠르게 동작하는 minimal GUI tool이며 EEPROM을 자동으로 감지합니다. Documentation을 많이 확인하지 않고 firmware를 신속하게 추출해야 할 때 유용할 수 있습니다.

![drawing](../../images/connected_status_ch341a.jpg)

Firmware를 dump한 후 binary file을 분석할 수 있습니다. strings, hexdump, xxd, binwalk 등의 tool을 사용하면 firmware와 전체 file system에서 많은 정보를 추출할 수 있습니다.

Firmware의 contents를 추출하려면 binwalk를 사용할 수 있습니다. Binwalk는 hex signature를 분석하고 binary file에서 file을 식별하며 이를 추출할 수 있습니다.
```
binwalk -e <filename>
```
도구와 구성에 따라 `.bin` 또는 `.rom`일 수 있습니다.

> [!CAUTION]
> firmware extraction은 섬세한 작업이며 많은 인내심이 필요합니다. 잘못 다루면 firmware가 손상되거나 완전히 지워져 장치를 사용할 수 없게 될 수 있습니다. firmware를 추출하기 전에 해당 장치를 충분히 조사하는 것이 좋습니다.

### Bus Pirate + flashrom

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Bus Pirate + flashrom](<../../images/image (910).png>)

Pirate Bus의 PINOUT에 SPI 연결을 위한 **MOSI** 및 **MISO** 핀이 표시되어 있더라도 일부 SPI는 핀을 DI 및 DO로 표시할 수 있습니다. **MOSI -> DI, MISO -> DO**

![CH341A EEPROM Programmer and Reader - Bus Pirate + flashrom: Note that even if the PINOUT of the Pirate Bus indicates pins for MOSI and MISO to connect to SPI however some SPIs may...](<../../images/image (360).png>)

Windows 또는 Linux에서는 [**`flashrom`**](https://www.flashrom.org/Flashrom) 프로그램을 사용하여 다음과 같은 명령을 실행해 flash memory의 내용을 dump할 수 있습니다:
```bash
# In this command we are indicating:
# -VV Verbose
# -c <chip> The chip (if you know it better, if not, don'tindicate it and the program might be able to find it)
# -p <programmer> In this case how to contact th chip via the Bus Pirate
# -r <file> Image to save in the filesystem
flashrom -VV -c "W25Q64.V" -p buspirate_spi:dev=COM3 -r flash_content.img
```
{{#include ../../banners/hacktricks-training.md}}
