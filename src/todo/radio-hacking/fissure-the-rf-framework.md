# FISSURE - RF 프레임워크

{{#include ../../banners/hacktricks-training.md}}

**주파수 독립적인 SDR 기반 신호 이해 및 리버스 엔지니어링**

FISSURE는 모든 숙련도 수준을 대상으로 설계된 open-source RF 및 리버스 엔지니어링 프레임워크로, 신호 탐지 및 분류, 프로토콜 탐색, attack 실행, IQ 조작, 취약점 분석, 자동화, AI/ML을 위한 hooks를 제공합니다. 이 프레임워크는 software modules, radios, protocols, signal data, scripts, flow graphs, reference material 및 third-party tools를 신속하게 통합할 수 있도록 만들어졌습니다. FISSURE는 software를 한곳에 유지하고, 팀이 동일하게 검증된 특정 Linux distributions용 baseline configuration을 공유하면서 손쉽게 작업을 시작할 수 있도록 지원하는 workflow enabler입니다.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE에 포함된 프레임워크와 tools는 RF energy를 탐지하고, signals의 특성을 파악하며, samples를 수집 및 분석하고, transmit 또는 injection techniques를 개발하며, custom payloads 또는 messages를 제작하도록 설계되었습니다. 또한 FISSURE는 identification, packet crafting 및 fuzzing을 위한 protocol 및 signal information과 traffic simulation 및 testing을 위한 archives 및 playlists를 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Python codebase와 graphical interface는 초보자가 RF 및 리버스 엔지니어링 tools를 학습하는 데 도움을 줍니다. Educators는 내장된 lessons를 사용할 수 있으며, developers와 researchers는 자체 modules와 workflows를 통합할 수 있습니다. 현재 releases는 distributed sensor nodes, TAK integration, geolocation workflows 및 role-specific Apptainer deployments도 지원합니다.<sup>[[1]](#references)[[3]](#references)</sup>

**추가 정보**

* [AIS 페이지](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 시작하기

**지원됨**

현재 FISSURE는 PyQt5 및 GNU Radio 3.8 또는 3.10을 사용하는 active development용 **`Python3`** branch를 사용합니다. 더 이상 사용되지 않는 **`Python2_maint-3.7`** branch는 GNU Radio 3.7이 필요한 구형 operating systems 및 third-party tools를 위해 계속 제공됩니다. 이전의 `Python3_maint-3.8` 및 `Python3_maint-3.10` branch names는 historical names이며, GNU Radio maintenance selection은 이제 `Python3` branch에서 처리됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | 지원되는 Linux version 사용 | 일치하는 version 사용 |

**진행 중 (beta)**

이 operating systems는 아직 beta status입니다. 현재 개발 중이며 여러 features가 누락된 것으로 알려져 있습니다. status가 해제될 때까지 installer의 항목이 기존 programs와 충돌하거나 설치에 실패할 수 있습니다.

| Operating System | FISSURE Branch | Default GNU Radio branch |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

일부 third-party tools는 모든 OS에서 작동하지 않습니다. 설치하기 전에 최신 [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) documentation을 확인하세요.<sup>[[3]](#references)</sup>

**설치**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```
submodule 단계에서는 FISSURE에서 사용하는 GNU Radio out-of-tree modules를 다운로드하며, 해당 모듈을 설치할 때 필요합니다. 또한 installer는 설치 GUI를 실행하는 데 필요한 누락된 PyQt dependencies도 설치합니다.<sup>[[3]](#references)</sup>

다음으로 운영 체제에 가장 적합한 옵션을 선택합니다(OS가 옵션 중 하나와 일치하면 자동으로 감지됩니다).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

기존 충돌을 방지하려면 FISSURE를 깨끗한 운영 체제에 설치하는 것이 좋습니다. FISSURE 내의 다양한 도구를 사용할 때 오류가 발생하지 않도록 권장되는 모든 checkbox(Default button)를 선택합니다. 설치 과정에서는 여러 prompt가 표시되며, 대부분 elevated permissions와 사용자 이름을 요청합니다. 항목 끝에 "Verify" section이 포함되어 있으면 installer가 뒤따르는 command를 실행하고, 해당 command에서 오류가 발생했는지에 따라 checkbox 항목을 녹색 또는 빨간색으로 강조 표시합니다. "Verify" section이 없는 선택된 항목은 설치 후에도 검은색으로 유지됩니다.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**사용법**

terminal을 열고 다음을 입력합니다:
```
fissure
```
FISSURE Help 메뉴에서 사용법에 관한 자세한 내용을 확인하세요.

## Details

**Components**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**Capabilities**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**Hardware**

다음 Hardware는 FISSURE에 서로 다른 수준으로 통합되어 있습니다:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## Lessons

FISSURE에는 다양한 기술과 기법을 익히는 데 도움이 되는 여러 가이드가 포함되어 있습니다. 대부분의 가이드에는 FISSURE에 통합된 다양한 도구를 사용하는 단계가 포함되어 있습니다.

* [Lesson1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [Lesson2: Lua Dissectors](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [Lesson3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [Lesson4: ESP Boards](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [Lesson5: Radiosonde Tracking](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [Lesson6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [Lesson7: Data Types](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [Lesson8: Custom GNU Radio Blocks](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [Lesson9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [Lesson10: Ham Radio Exams](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [Lesson11: Wi-Fi Tools](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [Lesson12: Creating Bootable USBs](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [Lesson13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [Lesson14: Ceiling Fans](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## Roadmap

* [ ] 더 많은 Hardware 유형, RF 프로토콜, 신호 매개변수 및 분석 도구 추가
* [ ] 더 많은 운영 체제 지원
* [ ] FISSURE를 중심으로 수업 자료 개발(RF Attacks, Wi-Fi, GNU Radio, PyQt 등)
* [ ] 선택 가능한 AI/ML 기법을 사용하여 signal conditioner, feature extractor 및 signal classifier 생성
* [ ] 알려지지 않은 신호에서 bitstream을 생성하기 위한 recursive demodulation 메커니즘 구현
* [ ] 주요 FISSURE 구성 요소를 generic sensor node deployment scheme으로 전환

## Contributing

FISSURE를 개선하기 위한 제안은 적극적으로 환영합니다. 다음 항목에 관한 의견이 있다면 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 페이지 또는 Discord Server에 댓글을 남겨 주세요.

* 새로운 기능 제안 및 설계 변경
* 설치 단계가 포함된 Software tools
* 새로운 Lesson 또는 기존 Lesson을 위한 추가 자료
* 관심 있는 RF 프로토콜
* 통합을 위한 더 많은 Hardware 및 SDR 유형
* Python의 IQ analysis scripts
* 설치 수정 및 개선

FISSURE의 개선을 위한 Contributions는 개발을 앞당기는 데 매우 중요합니다. 여러분의 모든 Contributions를 감사하게 생각합니다. code development를 통해 기여하려면 repo를 fork하고 pull request를 생성하세요.

1. 프로젝트 fork
2. feature branch 생성 (`git checkout -b feature/AmazingFeature`)
3. 변경 사항 commit (`git commit -m 'Add some AmazingFeature'`)
4. branch에 push (`git push origin feature/AmazingFeature`)
5. pull request 생성

버그를 알리기 위한 [Issues](https://github.com/ainfosec/FISSURE/issues) 생성도 환영합니다.

## Collaborating

Assured Information Security, Inc. (AIS) Business Development에 연락하여 FISSURE collaboration 기회를 제안하고 공식화하세요. 여기에는 Software 통합을 위한 시간 할애, AIS의 숙련된 인력이 기술적 문제에 대한 solution을 개발하도록 하는 것, 또는 FISSURE를 다른 platforms/applications에 통합하는 것 등이 포함됩니다.

## License

GPL-3.0

License details는 LICENSE file을 참조하세요.

## Contact

Discord Server 참여: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter 팔로우: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## Credits

다음 developers에게 감사의 뜻을 전합니다.

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## Acknowledgments

이 프로젝트에 기여한 Dr. Samuel Mantravadi와 Joseph Reith에게 특별히 감사드립니다.

## References

- [1] [FISSURE - RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE documentation - Installation](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
