# FISSURE - The RF Framework

{{#include ../../banners/hacktricks-training.md}}

**Frequency Independent SDR-based Signal Understanding and Reverse Engineering**

FISSURE는 모든 숙련도 수준을 대상으로 설계된 open-source RF 및 reverse engineering framework로, signal detection 및 classification, protocol discovery, attack execution, IQ manipulation, vulnerability analysis, automation, AI/ML을 위한 hooks를 제공합니다. 이 framework는 software modules, radios, protocols, signal data, scripts, flow graphs, reference material 및 third-party tools를 신속하게 통합할 수 있도록 구축되었습니다. FISSURE는 software를 한곳에 유지하고, 팀이 특정 Linux distributions에 대해 검증된 동일한 baseline configuration을 공유하면서 빠르게 적응할 수 있도록 지원하는 workflow enabler입니다.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE에 포함된 framework와 tools는 RF energy의 존재를 감지하고, signal의 특성을 파악하며, samples를 수집 및 분석하고, transmit 및/또는 injection techniques를 개발하며, custom payloads 또는 messages를 제작하도록 설계되었습니다. FISSURE에는 identification, packet crafting 및 fuzzing을 지원하기 위해 protocol 및 signal 정보가 계속해서 추가되는 library가 포함되어 있습니다. Online archive 기능을 통해 signal files를 다운로드하고, traffic을 시뮬레이션하며 systems를 테스트하기 위한 playlists를 생성할 수 있습니다.

친숙한 Python codebase와 user interface를 통해 beginners도 RF 및 reverse engineering과 관련된 인기 있는 tools와 techniques를 빠르게 익힐 수 있습니다. Cybersecurity 및 engineering 교육자는 내장된 material을 활용하거나 framework를 사용하여 실제 applications를 시연할 수 있습니다. Developers와 researchers는 FISSURE를 일상적인 tasks에 사용하거나, cutting-edge solutions를 더 많은 사용자에게 공개할 수 있습니다. 커뮤니티에서 FISSURE에 대한 인지도와 사용량이 증가함에 따라 capabilities의 범위와 포함하는 technology의 폭도 확장될 것입니다.

**Additional Information**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## Getting Started

**Supported**

FISSURE에는 file navigation을 간소화하고 code redundancy를 줄이기 위해 세 개의 branches가 있습니다. Python2\_maint-3.7 branch는 Python2, PyQt4 및 GNU Radio 3.7을 기반으로 구축된 codebase를 포함하며, Python3\_maint-3.8 branch는 Python3, PyQt5 및 GNU Radio 3.8을 기반으로 구축되었습니다. Python3\_maint-3.10 branch는 Python3, PyQt5 및 GNU Radio 3.10을 기반으로 구축되었습니다.

|   Operating System   |   FISSURE Branch   |
| :------------------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**In-Progress (beta)**

이 operating systems는 아직 beta 상태입니다. 현재 개발 중이며, 여러 features가 누락된 것으로 알려져 있습니다. installer의 항목이 기존 programs와 충돌하거나, 해당 상태가 제거될 때까지 설치에 실패할 수 있습니다.

|     Operating System     |    FISSURE Branch   |
| :----------------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

참고: 일부 software tools는 모든 OS에서 작동하지 않습니다. [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)를 참조하십시오.

**Installation**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
설치 GUI를 실행하는 데 필요한 PyQt 소프트웨어 dependencies가 발견되지 않은 경우 이를 설치합니다.

그다음 사용 중인 운영 체제에 가장 잘 맞는 옵션을 선택합니다(운영 체제가 해당 옵션과 일치하면 자동으로 감지됩니다).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

기존 충돌을 방지하려면 깨끗한 운영 체제에 FISSURE를 설치하는 것이 좋습니다. FISSURE 내의 다양한 도구를 사용하는 동안 오류가 발생하지 않도록 권장되는 모든 체크박스를 선택합니다(Default 버튼). 설치 과정에서 여러 프롬프트가 표시되며, 대부분 elevated permissions 및 사용자 이름을 요청합니다. 항목 끝에 "Verify" 섹션이 있으면 installer가 그 뒤에 나오는 command를 실행하고, command에서 오류가 발생했는지에 따라 해당 체크박스 항목을 녹색 또는 빨간색으로 강조 표시합니다. "Verify" 섹션이 없는 선택된 항목은 설치 후에도 검은색으로 유지됩니다.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**사용법**

터미널을 열고 다음을 입력합니다:
```
fissure
```
자세한 사용법은 FISSURE Help 메뉴를 참조하세요.

## 세부 정보

**구성 요소**

* Dashboard
* Central Hub (HIPRFISR)
* Target Signal Identification (TSI)
* Protocol Discovery (PD)
* Flow Graph & Script Executor (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**기능**

| ![Signal Detector icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**Signal Detector**_ | ![IQ Manipulation icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ Manipulation**_      | ![Signal Lookup icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**Signal Lookup**_          | ![Pattern Recognition icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**Pattern Recognition**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![Attacks icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**Attacks**_           | ![Fuzzing icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**Fuzzing**_         | ![Signal Playlists icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**Signal Playlists**_       | ![Image Gallery icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**Image Gallery**_  |
| ![Packet Crafting icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**Packet Crafting**_   | ![Scapy Integration icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy Integration**_ | ![CRC Calculator icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC Calculator**_ | ![Logging icon](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**Logging**_            |

**하드웨어**

다음은 통합 수준이 서로 다른 "지원되는" 하드웨어 목록입니다.

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 Adapters
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 레슨

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

## 로드맵

* [ ] 더 많은 하드웨어 유형, RF 프로토콜, 신호 매개변수 및 분석 도구 추가
* [ ] 더 많은 운영 체제 지원
* [ ] FISSURE를 중심으로 한 강의 자료 개발 (RF Attacks, Wi-Fi, GNU Radio, PyQt 등)
* [ ] 선택 가능한 AI/ML 기법을 사용하여 signal conditioner, feature extractor 및 signal classifier 생성
* [ ] 알려지지 않은 신호에서 bitstream을 생성하기 위한 recursive demodulation 메커니즘 구현
* [ ] 주요 FISSURE 구성 요소를 generic sensor node deployment scheme으로 전환

## 기여

FISSURE 개선을 위한 제안은 언제나 환영합니다. 다음과 관련된 의견이 있다면 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 페이지 또는 Discord Server에 댓글을 남겨 주세요.

* 새로운 기능 제안 및 설계 변경
* 설치 단계가 포함된 소프트웨어 도구
* 새로운 레슨 또는 기존 레슨을 위한 추가 자료
* 관심 있는 RF 프로토콜
* 통합을 위한 더 많은 하드웨어 및 SDR 유형
* Python의 IQ analysis scripts
* 설치 수정 및 개선

FISSURE의 개발을 가속화하려면 기여가 매우 중요합니다. 여러분의 모든 기여에 감사드립니다. 코드 개발을 통해 기여하려면 repo를 fork하고 pull request를 생성하세요.

1. 프로젝트 fork
2. feature branch 생성 (`git checkout -b feature/AmazingFeature`)
3. 변경 사항 commit (`git commit -m 'Add some AmazingFeature'`)
4. branch에 push (`git push origin feature/AmazingFeature`)
5. pull request 열기

버그에 대한 관심을 환기하기 위한 [Issues](https://github.com/ainfosec/FISSURE/issues) 생성도 환영합니다.

## 협업

Assured Information Security, Inc. (AIS) Business Development에 연락하여 FISSURE 협업 기회를 제안하고 공식화할 수 있습니다. 협업 방식은 소프트웨어 통합에 시간을 할애하는 것, AIS의 유능한 인력이 기술적 문제에 대한 솔루션을 개발하도록 하는 것, 또는 FISSURE를 다른 플랫폼/애플리케이션에 통합하는 것 등이 될 수 있습니다.

## 라이선스

GPL-3.0

라이선스 세부 정보는 LICENSE 파일을 참조하세요.

## 연락처

Discord Server 참여: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter 팔로우: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## 크레딧

다음 개발자들에게 감사의 뜻을 전합니다.

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 감사의 말

이 프로젝트에 기여해 주신 Dr. Samuel Mantravadi와 Joseph Reith에게 특별히 감사드립니다.

## 참고 자료

- [1] [FISSURE - The RF Framework (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE Paper (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)

{{#include ../../banners/hacktricks-training.md}}
