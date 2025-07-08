# FISSURE - The RF Framework

{{#include /banners/hacktricks-training.md}}

**주파수 독립 SDR 기반 신호 이해 및 역설계**

FISSURE는 신호 탐지 및 분류, 프로토콜 발견, 공격 실행, IQ 조작, 취약점 분석, 자동화 및 AI/ML을 위한 훅을 갖춘 모든 기술 수준을 위한 오픈 소스 RF 및 역설계 프레임워크입니다. 이 프레임워크는 소프트웨어 모듈, 라디오, 프로토콜, 신호 데이터, 스크립트, 흐름 그래프, 참조 자료 및 타사 도구의 신속한 통합을 촉진하기 위해 구축되었습니다. FISSURE는 소프트웨어를 한 곳에 유지하고 팀이 특정 Linux 배포판에 대한 동일한 검증된 기본 구성을 공유하면서 쉽게 작업을 시작할 수 있도록 하는 워크플로우 지원 도구입니다.

FISSURE에 포함된 프레임워크와 도구는 RF 에너지의 존재를 감지하고, 신호의 특성을 이해하며, 샘플을 수집하고 분석하고, 전송 및/또는 주입 기술을 개발하고, 사용자 정의 페이로드 또는 메시지를 제작하도록 설계되었습니다. FISSURE는 식별, 패킷 제작 및 퍼징을 지원하기 위해 프로토콜 및 신호 정보의 증가하는 라이브러리를 포함하고 있습니다. 신호 파일을 다운로드하고 트래픽을 시뮬레이션하고 시스템을 테스트하기 위한 재생 목록을 구축할 수 있는 온라인 아카이브 기능이 있습니다.

친숙한 Python 코드베이스와 사용자 인터페이스는 초보자가 RF 및 역설계와 관련된 인기 있는 도구와 기술에 대해 빠르게 배울 수 있도록 합니다. 사이버 보안 및 공학 교육자는 내장된 자료를 활용하거나 프레임워크를 사용하여 자신의 실제 응용 프로그램을 시연할 수 있습니다. 개발자와 연구자는 FISSURE를 일상 작업에 사용하거나 최첨단 솔루션을 더 넓은 청중에게 노출할 수 있습니다. FISSURE에 대한 인식과 사용이 커짐에 따라 그 기능의 범위와 포함하는 기술의 폭도 확장될 것입니다.

**추가 정보**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 시작하기

**지원되는 운영 체제**

FISSURE에는 파일 탐색을 쉽게 하고 코드 중복을 줄이기 위해 세 가지 브랜치가 있습니다. Python2\_maint-3.7 브랜치는 Python2, PyQt4 및 GNU Radio 3.7을 기반으로 구축된 코드베이스를 포함하고 있으며; Python3\_maint-3.8 브랜치는 Python3, PyQt5 및 GNU Radio 3.8을 기반으로 구축되었고; Python3\_maint-3.10 브랜치는 Python3, PyQt5 및 GNU Radio 3.10을 기반으로 구축되었습니다.

|   운영 체제   |   FISSURE 브랜치   |
| :-----------: | :----------------: |
|  Ubuntu 18.04 (x64)  | Python2\_maint-3.7 |
| Ubuntu 18.04.5 (x64) | Python2\_maint-3.7 |
| Ubuntu 18.04.6 (x64) | Python2\_maint-3.7 |
| Ubuntu 20.04.1 (x64) | Python3\_maint-3.8 |
| Ubuntu 20.04.4 (x64) | Python3\_maint-3.8 |
|  KDE neon 5.25 (x64) | Python3\_maint-3.8 |

**진행 중 (베타)**

이 운영 체제는 여전히 베타 상태입니다. 개발 중이며 여러 기능이 누락된 것으로 알려져 있습니다. 설치 프로그램의 항목이 기존 프로그램과 충돌하거나 상태가 제거될 때까지 설치에 실패할 수 있습니다.

|     운영 체제     |    FISSURE 브랜치   |
| :----------------: | :-----------------: |
| DragonOS Focal (x86\_64) |  Python3\_maint-3.8 |
|    Ubuntu 22.04 (x64)    | Python3\_maint-3.10 |

참고: 특정 소프트웨어 도구는 모든 OS에서 작동하지 않습니다. [Software And Conflicts](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Help/Markdown/SoftwareAndConflicts.md)를 참조하십시오.

**설치**
```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout <Python2_maint-3.7> or <Python3_maint-3.8> or <Python3_maint-3.10>
git submodule update --init
./install
```
이것은 설치 GUI를 시작하는 데 필요한 PyQt 소프트웨어 종속성을 설치합니다. 종속성이 발견되지 않으면 설치가 진행되지 않습니다.

다음으로, 운영 체제에 가장 적합한 옵션을 선택하십시오 (운영 체제가 옵션과 일치하면 자동으로 감지되어야 합니다).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

기존의 충돌을 피하기 위해 깨끗한 운영 체제에 FISSURE를 설치하는 것이 권장됩니다. FISSURE 내의 다양한 도구를 운영하는 동안 오류를 피하기 위해 모든 권장 체크박스를 선택하십시오 (기본 버튼). 설치 과정에서 여러 번의 프롬프트가 표시되며, 대부분은 상승된 권한과 사용자 이름을 요청합니다. 항목 끝에 "Verify" 섹션이 포함된 경우, 설치 관리자는 그 뒤에 오는 명령을 실행하고 명령에 의해 오류가 발생하는지에 따라 체크박스 항목을 초록색 또는 빨간색으로 강조 표시합니다. "Verify" 섹션이 없는 체크된 항목은 설치 후 검은색으로 유지됩니다.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**사용법**

터미널을 열고 입력하십시오:
```
fissure
```
FISSURE 사용에 대한 자세한 내용은 도움말 메뉴를 참조하십시오.

## 세부정보

**구성 요소**

* 대시보드
* 중앙 허브 (HIPRFISR)
* 목표 신호 식별 (TSI)
* 프로토콜 발견 (PD)
* 흐름 그래프 및 스크립트 실행기 (FGE)

![components](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**기능**

| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**신호 탐지기**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ 조작**_      | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**신호 조회**_          | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**패턴 인식**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**공격**_           | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**퍼징**_         | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**신호 재생 목록**_       | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**이미지 갤러리**_  |
| ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**패킷 제작**_   | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy 통합**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC 계산기**_ | ![](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**로깅**_            |

**하드웨어**

다음은 다양한 통합 수준을 가진 "지원되는" 하드웨어 목록입니다:

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx
* HackRF
* RTL2832U
* 802.11 어댑터
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR

## 교훈

FISSURE는 다양한 기술과 기법에 익숙해지기 위한 여러 유용한 가이드를 제공합니다. 많은 가이드에는 FISSURE에 통합된 다양한 도구를 사용하는 단계가 포함되어 있습니다.

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

* [ ] 더 많은 하드웨어 유형, RF 프로토콜, 신호 매개변수, 분석 도구 추가
* [ ] 더 많은 운영 체제 지원
* [ ] FISSURE에 대한 수업 자료 개발 (RF 공격, Wi-Fi, GNU Radio, PyQt 등)
* [ ] 선택 가능한 AI/ML 기술을 갖춘 신호 조정기, 특징 추출기 및 신호 분류기 생성
* [ ] 알려지지 않은 신호에서 비트스트림을 생성하기 위한 재귀 변조 메커니즘 구현
* [ ] 주요 FISSURE 구성 요소를 일반 센서 노드 배포 계획으로 전환

## 기여

FISSURE 개선을 위한 제안은 적극 권장됩니다. 다음 사항에 대한 의견이 있으시면 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 페이지나 Discord 서버에 댓글을 남겨주세요:

* 새로운 기능 제안 및 디자인 변경
* 설치 단계가 포함된 소프트웨어 도구
* 새로운 교훈 또는 기존 교훈에 대한 추가 자료
* 관심 있는 RF 프로토콜
* 통합을 위한 더 많은 하드웨어 및 SDR 유형
* Python의 IQ 분석 스크립트
* 설치 수정 및 개선

FISSURE 개선을 위한 기여는 개발을 가속화하는 데 중요합니다. 여러분의 기여는 매우 감사하게 생각합니다. 코드 개발을 통해 기여하고 싶으시면, 레포를 포크하고 풀 리퀘스트를 생성해 주세요:

1. 프로젝트 포크
2. 기능 브랜치 생성 (`git checkout -b feature/AmazingFeature`)
3. 변경 사항 커밋 (`git commit -m 'Add some AmazingFeature'`)
4. 브랜치에 푸시 (`git push origin feature/AmazingFeature`)
5. 풀 리퀘스트 열기

버그에 대한 주의를 환기시키기 위해 [Issues](https://github.com/ainfosec/FISSURE/issues)를 생성하는 것도 환영합니다.

## 협업

Assured Information Security, Inc. (AIS) 비즈니스 개발에 연락하여 FISSURE 협업 기회를 제안하고 공식화하세요. 소프트웨어 통합을 위한 시간 할애, AIS의 재능 있는 인력이 기술적 문제를 위한 솔루션을 개발하는 것, 또는 FISSURE를 다른 플랫폼/응용 프로그램에 통합하는 것 등이 포함됩니다.

## 라이센스

GPL-3.0

라이센스 세부정보는 LICENSE 파일을 참조하십시오.

## 연락처

Discord 서버에 참여하세요: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter에서 팔로우하세요: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

비즈니스 개발 - Assured Information Security, Inc. - bd@ainfosec.com

## 크레딧

다음 개발자들에게 감사드립니다:

[Credits](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 감사의 말

이 프로젝트에 기여한 Dr. Samuel Mantravadi와 Joseph Reith에게 특별히 감사드립니다.



{{#include /banners/hacktricks-training.md}}
