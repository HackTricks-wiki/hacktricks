# FISSURE - RF 프레임워크

{{#include ../../banners/hacktricks-training.md}}

**주파수 비의존 SDR 기반 신호 이해 및 리버스 엔지니어링**

FISSURE는 모든 기술 수준의 사용자를 위해 설계된 오픈 소스 RF 및 리버스 엔지니어링 프레임워크로, 신호 탐지 및 분류, 프로토콜 탐색, 공격 실행, IQ 조작, 취약점 분석, 자동화, AI/ML을 위한 기능을 제공합니다. 이 프레임워크는 소프트웨어 모듈, 라디오, 프로토콜, 신호 데이터, 스크립트, 플로 그래프, 참조 자료 및 타사 도구를 신속하게 통합할 수 있도록 만들어졌습니다. FISSURE는 소프트웨어를 한곳에 모아 워크플로를 지원하며, 팀이 특정 Linux 배포판에 대해 검증된 동일한 기본 구성을 공유하면서 손쉽게 작업을 시작할 수 있도록 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

FISSURE에 포함된 프레임워크와 도구는 RF 에너지를 탐지하고, 신호 특성을 분석하고, 샘플을 수집 및 분석하고, 송신 또는 인젝션 기법을 개발하고, 사용자 지정 페이로드나 메시지를 제작하도록 설계되었습니다. 또한 FISSURE는 식별, 패킷 제작 및 fuzzing에 필요한 프로토콜 및 신호 정보를 제공하며, 트래픽 시뮬레이션 및 테스트를 위한 아카이브와 재생 목록도 제공합니다.<sup>[[1]](#references)[[2]](#references)</sup>

Python 코드베이스와 그래픽 인터페이스는 초보자가 RF 및 리버스 엔지니어링 도구를 익히는 데 도움을 줍니다. 교육자는 내장된 강의를 활용할 수 있고, 개발자와 연구자는 자신의 모듈과 워크플로를 통합할 수 있습니다. 최신 릴리스는 분산 센서 노드, TAK 통합, 지리 위치 워크플로 및 역할별 Apptainer 배포도 지원합니다.<sup>[[1]](#references)[[3]](#references)</sup>

**추가 정보**

* [AIS Page](https://www.ainfosec.com/technologies/fissure/)
* [GRCon22 Slides](https://events.gnuradio.org/event/18/contributions/246/attachments/84/164/FISSURE\_Poore\_GRCon22.pdf)
* [GRCon22 Paper](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE\_Paper\_Poore\_GRCon22.pdf)
* [GRCon22 Video](https://www.youtube.com/watch?v=1f2umEKhJvE)
* [Hack Chat Transcript](https://hackaday.io/event/187076-rf-hacking-hack-chat/log/212136-hack-chat-transcript-part-1)

## 시작하기

**지원**

현재 FISSURE는 PyQt5 및 GNU Radio 3.8 또는 3.10을 사용하는 **`Python3`** 브랜치에서 활발히 개발되고 있습니다. 더 이상 사용되지 않는 **`Python2_maint-3.7`** 브랜치는 GNU Radio 3.7이 필요한 구형 운영 체제 및 타사 도구를 위해 계속 제공됩니다. 이전의 `Python3_maint-3.8` 및 `Python3_maint-3.10` 브랜치 이름은 과거에 사용된 이름이며, 이제 GNU Radio 유지보수 버전 선택은 `Python3` 브랜치에서 처리됩니다.<sup>[[1]](#references)[[3]](#references)</sup>

| 운영 체제 | FISSURE 브랜치 | 기본 GNU Radio 브랜치 |
| :--: | :--: | :--: |
| DragonOS Noble (24.04) | Python3 | maint-3.10 |
| Kali | Python3 | maint-3.10 |
| Raspberry Pi OS | Python3 | maint-3.10 |
| Ubuntu 18.04 | Python2\_maint-3.7 | maint-3.7 |
| Ubuntu 20.04 | Python3 | maint-3.8 |
| Ubuntu 22.04 | Python3 | maint-3.10 |
| Ubuntu 24.04 / Ubuntu ARM | Python3 | maint-3.10 |
| Windows 11 WSL2 | 지원되는 Linux 버전 사용 | 해당 버전에 맞는 버전 사용 |

**개발 중 (베타)**

이 운영 체제는 아직 베타 상태입니다. 개발 중이며 일부 기능이 누락된 것으로 알려져 있습니다. 설치 프로그램의 항목이 기존 프로그램과 충돌하거나, 베타 상태가 해제될 때까지 설치되지 않을 수 있습니다.

| 운영 체제 | FISSURE 브랜치 | 기본 GNU Radio 브랜치 |
| :--: | :--: | :--: |
| BackBox Linux | Python3 | maint-3.10 |
| KDE neon | Python3 | maint-3.10 |
| Parrot Security 6.1 | Python3 | maint-3.10 |

일부 타사 도구는 모든 OS에서 작동하지 않습니다. 설치하기 전에 최신 [Known Conflicts and Third-Party Software](https://fissure.readthedocs.io/en/latest/pages/installation.html#known-conflicts) 문서를 확인하세요.<sup>[[3]](#references)</sup>

**설치**

```
git clone https://github.com/ainfosec/FISSURE.git
cd FISSURE
git checkout Python3  # optional; use Python2_maint-3.7 only for legacy requirements
git submodule update --init
./install
```

하위 모듈 단계에서는 FISSURE에서 사용하는 GNU Radio out-of-tree 모듈을 다운로드하며, 해당 모듈을 설치할 때 필요합니다. 설치 프로그램은 설치 GUI를 실행하는 데 필요한 PyQt 종속성이 누락된 경우에도 설치합니다.<sup>[[3]](#references)</sup>

다음으로 운영 체제에 가장 적합한 옵션을 선택합니다(운영 체제가 옵션 중 하나와 일치하면 자동으로 감지됩니다).

|                                          Python2\_maint-3.7                                          |                                          Python3\_maint-3.8                                          |                                          Python3\_maint-3.10                                         |
| :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------: |
| ![install1b](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1b.png) | ![install1a](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1a.png) | ![install1c](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install1c.png) |

기존 충돌을 방지하려면 깨끗한 운영 체제에 FISSURE를 설치하는 것이 좋습니다. FISSURE의 여러 도구를 사용하는 동안 오류가 발생하지 않도록 권장 체크박스를 모두 선택합니다(Default 버튼). 설치 중에는 여러 번 메시지가 표시되며, 대부분 상승된 권한과 사용자 이름을 묻습니다. 항목 끝에 "Verify" 섹션이 있으면 설치 프로그램이 그 뒤에 나오는 명령을 실행하고, 명령에서 오류가 발생했는지에 따라 해당 체크박스 항목을 녹색 또는 빨간색으로 강조 표시합니다. "Verify" 섹션이 없는 체크된 항목은 설치가 끝난 후에도 검은색으로 표시됩니다.

![install2](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/install2.png)

**사용법**

터미널을 열고 다음을 입력합니다:

```
fissure
```

FISSURE 사용에 대한 자세한 내용은 Help 메뉴를 참조하세요.

## 세부 정보

**구성 요소**

* 대시보드
* Central Hub (HIPRFISR)
* 표적 신호 식별 (TSI)
* 프로토콜 탐색 (PD)
* Flow Graph 및 스크립트 실행기 (FGE)

![구성 요소](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/components.png)

**기능**

| ![신호 감지기 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/detector.png)_**신호 감지기**_ | ![IQ 조작 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/iq.png)_**IQ 조작**_      | ![신호 검색 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/library.png)_**신호 검색**_          | ![패턴 인식 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/pd.png)_**패턴 인식**_ |
| --------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| ![공격 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/attack.png)_**공격**_           | ![퍼징 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/fuzzing.png)_**퍼징**_         | ![신호 재생 목록 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/archive.png)_**신호 재생 목록**_       | ![이미지 갤러리 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/gallery.png)_**이미지 갤러리**_  |
| ![패킷 제작 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/packet.png)_**패킷 제작**_   | ![Scapy 통합 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/scapy.png)_**Scapy 통합**_ | ![CRC 계산기 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/crc\_calculator.png)_**CRC 계산기**_ | ![로깅 아이콘](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Icons/README/log.png)_**로깅**_            |

**하드웨어**

다음 하드웨어는 FISSURE와 통합된 수준이 각각 다릅니다:<sup>[[1]](#references)[[3]](#references)</sup>

* USRP: X3xx, B2xx, B20xmini, USRP2, N2xx, X410
* HackRF
* RTL2832U
* 802.11 어댑터
* LimeSDR
* bladeRF, bladeRF 2.0 micro
* Open Sniffer
* PlutoSDR
* SDRplay: RSPduo, RSPdx, RSPdx R2

## 강의

FISSURE에는 다양한 기술과 기법을 익히는 데 도움이 되는 여러 가이드가 포함되어 있습니다. 대부분은 FISSURE에 통합된 여러 도구의 사용 단계를 안내합니다.

* [강의 1: OpenBTS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson1\_OpenBTS.md)
* [강의 2: Lua 디섹터](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson2\_LuaDissectors.md)
* [강의 3: Sound eXchange](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson3\_Sound\_eXchange.md)
* [강의 4: ESP 보드](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson4\_ESP\_Boards.md)
* [강의 5: 라디오존데 추적](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson5\_Radiosonde\_Tracking.md)
* [강의 6: RFID](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson6\_RFID.md)
* [강의 7: 데이터 유형](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson7\_Data\_Types.md)
* [강의 8: 사용자 지정 GNU Radio 블록](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson8\_Custom\_GNU\_Radio\_Blocks.md)
* [강의 9: TPMS](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson9\_TPMS.md)
* [강의 10: 아마추어 무선 시험](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson10\_Ham\_Radio\_Exams.md)
* [강의 11: Wi-Fi 도구](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/Lessons/Markdown/Lesson11\_WiFi\_Tools.md)
* [강의 12: 부팅 가능한 USB 만들기](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson12_Creating_Bootable_USBs.md)
* [강의 13: Z-Wave](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson13_Z-Wave.md)
* [강의 14: 천장 선풍기](https://github.com/ainfosec/FISSURE/blob/Python3/docs/Lessons/Markdown/Lesson14_Ceiling_Fans.md)

## 로드맵

* [ ] 더 많은 하드웨어 유형, RF 프로토콜, 신호 매개변수 및 분석 도구 추가
* [ ] 더 많은 운영 체제 지원
* [ ] FISSURE를 활용한 강의 자료 개발 (RF 공격, Wi-Fi, GNU Radio, PyQt 등)
* [ ] 선택 가능한 AI/ML 기법을 사용해 신호 컨디셔너, 특징 추출기 및 신호 분류기 제작
* [ ] 알 수 없는 신호에서 비트스트림을 생성하는 재귀적 복조 메커니즘 구현
* [ ] 주요 FISSURE 구성 요소를 범용 센서 노드 배포 방식으로 전환

## 기여하기

FISSURE 개선을 위한 제안은 언제든 환영합니다. 다음 사항에 대한 의견이 있다면 [Discussions](https://github.com/ainfosec/FISSURE/discussions) 페이지나 Discord 서버에 댓글을 남겨 주세요.

* 새로운 기능 제안 및 설계 변경
* 설치 단계가 포함된 소프트웨어 도구
* 새 강의 또는 기존 강의를 위한 추가 자료
* 관심 있는 RF 프로토콜
* 통합할 추가 하드웨어 및 SDR 유형
* Python으로 작성한 IQ 분석 스크립트
* 설치 관련 수정 및 개선

FISSURE 개선을 위한 기여는 개발을 앞당기는 데 매우 중요합니다. 어떤 기여든 크게 감사드립니다. 코드 개발을 통해 기여하려면 저장소를 fork한 후 pull request를 생성하세요.

1. 프로젝트를 fork합니다
2. 기능 브랜치를 생성합니다 (`git checkout -b feature/AmazingFeature`)
3. 변경 사항을 commit합니다 (`git commit -m 'Add some AmazingFeature'`)
4. 브랜치에 push합니다 (`git push origin feature/AmazingFeature`)
5. pull request를 엽니다

버그를 알리기 위한 [Issues](https://github.com/ainfosec/FISSURE/issues) 작성도 환영합니다.

## 협업

FISSURE 협업 기회를 제안하고 구체화하려면 Assured Information Security, Inc. (AIS) Business Development에 문의하세요. 소프트웨어 통합에 시간을 할애하거나, AIS의 숙련된 인력이 기술적 과제를 해결할 솔루션을 개발하거나, FISSURE를 다른 플랫폼/애플리케이션에 통합하는 방식으로 협업할 수 있습니다.

## 라이선스

GPL-3.0

라이선스에 대한 자세한 내용은 LICENSE 파일을 참조하세요.

## 연락처

Discord 서버에 참여하세요: [https://discord.gg/JZDs5sgxcG](https://discord.gg/JZDs5sgxcG)

Twitter에서 팔로우하세요: [@FissureRF](https://twitter.com/fissurerf), [@AinfoSec](https://twitter.com/ainfosec)

Chris Poore - Assured Information Security, Inc. - poorec@ainfosec.com

Business Development - Assured Information Security, Inc. - bd@ainfosec.com

## 크레딧

다음 개발자들에게 감사의 뜻을 전합니다.

[크레딧](https://github.com/ainfosec/FISSURE/blob/Python3\_maint-3.8/CREDITS.md)

## 감사의 말

이 프로젝트에 기여해 주신 Samuel Mantravadi 박사와 Joseph Reith에게 특별히 감사드립니다.

## References

- [1] [FISSURE - RF 프레임워크 (GitHub)](https://github.com/ainfosec/FISSURE)
- [2] [FISSURE 논문 (GRCon22)](https://events.gnuradio.org/event/18/contributions/246/attachments/84/167/FISSURE_Paper_Poore_GRCon22.pdf)
- [3] [FISSURE 문서 - 설치](https://fissure.readthedocs.io/en/latest/pages/installation.html)
{{#include ../../banners/hacktricks-training.md}}
