# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks는 기기의 논리적 인터페이스에는 포함되지 않지만 내부 상태와 *상관관계가 있는* 물리적 또는 마이크로아키텍처상의 *leakage*를 관찰해 비밀을 복구합니다. 예를 들면 스마트카드가 순간적으로 소비하는 전류를 측정하거나, 네트워크를 통해 CPU 전력 관리 효과를 악용하는 방식이 있습니다.

---

## 주요 Leakage 채널

| 채널 | 일반적인 대상 | 계측 장비 |
|---------|---------------|-----------------|
| 전력 소비 | 스마트카드, IoT MCU, FPGA | 오실로스코프와 션트 저항 또는 차동 프로브. CW503은 프로브/LNA용 전원 공급 장치이지, 프로브 자체가 아닙니다<sup>[[11]](#references)</sup> |
| 전자기장 (EM) | CPU, RFID, AES 가속기 | H-field/근거리 프로브와 저잡음 증폭기, 오실로스코프 또는 RTL-SDR 같은 SDR 수신기<sup>[[13]](#references)</sup> |
| 실행 시간 / 캐시 | 데스크톱 및 클라우드 CPU | 고정밀 타이머(`rdtsc`/`rdtscp`) 또는 원격 time-of-flight |
| 음향 / 기계적 진동 | 키보드, 3-D 프린터, 프린터, 릴레이 및 CPU 전압 조정기 | MEMS 마이크 또는 레이저 진동계<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 광학 및 열 | 상태 LED, 디스플레이, DRAM 및 열적으로 연결된 기기 | 포토다이오드, 고속 카메라 또는 IR 카메라<sup>[[7]](#references)[[16]](#references)</sup> |
| 결함 주입 | ASIC/MCU 암호화 | 클록/전압 글리치, EMFI 또는 레이저 주입 |

---

## 전력 분석

### Simple Power Analysis (SPA)
단일 *trace*를 관찰하고, 눈에 보이는 특징을 분기, 모듈러 곱셈 또는 서로 다른 명령어 시퀀스 같은 연산과 연관 짓습니다.<sup>[[1]](#references)</sup>

정확한 설정은 대상에 따라 다릅니다. 다음 예제는 스코프와 타깃을 연결하고 구성한 뒤 사용하는 최신 ChipWhisperer 고수준 캡처 API를 이용합니다.<sup>[[1]](#references)</sup>

```python
import chipwhisperer as cw

scope = cw.scope()
scope.default_setup()
target = cw.target(scope)
ktp = cw.ktp.Basic()
key, plaintext = ktp.next()
trace = cw.capture_trace(scope, target, plaintext, key)
if trace is not None:
    print(trace.wave)  # NumPy array of power samples
```

### Differential/Correlation Power Analysis (DPA/CPA)
여러 개의 trace를 획득하고, key byte `k`를 가정한 뒤 Hamming-weight (HW) 또는 Hamming-distance (HD) leakage model을 계산해 각 sample과의 상관관계를 구합니다. 필요한 trace 수는 대상, 노이즈, 정렬, 대응책, leakage model에 따라 달라지며 고정된 임계값은 없습니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 표준적인 기준 기법입니다. leakage가 비선형이거나 trace가 잘 정렬되지 않은 경우 Template attacks, mutual-information analysis, machine-learning 접근법이 유용할 수 있습니다.

---

## 전자기 분석 (EMA)
근거리장 EM 분석은 전원 경로에 션트를 삽입하지 않고도 데이터에 따라 달라지는 동작을 관찰할 수 있습니다. 다만 power trace와 동일한 신호가 반드시 드러나는 것은 아닙니다. 프로브 위치와 방향, 대역폭, 프런트엔드 게인, 트리거 품질, 거리가 모두 영향을 줍니다.

---

## 타이밍 및 마이크로아키텍처 공격
최신 CPU는 공유 리소스를 통해 비밀 정보를 leak합니다:
* **Hertzbleed (2022)** – 데이터에 따라 달라지는 동적 전압 및 주파수 스케일링으로 원격 타이밍 채널이 만들어집니다. 최초의 end-to-end 키 복구 시연은 SIKE를 대상으로 했으며, 후속 연구에서는 다른 프리미티브도 다룹니다.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient execution을 통해 보안 경계를 넘어 vector gather 명령어가 사용하는 데이터가 노출될 수 있습니다.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 추측 실행 중 vector-register 상태를 잘못 처리하면 동일한 물리 코어의 데이터가 노출될 수 있습니다.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – transient-execution 공격은 phantom execution과 transient execution 중의 학습을 결합하여 공격자가 제어하는 misprediction gadget을 만듭니다.<sup>[[5]](#references)</sup>

---

## 음향 및 광학 공격
통제된 실험에서 노트북 소음을 이용해 RSA 키를 복구한 사례가 있으며, 가까이 있는 휴대전화 마이크를 사용한 경우도 포함됩니다.<sup>[[6]](#references)</sup> 별도의 2023년 키보드 연구에서는 근처 휴대전화로 녹음한 데이터를 학습시켰을 때 95%, Zoom 오디오를 학습시켰을 때 93%의 정확도로 키 입력을 분류했습니다. 이 수치는 해당 논문의 학습된 기기 실험 결과이지, 임의의 키보드나 피해자에게 일반화할 수 있는 결과가 아닙니다.<sup>[[9]](#references)</sup> 상태 LED에서 나오는 광학 방출도 처리된 데이터와 연관 지을 수 있습니다. 이러한 결과는 대상과 실험 환경에 따라 다르므로, 다른 기기에도 동일한 탐지 거리나 성공률이 적용된다고 일반화하지 마세요.<sup>[[7]](#references)</sup>

---

## 결함 주입 및 차분 결함 분석 (DFA)
제어된 결함 주입과 side-channel 관측을 결합하면 일부 알고리즘 및 구현에서 키 탐색 범위를 줄일 수 있습니다. 일반적인 실험실 플랫폼에는 ChipWhisperer의 전압/클록 glitching 기능과 ChipSHOUTER 또는 PicoEMP 같은 전용 EM 결함 주입 도구가 있습니다. 이전 초안의 “sub-1 ns” 설명을 사양으로 사용해서는 안 됩니다. ChipSHOUTER의 공개 매뉴얼에는 1 mm 팁 사용 시 일반적인 주입 펄스 폭이 **15–80 ns**, 4 mm 팁 사용 시 **24–480 ns**로 기재되어 있습니다. 단, 트리거/펄스 지터는 피코초 단위로 지정됩니다. 필요한 타이밍 해상도, 프로브 위치, 결함이 발생한 출력의 개수는 대상과 결함 모델에 따라 다릅니다.<sup>[[1]](#references)[[10]](#references)</sup>

## 이전 초안에서 검증되지 않은 연구 단서

이전 초안에는 다음 주장도 있었습니다. RTL-SDR을 사용해 **500 MHz–3 GHz** EM 설정으로 **10 cm** 이상 떨어진 곳에서 STM32 키를 복구했다는 주장, “Black Hat 2023”에서 DDR4 동작 LED를 통해 1분 이내에 AES 라운드 키를 알아냈다는 주장, 그리고 **GlitchKit-R5**라는 2025년 오픈소스 RISC-V glitching 플랫폼에 관한 주장입니다. 이번 검토 과정에서는 이에 부합하는 주요 논문, 학회 자료 또는 프로젝트 저장소를 찾지 못했습니다. 이 구체적인 내용은 확립된 결과나 도구 권장 사항이 아니라 검색/재현을 위한 단서로 남겨 둡니다.

---

## 일반적인 공격 워크플로
1. leakage 채널 및 측정 지점 식별 (VCC 핀, 디커플링 커패시터, 근거리장 지점).
2. 트리거 삽입 (GPIO 또는 패턴 기반).  
3. 선택한 통계 검정에 필요한 trace를 충분히 수집하고, 평문/암호문 및 기타 메타데이터를 기록합니다.
4. 전처리 (정렬, 평균 제거, LP/HP 필터, wavelet, PCA).
5. 통계 또는 ML 기반 키 복구 (CPA, MIA, DL-SCA).
6. 이상치를 검증하고 반복합니다.

---

## 방어 및 보안 강화
* **Constant-time** 구현 및 메모리 하드 알고리즘.
* **Masking/shuffling** – 비밀 정보를 무작위 share로 나눕니다. 1차 저항성은 TVLA로 인증됩니다.
* **Hiding** – 온칩 전압 조정기, 무작위 클록, dual-rail 로직, EM 차폐.
* **결함 탐지** – 중복 연산, 임계값 서명.
* **운영 측면** – 암호화 커널에서 DVFS/turbo를 비활성화하고, SMT를 격리하며, 멀티테넌트 클라우드에서 공동 배치를 금지합니다.

---

## 도구 및 프레임워크
* **ChipWhisperer-Husky** (2024) – 500 MS/s 오실로스코프 + Cortex-M 트리거. 위와 같은 Python API를 제공합니다.<sup>[[1]](#references)</sup>
* **Riscure Inspector 및 결함 주입 제품** – 상용 분석 및 자동화된 테스트 도구.
* **scaaml** – TensorFlow 기반 deep-learning SCA 도구 및 데이터셋.<sup>[[12]](#references)</sup>
* **pyecsca** – side channel을 통해 블랙박스 ECC 구현을 리버스 엔지니어링하기 위한 오픈소스 툴킷.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer 문서](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed 공격 논문](https://www.hertzbleed.com/)
- [3] [Downfall: 추측 실행 데이터 수집 악용](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: transient execution 중 학습을 통한 새로운 공격 표면 노출](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [저대역폭 음향 암호 분석을 통한 RSA 키 추출](https://eprint.iacr.org/2013/857.pdf)
- [7] [광학 방출에서의 정보 누출](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca 아티팩트 문서](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [키보드에 대한 실용적인 deep learning 기반 음향 side-channel 공격](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER 사용자 매뉴얼](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer 문서 — CW503 프로브 전원 공급 장치](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML 문서](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR을 이용한 저비용 전자기 side-channel 공격 수행](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [지식재산 디코딩: 3D 프린터에 대한 음향 및 자기 side-channel 공격](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — 프린터에 대한 음향 side-channel 공격](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM을 이용한 온도 감시](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
