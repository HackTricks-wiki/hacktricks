# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel 공격은 기기의 내부 상태와 *상관관계가 있지만* 기기의 논리적 인터페이스에는 *포함되지 않는* 물리적 또는 마이크로아키텍처상의 "누설"을 관찰해 비밀을 복구합니다. 예를 들어 스마트카드가 순간적으로 소비하는 전류를 측정하거나 네트워크를 통해 CPU 전력 관리 효과를 악용하는 방법이 있습니다.

ARM debug 하드웨어에 접근할 수 있는 대상의 경우, [CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md)는 전력 또는 EM 캡처와 함께 실행 경로의 참조 정보를 제공할 수 있습니다. 이는 debug trace이며 누설 채널은 아닙니다.<sup>[[17]](#references)</sup>

---

## 주요 누설 채널

| 채널 | 일반적인 대상 | 계측 장비 |
|---------|---------------|-----------------|
| 전력 소비 | Smart card, IoT MCU, FPGA | 오실로스코프와 션트 저항 또는 차동 프로브; CW503은 프로브/LNA용 전원 공급 장치이며 그 자체가 프로브는 아닙니다<sup>[[11]](#references)</sup> |
| 전자기장(EM) | CPU, RFID, AES 가속기 | H-field/근접장 프로브와 저잡음 증폭기, 오실로스코프 또는 RTL-SDR 같은 SDR 수신기<sup>[[13]](#references)</sup> |
| 실행 시간 / 캐시 | 데스크톱 및 클라우드 CPU | 고정밀 타이머(`rdtsc`/`rdtscp`) 또는 원격 비행 시간 측정 |
| 음향 / 기계적 신호 | 키보드, 3D 프린터, 프린터, 릴레이, CPU 전압 조정기 | MEMS 마이크 또는 레이저 진동계<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 광학 및 열 | 상태 LED, 디스플레이, DRAM, 열적으로 결합된 기기 | 포토다이오드, 고속 카메라 또는 IR 카메라<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU 암호화 | Clock/voltage glitch, EMFI 또는 레이저 주입 |

---

## 전력 분석

### Simple Power Analysis (SPA)
*단일* 트레이스를 관찰하고, 눈에 보이는 특징을 분기, 모듈러 곱셈 또는 서로 다른 명령 시퀀스 같은 연산과 연관 짓습니다.<sup>[[1]](#references)</sup>

정확한 설정은 대상에 따라 다릅니다. 다음 예제는 오실로스코프와 대상 장치가 연결 및 구성된 후의 최신 고수준 ChipWhisperer 캡처 API를 사용합니다.<sup>[[1]](#references)</sup>

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
여러 트레이스를 수집하고, 키 바이트 `k`를 가정한 뒤, Hamming-weight (HW) 또는 Hamming-distance (HD) 누설 모델을 계산해 각 샘플과 상관관계를 분석합니다. 필요한 트레이스 수는 대상, 노이즈, 정렬 상태, 대응책 및 누설 모델에 따라 달라지며, 고정된 임계값은 없습니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 표준적인 baseline입니다. leakage가 비선형이거나 trace 정렬이 잘 되지 않는 경우, Template attacks, mutual-information analysis, machine-learning 방식이 유용할 수 있습니다.

---

## 전자기 분석 (EMA)
Near-field EM analysis는 전원 경로에 shunt를 삽입하지 않고도 데이터에 따라 달라지는 활동을 관찰할 수 있습니다. 하지만 power trace와 동일한 신호가 반드시 노출되는 것은 아닙니다. probe 위치와 방향, bandwidth, front-end gain, trigger 품질, 거리 모두 영향을 줍니다.

---

## 타이밍 및 Micro-architectural 공격
최신 CPU는 공유 리소스를 통해 secret을 leak합니다.
* **Hertzbleed (2022)** – 데이터에 따라 달라지는 dynamic voltage and frequency scaling이 원격 timing channel을 만듭니다. 최초의 end-to-end key-recovery 시연은 SIKE를 대상으로 했으며, 후속 연구에서는 다른 primitive도 다룹니다.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution을 통해 보안 경계를 넘어 vector gather 명령어에서 사용되는 데이터가 노출될 수 있습니다.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – speculative vector-register 상태를 잘못 처리하면 동일한 physical core의 데이터가 노출될 수 있습니다.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – transient-execution 공격은 phantom execution과 transient execution 중의 training을 결합해 공격자가 제어하는 misprediction gadget을 만듭니다.<sup>[[5]](#references)</sup>

---

## 음향 및 광학 공격
통제된 실험에서 노트북 소음을 이용해 RSA key를 복구한 사례가 있으며, 가까이 있는 휴대전화의 microphone을 사용한 경우도 포함됩니다.<sup>[[6]](#references)</sup> 별도의 2023년 keyboard 연구에서는 가까운 휴대전화로 녹음한 데이터로 학습했을 때 keystroke를 95% 정확도로 분류했고, Zoom audio로 학습했을 때는 93% 정확도를 보였습니다. 이 수치는 해당 논문에서 학습된 장치를 대상으로 한 실험 결과이며, 임의의 keyboard나 피해자에게 적용되는 것은 아닙니다.<sup>[[9]](#references)</sup> Status LED에서 나오는 optical emanation도 처리된 데이터와 연관 지을 수 있습니다. 이러한 결과는 대상과 설정에 따라 다르므로, 그 범위나 성공률을 관련 없는 장치에 일반화하지 마세요.<sup>[[7]](#references)</sup>

---

## Fault Injection 및 Differential Fault Analysis (DFA)
통제된 fault와 side-channel 관측을 결합하면 일부 알고리즘과 구현에서 key 검색 범위를 줄일 수 있습니다. 일반적인 lab 플랫폼에는 ChipWhisperer의 voltage/clock glitching 기능과 ChipSHOUTER 또는 PicoEMP 같은 전용 EM fault-injection 도구가 있습니다. 이전 초안의 “sub-1 ns”라는 설명은 사양으로 사용하면 안 됩니다. ChipSHOUTER의 공개 매뉴얼에는 1 mm tip 사용 시 삽입 pulse 폭이 일반적으로 **15–80 ns**, 4 mm tip 사용 시 **24–480 ns**로 기재되어 있습니다. (단, trigger/pulse jitter는 picosecond 단위로 명시되어 있습니다.) 필요한 timing resolution, probe 위치, faulty output의 개수는 대상과 fault model에 따라 달라집니다.<sup>[[1]](#references)[[10]](#references)</sup>

## 이전 초안에서 검증되지 않은 연구 단서

이전 초안에는 다음과 같은 주장도 있었습니다. RTL-SDR을 이용한 **500 MHz–3 GHz** EM setup으로 **10 cm**가 넘는 거리에서 STM32 key를 복구했다는 주장, “Black Hat 2023”에서 DDR4 activity LED를 통해 1분 이내에 AES round key를 알아냈다는 주장, 그리고 **GlitchKit-R5**라는 2025년 오픈소스 RISC-V glitching 플랫폼입니다. 이번 검토에서 이에 부합하는 1차 논문, conference 자료 또는 프로젝트 저장소를 찾지 못했습니다. 이 세부 정보는 확립된 결과나 도구 추천이 아니라, 검색 및 재현을 위한 단서로 남겨둡니다.

---

## 일반적인 공격 워크플로
1. leakage channel 및 mount point를 식별합니다 (VCC pin, decoupling cap, near-field spot).
2. Trigger를 삽입합니다 (GPIO 또는 pattern-based).
3. 선택한 통계 검정에 충분한 trace를 수집하고, plaintext/ciphertext 및 기타 metadata를 기록합니다.
4. 전처리합니다 (정렬, 평균 제거, LP/HP filter, wavelet, PCA).
5. 통계 또는 ML을 이용해 key를 복구합니다 (CPA, MIA, DL-SCA).
6. 이상치를 검증하고 반복합니다.

---

## 방어 및 강화
* **Constant-time** 구현 및 memory-hard 알고리즘.
* **Masking/shuffling** – secret을 무작위 share로 나눕니다. 1차 저항성은 TVLA로 인증됩니다.
* **Hiding** – on-chip voltage regulator, 무작위 clock, dual-rail logic, EM shield.
* **Fault 탐지** – 중복 연산, threshold signature.
* **운영 측면** – crypto kernel에서 DVFS/turbo를 비활성화하고, SMT를 격리하며, multi-tenant cloud에서 co-location을 금지합니다.

---

## 도구 및 프레임워크
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger. Python API는 위와 같습니다.<sup>[[1]](#references)</sup>
* **Riscure Inspector 및 fault-injection 제품** – 상용 분석 및 자동화된 테스트 도구.
* **scaaml** – TensorFlow 기반 deep-learning SCA 도구 및 dataset.<sup>[[12]](#references)</sup>
* **pyecsca** – side-channel을 통해 black-box ECC 구현을 reverse-engineering하기 위한 오픈소스 toolkit.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer 문서](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed 공격 논문](https://www.hertzbleed.com/)
- [3] [Downfall: Speculative Data Gathering 악용](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Transient Execution 중의 Training을 통한 새로운 공격 표면 노출](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [저대역폭 Acoustic Cryptanalysis를 통한 RSA Key 추출](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical Emanation을 통한 정보 누출](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact 문서](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboard에 대한 실용적인 Deep Learning 기반 Acoustic Side Channel 공격](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER 사용자 매뉴얼](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer 문서 — CW503 probe 전원 공급 장치](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML 문서](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR을 이용한 저비용 전자기 side-channel 공격 수행](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [지식재산 해독: 3-D Printer에 대한 Acoustic 및 Magnetic Side-Channel 공격](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printer에 대한 Acoustic Side-Channel 공격](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM을 이용한 온도 감시](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [명령어 추적: ETM, ITM, TPIU를 이용한 실시간 ARM 추적](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
