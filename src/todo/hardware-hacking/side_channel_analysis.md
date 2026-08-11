# 사이드 채널 분석 공격

{{#include ../../banners/hacktricks-training.md}}

사이드 채널 공격은 장치의 논리적 인터페이스에는 포함되지 않지만 내부 상태와 *상관관계가 있는* 물리적 또는 마이크로아키텍처상의 "leakage"를 관찰하여 비밀을 복구합니다. 예를 들어 스마트 카드가 순간적으로 소비하는 전류를 측정하거나, 네트워크를 통해 CPU 전원 관리 효과를 악용하는 방법 등이 있습니다.

---

## 주요 Leakage 채널

| 채널 | 일반적인 대상 | 계측 장비 |
|---------|---------------|-------------|
| 전력 소비 | 스마트 카드, IoT MCU, FPGA | 오실로스코프와 션트 저항 또는 차동 프로브; CW503은 프로브/LNA용 전원 공급 장치이며, 그 자체가 프로브는 아닙니다<sup>[[11]](#references)</sup> |
| 전자기장(EM) | CPU, RFID, AES 가속기 | RTL-SDR과 같은 H-field/근접장 프로브와 저잡음 증폭기 및 오실로스코프 또는 SDR 수신기<sup>[[13]](#references)</sup> |
| 실행 시간 / 캐시 | 데스크톱 및 클라우드 CPU | 고정밀 타이머(`rdtsc`/`rdtscp`) 또는 원격 time-of-flight |
| 음향 / 기계적 진동 | 키보드, 3D 프린터, 프린터, 릴레이 및 CPU 전압 조정기 | MEMS 마이크 또는 레이저 진동계<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 광학 및 열 | 상태 LED, 디스플레이, DRAM 및 열적으로 결합된 장치 | 포토다이오드, 고속 카메라 또는 IR 카메라<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU 암호화 | 클록/전압 glitch, EMFI 또는 레이저 주입 |

---

## 전력 분석

### Simple Power Analysis (SPA)
*단일* trace를 관찰하고 분기, 모듈러 곱셈 또는 서로 다른 명령어 시퀀스와 같은 연산을 식별 가능한 특징과 연관시킵니다.<sup>[[1]](#references)</sup>

정확한 설정은 대상에 따라 다릅니다. 다음 예제에서는 scope와 target이 연결되고 구성된 후 현재의 상위 수준 ChipWhisperer capture API를 사용합니다:<sup>[[1]](#references)</sup>
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
여러 트레이스를 수집하고, 키 바이트 `k`를 가정한 뒤, Hamming-weight (HW) 또는 Hamming-distance (HD) leakage model을 계산하여 각 샘플과 상관관계를 분석합니다. 필요한 트레이스 수는 대상, 노이즈, 정렬, countermeasures 및 leakage model에 따라 결정되며, 고정된 임계값이 아닙니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 표준 baseline입니다. leakage가 nonlinear하거나 trace 정렬이 잘 되지 않을 때는 Template attacks, mutual-information analysis, machine-learning approaches가 유용할 수 있습니다.

---

## Electromagnetic Analysis (EMA)
Near-field EM analysis는 supply path에 shunt를 삽입하지 않고도 data-dependent activity를 관찰할 수 있습니다. 그러나 power trace와 반드시 동일한 signal을 노출하는 것은 아닙니다. probe position, orientation, bandwidth, front-end gain, trigger quality, distance가 모두 영향을 미칩니다.

---

## Timing & Micro-architectural Attacks
Modern CPUs는 shared resources를 통해 secret을 leak합니다:
* **Hertzbleed (2022)** – Data-dependent dynamic voltage and frequency scaling이 remote timing channel을 생성합니다. 최초의 end-to-end key-recovery demonstration은 SIKE를 대상으로 했으며, 후속 연구에서는 다른 primitives도 다룹니다.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution을 통해 security boundaries를 넘어 vector gather instructions가 사용하는 data가 노출될 수 있습니다.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – Speculative vector-register state의 잘못된 처리로 인해 동일한 physical core의 data가 노출될 수 있습니다.<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Transient-execution attack은 phantom execution과 transient execution 중 training을 결합하여 attacker-controlled misprediction gadgets를 생성합니다.<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
Acoustic leakage는 통제된 실험에서 laptop noise를 통해 RSA keys를 복구하는 데 사용되었으며, 가까운 mobile phone microphone을 사용한 경우도 포함됩니다.<sup>[[6]](#references)</sup> 별도의 2023 keyboard study에서는 가까운 phone으로 녹음한 데이터를 사용해 training했을 때 keystrokes를 95% accuracy로 분류했고, Zoom audio로 training했을 때는 93% accuracy를 기록했습니다. 이러한 수치는 해당 논문의 trained-device experiment를 설명하는 것이며, 임의의 keyboard나 victim에 적용되는 수치가 아닙니다.<sup>[[9]](#references)</sup> Status LEDs에서 발생하는 optical emanations도 processed data와 상관관계를 가질 수 있습니다. 이러한 결과는 target과 setup에 따라 달라지므로, 그 range나 success rate를 관련 없는 devices에 일반화해서는 안 됩니다.<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
Controlled faults와 side-channel observations를 결합하면 일부 algorithms와 implementations에서 key search 범위를 줄일 수 있습니다. 일반적인 lab platforms로는 ChipWhisperer의 voltage/clock glitching features와 ChipSHOUTER 또는 PicoEMP 같은 dedicated EM fault-injection tools가 있습니다. 이전 draft의 “sub-1 ns” 설명을 specification으로 사용해서는 안 됩니다. ChipSHOUTER의 published manual에는 1 mm tip 사용 시 일반적인 inserted-pulse width가 **15–80 ns**, 4 mm tip 사용 시 **24–480 ns**로 기재되어 있습니다(단, trigger/pulse jitter는 picoseconds 단위로 지정됨). 필요한 timing resolution, probe placement, faulty outputs의 수는 target과 fault model에 따라 달라집니다.<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

이전 draft에서는 다음과 같은 주장도 제기했습니다. RTL-SDR을 사용한 **500 MHz–3 GHz** EM setup으로 **10 cm** 이상 떨어진 위치에서 STM32 key를 복구했다는 주장, “Black Hat 2023”에서 DDR4 activity LED가 1분 이내에 AES round key를 드러냈다는 주장, 그리고 **GlitchKit-R5**라는 2025년 open-source RISC-V glitching platform에 대한 주장입니다. 이번 audit 동안 이에 부합하는 primary paper, conference material 또는 project repository를 찾지 못했습니다. 이러한 정확한 세부 사항은 확립된 results나 tooling recommendations가 아니라, 검색 및 재현을 위한 leads로 유지합니다.

---

## Typical Attack Workflow
1. leakage channel 및 mount point 식별(VCC pin, decoupling cap, near-field spot).
2. trigger 삽입(GPIO 또는 pattern-based).
3. 선택한 statistical test에 충분한 traces를 수집하고 plaintext/ciphertext 및 기타 metadata를 기록합니다.
4. Pre-process(alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical 또는 ML key recovery(CPA, MIA, DL-SCA).
6. Outliers를 검증하고 반복합니다.

---

## Defences & Hardening
* **Constant-time** implementations 및 memory-hard algorithms.
* **Masking/shuffling** – Secret을 random shares로 분할하며, first-order resistance는 TVLA로 인증됩니다.
* **Hiding** – On-chip voltage regulators, randomised clock, dual-rail logic, EM shields.
* **Fault detection** – Redundant computation, threshold signatures.
* **Operational** – Crypto kernels에서 DVFS/turbo를 비활성화하고, SMT를 격리하며, multi-tenant clouds에서 co-location을 금지합니다.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; 위와 같은 Python API.<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – Commercial analysis 및 automated test tooling.
* **scaaml** – TensorFlow 기반 deep-learning SCA tooling 및 datasets.<sup>[[12]](#references)</sup>
* **pyecsca** – Side channels를 통해 black-box ECC implementations를 reverse-engineering하기 위한 open-source toolkit.<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Speculative Data Gathering 악용](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Transient Execution 중 Training을 통한 새로운 Attack Surfaces 노출](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [Low-Bandwidth Acoustic Cryptanalysis를 통한 RSA Key Extraction](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical Emanations에서의 Information Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact documentation](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboards에 대한 Practical Deep Learning-Based Acoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER user manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer documentation — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML documentation](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDR을 사용한 low-cost electromagnetic side-channel attacks 수행](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Intellectual Property Decoding: 3-D Printer에 대한 Acoustic and Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printers에 대한 Acoustic Side-Channel Attacks](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAM을 사용한 Temperature Spying](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
