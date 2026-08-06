# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks는 장치의 논리적 인터페이스에 포함되지 않지만 내부 상태와 *상관관계가 있는* 물리적 또는 마이크로아키텍처상의 "leakage"를 관찰하여 secret을 복구합니다. 예를 들어 smart-card가 순간적으로 소비하는 전류를 측정하거나, 네트워크를 통해 CPU power-management 효과를 악용하는 방법이 있습니다.

---

## 주요 Leakage 채널

| 채널 | 일반적인 대상 | 계측 장비 |
|---------|---------------|-----------------|
| 전력 소비 | Smart-cards, IoT MCU, FPGA | 오실로스코프 + 션트 저항/HS probe (예: CW503) |
| 전자기장 (EM) | CPU, RFID, AES accelerator | H-field probe + LNA, ChipWhisperer/RTL-SDR |
| 실행 시간 / cache | Desktop 및 cloud CPU | 고정밀 timer (rdtsc/rdtscp), 원격 time-of-flight |
| 음향 / 기계적 진동 | Keyboard, 3-D printer, relay | MEMS microphone, laser vibrometer |
| 광학 및 열 | LED, laser printer, DRAM | Photodiode / high-speed camera, IR camera |
| Fault 유발 | ASIC/MCU crypto | Clock/voltage glitch, EMFI, laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
*단일* trace를 관찰하고 peak/valley를 연산에 직접 연결합니다(예: DES S-box).<sup>[[1]](#references)</sup>
```python
# ChipWhisperer-husky example – capture one AES trace
from chipwhisperer.capture.api.programmers import STMLink
from chipwhisperer.capture import CWSession
cw = CWSession(project='aes')
trig = cw.scope.trig
cw.connect(cw.capture.scopes[0])
cw.capture.init()
trace = cw.capture.capture_trace()
print(trace.wave)  # numpy array of power samples
```
### Differential/Correlation Power Analysis (DPA/CPA)
* N > 1 000*개의 trace를 획득하고, key byte `k`를 가정한 뒤 HW/HD model을 계산하여 leakage와 상관관계를 분석합니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 여전히 state-of-the-art이지만, machine-learning variants (MLA, deep-learning SCA)가 이제 ASCAD-v2 (2023)와 같은 competitions를 지배하고 있습니다.

---

## Electromagnetic Analysis (EMA)
Near-field EM probes (500 MHz–3 GHz)는 shunt를 삽입하지 않고도 power analysis와 동일한 정보를 leak합니다. 2024년 research에서는 spectrum correlation과 저가형 RTL-SDR front-end를 사용해 STM32에서 **10 cm 이상** 떨어진 위치에서도 key recovery가 가능함을 입증했습니다.

---

## Timing & Micro-architectural Attacks
Modern CPU는 shared resource를 통해 secret을 leak합니다:
* **Hertzbleed (2022)** – DVFS frequency scaling이 Hamming weight와 상관관계를 가지므로, *remote* 방식으로 EdDSA key를 추출할 수 있습니다.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution을 사용해 SMT thread 간 AVX-gather data를 읽습니다.<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction을 통해 cross-domain으로 register를 leak합니다.<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* 2024년 "​iLeakKeys"는 CNN classifier를 사용해 **Zoom을 통한 smart-phone microphone**으로 laptop keystroke를 복원하여 95 %의 accuracy를 보였습니다.
* High-speed photodiode는 DDR4 activity LED를 capture하고 1분 이내에 AES round key를 reconstruct합니다 (BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Fault와 side-channel leakage를 결합하면 key search를 단축할 수 있습니다 (예: 1-trace AES DFA). 최근 hobbyist 가격대의 tools:
* **ChipSHOUTER & PicoEMP** – 1 ns 미만의 electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – RISC-V SoC를 지원하는 open-source clock/voltage glitch platform.

---

## Typical Attack Workflow
1. leakage channel과 mount point 식별 (VCC pin, decoupling cap, near-field spot).
2. trigger 삽입 (GPIO 또는 pattern-based).
3. 적절한 sampling/filter를 사용해 1 k개 이상의 trace 수집.
4. Pre-process (alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical 또는 ML key recovery (CPA, MIA, DL-SCA).
6. Validate하고 outlier를 대상으로 반복.

---

## Defences & Hardening
* **Constant-time** implementation 및 memory-hard algorithm.
* **Masking/shuffling** – secret을 random share로 분할하며, first-order resistance는 TVLA로 인증됩니다.
* **Hiding** – on-chip voltage regulator, randomised clock, dual-rail logic, EM shield.
* **Fault detection** – redundant computation, threshold signature.
* **Operational** – crypto kernel에서 DVFS/turbo를 비활성화하고, SMT를 isolate하며, multi-tenant cloud에서 co-location을 금지합니다.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; 위와 같은 Python API.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial tool이며 automated leakage assessment (TVLA-2.0)을 지원합니다.
* **scaaml** – TensorFlow 기반 deep-learning SCA library (v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
