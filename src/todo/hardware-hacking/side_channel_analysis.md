# Side Channel Analysis 공격

{{#include ../../banners/hacktricks-training.md}}

Side-channel 공격은 device의 logical interface에 포함되지 않지만 내부 상태와 *correlated*된 물리적 또는 micro-architectural "leakage"를 관찰하여 secret을 복구합니다. 예를 들어 smart-card가 순간적으로 사용하는 전류를 측정하거나, network를 통해 CPU power-management 효과를 악용하는 방법 등이 있습니다.

---

## 주요 Leakage 채널

| 채널 | 일반적인 Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards, IoT MCUs, FPGAs | Oscilloscope + shunt resistor/HS probe (예: CW503)
| Electromagnetic field (EM) | CPUs, RFID, AES accelerators | H-field probe + LNA, ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop 및 cloud CPUs | High-precision timers (rdtsc/rdtscp), remote time-of-flight
| Acoustic / mechanical | Keyboards, 3-D printers, relays | MEMS microphone, laser vibrometer
| Optical & thermal | LEDs, laser printers, DRAM | Photodiode / high-speed camera, IR camera
| Fault-induced | ASIC/MCU cryptos | Clock/voltage glitch, EMFI, laser injection

---

## Power Analysis

### Simple Power Analysis (SPA)
단일 trace를 관찰하고 peak/valley를 operation과 직접 연결합니다(예: DES S-box).
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
*N > 1 000*개의 trace를 수집하고, 키 바이트 `k`를 가정한 뒤 HW/HD 모델을 계산하여 leakage와 상관관계를 분석합니다.
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA는 여전히 state-of-the-art이지만, machine-learning 변형(MLA, deep-learning SCA)이 현재 ASCAD-v2(2023)와 같은 대회를 지배하고 있습니다.

---

## Electromagnetic Analysis (EMA)
근접장 EM probe(500 MHz–3 GHz)는 shunt를 삽입하지 않고도 power analysis와 동일한 정보를 leak합니다. 2024년 연구에서는 spectrum correlation과 저가형 RTL-SDR front-end를 사용해 STM32에서 **10 cm 이상** 떨어진 거리에서도 key recovery가 가능함을 입증했습니다.

---

## Timing & Micro-architectural Attacks
Modern CPU는 공유 리소스를 통해 secret을 leak합니다:
* **Hertzbleed (2022)** – DVFS frequency scaling이 Hamming weight와 상관관계를 이루어 *remote* 방식으로 EdDSA key를 추출할 수 있습니다.<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-execution을 사용해 SMT thread 간 AVX-gather data를 읽습니다.
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-prediction을 통해 domain 간 register를 leak합니다.

---

## Acoustic & Optical Attacks
* 2024년의 "​iLeakKeys"는 CNN classifier를 사용해 **Zoom을 통한 smartphone microphone** 입력에서 laptop keystroke를 95 % 정확도로 복구했습니다.
* High-speed photodiode는 DDR4 activity LED를 capture하고 1분 이내에 AES round key를 reconstruct합니다(BlackHat 2023).

---

## Fault Injection & Differential Fault Analysis (DFA)
Fault와 side-channel leakage를 결합하면 key search를 단축할 수 있습니다(예: 1-trace AES DFA). 최근에는 hobbyist 가격대의 다음 도구를 사용할 수 있습니다:
* **ChipSHOUTER & PicoEMP** – 1 ns 미만의 electromagnetic pulse glitching.
* **GlitchKit-R5 (2025)** – RISC-V SoC를 지원하는 open-source clock/voltage glitch platform.

---

## Typical Attack Workflow
1. Leakage channel 및 mount point 식별(VCC pin, decoupling cap, near-field spot).
2. Trigger 삽입(GPIO 또는 pattern-based).
3. 적절한 sampling/filter를 적용해 1 k개를 초과하는 trace 수집.
4. Pre-process 수행(alignment, mean removal, LP/HP filter, wavelet, PCA).
5. Statistical 또는 ML key recovery 수행(CPA, MIA, DL-SCA).
6. Outlier를 검증하고 반복.

---

## Defences & Hardening
* **Constant-time** implementation 및 memory-hard algorithm.
* **Masking/shuffling** – secret을 random share로 분할하며, first-order resistance는 TVLA로 인증됩니다.
* **Hiding** – on-chip voltage regulator, randomised clock, dual-rail logic, EM shield.
* **Fault detection** – redundant computation, threshold signature.
* **Operational** – crypto kernel에서 DVFS/turbo를 비활성화하고, SMT를 격리하며, multi-tenant cloud에서 co-location을 금지합니다.

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger; 위와 같은 Python API.<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial 도구로, automated leakage assessment(TVLA-2.0)을 지원합니다.
* **scaaml** – TensorFlow 기반 deep-learning SCA library(v1.2 – 2025).
* **pyecsca** – ANSSI open-source ECC SCA framework.

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
