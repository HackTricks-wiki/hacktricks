# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks 通过观察与内部状态*相关*、但不属于设备逻辑接口的物理或微架构“leakage”来恢复机密信息。示例包括测量 smart-card 瞬时消耗的电流，以及通过网络滥用 CPU 电源管理效应。

---

## 主要 Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | Smart-cards、IoT MCU、FPGA | 示波器 + 分流电阻/HS 探头（例如 CW503）
| Electromagnetic field (EM) | CPU、RFID、AES 加速器 | H-field 探头 + LNA、ChipWhisperer/RTL-SDR
| Execution time / caches | Desktop 和 cloud CPU | 高精度计时器（rdtsc/rdtscp）、远程 time-of-flight
| Acoustic / mechanical | 键盘、3-D 打印机、继电器 | MEMS 麦克风、激光测振仪
| Optical & thermal | LED、激光打印机、DRAM | 光电二极管/高速摄像机、IR 摄像机
| Fault-induced | ASIC/MCU cryptos | 时钟/电压 glitch、EMFI、激光注入

---

## Power Analysis

### Simple Power Analysis (SPA)
观察一条*单独的* trace，并将峰值/谷值直接与操作（例如 DES S-boxes）关联起来。<sup>[[1]](#references)</sup>
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
采集 *N > 1 000* 条 traces，假设密钥字节 `k`，计算 HW/HD model，并将其与 leakage 进行 correlation。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA remains state-of-the-art，但 machine-learning variants（MLA、deep-learning SCA）如今主导着 ASCAD-v2（2023）等竞赛。

---

## Electromagnetic Analysis（EMA）
Near-field EM probes（500 MHz–3 GHz）能够在*无需插入分流电阻*的情况下泄露与 power analysis 相同的信息。2024 年的研究表明，使用 spectrum correlation 和低成本 RTL-SDR front-ends，即使距离 STM32 **超过 10 cm** 也能恢复密钥。

---

## Timing & Micro-architectural Attacks
现代 CPU 会通过共享资源泄露 secrets：
* **Hertzbleed（2022）** – DVFS frequency scaling 与 Hamming weight 相关联，从而允许*远程*提取 EdDSA keys。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling（Intel，2023）** – 利用 transient-execution 跨 SMT threads 读取 AVX-gather data。<sup>[[3]](#references)</sup>
* **Zenbleed（AMD，2023）与 Inception（AMD，2023）** – speculative vector mis-prediction 跨 domain 泄露 registers。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* 2024 年的“​iLeakKeys”表明，使用 CNN classifier，可通过 **Zoom 上的 smartphone microphone** 以 95 % 的准确率恢复 laptop keystrokes。
* High-speed photodiodes 捕获 DDR4 activity LED，并在不到 1 分钟内重建 AES round keys（BlackHat 2023）。

---

## Fault Injection & Differential Fault Analysis（DFA）
将 faults 与 side-channel leakage 结合，可以缩短 key search（例如 1-trace AES DFA）。近期价格适合 hobbyist 的 tools：
* **ChipSHOUTER & PicoEMP** – sub-1 ns electromagnetic pulse glitching。
* **GlitchKit-R5（2025）** – 支持 RISC-V SoCs 的 open-source clock/voltage glitch platform。

---

## Typical Attack Workflow
1. 识别 leakage channel 和 mount point（VCC pin、decoupling cap、near-field spot）。
2. 插入 trigger（GPIO 或 pattern-based）。
3. 使用适当的 sampling/filters 收集超过 1 k 条 traces。
4. 进行 pre-process（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. 进行 statistical 或 ML key recovery（CPA、MIA、DL-SCA）。
6. 验证并针对 outliers 迭代。

---

## Defences & Hardening
* **Constant-time** implementations 与 memory-hard algorithms。
* **Masking/shuffling** – 将 secrets 拆分为 random shares；一阶 resistance 已通过 TVLA 认证。
* **Hiding** – on-chip voltage regulators、randomised clock、dual-rail logic、EM shields。
* **Fault detection** – redundant computation、threshold signatures。
* **Operational** – 在 crypto kernels 中禁用 DVFS/turbo、隔离 SMT、在 multi-tenant clouds 中禁止 co-location。

---

## Tools & Frameworks
* **ChipWhisperer-Husky**（2024）– 500 MS/s scope + Cortex-M trigger；Python API 如上所述。<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial，支持 automated leakage assessment（TVLA-2.0）。
* **scaaml** – 基于 TensorFlow 的 deep-learning SCA library（v1.2 – 2025）。
* **pyecsca** – ANSSI open-source ECC SCA framework。

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
