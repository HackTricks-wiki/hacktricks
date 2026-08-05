# 侧信道分析攻击

{{#include ../../banners/hacktricks-training.md}}

侧信道攻击通过观察与内部状态相关、但不属于设备逻辑接口的物理或微架构“leakage”来恢复 secret。示例包括测量智能卡的瞬时电流，以及通过网络滥用 CPU 电源管理效应。

---

## 主要 leakage 通道

| 通道 | 典型目标 | 仪器 |
|---------|---------------|-----------------|
| 功耗 | 智能卡、IoT MCU、FPGA | 示波器 + 分流电阻/HS 探头（例如 CW503） |
| 电磁场（EM） | CPU、RFID、AES 加速器 | H 场探头 + LNA、ChipWhisperer/RTL-SDR |
| 执行时间 / cache | 桌面和 cloud CPU | 高精度计时器（rdtsc/rdtscp）、远程 time-of-flight |
| 声学 / 机械 | 键盘、3-D 打印机、继电器 | MEMS 麦克风、激光测振仪 |
| 光学与热学 | LED、激光打印机、DRAM | 光电二极管 / 高速摄像机、红外相机 |
| 故障诱导 | ASIC/MCU cryptos | 时钟/电压 glitch、EMFI、激光注入 |

---

## 功耗分析

### 简单功耗分析（SPA）
观察单条 trace，并将峰值/谷值直接与操作（例如 DES S-box）关联。
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
获取 *N > 1 000* 条 traces，假设密钥字节 `k`，计算 HW/HD model，并将其与 leakage 进行相关性分析。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA 仍是 state-of-the-art，但 machine-learning 变体（MLA、deep-learning SCA）如今已主导 ASCAD-v2（2023）等竞赛。

---

## 电磁分析（EMA）
近场 EM 探头（500 MHz–3 GHz）无需插入分流电阻，即可 leak 与 power analysis 相同的信息。2024 年的研究证明，使用 spectrum correlation 和低成本 RTL-SDR 前端，即使距离 STM32 **超过 10 cm**，也能恢复密钥。

---

## Timing 与 Micro-architectural Attacks
现代 CPU 会通过共享资源 leak secrets：
* **Hertzbleed（2022）** – DVFS frequency scaling 与 Hamming weight 相关，从而允许*远程*提取 EdDSA 密钥。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling（Intel，2023）** – 利用 transient-execution 跨 SMT threads 读取 AVX-gather 数据。
* **Zenbleed（AMD，2023）与 Inception（AMD，2023）** – speculative vector mis-prediction 跨 domain leak registers。

---

## Acoustic 与 Optical Attacks
* 2024 年的 “​iLeakKeys” 表明，使用 CNN classifier，可通过 **Zoom 上的 smartphone microphone** 以 95% 的准确率恢复 laptop keystrokes。
* High-speed photodiodes 捕获 DDR4 activity LED，并在 <1 分钟内重构 AES round keys（BlackHat 2023）。

---

## Fault Injection 与 Differential Fault Analysis（DFA）
将 faults 与 side-channel leakage 结合，可缩短 key search（例如 1-trace AES DFA）。近期价格适合 hobbyist 的工具：
* **ChipSHOUTER 与 PicoEMP** – 亚 1 ns 的 electromagnetic pulse glitching。
* **GlitchKit-R5（2025）** – open-source clock/voltage glitch platform，支持 RISC-V SoCs。

---

## Typical Attack Workflow
1. Identify leakage channel 与 mount point（VCC pin、decoupling cap、near-field spot）。
2. Insert trigger（GPIO 或 pattern-based）。
3. 使用适当的 sampling/filters 收集 >1 k traces。
4. Pre-process（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. Statistical 或 ML key recovery（CPA、MIA、DL-SCA）。
6. Validate 并针对 outliers 迭代。

---

## Defences 与 Hardening
* **Constant-time** implementations 与 memory-hard algorithms。
* **Masking/shuffling** – 将 secrets 拆分为 random shares；通过 TVLA 认证 first-order resistance。
* **Hiding** – on-chip voltage regulators、randomised clock、dual-rail logic、EM shields。
* **Fault detection** – redundant computation、threshold signatures。
* **Operational** – 在 crypto kernels 中禁用 DVFS/turbo、隔离 SMT、禁止 multi-tenant clouds 中的 co-location。

---

## Tools 与 Frameworks
* **ChipWhisperer-Husky**（2024）– 500 MS/s scope + Cortex-M trigger；Python API 如上所述。<sup>[[1]](#references)</sup>
* **Riscure Inspector 与 FI** – commercial，支持 automated leakage assessment（TVLA-2.0）。
* **scaaml** – 基于 TensorFlow 的 deep-learning SCA library（v1.2 – 2025）。
* **pyecsca** – ANSSI open-source ECC SCA framework。

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
