# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks 通过观察与内部状态存在*相关性*、但不属于设备逻辑接口的物理或微架构“leakage”来恢复 secrets。示例包括测量 smart-card 的瞬时电流消耗，以及通过网络滥用 CPU 的 power-management effects。

---

## 主要 leakage 通道

| 通道 | 典型目标 | 仪器设备 |
|---------|---------------|-----------------|
| 功耗 | Smart cards、IoT MCUs、FPGAs | Oscilloscope 加分流电阻或 differential probe；CW503 是用于 probes/LNAs 的电源，而不是 probe 本身<sup>[[11]](#references)</sup> |
| 电磁场（EM） | CPUs、RFID、AES accelerators | H-field/near-field probe，加 low-noise amplifier 和 oscilloscope，或 RTL-SDR 等 SDR receiver<sup>[[13]](#references)</sup> |
| 执行时间 / caches | Desktop 和 cloud CPUs | 高精度计时器（`rdtsc`/`rdtscp`）或远程 time-of-flight |
| 声学 / 机械 | Keyboards、3-D printers、printers、relays 和 CPU voltage regulators | MEMS microphone 或 laser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学与热 | Status LEDs、displays、DRAM 以及热耦合设备 | Photodiode、high-speed camera 或 IR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCU cryptography | Clock/voltage glitch、EMFI 或 laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
观察*单条* trace，并将可见特征与 branches、modular multiplication 或不同的 instruction sequences 等操作关联起来。<sup>[[1]](#references)</sup>

具体 setup 取决于目标。以下示例使用的是在 scope 和 target 连接并配置完成后，ChipWhisperer 当前的 high-level capture API：<sup>[[1]](#references)</sup>
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
获取多条 traces，假设一个密钥字节 `k`，计算 Hamming-weight (HW) 或 Hamming-distance (HD) leakage model，并将其与每个 sample 进行 correlation。所需的 trace 数量取决于目标、噪声、对齐方式、countermeasures 和 leakage model；它不是一个固定阈值。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA 是一种标准基线。当 leakage 呈非线性或 traces 对齐不佳时，Template attacks、mutual-information analysis 和 machine-learning approaches 可能会很有用。

---

## Electromagnetic Analysis (EMA)
近场 EM analysis 可以在不将 shunt 插入供电路径的情况下，观测依赖数据的活动。它不一定会暴露与 power trace 相同的信号：探针位置、方向、带宽、前端增益、触发质量以及距离都会产生影响。

---

## Timing & Micro-architectural Attacks
现代 CPU 会通过共享资源泄露 secrets：
* **Hertzbleed (2022)** – 依赖数据的动态电压和频率调节会产生远程 timing channel。最初的端到端 key-recovery 演示针对 SIKE；后续研究讨论了其他 primitives。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient execution 可以跨越 security boundaries 暴露 vector gather instructions 使用的数据。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 对 speculative vector-register state 的错误处理可能泄露来自同一 physical core 的数据。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 一种 transient-execution attack 将 phantom execution 与 transient execution 中的 training 相结合，从而创建由 attacker 控制的 misprediction gadgets。<sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
在一项受控实验中，研究人员曾利用 acoustic leakage 从 laptop 噪声中恢复 RSA keys，包括使用附近 mobile phone 的 microphone。<sup>[[6]](#references)</sup> 另一项 2023 年的 keyboard study 在使用附近 phone 的录音进行训练时，以 95% 的准确率对 keystrokes 进行分类；使用 Zoom 音频训练时，准确率为 93%。这些数值描述的是该论文中针对经过训练的设备进行的实验，并不适用于任意 keyboard 或 victim。<sup>[[9]](#references)</sup> Status LEDs 的 optical emanations 也可以与处理中的数据进行相关分析。这些结果取决于具体 target 和 setup；不要将其 range 或 success rate 泛化到无关设备。<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
将受控 faults 与 side-channel observations 结合，可以缩小某些 algorithms 和 implementations 的 key search 范围。常见的实验室平台包括 ChipWhisperer 的 voltage/clock glitching 功能，以及 ChipSHOUTER 或 PicoEMP 等专用 EM fault-injection 工具。早期 draft 中关于“sub-1 ns”的描述不应作为规格使用：ChipSHOUTER 发布的 manual 列出，使用其 1 mm tip 时典型 inserted-pulse widths 为 **15–80 ns**，使用 4 mm tip 时为 **24–480 ns**（但 trigger/pulse jitter 的规格以 picoseconds 表示）。所需的 timing resolution、probe placement 以及 faulty outputs 数量取决于 target 和 fault model。<sup>[[1]](#references)[[10]](#references)</sup>

## Unverified Research Leads Retained from the Earlier Draft

早期 draft 还声称：一个 **500 MHz–3 GHz** 的 EM setup 使用 RTL-SDR 从超过 **10 cm** 的距离恢复 STM32 key；DDR4 activity LED 在“Black Hat 2023”中于一分钟内暴露 AES round key；以及一个名为 **GlitchKit-R5**、于 2025 年发布的 open-source RISC-V glitching platform。在本次 audit 期间，未能找到相匹配的 primary paper、conference material 或 project repository。这些确切细节被保留为 search/reproduction leads，而不是已确立的 results 或 tooling recommendations。

---

## Typical Attack Workflow
1. 确定 leakage channel 和 mount point（VCC pin、decoupling cap、near-field spot）。
2. 插入 trigger（GPIO 或基于 pattern 的 trigger）。
3. 为所选 statistical test 收集足够的 traces，同时记录 plaintext/ciphertext 及其他 metadata。
4. 进行预处理（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. 通过 statistical 或 ML key recovery（CPA、MIA、DL-SCA）恢复 key。
6. 验证并针对 outliers 迭代。

---

## Defences & Hardening
* **Constant-time** implementations 和 memory-hard algorithms。
* **Masking/shuffling** – 将 secrets 拆分为 random shares；其 first-order resistance 已通过 TVLA 认证。
* **Hiding** – on-chip voltage regulators、randomised clock、dual-rail logic、EM shields。
* **Fault detection** – redundant computation、threshold signatures。
* **Operational** – 在 crypto kernels 中禁用 DVFS/turbo，隔离 SMT，并禁止 multi-tenant clouds 中的 co-location。

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger；Python API 如上所述。<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – 商业化 analysis 和 automated test tooling。
* **scaaml** – 基于 TensorFlow 的 deep-learning SCA tooling 和 datasets。<sup>[[12]](#references)</sup>
* **pyecsca** – 用于通过 side channels 对 black-box ECC implementations 进行 reverse-engineering 的 open-source toolkit。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer 文档](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack 论文](https://www.hertzbleed.com/)
- [3] [Downfall：利用 Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception：通过 Transient Execution 中的 Training 暴露新的 Attack Surfaces](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [通过低带宽 Acoustic Cryptanalysis 提取 RSA Key](https://eprint.iacr.org/2013/857.pdf)
- [7] [来自 Optical Emanations 的 Information Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifact 文档](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [一种基于 Practical Deep Learning 的 Keyboard Acoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER 用户手册](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer 文档 — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML 文档](https://google.github.io/scaaml/)
- [13] [FOSDEM — 使用 RTL-SDR 执行低成本 Electromagnetic Side-Channel Attacks](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [解码 Intellectual Property：针对 3-D Printer 的 Acoustic and Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — 针对 Printers 的 Acoustic Side-Channel Attacks](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [使用 DRAM 监视 Temperature](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
