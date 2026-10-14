# 侧信道分析攻击

{{#include ../../banners/hacktricks-training.md}}

侧信道攻击通过观察与内部状态*相关*、但不属于设备逻辑接口的物理或微架构“leakage”来恢复秘密。示例包括测量智能卡消耗的瞬时电流，以及通过网络滥用 CPU 电源管理效应。

---

## 主要泄漏通道

| 通道 | 典型目标 | 仪器 |
|---------|---------------|-----------------|
| 功耗 | 智能卡、IoT MCU、FPGA | 示波器，加分流电阻或差分探头；CW503 是用于探头/LNA 的电源，而不是探头本身<sup>[[11]](#references)</sup> |
| 电磁场 (EM) | CPU、RFID、AES 加速器 | H 场/近场探头，加低噪声放大器和示波器，或 RTL-SDR 等 SDR 接收机<sup>[[13]](#references)</sup> |
| 执行时间 / 缓存 | 桌面和云端 CPU | 高精度计时器（`rdtsc`/`rdtscp`）或远程飞行时间测量 |
| 声学 / 机械 | 键盘、3D 打印机、打印机、继电器和 CPU 电压调节器 | MEMS 麦克风或激光测振仪<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学与热学 | 状态 LED、显示器、DRAM 和热耦合设备 | 光电二极管、高速摄像机或红外摄像机<sup>[[7]](#references)[[16]](#references)</sup> |
| 故障注入 | ASIC/MCU 加密 | 时钟/电压 glitch、EMFI 或激光注入 |

---

## 功耗分析

### 简单功耗分析（SPA）
观察*单条*轨迹，并将可见特征与分支、模乘或不同指令序列等操作联系起来。<sup>[[1]](#references)</sup>

具体设置取决于目标。以下示例使用 ChipWhisperer 的当前高级捕获 API，此时示波器和目标设备已连接并配置完毕：<sup>[[1]](#references)</sup>

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
采集多条 traces，假设一个密钥字节 `k`，计算 Hamming-weight (HW) 或 Hamming-distance (HD) leakage model，并将其与每个采样点进行相关性分析。所需的 traces 数量取决于目标、噪声、对齐情况、对策和 leakage model；它并非固定阈值。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA 是标准基线。当泄漏呈非线性或 traces 对齐不佳时，Template attacks、mutual-information analysis 和 machine-learning 方法可能会有用。

---

## 电磁分析 (EMA)
近场 EM 分析可以观测依赖于数据的活动，而无需在电源路径中插入分流器。它不一定会暴露与功耗 trace 相同的信号：探头位置、方向、带宽、前端增益、触发质量和距离都会产生影响。

---

## 时序与微架构攻击
现代 CPU 会通过共享资源泄漏秘密：
* **Hertzbleed (2022)** – 依赖于数据的动态电压和频率调节会产生远程时序通道。最初的端到端密钥恢复演示针对 SIKE；后续研究讨论了其他原语。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – 瞬态执行可以跨越安全边界暴露向量 gather 指令使用的数据。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 对推测执行期间向量寄存器状态的不正确处理，可能泄露同一物理核心中的数据。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 一种瞬态执行攻击，它将 phantom execution 与瞬态执行训练结合起来，从而构造由攻击者控制的错误预测 gadget。<sup>[[5]](#references)</sup>

---

## 声学与光学攻击
在一项受控实验中，研究人员利用声学泄漏从笔记本电脑噪声中恢复了 RSA 密钥，甚至使用了附近手机的麦克风。<sup>[[6]](#references)</sup> 另一项 2023 年的键盘研究表明，使用附近手机录音进行训练时，击键分类准确率达到 95%；使用 Zoom 音频进行训练时，准确率达到 93%。这些数据描述的是该论文中针对经过训练的设备所做的实验，并不代表任意键盘或受害者。<sup>[[9]](#references)</sup> 状态 LED 发出的光学辐射也可以与处理中的数据相关联。这些结果取决于目标和设置；不要将其作用距离或成功率泛化到无关设备。<sup>[[7]](#references)</sup>

---

## 故障注入与差分故障分析 (DFA)
将可控故障与侧信道观测结合起来，可以缩小某些算法和实现的密钥搜索范围。常见的实验平台包括 ChipWhisperer 的电压/时钟 glitch 功能，以及 ChipSHOUTER 或 PicoEMP 等专用 EM 故障注入工具。早期草稿中的“低于 1 ns”描述不应作为规格使用：ChipSHOUTER 发布的手册列出的典型注入脉冲宽度为：使用 1 mm 探头时为 **15–80 ns**，使用 4 mm 探头时为 **24–480 ns**（尽管触发/脉冲抖动的规格以皮秒为单位）。所需的时序分辨率、探头位置和故障输出数量取决于目标和故障模型。<sup>[[1]](#references)[[10]](#references)</sup>

## 保留自早期草稿的未经验证研究线索

早期草稿还声称：一套 **500 MHz–3 GHz** 的 EM 装置可以使用 RTL-SDR 从超过 **10 cm** 的距离恢复 STM32 密钥；一盏 DDR4 活动 LED 能在不到一分钟内泄露 AES 轮密钥，相关内容发表于“Black Hat 2023”；以及一个名为 **GlitchKit-R5** 的 2025 年开源 RISC-V glitching 平台。在本次审查期间，未能找到相符的原始论文、会议资料或项目仓库。这些具体细节仅作为搜索/复现线索保留，并非已确立的结果或工具推荐。

---

## 典型攻击工作流程
1. 确定泄漏通道和接入点（VCC 引脚、去耦电容、近场位置）。
2. 插入触发器（GPIO 或基于模式的触发器）。  
3. 为所选统计检验采集足够数量的 traces，并记录明文/密文和其他元数据。
4. 预处理（对齐、去均值、LP/HP 滤波、小波、PCA）。
5. 使用统计或 ML 方法恢复密钥（CPA、MIA、DL-SCA）。
6. 验证并针对异常值迭代。

---

## 防御与加固
* **恒定时间**实现与内存困难算法。
* **Masking/shuffling** – 将秘密拆分为随机份额；通过 TVLA 认证一阶抗性。
* **隐藏** – 片上稳压器、随机化时钟、双轨逻辑、EM 屏蔽。
* **故障检测** – 冗余计算、阈值签名。
* **运维措施** – 在加密内核中禁用 DVFS/turbo、隔离 SMT、禁止多租户云中的共置。

---

## 工具与框架
* **ChipWhisperer-Husky** (2024) – 500 MS/s 示波器 + Cortex-M 触发器；Python API 如上所述。<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – 商业分析与自动化测试工具。
* **scaaml** – 基于 TensorFlow 的 deep-learning SCA 工具和数据集。<sup>[[12]](#references)</sup>
* **pyecsca** – 用于通过侧信道对黑盒 ECC 实现进行逆向工程的开源工具包。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer 文档](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed 攻击论文](https://www.hertzbleed.com/)
- [3] [Downfall：利用推测性数据收集](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception：通过瞬态执行训练揭示新的攻击面](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [通过低带宽声学密码分析提取 RSA 密钥](https://eprint.iacr.org/2013/857.pdf)
- [7] [来自光学辐射的信息泄漏](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca 工件文档](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [针对键盘的实用深度学习声学侧信道攻击](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER 用户手册](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer 文档 — CW503 探头电源](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML 文档](https://google.github.io/scaaml/)
- [13] [FOSDEM — 使用 RTL-SDR 执行低成本电磁侧信道攻击](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [解码知识产权：针对 3D 打印机的声学与磁性侧信道攻击](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — 针对打印机的声学侧信道攻击](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [利用 DRAM 窃听温度](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
