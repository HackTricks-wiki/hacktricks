# 侧信道分析攻击

{{#include ../../banners/hacktricks-training.md}}

侧信道攻击通过观察物理或微架构层面的“leakage”来恢复机密信息。这些“leakage”与内部状态*相关*，但并非设备逻辑接口的一部分。例子包括测量智能卡的瞬时电流，以及通过网络利用 CPU 电源管理效应。

对于可访问 ARM 调试硬件的目标，[通过 SWO 进行 CoreSight ETM 跟踪](arm-coresight-instruction-tracing.md)可以在采集功耗或 EM 数据时提供执行路径参考；它是调试跟踪，而不是泄漏通道。<sup>[[17]](#references)</sup>

---

## 主要泄漏通道

| 通道 | 典型目标 | 仪器设备 |
|---------|---------------|-----------------|
| 功耗 | 智能卡、IoT MCU、FPGA | 示波器加分流电阻或差分探头；CW503 是为探头/LNA 供电的电源，不是探头本身<sup>[[11]](#references)</sup> |
| 电磁场 (EM) | CPU、RFID、AES 加速器 | H 场/近场探头加低噪声放大器，以及示波器或 RTL-SDR 等 SDR 接收器<sup>[[13]](#references)</sup> |
| 执行时间 / 缓存 | 桌面和云端 CPU | 高精度计时器（`rdtsc`/`rdtscp`）或远程飞行时间测量 |
| 声学 / 机械 | 键盘、3-D 打印机、打印机、继电器和 CPU 电压调节器 | MEMS 麦克风或激光测振仪<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学与热 | 状态 LED、显示器、DRAM 和热耦合设备 | 光电二极管、高速摄像机或红外摄像机<sup>[[7]](#references)[[16]](#references)</sup> |
| 故障注入 | ASIC/MCU 密码系统 | 时钟/电压 glitch、EMFI 或激光注入 |

---

## 功耗分析

### 简单功耗分析 (SPA)
观察*单条*轨迹，并将可见特征与分支、模乘或不同指令序列等操作联系起来。<sup>[[1]](#references)</sup>

具体设置取决于目标。以下示例使用 ChipWhisperer 当前的高级采集 API，前提是示波器和目标设备已连接并配置：<sup>[[1]](#references)</sup>

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

### 差分/相关功耗分析 (DPA/CPA)
采集多条轨迹，假设一个密钥字节 `k`，计算汉明重量 (HW) 或汉明距离 (HD) 泄漏模型，并将其与每个采样点进行相关性分析。所需轨迹数量取决于目标、噪声、对齐情况、对策和泄漏模型；它不是一个固定阈值。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA 是标准基线。当 leak 呈非线性或 traces 对齐不佳时，模板攻击、互信息分析和机器学习方法可能会有用。

---

## 电磁分析 (EMA)
近场 EM 分析可以观测与数据相关的活动，而无需在电源路径中串入分流器。它不一定会暴露与功耗 trace 相同的信号：探头位置、方向、带宽、前端增益、触发质量和距离都会产生影响。

---

## 时序与微架构攻击
现代 CPU 会通过共享资源泄漏秘密：
* **Hertzbleed (2022)** – 与数据相关的动态电压和频率调节会形成远程时序通道。最初的端到端密钥恢复演示针对 SIKE；后续工作则讨论了其他原语。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – 瞬态执行可以跨越安全边界，暴露向量 gather 指令使用的数据。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 对推测执行中的向量寄存器状态处理不当，可能泄露同一物理核心中的数据。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 一种瞬态执行攻击，将 phantom execution 与瞬态执行训练结合，构造攻击者可控的错误预测 gadget。<sup>[[5]](#references)</sup>

---

## 声学与光学攻击
在受控实验中，研究人员曾利用笔记本电脑噪声恢复 RSA 密钥，其中包括使用附近手机的麦克风进行录音。<sup>[[6]](#references)</sup> 另一项 2023 年的键盘研究表明，使用附近手机录音进行训练时，按键分类准确率为 95%；使用 Zoom 音频进行训练时，准确率为 93%。这些数字描述的是该论文中针对训练设备进行的实验，并不代表任意键盘或受害者的情况。<sup>[[9]](#references)</sup> 状态 LED 的光学辐射也可以与处理中的数据相关联。这些结果取决于具体目标和实验设置；不要将其范围或成功率泛化到无关设备。<sup>[[7]](#references)</sup>

---

## 故障注入与差分故障分析 (DFA)
将受控故障与侧信道观测结合，可以缩小某些算法和实现的密钥搜索范围。常见实验平台包括 ChipWhisperer 的电压/时钟 glitching 功能，以及 ChipSHOUTER 或 PicoEMP 等专用 EM 故障注入工具。早期草稿中的“低于 1 ns”描述不应作为规格使用：ChipSHOUTER 已发布的手册列出的典型注入脉冲宽度为使用 1 mm 探头尖端时 **15–80 ns**，使用 4 mm 探头尖端时为 **24–480 ns**（但触发/脉冲抖动的规格以皮秒计）。所需的时序分辨率、探头位置和故障输出数量取决于目标和故障模型。<sup>[[1]](#references)[[10]](#references)</sup>

## 保留自早期草稿的未验证研究线索

早期草稿还声称：一套 **500 MHz–3 GHz** 的 EM 装置使用 RTL-SDR 从 **10 cm** 以上距离恢复 STM32 密钥；DDR4 活动 LED 在“Black Hat 2023”上不到一分钟便泄露 AES 轮密钥；以及一个名为 **GlitchKit-R5** 的 2025 年开源 RISC-V glitching 平台。本次审查未能找到相匹配的主要论文、会议资料或项目仓库。这些具体信息仅作为搜索/复现实验线索保留，不应视为已证实的结果或工具推荐。

---

## 典型攻击工作流
1. 确定泄漏通道和安装点（VCC 引脚、去耦电容、近场位置）。
2. 插入触发器（GPIO 或基于模式的触发器）。  
3. 为所选统计检验收集足够的 traces，并记录明文/密文及其他元数据。
4. 预处理（对齐、去均值、LP/HP 滤波、小波、PCA）。
5. 使用统计方法或 ML 恢复密钥（CPA、MIA、DL-SCA）。
6. 验证并针对异常值迭代调整。

---

## 防御与加固
* **恒定时间**实现与内存困难算法。
* **Masking/shuffling** – 将秘密拆分为随机份额；通过 TVLA 认证一阶抗性。
* **隐藏** – 片上电压调节器、随机化时钟、双轨逻辑、EM 屏蔽。
* **故障检测** – 冗余计算、阈值签名。
* **运维措施** – 在加密内核中禁用 DVFS/turbo、隔离 SMT、禁止在多租户云中共置。

---

## 工具与框架
* **ChipWhisperer-Husky** (2024) – 500 MS/s 示波器 + Cortex-M 触发器；Python API 同上。<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – 商用分析和自动化测试工具。
* **scaaml** – 基于 TensorFlow 的深度学习 SCA 工具和数据集。<sup>[[12]](#references)</sup>
* **pyecsca** – 用于通过侧信道对黑盒 ECC 实现进行逆向工程的开源工具包。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhisperer 文档](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed 攻击论文](https://www.hertzbleed.com/)
- [3] [Downfall：利用推测性数据收集](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception：通过瞬态执行训练揭示新的攻击面](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [通过低带宽声学密码分析提取 RSA 密钥](https://eprint.iacr.org/2013/857.pdf)
- [7] [光学辐射中的信息泄漏](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca 工件文档](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [针对键盘的实用深度学习声学侧信道攻击](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER 用户手册](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhisperer 文档 — CW503 探头电源](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAML 文档](https://google.github.io/scaaml/)
- [13] [FOSDEM — 使用 RTL-SDR 执行低成本电磁侧信道攻击](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [解码知识产权：针对 3D 打印机的声学与磁性侧信道攻击](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — 针对打印机的声学侧信道攻击](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [利用 DRAM 监测温度](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [跟踪指令：使用 ETM、ITM 和 TPIU 进行 ARM 实时跟踪](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
