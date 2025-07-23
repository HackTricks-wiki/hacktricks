# 侧信道分析攻击

{{#include ../../banners/hacktricks-training.md}}

侧信道攻击通过观察与内部状态*相关*的物理或微架构“泄漏”来恢复秘密，但这些“泄漏”*不是*设备逻辑接口的一部分。 示例包括测量智能卡瞬时电流到滥用网络上的CPU电源管理效应。

---

## 主要泄漏通道

| 通道 | 典型目标 | 仪器 |
|---------|---------------|-----------------|
| 功耗 | 智能卡、物联网MCU、FPGA | 示波器 + 分流电阻/高频探头（例如CW503） |
| 电磁场（EM） | CPU、RFID、AES加速器 | H场探头 + LNA，ChipWhisperer/RTL-SDR |
| 执行时间/缓存 | 桌面和云CPU | 高精度计时器（rdtsc/rdtscp），远程飞行时间 |
| 声学/机械 | 键盘、3D打印机、继电器 | MEMS麦克风，激光振动计 |
| 光学和热 | LED、激光打印机、DRAM | 光电二极管/高速相机，红外相机 |
| 故障诱导 | ASIC/MCU加密 | 时钟/电压故障，EMFI，激光注入 |

---

## 功率分析

### 简单功率分析（SPA）
观察*单个*波形并直接将峰值/谷值与操作（例如DES S盒）关联。
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
获取 *N > 1 000* 跟踪，假设密钥字节 `k`，计算 HW/HD 模型并与泄漏进行相关性分析。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPA 仍然是最先进的，但机器学习变体（MLA，深度学习 SCA）现在主导了 ASCAD-v2（2023）等比赛。

---

## 电磁分析 (EMA)
近场 EM 探头（500 MHz–3 GHz）泄漏与功率分析相同的信息 *而不* 插入分流器。2024 年的研究表明，使用频谱相关和低成本 RTL-SDR 前端可以在 **>10 cm** 的距离内从 STM32 恢复密钥。

---

## 时序与微架构攻击
现代 CPU 通过共享资源泄漏秘密：
* **Hertzbleed (2022)** – DVFS 频率缩放与 Hamming 权重相关，允许 *远程* 提取 EdDSA 密钥。
* **Downfall / Gather Data Sampling (Intel, 2023)** – 瞬态执行读取 SMT 线程中的 AVX-gather 数据。
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – 投机向量误预测泄漏跨域寄存器。

有关 Spectre 类问题的广泛处理，请参见 {{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}

---

## 声学与光学攻击
* 2024 年的 "​iLeakKeys" 显示从 **智能手机麦克风通过 Zoom** 恢复笔记本电脑按键的准确率为 95% ，使用 CNN 分类器。
* 高速光电二极管捕获 DDR4 活动 LED，并在 <1 分钟内重构 AES 轮密钥（BlackHat 2023）。

---

## 故障注入与差分故障分析 (DFA)
将故障与侧信道泄漏结合可以快捷地搜索密钥（例如 1-trace AES DFA）。最近的业余爱好者价格工具：
* **ChipSHOUTER & PicoEMP** – 亚 1 ns 电磁脉冲故障。
* **GlitchKit-R5 (2025)** – 开源时钟/电压故障平台，支持 RISC-V SoC。

---

## 典型攻击工作流程
1. 确定泄漏通道和安装点（VCC 引脚，去耦电容，近场点）。
2. 插入触发器（GPIO 或基于模式）。
3. 收集 >1 k 跟踪，使用适当的采样/过滤器。
4. 预处理（对齐，均值去除，低通/高通滤波，小波，PCA）。
5. 统计或 ML 密钥恢复（CPA，MIA，DL-SCA）。
6. 验证并对异常值进行迭代。

---

## 防御与加固
* **恒定时间** 实现和内存硬算法。
* **掩码/洗牌** – 将秘密分割成随机份额；第一阶抗性由 TVLA 认证。
* **隐藏** – 芯片内电压调节器，随机时钟，双轨逻辑，EM 屏蔽。
* **故障检测** – 冗余计算，阈值签名。
* **操作** – 在加密内核中禁用 DVFS/涡轮，隔离 SMT，禁止在多租户云中共存。

---

## 工具与框架
* **ChipWhisperer-Husky** (2024) – 500 MS/s 示波器 + Cortex-M 触发器；Python API 如上。
* **Riscure Inspector & FI** – 商业，支持自动泄漏评估（TVLA-2.0）。
* **scaaml** – 基于 TensorFlow 的深度学习 SCA 库（v1.2 – 2025）。
* **pyecsca** – ANSSI 开源 ECC SCA 框架。

---

## 参考文献

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
