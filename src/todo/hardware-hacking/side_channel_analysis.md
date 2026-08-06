# サイドチャネル解析攻撃

{{#include ../../banners/hacktricks-training.md}}

サイドチャネル攻撃は、デバイスの論理インターフェースの一部ではないものの、内部状態と*相関する*物理的またはマイクロアーキテクチャ上の「leakage」を観測することで、秘密情報を復元します。例として、スマートカードが瞬間的に消費する電流の測定から、ネットワーク経由でCPUの電力管理による影響を悪用する手法まであります。

---

## 主なLeakageチャネル

| チャネル | 典型的な対象 | 計測機器 |
|---------|---------------|-----------------|
| 電力消費 | スマートカード、IoT MCU、FPGA | オシロスコープ + シャント抵抗/HSプローブ（例: CW503） |
| 電磁界（EM） | CPU、RFID、AESアクセラレータ | H-fieldプローブ + LNA、ChipWhisperer/RTL-SDR |
| 実行時間 / キャッシュ | デスクトップおよびクラウドCPU | 高精度タイマー（rdtsc/rdtscp）、リモートtime-of-flight |
| 音響 / 機械 | キーボード、3-Dプリンター、リレー | MEMSマイク、レーザー振動計 |
| 光学および熱 | LED、レーザープリンター、DRAM | フォトダイオード / 高速カメラ、赤外線カメラ |
| Fault-induced | ASIC/MCU暗号 | クロック/電圧glitch、EMFI、レーザー注入 |

---

## 電力解析

### Simple Power Analysis (SPA)
*単一の*traceを観測し、ピーク/谷を操作（例: DES S-box）に直接関連付けます。<sup>[[1]](#references)</sup>
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
トレースを *N > 1 000* 件取得し、鍵バイト `k` を仮定し、HW/HD モデルを計算して leakage と相関させる。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは依然としてstate-of-the-artですが、machine-learning variants（MLA、deep-learning SCA）が現在ではASCAD-v2（2023）のようなcompetitionを席巻しています。

---

## Electromagnetic Analysis (EMA)
Near-field EM probes（500 MHz–3 GHz）は、shuntを挿入することなくpower analysisと同一の情報をleakします。2024年の研究では、spectrum correlationと低コストのRTL-SDR front-endsを使用し、STM32から**10 cm超**離れた位置でのkey recoveryが実証されました。

---

## Timing & Micro-architectural Attacks
Modern CPUsは、共有リソースを通じてsecretをleakします：
* **Hertzbleed (2022)** – DVFS frequency scalingがHamming weightと相関し、EdDSA keysの*remote* extractionを可能にします。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-executionにより、SMT threads間でAVX-gather dataを読み取ります。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-predictionにより、domainをまたいでregistersをleakします。<sup>[[4]](#references)</sup><sup>[[5]](#references)</sup>

---

## Acoustic & Optical Attacks
* 2024年の「​iLeakKeys」では、CNN classifierを使用し、**Zoom経由のsmart-phone microphone**からlaptop keystrokesを95 %のaccuracyでrecoverできることが示されました。
* High-speed photodiodesはDDR4 activity LEDをcaptureし、1分未満でAES round keysをreconstructします（BlackHat 2023）。

---

## Fault Injection & Differential Fault Analysis (DFA)
faultsとside-channel leakageを組み合わせることで、key searchを短縮できます（例：1-trace AES DFA）。近年のhobbyist向け価格帯のtools：
* **ChipSHOUTER & PicoEMP** – 1 ns未満のelectromagnetic pulse glitching。
* **GlitchKit-R5 (2025)** – RISC-V SoCsをサポートするopen-source clock/voltage glitch platform。

---

## Typical Attack Workflow
1. leakage channelとmount pointを特定します（VCC pin、decoupling cap、near-field spot）。
2. triggerを挿入します（GPIOまたはpattern-based）。
3. 適切なsampling/filtersを使用して、1 k以上のtracesをcollectします。
4. Pre-processします（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. StatisticalまたはMLによるkey recoveryを実行します（CPA、MIA、DL-SCA）。
6. 検証し、outliersについてiterateします。

---

## Defences & Hardening
* **Constant-time** implementationsとmemory-hard algorithms。
* **Masking/shuffling** – secretをrandom sharesに分割し、TVLAによってfirst-order resistanceをcertifyします。
* **Hiding** – on-chip voltage regulators、randomised clock、dual-rail logic、EM shields。
* **Fault detection** – redundant computation、threshold signatures。
* **Operational** – crypto kernelsでDVFS/turboをdisableし、SMTをisolateし、multi-tenant cloudsでのco-locationをprohibitします。

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger。Python APIは上記と同様です。<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial製品で、automated leakage assessment（TVLA-2.0）をサポートします。
* **scaaml** – TensorFlow-based deep-learning SCA library（v1.2 – 2025）。
* **pyecsca** – ANSSIのopen-source ECC SCA framework。

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)
- [3] [Downfall: Exploiting Speculative Data Gathering](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Exposing New Attack Surfaces with Training in Transient Execution](https://comsec.ethz.ch/research/microarch/inception/)

{{#include ../../banners/hacktricks-training.md}}
