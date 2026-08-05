# Side Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks は、デバイスの論理インターフェースの一部ではないものの、内部状態と*相関する*物理的またはマイクロアーキテクチャ上の「leakage」を観測することで秘密情報を復元します。例として、スマートカードが瞬間的に消費する電流の測定から、ネットワーク経由で CPU の電力管理による影響を悪用する手法まであります。

---

## Main Leakage Channels

| Channel | Typical Target | Instrumentation |
|---------|---------------|-----------------|
| Power consumption | スマートカード、IoT MCU、FPGA | オシロスコープ + シャント抵抗/HS probe（例: CW503） |
| Electromagnetic field (EM) | CPU、RFID、AES accelerators | H-field probe + LNA、ChipWhisperer/RTL-SDR |
| Execution time / caches | デスクトップおよびクラウドの CPU | 高精度タイマー（rdtsc/rdtscp）、リモート time-of-flight |
| Acoustic / mechanical | キーボード、3-D プリンター、リレー | MEMS microphone、laser vibrometer |
| Optical & thermal | LED、レーザープリンター、DRAM | Photodiode / high-speed camera、IR camera |
| Fault-induced | ASIC/MCU cryptos | Clock/voltage glitch、EMFI、laser injection |

---

## Power Analysis

### Simple Power Analysis (SPA)
単一の*trace*を観測し、ピークや谷を操作（例: DES S-boxes）に直接関連付けます。
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
* N > 1 000* 個の trace を取得し、key byte `k` を仮定して、HW/HD model を計算し、leakage と相関させる。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは依然としてstate-of-the-artですが、現在ではASCAD-v2（2023）などのコンペティションでmachine-learning variants（MLA、deep-learning SCA）が主流です。

---

## Electromagnetic Analysis (EMA)
Near-field EM probes（500 MHz–3 GHz）は、shuntを挿入せずにpower analysisと同一の情報をleakします。2024年の研究では、spectrum correlationと低コストのRTL-SDR front-endを使用し、STM32から**10 cm超**離れた位置でのkey recoveryが実証されました。

---

## Timing & Micro-architectural Attacks
Modern CPUsは、共有リソースを通じてsecretをleakします:
* **Hertzbleed (2022)** – DVFSのfrequency scalingがHamming weightと相関し、EdDSA keysの*remote* extractionを可能にします。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – transient-executionにより、SMT threads間でAVX-gather dataを読み取ります。
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – speculative vector mis-predictionにより、domainをまたいでregistersをleakします。

---

## Acoustic & Optical Attacks
* 2024年の「​iLeakKeys」では、CNN classifierを使用し、**smart-phone microphone over Zoom**からlaptop keystrokesを95 %のaccuracyでrecoverできることが示されました。
* High-speed photodiodesはDDR4 activity LEDをcaptureし、1分未満でAES round keysをreconstructします（BlackHat 2023）。

---

## Fault Injection & Differential Fault Analysis (DFA)
faultとside-channel leakageを組み合わせることで、key searchを短縮できます（例: 1-trace AES DFA）。近年のhobbyist-priced tools:
* **ChipSHOUTER & PicoEMP** – 1 ns未満のelectromagnetic pulse glitching。
* **GlitchKit-R5 (2025)** – RISC-V SoCsをサポートするopen-source clock/voltage glitch platform。

---

## Typical Attack Workflow
1. leakage channelとmount point（VCC pin、decoupling cap、near-field spot）を特定する。
2. trigger（GPIOまたはpattern-based）を挿入する。
3. 適切なsampling/filtersを使用して、1 k trace超をcollectする。
4. Pre-processする（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. StatisticalまたはML key recoveryを行う（CPA、MIA、DL-SCA）。
6. outliersをvalidateし、iterateする。

---

## Defences & Hardening
* **Constant-time** implementationsとmemory-hard algorithms。
* **Masking/shuffling** – secretをrandom sharesに分割し、TVLAによってfirst-order resistanceをcertifyする。
* **Hiding** – on-chip voltage regulators、randomised clock、dual-rail logic、EM shields。
* **Fault detection** – redundant computation、threshold signatures。
* **Operational** – crypto kernelsでDVFS/turboをdisableし、SMTをisolateし、multi-tenant cloudsでのco-locationをprohibitする。

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger。上記のPython API。<sup>[[1]](#references)</sup>
* **Riscure Inspector & FI** – commercial製品で、automated leakage assessment（TVLA-2.0）をサポート。
* **scaaml** – TensorFlowベースのdeep-learning SCA library（v1.2 – 2025）。
* **pyecsca** – ANSSIのopen-source ECC SCA framework。

---

## References

- [1] [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
