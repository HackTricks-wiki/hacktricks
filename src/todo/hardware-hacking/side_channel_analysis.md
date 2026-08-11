# サイドチャネル解析攻撃

{{#include ../../banners/hacktricks-training.md}}

サイドチャネル攻撃は、デバイスの論理インターフェースの一部ではないものの、内部状態と*相関する*物理的またはマイクロアーキテクチャ上の「漏洩」を観測することで秘密情報を復元します。例として、スマートカードが瞬間的に消費する電流の測定から、ネットワーク経由でCPUの電力管理による影響を悪用するものまであります。

---

## 主な漏洩チャネル

| チャネル | 典型的な対象 | 計測機器 |
|---------|---------------|-----------------|
| 消費電力 | スマートカード、IoT MCU、FPGA | オシロスコープとシャント抵抗または差動プローブ。CW503はプローブ/LNA用の電源であり、それ自体がプローブではありません<sup>[[11]](#references)</sup> |
| 電磁場（EM） | CPU、RFID、AESアクセラレータ | Hフィールド/近磁界プローブと低ノイズアンプ、およびオシロスコープまたはRTL-SDRなどのSDRレシーバー<sup>[[13]](#references)</sup> |
| 実行時間 / キャッシュ | デスクトップおよびcloud CPU | 高精度タイマー（`rdtsc`/`rdtscp`）またはリモートのtime-of-flight |
| 音響 / 機械 | キーボード、3-Dプリンター、プリンター、リレー、CPU電圧レギュレーター | MEMSマイクまたはレーザー振動計<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学および熱 | ステータスLED、ディスプレイ、DRAM、熱的に結合されたデバイス | フォトダイオード、高速度カメラ、または赤外線カメラ<sup>[[7]](#references)[[16]](#references)</sup> |
| フォールトインジェクション | ASIC/MCU暗号処理 | クロック/電圧グリッチ、EMFI、またはレーザーインジェクション |

---

## Power Analysis

### Simple Power Analysis (SPA)
*単一の*トレースを観測し、分岐、モジュラー乗算、異なる命令シーケンスなどの演算と、目視可能な特徴を関連付けます。<sup>[[1]](#references)</sup>

正確なセットアップは対象によって異なります。以下では、scopeとtargetを接続して設定した後の、現行の高レベルChipWhisperer capture APIを使用します。<sup>[[1]](#references)</sup>
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
複数のトレースを取得し、鍵バイト `k` を仮定して、Hamming-weight (HW) または Hamming-distance (HD) の漏洩モデルを計算し、それを各サンプルと相関させます。必要なトレース数は対象、ノイズ、アライメント、対策、漏洩モデルによって決まり、固定されたしきい値ではありません。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは標準的なベースラインです。leakが非線形である場合や、traceのアライメントが不十分な場合は、Template attacks、mutual-information analysis、machine-learning approachesが有用です。

---

## 電磁波解析 (EMA)
近傍界EM解析では、電源経路にシャントを挿入せずに、データ依存の活動を観測できます。ただし、必ずしもpower traceと同じ信号が得られるわけではありません。probeの位置、向き、帯域幅、フロントエンドのゲイン、triggerの品質、距離がすべて影響します。

---

## Timing & Micro-architectural Attacks
現代のCPUは、共有リソースを通じてsecretをleakします。
* **Hertzbleed (2022)** – データ依存のdynamic voltage and frequency scalingにより、remote timing channelが作られます。最初のend-to-end key-recoveryの実証ではSIKEが対象となり、後続研究では他のprimitiveも扱われています。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – Transient executionにより、security boundaryを越えてvector gather instructionsが使用するデータを露出させられます。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – speculative vector-register stateの不適切な処理により、同じphysical coreからデータを開示できます。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – Transient-execution attackで、phantom executionとtransient executionにおけるtrainingを組み合わせ、attacker-controlled misprediction gadgetsを作成します。<sup>[[5]](#references)</sup>

---

## 音響・光学攻撃
音響leakageは、制御された実験において、ノートPCのノイズからRSA keyを復元するために利用されています。近くにある携帯電話のマイクも使用されています。<sup>[[6]](#references)</sup> 別の2023年のkeyboard研究では、近くのphoneで録音したデータでtrainingした場合にkeystrokeを95%の精度で分類し、Zoom audioでtrainingした場合には93%の精度で分類しました。これらの数値は、その論文におけるtrained-device experimentを示すものであり、任意のkeyboardやvictimに適用できるものではありません。<sup>[[9]](#references)</sup> status LEDからのoptical emanationsも、処理されたデータと相関させることができます。これらの結果はtargetとsetupに依存するため、無関係なデバイスにその到達距離や成功率を一般化しないでください。<sup>[[7]](#references)</sup>

---

## Fault Injection & Differential Fault Analysis (DFA)
制御されたfaultとside-channel observationsを組み合わせることで、一部のalgorithmやimplementationではkey searchを削減できます。一般的なlab platformには、ChipWhispererのvoltage/clock glitching機能や、ChipSHOUTER、PicoEMPなどの専用EM fault-injection toolがあります。以前のdraftにあった「sub-1 ns」という説明は仕様として使用すべきではありません。ChipSHOUTERの公開manualには、1 mm tipで通常のinserted-pulse widthが**15–80 ns**、4 mm tipで**24–480 ns**と記載されています（ただし、trigger/pulse jitterはpicosecond単位で仕様化されています）。必要なtiming resolution、probe placement、faulty outputの数は、targetとfault modelによって異なります。<sup>[[1]](#references)[[10]](#references)</sup>

## 以前のdraftから保持された未検証のResearch Leads

以前のdraftでは、**500 MHz–3 GHz**のEM setupにより、RTL-SDRを使って**10 cm**以上離れた場所からSTM32 keyを復元したこと、DDR4 activity LEDが「Black Hat 2023」で1分未満にAES round keyを明らかにしたこと、そしてGlitchKit-R5という2025年のopen-source RISC-V glitching platformも主張されていました。このaudit中に、一致するprimary paper、conference material、project repositoryは確認できませんでした。これらの正確な詳細は、確立された結果やtooling recommendationではなく、検索・再現の手がかりとして保持されています。

---

## 典型的な攻撃ワークフロー
1. leakage channelとmount point（VCC pin、decoupling cap、near-field spot）を特定する。
2. trigger（GPIOまたはpattern-based）を挿入する。
3. 選択したstatistical testに十分な数のtraceを収集し、plaintext/ciphertextやその他のmetadataを記録する。
4. Pre-processする（alignment、mean removal、LP/HP filter、wavelet、PCA）。
5. StatisticalまたはMLによるkey recovery（CPA、MIA、DL-SCA）。
6. outlierを検証し、反復する。

---

## 防御とHardening
* **Constant-time** implementationとmemory-hard algorithm。
* **Masking/shuffling** – secretをrandom shareに分割し、first-order resistanceをTVLAでcertifyする。
* **Hiding** – on-chip voltage regulator、randomised clock、dual-rail logic、EM shield。
* **Fault detection** – redundant computation、threshold signature。
* **Operational** – crypto kernelでDVFS/turboを無効化し、SMTを分離し、multi-tenant cloudでのco-locationを禁止する。

---

## Tools & Frameworks
* **ChipWhisperer-Husky** (2024) – 500 MS/s scope + Cortex-M trigger。上記のPython APIを使用します。<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – commercial analysisおよびautomated test tooling。
* **scaaml** – TensorFlowベースのdeep-learning SCA toolingおよびdataset。<sup>[[12]](#references)</sup>
* **pyecsca** – side channelを通じてblack-box ECC implementationをreverse-engineeringするためのopen-source toolkit。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhispererドキュメント](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed攻撃論文](https://www.hertzbleed.com/)
- [3] [Downfall: Speculative Data Gatheringの悪用](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: Transient ExecutionにおけるTrainingによる新たな攻撃対象領域の露出](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [低帯域音響CryptanalysisによるRSA Keyの抽出](https://eprint.iacr.org/2013/857.pdf)
- [7] [Optical EmanationsからのInformation Leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca artifactドキュメント](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [Keyboardに対する実用的なDeep LearningベースのAcoustic Side Channel Attack](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTER user manual](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhispererドキュメント — CW503 probe power supply](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAMLドキュメント](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDRを使用した低コストな電磁side-channel attackの実行](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [Intellectual PropertyのDecode: 3-D Printerに対するAcoustic and Magnetic Side-Channel Attack](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — Printerに対するAcoustic Side-Channel Attack](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAMを使用したTemperatureの盗聴](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
