# サイドチャネル分析攻撃

{{#include ../../banners/hacktricks-training.md}}

サイドチャネル攻撃は、内部状態と*相関*のある物理的またはマイクロアーキテクチャの「漏洩」を観察することによって秘密を回収しますが、デバイスの論理インターフェースの一部ではありません。例としては、スマートカードによって引き出される瞬時の電流を測定することから、ネットワーク上でのCPUの電力管理効果を悪用することまで多岐にわたります。

---

## 主な漏洩チャネル

| チャネル | 典型的なターゲット | 計測機器 |
|---------|---------------|-----------------|
| 電力消費 | スマートカード、IoT MCU、FPGA | オシロスコープ + シャント抵抗/HSプローブ (例: CW503) |
| 電磁場 (EM) | CPU、RFID、AESアクセラレーター | Hフィールドプローブ + LNA、ChipWhisperer/RTL-SDR |
| 実行時間 / キャッシュ | デスクトップ & クラウドCPU | 高精度タイマー (rdtsc/rdtscp)、リモート飛行時間 |
| 音響 / 機械的 | キーボード、3Dプリンター、リレー | MEMSマイクロフォン、レーザー振動計 |
| 光学 & 熱 | LED、レーザープリンター、DRAM | フォトダイオード / 高速カメラ、IRカメラ |
| 故障誘発 | ASIC/MCU暗号 | クロック/電圧グリッチ、EMFI、レーザー注入 |

---

## 電力分析

### シンプル電力分析 (SPA)
*単一*のトレースを観察し、ピーク/谷を操作 (例: DES Sボックス) に直接関連付けます。
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
*N > 1 000* トレースを取得し、キー バイト `k` を仮定し、HW/HD モデルを計算し、漏洩と相関させます。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは最先端の技術ですが、機械学習のバリアント（MLA、深層学習SCA）がASCAD-v2（2023）などの競技会で支配的になっています。

---

## 電磁分析 (EMA)
近接場EMプローブ（500 MHz–3 GHz）は、シャントを挿入することなく、電力分析と同じ情報を漏洩します。2024年の研究では、スペクトル相関と低コストのRTL-SDRフロントエンドを使用して、**>10 cm**の距離からSTM32のキー回復が実証されました。

---

## タイミングおよびマイクロアーキテクチャ攻撃
現代のCPUは共有リソースを通じて秘密を漏洩します：
* **Hertzbleed (2022)** – DVFS周波数スケーリングがハミング重みと相関し、*リモート*でEdDSAキーを抽出可能にします。
* **Downfall / Gather Data Sampling (Intel, 2023)** – 一時実行を使用して、SMTスレッド間でAVX-gatherデータを読み取ります。
* **Zenbleed (AMD, 2023) & Inception (AMD, 2023)** – 投機的ベクトル誤予測がクロスドメインでレジスタを漏洩します。

Spectreクラスの問題についての広範な扱いについては、{{#ref}}
../../cpu-microarchitecture/microarchitectural-attacks.md
{{#endref}}をご覧ください。

---

## 音響および光学攻撃
* 2024年の「iLeakKeys」は、CNN分類器を使用して**スマートフォンのマイクからZoom経由で**ノートパソコンのキーストロークを95%の精度で回復することを示しました。
* 高速フォトダイオードはDDR4アクティビティLEDをキャプチャし、AESラウンドキーを1分未満で再構築します（BlackHat 2023）。

---

## フォルトインジェクションおよび差分フォルト分析 (DFA)
フォルトとサイドチャネル漏洩を組み合わせることで、キー検索をショートカットします（例：1トレースAES DFA）。最近のホビー向け価格のツール：
* **ChipSHOUTER & PicoEMP** – 1 ns未満の電磁パルスグリッチ。
* **GlitchKit-R5 (2025)** – RISC-V SoCをサポートするオープンソースのクロック/電圧グリッチプラットフォーム。

---

## 典型的な攻撃ワークフロー
1. 漏洩チャネルとマウントポイントを特定する（VCCピン、デカップリングキャップ、近接場スポット）。
2. トリガーを挿入する（GPIOまたはパターンベース）。
3. 適切なサンプリング/フィルターで>1 kトレースを収集する。
4. 前処理（アライメント、平均除去、LP/HPフィルター、ウェーブレット、PCA）。
5. 統計的またはMLキー回復（CPA、MIA、DL-SCA）。
6. 外れ値を検証し、反復する。

---

## 防御および強化
* **定数時間**実装およびメモリハードアルゴリズム。
* **マスキング/シャッフル** – 秘密をランダムなシェアに分割；第一順抵抗はTVLAによって認証されています。
* **隠蔽** – チップ上の電圧レギュレーター、ランダム化されたクロック、デュアルレールロジック、EMシールド。
* **フォルト検出** – 冗長計算、しきい値署名。
* **運用** – 暗号カーネルでDVFS/ターボを無効にし、SMTを隔離し、マルチテナントクラウドでの共存を禁止します。

---

## ツールおよびフレームワーク
* **ChipWhisperer-Husky** (2024) – 500 MS/sスコープ + Cortex-Mトリガー；上記のPython API。
* **Riscure Inspector & FI** – 商用、自動漏洩評価（TVLA-2.0）をサポート。
* **scaaml** – TensorFlowベースの深層学習SCAライブラリ（v1.2 – 2025）。
* **pyecsca** – ANSSIオープンソースECC SCAフレームワーク。

---

## 参考文献

* [ChipWhisperer Documentation](https://chipwhisperer.readthedocs.io/en/latest/)
* [Hertzbleed Attack Paper](https://www.hertzbleed.com/)


{{#include ../../banners/hacktricks-training.md}}
