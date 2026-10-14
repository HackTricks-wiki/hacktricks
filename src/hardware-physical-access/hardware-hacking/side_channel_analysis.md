# Side-Channel Analysis Attacks

{{#include ../../banners/hacktricks-training.md}}

Side-channel attacks は、デバイスの内部状態と *相関* する一方で、デバイスの論理インターフェースには含まれない物理的またはマイクロアーキテクチャ上の「leakage」を観測して秘密を復元します。例として、スマートカードが瞬間的に消費する電流の測定から、ネットワーク経由でCPUの電力管理効果を悪用する手法まであります。

---

## 主なLeakageチャネル

| チャネル | 典型的なターゲット | 計測機器 |
|---------|---------------|-----------------|
| 電力消費 | スマートカード、IoT MCU、FPGA | オシロスコープとシャント抵抗または差動プローブ。CW503はプローブ/LNA用の電源であり、それ自体はプローブではありません<sup>[[11]](#references)</sup> |
| 電磁界（EM） | CPU、RFID、AESアクセラレーター | H-field/近接場プローブと低ノイズアンプ、およびオシロスコープまたはRTL-SDRなどのSDR受信機<sup>[[13]](#references)</sup> |
| 実行時間 / キャッシュ | デスクトップおよびクラウドのCPU | 高精度タイマー（`rdtsc`/`rdtscp`）またはリモートの伝搬時間 |
| 音響 / 機械的振動 | キーボード、3-Dプリンター、プリンター、リレー、CPU電圧レギュレーター | MEMSマイクまたはレーザー振動計<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学 / 熱 | ステータスLED、ディスプレイ、DRAM、熱的に結合したデバイス | フォトダイオード、高速カメラ、または赤外線カメラ<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCUの暗号処理 | クロック/電圧グリッチ、EMFI、またはレーザー照射 |

---

## Power Analysis

### Simple Power Analysis (SPA)
*単一の*トレースを観察し、目に見える特徴を分岐、剰余乗算、異なる命令シーケンスなどの処理と関連付けます。<sup>[[1]](#references)</sup>

正確なセットアップはターゲットによって異なります。以下では、スコープとターゲットを接続して設定した後に使用する、現行のChipWhisperer高レベルキャプチャAPIを示します。<sup>[[1]](#references)</sup>

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
複数の traces を取得し、鍵バイト `k` を仮定して、Hamming-weight (HW) または Hamming-distance (HD) の leakage model を計算し、各サンプルとの相関を求めます。必要な trace 数は対象、ノイズ、アライメント、対策、leakage model によって決まり、固定のしきい値はありません。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは標準的なベースラインです。leakageが非線形である場合や、トレースの位置合わせが不十分な場合は、Template attacks、mutual-information analysis、機械学習の手法が有効です。

---

## 電磁解析（EMA）
近傍界EM解析では、電源経路にシャントを挿入せずに、データに依存する動作を観測できます。ただし、必ずしも電力トレースと同じ信号が得られるわけではありません。プローブの位置、向き、帯域幅、フロントエンドのゲイン、トリガーの品質、距離がすべて影響します。

---

## タイミング攻撃とマイクロアーキテクチャ攻撃
最新のCPUは、共有リソースを通じて秘密情報をleakします。
* **Hertzbleed (2022)** – データに依存する動的な電圧・周波数スケーリングによって、リモートタイミングチャネルが生じます。最初のエンドツーエンドの鍵回復実証ではSIKEが標的でした。後続研究では、ほかのプリミティブも論じられています。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – 一時的実行により、セキュリティ境界を越えて、ベクトルgather命令で使用されるデータが漏えいする可能性があります。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 投機的なベクトルレジスター状態の誤った処理により、同じ物理コア上のデータが漏えいする可能性があります。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 一時的実行攻撃でphantom executionと一時的実行中のトレーニングを組み合わせ、攻撃者が制御する誤予測ガジェットを作り出します。<sup>[[5]](#references)</sup>

---

## 音響攻撃と光学攻撃
制御された実験では、ノートPCの動作音からRSA鍵を回復する音響leakageが実証されており、近くに置いた携帯電話のマイクも使われました。<sup>[[6]](#references)</sup> 2023年の別のキーボード研究では、近くの携帯電話で録音した音声で学習した場合に95%、Zoomの音声で学習した場合に93%の精度でキー入力を分類しました。これらの数値は、同論文で学習に使われたデバイスを対象とする実験の結果であり、任意のキーボードや被害者に当てはまるものではありません。<sup>[[9]](#references)</sup> ステータスLEDからの光学的放射も、処理データと相関づけられる場合があります。これらの結果は標的とセットアップに固有のものであり、範囲や成功率を無関係なデバイスに一般化しないでください。<sup>[[7]](#references)</sup>

---

## フォールトインジェクションと差分フォールト解析（DFA）
制御されたフォールトとサイドチャネル観測を組み合わせると、一部のアルゴリズムや実装で鍵の探索範囲を縮小できます。一般的なラボ用プラットフォームには、ChipWhispererの電圧・クロックグリッチ機能や、ChipSHOUTER、PicoEMPなどの専用EMフォールトインジェクションツールがあります。以前の草稿にあった「sub-1 ns」という記述は仕様として使用しないでください。ChipSHOUTERの公開マニュアルでは、挿入されるパルス幅の標準値は、1 mmチップで**15–80 ns**、4 mmチップで**24–480 ns**とされています（ただし、トリガー／パルスのジッターはピコ秒単位で規定されています）。必要なタイミング分解能、プローブの配置、フォールト出力の数は、標的とフォールトモデルによって異なります。<sup>[[1]](#references)[[10]](#references)</sup>

## 以前の草稿から引き継いだ未検証の研究情報

以前の草稿では、次の内容も主張されていました。RTL-SDRを使用し、**500 MHz–3 GHz**のEMセットアップで**10 cm**を超える距離からSTM32の鍵を回復したこと、「Black Hat 2023」でDDR4のアクティビティLEDからAESのラウンド鍵を1分未満で読み取ったこと、そして2025年にオープンソースのRISC-Vグリッチプラットフォーム**GlitchKit-R5**が登場したことです。今回の監査では、該当する一次論文、カンファレンス資料、プロジェクトリポジトリを確認できませんでした。これらの詳細は、確立された結果やツールの推奨事項ではなく、検索・再現の手掛かりとして記載しています。

---

## 一般的な攻撃ワークフロー
1. leakageチャネルと接続箇所（VCCピン、デカップリングコンデンサ、近傍界の測定箇所）を特定する。
2. トリガー（GPIOまたはパターンベース）を挿入する。  
3. 選択した統計検定に必要な数のトレースを収集し、平文／暗号文やその他のメタデータを記録する。
4. 前処理を行う（位置合わせ、平均値の除去、LP/HPフィルター、ウェーブレット、PCA）。
5. 統計手法またはMLによる鍵回復を行う（CPA、MIA、DL-SCA）。
6. 外れ値を検証し、反復する。

---

## 防御と強化
* **定時間**実装とメモリハードなアルゴリズム。
* **マスキング／シャッフリング** – 秘密情報をランダムなシェアに分割する。一次耐性はTVLAで認証する。
* **隠蔽** – オンチップ電圧レギュレーター、ランダム化クロック、デュアルレール論理、EMシールド。
* **フォールト検出** – 冗長計算、しきい値署名。
* **運用面** – 暗号処理カーネルではDVFS／ターボを無効にし、SMTを分離し、マルチテナントクラウドでの同居を禁止する。

---

## ツールとフレームワーク
* **ChipWhisperer-Husky** (2024) – 500 MS/sのオシロスコープとCortex-Mトリガーを搭載。Python APIは前述のとおりです。<sup>[[1]](#references)</sup>
* **Riscure Inspector and fault-injection products** – 商用の解析ツールおよび自動テストツール。
* **scaaml** – TensorFlowベースのディープラーニングSCAツールおよびデータセット。<sup>[[12]](#references)</sup>
* **pyecsca** – サイドチャネルを通じてブラックボックスのECC実装をリバースエンジニアリングするためのオープンソースツールキット。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhispererのドキュメント](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed攻撃の論文](https://www.hertzbleed.com/)
- [3] [Downfall: 投機的なデータ収集の悪用](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: 一時的実行中のトレーニングによる新たな攻撃対象領域の露呈](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [低帯域幅の音響暗号解析によるRSA鍵の抽出](https://eprint.iacr.org/2013/857.pdf)
- [7] [光学的放射からの情報漏えい](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca成果物のドキュメント](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [キーボードに対する実用的なディープラーニングベースの音響サイドチャネル攻撃](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTERユーザーマニュアル](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhispererのドキュメント — CW503プローブ電源](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAMLドキュメント](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDRを使った低コストな電磁サイドチャネル攻撃の実施](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [知的財産の解読：3Dプリンターに対する音響・磁気サイドチャネル攻撃](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — プリンターに対する音響サイドチャネル攻撃](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAMを使った温度のスパイ行為](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
{{#include ../../banners/hacktricks-training.md}}
