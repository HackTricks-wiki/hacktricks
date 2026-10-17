# サイドチャネル解析攻撃

{{#include ../../banners/hacktricks-training.md}}

サイドチャネル攻撃では、デバイスの論理インターフェースの一部ではないものの、内部状態と*相関する*物理的またはマイクロアーキテクチャ上の「漏洩」を観測して秘密情報を復元します。たとえば、スマートカードが瞬間的に消費する電流を測定する方法から、ネットワーク経由でCPUの電力管理による影響を悪用する方法まであります。

ARM debug hardwareにアクセスできるターゲットでは、[CoreSight ETM tracing over SWO](arm-coresight-instruction-tracing.md)を、電力やEMのキャプチャと併せて実行経路の参照情報として利用できます。これはdebug traceであり、漏洩チャネルではありません。<sup>[[17]](#references)</sup>

---

## 主な漏洩チャネル

| チャネル | 主なターゲット | 計測機器 |
|---------|---------------|-----------------|
| 電力消費 | Smart cards、IoT MCU、FPGA | オシロスコープとシャント抵抗または差動プローブ。CW503はプローブ/LNA用の電源であり、プローブそのものではありません<sup>[[11]](#references)</sup> |
| 電磁場 (EM) | CPU、RFID、AES accelerator | H-field/near-field probeと低ノイズアンプ、オシロスコープ、またはRTL-SDRなどのSDR receiver<sup>[[13]](#references)</sup> |
| 実行時間 / cache | DesktopおよびcloudのCPU | 高精度タイマー (`rdtsc`/`rdtscp`) またはリモートのtime-of-flight |
| 音響 / 機械振動 | キーボード、3-D printer、printer、relay、CPU voltage regulator | MEMS microphoneまたはlaser vibrometer<sup>[[6]](#references)[[9]](#references)[[14]](#references)[[15]](#references)</sup> |
| 光学 / 熱 | ステータスLED、ディスプレイ、DRAM、熱的に結合されたデバイス | フォトダイオード、高速カメラ、またはIR camera<sup>[[7]](#references)[[16]](#references)</sup> |
| Fault injection | ASIC/MCUの暗号処理 | Clock/voltage glitch、EMFI、またはレーザー注入 |

---

## 電力解析

### Simple Power Analysis (SPA)
*単一の*トレースを観察し、目に見える特徴を分岐、modular multiplication、異なる命令シーケンスなどの操作と関連付けます。<sup>[[1]](#references)</sup>

正確なセットアップはターゲットによって異なります。以下では、scopeとtargetを接続して設定した後に使用する、現行の高レベルなChipWhisperer capture APIを示します。<sup>[[1]](#references)</sup>

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
複数のトレースを取得し、鍵バイト `k` を仮定して、ハミング重み（HW）またはハミング距離（HD）のリーケージモデルを計算し、各サンプルとの相関を求めます。必要なトレース数は対象、ノイズ、アライメント、対策、リーケージモデルによって決まり、固定のしきい値はありません。
```python
import numpy as np
corr = np.corrcoef(leakage_model(k), traces[:,sample])
```
CPAは標準的なベースラインです。leakが非線形である場合やトレースのアライメントが不十分な場合は、Template attacks、相互情報量解析、機械学習の手法が有効です。

---

## 電磁波解析 (EMA)
近傍界EM解析では、電源経路にシャントを挿入せずに、データに依存する動作を観測できます。ただし、必ずしも電力トレースと同じ信号が得られるとは限りません。プローブの位置、向き、帯域幅、フロントエンドのゲイン、トリガー品質、距離がすべて影響します。

---

## タイミング攻撃とマイクロアーキテクチャ攻撃
現代のCPUは、共有リソースを通じて秘密情報をleakします。
* **Hertzbleed (2022)** – データ依存の動的電圧・周波数スケーリングにより、リモートタイミングチャネルが生じます。最初のエンドツーエンドの鍵回復実証ではSIKEが標的とされました。後続研究では、ほかのプリミティブも論じられています。<sup>[[2]](#references)</sup>
* **Downfall / Gather Data Sampling (Intel, 2023)** – 過渡実行により、セキュリティ境界を越えて、ベクトルのgather命令が使用するデータが漏えいする可能性があります。<sup>[[3]](#references)</sup>
* **Zenbleed (AMD, 2023)** – 投機実行中のベクトルレジスタ状態を誤って処理すると、同じ物理コア上のデータが漏えいする可能性があります。<sup>[[4]](#references)</sup>
* **Inception (AMD, 2023)** – 過渡実行攻撃でphantom executionと過渡実行中のトレーニングを組み合わせ、攻撃者が制御する誤予測ガジェットを作り出します。<sup>[[5]](#references)</sup>

---

## 音響攻撃と光学攻撃
制御された実験では、ノートPCのノイズからRSA鍵を回復するために音響leakageが利用されており、近くに置いた携帯電話のマイクも使われました。<sup>[[6]](#references)</sup> 2023年の別のキーボード研究では、近くに置いた携帯電話の録音で学習した場合に95%、Zoomの音声で学習した場合に93%の精度でキーストロークを分類しました。これらの数値は、その論文における学習済みデバイスを使った実験の結果であり、任意のキーボードや被害者に当てはまるものではありません。<sup>[[9]](#references)</sup> ステータスLEDからの光学的放射も、処理データと相関させることができます。これらの結果は標的とセットアップに固有のものであり、その到達距離や成功率を無関係なデバイスに一般化しないでください。<sup>[[7]](#references)</sup>

---

## フォールト注入と差分フォールト解析 (DFA)
制御されたフォールトとサイドチャネル観測を組み合わせると、一部のアルゴリズムや実装で鍵探索を削減できます。一般的な実験室用プラットフォームには、ChipWhispererの電圧/クロックグリッチ機能や、ChipSHOUTER、PicoEMPなどの専用EMフォールト注入ツールがあります。以前の草稿にあった「1 ns未満」という記述は仕様として使うべきではありません。ChipSHOUTERの公開マニュアルでは、1 mmチップで挿入されるパルス幅の代表値は**15–80 ns**、4 mmチップでは**24–480 ns**とされています（ただし、トリガー/パルスのジッターはピコ秒単位で規定されています）。必要なタイミング分解能、プローブの配置、フォールトが発生した出力の必要数は、標的とフォールトモデルによって異なります。<sup>[[1]](#references)[[10]](#references)</sup>

## 以前の草稿から残した未検証の研究情報

以前の草稿には、次の主張もありました。RTL-SDRを使い、**500 MHz–3 GHz**のEMセットアップで**10 cm**以上離れた位置からSTM32の鍵を回復したという主張、「Black Hat 2023」でDDR4の動作LEDからAESのラウンド鍵が1分未満で判明したという主張、そして**GlitchKit-R5**という2025年のオープンソースRISC-Vグリッチングプラットフォームです。この監査では、該当する一次論文、カンファレンス資料、プロジェクトリポジトリを確認できませんでした。これらの詳細は、確立された結果やツールの推奨事項ではなく、検索・再現の手掛かりとして残しています。

---

## 一般的な攻撃ワークフロー
1. leakageチャネルと取り付け位置（VCCピン、デカップリングコンデンサ、近傍界のスポット）を特定する。
2. トリガー（GPIOまたはパターンベース）を挿入する。
3. 選択した統計検定に必要な数のトレースを収集し、平文/暗号文やその他のメタデータを記録する。
4. 前処理（アライメント、平均値除去、LP/HPフィルター、ウェーブレット、PCA）を行う。
5. 統計手法またはMLによる鍵回復（CPA、MIA、DL-SCA）を行う。
6. 外れ値を検証し、反復する。

---

## 防御と強化
* **定時間**実装とメモリハードなアルゴリズム。
* **マスキング/シャッフリング** – 秘密情報をランダムなシェアに分割する。一次耐性はTVLAで認証されます。
* **隠蔽** – オンチップ電圧レギュレーター、ランダム化クロック、デュアルレール論理、EMシールド。
* **フォールト検出** – 冗長計算、しきい値署名。
* **運用面** – 暗号処理カーネルでDVFS/turboを無効化し、SMTを分離し、マルチテナントクラウドでの同居を禁止する。

---

## ツールとフレームワーク
* **ChipWhisperer-Husky** (2024) – 500 MS/sオシロスコープ + Cortex-Mトリガー。上記のPython APIを使用します。<sup>[[1]](#references)</sup>
* **Riscure Inspectorおよびフォールト注入製品** – 商用解析および自動テストツール。
* **scaaml** – TensorFlowベースのdeep-learning SCAツールとデータセット。<sup>[[12]](#references)</sup>
* **pyecsca** – サイドチャネルを通じてブラックボックスのECC実装をリバースエンジニアリングするオープンソースツールキット。<sup>[[8]](#references)</sup>

---

## References

- [1] [ChipWhispererドキュメント](https://chipwhisperer.readthedocs.io/en/latest/)
- [2] [Hertzbleed攻撃論文](https://www.hertzbleed.com/)
- [3] [Downfall: 投機的データ収集の悪用](https://downfall.page/)
- [4] [Zenbleed](https://lock.cmpxchg8b.com/zenbleed.html)
- [5] [Inception: 過渡実行中のトレーニングによる新たな攻撃対象領域の露呈](https://comsec.ethz.ch/research/microarch/inception/)
- [6] [低帯域音響暗号解析によるRSA鍵の抽出](https://eprint.iacr.org/2013/857.pdf)
- [7] [光学的放射からの情報leakage](https://ora.ox.ac.uk/objects/uuid%3A4fe94cf8-052a-4025-a312-4a62f58fffac)
- [8] [pyecsca成果物のドキュメント](https://artifacts.iacr.org/tches/2024/a26/readme.html)
- [9] [キーボードに対する実用的な深層学習ベースの音響サイドチャネル攻撃](https://arxiv.org/abs/2308.01074)
- [10] [NewAE - ChipSHOUTERユーザーマニュアル](https://media.newae.com/manuals/ChipSHOUTER_PRESS_1.3.pdf)
- [11] [ChipWhispererドキュメント — CW503プローブ電源](https://chipwhisperer.readthedocs.io/en/latest/Tools/CW503%20Probe%20Power%20Supply.html)
- [12] [Google SCAAMLドキュメント](https://google.github.io/scaaml/)
- [13] [FOSDEM — RTL-SDRを使った低コスト電磁サイドチャネル攻撃の実施](https://archive.fosdem.org/2019/schedule/event/sdr_em_sidechannel_attacks/attachments/slides/2931/export/events/attachments/sdr_em_sidechannel_attacks/slides/2931/robyns2019fosdem.pdf)
- [14] [知的財産の解読: 3Dプリンターに対する音響・磁気サイドチャネル攻撃](https://arxiv.org/abs/2411.10887)
- [15] [USENIX Security — プリンターに対する音響サイドチャネル攻撃](https://www.usenix.org/conference/usenixsecurity10/acoustic-side-channel-attacks-printers)
- [16] [DRAMを使った温度のスパイ](https://bearhw.ece.vt.edu/content/dam/bearhw_ece_vt_edu/publications/caslab/xiong2019spying.pdf)
- [17] [命令を追う: ETM、ITM、TPIUを使ったARMのライブトレース](https://voidstarsec.com/blog/arm-tracing-etm-itm)
{{#include ../../banners/hacktricks-training.md}}
