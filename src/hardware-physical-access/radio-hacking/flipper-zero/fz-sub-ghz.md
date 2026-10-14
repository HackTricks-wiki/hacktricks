# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## はじめに <a href="#introduction" id="introduction"></a>

Flipper Zeroは内蔵モジュールにより、設定された地域の周波数制限の範囲内で、**300～928 MHzの無線周波数を受信・送信**できます。ゲート、バリア、無線ロック、スイッチ、ワイヤレスドアベル、スマートライトなどのデバイスで使われる、互換性のあるリモコンの読み取り、保存、エミュレートが可能です。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHzハードウェア <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zeroには、CC1101トランシーバーと無線アンテナをベースにしたサブ1 GHzモジュールが内蔵されています。実際の通信距離は、周波数、アンテナ、環境、送信機によって異なります。Flipperのドキュメントによると、条件が良ければ約50メートルまで通信できます。ハードウェアは300～348 MHz、387～464 MHz、779～928 MHzに対応していますが、ファームウェアと地域の規制によって、送信可能な周波数はさらに制限されます。<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> リモコンが使用している周波数を見つける方法

解析中、Flipper Zeroは周波数設定で利用可能なすべての周波数の信号強度（RSSI）をスキャンします。Flipper Zeroは、RSSI値が最も高く、信号強度が-90 [dBm](https://en.wikipedia.org/wiki/DBm)を超える周波数を表示します。<sup>[[1]](#references)</sup>

リモコンの周波数を特定するには、次の手順を実行します。

1. リモコンをFlipper Zeroの左側にぴったり近づけます。
2. **Main Menu** **→ Sub-GHz**に進みます。
3. **Frequency Analyzer**を選択し、解析したいリモコンのボタンを長押しします。
4. 画面に表示された周波数を確認します。

### Read

> [!TIP]
> 使用されている周波数の情報を確認する（周波数を特定する別の方法）

**Read**オプションは、設定された周波数と変調方式（デフォルトでは433.92 MHz AM）で受信を行います。対応する信号を認識すると、画面に情報が表示され、後で保存して再生できます。<sup>[[1]](#references)</sup>

Readの使用中に**左ボタン**を押すと、設定を**変更できます**。\
現在、**4種類の変調方式**（AM270、AM650、FM328、FM476）と、**複数の主要な周波数**が保存されています。

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

許可されている周波数を選択できます。リモコンが使用する周波数がわからない場合は、**HoppingをON**（デフォルトではOFF）にしてから、Flipperが信号を捕捉して周波数を表示するまで、リモコンのボタンを数回押します。

> [!CAUTION]
> 周波数の切り替えには時間がかかるため、切り替え中に送信された信号を取り逃すことがあります。より確実に受信するには、Frequency Analyzerで特定した周波数に固定してください。

### **Read Raw**

> [!TIP]
> 設定周波数の信号を取得（および再生）する

**Read Raw**オプションは、選択した周波数で送信された信号を記録します。許可されたテスト中に信号を取得して再生するために使用できます。<sup>[[1]](#references)</sup>

デフォルトでは、**Read Rawも433.92 MHz、AM650を使用します**。Readで別の周波数または変調方式の信号が検出された場合は、Read Raw内でLeftを押して設定を変更してください。

### Brute-Force

ガレージドアなどのデバイスで使われているプロトコルがわかっている場合、**候補コードを生成し、Flipper Zeroで送信できる**ことがあります。`flipperzero-bruteforce`プロジェクトは、一般的な固定コードプロトコルをいくつかサポートしています。<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> 設定済みのプロトコル一覧から信号を追加する

#### 対応プロトコル一覧 <a href="#id-3iglu" id="id-3iglu"></a>

Add Manuallyメニューには、Flipper Zeroのドキュメントに記載されたプロトコルプリセットが表示されます。<sup>[[4]](#references)</sup>

| Princeton_433 (works with the majority of static code systems) | 433.92 | Static  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | Static  |
| Nice Flo 24bit_433                                             | 433.92 | Static  |
| CAME 12bit_433                                                 | 433.92 | Static  |
| CAME 24bit_433                                                 | 433.92 | Static  |
| Linear_300                                                     | 300.00 | Static  |
| CAME TWEE                                                      | 433.92 | Static  |
| Gate TX_433                                                    | 433.92 | Static  |
| DoorHan_315                                                    | 315.00 | Dynamic |
| DoorHan_433                                                    | 433.92 | Dynamic |
| LiftMaster_315                                                 | 315.00 | Dynamic |
| LiftMaster_390                                                 | 390.00 | Dynamic |
| Security+2.0_310                                               | 310.00 | Dynamic |
| Security+2.0_315                                               | 315.00 | Dynamic |
| Security+2.0_390                                               | 390.00 | Dynamic |

### 対応Sub-GHzベンダー

Flipper Zeroの対応ベンダー一覧を確認してください。<sup>[[5]](#references)</sup>

### 地域別の対応周波数

送信する前に、公式の地域別周波数一覧を確認してください。<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> 保存された周波数のdBmを確認する

## References

- [1] [Sub-GHz - Flipper Zeroユーザードキュメント](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101データシート](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - 手動で作成したリモコンを追加する](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - 対応Sub-GHzベンダー](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - 地域別Sub-GHz周波数](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
