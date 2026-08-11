# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Introduction <a href="#introduction" id="introduction"></a>

Flipper Zero は、内蔵モジュールにより、設定された地域の周波数制限に従って、**300～928 MHz の範囲の無線周波数を受信および送信**できます。ゲート、バリア、無線ロック、スイッチ、ワイヤレスドアベル、スマートライト、その他のデバイスで使用される互換性のあるリモートコントロールを読み取り、保存し、エミュレートできます。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz Hardware <a href="#sub-ghz-hardware" id="sub-ghz-hardware"></a>

Flipper Zero には、CC1101 トランシーバーと無線アンテナをベースとした、1 GHz 未満対応の内蔵モジュールがあります。実際の通信距離は、周波数、アンテナ、環境、送信機によって異なります。Flipper のドキュメントでは、良好な条件下で約 50 メートルまで対応するとされています。このハードウェアは 300～348 MHz、387～464 MHz、779～928 MHz をカバーしますが、firmware と地域の規則によって送信範囲はさらに制限されます。<sup>[[1]](#references)[[2]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!TIP]
> リモートが使用している周波数を見つける方法

分析中、Flipper Zero は周波数設定で利用可能なすべての周波数における信号強度（RSSI）をスキャンします。Flipper Zero は、RSSI 値が最も高く、信号強度が -90 [dBm](https://en.wikipedia.org/wiki/DBm) より高い周波数を表示します。<sup>[[1]](#references)</sup>

リモートの周波数を特定するには、次の手順を実行します。

1. リモートコントロールを Flipper Zero の左側に非常に近づけます。
2. **Main Menu** **→ Sub-GHz** に移動します。
3. **Frequency Analyzer** を選択し、分析したいリモートコントロールのボタンを長押しします。
4. 画面上の周波数の値を確認します。

### Read

> [!TIP]
> 使用されている周波数に関する情報を見つける（使用周波数を確認する別の方法）

**Read** オプションは、設定された周波数と変調方式（デフォルトでは 433.92 MHz AM）を監視します。対応する信号を認識すると、画面に情報が表示され、その情報を保存して後で再生できます。<sup>[[1]](#references)</sup>

Read の使用中は、**左ボタン**を押して**設定**できます。\
現時点では **4 つの変調方式**（AM270、AM650、FM328、FM476）と、関連する**複数の周波数**が保存されています。

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

許可されている任意の周波数を選択できます。リモートが使用している周波数が不明な場合は、**Hopping を ON**（デフォルトではオフ）に設定し、Flipper が信号を取得して周波数を報告するまで、リモートのボタンを数回押します。

> [!CAUTION]
> 周波数の切り替えには時間がかかるため、切り替え中に送信された信号は取り逃す可能性があります。より良好に信号を受信するには、Frequency Analyzer で特定した固定周波数を設定してください。

### **Read Raw**

> [!TIP]
> 設定された周波数の信号を盗み取り（そして再生する）

**Read Raw** オプションは、選択した周波数で送信された信号を記録します。これは、許可されたテスト中に信号を取得して再生するために使用できます。<sup>[[1]](#references)</sup>

デフォルトでは、**Read Raw も AM650 の 433.92 MHz を使用します**。Read オプションで別の周波数または変調方式の信号が見つかった場合は、Read Raw 内で Left を押して設定を変更します。

### Brute-Force

ガレージドアなどのデバイスで使用されているプロトコルが分かっている場合、**候補コードを生成して Flipper Zero で送信**できる可能性があります。`flipperzero-bruteforce` project は、一般的な複数の static-code プロトコルに対応しています。<sup>[[3]](#references)</sup>

### Add Manually

> [!TIP]
> 設定済みのプロトコル一覧から信号を追加する

#### List of supported protocols <a href="#id-3iglu" id="id-3iglu"></a>

Add Manually メニューには、Flipper Zero によってドキュメント化されているプロトコル preset が表示されます。<sup>[[4]](#references)</sup>

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

### Supported Sub-GHz vendors

Flipper Zero の supported-vendors list を確認してください。<sup>[[5]](#references)</sup>

### Supported Frequencies by region

送信前に、公式の regional-frequency list を確認してください。<sup>[[6]](#references)</sup>

### Test

> [!TIP]
> 保存した周波数の dBm を取得する

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)
- [2] [Texas Instruments CC1101 data sheet](https://www.ti.com/lit/ds/symlink/cc1101.pdf)
- [3] [tobiabocchi/flipperzero-bruteforce](https://github.com/tobiabocchi/flipperzero-bruteforce)
- [4] [Flipper Zero - Add a manually created remote](https://docs.flipperzero.one/sub-ghz/add-new-remote)
- [5] [Flipper Zero - Supported Sub-GHz vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)
- [6] [Flipper Zero - Regional Sub-GHz frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)
{{#include ../../../banners/hacktricks-training.md}}
