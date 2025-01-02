# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは**300-928 MHzの範囲でラジオ周波数を受信および送信**できる内蔵モジュールを備えており、リモコンを読み取り、保存し、エミュレートすることができます。これらのコントロールは、ゲート、バリア、ラジオロック、リモートコントロールスイッチ、ワイヤレスドアベル、スマートライトなどとの相互作用に使用されます。Flipper Zeroは、あなたのセキュリティが侵害されているかどうかを学ぶのに役立ちます。

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは、[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101チップ](https://www.ti.com/lit/ds/symlink/cc1101.pdf)に基づく内蔵のサブ1 GHzモジュールとラジオアンテナを備えており（最大範囲は50メートル）、CC1101チップとアンテナは、300-348 MHz、387-464 MHz、779-928 MHzの周波数帯域で動作するように設計されています。

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## Actions

### Frequency Analyser

> [!NOTE]
> リモコンが使用している周波数を見つける方法

分析中、Flipper Zeroは周波数設定で利用可能なすべての周波数で信号強度（RSSI）をスキャンしています。Flipper Zeroは、最も高いRSSI値を持つ周波数を表示し、信号強度が-90 [dBm](https://en.wikipedia.org/wiki/DBm)より高い場合に表示します。

リモコンの周波数を特定するには、次の手順を実行します。

1. リモコンをFlipper Zeroの左側に非常に近く置きます。
2. **メインメニュー** **→ Sub-GHz**に移動します。
3. **Frequency Analyzer**を選択し、分析したいリモコンのボタンを押し続けます。
4. 画面に表示される周波数値を確認します。

### Read

> [!NOTE]
> 使用されている周波数に関する情報を見つける（使用されている周波数を見つける別の方法）

**Read**オプションは、指定された変調で**設定された周波数をリスニング**します：デフォルトは433.92 AMです。読み取り中に**何かが見つかった場合**、**情報が画面に表示されます**。この情報は、将来信号を再現するために使用できます。

Readを使用中は、**左ボタン**を押して**設定する**ことができます。\
この時点で**4つの変調**（AM270、AM650、FM328、FM476）と**いくつかの関連周波数**が保存されています：

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**興味のある周波数を設定する**ことができますが、リモコンが使用している可能性のある周波数が**不明な場合**は、**HoppingをONに設定**（デフォルトはOff）し、Flipperがそれをキャプチャして周波数を設定するために必要な情報を提供するまでボタンを何度も押してください。

> [!CAUTION]
> 周波数を切り替えるには時間がかかるため、切り替え時に送信された信号が失われる可能性があります。信号の受信を改善するために、Frequency Analyzerによって決定された固定周波数を設定してください。

### **Read Raw**

> [!NOTE]
> 設定された周波数で信号を盗む（および再生する）

**Read Raw**オプションは、リスニング周波数で送信された信号を**記録**します。これを使用して信号を**盗み**、**繰り返す**ことができます。

デフォルトでは**Read Rawも433.92のAM650**で動作しますが、Readオプションで興味のある信号が**異なる周波数/変調**にあることがわかった場合は、Read Rawオプション内で左を押すことでそれを変更できます。

### Brute-Force

ガレージドアで使用されるプロトコルがわかっている場合、Flipper Zeroを使用して**すべてのコードを生成し、送信する**ことが可能です。これは一般的なガレージのタイプをサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!NOTE]
> 設定されたプロトコルのリストから信号を追加する

#### [サポートされているプロトコルのリスト](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433（ほとんどの静的コードシステムで動作） | 433.92 | 静的  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | 静的  |
| Nice Flo 24bit_433                                             | 433.92 | 静的  |
| CAME 12bit_433                                                 | 433.92 | 静的  |
| CAME 24bit_433                                                 | 433.92 | 静的  |
| Linear_300                                                     | 300.00 | 静的  |
| CAME TWEE                                                      | 433.92 | 静的  |
| Gate TX_433                                                    | 433.92 | 静的  |
| DoorHan_315                                                    | 315.00 | 動的  |
| DoorHan_433                                                    | 433.92 | 動的  |
| LiftMaster_315                                                 | 315.00 | 動的  |
| LiftMaster_390                                                 | 390.00 | 動的  |
| Security+2.0_310                                               | 310.00 | 動的  |
| Security+2.0_315                                               | 315.00 | 動的  |
| Security+2.0_390                                               | 390.00 | 動的  |

### サポートされているSub-GHzベンダー

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)のリストを確認してください。

### 地域別のサポートされている周波数

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)のリストを確認してください。

### Test

> [!NOTE]
> 保存された周波数のdBmsを取得する

## Reference

- [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
