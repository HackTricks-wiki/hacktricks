# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは、内蔵モジュールにより**300〜928 MHzの範囲の無線周波数を受信および送信**でき、リモートコントロールの読み取り、保存、エミュレートが可能です。これらのコントロールは、ゲート、バリア、無線ロック、リモートコントロールスイッチ、ワイヤレスドアベル、スマートライトなどとの通信に使用されます。Flipper Zeroを使えば、セキュリティが侵害されているかどうかを確認できます。

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroには、[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf)をベースにしたサブ1 GHzモジュールと無線アンテナが内蔵されています（最大通信距離は50メートル）。CC1101チップとアンテナは、300〜348 MHz、387〜464 MHz、779〜928 MHzの帯域で動作するように設計されています。

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> リモートが使用している周波数の調べ方

解析中、Flipper Zeroは周波数設定で利用可能なすべての周波数における信号強度（RSSI）をスキャンします。Flipper Zeroは、-90 [dBm](https://en.wikipedia.org/wiki/DBm)より高い信号強度を持つ、RSSI値が最も高い周波数を表示します。<sup>[[1]](#references)</sup>

リモートの周波数を特定するには、次の手順を実行します。

1. リモートコントロールをFlipper Zeroの左側のすぐ近くに置きます。
2. **Main Menu** **→ Sub-GHz**に移動します。
3. **Frequency Analyzer**を選択し、解析したいリモートコントロールのボタンを長押しします。
4. 画面上の周波数の値を確認します。

### Read

> [!TIP]
> 使用されている周波数に関する情報を確認する（使用周波数を調べる別の方法）

**Read**オプションは、指定された変調方式で**設定された周波数を受信**します。デフォルトでは433.92 AMです。読み取り中に**何かが検出される**と、画面に**情報が表示されます**。この情報は、後で信号を再現するために使用できます。<sup>[[1]](#references)</sup>

Readの使用中は、**左ボタン**を押して**設定する**ことができます。\
現在は**4種類の変調方式**（AM270、AM650、FM328、FM476）と、**複数の関連する周波数**が保存されています。

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**関心のある任意の周波数**を設定できます。ただし、リモートが使用している周波数が**どれか分からない**場合は、**HoppingをON**（デフォルトではOFF）に設定し、Flipperが信号を捕捉して周波数設定に必要な情報を表示するまで、ボタンを数回押します。

> [!CAUTION]
> 周波数の切り替えには時間がかかるため、切り替え中に送信された信号を取りこぼす可能性があります。より良好に信号を受信するには、Frequency Analyzerで特定した固定周波数を設定してください。

### **Read Raw**

> [!TIP]
> 設定された周波数の信号を盗み出す（および再生する）

**Read Raw**オプションは、受信周波数で送信された**信号を記録**します。これは、信号を**盗み出して**、**再送信**するために使用できます。<sup>[[1]](#references)</sup>

デフォルトでは、**Read RawもAM650の433.92**に設定されています。ただし、Readオプションで目的の信号が**別の周波数または変調方式であることが分かった場合は、Read Rawオプション内で左ボタンを押して設定を変更できます**。

### Brute-Force

たとえばガレージドアで使用されているプロトコルが分かっている場合、**すべてのコードを生成してFlipper Zeroで送信できます。**これは、一般的なガレージの種類を幅広くサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### Add Manually

> [!TIP]
> 設定済みのプロトコル一覧から信号を追加する

#### [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote)の一覧 <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton_433 (大半の固定コードシステムで動作) | 433.92 | 静的  |
| -------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit_433                                             | 433.92 | 静的  |
| Nice Flo 24bit_433                                             | 433.92 | 静的  |
| CAME 12bit_433                                                 | 433.92 | 静的  |
| CAME 24bit_433                                                 | 433.92 | 静的  |
| Linear_300                                                     | 300.00 | 静的  |
| CAME TWEE                                                      | 433.92 | 静的  |
| Gate TX_433                                                    | 433.92 | 静的  |
| DoorHan_315                                                    | 315.00 | 動的 |
| DoorHan_433                                                    | 433.92 | 動的 |
| LiftMaster_315                                                 | 315.00 | 動的 |
| LiftMaster_390                                                 | 390.00 | 動的 |
| Security+2.0_310                                               | 310.00 | 動的 |
| Security+2.0_315                                               | 315.00 | 動的 |
| Security+2.0_390                                               | 390.00 | 動的 |

### Supported Sub-GHz vendors

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)で一覧を確認してください。

### Supported Frequencies by region

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)で一覧を確認してください。

### Test

> [!TIP]
> 保存された周波数のdBmを取得する

## References

- [1] [Sub-GHz - Flipper Zero User Documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
