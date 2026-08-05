# FZ - Sub-GHz

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは、内蔵モジュールにより**300-928 MHzの範囲のradio frequenciesを受信および送信**でき、remote controlsの読み取り、保存、emulateが可能です。これらのcontrolsは、gate、barrier、radio lock、remote control switch、wireless doorbell、smart lightなどとのインタラクションに使用されます。Flipper Zeroは、セキュリティがcompromiseされているかどうかの確認に役立ちます。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (714).png" alt=""><figcaption></figcaption></figure>

## Sub-GHz hardware <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroには、[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101 chip](https://www.ti.com/lit/ds/symlink/cc1101.pdf)とradio antenna（最大rangeは50 meters）をベースにした、内蔵のsub-1 GHz moduleがあります。CC1101 chipとantennaはどちらも、300-348 MHz、387-464 MHz、779-928 MHz bandsで動作するよう設計されています。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (923).png" alt=""><figcaption></figcaption></figure>

## 操作

### Frequency Analyser

> [!TIP]
> remoteが使用しているfrequencyの確認方法

分析時、Flipper Zeroはfrequency configurationで利用可能なすべてのfrequenciesでsignal strength（RSSI）をscanします。Flipper Zeroは、-90 [dBm](https://en.wikipedia.org/wiki/DBm)より高いsignal strengthを持つ、RSSI valueが最も高いfrequencyを表示します。<sup>[[1]](#references)</sup>

remoteのfrequencyを特定するには、次の操作を行います。

1. remote controlをFlipper Zeroの左側に非常に近づけます。
2. **Main Menu** **→ Sub-GHz**に移動します。
3. **Frequency Analyzer**を選択し、分析したいremote controlのbuttonを長押しします。
4. 画面上のfrequency valueを確認します。

### Read

> [!TIP]
> 使用されているfrequencyの情報を確認する（使用されているfrequencyを確認する別の方法）

**Read** optionは、指定されたmodulationで**configured frequencyをlisten**します。Read中に**何かが検出される**と、画面に**情報が表示され**ます。この情報は、後でsignalをreplicateするために使用できます。<sup>[[1]](#references)</sup>

Readの使用中は、**left button**を押して**設定**できます。\
現在、**4つのmodulations**（AM270、AM650、FM328、FM476）と、**複数の関連するfrequencies**が保存されています。

<figure><img src="../../../images/image (947).png" alt=""><figcaption></figcaption></figure>

**興味のあるものを任意に設定**できます。ただし、手元のremoteが使用しているfrequencyが**不明な場合**は、**HoppingをON**（デフォルトではOff）に設定し、Flipperがsignalをcaptureしてfrequency設定に必要な情報を表示するまでbuttonを何度か押します。

> [!CAUTION]
> frequenciesの切り替えには時間がかかるため、切り替え中に送信されたsignalsをmissする可能性があります。より良いsignal receptionのため、Frequency Analyzerで特定したfixed frequencyを設定してください。

### **Read Raw**

> [!TIP]
> configured frequencyのsignalをstealしてreplayする

**Read Raw** optionは、listening frequencyで送信されたsignalsを**record**します。これはsignalを**steal**して**repeat**するために使用できます。

デフォルトでは、**Read RawもAM650の433.92**ですが、Read optionで目的のsignalが**異なるfrequency/modulationにあることが判明した場合は、Read Raw option内でleftを押して変更することもできます**。

### ブルートフォース

garage doorで使用されているprotocolがわかっている場合、**すべてのcodesをgenerateしてFlipper Zeroで送信できます。**これは、一般的なgarageのcommon typesをサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 手動で追加

> [!TIP]
> configured list of protocolsからsignalsを追加する

#### [supported protocols](https://docs.flipperzero.one/sub-ghz/add-new-remote)の一覧 <a href="#id-3iglu" id="id-3iglu"></a>

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

### サポートされているSub-GHz vendors

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)のlistを確認してください。

### region別のサポートされているFrequencies

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)のlistを確認してください。

### Test

> [!TIP]
> 保存されたfrequenciesのdBmsを取得する

## References

- [1] [Flipper Zero Sub-GHz documentation](https://docs.flipperzero.one/sub-ghz)

{{#include ../../../banners/hacktricks-training.md}}
