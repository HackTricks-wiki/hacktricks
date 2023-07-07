# FZ - Sub-GHz

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## イントロ <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは、内蔵モジュールを使用して、300-928 MHzの範囲の無線周波数を**受信および送信**することができます。このモジュールは、リモートコントロールを読み取り、保存、エミュレートすることができます。これらのコントロールは、ゲート、バリア、ラジオロック、リモートコントロールスイッチ、ワイヤレスドアベル、スマートライトなどの操作に使用されます。Flipper Zeroは、セキュリティが侵害されているかどうかを確認するのに役立ちます。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHzハードウェア <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroには、[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101チップ](https://www.ti.com/lit/ds/symlink/cc1101.pdf)と無線アンテナ（最大範囲は50メートル）を搭載した、内蔵のサブ1 GHzモジュールがあります。CC1101チップとアンテナは、300-348 MHz、387-464 MHz、および779-928 MHzの周波数で動作するように設計されています。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## アクション

### 周波数アナライザー

{% hint style="info" %}
リモートが使用している周波数を見つける方法
{% endhint %}

解析中、Flipper Zeroは周波数設定で利用可能なすべての周波数で信号強度（RSSI）をスキャンします。Flipper Zeroは、-90 [dBm](https://en.wikipedia.org/wiki/DBm)よりも高い信号強度を持つ最も高いRSSI値の周波数を表示します。

リモートの周波数を特定するには、次の手順を実行します。

1. リモートコントロールをFlipper Zeroの左側に非常に近づけます。
2. **メインメニュー** **→ サブ-GHz**に移動します。
3. **周波数アナライザー**を選択し、解析したいリモートコントロールのボタンを押し続けます。
4. 画面上の周波数値を確認します。

### 読み取り

{% hint style="info" %}
使用されている周波数に関する情報を見つける（使用されている周波数を見つける別の方法もあります）
{% endhint %}

**読み取り**オプションは、指定された変調（デフォルトでは433.92 AM）で設定された周波数で**リスニング**します。読み取り中に**何かが見つかると**、画面に情報が表示されます。この情報は、将来の信号の複製に使用できます。

Readを使用している間に、**左ボタン**を押して**設定**することができます。\
現在、**4つの変調**（AM270、AM650、FM328、FM476）があり、**いくつかの関連する周波数**が保存されています。

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

**興味のある周波数**を設定できますが、リモートで使用されている周波数が**わからない場合は、ホッピングをONに設定**（デフォルトではオフ）し、Flipperがキャプチャし、必要な周波数を提供するまでボタンを何度も押します。

{% hint style="danger" %}
周波数の切り替えには時間がかかるため、切り替え時に送信される信号は見逃される可能性があります。信号の受信を改善するために、周波数アナライザーで決定された固定周波数を設定してください。
{% endhint %}

### **生データの読み取り**

{% hint style="info" %}
設定された周波数での信号を盗み（および再生）する
{% endhint %}

**生データの読み取り**オプションは、リスニング周波数で送信される信号を**記録**します。これを使用して信号を**盗み**、**再生**することができます。

デフォルトでは、**Read Raw**も433.92のAM650ですが、Readオプションで興味のある信号が異なる周波数/変調にあることがわかった場合は、左を押して（Read Rawオプション内で）それを変更することもできます。

### ブルートフォース

ガレージドアなどで使用されるプロトコルがわかっている場合、Flipper Zeroで**すべてのコードを生成し、送信**することができます。これは、一般的なガレージの一般的なタイプをサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*
### 手動で追加

{% hint style="info" %}
設定されたプロトコルのリストから信号を追加します
{% endhint %}

#### [サポートされているプロトコルのリスト](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (ほとんどの静的コードシステムで動作します) | 433.92 | 静的  |
| --------------------------------------------------------------- | ------ | ------- |
| Nice Flo 12bit\_433                                             | 433.92 | 静的  |
| Nice Flo 24bit\_433                                             | 433.92 | 静的  |
| CAME 12bit\_433                                                 | 433.92 | 静的  |
| CAME 24bit\_433                                                 | 433.92 | 静的  |
| Linear\_300                                                     | 300.00 | 静的  |
| CAME TWEE                                                       | 433.92 | 静的  |
| Gate TX\_433                                                    | 433.92 | 静的  |
| DoorHan\_315                                                    | 315.00 | 動的 |
| DoorHan\_433                                                    | 433.92 | 動的 |
| LiftMaster\_315                                                 | 315.00 | 動的 |
| LiftMaster\_390                                                 | 390.00 | 動的 |
| Security+2.0\_310                                               | 310.00 | 動的 |
| Security+2.0\_315                                               | 315.00 | 動的 |
| Security+2.0\_390                                               | 390.00 | 動的 |

### サポートされているSub-GHzベンダー

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)でリストを確認してください。

### 地域別のサポートされている周波数

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)でリストを確認してください。

### テスト

{% hint style="info" %}
保存された周波数のdBmを取得します
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)
*

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
