# FZ - Sub-GHz

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>を通じて、ゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **Discordグループ**に参加する💬（https://discord.gg/hRep4RUj7f）または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**🐦で私たちをフォローする[**@carlospolopm**](https://twitter.com/hacktricks_live)。
- **HackTricks**（https://github.com/carlospolop/hacktricks）と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

## イントロ <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは、**300-928 MHzの範囲で無線周波数を受信および送信**できる内蔵モジュールを備えており、リモートコントロールを読み取り、保存し、エミュレートできます。これらのコントロールは、ゲート、バリア、ラジオロック、リモートコントロールスイッチ、ワイヤレスドアベル、スマートライトなどとのやり取りに使用されます。Flipper Zeroは、セキュリティが危険にさらされているかどうかを学ぶのに役立ちます。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHzハードウェア <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroには、[﻿](https://www.st.com/en/nfc/st25r3916.html#overview)﻿[CC1101チップ](https://www.ti.com/lit/ds/symlink/cc1101.pdf)に基づく内蔵サブ1 GHzモジュールと、無線アンテナ（最大範囲は50メートル）が搭載されています。CC1101チップとアンテナは、300-348 MHz、387-464 MHz、779-928 MHzの周波数で動作するよう設計されています。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## アクション

### 周波数アナライザ

{% hint style="info" %}
リモートが使用している周波数を見つける方法
{% endhint %}

分析中、Flipper Zeroは周波数構成で利用可能なすべての周波数で信号強度（RSSI）をスキャンしています。Flipper Zeroは、-90 [dBm](https://en.wikipedia.org/wiki/DBm)よりも高い信号強度を持つ周波数を画面に表示します。

リモコンの周波数を特定するには、次の手順を実行します：

1. リモコンをFlipper Zeroの左側に非常に近づけます。
2. **メインメニュー** **→ Sub-GHz**に移動します。
3. **周波数アナライザ**を選択し、分析したいリモコンのボタンを押し続けます。
4. 画面上の周波数値を確認します。

### 読み取り

{% hint style="info" %}
使用されている周波数に関する情報を見つける（また、使用されている周波数を見つける別の方法）
{% endhint %}

**Read**オプションは、指定された変調で設定された周波数で**リスニング**を行います：デフォルトでは433.92 AMです。読み取り時に**何かが見つかると**、画面に情報が表示されます。この情報は、将来信号を複製するために使用できます。

Readを使用している間に、**左ボタン**を押して**設定**することができます。\
現時点では、**4つの変調**（AM270、AM650、FM328、FM476）があり、**いくつかの重要な周波数**が保存されています：

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

興味を持つ**任意の周波数を設定**できますが、リモコンで使用されている周波数がわからない場合は、**HoppingをONに設定**（デフォルトではOff）し、Flipperがそれをキャプチャして必要な周波数を設定する情報を提供するまでボタンを数回押します。

{% hint style="danger" %}
周波数間の切り替えには時間がかかるため、切り替え時に送信される信号を見逃す可能性があります。信号をより良く受信するためには、周波数アナライザで決定された固定周波数を設定してください。
{% endhint %}

### **Raw読み取り**

{% hint style="info" %}
設定された周波数で信号を盗み（および再生）ます
{% endhint %}

**Raw読み取り**オプションは、リスニング周波数で送信された信号を記録します。これを使用して信号を盗み、繰り返すことができます。

デフォルトでは**Raw読み取りも433.92でAM650**ですが、Readオプションで興味を持つ信号が**異なる周波数/変調にあることがわかった場合は、それも変更**できます（Raw読み取りオプション内で左を押します）。

### ブルートフォース

例えばガレージドアで使用されているプロトコルがわかっている場合、**Flipper Zeroですべてのコードを生成して送信**することができます。これは一般的なガレージのタイプをサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)

### 手動で追加

{% hint style="info" %}
設定されたプロトコルリストから信号を追加します
{% endhint %}

#### [サポートされているプロトコルのリスト](https://docs.flipperzero.one/sub-ghz/add-new-remote) <a href="#id-3iglu" id="id-3iglu"></a>

| Princeton\_433（ほとんどの静的コードシステムと互換性があります） | 433.92 | 静的  |
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

[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)のリストを確認してください。

### 地域別のサポートされている周波数

[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)のリストを確認してください。

### テスト

{% hint style="info" %}
保存された周波数のdBmを取得します
{% endhint %}

## 参考

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
