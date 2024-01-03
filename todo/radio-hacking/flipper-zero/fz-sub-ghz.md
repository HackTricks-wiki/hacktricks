# FZ - Sub-GHz

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正してください。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体にわたる問題を見つけます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## イントロ <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroは内蔵モジュールを使用して、300-928 MHzの範囲の無線周波数を**受信および送信**できます。これはリモコンを読み取り、保存し、エミュレートすることができます。これらのコントロールは、ゲート、バリア、無線ロック、リモコンスイッチ、ワイヤレスドアベル、スマートライトなどとの対話に使用されます。Flipper Zeroは、セキュリティが侵害されているかどうかを学ぶのに役立ちます。

<figure><img src="../../../.gitbook/assets/image (3) (2) (1).png" alt=""><figcaption></figcaption></figure>

## Sub-GHzハードウェア <a href="#kfpn7" id="kfpn7"></a>

Flipper Zeroには、[CC1101チップ](https://www.ti.com/lit/ds/symlink/cc1101.pdf)に基づいたsub-1 GHzモジュールと無線アンテナ（最大範囲は50メートル）が内蔵されています。CC1101チップとアンテナは、300-348 MHz、387-464 MHz、779-928 MHzの帯域で動作するように設計されています。

<figure><img src="../../../.gitbook/assets/image (1) (8) (1).png" alt=""><figcaption></figcaption></figure>

## アクション

### 周波数アナライザー

{% hint style="info" %}
リモコンが使用している周波数を見つける方法
{% endhint %}

分析時、Flipper Zeroは周波数設定で利用可能なすべての周波数で信号強度（RSSI）をスキャンします。Flipper Zeroは、信号強度が-90 [dBm](https://en.wikipedia.org/wiki/DBm)より高い最も高いRSSI値の周波数を表示します。

リモコンの周波数を決定するには、次の手順を実行します：

1. リモコンをFlipper Zeroの左側に非常に近づけます。
2. **メインメニュー** → **Sub-GHz**に移動します。
3. **周波数アナライザー**を選択し、分析したいリモコンのボタンを押し続けます。
4. 画面上の周波数値を確認します。

### 読み取り

{% hint style="info" %}
使用されている周波数に関する情報を見つける（使用されている周波数を見つける別の方法）
{% endhint %}

**読み取り**オプションは、指定された変調で設定された周波数で**リッスンします**：デフォルトでは433.92 AMです。読み取り時に**何かが見つかった場合**、**情報が画面に表示されます**。この情報は将来的に信号を複製するために使用できます。

読み取りを使用している間、**左ボタン**を押して**設定する**ことができます。\
現時点では**4つの変調**（AM270、AM650、FM328、FM476）と、**いくつかの関連する周波数**が保存されています：

<figure><img src="../../../.gitbook/assets/image (28).png" alt=""><figcaption></figcaption></figure>

興味のある**任意の周波数を設定できます**が、リモコンが使用している周波数が**どれかわからない場合は**、**ホッピングをONに設定します**（デフォルトではオフ）。そして、Flipperがキャプチャして必要な情報を提供するまで、何度もボタンを押します。

{% hint style="danger" %}
周波数の切り替えには時間がかかるため、切り替え時に送信された信号を見逃すことがあります。より良い信号受信のために、周波数アナライザーで決定された固定周波数を設定してください。
{% endhint %}

### **生データ読み取り**

{% hint style="info" %}
設定された周波数で信号を盗む（そして再生する）
{% endhint %}

**生データ読み取り**オプションは、リスニング周波数で送信される**信号を記録します**。これは、信号を**盗んで**、**繰り返す**ために使用できます。

デフォルトでは**生データ読み取りも433.92のAM650**ですが、読み取りオプションで興味のある信号が**異なる周波数/変調**であることがわかった場合、**生データ読み取りオプションの内部で左を押すことで変更することもできます**。

### ブルートフォース

例えばガレージドアに使用されているプロトコルがわかっている場合、**すべてのコードを生成してFlipper Zeroで送信することが可能です**。これは一般的なガレージタイプをサポートする例です：[**https://github.com/tobiabocchi/flipperzero-bruteforce**](https://github.com/tobiabocchi/flipperzero-bruteforce)\*\*\*\*

### 手動で追加

{% hint style="info" %}
設定されたプロトコルリストから信号を追加する
{% endhint %}

#### [サポートされているプロトコル](https://docs.flipperzero.one/sub-ghz/add-new-remote)のリスト <a href="#3iglu" id="3iglu"></a>

| Princeton\_433 (静的コードシステムの大多数で動作) | 433.92 | 静的  |
| --------------------------------------------------- | ------ | ----- |
| Nice Flo 12bit\_433                                 | 433.92 | 静的  |
| Nice Flo 24bit\_433                                 | 433.92 | 静的  |
| CAME 12bit\_433                                     | 433.92 | 静的  |
| CAME 24bit\_433                                     | 433.92 | 静的  |
| Linear\_300                                         | 300.00 | 静的  |
| CAME TWEE                                           | 433.92 | 静的  |
| Gate TX\_433                                        | 433.92 | 静的  |
| DoorHan\_315                                        | 315.00 | 動的 |
| DoorHan\_433                                        | 433.92 | 動的 |
| LiftMaster\_315                                     | 315.00 | 動的 |
| LiftMaster\_390                                     | 390.00 | 動的 |
| Security+2.0\_310                                   | 310.00 | 動的 |
| Security+2.0\_315                                   | 315.00 | 動的 |
| Security+2.0\_390                                   | 390.00 | 動的 |

### サポートされているSub-GHzベンダー

リストは[https://docs.flipperzero.one/sub-ghz/supported-vendors](https://docs.flipperzero.one/sub-ghz/supported-vendors)で確認してください。

### 地域別にサポートされている周波数

リストは[https://docs.flipperzero.one/sub-ghz/frequencies](https://docs.flipperzero.one/sub-ghz/frequencies)で確認してください。

### テスト

{% hint style="info" %}
保存された周波数のdBmを取得する
{% endhint %}

## 参考文献

* [https://docs.flipperzero.one/sub-ghz](https://docs.flipperzero.one/sub-ghz)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より早く修正してください。Intruderは攻撃面を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリ、クラウドシステムまで、技術スタック全体にわたる問題を見つけます。今日[**無料で試す**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
