# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## イントロ <a href="#9wrzi" id="9wrzi"></a>

RFIDとNFCに関する情報は、次のページを参照してください：

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## サポートされているNFCカード <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
NFCカード以外にも、Flipper Zeroは**他の種類の高周波カード**（Mifare ClassicやUltralight、NTAGなど）もサポートしています。
{% endhint %}

新しいタイプのNFCカードは、サポートされるカードのリストに追加されます。Flipper Zeroは、以下の**NFCカードタイプA**（ISO 14443A）をサポートしています：

* ﻿**銀行カード（EMV）** — UID、SAK、ATQAの読み取りのみで保存はしません。
* ﻿**不明なカード** — UID、SAK、ATQAの読み取りとUIDのエミュレーションが可能です。

**NFCカードタイプB、タイプF、タイプV**については、Flipper ZeroはUIDの読み取りのみで保存はしません。

### NFCカードタイプA <a href="#uvusf" id="uvusf"></a>

#### 銀行カード（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは、銀行カードのデータを**保存せずに**UID、SAK、ATQA、および保存されたデータを読み取ることができます。

銀行カードの読み取り画面Flipper Zeroは、銀行カードのデータを**保存およびエミュレートせずに**読み取ることができます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 不明なカード <a href="#37eo8" id="37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない**場合、UID、SAK、ATQAのみを**読み取りおよび保存**することができます。

不明なカードの読み取り画面不明なNFCカードの場合、Flipper ZeroはUIDのエミュレーションのみが可能です。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFCカードタイプB、F、V <a href="#wyg51" id="wyg51"></a>

**NFCカードタイプB、F、V**については、Flipper ZeroはUIDの読み取りのみで保存はしません。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## アクション

NFCについてのイントロについては、[**このページ**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)を読んでください。

### 読み取り

Flipper Zeroは**NFCカードを読み取る**ことができますが、ISO 14443に基づく**すべてのプロトコルを理解するわけではありません**。ただし、**UIDは低レベルの属性**であるため、UIDが既に読み取られているが、ハイレベルのデータ転送プロトコルがまだ不明な状況になることがあります。UIDを使用してプリミティブなリーダーで読み取り、エミュレート、手動で入力することができます。

#### UIDの読み取りと内部のデータの読み取り <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHzのタグの読み取りは2つのパートに分けることができます：

* **低レベルの読み取り** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいてハイレベルのプロトコルを推測しようとします。これはあくまで一部の要素に基づく推測であり、100％確実ではありません。
* **ハイレベルの読み取り** — 特定のハイレベルのプロトコルを使用してカードのメモリからデータを読み取ります。これはMifare Ultralightのデータの読み取り、Mifare Classicのセクターの読み取り、PayPass/Apple Payからカードの属性の読み取りなどが該当します。
### 特定の読み取り

Flipper Zeroが低レベルデータからカードの種類を見つけることができない場合、`追加のアクション`で`特定のカードの種類を読み取る`を選択し、**手動で読み取りたいカードの種類を指定**することができます。

#### EMV銀行カード（PayPass、payWave、Apple Pay、Google Pay）<a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UIDだけでなく、銀行カードからはさらに多くのデータを抽出することができます。カードの表面にある16桁の**カード番号全体**、**有効期限**、そして一部の場合は**所有者の名前**と**最新の取引のリスト**を取得することができます。\
ただし、この方法では**CVV（カードの裏面にある3桁の番号）は読み取れません**。また、**銀行カードはリプレイ攻撃から保護されているため**、Flipperでコピーしてからそれをエミュレートして支払いを試みることはできません。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
