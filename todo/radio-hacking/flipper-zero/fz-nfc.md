# FZ - NFC

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングトリックを共有するには、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください**。

</details>

## イントロ <a href="#id-9wrzi" id="id-9wrzi"></a>

RFIDとNFCに関する情報は次のページを参照してください：

{% content-ref url="../pentesting-rfid.md" %}
[pentesting-rfid.md](../pentesting-rfid.md)
{% endcontent-ref %}

## サポートされているNFCカード <a href="#id-9wrzi" id="id-9wrzi"></a>

{% hint style="danger" %}
NFCカード以外にも、Flipper Zeroはいくつかの**Mifare** ClassicやUltralight、**NTAG**などの**他の種類の高周波カード**をサポートしています。
{% endhint %}

新しい種類のNFCカードがサポートされる予定です。Flipper Zeroは以下の**NFCカードタイプA**（ISO 14443A）をサポートしています：

* ﻿**銀行カード（EMV）** — UID、SAK、ATQAのみを読み取り、保存しません。
* ﻿**不明なカード** — （UID、SAK、ATQA）を読み取り、UIDをエミュレートします。

**NFCカードタイプB、タイプF、およびタイプV**について、Flipper ZeroはUIDを保存せずに読み取ることができます。

### NFCカードタイプA <a href="#uvusf" id="uvusf"></a>

#### 銀行カード（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは、銀行カードのデータを**保存せずに**UID、SAK、ATQA、および保存されたデータを読み取ることができます。

銀行カードの読み取り画面Flipper Zeroは、銀行カードのデータを**保存およびエミュレートせずに**読み取ることができます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 不明なカード <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない**場合、UID、SAK、ATQAのみを**読み取り、保存**することができます。

不明なカードの読み取り画面不明なNFCカードの場合、Flipper ZeroはUIDのみをエミュレートできます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFCカードタイプB、F、およびV <a href="#wyg51" id="wyg51"></a>

**NFCカードタイプB、F、およびV**について、Flipper ZeroはUIDを保存せずに読み取り、表示することができます。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## アクション

NFCに関するイントロについては、[**このページ**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)を参照してください。

### 読み取り

Flipper Zeroは**NFCカードを読み取る**ことができますが、ISO 14443に基づく**すべてのプロトコルを理解しているわけではありません**。ただし、**UIDは低レベルの属性**であるため、**UIDが既に読み取られているが、高レベルのデータ転送プロトコルがまだ不明**な状況に陥ることがあります。プリミティブリーダーではUIDを使用して認証する場合、Flipperを使用してUIDを読み取り、エミュレート、手動で入力することができます。

#### UIDの読み取りと内部データの読み取りの比較 <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHzタグの読み取りを2つの部分に分けることができます：

* **低レベルの読み取り** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいて高レベルのプロトコルを推測しようとします。これは、特定の要因に基づく推測に過ぎないため、100％確実ではありません。
* **高レベルの読み取り** — 特定の高レベルプロトコルを使用してカードのメモリからデータを読み取ります。これは、Mifare Ultralightのデータの読み取り、Mifare Classicからセクターの読み取り、PayPass/Apple Payからカードの属性の読み取りなどが該当します。

### 特定の読み取り

Flipper Zeroが低レベルデータからカードのタイプを特定できない場合、`Extra Actions`で`Read Specific Card Type`を選択し、**手動で**読み取りたいカードのタイプを指定できます。

#### EMV銀行カード（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UIDを単に読み取るだけでなく、銀行カードから多くのデータを抽出することができます。銀行カードのフロントにある16桁の**完全なカード番号**、**有効期限**、場合によっては**所有者の名前**と**最近の取引のリスト**さらに、**この方法ではCVVは読み取れません**（カード裏面の3桁）。また、**銀行カードはリプレイ攻撃から保護されている**ため、Flipperでコピーしてから何かを支払うためにエミュレートしようとしても機能しません。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)**に参加するか、**[**Telegramグループ**](https://t.me/peass)**に参加するか、Twitterで私をフォローしてください 🐦**[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングトリックを共有するために、PRを** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
