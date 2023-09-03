# FZ - NFC

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)をご覧ください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できます。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## イントロ <a href="#9wrzi" id="9wrzi"></a>

RFIDとNFCに関する情報は、次のページを参照してください：

{% content-ref url="../../../radio-hacking/pentesting-rfid.md" %}
[pentesting-rfid.md](../../../radio-hacking/pentesting-rfid.md)
{% endcontent-ref %}

## サポートされているNFCカード <a href="#9wrzi" id="9wrzi"></a>

{% hint style="danger" %}
NFCカード以外にも、Flipper Zeroは**他の種類の高周波カード**（複数の**Mifare** ClassicおよびUltralightおよび**NTAG**など）をサポートしています。
{% endhint %}

新しいタイプのNFCカードは、サポートされるカードのリストに追加されます。Flipper Zeroは、次の**NFCカードタイプA**（ISO 14443A）をサポートしています：

* ﻿**銀行カード（EMV）** — UID、SAK、ATQAのみを読み取り、保存しません。
* ﻿**不明なカード** — UID、SAK、ATQAを読み取り、UIDをエミュレートします。

**NFCカードタイプB、タイプF、およびタイプV**については、Flipper ZeroはUIDを保存せずに読み取ることができます。

### NFCカードタイプA <a href="#uvusf" id="uvusf"></a>

#### 銀行カード（EMV） <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは、銀行カードのデータを**保存せずに**UID、SAK、ATQA、および保存されたデータを読み取ることができます。

銀行カードの読み取り画面銀行カードの場合、Flipper Zeroはデータを**保存せずに読み取る**ことしかできません。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### 不明なカード <a href="#37eo8" id="37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない**場合、UID、SAK、ATQAのみを**読み取り、保存**することができます。

不明なカードの読み取り画面不明なNFCカードの場合、Flipper ZeroはUIDのみをエミュレートすることができます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFCカードタイプB、F、およびV <a href="#wyg51" id="wyg51"></a>

**NFCカードタイプB、F、およびV**については、Flipper ZeroはUIDを保存せずに読み取り、表示することができます。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## アクション

NFCについてのイントロについては、[**このページ**](../../../radio-hacking/pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)を読んでください。

### 読み取り

Flipper Zeroは**NFCカードを読み取る**ことができますが、ISO 14443に基づくすべてのプロトコルを**理解するわけではありません**。ただし、**UIDは低レベルの属性**であるため、UIDが既に読み取られているが、ハイレベルのデータ転送プロトコルがまだ不明な状況になることがあります。UIDを使用して認証するプリミティブリーダーのために、Flipperを使用してUIDを読み取り、エミュレート、手動で入力することができます。
#### UIDの読み取りと内部データの読み取り<a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../.gitbook/assets/image (26).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHzのタグの読み取りは2つのパートに分けられます：

* **低レベルの読み取り** - UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいて高レベルのプロトコルを推測しようとします。これはあくまで特定の要素に基づく推測であり、100％確実ではありません。
* **高レベルの読み取り** - 特定の高レベルのプロトコルを使用して、カードのメモリからデータを読み取ります。これは、Mifare Ultralightのデータの読み取り、Mifare Classicのセクターの読み取り、PayPass/Apple Payからカードの属性の読み取りなどです。

### 特定の読み取り

Flipper Zeroが低レベルのデータからカードのタイプを見つけることができない場合、`Extra Actions`で`Read Specific Card Type`を選択し、**手動で読み取りたいカードのタイプを指定**することができます。

#### EMV銀行カード（PayPass、payWave、Apple Pay、Google Pay）<a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UIDだけでなく、銀行カードからはさらに多くのデータを抽出することができます。カードの表面にある16桁の**カード番号**、**有効期限**、そして場合によっては**所有者の名前**と**最近の取引のリスト**を取得することができます。\
ただし、この方法では**CVV（カードの裏面にある3桁の番号）は読み取れません**。また、**銀行カードはリプレイ攻撃から保護されているため**、Flipperでコピーしてから何かを支払うためにエミュレートすることはできません。

## 参考文献

* [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

最も重要な脆弱性を見つけて、より速く修正できるようにしましょう。Intruderは攻撃対象を追跡し、積極的な脅威スキャンを実行し、APIからWebアプリまで、クラウドシステムまで、技術スタック全体で問題を見つけます。[**無料でお試しください**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks)。

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください**。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください**。

</details>
