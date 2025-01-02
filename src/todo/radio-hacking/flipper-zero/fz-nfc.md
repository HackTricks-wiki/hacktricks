# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## Intro <a href="#id-9wrzi" id="id-9wrzi"></a>

RFIDとNFCに関する情報は、以下のページを確認してください：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Supported NFC cards <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFCカードの他に、Flipper Zeroは**他のタイプの高周波カード**、例えばいくつかの**Mifare** ClassicやUltralight、**NTAG**をサポートしています。

新しいタイプのNFCカードがサポートカードのリストに追加されます。Flipper Zeroは以下の**NFCカードタイプA**（ISO 14443A）をサポートしています：

- **銀行カード（EMV）** — UID、SAK、ATQAのみを読み取り、保存せずに表示します。
- **不明なカード** — UID、SAK、ATQAを読み取り、UIDをエミュレートします。

**NFCカードタイプB、タイプF、タイプV**については、Flipper ZeroはUIDを読み取ることができますが、保存はできません。

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは銀行カードのUID、SAK、ATQA、保存されたデータを**保存せずに**読み取ることができます。

銀行カード読み取り画面銀行カードについて、Flipper Zeroはデータを**保存せずにエミュレートすることなく**読み取ることができます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=916&#x26;w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない場合**、UID、SAK、ATQAのみを**読み取り、保存**できます。

不明なカード読み取り画面不明なNFCカードについて、Flipper ZeroはUIDのみをエミュレートできます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=932&#x26;w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

**NFCカードタイプB、F、V**について、Flipper ZeroはUIDを**読み取り、表示**することができますが、保存はできません。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&#x26;ixlib=react-9.1.1&#x26;h=1080&#x26;w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFCについてのイントロは[**このページを読んでください**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz)。

### Read

Flipper Zeroは**NFCカードを読み取る**ことができますが、**ISO 14443に基づくすべてのプロトコルを理解しているわけではありません**。ただし、**UIDは低レベルの属性であるため**、**UIDがすでに読み取られているが、高レベルのデータ転送プロトコルがまだ不明な状況**に直面することがあります。Flipperを使用して、UIDを認証に使用する原始的なリーダーのためにUIDを読み取り、エミュレートし、手動で入力することができます。

#### Reading the UID VS Reading the Data Inside <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHzタグの読み取りは2つの部分に分けられます：

- **低レベルの読み取り** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいて高レベルのプロトコルを推測しようとします。これは特定の要因に基づく仮定に過ぎないため、100%確実ではありません。
- **高レベルの読み取り** — 特定の高レベルプロトコルを使用してカードのメモリからデータを読み取ります。これは、Mifare Ultralightのデータを読み取ること、Mifare Classicのセクターを読み取ること、またはPayPass/Apple Payからカードの属性を読み取ることになります。

### Read Specific
