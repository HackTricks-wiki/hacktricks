# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## はじめに <a href="#id-9wrzi" id="id-9wrzi"></a>

RFIDとNFCの詳細については、以下のページを確認してください。


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 対応しているNFCカード <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFCカード以外にも、Flipper Zeroは複数の**Mifare** ClassicやUltralight、**NTAG**などの**その他の種類の高周波カード**に対応しています。

対応カードのリストには、新しい種類のNFCカードが追加されます。Flipper Zeroは、以下の**NFCカード type A**（ISO 14443A）に対応しています。

- **Bank cards (EMV)** — UID、SAK、ATQAのみを読み取り、保存はしません。
- **Unknown cards** — UID、SAK、ATQAを読み取り、UIDをemulateします。

**NFC cards type B、type F、type V**の場合、Flipper ZeroはUIDを保存せずに読み取ることができます。

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

Flipper Zeroは、Bank cardsのUID、SAK、ATQA、および保存データを**保存せずに**読み取ることしかできません。

Bank card reading screenBank cardsの場合、Flipper Zeroはデータを**保存およびemulateせずに**読み取ることしかできません。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zeroが**NFCカードの種類を判別できない**場合、**UID、SAK、ATQA**のみを**読み取り、保存**できます。

Unknown card reading screenUnknown NFC cardsの場合、Flipper ZeroはUIDのみをemulateできます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

**NFC cards types B、F、V**の場合、Flipper ZeroはUIDを保存せずに**読み取り、表示する**ことしかできません。

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFCの概要については、[**このページを読んでください**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### Read

Flipper Zeroは**NFCカードを読み取る**ことができますが、ISO 14443をベースとする**すべてのprotocolを理解できるわけではありません**。ただし、**UIDはlow-level attribute**であるため、**UIDはすでに読み取られているものの、high-level data transfer protocolはまだ不明**という状況になることがあります。UIDをauthorizationに使用するprimitive readerに対しては、Flipperを使用してUIDを読み取り、emulateし、手動で入力できます。<sup>[[1]](#references)</sup>

#### UIDの読み取りと内部データの読み取りの違い <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipperでは、13.56 MHz tagsの読み取りは2つの部分に分けられます。<sup>[[1]](#references)</sup>

- **Low-level read** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこのデータに基づいてhigh-level protocolを推測します。これは特定の要因に基づく単なる推測であるため、100%確実とは限りません。
- **High-level read** — 特定のhigh-level protocolを使用して、カードのmemoryからデータを読み取ります。これは、Mifare Ultralightのデータを読み取ること、Mifare Classicのsectorを読み取ること、またはPayPass/Apple Payからカードのattributeを読み取ることを意味します。

### Read Specific

Flipper Zeroがlow level dataからカードの種類を見つけられない場合、`Extra Actions`で`Read Specific Card Type`を選択し、読み取りたいカードの種類を**手動で****指定**できます。

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

UIDを単に読み取るだけでなく、Bank cardからさらに多くのデータを抽出できます。**カード番号全体**（カード表面の16桁）、**有効期限**、場合によっては**所有者の名前**と**最新の取引履歴**の一覧まで取得できます。\
ただし、この方法で**CVV**（カード裏面の3桁）を読み取ることはできません。また、**Bank cardsはreplay attacksから保護**されているため、Flipperでコピーしてから支払いのためにemulateしようとしても機能しません。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper ZeroでRFID Protocolsを詳しく調べる](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
