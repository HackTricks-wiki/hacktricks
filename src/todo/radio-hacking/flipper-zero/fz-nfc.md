# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## 概要 <a href="#id-9wrzi" id="id-9wrzi"></a>

RFID と NFC の詳細については、以下のページを確認してください:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 対応している NFC カード <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> NFC カード以外にも、Flipper Zero は複数の **Mifare** Classic や Ultralight、**NTAG** などの**その他の種類の High-frequency cards**に対応しています。

以下の対応機能一覧は、元の記事で文書化されていた firmware について説明したものであり、現在の完全な対応マトリクスとして扱うべきではありません。Flipper firmware では、時間の経過とともにプロトコルが追加され、NFC の動作も変更されています。インストールされている firmware の現在の公式ドキュメントを確認してください。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **Bank cards (EMV)** — UID、SAK、ATQA のみを読み取り、保存はしません。
- **Unknown cards** — UID、SAK、ATQA を読み取り、UID を emulate します。

**NFC card types B, F, and V**では、文書化された firmware は UID を保存せずに読み取ることができました。

### NFC cards type A <a href="#uvusf" id="uvusf"></a>

#### Bank card (EMV) <a href="#kzmrp" id="kzmrp"></a>

文書化された firmware は、bank card から UID、SAK、ATQA、および利用可能な application data を**保存せずに**読み取ることができました。

これらの bank card では、firmware はデータを表示しましたが、カードの保存や emulation は行いませんでした。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### Unknown cards <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zero が**NFC card の種類を判別できない**場合、**UID、SAK、ATQA**のみを**読み取り、保存**できます。

Unknown NFC card の場合、このモードでは UID のみを emulate できます。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFC cards types B, F, and V <a href="#wyg51" id="wyg51"></a>

元の記事で文書化されていた firmware では、NFC card types B、F、V は identifier を読み取って表示することしかできず、保存はできませんでした。<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## Actions

NFC の概要については、[**このページを読んでください**](../pentesting-rfid.md#high-frequency-rfid-tags-13.56-mhz).

### 読み取り

Flipper Zero は NFC cards を読み取れますが、ISO 14443 上に構築されたすべての higher-level protocol を実装しているわけではありません。そのため、low-level の UID、SAK、ATQA は取得できても、application protocol は不明なままになる場合があります。UID のみで認証する primitive access systems では、tool によって identifier を読み取り、手動で入力し、emulate できます。暗号学的な認証を使用する systems では、コピーした UID だけでは不十分です。<sup>[[1]](#references)</sup>

#### UID の読み取り VS 内部データの読み取り <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipper では、13.56 MHz tags の読み取りは2つの部分に分けられます:<sup>[[1]](#references)</sup>

- **Low-level read** — UID、SAK、ATQA のみを読み取ります。Flipper は、カードから読み取ったこのデータに基づいて high-level protocol を推測しようとします。これは特定の要因に基づく仮定にすぎないため、100%確実とは限りません。
- **High-level read** — 特定の high-level protocol を使用して、カードの memory からデータを読み取ります。Mifare Ultralight のデータの読み取り、Mifare Classic の sectors の読み取り、または PayPass/Apple Pay のカード attributes の読み取りなどが該当します。

### 特定の読み取り

Flipper Zero が low level data からカードの種類を判別できない場合、`Extra Actions` で `Read Specific Card Type` を選択し、**読み取りたいカードの種類を手動で**指定できます。

#### EMV Bank Cards (PayPass, payWave, Apple Pay, Google Pay) <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

以前の Flipper firmware と互換性のある EMV cards では、UID 以外に、カードから利用可能な records として PAN、expiration date、cardholder name、transaction log などが公開される場合がありました。利用可能かどうかは、card、application、firmware によって異なります。この方法で、カードに印字された magnetic-stripe CVV が公開されることはありません。また、これらの records を読み取っても、contactless payment に必要な cryptographic transaction capability が clone されるわけではありません。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero で RFID Protocols を詳しく理解する](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
