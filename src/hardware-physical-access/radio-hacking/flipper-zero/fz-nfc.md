# FZ - NFC

{{#include ../../../banners/hacktricks-training.md}}

## はじめに <a href="#id-9wrzi" id="id-9wrzi"></a>

RFIDとNFCについては、次のページを確認してください。


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 対応するNFCカード <a href="#id-9wrzi" id="id-9wrzi"></a>

> [!CAUTION]
> Flipper ZeroはNFCカードに加えて、複数の**Mifare** Classic、Ultralight、**NTAG**など、**他の種類の高周波カード**にも対応しています。

以下の機能一覧は、元の記事で説明されているファームウェアを対象としたもので、現在の対応状況を網羅したものではありません。Flipperのファームウェアでは、時間の経過とともにプロトコルが追加され、NFCの動作も変更されています。インストールされているファームウェアの最新の公式ドキュメントを確認してください。<sup>[[1]](#references)</sup><sup>[[2]](#references)</sup>

- **銀行カード（EMV）** — UID、SAK、ATQAのみを読み取り、保存はしません。
- **不明なカード** — UID、SAK、ATQAを読み取り、UIDをエミュレートします。

**NFCカードのタイプB、F、V**では、説明されているファームウェアはUIDを保存せずに読み取ることができました。

### NFCカードのタイプA <a href="#uvusf" id="uvusf"></a>

#### 銀行カード（EMV） <a href="#kzmrp" id="kzmrp"></a>

説明されているファームウェアは、銀行カードのUID、SAK、ATQA、および取得可能なアプリケーションデータを**保存せずに**読み取ることができました。

これらの銀行カードでは、ファームウェアはカードのデータを表示しますが、保存もエミュレートもしません。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-26-31.png?auto=format&ixlib=react-9.1.1&h=916&w=2662" alt=""><figcaption></figcaption></figure>

#### 不明なカード <a href="#id-37eo8" id="id-37eo8"></a>

Flipper Zeroが**NFCカードのタイプを特定できない**場合、**UID、SAK、ATQA**のみを**読み取って保存**できます。

不明なNFCカードの場合、このモードでエミュレートできるのはUIDのみです。

<figure><img src="https://cdn.flipperzero.one/Monosnap_Miro_2022-08-17_12-27-53.png?auto=format&ixlib=react-9.1.1&h=932&w=2634" alt=""><figcaption></figcaption></figure>

### NFCカードのタイプB、F、V <a href="#wyg51" id="wyg51"></a>

元の記事で説明されているファームウェアでは、NFCカードのタイプB、F、Vは識別子を読み取って表示することしかできず、保存はできませんでした。<sup>[[1]](#references)</sup>

<figure><img src="https://archbee.imgix.net/3StCFqarJkJQZV-7N79yY/zBU55Fyj50TFO4U7S-OXH_screenshot-2022-08-12-at-182540.png?auto=format&ixlib=react-9.1.1&h=1080&w=2704" alt=""><figcaption></figcaption></figure>

## 操作

NFCの概要については、[**こちらのページをお読みください**](../pentesting-rfid.md#high-frequency-rfid-tags-1356-mhz-1)。

### 読み取り

Flipper ZeroはNFCカードを読み取れますが、ISO 14443を基盤とするすべての上位プロトコルを実装しているわけではありません。そのため、低レベルのUID、SAK、ATQAを取得できても、アプリケーションプロトコルを特定できない場合があります。UIDだけで認証する単純なアクセスシステムでは、UIDの読み取り、手動入力、エミュレートが可能です。暗号学的認証を行うシステムでは、UIDのコピーだけでは不十分です。<sup>[[1]](#references)</sup>

#### UIDの読み取りと内部データの読み取りの違い <a href="#reading-the-uid-vs-reading-the-data-inside" id="reading-the-uid-vs-reading-the-data-inside"></a>

<figure><img src="../../../images/image (217).png" alt=""><figcaption></figcaption></figure>

Flipperで13.56 MHzのタグを読み取る処理は、次の2つに分けられます。<sup>[[1]](#references)</sup>

- **低レベル読み取り** — UID、SAK、ATQAのみを読み取ります。Flipperは、カードから読み取ったこれらのデータをもとに上位プロトコルを推測します。特定の要素に基づく推測にすぎないため、確実とは言えません。
- **高レベル読み取り** — 特定の上位プロトコルを使用して、カードのメモリからデータを読み取ります。たとえば、Mifare Ultralightのデータ、Mifare Classicのセクター、PayPass/Apple Payのカード属性を読み取ります。

### 特定タイプの読み取り

Flipper Zeroが低レベルデータからカードのタイプを特定できない場合は、`Extra Actions`で`Read Specific Card Type`を選択し、**読み取りたいカードのタイプを手動で指定**できます。

#### EMV銀行カード（PayPass、payWave、Apple Pay、Google Pay） <a href="#emv-bank-cards-paypass-paywave-apple-pay-google-pay" id="emv-bank-cards-paypass-paywave-apple-pay-google-pay"></a>

古いFlipperファームウェアと互換性のあるEMVカードでは、UID以外の情報も取得できる場合があり、カードから利用可能な記録によっては、PAN、有効期限、カード名義人、取引ログなどが含まれる可能性があります。取得できる情報は、カード、アプリケーション、ファームウェアによって異なります。カードに印字された磁気ストライプ用CVVはこの方法では取得できません。また、これらの記録を読み取っても、非接触決済に必要な暗号学的な取引機能を複製することはできません。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper ZeroでRFIDプロトコルを詳しく見る](https://blog.flipperzero.one/rfid/)
- [2] [Flipper Zero documentation - NFC](https://docs.flipper.net/zero/nfc)
{{#include ../../../banners/hacktricks-training.md}}
