# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

125 kHzタグの仕組みについては、以下を参照してください。

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[低周波RFIDの概要](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)では、一般的なタグファミリーとデータ形式について説明しています。

## 操作

### 読み取り

**Read**を使ってタグデータを取得します。読み取りに成功すると、Flipper Zeroは保存したタグをエミュレートできます。<sup>[[1]](#references)</sup>

> [!WARNING]
> 一部のインターコムリーダーは、読み取り前に書き込みコマンドを送信し、書き込み可能な複製タグを検出しようとします。Flipper Zeroのエミュレーションでは、書き込み可能なタグメモリを同じ方法で公開しません。<sup>[[1]](#references)</sup>

### 手動で追加

Flipper Zeroにタグデータを手動で入力して保存し、その後エミュレートできます。<sup>[[1]](#references)</sup>

#### カードに記載されたID

カードによっては、IDの全部または一部が外面に印刷されています。

- **EM Marin**

たとえば、画像のEM-Marinカードには、5バイトのIDのうち末尾3バイトが記載されています。タグを読み取れない場合は、不足している2バイトをbrute-forceできる可能性があります。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

同様に、画像のHIDカードには、3バイトのIDのうち2バイトだけが印刷されています。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

タグを読み取るか、IDを手動で入力すると、Flipper Zeroは保存した認証情報をエミュレートできます。書き込みに対応したタグであれば、保存したデータを互換性のあるカードに書き込むこともできます。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFIDプロトコルを掘り下げる](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
