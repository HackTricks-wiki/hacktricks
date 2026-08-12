# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## 導入

125 kHzタグの動作の背景については、以下を参照してください。

{{#ref}}
../pentesting-rfid.md
{{#endref}}

[低周波RFIDの概要](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)では、一般的なタグの種類とデータ形式について説明しています。

## 操作

### 読み取り

**Read**を使用してタグデータをキャプチャします。読み取りに成功すると、Flipper Zeroは保存したタグをエミュレートできます。<sup>[[1]](#references)</sup>

> [!WARNING]
> 一部のインターホンリーダーは、読み取り前に書き込みコマンドを発行して、書き込み可能な複製タグを検出しようとします。Flipper Zeroのエミュレーションでは、書き込み可能なタグメモリを同じ方法で公開しません。<sup>[[1]](#references)</sup>

### 手動で追加

Flipper Zeroにタグデータを手動で入力して保存し、その後エミュレートできます。<sup>[[1]](#references)</sup>

#### カード上のID

カードによっては、IDの全部または一部が外装に印刷されています。

- **EM Marin**

たとえば、画像のEM-Marinカードには、5バイトあるIDのうち最後の3バイトが表示されています。タグを読み取れない場合は、不足している2バイトをbrute-forceできる可能性があります。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

同様に、画像のHIDカードには、3バイトあるIDのうち2バイトだけが印刷されています。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

タグを読み取るか、IDを手動で入力した後、Flipper Zeroは保存した認証情報をエミュレートできます。対応している書き込み可能なタグでは、保存したデータを互換性のあるカードに書き込むこともできます。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zero: RFIDプロトコルを深掘り](https://blog.flipperzero.one/rfid/)
{{#include ../../../banners/hacktricks-training.md}}
