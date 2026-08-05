# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}


## 概要

125kHzタグの仕組みについて詳しくは、以下を確認してください:


{{#ref}}
../pentesting-rfid.md
{{#endref}}

## 操作

これらのタイプのタグについて詳しくは、[**この概要を読んでください**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)。

### 読み取り

カード情報の**読み取り**を試みます。その後、それらを**emulate**できます。<sup>[[1]](#references)</sup>

> [!WARNING]
> 一部のインターホンは、読み取り前にwrite commandを送信することで、キーの複製から自身を保護しようとします。writeが成功した場合、そのタグは偽物とみなされます。FlipperがRFIDをemulateする場合、readerがそれをオリジナルと区別する方法はないため、このような問題は発生しません。

### 手動で追加

手動で入力したデータを示す**偽のカードをFlipper Zeroで作成**し、それをemulateできます。

#### カード上のID

カードを入手した際、ID（またはその一部）がカードの表面に見える形で書かれていることがあります。

- **EM Marin**

たとえば、このEM-Marinカードでは、物理カード上で5バイトのうち最後の3バイトを**平文で読み取る**ことができます。\
カードから読み取れない場合は、残りの2バイトをbrute-forceできます。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

このHIDカードでも同様に、3バイトのうち2バイトだけがカードに印刷されています。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

カードを**コピー**するか、IDを**手動で入力**した後、Flipper Zeroでそれを**emulate**するか、実際のカードに**write**できます。<sup>[[1]](#references)</sup>

## 参考資料

- [1] [Diving into RFID Protocols with Flipper Zero](https://blog.flipperzero.one/rfid/)


{{#include ../../../banners/hacktricks-training.md}}
