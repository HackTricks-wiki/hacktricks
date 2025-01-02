# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## はじめに

125kHzタグの動作についての詳細は、以下を確認してください：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## アクション

これらのタイプのタグについての詳細は、[**このイントロを読む**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)で確認できます。

### 読み取り

カード情報を**読み取る**ことを試みます。その後、**エミュレート**できます。

> [!WARNING]
> 一部のインターホンは、読み取り前に書き込みコマンドを送信することでキーの複製から自分自身を保護しようとします。書き込みが成功すると、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートする際、リーダーは元のものと区別する方法がないため、そのような問題は発生しません。

### 手動で追加

**手動でデータを指定してFlipper Zeroに偽カードを作成**し、その後エミュレートできます。

#### カードのID

カードを取得すると、ID（またはその一部）がカードに表示されていることがあります。

- **EM Marin**

例えば、このEM-Marinカードでは、物理カードの最後の3バイトのうちの5バイトを**クリアで読み取る**ことが可能です。\
他の2バイトは、カードから読み取れない場合はブルートフォースで解読できます。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

このHIDカードでも同様に、3バイトのうちの2バイトのみがカードに印刷されています。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### エミュレート/書き込み

カードを**コピー**したり、IDを**手動で入力**した後、Flipper Zeroで**エミュレート**したり、実際のカードに**書き込む**ことが可能です。

## 参考文献

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../../banners/hacktricks-training.md}}
