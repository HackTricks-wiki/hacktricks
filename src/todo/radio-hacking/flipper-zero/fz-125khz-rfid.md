# FZ - 125kHz RFID

{{#include ../../../banners/hacktricks-training.md}}

## Intro

125kHzタグの動作についての詳細は、以下を確認してください：

{{#ref}}
../pentesting-rfid.md
{{#endref}}

## Actions

これらのタイプのタグについての詳細は、[**このイントロを読む**](../pentesting-rfid.md#low-frequency-rfid-tags-125khz)で確認できます。

### Read

カード情報を**読み取る**ことを試みます。その後、**エミュレート**できます。

> [!WARNING]
> 一部のインターホンは、読み取り前に書き込みコマンドを送信することでキーの複製から自分自身を保護しようとします。書き込みが成功すると、そのタグは偽物と見なされます。FlipperがRFIDをエミュレートする際、リーダーは元のものと区別する方法がないため、そのような問題は発生しません。

### Add Manually

Flipper Zeroで**手動でデータを指定して偽のカードを作成**し、その後エミュレートできます。

#### IDs on cards

カードを取得すると、カードの一部にIDが書かれていることがあります。

- **EM Marin**

例えば、このEM-Marinカードでは、物理カードの最後の3バイトのうちの5バイトが**クリアで読み取れる**ことが可能です。\
他の2バイトは、カードから読み取れない場合はブルートフォースで解読できます。

<figure><img src="../../../images/image (104).png" alt=""><figcaption></figcaption></figure>

- **HID**

このHIDカードでも同様に、3バイトのうちの2バイトのみがカードに印刷されています。

<figure><img src="../../../images/image (1014).png" alt=""><figcaption></figcaption></figure>

### Emulate/Write

カードを**コピー**したり、IDを**手動で入力**した後、Flipper Zeroでそれを**エミュレート**したり、実際のカードに**書き込む**ことが可能です。

## References

- [https://blog.flipperzero.one/rfid/](https://blog.flipperzero.one/rfid/)

{{#include ../../../banners/hacktricks-training.md}}
