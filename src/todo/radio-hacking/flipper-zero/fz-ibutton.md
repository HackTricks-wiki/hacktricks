# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## Intro

iButtonについての詳細は以下を参照してください:

{{#ref}}
../ibutton.md
{{#endref}}

## Design

以下の画像の**青**い部分が、Flipperが**読み取るために本物のiButtonを置く必要がある**場所です。**緑**の部分は、Flipper zeroで**iButtonを正しくエミュレートするためにリーダーに触れる必要がある**場所です。

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### Read

リードモードでは、FlipperはiButtonキーが触れるのを待っており、**Dallas、Cyfral、Metakom**の3種類のキーを処理できます。Flipperは**キーのタイプを自動的に判断します**。キーのプロトコル名はID番号の上に表示されます。

### Add manually

**手動で**iButtonを追加することが可能です: **Dallas、Cyfral、Metakom**

### **Emulate**

保存されたiButton（読み取りまたは手動追加）を**エミュレート**することが可能です。

> [!NOTE]
> Flipper Zeroの期待される接触がリーダーに触れない場合は、**外部GPIOを使用できます:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [https://blog.flipperzero.one/taming-ibutton/](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
