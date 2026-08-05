# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## 概要

iButton の詳細については、以下を確認してください:


{{#ref}}
../ibutton.md
{{#endref}}

## 設計

以下の画像の**青色**の部分は、Flipper が**読み取れるように、実際の iButton を配置する**位置です。**緑色**の部分は、Flipper zero で**正しく iButton をエミュレートするために**リーダーに接触させる位置です。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 読み取り

Read Mode では、Flipper は iButton キーが接触するのを待機し、3 種類のキー、**Dallas、Cyfral、Metakom** を読み取れます。Flipper は**キーの種類を自動的に判別します**。キーのプロトコル名は、ID 番号の上に画面表示されます。<sup>[[1]](#references)</sup>

### 手動で追加

**Dallas、Cyfral、Metakom** タイプの iButton を**手動で追加できます**。

### **エミュレート**

保存した iButton（読み取ったもの、または手動で追加したもの）を**エミュレートできます**。

> [!TIP]
> Flipper Zero をリーダーに接触させて、想定どおりの接点を作れない場合は、**外部 GPIO を使用できます:**

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## 参考資料

- [1] [Taming iButton Keys with Flipper Zero](https://blog.flipperzero.one/taming-ibutton/)

{{#include ../../../banners/hacktricks-training.md}}
