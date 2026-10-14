# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

iButton技術の概要については、以下を参照してください。

{{#ref}}
../ibutton.md
{{#endref}}

## 設計

以下の画像では、**青色**の領域が、読み取り時に物理iButtonをFlipper Zeroの接点に当てる位置を示しています。**緑色**の領域は、エミュレーション時にリーダーへ接触させる接点を示しています。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## 操作

### 読み取り

Readモードでは、Flipper Zeroはキーが接点に触れるのを待ち、プロトコルを検出して、キーIDの上にプロトコルを表示します。内蔵アプリケーションは、Dallas、Cyfral、Metakomのアクセス制御キーに対応しています。<sup>[[2]](#references)</sup>

### 手動で追加

Dallas、Cyfral、Metakomプロトコルのキー情報を手動で入力できます。<sup>[[2]](#references)</sup>

### エミュレート

物理キーから読み取ったキーも、手動で入力したキーも、保存したキーをエミュレートできます。<sup>[[2]](#references)</sup>

> [!TIP]
> 内蔵接点がリーダーに届かない場合は、GPIOピンを介してデータ接点とグラウンド接点を接続してください。<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper ZeroでiButtonキーを使いこなす](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zeroドキュメント - iButtonキーの読み取り](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}

