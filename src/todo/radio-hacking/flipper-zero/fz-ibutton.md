# FZ - iButton

{{#include ../../../banners/hacktricks-training.md}}

## はじめに

iButton technologyの背景については、以下を参照してください。

{{#ref}}
../ibutton.md
{{#endref}}

## 設計

次の画像では、**青色**の領域が、読み取りのために物理的なiButtonをFlipper Zeroの接点に当てる位置を示しています。**緑色**の領域は、emulation中にreaderに接触させるべき接点を示しています。<sup>[[1]](#references)</sup>

<figure><img src="../../../images/image (565).png" alt=""><figcaption></figcaption></figure>

## Actions

### 読み取り

Read modeでは、Flipper Zeroはkeyが接点に触れるのを待ち、protocolを検出し、key IDの上にprotocolを表示します。組み込みapplicationは、Dallas、Cyfral、Metakomのaccess-control keyをサポートしています。<sup>[[2]](#references)</sup>

### 手動で追加

Dallas、Cyfral、Metakom protocolのkey dataを手動で入力できます。<sup>[[2]](#references)</sup>

### Emulate

物理keyから読み取ったものでも、手動で入力したものでも、保存済みのkeyをemulateできます。<sup>[[2]](#references)</sup>

> [!TIP]
> 組み込み接点がreaderに届かない場合は、GPIO pinsを介してdata接点とground接点を接続してください。<sup>[[2]](#references)</sup>

<figure><img src="../../../images/image (138).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Flipper ZeroでiButton Keysを使いこなす](https://blog.flipperzero.one/taming-ibutton/)
- [2] [Flipper Zero documentation - iButton keysの読み取り](https://docs.flipper.net/zero/ibutton/read)
{{#include ../../../banners/hacktricks-training.md}}
