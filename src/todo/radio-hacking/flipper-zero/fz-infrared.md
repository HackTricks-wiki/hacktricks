# FZ - 赤外線

{{#include ../../../banners/hacktricks-training.md}}

## 概要 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の仕組みについて詳しくは、以下を確認してください:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper ZeroのIR信号受信機 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zeroは、一般的なIRリモコンから信号をキャプチャするために、復調IRレシーバーを使用します。一部のスマートフォンには、特定のXiaomiモデルを含め、IRトランスミッターが搭載されていますが、ほとんどの端末はリモコン信号を受信してデコードできません。<sup>[[1]](#references)</sup>

Flipperの赤外線**受信機は非常に高感度です**。リモコンとテレビの**間のどこかにいる**だけでも、**信号をキャッチできます**。リモコンをFlipperのIRポートに直接向ける必要はありません。これは、誰かがテレビの近くに立ってチャンネルを切り替えているときに便利です。その際、あなたとFlipperの両方がテレビから離れた場所にいても使用できます。

Protocolのデコードはソフトウェアで行われます。認識されたProtocolはデコード済みのコマンドとして保存でき、サポートされていないProtocolは、ハードウェアの搬送周波数とタイミングの制限内で、raw timing dataとしてキャプチャして再生できます。<sup>[[1]](#references)</sup>

## アクション

### Universal Remotes

Flipper ZeroのUniversal Remoteモードは、対応するテレビ、オーディオ機器、プロジェクター、エアコン向けに、赤外線データベース内の既知のコマンドを順番に試します。すべてのデバイスを制御できるとは限らないため、自分が所有している機器、またはテストの許可を得ている機器に対してのみ使用してください。<sup>[[1]](#references)</sup>

Universal Remoteモードで電源ボタンを押すだけで、Flipperは認識しているすべてのテレビに対して、**順番に「Power Off」コマンドを送信**します。テレビがその信号を受信すると、反応して電源が切れます。

このようなbrute-forceには時間がかかります。dictionaryが大きいほど、完了までの時間も長くなります。テレビからのフィードバックがないため、テレビが正確にどの信号を認識したのかを知ることはできません。

### 新しいリモコンを学習

Flipper Zeroは**赤外線信号をキャプチャできます**。Protocolとコマンドを認識できた場合は、デコード済みの表現を保存します。それ以外の場合は、後で再生できるようにraw timing dataを保存できます。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zeroの赤外線ポートによるテレビの乗っ取り](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
