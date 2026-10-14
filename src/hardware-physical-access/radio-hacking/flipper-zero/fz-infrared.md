# FZ - 赤外線

{{#include ../../../banners/hacktricks-training.md}}

## はじめに <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の仕組みについて詳しくは、こちらを確認してください。


{{#ref}}
../infrared.md
{{#endref}}

## Flipper ZeroのIR信号受信機 <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

Flipper Zeroは、一般的なIRリモコンから信号を取得するために、復調式IR受信機を使用します。一部のスマートフォン（特定のXiaomiモデルなど）にはIR送信機が搭載されていますが、リモコン信号を受信してデコードできるものはほとんどありません。<sup>[[1]](#references)</sup>

Flipperの赤外線**受信機は非常に高感度**です。リモコンとテレビの**間のどこかにいる状態でも**、信号を**受信できます**。リモコンをFlipperのIRポートに直接向ける必要はありません。これは、誰かがテレビの近くに立ってチャンネルを切り替えていて、自分とFlipperが離れた場所にいる場合に便利です。

プロトコルのデコードはソフトウェアで行われます。認識されたプロトコルはデコード済みコマンドとして保存でき、未対応のプロトコルは生のタイミングデータとして取得して再生できます。ただし、ハードウェアの搬送波周波数とタイミングの制限を受けます。<sup>[[1]](#references)</sup>

## 操作

### ユニバーサルリモコン

Flipper Zeroのユニバーサルリモコンモードは、対応するテレビ、オーディオ機器、プロジェクター、エアコン向けに、赤外線データベースに登録された既知のコマンドを順に送信します。すべての機器を操作できるとは限りません。また、自分が所有する機器、またはテストを許可された機器にのみ使用してください。<sup>[[1]](#references)</sup>

ユニバーサルリモコンモードで電源ボタンを押すだけで、Flipperは認識しているすべてのテレビ（Sony、Samsung、Panasonicなど）に「Power Off」コマンドを**順番に送信**します。テレビが信号を受信すると反応し、電源が切れます。

このbrute-forceには時間がかかります。辞書が大きいほど、完了までに時間がかかります。テレビから応答がないため、テレビがどの信号を認識したのかを特定することはできません。

### 新しいリモコンを学習

Flipper Zeroは**赤外線信号を取得できます**。プロトコルとコマンドを認識できた場合は、デコードされた形式で保存します。認識できない場合は、後で再生できるよう、生のタイミングデータを保存できます。<sup>[[1]](#references)</sup>

## References

- [1] [Flipper Zeroの赤外線ポートでテレビを乗っ取る](https://blog.flipperzero.one/infrared/)
{{#include ../../../banners/hacktricks-training.md}}
