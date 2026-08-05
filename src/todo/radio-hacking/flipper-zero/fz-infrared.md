# FZ - 赤外線

{{#include ../../../banners/hacktricks-training.md}}

## はじめに <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

赤外線の仕組みについて詳しくは、以下を確認してください:


{{#ref}}
../infrared.md
{{#endref}}

## Flipper ZeroのIR Signal Receiver <a href="#ir-signal-receiver-in-flipper-zero" id="ir-signal-receiver-in-flipper-zero"></a>

FlipperはデジタルIR Signal ReceiverであるTSOPを使用しており、**IR remoteからの信号を傍受できます**。XiaomiのようにIRポートを搭載した**スマートフォン**もありますが、**ほとんどの機種は信号を送信することしかできず、受信はできない**ことに注意してください。<sup>[[1]](#references)</sup>

Flipperの赤外線**receiverは非常に高感度です**。remoteとTVの**間のどこかに**いるだけでも、**信号をキャッチできます**。remoteをFlipperのIRポートへ直接向ける必要はありません。これは、誰かがTVの近くに立ってチャンネルを切り替えているときに、あなたとFlipperがある程度離れた場所にいる場合に役立ちます。

赤外線信号の**decodingは**ソフトウェア**側で行われる**ため、Flipper Zeroは原理上、あらゆるIR remote codeの**受信と送信をサポートできます**。認識できない**unknown** protocolの場合は、受信したraw signalをそのまま**記録して再生します**。<sup>[[1]](#references)</sup>

## Actions

### Universal Remotes

Flipper Zeroは、**あらゆるTV、エアコン、メディアセンターを操作するuniversal remote**として使用できます。このモードでは、Flipperは**SDカード上のdictionaryに従って**、サポートされているすべてのmanufacturerの**known codeをbruteforce**します。レストランのTVを消すために、特定のremoteを選ぶ必要はありません。<sup>[[1]](#references)</sup>

Universal Remoteモードでpower buttonを押すだけで、Flipperは認識しているすべてのTVに対して**「Power Off」** commandを**順番に送信**します。TVがその信号を受信すると、反応して電源が切れます。

このbrute-forceには時間がかかります。dictionaryが大きいほど、完了までに時間がかかります。TVからのfeedbackがないため、TVが正確にどの信号を認識したのかを知ることはできません。

### Learn New Remote

Flipper Zeroで**赤外線信号をcapture**できます。信号が**database内に見つかる**と、Flipperは自動的に**どのdeviceのものかを把握し**、操作できるようにします。\
見つからない場合でも、Flipperはその**信号を保存**し、**replay**できるようにします。<sup>[[1]](#references)</sup>

## References

- [1] [Taking over TVs with Flipper Zero Infrared Port](https://blog.flipperzero.one/infrared/)

{{#include ../../../banners/hacktricks-training.md}}
