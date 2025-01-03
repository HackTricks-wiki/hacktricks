# JTAG

{{#include ../../banners/hacktricks-training.md}}

## JTAGenum

[**JTAGenum** ](https://github.com/cyphunk/JTAGenum)は、Raspberry PIまたはArduinoを使用して、未知のチップからJTAGピンを探すために使用できるツールです。\
**Arduino**では、**2から11のピンをJTAGに属する可能性のある10ピンに接続します**。プログラムをArduinoにロードすると、すべてのピンをブルートフォースで試して、どのピンがJTAGに属するかを見つけます。\
**Raspberry PI**では、**1から6のピンのみを使用できます**（6ピンなので、各潜在的なJTAGピンをテストするのが遅くなります）。

### Arduino

Arduinoでは、ケーブルを接続した後（ピン2から11をJTAGピンに、Arduino GNDをベースボードGNDに接続）、**JTAGenumプログラムをArduinoにロード**し、シリアルモニターで**`h`**（ヘルプコマンド）を送信すると、ヘルプが表示されます：

![](<../../images/image (939).png>)

![](<../../images/image (578).png>)

**「No line ending」と115200baudを設定します**。\
スキャンを開始するためにコマンドsを送信します：

![](<../../images/image (774).png>)

JTAGに接続している場合、**FOUND!**で始まる1つまたは複数の**行が表示され、JTAGのピンを示します**。

{{#include ../../banners/hacktricks-training.md}}
