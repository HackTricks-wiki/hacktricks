# Office file analysis

{{#include ../../../banners/hacktricks-training.md}}

さらなる情報は[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)を確認してください。これは要約です：

Microsoftは多くのオフィス文書フォーマットを作成しており、主に**OLEフォーマット**（RTF、DOC、XLS、PPTなど）と**Office Open XML (OOXML)フォーマット**（DOCX、XLSX、PPTXなど）の2種類があります。これらのフォーマットにはマクロが含まれることがあり、フィッシングやマルウェアの標的となります。OOXMLファイルはzipコンテナとして構造化されており、解凍することでファイルとフォルダの階層やXMLファイルの内容を確認できます。

OOXMLファイル構造を探るための文書を解凍するコマンドと出力構造が示されています。これらのファイルにデータを隠す技術が文書化されており、CTFチャレンジ内でのデータ隠蔽の革新が続いていることを示しています。

分析のために、**oletools**と**OfficeDissector**はOLEおよびOOXML文書を調査するための包括的なツールセットを提供します。これらのツールは、しばしばマルウェア配信のベクターとして機能する埋め込まれたマクロを特定し分析するのに役立ちます。VBAマクロの分析は、Libre Officeを利用することでMicrosoft Officeなしで行うことができ、ブレークポイントやウォッチ変数を使ってデバッグが可能です。

**oletools**のインストールと使用は簡単で、pipを介してインストールし、文書からマクロを抽出するためのコマンドが提供されています。マクロの自動実行は、`AutoOpen`、`AutoExec`、または`Document_Open`のような関数によってトリガーされます。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
{{#include ../../../banners/hacktricks-training.md}}
