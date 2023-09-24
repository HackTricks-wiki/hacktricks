# オフィスファイルの分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**できます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 導入

マイクロソフトは**数十種類のオフィスドキュメントファイル形式**を作成しており、その多くは**マクロ**（VBAスクリプト）を**含む**ため、フィッシング攻撃やマルウェアの配布に人気があります。

大まかに言えば、オフィスファイル形式には2つの世代があります：**OLE形式**（RTF、DOC、XLS、PPTなどのファイル拡張子）と「**Office Open XML**」形式（DOCX、XLSX、PPTXなどのファイル拡張子を含む）。**両方の**形式は、リンクまたは埋め込まれたコンテンツ（オブジェクト）を**有効にする**構造化された複合ファイルバイナリ形式です。OOXMLファイルはzipファイルコンテナですので、隠されたデータをチェックする最も簡単な方法の1つは、単にドキュメントを`unzip`することです：
```
$ unzip example.docx
Archive:  example.docx
inflating: [Content_Types].xml
inflating: _rels/.rels
inflating: word/_rels/document.xml.rels
inflating: word/document.xml
inflating: word/theme/theme1.xml
extracting: docProps/thumbnail.jpeg
inflating: word/comments.xml
inflating: word/settings.xml
inflating: word/fontTable.xml
inflating: word/styles.xml
inflating: word/stylesWithEffects.xml
inflating: docProps/app.xml
inflating: docProps/core.xml
inflating: word/webSettings.xml
inflating: word/numbering.xml
$ tree
.
├── [Content_Types].xml
├── _rels
├── docProps
│   ├── app.xml
│   ├── core.xml
│   └── thumbnail.jpeg
└── word
├── _rels
│   └── document.xml.rels
├── comments.xml
├── document.xml
├── fontTable.xml
├── numbering.xml
├── settings.xml
├── styles.xml
├── stylesWithEffects.xml
├── theme
│   └── theme1.xml
└── webSettings.xml
```
以下は、ファイルとフォルダの階層によって一部の構造が作成されています。残りの部分はXMLファイル内で指定されています。[_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d)では、データ隠蔽技術のいくつかのアイデアが詳細に説明されていますが、CTFチャレンジの作成者は常に新しいアイデアを考え出しています。

再び、OLEおよびOOXMLドキュメントの調査と分析のためのPythonツールセットが存在します: [oletools](http://www.decalage.info/python/oletools)。特にOOXMLドキュメントについては、[OfficeDissector](https://www.officedissector.com)は非常に強力な分析フレームワーク（およびPythonライブラリ）です。後者には、使用方法の[クイックガイド](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)も含まれています。

時には、隠された静的データを見つけることが課題ではなく、VBAマクロを分析してその動作を判断することが課題となります。これはより現実的なシナリオであり、フィールドのアナリストが毎日実行する作業の一つです。前述の解析ツールは、マクロが存在するかどうかを示し、おそらくそれを抽出することもできます。Windows上のOfficeドキュメントの典型的なVBAマクロは、PowerShellスクリプトを%TEMP%にダウンロードし、実行しようとします。その場合、PowerShellスクリプトの分析タスクも発生します。ただし、悪意のあるVBAマクロは通常複雑ではありません。なぜなら、VBAは[通常、コード実行の起点として使用されるだけだからです](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/)。複雑なVBAマクロを理解する必要がある場合や、マクロが難読化されておりアンパッカールーチンがある場合、このためにMicrosoft Officeのライセンスを所有する必要はありません。[Libre Office](http://libreoffice.org)を使用することができます。[そのインターフェース](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)は、プログラムのデバッグを行ったことがある人にとっては馴染みのあるものです。ブレークポイントを設定し、ウォッチ変数を作成し、アンパックされた後の値をキャプチャすることができますが、ペイロードの動作が実行される前です。特定のドキュメントのマクロをコマンドラインから起動することさえできます。
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)

oletoolsは、OLEオブジェクトを分析するための一連のツールです。OLEオブジェクトは、Microsoft Officeファイル（.doc、.xls、.pptなど）に埋め込まれたバイナリデータです。oletoolsを使用すると、OLEオブジェクトを分析し、潜在的な脅威やセキュリティ上の問題を特定することができます。

oletoolsには、次のようなツールが含まれています。

- **olebrowse**: OLEオブジェクトをブラウズし、そのプロパティやストリームを表示します。
- **oleid**: OLEオブジェクトの種類を識別し、潜在的な脅威を特定します。
- **olevba**: VBAマクロを分析し、潜在的なマルウェアの存在を検出します。
- **olemeta**: OLEオブジェクトのメタデータを表示します。
- **oledump**: OLEオブジェクトをダンプし、その内容を分析します。

これらのツールを使用すると、Officeファイル内の潜在的な脅威やセキュリティ上の問題を特定し、対策を講じることができます。oletoolsは、セキュリティアナリストやフォレンジックエキスパートにとって非常に便利なツールです。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自動実行

`AutoOpen`、`AutoExec`、または`Document_Open`のようなマクロ関数は、**自動的に実行**されます。

## 参考文献

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって**強化されたワークフロー**を簡単に構築し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
