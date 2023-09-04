# オフィスファイルの分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## はじめに

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
如您所见，文件和文件夹层次结构创建了一部分结构，其余部分在XML文件中指定。[_New Steganographic Techniques for the OOXML File Format_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d)详细介绍了一些数据隐藏技术的想法，但CTF挑战的作者们总是会想出新的技巧。

再次强调，存在用于检查和分析OLE和OOXML文档的Python工具集：[oletools](http://www.decalage.info/python/oletools)。特别针对OOXML文档，[OfficeDissector](https://www.officedissector.com)是一个非常强大的分析框架（和Python库）。后者包括一个[使用指南](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)。

有时，挑战不在于找到隐藏的静态数据，而是分析VBA宏以确定其行为。这是一个更现实的场景，也是领域中的分析人员每天执行的任务。前面提到的分析工具可以指示是否存在宏，并可能为您提取它。在Windows上，Office文档中的典型VBA宏将下载一个PowerShell脚本到%TEMP%并尝试执行它，这样您现在也有了一个PowerShell脚本分析任务。但恶意VBA宏很少复杂，因为VBA通常只用作启动代码执行的平台。如果您确实需要理解复杂的VBA宏，或者宏被混淆并具有解包例程，您不需要拥有Microsoft Office的许可证来调试它。您可以使用[Libre Office](http://libreoffice.org)：[其界面](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)对于任何调试过程序的人来说都是熟悉的；您可以设置断点、创建监视变量并在解包后但执行任何有效负载行为之前捕获值。您甚至可以从命令行启动特定文档的宏。
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

これらのツールを使用すると、Officeファイル内のOLEオブジェクトを詳細に調査し、潜在的なセキュリティ上の問題を特定することができます。oletoolsは、フォレンジック分析やセキュリティ監査などの目的で広く使用されています。
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自動実行

`AutoOpen`、`AutoExec`、または`Document_Open`のようなマクロ関数は、**自動的に** **実行**されます。

## 参考文献

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって**強化されたワークフロー**を簡単に構築し、**自動化**することができます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksをPDFでダウンロードしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
