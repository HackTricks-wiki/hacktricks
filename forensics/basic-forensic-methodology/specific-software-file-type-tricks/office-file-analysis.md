# Officeファイル分析

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
世界で**最も進んだ**コミュニティツールを駆使して、簡単に**ワークフローを構築し自動化する**ために[**Trickest**](https://trickest.com/?utm_campaign=hacktrics\&utm_medium=banner\&utm_source=hacktricks)を使用してください。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## はじめに

Microsoftは**数十種類のオフィス文書ファイル形式**を作成しており、その多くはマクロ（VBAスクリプト）を**含む能力**があるため、フィッシング攻撃やマルウェアの配布によく使用されます。

大まかに言うと、Officeファイル形式には二つの世代があります：**OLE形式**（RTF、DOC、XLS、PPTなどのファイル拡張子）と"**Office Open XML**"形式（DOCX、XLSX、PPTXなどのファイル拡張子を含む）。**両方**の形式は構造化された複合ファイルバイナリ形式であり、リンクされたまたは埋め込まれたコンテンツ（オブジェクト）を**可能にします**。OOXMLファイルはzipファイルコンテナであり、隠されたデータをチェックする最も簡単な方法の一つは、単に文書を`unzip`することです：
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
```markdown
ファイルとフォルダの階層によって構造の一部が作成されます。残りの部分はXMLファイル内で指定されています。[_OOXMLファイル形式の新しいステガノグラフィック技術_, 2011](http://download.springer.com/static/pdf/713/chp%3A10.1007%2F978-3-642-23300-5\_27.pdf?originUrl=http%3A%2F%2Flink.springer.com%2Fchapter%2F10.1007%2F978-3-642-23300-5\_27\&token2=exp=1497911340\~acl=%2Fstatic%2Fpdf%2F713%2Fchp%25253A10.1007%25252F978-3-642-23300-5\_27.pdf%3ForiginUrl%3Dhttp%253A%252F%252Flink.springer.com%252Fchapter%252F10.1007%252F978-3-642-23300-5\_27\*\~hmac=aca7e2655354b656ca7d699e8e68ceb19a95bcf64e1ac67354d8bca04146fd3d)はデータ隠蔽技術についていくつかのアイデアを詳述していますが、CTFチャレンジの作者は常に新しいものを考案しています。

再び、OLEとOOXMLドキュメントの**分析**のためのPythonツールセットが存在します：[oletools](http://www.decalage.info/python/oletools)。特にOOXMLドキュメントの場合、[OfficeDissector](https://www.officedissector.com)は非常に強力な分析フレームワーク（およびPythonライブラリ）です。後者には[使用方法のクイックガイド](https://github.com/grierforensics/officedissector/blob/master/doc/html/\_sources/txt/ANALYZING\_OOXML.txt)が含まれています。

時には、隠された静的データを見つけることが課題ではなく、**VBAマクロを分析**してその振る舞いを判断することが課題です。これはより現実的なシナリオであり、現場のアナリストが毎日行っている作業です。前述の解析ツールはマクロが存在するかどうかを示し、おそらくそれを抽出してくれるでしょう。Windows上のOfficeドキュメント内の典型的なVBAマクロは、%TEMP%にPowerShellスクリプトをダウンロードし、実行しようとします。その場合、PowerShellスクリプトの分析タスクも発生します。しかし、悪意のあるVBAマクロは複雑であることは稀で、VBAは[通常、コード実行をブートストラップするためのプラットフォームとして使用されるだけです](https://www.lastline.com/labsblog/party-like-its-1999-comeback-of-vba-malware-downloaders-part-3/)。複雑なVBAマクロを理解する必要がある場合、またはマクロが難読化されており、アンパッカールーチンを持っている場合、これをデバッグするためにMicrosoft Officeのライセンスを所有している必要はありません。[Libre Office](http://libreoffice.org)を使用できます：[そのインターフェース](http://www.debugpoint.com/2014/09/debugging-libreoffice-macro-basic-using-breakpoint-and-watch/)はプログラムのデバッグ経験がある人には馴染み深いもので、ブレークポイントを設定し、ウォッチ変数を作成し、ペイロードの振る舞いが実行される前にアンパックされた後の値をキャプチャすることができます。特定のドキュメントのマクロをコマンドラインから開始することもできます：
```
```
$ soffice path/to/test.docx macro://./standard.module1.mymacro
```
## [oletools](https://github.com/decalage2/oletools)
```bash
sudo pip3 install -U oletools
olevba -c /path/to/document #Extract macros
```
## 自動実行

マクロ機能 `AutoOpen`、`AutoExec`、`Document_Open` は**自動的に** **実行されます**。

## 参照

* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使用して、世界で**最も先進的な**コミュニティツールを活用したワークフローを簡単に**自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert) で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWS ハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
