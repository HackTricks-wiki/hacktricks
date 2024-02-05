# PDFファイルの分析

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**PDFでHackTricksをダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@hacktricks_live**をフォローする🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

出典：[https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDFは非常に複雑なドキュメントファイル形式であり、数年間にわたって書くための十分なトリックや隠し場所があります。これはCTFフォレンジックチャレンジでも人気があります。NSAは2008年に「Adobe PDFファイルの隠しデータとメタデータ：公開リスクと対策」と題したガイドを作成しました。元のURLではもう入手できませんが、[こちらでコピーを見つけることができます](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)。Ange AlbertiniはGitHubで[PDFファイル形式のトリック](https://github.com/corkami/docs/blob/master/PDF/PDF.md)のウィキを保持しています。

PDF形式は部分的にプレーンテキストであり、HTMLのようなものですが、内容には多くのバイナリ「オブジェクト」が含まれています。Didier Stevensは、その形式について[良い入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を書いています。バイナリオブジェクトには、圧縮されたり暗号化されたりするデータが含まれることがあり、JavaScriptやFlashなどのスクリプト言語でのコンテンツも含まれます。PDFの構造を表示するには、テキストエディタで閲覧するか、OrigamiのようなPDF認識ファイル形式エディタで開くことができます。

[qpdf](https://github.com/qpdf/qpdf)は、PDFを探索し、情報を変換したり抽出したりするのに役立つツールの1つです。別のツールとして、Rubyのフレームワークである[Origami](https://github.com/mobmewireless/origami-pdf)があります。

隠しデータを探るためにPDFコンテンツを探索する際にチェックすべき隠し場所には、次のものがあります：

- 非表示のレイヤー
- Adobeのメタデータ形式「XMP」
- PDFの「増分生成」機能、以前のバージョンが保持されているがユーザーには表示されない
- 白地に白色のテキスト
- 画像の後ろのテキスト
- 画像の上に重なる画像
- 非表示のコメント

PDFファイル形式で作業するためのいくつかのPythonパッケージもあり、[PeepDF](https://github.com/jesparza/peepdf)のようなパッケージを使用して独自の解析スクリプトを作成できます。

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**PDFでHackTricksをダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見る
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で**@hacktricks_live**をフォローする🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、**[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>
