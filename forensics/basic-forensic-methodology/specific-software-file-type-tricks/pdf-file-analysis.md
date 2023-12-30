# PDFファイル分析

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も進んだコミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化する**。\
今すぐアクセス:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

出典: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDFは非常に複雑なドキュメントファイル形式であり、[何年にもわたって書くことができるほどのトリックと隠れ場所](https://www.sultanik.com/pocorgtfo/)があります。これはCTFフォレンジックチャレンジにも人気です。NSAは2008年にこれらの隠れ場所についてのガイド「Adobe PDFファイルの隠されたデータとメタデータ：公開リスクと対策」を書きました。元のURLではもう利用できませんが、[ここでコピーを見つけることができます](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)。Ange AlbertiniもGitHub上に[PDFファイル形式のトリック](https://github.com/corkami/docs/blob/master/PDF/PDF.md)に関するwikiを維持しています。

PDF形式は部分的にはHTMLのようなプレーンテキストですが、内容には多くのバイナリ「オブジェクト」が含まれています。Didier Stevensは、この形式について[良い入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を書いています。バイナリオブジェクトには、JavaScriptやFlashなどのスクリプト言語でのコンテンツを含む、圧縮されたり暗号化されたデータがあります。PDFの構造を表示するには、テキストエディタでブラウズするか、OrigamiのようなPDF対応のファイル形式エディタで開くことができます。

[qpdf](https://github.com/qpdf/qpdf)は、PDFを探索し、情報を変換または抽出するのに役立つツールの一つです。もう一つはRubyのフレームワークである[Origami](https://github.com/mobmewireless/origami-pdf)です。

PDFコンテンツを隠されたデータを探索する際にチェックすべき隠れ場所には以下が含まれます:

* 非表示のレイヤー
* Adobeのメタデータ形式「XMP」
* PDFの「インクリメンタル生成」機能で、以前のバージョンが保持されているがユーザーには見えない
* 白い背景に白いテキスト
* 画像の後ろのテキスト
* 重なる画像の後ろの画像
* 表示されないコメント

PDFファイル形式で作業するためのいくつかのPythonパッケージもあります。例えば[PeepDF](https://github.com/jesparza/peepdf)は、独自の解析スクリプトを書くことを可能にします。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* 独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションである[**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
