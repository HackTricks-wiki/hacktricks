# PDFファイルの分析

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによるワークフローを簡単に構築し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

From: [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)

PDFは非常に複雑なドキュメントファイル形式であり、[何年もの間にわたって書かれるほど](https://www.sultanik.com/pocorgtfo/)のトリックや隠し場所があります。これは、CTFフォレンジックの課題でも人気があります。NSAは2008年に「Hidden Data and Metadata in Adobe PDF Files: Publication Risks and Countermeasures」というタイトルのガイドを作成しましたが、元のURLでは入手できなくなっています。ただし、[ここでコピーを見つけることができます](http://www.itsecure.hu/library/file/Biztons%C3%A1gi%20%C3%BAtmutat%C3%B3k/Alkalmaz%C3%A1sok/Hidden%20Data%20and%20Metadata%20in%20Adobe%20PDF%20Files.pdf)。Ange Albertiniは、[PDFファイル形式のトリックの](https://github.com/corkami/docs/blob/master/PDF/PDF.md)GitHub上のウィキも保持しています。

PDF形式は部分的にはHTMLのようなプレーンテキストですが、多くのバイナリ「オブジェクト」を含んでいます。Didier Stevensは、[フォーマットに関する良い入門資料](https://blog.didierstevens.com/2008/04/09/quickpost-about-the-physical-and-logical-structure-of-pdf-files/)を書いています。バイナリオブジェクトには、圧縮または暗号化されたデータが含まれることもあり、JavaScriptやFlashのようなスクリプト言語でのコンテンツも含まれます。PDFの構造を表示するには、テキストエディタで閲覧するか、OrigamiのようなPDF対応のファイル形式エディタで開くことができます。

[qpdf](https://github.com/qpdf/qpdf)は、PDFを探索し、情報を変換または抽出するのに役立つツールの1つです。もう1つはRubyのフレームワークである[Origami](https://github.com/mobmewireless/origami-pdf)です。

隠しデータを探索する際にチェックするいくつかの隠し場所には、次のものがあります。

* 非表示のレイヤー
* Adobeのメタデータ形式「XMP」
* PDFの「増分生成」機能（以前のバージョンはユーザーには表示されませんが、保持されます）
* 白い背景に白いテキスト
* 画像の後ろにテキスト
* 重なり合った画像の後ろに画像
* 非表示のコメント

また、[PeepDF](https://github.com/jesparza/peepdf)のようなPythonパッケージもあり、PDFファイル形式で作業するためのもので、独自の解析スクリプトを作成することができます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
