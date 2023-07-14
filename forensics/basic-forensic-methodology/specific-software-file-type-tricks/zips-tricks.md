# ZIPのトリック

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。これは、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私を[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローしてください。
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

ZIPファイルに関するいくつかのコマンドラインツールがあります。これらは役立つ情報を提供します。

* `unzip`は、ZIPファイルの解凍ができない理由についての情報を表示することがあります。
* `zipdetails -v`は、フォーマットのさまざまなフィールドに存在する値に関する詳細な情報を提供します。
* `zipinfo`は、ZIPファイルの内容についての情報をリストアップしますが、解凍はしません。
* `zip -F input.zip --out output.zip`と`zip -FF input.zip --out output.zip`は、破損したZIPファイルを修復しようとします。
* [fcrackzip](https://github.com/hyc/fcrackzip)は、ZIPのパスワードをブルートフォースで推測します（パスワードが7文字以下の場合など）。

[ZIPファイル形式の仕様](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

パスワードで保護されたZIPファイルに関する重要なセキュリティ上の注意点は、パスワードで保護されたRARや7zファイルとは異なり、圧縮されたファイルのファイル名と元のファイルサイズは暗号化されないことです。

また、ZIPのクラッキングに関する注意点として、暗号化されたZIPに圧縮されているファイルの中で暗号化されていない/非圧縮のコピーがある場合、[ここで詳しく説明されているように](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)、「平文攻撃」を実行してZIPをクラッキングすることができます。新しいZIPファイルのパスワード保護スキーム（"ZipCrypto"ではなくAES-256を使用）には、この弱点はありません。

From: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](http://127.0.0.1:5000/s/-L\_2uGJGU7AVNRcqRvEi/)
