# ZIPsのテクニック

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>

ZIPファイルに関するいくつかのコマンドラインツールがあり、それらについて知っておくと便利です。

* `unzip` は、ZIPが解凍できない理由について役立つ情報を出力することがよくあります。
* `zipdetails -v` は、フォーマットのさまざまなフィールドに存在する値に関する詳細情報を提供します。
* `zipinfo` は、ZIPファイルの内容についての情報を抽出せずにリストします。
* `zip -F input.zip --out output.zip` と `zip -FF input.zip --out output.zip` は、破損したZIPファイルを修復しようとします。
* [fcrackzip](https://github.com/hyc/fcrackzip) は、ZIPパスワードをブルートフォースで推測します（7文字以下のパスワード用）。

[Zipファイルフォーマット仕様](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

パスワード保護されたZIPファイルに関する重要なセキュリティ関連の注意点は、RARや7zファイルのように、圧縮されたファイルのファイル名と元のファイルサイズを暗号化しないということです。

ZIPクラッキングに関する別の注意点は、暗号化されたZIPに圧縮されているファイルの非暗号化/非圧縮コピーを持っている場合、"プレーンテキスト攻撃"を実行してZIPをクラックできるということです。[こちらで詳細](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)に説明されており、[この論文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)で説明されています。ZIPファイルをパスワード保護するための新しい方式（AES-256を使用し、"ZipCrypto"ではない）は、この弱点を持っていません。

出典: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>
