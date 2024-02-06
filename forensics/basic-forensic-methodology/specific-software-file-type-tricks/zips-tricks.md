# ZIPのトリック

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

zipファイルに関するいくつかのコマンドラインツールがあり、覚えておくと役立ちます。

- `unzip`は、zipファイルが解凍されない理由について役立つ情報を出力することがよくあります。
- `zipdetails -v`は、形式のさまざまなフィールドに存在する値に関する詳細情報を提供します。
- `zipinfo`は、zipファイルの内容に関する情報をリストアップし、それを展開することなく表示します。
- `zip -F input.zip --out output.zip`および`zip -FF input.zip --out output.zip`は、破損したzipファイルを修復しようとします。
- [fcrackzip](https://github.com/hyc/fcrackzip)は、zipのパスワードをブルートフォースで推測します（パスワードが7文字未満の場合など）。

[Zipファイル形式の仕様](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)

パスワードで保護されたzipファイルに関する重要なセキュリティ関連の注意点は、それらが含む圧縮ファイルのファイル名と元のファイルサイズを暗号化しないことです。これは、パスワードで保護されたRARや7zファイルとは異なります。

zipのクラックに関する別の注意点は、暗号化されたzipに圧縮されているファイルのうち1つでも暗号化されていない/非圧縮のコピーがある場合、"平文攻撃"を実行してzipをクラックできることです。詳細は[こちら](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)に記載されており、[この論文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)で説明されています。AES-256を使用してzipファイルをパスワードで保護する新しいスキーム（"ZipCrypto"ではなく）には、この弱点がありません。

From: [https://app.gitbook.com/@cpol/s/hacktricks/\~/edit/drafts/-LlM5mCby8ex5pOeV4pJ/forensics/basic-forensics-esp/zips-tricks](https://app.gitbook.com/o/Iwnw24TnSs9D9I2OtTKX/s/-L\_2uGJGU7AVNRcqRvEi/)
