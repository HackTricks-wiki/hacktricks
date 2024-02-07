# ZIPのトリック

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私たちをフォローする [**@hacktricks_live**](https://twitter.com/hacktricks_live)**。**
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

**コマンドラインツール**を使用して**zipファイル**を管理することは、zipファイルの診断、修復、クラックに不可欠です。以下はいくつかの主要なユーティリティです：

- **`unzip`**：zipファイルが展開されない理由を明らかにします。
- **`zipdetails -v`**：zipファイル形式のフィールドの詳細な分析を提供します。
- **`zipinfo`**：zipファイルの内容を抽出せずにリストします。
- **`zip -F input.zip --out output.zip`**および**`zip -FF input.zip --out output.zip`**：破損したzipファイルを修復しようとします。
- **[fcrackzip](https://github.com/hyc/fcrackzip)**：zipパスワードの総当たりクラックのためのツールで、約7文字までのパスワードに効果的です。

[Zipファイル形式の仕様](https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT)は、zipファイルの構造と標準に関する包括的な詳細を提供しています。

重要なのは、パスワードで保護されたzipファイルは、ファイル名やファイルサイズを**暗号化しない**ことです。これは、RARや7zファイルとは異なり、この情報を暗号化するものではありません。さらに、古いZipCryptoメソッドで暗号化されたzipファイルは、圧縮されたファイルの非暗号化コピーが利用可能な場合、**平文攻撃**に対して脆弱です。この攻撃は、既知のコンテンツを利用してzipのパスワードをクラックするためのもので、[HackThisの記事](https://www.hackthis.co.uk/articles/known-plaintext-attack-cracking-zip-files)で詳細に説明され、[この学術論文](https://www.cs.auckland.ac.nz/\~mike/zipattacks.pdf)でさらに説明されています。ただし、**AES-256**暗号で保護されたzipファイルは、この平文攻撃に対して免疫を持っており、機密データに対して安全な暗号化方法を選択する重要性を示しています。

# 参考文献
* [https://michael-myers.github.io/blog/categories/ctf/](https://michael-myers.github.io/blog/categories/ctf/)
