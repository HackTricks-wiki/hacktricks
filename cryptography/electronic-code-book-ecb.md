<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# ECB

(ECB) Electronic Code Book - 対称暗号化方式で、**クリアテキストの各ブロック**を**暗号文のブロック**で置き換えます。これは**最も単純な**暗号化方式です。主なアイデアは、クリアテキストを**Nビットのブロック**（入力データのブロックサイズ、暗号化アルゴリズムに依存）に**分割**し、その後、唯一の鍵を使用して各クリアテキストのブロックを暗号化（復号化）することです。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECBの使用には、複数のセキュリティ上の問題があります：

* 暗号化されたメッセージから**ブロックを削除**することができます。
* 暗号化されたメッセージから**ブロックを移動**することができます。

# 脆弱性の検出

アプリケーションに複数回ログインし、**常に同じクッキー**を取得すると想像してください。これは、アプリケーションのクッキーが**`<username>|<password>`**であるためです。\
次に、**同じ長いパスワード**と**ほぼ同じ** **ユーザー名**を持つ新しいユーザーを2人生成します。\
**2つのデコードされたクッキー**には、ブロック**`\x23U\xE45K\xCB\x21\xC8`**が複数回含まれていることに注意してください。
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
これは、クッキーの**ユーザー名とパスワードに複数回文字 "a" が含まれていた**ためです（例えば）。**異なる**ブロックは、**少なくとも1つの異なる文字**（おそらく区切り記号 "|" またはユーザー名に必要な違い）を含んでいるブロックです。

さて、攻撃者は単に、`<username><delimiter><password>` または `<password><delimiter><username>` の形式を見つける必要があります。そのために、彼は単に**類似した長いユーザー名とパスワードを持つ複数のユーザー名**を生成し、区切り記号の形式と長さを見つけるまで続けることができます。

| ユーザー名の長さ | パスワードの長さ | ユーザー名+パスワードの長さ | クッキーの長さ（デコード後） |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 脆弱性の悪用

クッキーの形式を知っている（`<username>|<password>`）、ユーザー名 `admin` をなりすますために、`aaaaaaaaadmin` という新しいユーザーを作成し、クッキーを取得してデコードします：
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
以前に作成されたユーザー名には、`\x23U\xE45K\xCB\x21\xC8`というパターンが見られます。\
次に、最初の8Bのブロックを削除すると、ユーザー名`admin`の有効なクッキーが得られます。
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## ブロックの移動

多くのデータベースでは、`WHERE username='admin';` と `WHERE username='admin    ';` の検索は同じです。 _(余分なスペースに注意)_

したがって、ユーザー `admin` をなりすます別の方法は次のとおりです。

* `len(<username>) + len(<delimiter) % len(block)` となるようなユーザー名を生成します。ブロックサイズが `8B` の場合、`username       ` というユーザー名を生成できます。デリミタには `|` を使用し、チャンク `<username><delimiter>` は 2 つの 8B ブロックを生成します。
* 次に、ユーザー名とスペースを含むブロックの正確な数を埋めるパスワードを生成します。例えば、`admin   ` というパスワードを生成します。

このユーザーのクッキーは、3 つのブロックで構成されます。最初の 2 つはユーザー名 + デリミタのブロックであり、3 つ目はパスワードのブロックです（ユーザー名を偽装しています）：`username       |admin   `

** その後、最初のブロックを最後のブロックと置き換えるだけで、ユーザー `admin` をなりすませることができます：`admin          |username`**

# 参考文献

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンや HackTricks の PDF をダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な [**NFT**](https://opensea.io/collection/the-peass-family) のコレクションです。

- [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f) または [**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)** をフォローしてください。**

- **ハッキングのトリックを共有するには、[hacktricks リポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud リポジトリ](https://github.com/carlospolop/hacktricks-cloud)に PR を提出してください。**

</details>
