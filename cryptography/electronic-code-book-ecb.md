<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出する**

</details>


# ECB

(ECB) Electronic Code Book - **ブロックごとにクリアテキストを暗号化**する対称暗号化スキーム。これは**最も単純な**暗号化スキームです。主なアイデアは、クリアテキストを**Nビットのブロック**（入力データのブロックサイズ、暗号化アルゴリズムに依存）に**分割**し、その後、唯一の鍵を使用して各クリアテキストブロックを暗号化（復号化）することです。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECBを使用すると、複数のセキュリティ上の影響があります：

- 暗号化されたメッセージから**ブロックを削除**できる
- 暗号化されたメッセージから**ブロックを移動**できる

# 脆弱性の検出

アプリケーションに複数回ログインし、**常に同じクッキーを取得**すると想像してください。これは、アプリケーションのクッキーが**`<username>|<password>`**であるためです。\
次に、**同じ長いパスワード**を持つ新しいユーザーを2人生成し、**ほぼ**同じ**ユーザー名**を持つようにします。\
**両方のユーザーの情報**が同じ**8バイトのブロック**であることがわかります。その後、これが**ECBが使用されている**ためかもしれないと考えます。

次の例のように、これらの**2つのデコードされたクッキー**には、何度もブロック**`\x23U\xE45K\xCB\x21\xC8`**が含まれていることに注意してください。
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
これは、**クッキーのユーザー名とパスワードには、複数回文字 "a" が含まれていた**ためです。**異なる**ブロックは、**少なくとも1つの異なる文字**（おそらく区切り記号 "|" またはユーザー名の必要な違い）を含んでいました。

攻撃者は、今や単に、フォーマットが `<ユーザー名><区切り記号><パスワード>` か `<パスワード><区切り記号><ユーザー名>` かを発見する必要があります。そのために、彼は単に**類似して長いユーザー名とパスワードを持つ複数のユーザー名を生成**し、フォーマットと区切り記号の長さを見つけるまで続けます:

| ユーザー名の長さ: | パスワードの長さ: | ユーザー名+パスワードの長さ: | デコード後のクッキーの長さ: |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 脆弱性の悪用

## ブロック全体の削除

クッキーのフォーマットを知っている場合（`<ユーザー名>|<パスワード>`）、ユーザー名 `admin` をなりすますために、`aaaaaaaaadmin` という新しいユーザーを作成し、クッキーを取得してデコードします:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
その前に作成されたユーザー名にのみ `a` が含まれているパターン `\x23U\xE45K\xCB\x21\xC8` を見ることができます。\
次に、最初の8Bブロックを削除すると、ユーザー名 `admin` 用の有効なクッキーが得られます:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## ブロックの移動

多くのデータベースでは、`WHERE username='admin';`を検索するのと`WHERE username='admin    ';`を検索するのは同じです（余分なスペースに注意）。

したがって、ユーザー`admin`をなりすます別の方法は次のとおりです：

- `len(<username>) + len(<delimiter) % len(block)`となるようなユーザー名を生成します。ブロックサイズが`8B`の場合、`username       `というユーザー名を生成できます。デリミターが`|`の場合、チャンク`<username><delimiter>`は8Bのブロックを2つ生成します。
- 次に、なりすましたいユーザー名とスペースを含むブロック数を正確に埋めるパスワードを生成します。例：`admin   `

このユーザーのクッキーは3つのブロックで構成されます：最初の2つはユーザー名+デリミターのブロックであり、3番目は（ユーザー名を偽装している）パスワードのブロックです：`username       |admin   `

** その後、最初のブロックを最後のブロックで置き換えるだけで、ユーザー`admin`をなりすませることができます：`admin          |username`**

# 参考文献

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))
