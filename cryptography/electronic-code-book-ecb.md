<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>


# ECB

ECB（Electronic Code Book）- 対称暗号化方式で、**平文の各ブロック**を**暗号文のブロック**に置き換えます。これは**最も単純な**暗号化方式です。主な考え方は、平文を**Nビットのブロック**に**分割**すること（ブロックのサイズや暗号化アルゴリズムに依存します）し、その後、唯一の鍵を使用して各平文ブロックを暗号化（復号）します。

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

ECBを使用することには複数のセキュリティ上の問題があります:

* **暗号化されたメッセージからブロックを削除できる**
* **暗号化されたメッセージのブロックを移動できる**

# 脆弱性の検出

あなたがアプリケーションに何度もログインし、**常に同じクッキーを取得する**と想像してください。これは、アプリケーションのクッキーが**`<username>|<password>`**であるためです。\
その後、**同じ長いパスワード**と**ほぼ同じ** **ユーザー名**を持つ2つの新しいユーザーを生成します。\
**8Bのブロック**で、**両方のユーザーの情報**が同じである部分が**等しい**ことがわかります。それから、これは**ECBが使用されている**可能性があると想像します。

以下の例のように。これらの**2つのデコードされたクッキー**が、ブロック**`\x23U\xE45K\xCB\x21\xC8`**を何度も含んでいることに注目してください。
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
これは、**クッキーのユーザー名とパスワードに「a」の文字が何度も含まれていたためです**（例として）。**異なるブロック**は、**少なくとも1つの異なる文字**（おそらく区切り文字「|」やユーザー名に必要な違い）を含んでいたブロックです。

今、攻撃者はフォーマットが `<username><delimiter><password>` か `<password><delimiter><username>` かを見つけるだけです。これを行うために、彼は**似たような長いユーザー名とパスワードをいくつか生成し、フォーマットと区切り文字の長さを見つけるまで続けます：**

| ユーザー名の長さ: | パスワードの長さ: | ユーザー名+パスワードの長さ: | クッキーの長さ（デコード後）: |
| ---------------- | ---------------- | ------------------------- | --------------------------------- |
| 2                | 2                | 4                         | 8                                 |
| 3                | 3                | 6                         | 8                                 |
| 3                | 4                | 7                         | 8                                 |
| 4                | 4                | 8                         | 16                                |
| 7                | 7                | 14                        | 16                                |

# 脆弱性の悪用

## ブロック全体の削除

クッキーのフォーマット（`<username>|<password>`）を知っているため、`admin`としてなりすますには、`aaaaaaaaadmin`という新しいユーザーを作成し、クッキーを取得してデコードします：
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
以下のパターン `\x23U\xE45K\xCB\x21\xC8` は、以前に `a` のみを含むユーザーネームで作成されました。\
その後、最初の8Bブロックを削除すると、ユーザーネーム `admin` のための有効なクッキーを得ることができます：
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## ブロックの移動

多くのデータベースでは、`WHERE username='admin';` と検索するのと `WHERE username='admin    ';` _(余分なスペースに注意)_ と検索するのは同じです。

したがって、ユーザー `admin` になりすます別の方法は以下の通りです：

* ユーザー名を生成します：`len(<username>) + len(<delimiter) % len(block)`。ブロックサイズが `8B` の場合、区切り文字 `|` を使って `username       ` というユーザー名を生成できます。これにより、`<username><delimiter>` のチャンクが 8B の 2 ブロックを生成します。
* 次に、偽装したいユーザー名とスペースを含む、正確なブロック数を埋めるパスワードを生成します。例えば：`admin   `

このユーザーのクッキーは 3 ブロックで構成されます：最初の 2 ブロックはユーザー名 + 区切り文字で、3 番目のブロックはパスワード（ユーザー名を偽装している）です：`username       |admin   `

** そして、最初のブロックを最後のブロックと置き換えるだけで、ユーザー `admin` になりすますことができます：`admin          |username`**

# 参考文献

* [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](http://cryptowiki.net/index.php?title=Electronic_Code_Book_\(ECB\))


<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricks をサポートする他の方法：

* **HackTricks にあなたの**会社を広告掲載したい場合や、**HackTricks を PDF でダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォロー**する。
* **HackTricks** の GitHub リポジトリ [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) に PR を提出して、あなたのハッキングのコツを共有する。

</details>
