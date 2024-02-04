# Pickle Rick

## Pickle Rick

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

![](../../.gitbook/assets/picklerick.gif)

このマシンは簡単なカテゴリに分類され、かなり簡単でした。

## 列挙

私は**Legion**というツールを使用してマシンを列挙し始めました：

![](<../../.gitbook/assets/image (79) (2).png>)

上記のように、2つのポートが開いていることがわかりました：80（**HTTP**）と22（**SSH**）

したがって、HTTPサービスを列挙するためにLegionを起動しました：

![](<../../.gitbook/assets/image (234).png>)

画像では、`robots.txt`に文字列`Wubbalubbadubdub`が含まれていることがわかります。

数秒後、`disearch`がすでに発見したものを確認しました：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

そして、最後の画像で**ログイン**ページが発見されました。

ルートページのソースコードをチェックすると、ユーザー名が発見されました：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

したがって、資格情報`R1ckRul3s:Wubbalubbadubdub`を使用してログインページにログインできます。

## ユーザー

これらの資格情報を使用すると、コマンドを実行できるポータルにアクセスできます：

![](<../../.gitbook/assets/image (241).png>)

catなどの一部のコマンドは許可されていませんが、たとえばgrepを使用して最初の成分（フラグ）を読むことができます：

![](<../../.gitbook/assets/image (242).png>)

その後、次のように使用しました：

![](<../../.gitbook/assets/image (243) (1).png>)

リバースシェルを取得するために：

![](<../../.gitbook/assets/image (239) (1).png>)

**2番目の成分**は`/home/rick`にあります。

![](<../../.gitbook/assets/image (240).png>)

## ルート

ユーザー**www-dataはsudoとして何でも実行できます**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**と**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>
