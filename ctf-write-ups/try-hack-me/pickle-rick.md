# ピックル・リック

## ピックル・リック

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

![](../../.gitbook/assets/picklerick.gif)

このマシンは簡単と分類され、実際に簡単でした。

## 列挙

私は[**Legion**](https://github.com/carlospolop/legion)というツールを使ってマシンの列挙を始めました：

![](<../../.gitbook/assets/image (79) (2).png>)

ご覧の通り、2つのポートが開いています：80 (**HTTP**) と 22 (**SSH**)

そこで、HTTPサービスの列挙のためにlegionを起動しました：

![](<../../.gitbook/assets/image (234).png>)

画像にあるように、`robots.txt`には`Wubbalubbadubdub`という文字列が含まれています。

数秒後、`disearch`がすでに発見したものを確認しました：

![](<../../.gitbook/assets/image (235).png>)

![](<../../.gitbook/assets/image (236).png>)

最後の画像にあるように、**ログイン**ページが発見されました。

ルートページのソースコードをチェックすると、ユーザー名が発見されました：`R1ckRul3s`

![](<../../.gitbook/assets/image (237) (1).png>)

したがって、`R1ckRul3s:Wubbalubbadubdub`の資格情報を使用してログインページにログインできます。

## ユーザー

これらの資格情報を使用すると、コマンドを実行できるポータルにアクセスします：

![](<../../.gitbook/assets/image (241).png>)

catのようないくつかのコマンドは許可されていませんが、例えばgrepを使用して最初の成分（フラグ）を読むことができます：

![](<../../.gitbook/assets/image (242).png>)

次に、私は使用しました：

![](<../../.gitbook/assets/image (243) (1).png>)

リバースシェルを取得するために：

![](<../../.gitbook/assets/image (239) (1).png>)

**第二の成分**は`/home/rick`で見つけることができます

![](<../../.gitbook/assets/image (240).png>)

## ルート

ユーザー**www-dataはsudoとして何でも実行できます**：

![](<../../.gitbook/assets/image (238).png>)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>
