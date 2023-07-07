# Linux環境変数

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## グローバル変数

グローバル変数は**子プロセス**によって継承されます。

現在のセッションのためにグローバル変数を作成するには、次のようにします：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は現在のセッションとその子プロセスからアクセスできます。

変数を**削除**するには、次のようにします：
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は、**現在のシェル/スクリプト**からのみ**アクセス**できます。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 現在の変数のリスト

To list the current environment variables in Linux, you can use the `printenv` command. This command will display all the variables and their values.

Linuxで現在の環境変数をリストするには、`printenv`コマンドを使用します。このコマンドは、すべての変数とその値を表示します。

```bash
$ printenv
```

This will output a list of all the environment variables currently set on your system.
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 永続的な環境変数

#### **すべてのユーザーの動作に影響を与えるファイル:**

* _**/etc/bash.bashrc**_: このファイルはインタラクティブシェル（通常のターミナル）が起動されるたびに読み込まれ、ここに指定されたすべてのコマンドが実行されます。
* _**/etc/profile および /etc/profile.d/\***_**:** このファイルはユーザーがログインするたびに読み込まれます。したがって、ここで実行されるすべてのコマンドは、ユーザーがログインする時点で一度だけ実行されます。
*   \*\*例: \*\*

`/etc/profile.d/somescript.sh`

```bash
#!/bin/bash
TEST=$(cat /var/somefile)
export $TEST
```

#### **特定のユーザーの動作に影響を与えるファイル:**

* _**\~/.bashrc**_: このファイルは _/etc/bash.bashrc_ ファイルと同じように動作しますが、特定のユーザーのみに対して実行されます。自分自身の環境を作成したい場合は、このファイルをホームディレクトリに変更または作成してください。
* _**\~/.profile, \~/.bash\_profile, \~/.bash\_login**_**:** これらのファイルは _/etc/profile_ と同じです。違いは実行方法です。このファイルは、このファイルが存在するユーザーがログインしたときにのみ実行されます。

**抜粋元:** [**こちら**](https://codeburst.io/linux-environment-variables-53cea0245dc9) **および** [**こちら**](https://www.gnu.org/software/bash/manual/html\_node/Bash-Startup-Files.html)

## 一般的な変数

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** で使用されるディスプレイ。この変数は通常 **:0.0** に設定されます。これは現在のコンピュータ上の最初のディスプレイを意味します。
* **EDITOR** – ユーザーの優先するテキストエディター。
* **HISTFILESIZE** – 履歴ファイルに含まれる行数の最大値。
* \*\*HISTSIZE - \*\*ユーザーがセッションを終了するときに履歴ファイルに追加される行数
* **HOME** – ホームディレクトリ。
* **HOSTNAME** – コンピュータのホスト名。
* **LANG** – 現在の言語。
* **MAIL** – ユーザーのメールスプールの場所。通常は **/var/spool/mail/USER** です。
* **MANPATH** – マニュアルページを検索するディレクトリのリスト。
* **OSTYPE** – オペレーティングシステムのタイプ。
* **PS1** – bash のデフォルトプロンプト。
* \*\*PATH - \*\*実行したいバイナリファイルが格納されているディレクトリのパスを保持します。ファイル名を指定するだけで相対パスや絶対パスを指定せずに実行できます。
* **PWD** – 現在の作業ディレクトリ。
* **SHELL** – 現在のコマンドシェルへのパス（例: **/bin/bash**）。
* **TERM** – 現在の端末のタイプ（例: **xterm**）。
* **TZ** – 自分のタイムゾーン。
* **USER** – 現在のユーザー名。

## ハッキングに関連する興味深い変数

### **HISTFILESIZE**

この変数の値を0に変更すると、セッションを終了するときに履歴ファイル（\~/.bash\_history）が削除されます。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

この変数の値を0に変更してください。これにより、セッションを終了するときにはどのコマンドも履歴ファイル（\~/.bash\_history）に追加されません。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

プロセスはここで宣言された**プロキシ**を使用して、**httpまたはhttps**を介してインターネットに接続します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL\_CERT\_FILE & SSL\_CERT\_DIR

プロセスは、**これらの環境変数**で指定された証明書を信頼します。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

プロンプトの表示方法を変更します。

[**こちら**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)を作成しました（別のものを基にしています、コードを読んでください）。

ルートユーザー：

![](<../.gitbook/assets/image (87).png>)

通常のユーザー：

![](<../.gitbook/assets/image (88).png>)

バックグラウンドで実行されているジョブが1つ、2つ、3つある場合：

![](<../.gitbook/assets/image (89).png>)

バックグラウンドで実行されているジョブが1つあり、1つが停止しており、最後のコマンドが正常に終了していない場合：

![](<../.gitbook/assets/image (90).png>)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローしてください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
