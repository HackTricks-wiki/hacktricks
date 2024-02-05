# Linux環境変数

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**か、**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れる
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングテクニックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## グローバル変数

グローバル変数は**子プロセス**によって**継承されます**。

現在のセッションにグローバル変数を作成するには、次のようにします：
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションおよびその子プロセスからアクセスできます。

次のようにして変数を**削除**できます：
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数** は **現在のシェル/スクリプト** からのみ **アクセス** できます。
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## 現在の変数のリスト
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## 永続的な環境変数

#### **すべてのユーザーの動作に影響を与えるファイル:**

* _**/etc/bash.bashrc**_: このファイルは対話型シェル（通常のターミナル）が起動されるたびに読み込まれ、ここに指定されたすべてのコマンドが実行されます。
* _**/etc/profile および /etc/profile.d/\***_**:** このファイルはユーザーがログインするたびに読み込まれます。したがって、ここで実行されるすべてのコマンドはユーザーのログイン時に1度だけ実行されます。
*   \*\*例: \*\*

`/etc/profile.d/somescript.sh`

```bash
#!/bin/bash
TEST=$(cat /var/somefile)
export $TEST
```

## 一般的な変数

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

* **DISPLAY** – **X** が使用するディスプレイ。通常、この変数は **:0.0** に設定されます。これは現在のコンピューター上の最初のディスプレイを意味します。
* **EDITOR** – ユーザーの選択したテキストエディター。
* **HISTFILESIZE** – 履歴ファイルに含まれる最大行数。
* **HISTSIZE** – ユーザーがセッションを終了するときに履歴ファイルに追加される行数。
* **HOME** – ホームディレクトリ。
* **HOSTNAME** – コンピューターのホスト名。
* **LANG** – 現在の言語。
* **MAIL** – ユーザーのメールスプールの場所。通常は **/var/spool/mail/USER** です。
* **MANPATH** – マニュアルページを検索するディレクトリのリスト。
* **OSTYPE** – オペレーティングシステムのタイプ。
* **PS1** – bash のデフォルトプロンプト。
* **PATH** – 実行したいバイナリファイルを保持するすべてのディレクトリのパス。ファイル名を指定するだけで相対パスまたは絶対パスを指定せずに実行できます。
* **PWD** – 現在の作業ディレクトリ。
* **SHELL** – 現在のコマンドシェルへのパス（たとえば、**/bin/bash**）。
* **TERM** – 現在の端末タイプ（たとえば、**xterm**）。
* **TZ** – 時間帯。
* **USER** – 現在のユーザー名。

## ハッキングに興味深い変数

### **HISTFILESIZE**

この変数の **値を 0 に変更** して、セッションを **終了** するときに **履歴ファイル**（\~/.bash\_history）が **削除される** ようにします。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

この変数の値を0に変更してください。これにより、セッションを終了するときには、どのコマンドも履歴ファイル（\~/.bash\_history）に追加されません。
```bash
export HISTSIZE=0
```
### http\_proxy & https\_proxy

プロセスは、ここで宣言された **プロキシ** を使用して、**httpまたはhttps** を介してインターネットに接続します。
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

プロンプトの表示を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../.gitbook/assets/image (87).png>)

通常のユーザー:

![](<../.gitbook/assets/image (88).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![](<../.gitbook/assets/image (89).png>)

バックグラウンドで実行中のジョブが1つ、停止中のジョブが1つ、最後のコマンドが正常に終了しなかった場合:

![](<../.gitbook/assets/image (90).png>)
