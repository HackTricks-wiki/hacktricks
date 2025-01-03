# Linux 環境変数

{{#include ../banners/hacktricks-training.md}}

## グローバル変数

グローバル変数は **子プロセス** に引き継がれます。

現在のセッションのためにグローバル変数を作成するには、次のようにします:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
この変数は、現在のセッションとその子プロセスからアクセス可能です。

変数を**削除**するには、次のようにします:
```bash
unset MYGLOBAL
```
## ローカル変数

**ローカル変数**は**現在のシェル/スクリプト**によってのみ**アクセス**できます。
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
## Common variables

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X**によって使用されるディスプレイ。この変数は通常**:0.0**に設定され、これは現在のコンピュータの最初のディスプレイを意味します。
- **EDITOR** – ユーザーの好みのテキストエディタ。
- **HISTFILESIZE** – 履歴ファイルに含まれる最大行数。
- **HISTSIZE** – ユーザーがセッションを終了したときに履歴ファイルに追加される行数。
- **HOME** – あなたのホームディレクトリ。
- **HOSTNAME** – コンピュータのホスト名。
- **LANG** – あなたの現在の言語。
- **MAIL** – ユーザーのメールスプールの場所。通常は**/var/spool/mail/USER**。
- **MANPATH** – マニュアルページを検索するためのディレクトリのリスト。
- **OSTYPE** – オペレーティングシステムのタイプ。
- **PS1** – bashのデフォルトプロンプト。
- **PATH** – バイナリファイルを実行するためのすべてのディレクトリのパスを格納します。ファイル名を指定するだけで、相対パスや絶対パスを使わずに実行できます。
- **PWD** – 現在の作業ディレクトリ。
- **SHELL** – 現在のコマンドシェルへのパス（例：**/bin/bash**）。
- **TERM** – 現在の端末タイプ（例：**xterm**）。
- **TZ** – あなたのタイムゾーン。
- **USER** – あなたの現在のユーザー名。

## Interesting variables for hacking

### **HISTFILESIZE**

この変数の**値を0に変更**すると、**セッションを終了**したときに**履歴ファイル**（\~/.bash_history）が**削除されます**。
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

この**変数の値を0に変更**してください。そうすれば、**セッションを終了**すると、任意のコマンドが**履歴ファイル**（\~/.bash_history）に追加されます。
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

プロセスは、ここで宣言された**プロキシ**を使用して、**httpまたはhttps**を介してインターネットに接続します。
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

プロセスは**これらの環境変数**で示された証明書を信頼します。
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

プロンプトの見た目を変更します。

[**これは例です**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

ルート:

![](<../images/image (897).png>)

通常のユーザー:

![](<../images/image (740).png>)

バックグラウンドで実行中のジョブが1つ、2つ、3つ:

![](<../images/image (145).png>)

バックグラウンドジョブが1つ、停止したジョブが1つ、最後のコマンドが正しく終了しなかった場合:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
