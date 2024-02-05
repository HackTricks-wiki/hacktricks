# Linuxフォレンジクス

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリに**PRを提出**することで、あなたのハッキングトリックを**共有**してください。

</details>

## 初期情報収集

### 基本情報

まず最初に、**USB**に**良く知られたバイナリとライブラリが含まれている**（単にUbuntuを取得して、_ / bin_、_ / sbin_、_ / lib_、および_ / lib64_のフォルダをコピーできます）USBを用意することをお勧めします。次に、USBをマウントし、環境変数を変更してこれらのバイナリを使用します：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一度システムを良いものや既知のバイナリを使用するように設定したら、**基本情報の抽出**を開始できます：
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### 疑わしい情報

基本情報を取得する際に、次のような奇妙な点をチェックする必要があります:

- **Rootプロセス**は通常、低いPIDで実行されるため、大きなPIDで実行されているRootプロセスが見つかった場合は疑わしいと考えられます
- `/etc/passwd`内でシェルを持たないユーザーの**登録されたログイン**を確認する
- `/etc/shadow`内でシェルを持たないユーザーの**パスワードハッシュ**を確認する

### メモリーダンプ

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME)を使用することをお勧めします。\
それを**コンパイル**するには、被害者のマシンが使用している**同じカーネル**を使用する必要があります。

{% hint style="info" %}
被害者のマシンにLiMEやその他の何かを**インストールすることはできない**ため、それに多くの変更を加えてしまいます
{% endhint %}

したがって、Ubuntuの同一バージョンがある場合は、`apt-get install lime-forensics-dkms`を使用できます。\
それ以外の場合は、[**LiME**](https://github.com/504ensicsLabs/LiME)をgithubからダウンロードし、正しいカーネルヘッダーを使用してコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー**を取得するには、単に`/lib/modules/<kernel version>`ディレクトリをあなたのマシンにコピーし、それを使用してLiMEを**コンパイル**します:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

- Raw（すべてのセグメントが連結されたもの）
- Padded（Rawと同じですが、右ビットにゼロが入っています）
- Lime（メタデータ付きの推奨フォーマット）

LiMEは、`path=tcp:4444`のような方法を使用して、**ダンプをネットワーク経由で送信**することもできます。

### ディスクイメージング

#### シャットダウン

まず、**システムをシャットダウンする**必要があります。これは常に選択肢としてはない場合があります。企業がシャットダウンする余裕のない本番サーバーである可能性があります。\
システムをシャットダウンする方法には、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の2つがあります。前者は**プロセスが通常通り終了**し、**ファイルシステムが同期**されることを可能にしますが、**マルウェア**が**証拠を破壊**する可能性もあります。後者の「プラグを抜く」アプローチは**一部の情報が失われる**可能性があります（メモリのイメージをすでに取得しているため、失われる情報はほとんどありません）が、**マルウェア**が何もできないでしょう。したがって、**マルウェア**の疑いがある場合は、システムで**`sync`** **コマンド**を実行してプラグを抜いてください。

#### ディスクのイメージを取得する

重要なのは、**コンピュータを事件に関連するものに接続する前に**、情報を変更しないように**読み取り専用でマウント**されることを確認する必要があることです。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

データがない状態でディスクイメージを作成します。
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 既知のマルウェアを検索

### 変更されたシステムファイル

一部のLinuxシステムには、多くのインストールされたコンポーネントの整合性を検証する機能があり、異常なファイルや場所にないファイルを特定する効果的な方法を提供します。たとえば、Linuxの`rpm -Va`は、RedHat Package Managerを使用してインストールされたすべてのパッケージを検証するように設計されています。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### マルウェア/ルートキット検出ツール

マルウェアを見つけるのに役立つツールについて学ぶために、以下のページを読んでください:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## インストールされたプログラムの検索

### パッケージマネージャ

Debianベースのシステムでは、_**/var/lib/dpkg/status**_ ファイルにはインストールされたパッケージの詳細が含まれ、_**/var/log/dpkg.log**_ ファイルにはパッケージがインストールされたときの情報が記録されます。\
RedHatおよび関連するLinuxディストリビューションでは、**`rpm -qa --root=/mntpath/var/lib/rpm`** コマンドを使用してシステム上のRPMデータベースの内容をリストアップできます。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### その他

**上記のコマンドではすべてのインストールされたプログラムがリストされるわけではありません**。なぜなら、一部のアプリケーションは特定のシステム用のパッケージとして利用できず、ソースからインストールする必要があるからです。そのため、_**/usr/local**_ や _**/opt**_ などの場所を調査すると、ソースコードからコンパイルされインストールされた他のアプリケーションが見つかるかもしれません。
```bash
ls /opt /usr/local
```
もう1つの良いアイデアは、**インストールされたパッケージに関連しない** **バイナリ**を**チェック**するために、**$PATH**内の**一般的なフォルダ**を**確認**することです：
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 削除された実行中のバイナリの回復

![](<../../.gitbook/assets/image (641).png>)

## オートスタートの場所の検査

### スケジュールされたタスク
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
### サービス

マルウェアが新しい、許可されていないサービスとして浸透することは非常に一般的です。Linuxには、コンピューターの起動時にサービスを開始するために使用されるスクリプトがいくつかあります。初期化起動スクリプト _**/etc/inittab**_ は、rc.sysinitや _**/etc/rc.d/**_ ディレクトリ内のさまざまな起動スクリプト、または古いバージョンでは _**/etc/rc.boot/**_ を呼び出します。Debianなどの他のLinuxバージョンでは、起動スクリプトは _**/etc/init.d/**_ ディレクトリに保存されています。さらに、一部の一般的なサービスは、Linuxのバージョンに応じて _**/etc/inetd.conf**_ または _**/etc/xinetd/**_ で有効になっています。デジタル調査者は、これらの起動スクリプトの各エントリを調査する必要があります。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### カーネルモジュール

Linuxシステムでは、マルウェアパッケージのルートキットコンポーネントとしてカーネルモジュールが一般的に使用されます。カーネルモジュールは、システムの起動時に `/lib/modules/'uname -r'` および `/etc/modprobe.d` ディレクトリ、および `/etc/modprobe` または `/etc/modprobe.conf` ファイル内の構成情報に基づいてロードされます。これらの領域は、マルウェアに関連するアイテムを調査する必要があります。

### その他の自動起動場所

Linuxがシステムにログインする際に自動的に実行する実行可能ファイルを起動するために使用するいくつかの設定ファイルがあり、これらにはマルウェアの痕跡が含まれている可能性があります。

* _**/etc/profile.d/\***_、_**/etc/profile**_、_**/etc/bash.bashrc**_ は、任意のユーザーアカウントがログインすると実行されます。
* _**∼/.bashrc**_、_**∼/.bash\_profile**_、_**\~/.profile**_、_**∼/.config/autostart**_ は、特定のユーザーがログインすると実行されます。
* _**/etc/rc.local**_ は、通常のシステムサービスがすべて起動した後に実行され、マルチユーザーランレベルに切り替えるプロセスの最後に実行されます。

## ログの調査

侵害されたシステムのすべての利用可能なログファイルを調査して、悪意のある実行や新しいサービスの作成などの関連活動の痕跡を探します。

### 純粋なログ

システムおよびセキュリティログに記録された**ログイン**イベントは、特定のアカウントを介して**マルウェア**または**侵入者**が特定の時間に侵害されたシステムにアクセスしたことを明らかにする可能性があります。マルウェア感染の周辺での他のイベントは、システムログにキャプチャされる可能性があります。これには、インシデントのタイミング周辺での**新しい** **サービス**の**作成**や新しいアカウントの作成が含まれます。\
興味深いシステムログイン:

* **/var/log/syslog** (debian) または **/var/log/messages** (Redhat)
* システム全体のアクティビティに関する一般的なメッセージと情報を表示します。
* **/var/log/auth.log** (debian) または **/var/log/secure** (Redhat)
* 成功または失敗したログイン、および認証プロセスに関する認証ログを保持します。保存場所はシステムタイプに依存します。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: 起動メッセージとブート情報。
* **/var/log/maillog** または **var/log/mail.log:** は、メールサーバーログ用であり、サーバー上で実行されているポストフィックス、smtpd、または関連する電子メールサービス情報に便利です。
* **/var/log/kern.log**: カーネルログと警告情報を保持します。カーネルアクティビティログ（例：dmesg、kern.log、klog）は、特定のサービスが繰り返しクラッシュしたことを示す可能性があり、不安定なトロイの木馬化されたバージョンがインストールされている可能性があります。
* **/var/log/dmesg**: デバイスドライバーメッセージのリポジトリです。このファイル内のメッセージを表示するには **dmesg** を使用します。
* **/var/log/faillog:** 失敗したログインに関する情報を記録します。ログイン資格情報のハッキングや総当たり攻撃などの潜在的なセキュリティ侵害を調査するのに便利です。
* **/var/log/cron**: Crond関連のメッセージ（cronジョブ）の記録を保持します。cronデーモンがジョブを開始したときなど。
* **/var/log/daemon.log:** 実行中のバックグラウンドサービスを追跡しますが、それらをグラフィカルに表現しません。
* **/var/log/btmp**: すべての失敗したログイン試行を記録します。
* **/var/log/httpd/**: Apache httpdデーモンの error\_log および access\_log ファイルを含むディレクトリです。httpdが遭遇したすべてのエラーが **error\_log** ファイルに保持されます。メモリ問題やその他のシステム関連のエラーなどを考えてください。**access\_log** はHTTP経由で受信したすべてのリクエストを記録します。
* **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQLログファイルで、起動、停止、再起動などのすべてのデバッグ、失敗、成功メッセージを記録します。ディレクトリはシステムが決定します。RedHat、CentOS、Fedora、およびその他のRedHatベースのシステムでは /var/log/mariadb/mariadb.log を使用します。ただし、Debian/Ubuntuでは /var/log/mysql/error.log ディレクトリを使用します。
* **/var/log/xferlog**: FTPファイル転送セッションを保持します。ファイル名やユーザーによるFTP転送などの情報が含まれます。
* **/var/log/\*** : このディレクトリ内の予期しないログを常にチェックする必要があります

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵入やマルウェアのインシデントで無効化または削除される場合があります。Linuxシステムのログは一般的に悪意のある活動に関する最も有用な情報のいくつかを含んでいるため、侵入者は定期的にそれらを削除します。したがって、利用可能なログファイルを調査する際には、削除や改ざんの兆候となる欠落や順序の逆転を探すことが重要です。
{% endhint %}

### コマンド履歴

多くのLinuxシステムは、各ユーザーアカウントのコマンド履歴を維持するように構成されています:

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### ログイン

`last -Faiwx` コマンドを使用すると、ログインしたユーザーのリストを取得できます。\
これらのログインが意味をなすかどうかを確認することをお勧めします:

* 未知のユーザーはいますか？
* シェルを持つべきでないユーザーはいますか？

これは重要です。**攻撃者**は時々 `/bin/bash` を `/bin/false` の中にコピーすることがあり、**lightdm** のようなユーザーが**ログインできる**ようになることがあります。

ログを読むことで、この情報を確認することもできます。

### アプリケーショントレース

* **SSH**: SSHを使用して侵害されたシステムとの間でシステムへの接続を行うと、各ユーザーアカウントのファイル（_**∼/.ssh/authorized\_keys**_ および _**∼/.ssh/known\_keys**_）にエントリが作成されます。これらのエントリには、リモートホストのホスト名やIPアドレスが示される場合があります。
* **Gnomeデスクトップ**: ユーザーアカウントには、Gnomeデスクトップで実行されているアプリケーションを使用して最近アクセスされたファイルに関する情報が含まれる _**∼/.recently-used.xbel**_ ファイルがある場合があります。
* **VIM**: ユーザーアカウントには、VIMの使用に関する詳細（検索文字列履歴やvimを使用して開かれたファイルへのパスなど）が含まれる _**∼/.viminfo**_ ファイルがある場合があります。
* **Open Office**: 最近のファイル。
* **MySQL**: ユーザーアカウントには、MySQLを使用して実行されたクエリが含まれる _**∼/.mysql\_history**_ ファイルがある場合があります。
* **Less**: ユーザーアカウントには、lessの使用に関する詳細（検索文字列履歴やlessを介して実行されたシェルコマンドなど）が含まれる _**∼/.lesshst**_ ファイルがある場合があります。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip) は、Linuxログファイル（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析してUSBイベント履歴テーブルを構築するための純粋なPython 3で書かれた小さなソフトウェアです。

使用されたすべてのUSBを知ることは興味深いですし、許可されたUSBのリストを持っていると、「違反イベント」（そのリストに含まれていないUSBの使用）を見つけるのに役立ちます。

### インストール
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多の例や情報は、[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip) 内にあります。

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も**高度な**コミュニティツールによって**強化**された**ワークフロー**を簡単に構築し、**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ユーザーアカウントとログオンアクティビティの確認

不審な名前やアカウント、または既知の不正イベントに近接して作成されたアカウントを探すために、_**/etc/passwd**_、_**/etc/shadow**_、および**セキュリティログ**を調べます。また、sudoの総当たり攻撃をチェックします。\
さらに、ユーザーに与えられた予期しない特権を確認するために、_**/etc/sudoers**_ や _**/etc/groups**_ などのファイルをチェックします。\
最後に、**パスワードのないアカウント**や**簡単に推測できるパスワード**を持つアカウントを探します。

## ファイルシステムの調査

ファイルシステムのデータ構造は、**マルウェア**事件に関連する**情報**、イベントの**タイミング**、および**マルウェア**の実際の**内容**など、多くの情報を提供できます。\
**マルウェア**は、ファイルシステムの解析を妨げるように設計されることが増えています。一部のマルウェアは、悪意のあるファイルの日時スタンプを変更して、タイムライン分析でそれらを見つけるのをより困難にします。他の悪意のあるコードは、ファイルシステムに格納されるデータ量を最小限に抑えるために、特定の情報のみをメモリに保存するように設計されています。\
このようなアンチフォレンジック技術に対処するためには、ファイルシステムの日時スタンプのタイムライン分析に注意を払うことと、マルウェアが見つかる可能性のある一般的な場所に保存されているファイルに注意を払うことが必要です。

* **autopsy** を使用すると、疑わしい活動を発見するのに役立つかもしれないイベントのタイムラインを見ることができます。また、**Sleuth Kit** の `mactime` 機能を直接使用することもできます。
* **$PATH** 内に**予期しないスクリプト**がないかを確認します（おそらくいくつかの sh スクリプトや php スクリプトがありますか？）
* `/dev` 内のファイルは特殊ファイルでしたが、マルウェアに関連する特殊でないファイルがここにあるかもしれません。
* “.. ”（ドットドットスペース）や “..^G ”（ドットドットコントロール-G）などの**異常な**または**隠しファイル**や**ディレクトリ**を探します。
* システム上の `/bin/bash` の setuid コピーを探します `find / -user root -perm -04000 –print`
* 同じ時期に大量のファイルが削除された**inodeの削除された日時スタンプ**を確認します。これは、ルートキットのインストールやトロイの木馬化されたサービスなどの悪意のある活動を示す可能性があります。
* inode は次に利用可能な基準で割り当てられるため、**同じ時期にシステムに配置された悪意のあるファイルは連続したinodeが割り当てられる可能性があります**。したがって、マルウェアの1つのコンポーネントが見つかった後は、隣接するinodeを調査することが生産的であるかもしれません。
* 新しいまたは変更されたファイルの **/bin** や **/sbin** のディレクトリをチェックします。
* ファイルやフォルダを**作成日**でソートして表示することで、最新のファイルやフォルダを見ることができます（通常、最後のものが表示されます）。

`ls -laR --sort=time /bin` を使用してフォルダ内の最新ファイルを確認できます。\
`ls -lai /bin |sort -n` を使用してフォルダ内のファイルのinodeを確認できます。

{% hint style="info" %}
**攻撃者**は**ファイルを正規**に見せるために**時刻を変更**できますが、**inode**を変更することはできません。同じフォルダ内の他のファイルと同じ時刻に作成および変更されたことを示す**ファイル**が、**予期しないほど大きなinode**である場合、その**ファイルのタイムスタンプが変更**されている可能性があります。
{% endhint %}

## 異なるファイルシステムバージョンのファイルを比較する

#### 追加されたファイル
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 変更されたコンテンツを見つける
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 削除されたファイルを見つける
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### その他のフィルター

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

追加されたファイル（`A`）、コピーされたファイル（`C`）、削除されたファイル（`D`）、変更されたファイル（`M`）、名前が変更されたファイル（`R`）、タイプ（つまり通常のファイル、シンボリックリンク、サブモジュールなど）が変更されたファイル（`T`）、マージされていないファイル（`U`）、不明なファイル（`X`）、またはペアリングが壊れたファイル（`B`）のみを選択します。フィルター文字（含まない場合も含む）の任意の組み合わせを使用できます。組み合わせに`*`（全てまたは無し）が追加されると、比較で他の基準に一致するファイルがある場合はすべてのパスが選択されます。他の基準に一致するファイルがない場合は、何も選択されません。

また、**これらの大文字の文字は除外するために小文字にすることもできます**。例：`--diff-filter=ad` は追加されたパスと削除されたパスを除外します。

すべての差分がすべてのタイプを表示できるわけではないことに注意してください。たとえば、インデックスから作業ツリーへの差分には追加されたエントリが決して含まれない（差分に含まれるパスのセットはインデックスにあるものに制限されるため）ことがあります。同様に、検出が無効になっている場合、コピーされたエントリや名前が変更されたエントリは表示されません。

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

**サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**してみたいですか？または、**PEASSの最新バージョンを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)コレクションを見つけます
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れます
* **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter**で[🐦](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)私をフォローします**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**

**ハッキングトリックを共有するには、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **と**[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
