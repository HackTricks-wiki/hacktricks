# Linuxフォレンジックス

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## 初期情報収集

### 基本情報

まず、**USB**に**既知の良いバイナリとライブラリ**を持っていることが推奨されます（単にUbuntuを取得し、_ /bin_、_ /sbin_、_ /lib_、および_ /lib64_のフォルダをコピーすることができます）。次に、USBをマウントし、環境変数を変更してこれらのバイナリを使用します：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムを良いものや既知のバイナリを使用するように設定したら、**基本的な情報を抽出**することができます。
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
#### 可疑情報

基本情報を取得する際に、以下のような奇妙なことをチェックする必要があります：

* **ルートプロセス**は通常、低いPIDで実行されます。したがって、大きなPIDを持つルートプロセスが見つかった場合は疑わしいと考えられます。
* `/etc/passwd`内のシェルのないユーザーの**登録済みログイン**をチェックします。
* シェルのないユーザーの**パスワードハッシュ**を`/etc/shadow`内でチェックします。

### メモリダンプ

実行中のシステムのメモリを取得するために、[**LiME**](https://github.com/504ensicsLabs/LiME)を使用することをお勧めします。\
それを**コンパイル**するためには、被害者のマシンが使用している**同じカーネル**を使用する必要があります。

{% hint style="info" %}
被害者のマシンには、LiMEや他の何かを**インストールすることはできない**ことを忘れないでください。なぜなら、それによっていくつかの変更が加えられるからです。
{% endhint %}

したがって、Ubuntuの同一バージョンがある場合は、`apt-get install lime-forensics-dkms`を使用できます。\
それ以外の場合は、[**LiME**](https://github.com/504ensicsLabs/LiME)をgithubからダウンロードし、正しいカーネルヘッダーを使用してコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー**を取得するためには、単にディレクトリ`/lib/modules/<kernel version>`を自分のマシンにコピーし、それを使用してLiMEを**コンパイル**します：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

* Raw（すべてのセグメントを連結したもの）
* Padded（Rawと同じですが、右ビットにゼロが入っています）
* Lime（メタデータを含む推奨フォーマット）

LiMEはまた、`path=tcp:4444`のような方法を使用して、システムに保存する代わりにダンプを**ネットワーク経由で送信する**ためにも使用できます。

### ディスクイメージング

#### システムのシャットダウン

まず、**システムをシャットダウンする**必要があります。これは常にオプションではありません。会社がシャットダウンする余裕のないプロダクションサーバーの場合もあります。\
システムをシャットダウンするには、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の2つの方法があります。前者は**プロセスが通常通り終了**し、**ファイルシステムが同期**されることを許しますが、**マルウェア**が**証拠を破壊**する可能性もあります。後者の「プラグを抜く」アプローチでは、**一部の情報が失われる**可能性があります（メモリのイメージを既に取得しているため、情報の損失はほとんどありません）が、**マルウェアは何もできません**。したがって、**マルウェア**が存在する可能性がある場合は、システムで**`sync`** **コマンド**を実行してからプラグを抜いてください。

#### ディスクのイメージを取る

ケースに関連する何かにコンピュータを接続する**前に**、情報を変更しないようにするために、それが**読み取り専用でマウントされることを確認する**必要があります。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

データがないディスクイメージの作成。
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
![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得してください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 既知のマルウェアを検索する

### 変更されたシステムファイル

一部のLinuxシステムには、多くのインストール済みコンポーネントの整合性を検証する機能があり、異常または場所にないファイルを特定する効果的な方法を提供します。たとえば、Linuxの`rpm -Va`は、RedHat Package Managerを使用してインストールされたすべてのパッケージを検証するために設計されています。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### マルウェア/ルートキット検出ツール

マルウェアを見つけるのに役立つツールについては、以下のページを読んでください：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## インストールされたプログラムの検索

### パッケージマネージャ

Debianベースのシステムでは、_**/var/lib/dpkg/status**_ ファイルにはインストールされたパッケージの詳細が含まれており、_**/var/log/dpkg.log**_ ファイルにはパッケージがインストールされたときの情報が記録されます。\
RedHatおよび関連するLinuxディストリビューションでは、**`rpm -qa --root=/mntpath/var/lib/rpm`** コマンドを使用してシステムのRPMデータベースの内容をリストアップすることができます。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### その他

上記のコマンドでは、すべてのインストールされたプログラムがリストされるわけではありません。なぜなら、一部のアプリケーションは特定のシステム向けのパッケージとして利用できず、ソースコードからインストールする必要があるからです。そのため、_**/usr/local**_ や _**/opt**_ などの場所を調べることで、ソースコードからコンパイルしてインストールされた他のアプリケーションが見つかるかもしれません。
```bash
ls /opt /usr/local
```
別の良いアイデアは、**インストールされたパッケージに関連しない** **バイナリ**を**$PATH**内の**一般的なフォルダ**で**チェックする**ことです:
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**し、自動化することができます。\
今すぐアクセスを取得してください：

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

マルウェアが新しい、許可されていないサービスとして浸透することは非常に一般的です。Linuxには、コンピュータの起動時にサービスを開始するために使用されるいくつかのスクリプトがあります。初期化の起動スクリプトである_**/etc/inittab**_は、_**/etc/rc.d/**_ディレクトリまたは一部の古いバージョンでは_**/etc/rc.boot/**_ディレクトリ、またはDebianなどの他のバージョンのLinuxでは_**/etc/init.d/**_ディレクトリの下のさまざまな起動スクリプトを呼び出します。さらに、一部の一般的なサービスは、Linuxのバージョンに応じて_**/etc/inetd.conf**_または_**/etc/xinetd/**_に有効にされます。デジタル調査官は、これらの起動スクリプトの各エントリを異常なものとして調査する必要があります。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### カーネルモジュール

Linuxシステムでは、マルウェアパッケージのルートキットコンポーネントとしてカーネルモジュールが一般的に使用されます。カーネルモジュールは、システムの起動時に`/lib/modules/'uname -r'`および`/etc/modprobe.d`ディレクトリ、および`/etc/modprobe`または`/etc/modprobe.conf`ファイルの設定情報に基づいてロードされます。これらの領域は、マルウェアに関連するアイテムを調査するために検査する必要があります。

### その他の自動起動場所

Linuxは、ユーザーがシステムにログインするときに実行可能ファイルを自動的に起動するために使用するいくつかの設定ファイルがあり、これらにはマルウェアの痕跡が含まれる可能性があります。

* _**/etc/profile.d/\***_、_**/etc/profile**_、_**/etc/bash.bashrc**_は、どのユーザーアカウントでもログインしたときに実行されます。
* _**∼/.bashrc**_、_**∼/.bash\_profile**_、_**\~/.profile**_、_**∼/.config/autostart**_は、特定のユーザーがログインしたときに実行されます。
* _**/etc/rc.local**_は、通常のシステムサービスがすべて起動した後、マルチユーザーランレベルに切り替えるプロセスの最後に実行されます。

## ログの調査

侵害されたシステム上のすべての利用可能なログファイルを調べて、悪意のある実行や関連するアクティビティ（新しいサービスの作成など）の痕跡を見つけます。

### 純粋なログ

システムログおよびセキュリティログに記録された**ログイン**イベントは、特定のアカウントを介して**マルウェア**または**侵入者がアクセス**したことを特定の時間に示すことができます。マルウェア感染の周辺での他のイベントは、システムログにキャプチャされることがあります。例えば、インシデントの時点での新しいサービスの作成や新しいアカウントの作成などです。\
興味深いシステムログイン：

* **/var/log/syslog**（Debian）または**/var/log/messages**（Redhat）
* システム全体のアクティビティに関する一般的なメッセージと情報を表示します。
* **/var/log/auth.log**（Debian）または**/var/log/secure**（Redhat）
* 成功または失敗したログイン、および認証プロセスの認証ログを保持します。ストレージはシステムのタイプに依存します。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**：起動メッセージとブート情報。
* **/var/log/maillog**または**var/log/mail.log**：メールサーバーログで、ポストフィックス、smtpd、またはサーバー上で実行されている関連するメールサービスの情報に便利です。
* **/var/log/kern.log**：カーネルログと警告情報を保持します。カーネルのアクティビティログ（例：dmesg、kern.log、klog）は、特定のサービスが繰り返しクラッシュしたことを示す可能性があります。これは、不安定なトロイの木馬バージョンがインストールされたことを示しています。
* **/var/log/dmesg**：デバイスドライバーメッセージのリポジトリです。このファイルのメッセージを表示するには、**dmesg**を使用します。
* **/var/log/faillog**：失敗したログインの情報を記録します。したがって、ログイン資格情報のハックやブルートフォース攻撃などの潜在的なセキュリティ侵害を調査するのに便利です。
* **/var/log/cron**：Crond関連のメッセージ（cronジョブ）の記録を保持します。cronデーモンがジョブを開始したときなどです。
* **/var/log/daemon.log**：バックグラウンドサービスの実行状況を追跡しますが、それらをグラフィカルに表現しません。
* **/var/log/btmp**：すべての失敗したログイン試行のメモを保持します。
* **/var/log/httpd/**：Apache httpdデーモンのerror\_logおよびaccess\_logファイルが含まれるディレクトリです。httpdが遭遇したすべてのエラーは、**error\_log**ファイルに保持されます。メモリの問題や他のシステム関連のエラーなどです。**access\_log**は、HTTP経由で受信したすべてのリクエストをログに記録します。
* **/var/log/mysqld.log**または**/var/log/mysql.log**：MySQLログファイルで、開始、停止、再起動などのすべてのデバッグ、失敗、成功メッセージを記録します。ディレクトリはシステムが決定します。RedHat、CentOS、Fedora、およびその他のRedHatベースのシステムでは、/var/log/mariadb/mariadb.logを使用します。ただし、Debian/Ubuntuでは/var/log/mysql/error.logディレクトリを使用します。
* **/var/log/xferlog**：FTPファイル転送セッションを保持します。ファイル名やユーザーによるFTP転送などの情報が含まれます。
* **/var/log/\***：このディレクトリに予期しないログがないか常に確認する必要があります

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵入やマルウェアのインシデントで無効化または削除される場合があります。Linuxシステムのログには一般に最も有用な悪意のある活動に関する情報が含まれるため、侵入者は定期的にそれらを削除します。したがって、利用可能なログファイルを調査する際には、削除または改ざんの兆候となるギャップや順序外のエントリを探すことが重要です。
{% endhint %}

### コマンド履歴

多くのLinuxシステムは、各ユーザーアカウントのコマンド履歴を保持するように設定されています。

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### ログイン

`last -Faiwx`コマンドを使用すると、ログインしたユーザーのリストを取得できます。\
これらのログインが意味をな
### アプリケーションのトレース

* **SSH**: システムへのSSH接続は、侵害されたシステムからの接続として、各ユーザーアカウントのファイルにエントリが作成されます（_**∼/.ssh/authorized\_keys**_ および _**∼/.ssh/known\_keys**_）。これらのエントリには、リモートホストのホスト名またはIPアドレスが明示されている場合があります。
* **Gnomeデスクトップ**: ユーザーアカウントには、Gnomeデスクトップで実行されるアプリケーションを使用して最近アクセスされたファイルに関する情報が含まれる _**∼/.recently-used.xbel**_ ファイルがある場合があります。
* **VIM**: ユーザーアカウントには、VIMの使用に関する詳細が含まれる _**∼/.viminfo**_ ファイルがある場合があります。これには、検索文字列の履歴やvimを使用して開かれたファイルへのパスなどが含まれます。
* **Open Office**: 最近のファイル。
* **MySQL**: ユーザーアカウントには、MySQLを使用して実行されたクエリが含まれる _**∼/.mysql\_history**_ ファイルがある場合があります。
* **Less**: ユーザーアカウントには、検索文字列の履歴やlessを介して実行されたシェルコマンドなど、lessの使用に関する詳細が含まれる _**∼/.lesshst**_ ファイルがある場合があります。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip)は、Linuxのログファイル（ディストリビューションによっては `/var/log/syslog*` または `/var/log/messages*`）を解析してUSBイベント履歴テーブルを作成するための純粋なPython 3で書かれた小さなソフトウェアです。

**使用されたすべてのUSBデバイスを知る**ことは興味深いですし、USBデバイスの「違反イベント」（そのリストに含まれていないUSBデバイスの使用）を見つけるために認可されたUSBデバイスのリストを持っているとさらに便利です。

### インストール
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例

#### ファイルの復元

ファイルの復元は、削除されたファイルを回復するための手法です。削除されたファイルは、実際にはディスク上に残っていることがあります。復元するためには、ファイルのヘッダやフッタ、およびファイルの中身を特定する必要があります。一般的なツールとしては、`foremost`や`scalpel`があります。

#### メモリの解析

メモリの解析は、実行中のシステムのメモリを調査するための手法です。メモリには、プロセスの情報やユーザーのアクティビティなど、重要な情報が含まれています。メモリの解析には、`Volatility`や`Rekall`などのツールが使用されます。

#### ネットワークトラフィックの解析

ネットワークトラフィックの解析は、ネットワーク上で送受信されるデータを調査する手法です。ネットワークトラフィックには、通信の詳細やパケットの内容など、重要な情報が含まれています。ネットワークトラフィックの解析には、`Wireshark`や`tcpdump`などのツールが使用されます。

#### ログの解析

ログの解析は、システムやアプリケーションのログファイルを調査する手法です。ログには、システムの動作やイベントの記録が含まれています。ログの解析には、`grep`や`awk`などのツールが使用されます。

#### レジストリの解析

レジストリの解析は、Windowsシステムのレジストリデータベースを調査する手法です。レジストリには、システムの設定やユーザーのアクティビティなど、重要な情報が含まれています。レジストリの解析には、`RegRipper`や`Registry Explorer`などのツールが使用されます。

#### フォレンジックイメージの作成

フォレンジックイメージの作成は、証拠を保護するためにディスクやメモリのコピーを作成する手法です。フォレンジックイメージは、解析や復元作業を行う際に使用されます。フォレンジックイメージの作成には、`dd`や`dcfldd`などのツールが使用されます。
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
さらなる例や情報は、GitHub内で確認できます：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**することができます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ユーザーアカウントとログオンアクティビティの確認

不正なイベントに関連して近くで作成または使用された、異常な名前やアカウントを含む_**/etc/passwd**_、_**/etc/shadow**_、および**セキュリティログ**を調査します。また、sudoによるブルートフォース攻撃の可能性もチェックします。\
さらに、ユーザーに与えられた予期しない特権を持つファイル（_**/etc/sudoers**_や_**/etc/groups**_など）も確認します。\
最後に、パスワードのないアカウントや簡単に推測できるパスワードを持つアカウントを探します。

## ファイルシステムの調査

ファイルシステムのデータ構造は、**マルウェア**のインシデントに関連する**情報**（イベントのタイミングや**マルウェア**の実際の**内容**など）を提供する場合があります。\
**マルウェア**は、ファイルシステムの解析を困難にするために、日時スタンプを変更するなどの手法を使用することが増えています。他の悪意のあるコードは、ファイルシステムに格納されるデータ量を最小限に抑えるために、特定の情報のみをメモリに保存するように設計されています。\
このようなアンチフォレンジック技術に対処するためには、ファイルシステムの日時スタンプのタイムライン分析に**注意を払う**必要があります。また、マルウェアが見つかる可能性のある一般的な場所に保存されたファイルにも注意を払う必要があります。

* **autopsy**を使用すると、疑わしい活動を発見するのに役立つイベントのタイムラインを確認できます。また、**Sleuth Kit**の`mactime`機能を直接使用することもできます。
* **$PATH**内に予期しないスクリプトがないか確認します（おそらくいくつかのshスクリプトやphpスクリプトがありますか？）
* `/dev`内のファイルは特殊なファイルであるはずですが、マルウェアに関連する特殊でないファイルが見つかる場合があります。
* ".. "（ドットドットスペース）や"..^G "（ドットドットコントロールG）などの異常なまたは**隠しファイル**や**ディレクトリ**を探します。
* システム上の/bin/bashのsetuidコピー `find / -user root -perm -04000 –print`
* 削除された**inodeの日時スタンプ**を確認し、同じ時期に大量のファイルが削除されている場合は、ルートキットのインストールやトロイの木馬化されたサービスのインストールなどの悪意のある活動を示している可能性があります。
* inodeは次に利用可能な基準で割り当てられるため、**同じ時期にシステムに配置された悪意のあるファイルは連続したinodeが割り当てられる**場合があります。したがって、マルウェアの1つのコンポーネントが見つかった後は、隣接するinodeを調査することが生産的である場合があります。
* _/bin_や_/sbin_などのディレクトリも確認し、新しいまたは変更されたファイルの**変更された時刻**を調べます。
* ファイルやフォルダをアルファベット順ではなく、作成日時順に並べ替えたディレクトリのファイルとフォルダを見ると、より最近のファイルやフォルダがわかります（通常、最後のものです）。

`ls -laR --sort=time /bin`を使用して、フォルダの最新のファイルを確認できます。\
`ls -lai /bin |sort -n`を使用して、フォルダ内のファイルのinodeを確認できます。

{% hint style="info" %}
**攻撃者**は**時間**を**変更**して**ファイルを正規に見せかける**ことができますが、**inode**を変更することはできません。同じフォルダ内の他のファイルと同じように、あるファイルが作成および変更されたと示されているが、**inode**が予期しないほど大きい場合、そのファイルの**タイムスタンプが変更された**ことを意味します。
{% endhint %}

## 異なるファイルシステムバージョンの比較

#### 追加されたファイルの検索
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 変更されたコンテンツの検索

To find modified content in a Linux system, you can use various techniques and tools. Here are some methods you can follow:

1. **File Timestamps**: Check the timestamps of files to identify recently modified files. The `stat` command can be used to view the access, modification, and change timestamps of a file.

2. **Log Files**: Analyze system log files such as `/var/log/syslog` or `/var/log/auth.log` to identify any suspicious activities or modifications.

3. **File Integrity Monitoring (FIM)**: Use FIM tools like `Tripwire` or `AIDE` to monitor and detect changes in critical system files. These tools can generate reports highlighting any modifications.

4. **Version Control Systems**: If the system uses version control systems like `Git`, you can check the commit history to identify any recent changes made to files.

5. **System Audit Logs**: Review system audit logs, such as those generated by `auditd`, to identify any unauthorized modifications or access to files.

6. **Memory Analysis**: Analyze the system's memory using tools like `Volatility` to identify any suspicious processes or modifications in memory.

Remember to document any findings and preserve the integrity of the evidence during the investigation process.
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 削除されたファイルの検索

To find deleted files on a Linux system, you can use various techniques and tools. Here are some methods you can try:

1. **File Recovery Tools**: Use specialized file recovery tools like `extundelete`, `testdisk`, or `foremost` to scan the file system and recover deleted files.

2. **File System Journal**: Check the file system journal to identify recently deleted files. The journal records metadata changes, including file deletions. Tools like `jcat` and `icat` can help you analyze the journal.

3. **Inode Analysis**: Inodes store information about files on a Linux system. By examining the inode table, you can identify deleted files that still have their metadata intact. Tools like `istat` and `ifind` can assist in this analysis.

4. **Carving**: File carving involves searching for file signatures or specific file headers in unallocated disk space. This technique can help recover deleted files that no longer have their metadata available. Tools like `scalpel` and `foremost` are commonly used for file carving.

Remember to work on a copy of the disk or partition to avoid modifying the original data. Additionally, it's crucial to document your findings and follow proper forensic procedures to maintain the integrity of the evidence.

#### 削除されたファイルを見つける

Linuxシステム上で削除されたファイルを見つけるために、さまざまな手法とツールを使用することができます。以下にいくつかの試みるべき方法を示します：

1. **ファイル復元ツール**：`extundelete`、`testdisk`、または`foremost`などの専門のファイル復元ツールを使用して、ファイルシステムをスキャンし、削除されたファイルを回復します。

2. **ファイルシステムジャーナル**：ファイルシステムジャーナルをチェックして、最近削除されたファイルを特定します。ジャーナルは、ファイルの削除を含むメタデータの変更を記録します。`jcat`や`icat`などのツールを使用して、ジャーナルを分析することができます。

3. **Inodeの分析**：InodeはLinuxシステム上のファイルに関する情報を格納しています。Inodeテーブルを調査することで、メタデータが残っている削除されたファイルを特定することができます。`istat`や`ifind`などのツールがこの分析をサポートします。

4. **カービング**：カービングは、未割り当てのディスク領域でファイルのシグネチャや特定のファイルヘッダを検索する手法です。この技術を使用すると、メタデータが利用できなくなった削除されたファイルを回復することができます。`scalpel`や`foremost`などのツールがファイルカービングによく使用されます。

元のデータを変更しないために、ディスクまたはパーティションのコピーで作業することを忘れないでください。また、証拠の完全性を保つために、調査結果を文書化し、適切な法的手続きに従うことが重要です。
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### その他のフィルター

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

追加されたファイル (`A`)、コピーされたファイル (`C`)、削除されたファイル (`D`)、変更されたファイル (`M`)、名前が変更されたファイル (`R`)、タイプが変更されたファイル（通常のファイル、シンボリックリンク、サブモジュールなど） (`T`)、マージされていないファイル (`U`)、不明なファイル (`X`)、ペアリングが壊れたファイル (`B`) のみを選択します。フィルター文字の組み合わせには、任意の組み合わせ（なしも含む）が使用できます。組み合わせに `*`（全てまたは無し）が追加されると、比較に他の基準に一致するファイルがある場合、すべてのパスが選択されます。他の基準に一致するファイルがない場合、何も選択されません。

また、これらの大文字の文字は、除外するために小文字にすることもできます。例：`--diff-filter=ad` は追加されたパスと削除されたパスを除外します。

すべての差分がすべてのタイプを持つわけではないことに注意してください。たとえば、インデックスから作業ツリーへの差分には、追加されたエントリが存在しない場合があります（差分に含まれるパスのセットはインデックスに含まれるものに制限されるため）。同様に、コピーされたエントリと名前が変更されたエントリは、それらのタイプの検出が無効になっている場合には表示されません。

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

**サイバーセキュリティ企業で働いていますか？** **HackTricks**で**あなたの会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

**ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

![](<../../.gitbook/assets/image (9) (1) (2).png>)

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築して自動化しましょう。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
