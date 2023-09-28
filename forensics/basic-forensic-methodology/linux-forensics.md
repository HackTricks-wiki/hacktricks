# Linuxフォレンジックス

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです
* [**公式のPEASS＆HackTricksのスワッグ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

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

基本情報を取得する際に、以下のような奇妙なことに注意してください：

* **ルートプロセス**は通常、低いPIDで実行されます。したがって、大きなPIDを持つルートプロセスが見つかった場合は疑わしいと考えられます。
* `/etc/passwd`内のシェルのないユーザーの**登録済みログイン**を確認してください。
* シェルのないユーザーの**パスワードハッシュ**を`/etc/shadow`内で確認してください。

### メモリダンプ

実行中のシステムのメモリを取得するためには、[**LiME**](https://github.com/504ensicsLabs/LiME)を使用することをおすすめします。\
**コンパイル**するためには、被害者のマシンと同じカーネルを使用する必要があります。

{% hint style="info" %}
被害者のマシンには、LiMEや他の何かを**インストールすることはできません**。なぜなら、それによっていくつかの変更が加えられるからです。
{% endhint %}

したがって、Ubuntuの同一バージョンがある場合は、`apt-get install lime-forensics-dkms`を使用できます。\
それ以外の場合は、[**LiME**](https://github.com/504ensicsLabs/LiME)をgithubからダウンロードし、正しいカーネルヘッダーを使用してコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー**を取得するためには、単に`/lib/modules/<kernel version>`ディレクトリを自分のマシンに**コピー**し、それを使用してLiMEをコンパイルします：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

* Raw（すべてのセグメントを連結したもの）
* Padded（Rawと同じですが、右ビットにはゼロが入っています）
* Lime（メタデータを含む推奨フォーマット）

LiMEは、`path=tcp:4444`のような方法を使用して、システムに保存する代わりにダンプを**ネットワーク経由で送信する**ためにも使用できます。

### ディスクイメージング

#### シャットダウン

まず、システムを**シャットダウンする必要があります**。これは常にオプションではありません。なぜなら、システムが会社がシャットダウンする余裕のないプロダクションサーバーである場合もあるからです。\
システムをシャットダウンするには、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の2つの方法があります。前者は、**プロセスが通常通り終了**し、**ファイルシステムが同期**されることを許しますが、**マルウェア**が**証拠を破壊**する可能性もあります。後者の「プラグを抜く」アプローチでは、**いくつかの情報の損失**が発生する場合があります（メモリのイメージを既に取得しているため、情報の損失はほとんどありません）が、**マルウェアは何もできません**。したがって、**マルウェア**が存在する可能性がある場合は、システムで**`sync`** **コマンド**を実行してからプラグを抜いてください。

#### ディスクのイメージを取得する

ケースに関連する何かにコンピュータを接続する**前に**、情報を変更しないようにするために、それが**読み取り専用でマウントされることを確認する必要があります**。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

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
RedHatおよび関連するLinuxディストリビューションでは、**`rpm -qa --root=/mntpath/var/lib/rpm`** コマンドを使用してシステム上のRPMデータベースの内容をリストアップすることができます。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### その他

上記のコマンドでは、すべてのインストールされたプログラムがリストされるわけではありません。なぜなら、一部のアプリケーションは特定のシステム用のパッケージとして利用できず、ソースコードからインストールする必要があるからです。そのため、_**/usr/local**_ や _**/opt**_ などの場所を調査することで、ソースコードからコンパイルしてインストールされた他のアプリケーションが見つかるかもしれません。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

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

マルウェアが新しい、許可されていないサービスとして浸透することは非常に一般的です。Linuxには、コンピュータの起動時にサービスを開始するために使用されるいくつかのスクリプトがあります。初期化の起動スクリプトである_**/etc/inittab**_は、_**/etc/rc.d/**_ディレクトリまたは一部の古いバージョンでは_**/etc/rc.boot/**_ディレクトリ、または_**/etc/init.d/**_ディレクトリなど、他のスクリプトを呼び出します。また、Debianなどの他のバージョンのLinuxでは、起動スクリプトは_**/etc/init.d/**_ディレクトリに格納されています。さらに、一部の一般的なサービスは、Linuxのバージョンに応じて_**/etc/inetd.conf**_または_**/etc/xinetd/**_に有効にされています。デジタル調査官は、これらの起動スクリプトの各エントリを異常なものとして調査する必要があります。

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

システムログおよびセキュリティログに記録された**ログイン**イベントは、特定のアカウントで特定の時間にマルウェアまたは侵入者が侵害されたシステムにアクセスしたことを明らかにすることができます。マルウェア感染の周辺で発生した他のイベントは、システムログにキャプチャされる可能性があります。例えば、インシデントの発生時に新しいサービスや新しいアカウントの作成などです。\
興味深いシステムログイン：

* **/var/log/syslog**（Debian）または**/var/log/messages**（Redhat）
* システム全体のアクティビティに関する一般的なメッセージと情報を表示します。
* **/var/log/auth.log**（Debian）または**/var/log/secure**（Redhat）
* 成功または失敗したログイン、および認証プロセスの認証ログを保持します。ストレージはシステムのタイプに依存します。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**：起動メッセージとブート情報。
* **/var/log/maillog**または**var/log/mail.log**：メールサーバーログであり、ポストフィックス、smtpd、またはサーバー上で実行される関連する電子メールサービスの情報に便利です。
* **/var/log/kern.log**：カーネルログと警告情報を保持します。カーネルのアクティビティログ（例：dmesg、kern.log、klog）は、特定のサービスが繰り返しクラッシュしたことを示す可能性があり、不安定なトロイの木馬バージョンがインストールされていることを示す可能性があります。
* **/var/log/dmesg**：デバイスドライバーメッセージのリポジトリです。このファイルのメッセージを表示するには、**dmesg**を使用します。
* **/var/log/faillog**：失敗したログインの情報を記録します。したがって、ログイン資格情報のハックやブルートフォース攻撃などの潜在的なセキュリティ侵害を調査するのに便利です。
* **/var/log/cron**：Crond関連のメッセージ（cronジョブ）の記録を保持します。cronデーモンがジョブを開始したときなどです。
* **/var/log/daemon.log**：バックグラウンドサービスの実行状況を追跡しますが、それらをグラフィカルに表現しません。
* **/var/log/btmp**：すべての失敗したログイン試行のメモを保持します。
* **/var/log/httpd/**：Apache httpdデーモンのerror\_logおよびaccess\_logファイルが含まれるディレクトリです。httpdが遭遇したすべてのエラーは、**error\_log**ファイルに保持されます。メモリの問題や他のシステム関連のエラーなどです。**access\_log**は、HTTP経由で受信したすべてのリクエストをログに記録します。
* **/var/log/mysqld.log**または**/var/log/mysql.log**：MySQLログファイルであり、開始、停止、再起動などのすべてのデバッグ、失敗、成功メッセージを記録します。ディレクトリはシステムが決定します。RedHat、CentOS、Fedora、およびその他のRedHatベースのシステムでは、/var/log/mariadb/mariadb.logを使用します。ただし、Debian/Ubuntuでは、/var/log/mysql/error.logディレクトリを使用します。
* **/var/log/xferlog**：FTPファイル転送セッションを保持します。ファイル名やユーザーによるFTP転送などの情報が含まれます。
* **/var/log/\***：このディレクトリに予期しないログがないか常に確認する必要があります

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵入やマルウェアのインシデントで無効化または削除される場合があります。Linuxシステムのログは一般的に悪意のある活動に関する最も有用な情報の一部を含んでいるため、侵入者は定期的にそれらを削除します。したがって、利用可能なログファイルを調査する際には、削除または改ざんの兆候となるギャップや順序の逆転を探すことが重要です。
{% endhint %}

### コマンド履歴

多くのLinuxシステムは、各ユーザーアカウントのコマンド履歴を保持するように設定されています。

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### ログイン

`last -F
### アプリケーションのトレース

* **SSH**: システムへのSSH接続は、侵害されたシステムからの接続として、各ユーザーアカウントのファイルにエントリが作成されます（_**∼/.ssh/authorized\_keys**_ および _**∼/.ssh/known\_keys**_）。これらのエントリには、リモートホストのホスト名またはIPアドレスが明示されている場合があります。
* **Gnomeデスクトップ**: ユーザーアカウントには、Gnomeデスクトップで実行されるアプリケーションを使用して最近アクセスされたファイルに関する情報が含まれる _**∼/.recently-used.xbel**_ ファイルがある場合があります。
* **VIM**: ユーザーアカウントには、VIMの使用に関する詳細が含まれる _**∼/.viminfo**_ ファイルがある場合があります。これには、検索文字列の履歴やvimを使用して開かれたファイルへのパスなどが含まれます。
* **Open Office**: 最近のファイル。
* **MySQL**: ユーザーアカウントには、MySQLを使用して実行されたクエリが含まれる _**∼/.mysql\_history**_ ファイルがある場合があります。
* **Less**: ユーザーアカウントには、検索文字列の履歴やlessを介して実行されたシェルコマンドなど、lessの使用に関する詳細が含まれる _**∼/.lesshst**_ ファイルがある場合があります。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip)は、Linuxのログファイル（ディストリビューションによっては `/var/log/syslog*` または `/var/log/messages*`）を解析してUSBイベント履歴テーブルを作成するための純粋なPython 3で書かれた小さなソフトウェアです。

**使用されたすべてのUSBデバイスを知る**ことは興味深いですし、許可されたUSBデバイスのリストを持っている場合は、「違反イベント」（そのリストに含まれていないUSBデバイスの使用）を見つけるのに役立ちます。

### インストール
```
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例

#### Example 1: Collecting Volatile Data

#### 例1: 揮発性データの収集

To collect volatile data from a Linux system, follow these steps:

Linuxシステムから揮発性データを収集するには、以下の手順に従います。

1. Log in to the Linux system using appropriate credentials.

   適切な資格情報を使用してLinuxシステムにログインします。

2. Open a terminal and run the following command to list all running processes:

   ターミナルを開き、次のコマンドを実行して実行中のすべてのプロセスをリストします。

   ```bash
   ps aux
   ```

3. Take note of any suspicious or unfamiliar processes running on the system.

   システムで実行されている不審なプロセスや見慣れないプロセスに注意を払います。

4. Run the following command to list all open network connections:

   次のコマンドを実行して、すべてのオープンネットワーク接続をリストします。

   ```bash
   netstat -antp
   ```

5. Analyze the network connections and identify any suspicious or unauthorized connections.

   ネットワーク接続を分析し、不審な接続や不正な接続を特定します。

6. Run the following command to view the system's active network interfaces:

   次のコマンドを実行して、システムのアクティブなネットワークインターフェースを表示します。

   ```bash
   ifconfig -a
   ```

7. Take note of any additional network interfaces that are not expected to be present.

   存在するはずのない追加のネットワークインターフェースに注意を払います。

8. Run the following command to view the system's open files:

   次のコマンドを実行して、システムのオープンファイルを表示します。

   ```bash
   lsof
   ```

9. Look for any suspicious or unauthorized files that are open.

   開かれている不審なファイルや不正なファイルを探します。

10. Take screenshots or record the output of the above commands for further analysis.

    上記のコマンドの出力をさらに分析するためにスクリーンショットを撮影したり、記録したりします。

#### Example 2: Analyzing Log Files

#### 例2: ログファイルの分析

To analyze log files on a Linux system, follow these steps:

Linuxシステム上のログファイルを分析するには、以下の手順に従います。

1. Log in to the Linux system using appropriate credentials.

   適切な資格情報を使用してLinuxシステムにログインします。

2. Open a terminal and navigate to the directory containing the log files.

   ターミナルを開き、ログファイルが含まれているディレクトリに移動します。

3. Run the following command to view the contents of a log file:

   次のコマンドを実行して、ログファイルの内容を表示します。

   ```bash
   cat <log_file>
   ```

   Replace `<log_file>` with the actual name of the log file you want to analyze.

   `<log_file>`を分析したいログファイルの実際の名前に置き換えます。

4. Look for any suspicious or unusual entries in the log file.

   ログファイル内の不審なエントリや異常なエントリを探します。

5. Run the following command to filter the log file based on specific criteria:

   特定の基準に基づいてログファイルをフィルタリングするために、次のコマンドを実行します。

   ```bash
   grep <search_pattern> <log_file>
   ```

   Replace `<search_pattern>` with the specific pattern you want to search for in the log file.

   `<search_pattern>`をログファイル内で検索したい特定のパターンに置き換えます。

6. Analyze the filtered log entries and identify any suspicious or unauthorized activities.

   フィルタリングされたログエントリを分析し、不審な活動や不正な活動を特定します。

7. Take screenshots or record the output of the above commands for further analysis.

   上記のコマンドの出力をさらに分析するためにスクリーンショットを撮影したり、記録したりします。
```
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
さらなる例や情報は、[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)で確認できます。

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**することができます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ユーザーアカウントとログオンアクティビティの確認

不正なイベントに関連して近くで作成または使用された、異常な名前やアカウントを含む_**/etc/passwd**_、_**/etc/shadow**_、および**セキュリティログ**を調べます。また、sudoのブルートフォース攻撃も確認してください。\
さらに、ユーザーに与えられた予期しない特権を確認するために、_**/etc/sudoers**_や_**/etc/groups**_などのファイルもチェックします。\
最後に、パスワードのないアカウントや簡単に推測できるパスワードを持つアカウントを探します。

## ファイルシステムの調査

ファイルシステムのデータ構造は、**マルウェア**のインシデントに関連する**情報**、イベントの**タイミング**、および実際の**マルウェア**の**内容**など、大量の情報を提供することができます。\
**マルウェア**は、ファイルシステムの解析を妨げるために設計されることが増えています。一部のマルウェアは、タイムライン分析でそれらを見つけるのをより困難にするために、悪意のあるファイルの日時スタンプを変更します。他の悪意のあるコードは、ファイルシステムに格納されるデータ量を最小限に抑えるために、特定の情報のみをメモリに保存するように設計されています。\
このようなアンチフォレンジック技術に対処するためには、ファイルシステムの日時スタンプのタイムライン分析に**注意を払う**ことと、マルウェアが見つかる可能性のある一般的な場所に保存されたファイルに**注意を払う**ことが必要です。

* **autopsy**を使用すると、疑わしい活動を発見するのに役立つイベントのタイムラインを表示できます。また、**Sleuth Kit**の`mactime`機能も直接使用できます。
* **$PATH**内の予期しないスクリプト（おそらくいくつかのshスクリプトやphpスクリプト）をチェックします。
* `/dev`内のファイルは特殊なファイルでしたが、ここにはマルウェアに関連する特殊でないファイルがあるかもしれません。
* ".. "（ドットドットスペース）や"..^G "（ドットドットコントロールG）などの異常なまたは**隠しファイル**や**ディレクトリ**を探します。
* システム上の/bin/bashのsetuidコピーを探す`find / -user root -perm -04000 –print`
* 削除された**inodeの日時スタンプを確認**し、同じ時期に大量のファイルが削除されている場合は、ルートキットのインストールやトロイの木馬化されたサービスのような悪意のある活動を示している可能性があります。
* inodeは次に利用可能な基準で割り当てられるため、**同じ時期にシステムに配置された悪意のあるファイルは連続したinodeが割り当てられる**可能性があります。したがって、マルウェアの1つのコンポーネントが見つかった後は、隣接するinodeを調査することが生産的です。
* _/bin_や_/sbin_などのディレクトリもチェックし、新しいまたは変更されたファイルの**変更された時刻**を調べると興味深いかもしれません。
* ファイルやフォルダをアルファベット順ではなく、作成日時でソートされたディレクトリのファイルとフォルダを見ると、より最近のファイルやフォルダがわかります（通常、最後のものです）。

`ls -laR --sort=time /bin`を使用して、フォルダの最新のファイルを確認できます。\
`ls -lai /bin |sort -n`を使用して、フォルダ内のファイルのinodeを確認できます。

{% hint style="info" %}
**攻撃者**は**ファイルの時間**を**変更**して**ファイルを正規に見せかける**ことができますが、**inode**は**変更できません**。同じフォルダ内の他のファイルと同じ時刻に作成および変更されたことを示す**ファイル**が、**予期しないほど大きなinode**を持っている場合、そのファイルのタイムスタンプが**変更された**ことを意味します。
{% endhint %}

## 異なるファイルシステムバージョンのファイルを比較する

#### 追加されたファイルを見つける
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 変更されたコンテンツの検索

To find modified content in a Linux system, you can use various techniques and tools. Here are some steps you can follow:

1. **Timeline Analysis**: Analyze the system's timeline to identify any suspicious activities or changes. This can be done using tools like `fls`, `mactime`, or `timestomp`.

2. **File System Analysis**: Examine the file system for any recently modified files. Tools like `find`, `ls`, or `stat` can help you identify files with recent modification timestamps.

3. **Log Analysis**: Review system logs, such as `/var/log/syslog` or `/var/log/auth.log`, for any unusual or suspicious entries. Look for any log entries related to file modifications or unauthorized access.

4. **Metadata Analysis**: Analyze file metadata, such as file permissions, ownership, and timestamps, to identify any anomalies. Tools like `stat`, `ls`, or `file` can provide valuable information about file attributes.

5. **Hash Comparison**: Calculate and compare file hashes to detect any changes in file content. Tools like `md5sum`, `sha1sum`, or `sha256sum` can help you generate and compare file hashes.

6. **Memory Analysis**: Perform memory analysis to identify any suspicious processes or activities. Tools like `Volatility` or `LiME` can be used to extract and analyze memory dumps.

By following these steps, you can effectively identify any modified content in a Linux system and gather evidence for further investigation.
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 削除されたファイルの検索

Deleted files can often be recovered during a forensic investigation. When a file is deleted, it is not immediately removed from the storage device. Instead, the file system marks the space occupied by the file as available for reuse. This means that the file's content may still exist on the disk until it is overwritten by new data.

削除されたファイルは、フォレンジック調査中にしばしば回復することができます。ファイルが削除されると、ストレージデバイスから直ちに削除されるわけではありません。代わりに、ファイルシステムはファイルが占めていたスペースを再利用可能としてマークします。つまり、新しいデータによって上書きされるまで、ファイルの内容はディスク上に残る可能性があります。

To find deleted files on a Linux system, you can use various tools and techniques. Here are some common methods:

Linuxシステム上で削除されたファイルを見つけるために、さまざまなツールと技術を使用することができます。以下に一般的な方法をいくつか紹介します。

1. **File Carving**: File carving is a technique used to recover deleted files by searching for file signatures or headers in unallocated disk space. Tools like `foremost` and `scalpel` can be used for file carving.

   **ファイルカービング**: ファイルカービングは、削除されたファイルを回復するための技術であり、未割り当てのディスク領域でファイルのシグネチャやヘッダを検索します。`foremost`や`scalpel`などのツールを使用してファイルカービングを行うことができます。

2. **Metadata Analysis**: Metadata of files can provide valuable information about deleted files. Tools like `exiftool` and `libextractor` can be used to extract metadata from files and analyze it for evidence of deleted files.

   **メタデータの分析**: ファイルのメタデータには、削除されたファイルに関する貴重な情報が含まれている場合があります。`exiftool`や`libextractor`などのツールを使用して、ファイルからメタデータを抽出し、削除されたファイルの証拠を分析することができます。

3. **File System Journal**: Some Linux file systems, such as ext3 and ext4, maintain a journal that records file system activities. This journal can be analyzed to identify deleted files. Tools like `extundelete` and `testdisk` can be used for this purpose.

   **ファイルシステムジャーナル**: ext3やext4などの一部のLinuxファイルシステムは、ファイルシステムのアクティビティを記録するジャーナルを保持しています。このジャーナルを分析して削除されたファイルを特定することができます。`extundelete`や`testdisk`などのツールを使用することができます。

Remember that the success of recovering deleted files depends on various factors, such as the time elapsed since deletion and the extent of disk activity. It is important to perform forensic analysis as soon as possible to increase the chances of successful recovery.

削除されたファイルの回復の成功は、削除後の経過時間やディスクのアクティビティの範囲など、さまざまな要因に依存します。成功した回復の可能性を高めるために、できるだけ早くフォレンジック分析を行うことが重要です。
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### その他のフィルター

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

追加されたファイル (`A`)、コピーされたファイル (`C`)、削除されたファイル (`D`)、変更されたファイル (`M`)、名前が変更されたファイル (`R`)、タイプが変更されたファイル（通常のファイル、シンボリックリンク、サブモジュールなど） (`T`)、マージされていないファイル (`U`)、不明なファイル (`X`)、ペアリングが壊れたファイル (`B`) のみを選択します。フィルター文字の組み合わせには、任意の組み合わせが使用できます（組み合わせに `*`（すべてまたはなし）が追加された場合、比較で他の基準に一致するファイルがある場合はすべてのパスが選択されます。他の基準に一致するファイルがない場合は、何も選択されません）。

また、これらの大文字の文字は除外するために小文字にすることもできます。例：`--diff-filter=ad` は追加されたファイルと削除されたファイルを除外します。

すべての差分がすべてのタイプを持つわけではないことに注意してください。たとえば、インデックスから作業ツリーへの差分には、追加されたエントリが表示されることはありません（差分に含まれるパスのセットはインデックスに含まれるものに制限されるため）。同様に、コピーされたエントリと名前が変更されたエントリは、それらのタイプの検出が無効になっている場合には表示されません。

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

**サイバーセキュリティ企業で働いていますか？** **HackTricks**で**会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築して自動化しましょう。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
