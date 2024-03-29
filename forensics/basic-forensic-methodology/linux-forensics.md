# Linux Forensics

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**を使用して、ゼロからヒーローまでAWSハッキングを学びましょう</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**をフォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>

## Initial Information Gathering

### Basic Information

まず最初に、**USB**に**よく知られたバイナリとライブラリ**が含まれていることが推奨されます（単にUbuntuを取得して、_ /bin_、_ /sbin_、_ /lib_、および_ /lib64_のフォルダをコピーできます）。その後、USBをマウントし、環境変数を変更してこれらのバイナリを使用します：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一度システムを良いものや既知のバイナリを使用するように設定したら、**基本情報を抽出**することができます：
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

- **Rootプロセス** は通常、低いPIDで実行されます。そのため、大きなPIDで実行されているRootプロセスが見つかった場合は疑うべきです
- `/etc/passwd` 内でシェルを持たないユーザーの**登録されたログイン** を確認する
- `/etc/shadow` 内でシェルを持たないユーザーの**パスワードハッシュ** を確認する

### メモリーダンプ

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) を使用することをお勧めします。\
**コンパイル** するには、被害者マシンが使用している**同じカーネル** を使用する必要があります。

{% hint style="info" %}
被害者マシンに **LiME やその他の何かをインストールすることはできない** ことを覚えておいてください。それにより、いくつかの変更が加えられます
{% endhint %}

したがって、Ubuntuの同一バージョンがある場合は、`apt-get install lime-forensics-dkms` を使用できます\
それ以外の場合は、[**LiME**](https://github.com/504ensicsLabs/LiME) をgithub からダウンロードし、正しいカーネルヘッダーを使用してコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー** を取得するには、単にディレクトリ `/lib/modules/<kernel version>` をあなたのマシンにコピーし、それを使用して LiME を**コンパイル** します:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

- Raw（すべてのセグメントが連結されたもの）
- Padded（Rawと同じですが、右ビットにゼロが入っています）
- Lime（メタデータを含む推奨フォーマット）

LiMEは、`path=tcp:4444`のような方法を使用して、**ダンプをネットワーク経由で送信**することもできます。

### ディスクイメージング

#### シャットダウン

まず、**システムをシャットダウンする**必要があります。これは常に選択肢となるわけではありません。なぜなら、システムが企業がシャットダウンする余裕のない本番サーバーである場合があるからです。\
システムをシャットダウンする方法には、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の2つがあります。前者は**プロセスが通常通り終了**し、**ファイルシステム**が**同期**されることを可能にしますが、**悪意のあるソフトウェア**が**証拠を破壊**する可能性もあります。後者の「プラグを抜く」アプローチは、**一部の情報が失われる可能性**があります（メモリのイメージをすでに取得しているため、失われる情報はほとんどありません）し、**悪意のあるソフトウェア**が何もできなくなります。したがって、**悪意のあるソフトウェア**がある可能性がある場合は、システムで**`sync`** **コマンド**を実行してからプラグを抜いてください。

#### ディスクのイメージを取得する

**ケースに関連する何かにコンピュータを接続する前に**、情報を変更しないように**読み取り専用でマウント**されることを確認する必要があります。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も先進的なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 既知のマルウェアを検索

### 変更されたシステムファイル

Linuxには、潜在的に問題のあるファイルを見つけるために重要なシステムコンポーネントの整合性を確認するためのツールが用意されています。

* **RedHatベースのシステム**: 総合的なチェックには`rpm -Va`を使用します。
* **Debianベースのシステム**: 初期検証には`dpkg --verify`を使用し、その後`debsums | grep -v "OK$"`（`apt-get install debsums`を使用して`debsums`をインストールした後）を使用して問題を特定します。

### マルウェア/ルートキット検出ツール

マルウェアを見つけるのに役立つツールについて学ぶには、以下のページを参照してください：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## インストールされたプログラムを検索

DebianとRedHatの両方のシステムでインストールされたプログラムを効果的に検索するには、システムログやデータベースを活用し、一般的なディレクトリでの手動チェックを検討してください。

* Debianの場合、パッケージのインストールに関する詳細を取得するために、_**`/var/lib/dpkg/status`**_と_**`/var/log/dpkg.log`**_を調査し、`grep`を使用して特定の情報をフィルタリングします。
* RedHatユーザーは、インストールされたパッケージをリストアップするために`rpm -qa --root=/mntpath/var/lib/rpm`でRPMデータベースをクエリできます。

これらのパッケージマネージャーの外で手動でインストールされたソフトウェアを見つけるには、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_などのディレクトリを調査します。ディレクトリリストをシステム固有のコマンドと組み合わせて使用して、既知のパッケージに関連付けられていない実行可能ファイルを特定し、すべてのインストールされたプログラムを検索を強化します。
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 削除された実行中のバイナリの回復

/tmp/execから実行され、削除されたプロセスを想像してください。それを抽出することが可能です
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## オートスタートの場所を調査する

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

マルウェアがインストールされる可能性のあるサービスのパス：

- **/etc/inittab**: rc.sysinitなどの初期化スクリプトを呼び出し、さらに起動スクリプトに誘導します。
- **/etc/rc.d/** および **/etc/rc.boot/**: サービスの起動スクリプトが含まれており、後者は古いLinuxバージョンに見られます。
- **/etc/init.d/**: Debianなどの特定のLinuxバージョンで起動スクリプトを保存するために使用されます。
- サービスは、Linuxのバリアントに応じて **/etc/inetd.conf** または **/etc/xinetd/** を介してもアクティブ化される可能性があります。
- **/etc/systemd/system**: システムおよびサービスマネージャースクリプト用のディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**: マルチユーザーのランレベルで起動する必要があるサービスへのリンクが含まれています。
- **/usr/local/etc/rc.d/**: カスタムまたはサードパーティのサービス用。
- **\~/.config/autostart/**: ユーザー固有の自動起動アプリケーション用であり、ユーザーを標的としたマルウェアの隠れた場所となる可能性があります。
- **/lib/systemd/system/**: インストールされたパッケージによって提供されるシステム全体のデフォルトユニットファイル。

### カーネルモジュール

マルウェアによってルートキットコンポーネントとして頻繁に使用されるLinuxカーネルモジュールは、システム起動時にロードされます。これらのモジュールにとって重要なディレクトリとファイルは次のとおりです：

- **/lib/modules/$(uname -r)**: 実行中のカーネルバージョン用のモジュールを保持します。
- **/etc/modprobe.d**: モジュールのロードを制御する構成ファイルが含まれています。
- **/etc/modprobe** および **/etc/modprobe.conf**: グローバルモジュール設定用のファイル。

### その他の自動起動場所

Linuxは、ユーザーログイン時に自動的にプログラムを実行するためにさまざまなファイルを使用し、潜在的にマルウェアを隠す可能性があります：

- **/etc/profile.d/**\*、**/etc/profile**、および **/etc/bash.bashrc**: すべてのユーザーログイン時に実行されます。
- **\~/.bashrc**、**\~/.bash\_profile**、**\~/.profile**、および **\~/.config/autostart**: ユーザー固有のファイルで、それぞれのユーザーログイン時に実行されます。
- **/etc/rc.local**: すべてのシステムサービスが起動した後に実行され、マルチユーザー環境への移行の終了を示します。

## ログの調査

Linuxシステムは、さまざまなログファイルを介してユーザーのアクティビティやシステムイベントを追跡します。これらのログは、不正アクセス、マルウェア感染、およびその他のセキュリティインシデントを特定するために重要です。主要なログファイルには次のものがあります：

- **/var/log/syslog** (Debian) または **/var/log/messages** (RedHat): システム全体のメッセージとアクティビティをキャプチャします。
- **/var/log/auth.log** (Debian) または **/var/log/secure** (RedHat): 認証試行、成功および失敗したログインを記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して関連する認証イベントをフィルタリングします。
- **/var/log/boot.log**: システムの起動メッセージが含まれています。
- **/var/log/maillog** または **/var/log/mail.log**: メールサーバーのアクティビティを記録し、メール関連サービスの追跡に役立ちます。
- **/var/log/kern.log**: エラーや警告を含むカーネルメッセージを保存します。
- **/var/log/dmesg**: デバイスドライバーメッセージを保持します。
- **/var/log/faillog**: 失敗したログイン試行を記録し、セキュリティ侵害の調査を支援します。
- **/var/log/cron**: cronジョブの実行を記録します。
- **/var/log/daemon.log**: バックグラウンドサービスのアクティビティを追跡します。
- **/var/log/btmp**: 失敗したログイン試行を文書化します。
- **/var/log/httpd/**: Apache HTTPDのエラーおよびアクセスログが含まれています。
- **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQLデータベースのアクティビティを記録します。
- **/var/log/xferlog**: FTPファイル転送を記録します。
- **/var/log/**: ここで予期しないログを常にチェックしてください。

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵入やマルウェアのインシデントで無効化または削除される可能性があります。Linuxシステムのログは一般的に悪意のある活動に関する最も有用な情報のいくつかを含んでいるため、侵入者はそれらを定期的に削除します。したがって、利用可能なログファイルを調査する際には、削除や改ざんの兆候となるギャップや順序外のエントリを探すことが重要です。
{% endhint %}

**Linuxは各ユーザーのコマンド履歴を維持**しており、以下に保存されています：

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

さらに、`last -Faiwx` コマンドはユーザーログインのリストを提供します。未知または予期しないログインがあるかどうかを確認してください。

追加の特権を付与できるファイルをチェックしてください：

- 予期しないユーザー特権を確認するために `/etc/sudoers` を確認してください。
- 予期しないユーザー特権を確認するために `/etc/sudoers.d/` を確認してください。
- 異常なグループメンバーシップや権限を特定するために `/etc/groups` を調べてください。
- 異常なグループメンバーシップや権限を特定するために `/etc/passwd` を調べてください。

一部のアプリケーションは独自のログを生成することもあります：

- **SSH**: _\~/.ssh/authorized\_keys_ および _\~/.ssh/known\_hosts_ を調査して、不正なリモート接続を見つけます。
- **Gnomeデスクトップ**: Gnomeアプリケーションを介して最近アクセスされたファイルを示す _\~/.recently-used.xbel_ を調べます。
- **Firefox/Chrome**: _\~/.mozilla/firefox_ または _\~/.config/google-chrome_ でブラウザの履歴とダウンロードをチェックして、不審な活動を見つけます。
- **VIM**: アクセスされたファイルパスや検索履歴などの使用詳細を示す _\~/.viminfo_ を確認します。
- **Open Office**: 侵害されたファイルを示す可能性のある最近のドキュメントアクセスをチェックしてください。
- **FTP/SFTP**: 許可されていないファイル転送を示す _\~/.ftp\_history_ または _\~/.sftp\_history_ のログを確認してください。
- **MySQL**: 実行されたMySQLクエリを示す _\~/.mysql\_history_ を調査して、許可されていないデータベースアクティビティを明らかにします。
- **Less**: 閲覧されたファイルや実行されたコマンドなどの使用履歴を分析する _\~/.lesshst_ を確認してください。
- **Git**: リポジトリへの変更を示す _\~/.gitconfig_ およびプロジェクト _.git/logs_ を調べてください。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip) は、USBイベント履歴テーブルを構築するためにLinuxログファイル (`/var/log/syslog*` または `/var/log/messages*`、ディストリビューションによって異なります) を解析する純粋なPython 3で書かれた小さなソフトウェアです。

**使用されたすべてのUSBデバイスを把握することは興味深い**ですし、USBの許可リストを持っていると、そのリストに含まれていないUSBの使用を見つけるのに役立ちます。 

### インストール
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
更多示例和信息请查看github：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
使用[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)可以轻松构建和**自动化工作流程**，利用世界上**最先进**的社区工具。\
立即获取访问权限：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 检查用户帐户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和**安全日志**，查找是否有异常名称或在已知未经授权事件附近创建或使用的帐户。还要检查可能的sudo暴力攻击。\
此外，检查像 _**/etc/sudoers**_ 和 _**/etc/groups**_ 这样的文件，查看是否给用户授予了意外的特权。\
最后，查找没有密码或**易于猜测**密码的帐户。

## 检查文件系统

### 在恶意软件调查中分析文件系统结构

在调查恶意软件事件时，文件系统的结构是信息的重要来源，可以揭示事件序列和恶意软件的内容。然而，恶意软件作者正在开发技术来阻碍这种分析，例如修改文件时间戳或避免使用文件系统进行数据存储。

为了对抗这些反取证方法，重要的是：

* 使用像**Autopsy**这样的工具进行**彻底的时间线分析**，用于可视化事件时间线，或者使用**Sleuth Kit**的`mactime`获取详细的时间线数据。
* **调查系统的$PATH中的意外脚本**，这些脚本可能包括攻击者使用的shell或PHP脚本。
* **检查`/dev`中的非典型文件**，因为它传统上包含特殊文件，但可能包含与恶意软件相关的文件。
* **搜索隐藏文件或目录**，名称类似于".. "（点 点 空格）或"..^G"（点 点 控制-G），这可能隐藏恶意内容。
* 使用命令：`find / -user root -perm -04000 -print`来**识别setuid root文件**。这会找到具有提升权限的文件，可能会被攻击者滥用。
* **检查inode表中的删除时间戳**，以发现大量文件删除，可能表明存在rootkit或特洛伊木马。
* **检查相邻的inode**，查找一个后面的恶意文件，因为它们可能被放在一起。
* **检查常见的二进制目录**（_/bin_、_/sbin_）中最近修改的文件，因为这些文件可能被恶意软件修改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
**攻撃者** は **時間を変更** して **ファイルを正規** に見せかけることができますが、**inode** を変更することはできません。同じフォルダ内の他のファイルと同じ **時間に作成および変更** されたことを示す **ファイル** を見つけた場合、しかし **inode** が **予期しないほど大きい** 場合、その **ファイルのタイムスタンプが変更された** ことになります。
{% endhint %}

## 異なるファイルシステムバージョンのファイルを比較

### ファイルシステムバージョン比較の要約

ファイルシステムバージョンを比較し変更点を特定するために、簡略化された `git diff` コマンドを使用します：

* **新しいファイルを見つける** には、2つのディレクトリを比較します：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
* **変更されたコンテンツ**については、特定の行を無視して変更点をリストアップします。
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
* **削除されたファイルを検出するために**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
* **フィルターオプション** (`--diff-filter`) は、追加された (`A`)、削除された (`D`)、または変更された (`M`) ファイルなど、特定の変更を絞り込むのに役立ちます。
* `A`: 追加されたファイル
* `C`: コピーされたファイル
* `D`: 削除されたファイル
* `M`: 変更されたファイル
* `R`: 名前が変更されたファイル
* `T`: タイプの変更（例：ファイルからシンボリックリンクへ）
* `U`: マージされていないファイル
* `X`: 不明なファイル
* `B`: 破損したファイル

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **書籍: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>!</strong></summary>

**サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセス**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[NFTs](https://opensea.io/collection/the-peass-family)のコレクションを入手します
* [**公式PEASS＆HackTricksスウェグ**](https://peass.creator-spring.com)を手に入れます
* **💬** [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私をフォローしてください 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**

**ハッキングトリックを共有するには、** [**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で最も高度なコミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
