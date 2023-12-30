# Linuxフォレンジック

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も進んだ**コミュニティツールを駆使した**ワークフローの自動化**を簡単に構築できます。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローに学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**PEASSファミリー**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>

## 初期情報収集

### 基本情報

まず、**USB**に**良く知られたバイナリとライブラリ**を持っていることが推奨されます（ubuntuを取得して、_/bin_、_/sbin_、_/lib_、_/lib64_のフォルダをコピーするだけです）。次に、USBをマウントし、環境変数を変更してこれらのバイナリを使用するようにします：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムを良好で既知のバイナリを使用するように設定したら、**基本情報の抽出**を開始できます：
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

基本情報を取得する際には、以下のような奇妙な点に注意してください：

* **Rootプロセス**は通常、低いPIDで実行されますので、大きなPIDを持つrootプロセスがあれば疑うべきです
* `/etc/passwd`内でシェルを持たないユーザーの**登録ログイン**をチェックする
* シェルを持たないユーザーのための`/etc/shadow`内の**パスワードハッシュ**をチェックする

### メモリダンプ

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME)の使用を推奨します。\
**コンパイル**するには、被害者マシンが使用している**同じカーネル**を使用する必要があります。

{% hint style="info" %}
被害者マシンにLiMEやその他のものを**インストールしてはいけない**ことを覚えておいてください。それにより、様々な変更が加えられるためです。
{% endhint %}

もし、同じバージョンのUbuntuを持っている場合は、`apt-get install lime-forensics-dkms`を使用できます。\
他の場合は、githubから[**LiME**](https://github.com/504ensicsLabs/LiME)をダウンロードし、正しいカーネルヘッダーでコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー**を取得するには、単にディレクトリ`/lib/modules/<kernel version>`をあなたのマシンに**コピーし**、それを使用してLiMEを**コンパイル**します：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

* Raw（すべてのセグメントが連結されている）
* Padded（rawと同じですが、右側のビットにゼロが入っている）
* Lime（メタデータを含む推奨フォーマット）

LiMEは、`path=tcp:4444`のようなものを使用して、システムに保存する代わりに**ネットワーク経由でダンプを送信する**ためにも使用できます。

### ディスクイメージング

#### シャットダウン

まず、システムを**シャットダウンする**必要があります。これは常にオプションではありません。時にはシステムが会社がシャットダウンできないプロダクションサーバーであることがあります。\
システムをシャットダウンするには**2つの方法**があります。**通常のシャットダウン**と**「プラグを抜く」シャットダウン**です。最初の方法では、**プロセスが通常どおり終了し**、**ファイルシステム**が**同期されます**が、可能性のある**マルウェア**が**証拠を破壊する**ことも許されます。"プラグを抜く"アプローチは**いくつかの情報損失**を伴うかもしれません（メモリのイメージを既に取得しているので、失われる情報は多くありません）が、**マルウェアは何もする機会がありません**。したがって、**マルウェアがあると疑う**場合は、システムで**`sync`** **コマンド**を実行してプラグを抜いてください。

#### ディスクのイメージを取る

ケースに関連するものにコンピュータを接続する**前に**、情報を変更しないように**読み取り専用としてマウントされる**ことを確認する必要があることに注意が必要です。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

これ以上データのないディスクイメージをイメージングします。
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
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も高度な**コミュニティツールを駆使した**ワークフローの自動化**を簡単に構築できます。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 既知のマルウェアを検索

### 変更されたシステムファイル

一部のLinuxシステムには、多くのインストールされたコンポーネントの**整合性を検証する**機能があり、通常とは異なる、または場違いなファイルを特定する効果的な方法を提供します。例えば、Linuxの`rpm -Va`は、RedHat Package Managerを使用してインストールされたすべてのパッケージを検証するように設計されています。
```bash
#RedHat
rpm -Va
#Debian
dpkg --verify
debsums | grep -v "OK$" #apt-get install debsums
```
### マルウェア/ルートキット検出器

以下のページを読んで、マルウェアを見つけるのに役立つツールについて学びましょう：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## インストールされたプログラムの検索

### パッケージマネージャー

Debian系システムでは、_**/var/lib/dpkg/status**_ ファイルにインストールされたパッケージの詳細が含まれており、_**/var/log/dpkg.log**_ ファイルにはパッケージがインストールされたときの情報が記録されています。\
RedHatおよび関連するLinuxディストリビューションでは、**`rpm -qa --root=/mntpath/var/lib/rpm`** コマンドを使用して、システム上のRPMデータベースの内容をリストします。
```bash
#Debian
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
#RedHat
rpm -qa --root=/ mntpath/var/lib/rpm
```
### その他

**上記のコマンドでリストされないインストール済みプログラムもあります**。なぜなら、一部のアプリケーションは特定のシステムのパッケージとして利用できず、ソースからインストールする必要があるからです。したがって、_**/usr/local**_ や _**/opt**_ などの場所を調査することで、ソースコードからコンパイルしてインストールされた他のアプリケーションが見つかるかもしれません。
```bash
ls /opt /usr/local
```
別の良いアイデアは、**$PATH** 内の**共通フォルダー**を**インストールされたパッケージに関連しないバイナリ**について**確認する**ことです：
```bash
#Both lines are going to print the executables in /sbin non related to installed packages
#Debian
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
#RedHat
find /sbin/ –exec rpm -qf {} \; | grep "is not"
```
```markdown
<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も高度な**コミュニティツールを搭載した**ワークフローを簡単に構築し、自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 削除された実行中のバイナリを復元する

![](<../../.gitbook/assets/image (641).png>)

## 自動起動位置を検査する

### スケジュールされたタスク
```
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

マルウェアが新しい、不正なサービスとして定着することは非常に一般的です。Linuxには、コンピュータが起動する際にサービスを開始するために使用される多数のスクリプトがあります。初期化スタートアップスクリプト _**/etc/inittab**_ は、rc.sysinitや _**/etc/rc.d/**_ ディレクトリ内の様々なスタートアップスクリプト、または一部の古いバージョンでは _**/etc/rc.boot/**_ を呼び出します。Debianなどの他のLinuxバージョンでは、スタートアップスクリプトが _**/etc/init.d/**_ ディレクトリに格納されています。さらに、一部の一般的なサービスは、Linuxのバージョンに応じて _**/etc/inetd.conf**_ または _**/etc/xinetd/**_ で有効にされています。デジタル捜査官は、これらのスタートアップスクリプトを異常なエントリがないか調査する必要があります。

* _**/etc/inittab**_
* _**/etc/rc.d/**_
* _**/etc/rc.boot/**_
* _**/etc/init.d/**_
* _**/etc/inetd.conf**_
* _**/etc/xinetd/**_
* _**/etc/systemd/system**_
* _**/etc/systemd/system/multi-user.target.wants/**_

### カーネルモジュール

Linuxシステムでは、カーネルモジュールが一般的にマルウェアパッケージのルートキットコンポーネントとして使用されます。カーネルモジュールは、システムが起動する際に `/lib/modules/'uname -r'` と `/etc/modprobe.d` ディレクトリ、および `/etc/modprobe` または `/etc/modprobe.conf` ファイルの設定情報に基づいてロードされます。これらのエリアは、マルウェアに関連する項目がないか調査する必要があります。

### その他の自動起動場所

Linuxは、ユーザーがシステムにログインすると自動的に実行可能ファイルを起動するためにいくつかの設定ファイルを使用し、これらにはマルウェアの痕跡が含まれている可能性があります。

* _**/etc/profile.d/\***_ , _**/etc/profile**_ , _**/etc/bash.bashrc**_ は、任意のユーザーアカウントがログインする際に実行されます。
* _**∼/.bashrc**_ , _**∼/.bash\_profile**_ , _**\~/.profile**_ , _**∼/.config/autostart**_ は、特定のユーザーがログインする際に実行されます。
* _**/etc/rc.local**_ は、通常のシステムサービスがすべて開始された後、マルチユーザーレベルへの切り替えプロセスの最後に実行されます。

## ログの調査

侵害されたシステム上のすべての利用可能なログファイルを調べ、新しいサービスの作成など、悪意のある実行と関連する活動の痕跡を探します。

### 純粋なログ

システムとセキュリティログに記録された**ログイン**イベントには、ネットワーク経由のログインを含む、特定のアカウントを介して特定の時間に**マルウェア**または**侵入者がアクセスを得た**ことが明らかになる可能性があります。マルウェア感染の時刻の周辺で発生した他のイベントも、システムログに記録されることがあり、事件の時刻の周辺で**新しい** **サービス**や新しいアカウントの**作成**が含まれる可能性があります。\
興味深いシステムログイン:

* **/var/log/syslog** (debian) または **/var/log/messages** (Redhat)
* システムに関する一般的なメッセージと情報を示します。これは、グローバルシステム全体のすべての活動のデータログです。
* **/var/log/auth.log** (debian) または **/var/log/secure** (Redhat)
* 成功したログインと失敗したログイン、および認証プロセスの認証ログを保持します。保存はシステムタイプに依存します。
* `cat /var/log/auth.log | grep -iE "session opened for|accepted password|new session|not in sudoers"`
* **/var/log/boot.log**: 起動メッセージとブート情報。
* **/var/log/maillog** または **var/log/mail.log:** メールサーバーログで、サーバー上で実行されているpostfix、smtpd、またはメール関連サービスの情報に便利です。
* **/var/log/kern.log**: カーネルログと警告情報を保持します。カーネル活動ログ（例：dmesg、kern.log、klog）は、特定のサービスが繰り返しクラッシュしたことを示すことがあり、不安定なトロイの木馬版がインストールされた可能性を示唆しています。
* **/var/log/dmesg**: デバイスドライバーメッセージのリポジトリです。このファイルのメッセージを表示するには**dmesg**を使用します。
* **/var/log/faillog:** 失敗したログインの情報を記録します。したがって、ログイン資格情報のハックやブルートフォース攻撃など、潜在的なセキュリティ侵害を調査するのに便利です。
* **/var/log/cron**: Crond関連メッセージ（cronジョブ）の記録を保持します。cronデーモンがジョブを開始したときなどです。
* **/var/log/daemon.log:** バックグラウンドで実行されているサービスを追跡しますが、グラフィカルには表現しません。
* **/var/log/btmp**: すべての失敗したログイン試行をメモします。
* **/var/log/httpd/**: Apache httpdデーモンのerror\_logファイルとaccess\_logファイルが含まれているディレクトリです。httpdが遭遇するすべてのエラーは**error\_log**ファイルに保持されます。メモリ問題やその他のシステム関連のエラーを考えてください。**access\_log**はHTTP経由で入ってくるすべてのリクエストをログします。
* **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQLデーモンmysqldの開始、停止、再起動を含む、すべてのデバッグ、失敗、成功メッセージを記録するMySQLログファイルです。システムがディレクトリを決定します。RedHat、CentOS、Fedora、およびその他のRedHatベースのシステムは/var/log/mariadb/mariadb.logを使用します。しかし、Debian/Ubuntuは/var/log/mysql/error.logディレクトリを使用します。
* **/var/log/xferlog**: FTPファイル転送セッションを保持します。ファイル名やユーザーが開始したFTP転送などの情報が含まれます。
* **/var/log/\*** : このディレクトリに予期しないログがないか常にチェックするべきです

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵入またはマルウェアのインシデントで無効化または削除される可能性があります。Linuxシステムのログには一般的に悪意のある活動に関する最も有用な情報が含まれているため、侵入者はこれらを定期的に削除します。そのため、利用可能なログファイルを調査する際には、削除または改ざんの兆候となるギャップや順序がおかしいエントリを探すことが重要です。
{% endhint %}

### コマンド履歴

多くのLinuxシステムは、各ユーザーアカウントのコマンド履歴を維持するように設定されています：

* \~/.bash\_history
* \~/.history
* \~/.sh\_history
* \~/.\*\_history

### ログイン

`last -Faiwx` コマンドを使用すると、ログインしたユーザーのリストを取得できます。\
これらのログインが理にかなっているかどうかを確認することをお勧めします：

* 未知のユーザーはいますか？
* シェルにログインするべきでないユーザーはいますか？

これは重要です。**攻撃者**は時々 `/bin/bash` を `/bin/false` の中にコピーするため、**lightdm** のようなユーザーが**ログインできる**ようになることがあります。

この情報はログを読むことで確認することもできます。

### アプリケーションの痕跡

* **SSH**: SSHを使用して侵害されたシステムへの接続、およびそのシステムからの接続は、各ユーザーアカウントのファイルにエントリが作成されます（_**∼/.ssh/authorized\_keys**_ および _**∼/.ssh/known\_keys**_）。これらのエントリは、リモートホストのホスト名またはIPアドレスを明らかにすることができます。
* **Gnomeデスクトップ**: ユーザーアカウントには、Gnomeデスクトップで実行されているアプリケーションを使用して最近アクセスされたファイルに関する情報が含まれている _**∼/.recently-used.xbel**_ ファイルがある場合があります。
* **VIM**: ユーザーアカウントには、VIMの使用に関する詳細、検索文字列の履歴、およびvimを使用して開かれたファイルへのパスが含まれている _**∼/.viminfo**_ ファイルがある場合があります。
* **Open Office**: 最近のファイル。
* **MySQL**: ユーザーアカウントには、MySQLを使用して実行されたクエリが含まれている _**∼/.mysql\_history**_ ファイルがある場合があります。
* **Less**: ユーザーアカウントには、lessの使用に関する詳細、検索文字列の履歴、およびlessを介して実行されたシェルコマンドが含まれている _**∼/.lesshst**_ ファイルがある場合があります。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip) は、純粋なPython 3で書かれた小さなソフトウェアで、Linuxログファイル（`/var/log/syslog*` または `/var/log/messages*`、ディストリビューションによって異なります）を解析してUSBイベント履歴テーブルを構築します。

使用されたすべてのUSBを**知る**ことは興味深いことであり、承認されたUSBのリストがある場合には、そのリストに含まれていないUSBの使用（「違反イベント」）を見つけるのにさらに役立ちます。

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
以下は、GitHubにあるさらなる例と情報です：[https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で**最も進んだ**コミュニティツールによって動力を供給される**ワークフローを簡単に構築し自動化**します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## ユーザーアカウントとログオン活動のレビュー

_**/etc/passwd**_、_**/etc/shadow**_ および **セキュリティログ**を調査して、不審な名前やアカウントが作成されたり、不正アクセスが知られている時期に使用されたりしていないか確認します。また、sudoのブルートフォース攻撃の可能性もチェックします。\
さらに、_**/etc/sudoers**_ や _**/etc/groups**_ のようなファイルをチェックして、ユーザーに予期せぬ権限が与えられていないか確認します。\
最後に、**パスワードがない**アカウントや**簡単に推測できる**パスワードのアカウントを探します。

## ファイルシステムの調査

ファイルシステムのデータ構造は、イベントの**タイミング**や**マルウェア**の実際の**内容**に関連する大量の**情報**を提供することができます。\
**マルウェア**はファイルシステム分析を**妨害する**ようにますます設計されています。一部のマルウェアは、タイムライン分析で悪意のあるファイルを見つけにくくするために、ファイルの日付・時刻スタンプを変更します。他の悪意のあるコードは、ファイルシステムに保存されるデータ量を最小限に抑えるために、特定の情報をメモリにのみ保存するように設計されています。\
このようなアンチフォレンジック技術に対処するためには、ファイルシステムの日付・時刻スタンプのタイムライン分析に**注意深く注意を払い**、マルウェアが見つかる可能性のある一般的な場所に保存されているファイルを検査することが必要です。

* **autopsy** を使用すると、不審な活動を発見するのに役立つイベントのタイムラインを確認できます。また、**Sleuth Kit** の `mactime` 機能を直接使用することもできます。
* **$PATH** 内の**予期しないスクリプト**（shやphpスクリプトなど）をチェックします。
* `/dev` 内のファイルは特殊ファイルであることが多いですが、マルウェアに関連する非特殊ファイルを見つけることがあります。
* “.. ”（ドット ドット スペース）や “..^G ”（ドット ドット コントロール-G）など、通常ではないまたは**隠されたファイル**や**ディレクトリ**を探します。
* システム上の /bin/bash の Setuid コピーを探します `find / -user root -perm -04000 –print`
* 削除された**inodeの日付・時刻スタンプをレビュー**し、同時に多数のファイルが削除されている場合は、ルートキットやトロイの木馬化されたサービスのインストールなど、悪意のある活動を示す可能性があります。
* inodeは利用可能な次のベースで割り当てられるため、**ほぼ同時にシステムに配置された悪意のあるファイルは、連続するinodeが割り当てられる可能性があります**。したがって、マルウェアの一部が見つかった後、隣接するinodeを検査することは有益です。
* _/bin_ や _/sbin_ のようなディレクトリもチェックし、新しく変更されたファイルの**変更された時間**が興味深いかもしれません。
* アルファベット順ではなく、作成日によってファイルやフォルダを並べ替えて、どのファイルやフォルダが最近のものか（通常は最後のもの）を確認するのが興味深いです。

フォルダの最新のファイルを確認するには `ls -laR --sort=time /bin` を使用します。\
フォルダ内のファイルのinodeを確認するには `ls -lai /bin |sort -n` を使用します。

{% hint style="info" %}
**攻撃者**は**ファイル**が正当であるように見せるために**時間**を**変更**することができますが、**inode**を変更することはできません。同じフォルダ内の他のファイルと**同時**に作成され変更されたと**ファイル**が示しているが、**inode**が**予想外に大きい**場合、その**ファイルのタイムスタンプが変更された**ということです。
{% endhint %}

## 異なるファイルシステムバージョンのファイルを比較する

#### 追加されたファイルを見つける
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### 変更された内容を見つける
```bash
git diff --no-index --diff-filter=M _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/ | grep -E "^\+" | grep -v "Installed-Time"
```
#### 削除されたファイルを探す
```bash
git diff --no-index --diff-filter=A _openwrt1.extracted/squashfs-root/ _openwrt2.extracted/squashfs-root/
```
#### その他のフィルタ

**`-diff-filter=[(A|C|D|M|R|T|U|X|B)…​[*]]`**

追加されたファイル(`A`)、コピーされたファイル(`C`)、削除されたファイル(`D`)、変更されたファイル(`M`)、名前が変更されたファイル(`R`)、タイプが変更されたファイル（通常のファイル、シンボリックリンク、サブモジュールなど）(`T`)、マージされていないファイル(`U`)、不明なファイル(`X`)、またはペアリングが壊れたファイル(`B`)のみを選択します。フィルタ文字の任意の組み合わせ（なしを含む）が使用できます。組み合わせに`*`（すべてまたはなし）が追加されると、比較で他の基準に一致するファイルがある場合はすべてのパスが選択されます。他の基準に一致するファイルがない場合は、何も選択されません。

また、**これらの大文字を小文字にすることで除外することができます**。例えば、`--diff-filter=ad`は追加されたパスと削除されたパスを除外します。

すべてのdiffがすべてのタイプを特徴とするわけではないことに注意してください。例えば、インデックスから作業ツリーへのdiffは、diffに含まれるパスのセットがインデックスによって制限されているため、追加されたエントリを持つことは決してありません。同様に、コピーされたエントリや名前が変更されたエントリは、それらのタイプの検出が無効にされている場合には表示されません。

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

**サイバーセキュリティ会社**で働いていますか？**HackTricksで会社の広告を掲載**したいですか？または、**最新版のPEASSを入手**したり、**HackTricksをPDFでダウンロード**したいですか？[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを手に入れましょう。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手しましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加するか**、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。

**hacktricksリポジトリ**と**hacktricks-cloudリポジトリ**にPRを提出して、あなたのハッキングのコツを共有しましょう。

</details>

<figure><img src="../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用して、世界で**最も先進的な**コミュニティツールを搭載したワークフローを簡単に**自動化**しましょう。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
