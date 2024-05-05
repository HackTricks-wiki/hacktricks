# Linuxフォレンジクス

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度なコミュニティツール**によって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>**htARTE（HackTricks AWS Red Team Expert）**で**ゼロからヒーローまでのAWSハッキング**を学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手してください
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つけます
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、**あなたのハッキングトリックを共有**してください。

</details>

## 初期情報収集

### 基本情報

まず最初に、**USB**に**良く知られたバイナリとライブラリ**が含まれていることが推奨されます（単にUbuntuを取得して、_ /bin_、_ /sbin_、_ /lib_、および _/lib64_のフォルダをコピーできます）。その後、USBをマウントし、環境変数を変更してこれらのバイナリを使用します：
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

- **Rootプロセス** は通常、低いPIDで実行されます。そのため、大きなPIDで実行されているRootプロセスが見つかった場合は疑うべきです
- `/etc/passwd` 内にシェルを持たないユーザーの**登録済みログイン** を確認する
- `/etc/shadow` 内にシェルを持たないユーザーの**パスワードハッシュ** を確認する

### メモリーダンプ

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) を使用することをお勧めします。\
**コンパイル** するには、被害者マシンが使用している**同じカーネル** を使用する必要があります。

{% hint style="info" %}
被害者マシンに **LiME やその他の何かをインストールすることはできない** ため、それに多くの変更を加えてしまいます
{% endhint %}

したがって、Ubuntuの同一バージョンがある場合は、`apt-get install lime-forensics-dkms` を使用できます\
それ以外の場合は、[**LiME**](https://github.com/504ensicsLabs/LiME) をgithubからダウンロードし、正しいカーネルヘッダーを使用してコンパイルする必要があります。被害者マシンの**正確なカーネルヘッダー** を取得するには、単にディレクトリ `/lib/modules/<kernel version>` をあなたのマシンにコピーし、それを使用して LiME を**コンパイル** します:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

* Raw（すべてのセグメントが連結されたもの）
* Padded（Rawと同じですが、右ビットにゼロが入っています）
* Lime（メタデータ付きの推奨フォーマット）

LiMEはまた、`path=tcp:4444`のような方法を使用して、**ダンプをネットワーク経由で送信**するためにも使用できます。

### ディスクイメージング

#### シャットダウン

まず第一に、**システムをシャットダウンする必要があります**。これは常に選択肢というわけではありません。ときには、システムが企業がシャットダウンする余裕のない本番サーバーであることがあります。\
システムをシャットダウンする方法には、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の2つがあります。最初の方法は、**プロセスが通常通り終了**し、**ファイルシステム**が**同期**されることを可能にしますが、**悪意のあるソフトウェア**が**証拠を破壊**する可能性もあります。"プラグを抜く"アプローチは、**いくらかの情報損失**を伴うかもしれません（メモリのイメージをすでに取っているので、失われる情報はほとんどありません）が、**マルウェアはそれについて何もできません**。したがって、**マルウェア**がある可能性がある場合は、システムで**`sync`** **コマンド**を実行してプラグを抜いてください。

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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 既知のマルウェアを検索

### 変更されたシステムファイル

Linuxには、潜在的に問題のあるファイルを見つけるために重要なシステムコンポーネントの整合性を確認するためのツールが用意されています。

* **RedHatベースのシステム**: 総合的なチェックには `rpm -Va` を使用します。
* **Debianベースのシステム**: 初期検証には `dpkg --verify` を使用し、その後 `debsums | grep -v "OK$"`（`apt-get install debsums` を使用して `debsums` をインストールした後）を使用して問題を特定します。

### マルウェア/ルートキット検出ツール

マルウェアを見つけるのに役立つツールについて学ぶには、以下のページを参照してください：

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## インストールされたプログラムを検索

DebianとRedHatの両方のシステムでインストールされたプログラムを効果的に検索するには、システムログやデータベースを活用し、一般的なディレクトリでの手動チェックを検討してください。

* Debianの場合、パッケージのインストールに関する詳細情報を取得するには、_**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を調査し、`grep` を使用して特定の情報をフィルタリングします。
* RedHatユーザーは、`rpm -qa --root=/mntpath/var/lib/rpm` を使用してRPMデータベースをクエリし、インストールされたパッケージをリストアップできます。

これらのパッケージマネージャーの外で手動でインストールされたソフトウェアや、それら以外のディレクトリ（_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_）を探索して、既知のパッケージに関連付けられていない実行可能ファイルを特定するために、ディレクトリリストとシステム固有のコマンドを組み合わせて、すべてのインストールされたプログラムを検索を強化してください。
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
<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks)を使用して、世界で最も**高度な**コミュニティツールによって強化された**ワークフローを簡単に構築**および**自動化**します。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 削除された実行中のバイナリの回復

/tmp/exec から実行され、その後削除されたプロセスを想像してください。それを抽出することが可能です
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart の場所を調査する

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

マルウェアがサービスとしてインストールされる可能性のあるパス：

- **/etc/inittab**：rc.sysinitなどの初期化スクリプトを呼び出し、さらに起動スクリプトに誘導します。
- **/etc/rc.d/** および **/etc/rc.boot/**：サービスの起動スクリプトが含まれており、後者は古いLinuxバージョンに見られます。
- **/etc/init.d/**：Debianなどの特定のLinuxバージョンで使用され、起動スクリプトを格納します。
- サービスは、Linuxのバリアントに応じて **/etc/inetd.conf** または **/etc/xinetd/** からも起動される可能性があります。
- **/etc/systemd/system**：システムおよびサービスマネージャースクリプト用のディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**：マルチユーザーランレベルで起動する必要があるサービスへのリンクが含まれています。
- **/usr/local/etc/rc.d/**：カスタムまたはサードパーティのサービス用。
- **\~/.config/autostart/**：ユーザー固有の自動起動アプリケーション用であり、ユーザーを標的としたマルウェアの隠れた場所となる可能性があります。
- **/lib/systemd/system/**：インストールされたパッケージによって提供されるシステム全体のデフォルトユニットファイル。

### カーネルモジュール

マルウェアによってルートキットコンポーネントとしてよく使用されるLinuxカーネルモジュールは、システム起動時にロードされます。これらのモジュールにとって重要なディレクトリとファイルは次のとおりです：

- **/lib/modules/$(uname -r)**：実行中のカーネルバージョン用のモジュールを保持します。
- **/etc/modprobe.d**：モジュールのロードを制御する構成ファイルが含まれています。
- **/etc/modprobe** および **/etc/modprobe.conf**：グローバルモジュール設定用のファイル。

### その他の自動起動場所

Linuxは、ユーザーログイン時にプログラムを自動的に実行するためにさまざまなファイルを使用し、潜在的にマルウェアを隠す可能性があります：

- **/etc/profile.d/**\*、**/etc/profile**、および **/etc/bash.bashrc**：すべてのユーザーログイン時に実行されます。
- **\~/.bashrc**、**\~/.bash\_profile**、**\~/.profile**、および **\~/.config/autostart**：ユーザー固有のファイルで、ユーザーのログイン時に実行されます。
- **/etc/rc.local**：すべてのシステムサービスが起動した後に実行され、マルチユーザー環境への移行の終了を示します。

## ログの調査

Linuxシステムは、さまざまなログファイルを介してユーザーのアクティビティやシステムイベントを追跡します。これらのログは、不正アクセス、マルウェア感染、およびその他のセキュリティインシデントを特定するために重要です。主要なログファイルには次のものがあります：

- **/var/log/syslog**（Debian）または **/var/log/messages**（RedHat）：システム全体のメッセージとアクティビティをキャプチャします。
- **/var/log/auth.log**（Debian）または **/var/log/secure**（RedHat）：認証試行、成功および失敗したログインを記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して関連する認証イベントをフィルタリングします。
- **/var/log/boot.log**：システムの起動メッセージが含まれています。
- **/var/log/maillog** または **/var/log/mail.log**：メールサーバーのアクティビティを記録し、メール関連サービスの追跡に役立ちます。
- **/var/log/kern.log**：エラーや警告を含むカーネルメッセージを保存します。
- **/var/log/dmesg**：デバイスドライバーメッセージを保持します。
- **/var/log/faillog**：失敗したログイン試行を記録し、セキュリティ侵害の調査に役立ちます。
- **/var/log/cron**：cronジョブの実行を記録します。
- **/var/log/daemon.log**：バックグラウンドサービスのアクティビティを追跡します。
- **/var/log/btmp**：失敗したログイン試行を文書化します。
- **/var/log/httpd/**：Apache HTTPDのエラーおよびアクセスログが含まれています。
- **/var/log/mysqld.log** または **/var/log/mysql.log**：MySQLデータベースのアクティビティを記録します。
- **/var/log/xferlog**：FTPファイル転送を記録します。
- **/var/log/**：予期しないログがないか常に確認してください。

{% hint style="info" %}
Linuxシステムのログと監査サブシステムは、侵害やマルウェアのインシデントで無効化または削除される可能性があります。Linuxシステムのログは一般的に悪意のある活動に関する最も有用な情報のいくつかを含んでいるため、侵入者はそれらを定期的に削除します。したがって、利用可能なログファイルを調査する際には、削除や改ざんの兆候となる欠落や順序の逆転を探すことが重要です。
{% endhint %}

**Linuxは各ユーザーのコマンド履歴を維持**しており、以下に保存されています：

- \~/.bash\_history
- \~/.zsh\_history
- \~/.zsh\_sessions/\*
- \~/.python\_history
- \~/.\*\_history

さらに、`last -Faiwx` コマンドはユーザーログインのリストを提供します。未知のまたは予期しないログインがあるかどうかを確認してください。

追加の特権を付与できるファイルを確認してください：

- 予期しないユーザー特権が付与されている可能性がある場合は、`/etc/sudoers` を確認してください。
- 予期しないユーザー特権が付与されている可能性がある場合は、`/etc/sudoers.d/` を確認してください。
- 異常なグループメンバーシップや権限を特定するには、`/etc/groups` を調べてください。
- 異常なグループメンバーシップや権限を特定するには、`/etc/passwd` を調べてください。

一部のアプリケーションは独自のログを生成する場合があります：

- **SSH**：_\~/.ssh/authorized\_keys_ および _\~/.ssh/known\_hosts_ を調べて、不正なリモート接続を確認してください。
- **Gnomeデスクトップ**：Gnomeアプリケーションを介して最近アクセスされたファイルを示す _\~/.recently-used.xbel_ を調べてください。
- **Firefox/Chrome**：怪しい活動を示すために _\~/.mozilla/firefox_ または _\~/.config/google-chrome_ でブラウザの履歴とダウンロードを確認してください。
- **VIM**：アクセスされたファイルパスや検索履歴などの使用詳細を示す _\~/.viminfo_ を確認してください。
- **Open Office**：侵害されたファイルを示す可能性のある最近のドキュメントアクセスを確認してください。
- **FTP/SFTP**：不正なファイル転送を示す _\~/.ftp\_history_ または _\~/.sftp\_history_ のログを調査してください。
- **MySQL**：実行されたMySQLクエリを示す _\~/.mysql\_history_ を調査して、不正なデータベースアクティビティを明らかにしてください。
- **Less**：表示されたファイルや実行されたコマンドなどの使用履歴を分析する _\~/.lesshst_ を確認してください。
- **Git**：リポジトリへの変更を示す _\~/.gitconfig_ およびプロジェクト _.git/logs_ を調べてください。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip) は、USBイベント履歴テーブルを構築するためにLinuxログファイル（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析する、Python 3で書かれた小さなソフトウェアです。

**使用されたすべてのUSBデバイスを把握すること** は興味深いことであり、許可されたUSBデバイスのリストを持っていると、そのリストに含まれていないUSBデバイスの使用を見つけるのに役立ちます。

### インストール
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 例えば
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
## ユーザーアカウントとログオンアクティビティのレビュー

不審な名前やアカウント、または既知の不正イベントに近接して作成または使用されたアカウントを確認するために、_**/etc/passwd**_、_**/etc/shadow**_、および**セキュリティログ**を調査します。また、可能なsudoブルートフォース攻撃をチェックします。\
さらに、ユーザーに与えられた予期しない特権を確認するために、_**/etc/sudoers**_や_**/etc/groups**_などのファイルをチェックします。\
最後に、**パスワードのないアカウント**や**簡単に推測できるパスワード**を持つアカウントを探します。

## ファイルシステムの調査

### マルウェア調査におけるファイルシステム構造の分析

マルウェアインシデントを調査する際、ファイルシステムの構造は情報の重要な源であり、イベントの順序とマルウェアの内容を明らかにします。ただし、マルウェアの作者は、ファイルのタイムスタンプを変更したり、データ保存のためにファイルシステムを回避したりするなど、この分析を妨げる技術を開発しています。

これらのアンチフォレンジック手法に対抗するためには、次のことが重要です：

* **Autopsy**などのツールを使用して**詳細なタイムラインデータ**を取得するために**Sleuth Kit**の`mactime`を使用して**徹底的なタイムライン分析**を実施します。
* 攻撃者が使用するシェルやPHPスクリプトを含む、システムの$PATHに**予期しないスクリプト**を調査します。
* 通常は特殊ファイルを含むはずの**/dev**を**非典型的なファイル**を探しますが、マルウェア関連のファイルが格納されている可能性があります。
* ".. "（ドットドットスペース）や"..^G"（ドットドットコントロール-G）などの名前の**隠しファイルやディレクトリ**を検索します。これには悪意のあるコンテンツが隠されている可能性があります。
* `find / -user root -perm -04000 -print`コマンドを使用して、**setuid rootファイル**を特定します。これにより、攻撃者に悪用される可能性のある権限の昇格ファイルが見つかります。
* inodeテーブル内の**削除タイムスタンプ**を確認して、ルートキットやトロイの存在を示す可能性のある大量のファイル削除を検出します。
* 1つを特定した後、隣接する悪意のあるファイルを見つけるために**連続したinode**を調査します。
* 最近変更されたファイルを含む**一般的なバイナリディレクトリ**（_/bin_、_/sbin_）をチェックします。これらはマルウェアによって変更されている可能性があります。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
{% hint style="info" %}
**攻撃者**が**ファイルを見せかける**ために**時間を変更**できることに注意してくださいが、**inode**を変更することはできません。同じフォルダ内の他のファイルと同じ時間に作成および変更されたと示す**ファイル**が見つかった場合、**inode**が予期せず大きい場合、その**ファイルのタイムスタンプが変更された**ことになります。
{% endhint %}

## 異なるファイルシステムバージョンのファイルを比較する

### ファイルシステムバージョン比較の要約

変更点を特定するためにファイルシステムバージョンを比較するには、簡略化された`git diff`コマンドを使用します：

* **新しいファイルを見つける**には、2つのディレクトリを比較します：
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
* `T`: タイプの変更 (例: ファイルからシンボリックリンクへ)
* `U`: マージされていないファイル
* `X`: 不明なファイル
* `B`: 破損したファイル

## 参考文献

* [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems\_Ch3.pdf)
* [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
* [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
* **書籍: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

**サイバーセキュリティ企業**で働いていますか？ **HackTricks で企業を宣伝**してみたいですか？または、**PEASS の最新バージョンにアクセス**したいですか、または HackTricks を **PDF でダウンロード**したいですか？ [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！

* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを入手
* [**公式 PEASS & HackTricks スワッグ**](https://peass.creator-spring.com) を手に入れる
* **💬** [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks\_live)** をフォロー**してください。

**ハッキングトリックを共有するには、** [**hacktricks リポジトリ**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud リポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に PR を提出してください。**

</details>

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) を使用して、世界で最も高度なコミュニティツールによって強化された **ワークフローを簡単に構築**および **自動化** できます。\
今すぐアクセスしてください：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}
