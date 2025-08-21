# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 初期情報収集

### 基本情報

まず最初に、**良く知られたバイナリとライブラリが入った** **USB** を用意することをお勧めします（ubuntuを取得し、フォルダ _/bin_, _/sbin_, _/lib,_ および _/lib64_ をコピーするだけで済みます）。次に、USBをマウントし、これらのバイナリを使用するように環境変数を変更します：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムを良好で既知のバイナリを使用するように設定したら、**基本的な情報を抽出し始める**ことができます：
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

基本情報を取得する際には、以下のような奇妙な事柄をチェックする必要があります：

- **ルートプロセス**は通常低いPIDで実行されるため、大きなPIDを持つルートプロセスを見つけた場合は疑うべきです
- `/etc/passwd`内のシェルを持たないユーザーの**登録されたログイン**を確認します
- シェルを持たないユーザーのために、`/etc/shadow`内の**パスワードハッシュ**を確認します

### メモリダンプ

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME)を使用することをお勧めします。\
**コンパイル**するには、被害者のマシンが使用している**同じカーネル**を使用する必要があります。

> [!TIP]
> 被害者のマシンに**LiMEやその他のものをインストールすることはできない**ことを覚えておいてください。そうすると、いくつかの変更が加わります。

したがって、同一のUbuntuバージョンがある場合は、`apt-get install lime-forensics-dkms`を使用できます。\
他の場合は、githubから[**LiME**](https://github.com/504ensicsLabs/LiME)をダウンロードし、正しいカーネルヘッダーでコンパイルする必要があります。被害者のマシンの**正確なカーネルヘッダー**を取得するには、単に`/lib/modules/<kernel version>`ディレクトリをあなたのマシンに**コピー**し、それを使用してLiMEを**コンパイル**します：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**フォーマット**をサポートしています：

- Raw（すべてのセグメントが連結されたもの）
- Padded（Rawと同じですが、右側のビットにゼロが追加されています）
- Lime（メタデータ付きの推奨フォーマット）

LiMEは、システムに保存する代わりに**ネットワーク経由でダンプを送信する**ためにも使用できます。例えば：`path=tcp:4444`

### ディスクイメージング

#### シャットダウン

まず最初に、**システムをシャットダウンする**必要があります。これは常に選択肢ではなく、時にはシステムが会社がシャットダウンできないプロダクションサーバーであることがあります。\
システムをシャットダウンする方法は**2つ**あり、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**です。最初の方法では、**プロセスが通常通り終了する**ことを許可し、**ファイルシステム**が**同期される**ことを可能にしますが、同時に**マルウェア**が**証拠を破壊する**可能性もあります。「プラグを抜く」アプローチは**情報の損失**を伴う可能性があります（メモリのイメージをすでに取得しているため、失われる情報はあまり多くありません）し、**マルウェアは何もできる機会がありません**。したがって、**マルウェアの可能性がある**と疑う場合は、システムで**`sync`** **コマンド**を実行し、プラグを抜いてください。

#### ディスクのイメージを取得する

**ケースに関連する何かにコンピュータを接続する前に**、情報を変更しないように**読み取り専用でマウントされる**ことを確認することが重要です。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

データがこれ以上ないディスクイメージをイメージングする。
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
## 既知のマルウェアを検索

### 修正されたシステムファイル

Linuxは、システムコンポーネントの整合性を確保するためのツールを提供しており、潜在的に問題のあるファイルを特定するために重要です。

- **RedHatベースのシステム**: `rpm -Va`を使用して包括的なチェックを行います。
- **Debianベースのシステム**: 初期検証には`dpkg --verify`を使用し、その後`debsums | grep -v "OK$"`（`apt-get install debsums`で`debsums`をインストールした後）を実行して問題を特定します。

### マルウェア/ルートキット検出ツール

マルウェアを見つけるのに役立つツールについて学ぶには、以下のページを参照してください：

{{#ref}}
malware-analysis.md
{{#endref}}

## インストールされたプログラムを検索

DebianおよびRedHatシステムでインストールされたプログラムを効果的に検索するには、システムログやデータベースを活用し、一般的なディレクトリでの手動チェックを併用することを検討してください。

- Debianの場合、_**`/var/lib/dpkg/status`**_および_**`/var/log/dpkg.log`**_を調査してパッケージインストールに関する詳細を取得し、`grep`を使用して特定の情報をフィルタリングします。
- RedHatユーザーは、`rpm -qa --root=/mntpath/var/lib/rpm`を使用してインストールされたパッケージのリストを取得できます。

これらのパッケージマネージャーの外部で手動でインストールされたソフトウェアを明らかにするために、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、および_**`/sbin`**_のようなディレクトリを探索してください。ディレクトリリストとシステム固有のコマンドを組み合わせて、既知のパッケージに関連付けられていない実行可能ファイルを特定し、インストールされたすべてのプログラムの検索を強化します。
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
## 削除された実行中のバイナリを復元する

/tmp/exec から実行されたプロセスが削除されたと想像してください。それを抽出することが可能です。
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## 自動起動場所の検査

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
#### Hunt: Cron/Anacronの悪用と0anacronおよび疑わしいスタブ
攻撃者は、定期的な実行を確保するために、各/etc/cron.*/ディレクトリに存在する0anacronスタブを編集することがよくあります。
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSHの強化のロールバックとバックドアシェル
sshd_configやシステムアカウントシェルの変更は、アクセスを保持するための一般的なポストエクスプロイトです。
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox APIビーコンは通常、HTTPS経由でapi.dropboxapi.comまたはcontent.dropboxapi.comを使用し、Authorization: Bearerトークンを使用します。
- サーバーからの予期しないDropboxの出口を探すために、proxy/Zeek/NetFlowでハントします。
- Cloudflare Tunnel（`cloudflared`）は、アウトバウンド443経由でバックアップC2を提供します。
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### サービス

マルウェアがサービスとしてインストールされる可能性のあるパス：

- **/etc/inittab**: rc.sysinitのような初期化スクリプトを呼び出し、さらに起動スクリプトに指示します。
- **/etc/rc.d/** と **/etc/rc.boot/**: サービス起動用のスクリプトを含み、後者は古いLinuxバージョンで見られます。
- **/etc/init.d/**: Debianのような特定のLinuxバージョンで起動スクリプトを保存するために使用されます。
- サービスは、Linuxのバリアントに応じて **/etc/inetd.conf** または **/etc/xinetd/** を介しても有効化されることがあります。
- **/etc/systemd/system**: システムおよびサービスマネージャースクリプト用のディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**: マルチユーザーランレベルで起動すべきサービスへのリンクを含みます。
- **/usr/local/etc/rc.d/**: カスタムまたはサードパーティのサービス用。
- **\~/.config/autostart/**: ユーザー固有の自動起動アプリケーション用で、ユーザーをターゲットにしたマルウェアの隠れ場所になる可能性があります。
- **/lib/systemd/system/**: インストールされたパッケージによって提供されるシステム全体のデフォルトユニットファイル。

### カーネルモジュール

Linuxカーネルモジュールは、マルウェアがルートキットコンポーネントとして利用することが多く、システムブート時にロードされます。これらのモジュールにとって重要なディレクトリとファイルは以下の通りです：

- **/lib/modules/$(uname -r)**: 実行中のカーネルバージョンのモジュールを保持します。
- **/etc/modprobe.d**: モジュールのロードを制御するための設定ファイルを含みます。
- **/etc/modprobe** と **/etc/modprobe.conf**: グローバルモジュール設定用のファイル。

### その他の自動起動場所

Linuxは、ユーザーログイン時にプログラムを自動的に実行するためのさまざまなファイルを使用し、マルウェアを隠す可能性があります：

- **/etc/profile.d/**\*, **/etc/profile**、および **/etc/bash.bashrc**: すべてのユーザーログイン時に実行されます。
- **\~/.bashrc**、**\~/.bash_profile**、**\~/.profile**、および **\~/.config/autostart**: ユーザー固有のファイルで、ログイン時に実行されます。
- **/etc/rc.local**: すべてのシステムサービスが起動した後に実行され、マルチユーザー環境への移行の終了を示します。

## ログの調査

Linuxシステムは、さまざまなログファイルを通じてユーザーの活動やシステムイベントを追跡します。これらのログは、不正アクセス、マルウェア感染、その他のセキュリティインシデントを特定するために重要です。主要なログファイルには以下が含まれます：

- **/var/log/syslog** (Debian) または **/var/log/messages** (RedHat): システム全体のメッセージと活動をキャプチャします。
- **/var/log/auth.log** (Debian) または **/var/log/secure** (RedHat): 認証試行、成功したログインと失敗したログインを記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して関連する認証イベントをフィルタリングします。
- **/var/log/boot.log**: システム起動メッセージを含みます。
- **/var/log/maillog** または **/var/log/mail.log**: メールサーバーの活動をログに記録し、メール関連サービスの追跡に役立ちます。
- **/var/log/kern.log**: カーネルメッセージを保存し、エラーや警告を含みます。
- **/var/log/dmesg**: デバイスドライバーメッセージを保持します。
- **/var/log/faillog**: 失敗したログイン試行を記録し、セキュリティ侵害の調査に役立ちます。
- **/var/log/cron**: cronジョブの実行をログに記録します。
- **/var/log/daemon.log**: バックグラウンドサービスの活動を追跡します。
- **/var/log/btmp**: 失敗したログイン試行を文書化します。
- **/var/log/httpd/**: Apache HTTPDのエラーログとアクセスログを含みます。
- **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQLデータベースの活動をログに記録します。
- **/var/log/xferlog**: FTPファイル転送を記録します。
- **/var/log/**: ここで予期しないログを常に確認してください。

> [!TIP]
> Linuxシステムのログと監査サブシステムは、侵入やマルウェアのインシデントで無効化または削除される可能性があります。Linuxシステムのログは、悪意のある活動に関する最も有用な情報を含むことが多いため、侵入者はそれらを定期的に削除します。したがって、利用可能なログファイルを調査する際には、削除や改ざんの兆候である可能性のあるギャップや順序が乱れたエントリを探すことが重要です。

**Linuxは各ユーザーのコマンド履歴を保持します**。これは以下に保存されます：

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

さらに、`last -Faiwx` コマンドはユーザーログインのリストを提供します。未知または予期しないログインがないか確認してください。

追加の権限を付与できるファイルを確認してください：

- 予期しないユーザー権限が付与されている可能性があるため、`/etc/sudoers` を確認します。
- 予期しないユーザー権限が付与されている可能性があるため、`/etc/sudoers.d/` を確認します。
- 異常なグループメンバーシップや権限を特定するために、`/etc/groups` を調査します。
- 異常なグループメンバーシップや権限を特定するために、`/etc/passwd` を調査します。

一部のアプリも独自のログを生成します：

- **SSH**: 不正なリモート接続のために _\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を調査します。
- **Gnomeデスクトップ**: Gnomeアプリケーションを介して最近アクセスされたファイルのために _\~/.recently-used.xbel_ を確認します。
- **Firefox/Chrome**: 疑わしい活動のために _\~/.mozilla/firefox_ または _\~/.config/google-chrome_ でブラウザの履歴とダウンロードを確認します。
- **VIM**: アクセスされたファイルパスや検索履歴などの使用詳細のために _\~/.viminfo_ を確認します。
- **Open Office**: 侵害されたファイルを示す可能性のある最近の文書アクセスを確認します。
- **FTP/SFTP**: 不正なファイル転送の可能性があるため、_ \~/.ftp_history_ または _\~/.sftp_history_ のログを確認します。
- **MySQL**: 実行されたMySQLクエリを調査するために _\~/.mysql_history_ を調査し、不正なデータベース活動を明らかにします。
- **Less**: 表示されたファイルや実行されたコマンドを含む使用履歴のために _\~/.lesshst_ を分析します。
- **Git**: リポジトリの変更のために _\~/.gitconfig_ とプロジェクトの _.git/logs_ を調査します。

### USBログ

[**usbrip**](https://github.com/snovvcrash/usbrip) は、Linuxのログファイル（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析してUSBイベント履歴テーブルを構築するために純粋なPython 3で書かれた小さなソフトウェアです。

使用されたすべてのUSBを知ることは興味深く、"違反イベント"（そのリストに含まれていないUSBの使用）を見つけるために、承認されたUSBのリストがあるとさらに有用です。

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
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオン活動のレビュー

_**/etc/passwd**_、_**/etc/shadow**_、および**セキュリティログ**を調べて、知られている不正なイベントに近い位置で作成または使用された異常な名前やアカウントを探します。また、可能なsudoブルートフォース攻撃を確認してください。\
さらに、_**/etc/sudoers**_や_**/etc/groups**_のようなファイルをチェックして、ユーザーに与えられた予期しない特権を確認します。\
最後に、**パスワードなし**または**簡単に推測できる**パスワードを持つアカウントを探します。

## ファイルシステムの調査

### マルウェア調査におけるファイルシステム構造の分析

マルウェアインシデントを調査する際、ファイルシステムの構造は重要な情報源であり、イベントの順序やマルウェアの内容を明らかにします。しかし、マルウェアの著者は、ファイルのタイムスタンプを変更したり、データストレージのためにファイルシステムを回避したりするなど、この分析を妨げる技術を開発しています。

これらのアンチフォレンジック手法に対抗するためには、以下が重要です：

- **Autopsy**のようなツールを使用してイベントのタイムラインを視覚化するために、徹底的なタイムライン分析を行うこと、または**Sleuth Kit**の`mactime`を使用して詳細なタイムラインデータを取得します。
- 攻撃者によって使用されるシェルやPHPスクリプトを含む可能性のある、システムの$PATH内の予期しないスクリプトを調査します。
- 通常は特別なファイルを含む`/dev`を調べますが、マルウェア関連のファイルが存在する可能性があります。
- 悪意のあるコンテンツを隠す可能性のある、名前が「.. 」(ドットドットスペース)や「..^G」(ドットドットコントロール-G)の隠しファイルやディレクトリを検索します。
- 攻撃者によって悪用される可能性のある、昇格された権限を持つファイルを見つけるために、次のコマンドを使用してsetuid rootファイルを特定します：`find / -user root -perm -04000 -print`
- ルートキットやトロイの木馬の存在を示す可能性のある、大量のファイル削除を示すためにinodeテーブルの削除タイムスタンプをレビューします。
- 1つの悪意のあるファイルを特定した後、近くにある悪意のあるファイルのために連続したinodeを検査します。これらは一緒に配置されている可能性があります。
- マルウェアによって変更される可能性があるため、最近変更されたファイルのために一般的なバイナリディレクトリ（_/bin_、_/sbin_）を確認します。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> 注意してください、**攻撃者**は**時間**を**変更**して**ファイルを正当なものに見せる**ことができますが、**inode**を**変更**することはできません。もし**ファイル**が同じフォルダ内の他のファイルと**同時に**作成および変更されたことを示しているが、**inode**が**予期せず大きい**場合、その**ファイルのタイムスタンプが変更された**ことになります。

## 異なるファイルシステムバージョンの比較

### ファイルシステムバージョン比較の概要

ファイルシステムのバージョンを比較し、変更点を特定するために、簡略化された`git diff`コマンドを使用します：

- **新しいファイルを見つけるために**、2つのディレクトリを比較します：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **変更された内容**、特定の行を無視しながら変更をリストします:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **削除されたファイルを検出する**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **フィルターオプション** (`--diff-filter`) は、追加された (`A`)、削除された (`D`)、または変更された (`M`) ファイルなど、特定の変更に絞り込むのに役立ちます。
- `A`: 追加されたファイル
- `C`: コピーされたファイル
- `D`: 削除されたファイル
- `M`: 変更されたファイル
- `R`: 名前が変更されたファイル
- `T`: タイプの変更（例：ファイルからシンボリックリンクへ）
- `U`: マージされていないファイル
- `X`: 不明なファイル
- `B`: 壊れたファイル

## 参考文献

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **書籍: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)

{{#include ../../banners/hacktricks-training.md}}
