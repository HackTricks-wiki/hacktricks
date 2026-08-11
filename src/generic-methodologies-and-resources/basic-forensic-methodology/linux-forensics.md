# Linuxフォレンジック

{{#include ../../banners/hacktricks-training.md}}

## 初期情報収集

### 基本情報

まず、**既知の良質なバイナリとライブラリが入ったUSB**を用意しておくことを推奨します（Ubuntuを入手して、フォルダ _/bin_、_/sbin_、_/lib,_、_/lib64_ をコピーするだけでも構いません）。次にUSBをマウントし、それらのバイナリを使用するように環境変数を変更します。
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムが適切で既知のバイナリを使用するよう設定できたら、**基本的な情報の抽出**を開始できます：
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
#### Suspicious information

基本情報を取得する際は、次のような不審な点を確認する必要があります。

- **Root processes** は通常、低い PID で実行されるため、大きな PID を持つ root process を見つけた場合は、疑うべきです
- `/etc/passwd` 内で、shell を持たないユーザーの**登録済みログイン**を確認する
- shell を持たないユーザーの**password hashes**が `/etc/shadow` 内に存在しないか確認する

### Memory Dump

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) の使用が推奨されます。\
**compile**するには、被害マシンが使用しているものと**同じ kernel**を使用する必要があります。

> [!TIP]
> 被害マシンに **LiME やその他のものを install してはならない**ことを忘れないでください。これにより、被害マシンに複数の変更が加えられるためです。

そのため、Ubuntu の同一バージョンがある場合は、`apt-get install lime-forensics-dkms` を使用できます。\
それ以外の場合は、github から [**LiME**](https://github.com/504ensicsLabs/LiME) を download し、正しい kernel headers を使って compile する必要があります。被害マシンの**正確な kernel headers を取得**するには、`/lib/modules/<kernel version>` ディレクトリを自分のマシンに**コピー**し、それらを使って LiME を **compile**します。
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME は 3 つの **形式**をサポートしています：

- Raw（すべてのセグメントを連結）
- Padded（Raw と同じですが、右側のビットをゼロで埋める）
- Lime（metadata を含む推奨形式

LiME は、`path=tcp:4444` のような指定を使用して、システム上に保存する代わりに **dump を network 経由で送信**することもできます。

### Disk Imaging

#### シャットダウン

まず、システムを **シャットダウン**する必要があります。これは常に可能とは限りません。場合によっては、会社が停止させる余裕のない production server であることもあります。\
システムをシャットダウンする方法は **2 つ**あります。**通常のシャットダウン**と、**「plug the plug」シャットダウン**です。前者では、**processes が通常どおり終了**し、**filesystem** が **synchronize** されますが、同時に **malware** が **evidence を破壊**する可能性もあります。「pull the plug」方式では、**一部の情報が失われる可能性**があります（すでに memory の image を取得しているため、失われる情報は多くありません）が、**malware が何かを行う機会はありません**。したがって、**malware** が存在する可能性を **suspect** した場合は、システム上で **`sync`** **command** を実行してから、電源プラグを抜いてください。

#### disk の image を取得する

**case に関連するものへ computer を接続する前に**、情報の変更を避けるため、必ず **read only として mount される**ことを確認する必要があります。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

これ以上データを含まないディスクイメージのイメージング。
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
## 既知の Malware を検索

### 変更されたシステムファイル

Linux には、システムコンポーネントの整合性を確認するためのツールが用意されており、問題の可能性があるファイルを見つけるうえで重要です。<sup>[[1]](#references)</sup>

- **RedHat ベースのシステム**: `rpm -Va` を使用して包括的なチェックを実行します。
- **Debian ベースのシステム**: 最初の検証には `dpkg --verify` を使用し、その後 `debsums | grep -v "OK$"` を実行して問題を特定します（`apt-get install debsums` で `debsums` をインストールした後）。

### Malware/Rootkit 検出ツール

Malware の発見に役立つツールについては、次のページを参照してください:


{{#ref}}
malware-analysis.md
{{#endref}}

## インストール済みプログラムの検索

Debian と RedHat の両方のシステムでインストール済みプログラムを効果的に検索するには、一般的なディレクトリでの手動チェックに加えて、システムログとデータベースを活用します。<sup>[[1]](#references)</sup>

- Debian では、_**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を調べ、`grep` を使用して特定の情報を絞り込み、パッケージのインストールに関する詳細を取得します。
- RedHat ユーザーは、`rpm -qa --root=/mntpath/var/lib/rpm` で RPM データベースを照会し、インストール済みパッケージを一覧表示できます。

これらのパッケージマネージャーを使用せずに手動でインストールされたソフトウェアや、パッケージマネージャーの管理外にあるソフトウェアを見つけるには、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_ などのディレクトリを調べます。ディレクトリの一覧とシステム固有のコマンドを組み合わせて、既知のパッケージに関連付けられていない実行ファイルを特定すると、インストール済みプログラムをすべて検索しやすくなります。
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
## 削除された実行中バイナリの復元

/tmp/exec から実行された後に削除されたプロセスを想定します。これを抽出することが可能です。
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite と FTS5 を使ったシステムコールトレースのトリアージ

プロセスがまだ実行中であるか、ラボ環境で再実行できる場合、**`strace`** はカーネルモジュールや完全な EDR テレメトリを必要とせず、高速な挙動トレースを提供できます。大規模なトレースでは、生のログを直接読んだり、LLM に貼り付けたりするのは避け、**SQLite** データベースに保存して、必要最小限のサブセットだけをクエリしてください。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` のアタッチはプロセスのタイミングを変化させ、race condition やその他の脆弱なバグに影響を与える可能性があります。可能な場合は、コピーまたはラボシステム上での再現を優先してください。

### キャプチャ

新しいプロセスの場合：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
実行中のプロセスの場合：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Useful options:

- `-ff`: フォーク/スレッドを追跡し、プロセスごとの出力を保持
- `-ttt`: タイムラインの相関を容易にするエポックタイムスタンプ
- `-yy`: 可能な場合、ファイルディスクリプタをバッキングパス/ソケットに解決
- `-s 4096`: 長いパスやバッファ引数が切り詰められないようにする

### 正規化

実用的なスキーマは、システムコールごとに1行、引数ごとに1行とします：
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
これにより、異種の syscall 行を単一の横長テーブルに平坦化しようとする処理を避け、triage 中の join を予測しやすく保てます。

### FTS5 でテキスト量の多い引数をインデックス化する

大規模な trace では、`LIKE "%...%"` を使った単純な path 探索は非常に遅くなります。引数テキスト用の FTS5 インデックスを作成し、代わりにそれを検索します：
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
例: すべての行をスキャンせずに `/tmp` 配下のファイルアクティビティを復元する:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### 重要度の高い調査

- **PATH hijacking / fake sudo**: `~/.local/bin/` 配下への書き込みと `chmod`/`rename` のアクティビティを検索し、その後の `sudo` など特権的に見える名前への `execve` と関連付ける。
- **一時ファイルに対する TOCTOU**: 同じ `/tmp/...` パスについて、`stat`、`access`、`openat`、`rename`、`unlink`、`link`、`symlink`、`execve` を横断して追跡し、check/use の間隙を特定する。
- **クラッシュの根本原因**: あるプロセスによる同じ inode/path への書き込みまたは切り詰めと、別のプロセスによるファイルの `mmap` を関連付け、その後のシグナル/終了シーケンスを調べて `SIGBUS` を確認する。
- **ネットワーク送信先の復元**: `connect`、`sendto`、`sendmsg`、`recvfrom` および socket 関連の引数をフィルタリングし、相手側の IP とポートを抽出する。

### LLM-assisted trace analysis

LLM に支援させる場合は、**read-only** の SQLite handle を公開し、完全な schema を渡す。データベースを狭い helper functions の背後にラップするのではなく、raw SQL を発行させる。これは通常、join、時間的な相関、FTS lookup でより適切に機能する。

実用的なルール:

- データベースを read-only にする。例: `sqlite3 'file:trace.db?mode=ro'`
- 有効な `JOIN` および `FTS5 MATCH` クエリの例をモデルに与える。
- raw の複数 GB の `strace` ログを prompt に貼り付け**ない**。
- 次のように、焦点を絞った質問をする:
- 「このプログラムが書き込んだ永続ファイルを一覧表示して。」
- 「ユーザーが制御できる PATH ディレクトリ内で executable を作成または置換したか？」
- 「この trace が `SIGBUS` で終了する理由を説明して。」

## Autostart locations を調査する

### Scheduled Tasks
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
#### Hunt: 0anacron と不審なstubを介した Cron/Anacron abuse
攻撃者は、定期的な実行を確実にするため、各 /etc/cron.*/ ディレクトリに存在する 0anacron stub を編集することがよくあります。<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config とシステムアカウントのシェルへの変更は、アクセスを維持するための post-exploitation でよく行われます。<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons は通常、HTTPS 経由で api.dropboxapi.com または content.dropboxapi.com を使用し、Authorization: Bearer トークンを含めます。
- proxy/Zeek/NetFlow で、サーバーからの予期しない Dropbox egress を Hunt します。
- Cloudflare Tunnel（`cloudflared`）は、アウトバウンド 443 経由のバックアップ C2 を提供します。<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### サービス

マルウェアがサービスとしてインストールされる可能性のあるパス:

- **/etc/inittab**: rc.sysinit などの初期化スクリプトを呼び出し、さらに起動スクリプトへ処理を引き渡す。
- **/etc/rc.d/** および **/etc/rc.boot/**: サービス起動用のスクリプトを含む。後者は古い Linux バージョンに存在する。
- **/etc/init.d/**: Debian など一部の Linux バージョンで、起動スクリプトの保存に使用される。
- Linux の variant に応じて、サービスは **/etc/inetd.conf** または **/etc/xinetd/** 経由で有効化される場合もある。
- **/etc/systemd/system**: system および service manager のスクリプト用ディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel で起動すべきサービスへのリンクを含む。
- **/usr/local/etc/rc.d/**: カスタムサービスまたはサードパーティー製サービス用。
- **\~/.config/autostart/**: ユーザー固有の自動起動アプリケーション用。ユーザーを標的とするマルウェアの隠れ場所になる可能性がある。
- **/lib/systemd/system/**: インストール済みパッケージが提供するシステム全体のデフォルト unit ファイル。

#### 調査: systemd timers と transient units

systemd の persistence は `.service` ファイルに限定されない。.timer unit、ユーザーレベルの unit、実行時に作成される **transient units** を調査する。
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Transient units は、`/run/systemd/transient/` が**非永続的**であるため、見落としやすいです。live image を収集する場合は、シャットダウン前に取得してください。

### カーネルモジュール

Linux カーネルモジュールは、rootkit コンポーネントとして malware によく利用され、システム起動時にロードされます。これらのモジュールにとって重要なディレクトリとファイルは以下のとおりです。

- **/lib/modules/$(uname -r)**: 実行中のカーネルバージョン用のモジュールを保持します。
- **/etc/modprobe.d**: モジュールのロードを制御する設定ファイルが含まれます。
- **/etc/modprobe** および **/etc/modprobe.conf**: グローバルなモジュール設定用のファイルです。

### その他の Autostart ロケーション

Linux では、ユーザーのログイン時にプログラムを自動実行するさまざまなファイルが使用されており、malware が潜んでいる可能性があります。

- **/etc/profile.d/**\*、**/etc/profile**、**/etc/bash.bashrc**: すべてのユーザーのログイン時に実行されます。
- **\~/.bashrc**、**\~/.bash_profile**、**\~/.profile**、**\~/.config/autostart**: 各ユーザーのログイン時に実行される、ユーザー固有のファイルです。
- **/etc/rc.local**: すべてのシステムサービスの起動後に実行され、マルチユーザー環境への移行の完了を示します。

## ログを調査する

Linux システムは、さまざまなログファイルを通じてユーザーのアクティビティとシステムイベントを追跡します。これらのログは、不正アクセス、malware 感染、その他のセキュリティインシデントを特定するうえで重要です。<sup>[[2]](#references)</sup> 主なログファイルは以下のとおりです。

- **/var/log/syslog** (Debian) または **/var/log/messages** (RedHat): システム全体のメッセージとアクティビティを記録します。
- **/var/log/auth.log** (Debian) または **/var/log/secure** (RedHat): 認証の試行、成功したログイン、失敗したログインを記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して、関連する認証イベントをフィルタリングします。
- **/var/log/boot.log**: システムの起動メッセージが含まれます。
- **/var/log/maillog** または **/var/log/mail.log**: メールサーバーのアクティビティを記録し、メール関連サービスの追跡に役立ちます。
- **/var/log/kern.log**: エラーや警告を含むカーネルメッセージを保存します。
- **/var/log/dmesg**: デバイスドライバーのメッセージを保持します。
- **/var/log/faillog**: 失敗したログイン試行を記録し、セキュリティ侵害の調査に役立ちます。
- **/var/log/cron**: cron job の実行を記録します。
- **/var/log/daemon.log**: バックグラウンドサービスのアクティビティを追跡します。
- **/var/log/btmp**: 失敗したログイン試行を記録します。
- **/var/log/httpd/**: Apache HTTPD のエラーログとアクセスログが含まれます。
- **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQL データベースのアクティビティを記録します。
- **/var/log/xferlog**: FTP ファイル転送を記録します。
- **/var/log/**: ここに予期しないログがないか、必ず確認します。

> [!TIP]
> Linux のシステムログと audit サブシステムは、侵入または malware インシデントの際に無効化または削除されている可能性があります。Linux システムのログには通常、悪意のあるアクティビティに関する非常に有用な情報が含まれているため、侵入者は日常的にログを削除します。そのため、利用可能なログファイルを調査する際は、削除または改ざんの兆候である可能性のある、ログの欠落や時系列順でないエントリを探すことが重要です。

### Journald のトリアージ (`journalctl`)

最新の Linux ホストでは、**systemd journal** は通常、**service execution**、**auth events**、**package operations**、**kernel/user-space messages** に関する最も価値の高い情報源です。live response 中は、**persistent** journal (`/var/log/journal/`) と **runtime** journal (`/run/log/journal/`) の両方を保持するようにしてください。攻撃者による短時間のアクティビティは、後者にしか存在しない可能性があるためです。<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
トリアージに有用な journal フィールドには、`_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID`、`MESSAGE` があります。journald が永続ストレージなしで設定されている場合、`/run/log/journal/` 配下には最近のデータのみが存在すると考えてください。

### Audit framework triage (`auditd`)

`auditd` が有効な場合、ファイル変更、コマンド実行、ログイン活動、パッケージインストールについて**プロセスの帰属**が必要なときは、優先して使用してください。<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
ルールがキー付きでデプロイされていた場合は、生ログを grep するのではなく、それらを起点に pivot する：
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux は各ユーザーの command history を管理しており**、以下に保存されます。

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

さらに、`last -Faiwx` command はユーザーの login 一覧を提供します。不明または予期しない login がないか確認してください。

追加の rprivileges を付与できるファイルを確認します。

- 予期しない user privileges が付与されていないか、`/etc/sudoers` を確認します。
- 予期しない user privileges が付与されていないか、`/etc/sudoers.d/` を確認します。
- `/etc/groups` を調査し、通常とは異なる group memberships や permissions を特定します。
- `/etc/passwd` を調査し、通常とは異なる group memberships や permissions を特定します。

一部の app も独自の logs を生成します。

- **SSH**: 不正な remote connections がないか、_\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を調査します。
- **Gnome Desktop**: Gnome applications 経由で最近アクセスされた files を確認するため、_\~/.recently-used.xbel_ を調査します。
- **Firefox/Chrome**: suspicious activities がないか、_\~/.mozilla/firefox_ または _\~/.config/google-chrome_ の browser history と downloads を確認します。
- **VIM**: access された file paths や search history などの usage details を確認するため、_\~/.viminfo_ を調査します。
- **Open Office**: compromised files を示す可能性がある recent document access を確認します。
- **FTP/SFTP**: 不正な可能性がある file transfers がないか、_\~/.ftp_history_ または _\~/.sftp_history_ の logs を確認します。
- **MySQL**: 不正な database activities を明らかにする可能性がある、実行された MySQL queries を確認するため、_\~/.mysql_history_ を調査します。
- **Less**: viewed files や実行された commands などの usage history を確認するため、_\~/.lesshst_ を分析します。
- **Git**: repositories への変更を確認するため、_\~/.gitconfig_ と project の _.git/logs_ を調査します。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) は、pure Python 3 で書かれた小さな software で、Linux log files（distro に応じて `/var/log/syslog*` または `/var/log/messages*`）を解析し、USB event history tables を構築します。

**使用されたすべての USB を把握すること**は有用です。また、"violation events"（その list に含まれていない USB の使用）を見つけるために、authorized list of USBs があるとさらに便利です。

### Installation
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
github 内の詳細な例と情報: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオンアクティビティの確認

_**/etc/passwd**_、_**/etc/shadow**_、および **セキュリティログ** を調査し、既知の不正イベントの前後に作成または使用された、不審な名前やアカウントがないか確認します。また、sudo のブルートフォース攻撃の可能性も確認します。\
さらに、_**/etc/sudoers**_ や _**/etc/groups**_ などのファイルを確認し、ユーザーに予期しない権限が付与されていないか調べます。\
最後に、**パスワードが設定されていない**、または **容易に推測できる** パスワードを使用しているアカウントを探します。<sup>[[1]](#references)</sup>

## ファイルシステムの調査

### マルウェア調査におけるファイルシステム構造の分析

マルウェアインシデントを調査する際、ファイルシステムの構造は重要な情報源となり、イベントの順序とマルウェアの内容の両方を明らかにします。しかし、マルウェア作成者は、ファイルのタイムスタンプを変更したり、データの保存にファイルシステムを使用しないようにしたりするなど、この分析を妨げる技術を開発しています。<sup>[[1]](#references)</sup>

これらの anti-forensic 手法に対抗するには、以下を実施することが重要です。

- **Autopsy** などのツールを使用してイベントのタイムラインを可視化したり、**Sleuth Kit** の `mactime` を使用して詳細なタイムラインデータを取得したりするなど、**徹底的なタイムライン分析を実施**します。
- システムの $PATH にある **予期しないスクリプト** を調査します。これには、攻撃者が使用した shell または PHP スクリプトが含まれている可能性があります。
- **`/dev` にある非典型的なファイル**を調査します。通常、ここには特殊ファイルが含まれますが、マルウェア関連ファイルが存在する場合もあります。
- ".. "（ドット・ドット・スペース）や "..^G"（ドット・ドット・control-G）のような名前を持つ **隠しファイルやディレクトリ**を検索します。これらには悪意のあるコンテンツが隠されている可能性があります。
- `find / -user root -perm -04000 -print` コマンドを使用して **setuid root ファイル**を特定します。これは、攻撃者に悪用される可能性のある、昇格された権限を持つファイルを検索します。
- inode テーブル内の **削除タイムスタンプ**を確認し、大量のファイル削除がないか調べます。これは、rootkit や trojan の存在を示している可能性があります。
- 1つの悪意のあるファイルを特定した後、**連続する inode** を調査して近接する悪意のあるファイルがないか確認します。これらは一緒に配置された可能性があります。
- **一般的なバイナリディレクトリ**（_/bin_、_/sbin_）にある最近変更されたファイルを確認します。これらはマルウェアによって改変された可能性があります。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker** は **time** を **modify** して **files appear** **legitimate** のように見せることができますが、**inode** を **modify** することはできません。同じフォルダー内の他のファイルと **file** の作成時刻と変更時刻が**同じ**であるにもかかわらず、**inode** が**予想外に大きい**場合、そのファイルの **timestamps** は **modified** されています。

### inode に注目した簡易トリアージ

anti-forensics の疑いがある場合は、早い段階で次の inode に注目したチェックを実行します。
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
EXT filesystem image/device 上に疑わしい inode がある場合は、inode のメタデータを直接調査します：
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: `0` の場合、現在その inode を参照しているディレクトリエントリはありません。
- **dtime**: inode の unlink 時に設定される削除タイムスタンプ。
- **ctime/mtime**: メタデータやコンテンツの変更をインシデントのタイムラインと関連付けるのに役立ちます。

### Capabilities、xattrs、preload ベースの userland rootkits

Modern Linux の永続化では、明らかな **setuid** バイナリを避け、代わりに **file capabilities**、**extended attributes**、動的ローダーを悪用することがよくあります。
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
**writable** なパス（`/tmp`、`/dev/shm`、`/var/tmp`、または `/usr/local/lib` 配下の通常とは異なる場所など）から参照されるライブラリに特に注意してください。また、通常のパッケージ所有範囲外にある capability 付与バイナリを確認し、パッケージ検証結果（`rpm -Va`、`dpkg --verify`、`debsums`）と関連付けてください。

## 異なる filesystem version のファイルを比較する

### Filesystem Version Comparison Summary

filesystem version を比較して変更点を特定するには、簡略化した `git diff` コマンドを使用します。<sup>[[3]](#references)</sup>

- **新しいファイルを見つけるには**、2つのディレクトリを比較します：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **変更されたコンテンツについては**、特定の行を無視して変更点を一覧表示する：
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **削除されたファイルを検出するには**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) は、追加（`A`）、削除（`D`）、変更（`M`）されたファイルなど、特定の変更に絞り込むのに役立ちます。
- `A`: 追加されたファイル
- `C`: コピーされたファイル
- `D`: 削除されたファイル
- `M`: 変更されたファイル
- `R`: 名前が変更されたファイル
- `T`: 種類が変更されたファイル（例：ファイルからシンボリックリンク）
- `U`: マージされていないファイル
- `X`: 不明なファイル
- `B`: 破損したファイル

## References

- [1] [Linuxシステム向けマルウェアフォレンジック・フィールドガイド：デジタルフォレンジック・フィールドガイド – 第3章](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linuxログの解説](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diffドキュメント – --diff-filterオプション](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – 永続化のためのパッチ適用：DripDropper Linuxマルウェアがcloud内を移動する方法](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linuxジャーナルのフォレンジック分析](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - システムの監査](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [Pikeにご挨拶！](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5拡張](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
