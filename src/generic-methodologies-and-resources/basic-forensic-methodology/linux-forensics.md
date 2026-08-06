# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Initial Information Gathering

### Basic Information

まず、**既知の正常なバイナリとライブラリが入った** **USB** を用意することを推奨します（ubuntu を入手して、フォルダ _/bin_、 _/sbin_、 _/lib,_、 _/lib64_ をコピーするだけでも構いません）。次に USB をマウントし、それらのバイナリを使用するように環境変数を変更します。
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムが信頼できる既知のバイナリを使用するよう設定したら、**基本的な情報の抽出**を開始できます：
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

基本情報を取得する際は、次のような不審な点を確認してください。

- **Root processes** は通常、低い PID で実行されるため、大きな PID の root process を見つけた場合は疑うべきです
- `/etc/passwd` 内で、shell を持たないユーザーの **registered logins** を確認する
- `/etc/shadow` 内で、shell を持たないユーザーの **password hashes** を確認する

### Memory Dump

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) の使用が推奨されます。\
**compile** するには、victim machine が使用しているものと**同じ kernel**を使用する必要があります。

> [!TIP]
> victim machine に **LiME** やその他のものを**インストールすることはできない**点に注意してください。インストールすると、システムに複数の変更が加えられるためです。

そのため、Ubuntu の同一バージョンがある場合は、`apt-get install lime-forensics-dkms` を使用できます。\
それ以外の場合は、github から [**LiME**](https://github.com/504ensicsLabs/LiME) を download し、正しい kernel headers を使って compile する必要があります。victim machine の**正確な kernel headers を取得**するには、`/lib/modules/<kernel version>` ディレクトリを自分の machine に**コピー**し、それを使って LiME を**compile**します。
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**formats**をサポートしています：

- Raw（すべてのセグメントを連結）
- Padded（Rawと同じですが、右側のビットをゼロで埋める）
- Lime（metadataを含む推奨形式

LiMEは、`path=tcp:4444`のように、システム上に保存する代わりに**ネットワーク経由でdumpを送信**するためにも使用できます。

### ディスクイメージング

#### シャットダウン

まず、システムを**シャットダウン**する必要があります。これは常に可能とは限りません。システムが、会社として停止させる余裕のない本番サーバーである場合があるためです。\
システムをシャットダウンする方法には、**通常のシャットダウン**と**「プラグを抜く」シャットダウン**の**2つの方法**があります。前者では、**プロセスを通常どおり終了**させ、**ファイルシステム**を**同期**できますが、同時に**malware**が**証拠を破壊**する可能性もあります。「プラグを抜く」方法では、**一部の情報が失われる可能性**があります（すでにメモリのイメージを取得しているため、失われる情報はそれほど多くありません）が、**malwareが何らかの処理を行う機会はありません**。したがって、**malware**が存在する可能性を**疑っている**場合は、システム上で**`sync`** **command**を実行してから、プラグを抜いてください。

#### ディスクのイメージを取得する

**caseに関連するものへコンピューターを接続する前に**、情報が変更されないよう、必ず**read onlyとしてmountされる**ことを確認する必要がある点に注意してください。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

これ以上データのないディスクイメージのイメージング。
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

Linux にはシステムコンポーネントの整合性を確認するツールがあり、問題のある可能性があるファイルの発見に役立ちます。<sup>[[1]](#references)</sup>

- **RedHat ベースのシステム**: `rpm -Va` を使用して包括的なチェックを実行します。
- **Debian ベースのシステム**: 最初の検証には `dpkg --verify` を使用し、その後、問題を特定するために `debsums | grep -v "OK$"` を実行します（`apt-get install debsums` で `debsums` をインストールした後）。

### Malware/Rootkit Detectors

Malware の発見に役立つツールについては、次のページを参照してください:


{{#ref}}
malware-analysis.md
{{#endref}}

## インストール済みプログラムの検索

Debian と RedHat の両方のシステムでインストール済みプログラムを効果的に検索するには、一般的なディレクトリでの手動チェックに加えて、システムログとデータベースを活用します。<sup>[[1]](#references)</sup>

- Debian では、_**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を調査してパッケージのインストールに関する詳細を取得し、`grep` を使用して特定の情報を絞り込みます。
- RedHat ユーザーは、`rpm -qa --root=/mntpath/var/lib/rpm` で RPM データベースを検索し、インストール済みパッケージを一覧表示できます。

これらのパッケージマネージャーを使用せずに手動または別の方法でインストールされたソフトウェアを見つけるには、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_ などのディレクトリを調査します。ディレクトリの一覧とシステム固有のコマンドを組み合わせて、既知のパッケージに関連付けられていない実行ファイルを特定することで、インストール済みプログラムをすべて検索できます。
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

/tmp/exec から実行された後に削除されたプロセスを想定してください。抽出することが可能です。
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite と FTS5 を使った Syscall Trace Triage

プロセスがまだ実行中であるか、lab で再実行できる場合、**`strace`** は kernel module や完全な EDR telemetry を必要とせず、迅速な挙動 trace を取得できます。大規模な trace の場合は、raw log を直接読んだり LLM に貼り付けたりせず、**SQLite** database に保存して、必要最小限の subset のみを query してください。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` の attach によりプロセスの timing が変化し、race condition やその他の壊れやすい bug に影響する可能性があります。可能な場合は、copy/lab system 上での再現を優先してください。

### Capture

新しいプロセスの場合：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
実行中のプロセスの場合：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
Useful options:

- `-ff`: fork/thread を追跡し、プロセスごとの出力を保持
- `-ttt`: タイムラインの相関を容易にする epoch timestamp
- `-yy`: 可能な場合、file descriptor を対応する backing path/socket に解決
- `-s 4096`: 長い path と buffer の引数が切り詰められないようにする

### Normalize

実用的なスキーマは、1つのシステムコールにつき1行、1つの引数につき1行です。
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
これにより、異種の syscall 行を単一の幅広いテーブルに無理に平坦化することを避け、triage 中の join を予測可能な状態に保てます。

### FTS5 でテキスト量の多い引数にインデックスを作成する

`LIKE "%...%"` を使った単純な path hunting は、大規模な trace では非常に遅くなります。引数テキスト用の FTS5 インデックスを作成し、代わりにそれを検索します：
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
### High-signal investigations

- **PATH hijacking / fake sudo**: `~/.local/bin/` 以下への書き込みと `chmod`/`rename` アクティビティを検索し、その後の `sudo` のような特権関連に見える名前への `execve` と相関させます。
- **TOCTOU on temporary files**: 同じ `/tmp/...` パスについて、`stat`、`access`、`openat`、`rename`、`unlink`、`link`、`symlink`、`execve` を横断して追跡し、check/use の間隙を特定します。
- **Crash root cause**: あるプロセスによる同じ inode/path への書き込みまたは切り詰めと、別のプロセスによるファイルの `mmap` を相関させ、その後のシグナル/終了シーケンスを調べて `SIGBUS` を確認します。
- **Network destination recovery**: `connect`、`sendto`、`sendmsg`、`recvfrom` および socket 関連の引数をフィルタリングし、peer IP とポートを抽出します。

### LLM-assisted trace analysis

LLM に支援させたい場合は、**read-only** の SQLite handle を公開し、完全な schema を渡します。データベースを限定的な helper functions でラップするのではなく、raw SQL を発行させてください。これは通常、join、時間的な相関、FTS lookup でより適切に機能します。

実用的なルール:

- データベースは read-only にします。例えば `sqlite3 'file:trace.db?mode=ro'` を使用します。
- 有効な `JOIN` および `FTS5 MATCH` クエリの例をモデルに提供します。
- raw の数 GB に及ぶ `strace` ログを prompt に貼り付けないでください。
- 次のように焦点を絞った質問をします:
- 「このプログラムが書き込んだ永続ファイルを一覧表示してください。」
- 「ユーザーが制御できる PATH ディレクトリ内で、実行ファイルを作成または置換しましたか？」
- 「この trace が `SIGBUS` で終了する理由を説明してください。」

## Inspect Autostart locations

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
#### Hunt: 0anacron と不審な stub を介した Cron/Anacron abuse
攻撃者は、定期実行を確実に行うため、各 /etc/cron.*/ ディレクトリ配下に存在する 0anacron stub を編集することがよくあります。<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening の rollback と backdoor shell
sshd_config と system account の shell の変更は、access を維持するための post-exploitation でよく行われます。<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API ビーコンは通常、Authorization: Bearer トークンを使用し、HTTPS 経由で api.dropboxapi.com または content.dropboxapi.com に接続します。
- proxy/Zeek/NetFlow で、サーバーからの予期しない Dropbox への outbound 通信を Hunt します。
- Cloudflare Tunnel (`cloudflared`) は、outbound 443 経由で backup C2 を提供します。<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### サービス

マルウェアがサービスとしてインストールされる可能性のあるパス:

- **/etc/inittab**: rc.sysinit などの初期化スクリプトを呼び出し、さらにスタートアップスクリプトへ処理を引き継ぎます。
- **/etc/rc.d/** および **/etc/rc.boot/**: サービスの起動用スクリプトが含まれます。後者は古い Linux バージョンで使用されます。
- **/etc/init.d/**: Debian など一部の Linux バージョンで、スタートアップスクリプトの保存に使用されます。
- Linux の種類によっては、サービスが **/etc/inetd.conf** または **/etc/xinetd/** 経由で有効化される場合もあります。
- **/etc/systemd/system**: system および service manager のスクリプト用ディレクトリです。
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel で起動すべきサービスへのリンクが含まれます。
- **/usr/local/etc/rc.d/**: カスタムサービスやサードパーティ製サービス用です。
- **\~/.config/autostart/**: ユーザー固有の自動起動アプリケーション用で、ユーザーを標的とするマルウェアの隠し場所になる可能性があります。
- **/lib/systemd/system/**: インストール済みパッケージが提供する、システム全体のデフォルト unit ファイル用です。

#### Hunt: systemd timers and transient units

systemd による永続化は `.service` ファイルに限定されません。`.timer` units、ユーザーレベルの units、および実行時に作成される **transient units** を調査してください。
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
Transient units は `/run/systemd/transient/` が **非永続的** であるため、見落としやすい存在です。live image を収集する場合は、シャットダウン前に取得してください。

### Kernel Modules

Linux kernel modules は、rootkit コンポーネントとして malware によって利用されることが多く、system boot 時にロードされます。これらの modules にとって重要なディレクトリとファイルには、以下が含まれます。

- **/lib/modules/$(uname -r)**: 実行中の kernel version 用の modules を保持します。
- **/etc/modprobe.d**: module loading を制御する configuration files が含まれます。
- **/etc/modprobe** および **/etc/modprobe.conf**: global module settings 用のファイルです。

### Other Autostart Locations

Linux では、user login 時に programs を自動実行するためにさまざまなファイルが使用されており、malware が潜んでいる可能性があります。

- **/etc/profile.d/**\*, **/etc/profile**、および **/etc/bash.bashrc**: すべての user login に対して実行されます。
- **\~/.bashrc**、**\~/.bash_profile**、**\~/.profile**、および **\~/.config/autostart**: user ごとの login 時に実行されるファイルです。
- **/etc/rc.local**: すべての system services の起動後に実行され、multiuser environment への transition の終了を示します。

## Examine Logs

Linux systems は、さまざまな log files を通じて user activities と system events を記録します。これらの logs は、unauthorized access、malware infections、その他の security incidents を特定するうえで重要です。<sup>[[2]](#references)</sup> 主な log files には以下が含まれます。

- **/var/log/syslog** (Debian) または **/var/log/messages** (RedHat): system-wide messages と activities を記録します。
- **/var/log/auth.log** (Debian) または **/var/log/secure** (RedHat): authentication attempts、successful logins、failed logins を記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して、関連する authentication events を抽出します。
- **/var/log/boot.log**: system startup messages が含まれます。
- **/var/log/maillog** または **/var/log/mail.log**: email server activities を記録し、email-related services の追跡に役立ちます。
- **/var/log/kern.log**: errors や warnings を含む kernel messages を保存します。
- **/var/log/dmesg**: device driver messages が保持されます。
- **/var/log/faillog**: failed login attempts を記録し、security breach investigations に役立ちます。
- **/var/log/cron**: cron job executions を記録します。
- **/var/log/daemon.log**: background service activities を追跡します。
- **/var/log/btmp**: failed login attempts を記録します。
- **/var/log/httpd/**: Apache HTTPD の error logs と access logs が含まれます。
- **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQL database activities を記録します。
- **/var/log/xferlog**: FTP file transfers を記録します。
- **/var/log/**: ここに予期しない logs がないか、必ず確認してください。

> [!TIP]
> Linux system logs と audit subsystems は、intrusion や malware incident の際に無効化または削除されている可能性があります。Linux systems の logs には一般に malicious activities に関する最も有用な情報が含まれているため、intruders は日常的にこれらを削除します。そのため、利用可能な log files を調査する際は、削除または tampering の兆候である可能性のある空白や、順序が不正な entries を探すことが重要です。

### Journald triage (`journalctl`)

modern Linux hosts では、**systemd journal** は通常、**service execution**、**auth events**、**package operations**、および **kernel/user-space messages** に関する最も価値の高い source です。live response 中は、**persistent** journal (`/var/log/journal/`) と **runtime** journal (`/run/log/journal/`) の両方を保存するようにしてください。短時間しか存在しない attacker activity は、後者にしか存在しない可能性があるためです。<sup>[[5]](#references)</sup>
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
トリアージに役立つ journal フィールドには、`_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID`、`MESSAGE` などがあります。journald が永続ストレージなしで設定されている場合は、`/run/log/journal/` 配下に最近のデータしか存在しないことを想定してください。

### Audit framework のトリアージ（`auditd`）

`auditd` が有効な場合、ファイル変更、コマンド実行、ログインアクティビティ、パッケージインストールについて**プロセスの帰属**が必要なときは、常に `auditd` を優先してください。<sup>[[6]](#references)</sup>
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
キーを使ってルールがデプロイされていた場合は、生のログをgrepするのではなく、それらを起点にpivotする：
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux は各ユーザーの command history を保持しており**、以下に保存されます。

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

さらに、`last -Faiwx` コマンドはユーザーのログイン一覧を表示します。不明または予期しないログインがないか確認してください。

追加の特権を付与できるファイルを確認します。

- 予期しないユーザー特権が付与されていないか、`/etc/sudoers` を確認します。
- 予期しないユーザー特権が付与されていないか、`/etc/sudoers.d/` を確認します。
- 通常とは異なるグループメンバーシップや権限を特定するため、`/etc/groups` を調査します。
- 通常とは異なるグループメンバーシップや権限を特定するため、`/etc/passwd` を調査します。

一部のアプリも独自のログを生成します。

- **SSH**: 不正なリモート接続がないか、_\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を調査します。
- **Gnome Desktop**: Gnome アプリケーション経由で最近アクセスされたファイルを確認するため、_\~/.recently-used.xbel_ を調査します。
- **Firefox/Chrome**: 不審な活動がないか、_\~/.mozilla/firefox_ または _\~/.config/google-chrome_ のブラウザー履歴とダウンロードを確認します。
- **VIM**: アクセスしたファイルパスや検索履歴などの使用状況を確認するため、_\~/.viminfo_ を調査します。
- **Open Office**: 侵害されたファイルを示す可能性のある最近のドキュメントアクセスを確認します。
- **FTP/SFTP**: 不正なファイル転送がないか、_\~/.ftp_history_ または _\~/.sftp_history_ のログを確認します。
- **MySQL**: 実行された MySQL クエリを確認するため、_\~/.mysql_history_ を調査します。これにより、不正なデータベース活動が明らかになる可能性があります。
- **Less**: 表示したファイルや実行したコマンドなどの使用履歴を確認するため、_\~/.lesshst_ を分析します。
- **Git**: リポジトリへの変更を確認するため、_\~/.gitconfig_ とプロジェクトの _.git/logs_ を調査します。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) は、純粋な Python 3 で記述された小規模なソフトウェアであり、Linux のログファイル（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析して、USB イベント履歴テーブルを作成します。

**使用されたすべての USB を把握する**ことは重要です。また、"違反イベント"（そのリストに含まれていない USB の使用）を見つけるために、USB の認証済みリストがあると、さらに有用です。

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
github 内のその他の例と情報: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオンアクティビティの確認

_**/etc/passwd**_、_**/etc/shadow**_、および **security logs** を調査し、既知の不正なイベントの前後に作成または使用された、通常とは異なる名前やアカウントがないか確認します。また、sudo brute-force attacks の可能性も確認します。\
さらに、_**/etc/sudoers**_ や _**/etc/groups**_ などのファイルを確認し、ユーザーに予期しない権限が付与されていないか調べます。\
最後に、**no passwords** または **easily guessed** passwords のアカウントを探します。<sup>[[1]](#references)</sup>

## ファイルシステムの調査

### Malware Investigation におけるファイルシステム構造の分析

Malware incidents を調査する際、ファイルシステムの構造は重要な情報源となり、イベントの順序と malware の内容の両方を明らかにします。しかし、malware authors は、ファイルのタイムスタンプを変更したり、データの保存にファイルシステムを使用しないようにしたりするなど、この分析を妨げる技術を開発しています。<sup>[[1]](#references)</sup>

これらの anti-forensic methods に対抗するには、次のことが重要です。

- **Thorough timeline analysis を実施**し、イベントのタイムラインを可視化する **Autopsy** や、詳細なタイムラインデータを取得する **Sleuth Kit's** `mactime` などのツールを使用します。
- システムの $PATH にある **unexpected scripts** を調査します。これには、attackers が使用する shell または PHP scripts が含まれている可能性があります。
- **`/dev` にある atypical files を調査**します。通常は special files が含まれていますが、malware 関連の files が存在する場合もあります。
- ".. "（dot dot space）や "..^G"（dot dot control-G）のような名前を持つ **hidden files or directories** を検索します。これらは malicious content を隠している可能性があります。
- 次の command を使用して **setuid root files** を特定します: `find / -user root -perm -04000 -print` これは elevated permissions を持つ files を検出します。これらは attackers に悪用される可能性があります。
- inode tables の **deletion timestamps** を確認し、大量の file deletions がないか調べます。これは rootkits または trojans の存在を示している可能性があります。
- 1つの malicious file を特定した後、その近くにある **consecutive inodes** を調査します。これらは同じ場所に配置された可能性があります。
- **common binary directories**（_/bin_、_/sbin_）にある recently modified files を確認します。これらは malware によって変更された可能性があります。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker**は**time**を**modify**して**files appear**を**legitimate**に見せることができますが、**inode**を**modify**することはできません。ある**file**が、同じフォルダ内の他のすべてのfileと**同じtime**に作成および変更されたことを示しているにもかかわらず、**inode**が**予想外に大きい**場合、そのfileの**timestampsがmodify**されています。

### inodeに重点を置いた簡易トリアージ

anti-forensicsを疑う場合は、早い段階で次のinodeに重点を置いたチェックを実行します:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
疑わしい inode が EXT filesystem の image/device 上にある場合は、inode metadata を直接確認します:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: `0` の場合、現在 inode を参照しているディレクトリエントリはありません。
- **dtime**: inode が unlink されたときに設定される削除タイムスタンプ。
- **ctime/mtime**: メタデータやコンテンツの変更をインシデントのタイムラインと関連付けるのに役立ちます。

### Capabilities、xattrs、preload ベースの userland rootkits

Modern Linux persistence では、明らかな **setuid** バイナリを避け、代わりに **file capabilities**、**extended attributes**、および dynamic loader を悪用することがよくあります。
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
特に、`/tmp`、`/dev/shm`、`/var/tmp` などの **writable** なパスや、`/usr/local/lib` 配下の通常とは異なる場所から参照されるライブラリに注意してください。また、通常のパッケージ所有権の対象外にある capability 付きバイナリを確認し、パッケージ検証結果（`rpm -Va`、`dpkg --verify`、`debsums`）と関連付けてください。

## 異なる filesystem バージョンのファイルを比較する

### Filesystem バージョン比較の概要

Filesystem のバージョンを比較して変更点を特定するには、簡略化した `git diff` コマンドを使用します:<sup>[[3]](#references)</sup>

- **新しいファイルを見つけるには**、2つのディレクトリを比較します:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **変更されたコンテンツ**については、特定の行を無視して変更点を一覧表示してください。
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **削除されたファイルを検出するには**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options**（`--diff-filter`）を使用すると、追加（`A`）、削除（`D`）、変更（`M`）されたファイルなど、特定の変更に絞り込めます。
- `A`: 追加されたファイル
- `C`: コピーされたファイル
- `D`: 削除されたファイル
- `M`: 変更されたファイル
- `R`: 名前が変更されたファイル
- `T`: Type changes（例: ファイルから symlink への変更）
- `U`: マージされていないファイル
- `X`: 不明なファイル
- `B`: Broken files

## 参考文献

- [1] [Linux Systems向け Malware Forensics Field Guide: Digital Forensics Field Guides - Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logsの解説](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation - --diff-filter option](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary - persistenceのためのPatching: DripDropper Linux malwareがcloud内を移動する方法](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux JournalsのForensic Analysis](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - systemのAuditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [PikeにSay hi!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
