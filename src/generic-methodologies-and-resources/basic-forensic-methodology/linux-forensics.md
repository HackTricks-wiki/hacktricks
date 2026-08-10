# Linux Forensics

## Initial Information Gathering

### Basic Information

まず、**正常であることが確認されたバイナリとライブラリを入れた** **USB** を用意することを推奨します（Ubuntuを入手して、フォルダ _/bin_、_/sbin_、_/lib,_、_/lib64_ をコピーするだけで構いません）。次にUSBをマウントし、それらのバイナリを使用するように環境変数を変更します。
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
- shell を持たないユーザーの **password hashes** が `/etc/shadow` 内に存在しないか確認する

### Memory Dump

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) の使用が推奨されます。\
**compile** するには、victim machine が使用しているものと**同じ kernel**を使用する必要があります。

> [!TIP]
> victim machine に **LiME やその他のものを install することはできません**。install すると、victim machine に複数の変更が加えられるためです

そのため、Ubuntu の同一バージョンがある場合は、`apt-get install lime-forensics-dkms` を使用できます。\
それ以外の場合は、github から [**LiME**](https://github.com/504ensicsLabs/LiME) を download し、正しい kernel headers を使用して compile する必要があります。victim machine の**正確な kernel headers を取得**するには、`/lib/modules/<kernel version>` **directory をそのまま**自分の machine に copy し、それらを使用して LiME を **compile** します：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiMEは3つの**形式**をサポートします。

- Raw（すべてのセグメントを連結）
- Padded（Rawと同じですが、右側のビットをゼロで埋める）
- Lime（メタデータを含む推奨形式）

LiMEは、`path=tcp:4444`のように、システム上に保存する代わりに**ダンプをネットワーク経由で送信**するためにも使用できます。

### ディスクイメージング

#### シャットダウン

まず、システムを**シャットダウン**する必要があります。これは常に可能とは限りません。会社がシャットダウンを許容できない本番サーバーの場合があるためです。\
システムをシャットダウンする方法は**2つ**あります。**通常のシャットダウン**と、**「電源プラグを抜く」シャットダウン**です。前者では、**プロセスが通常どおり終了**し、**filesystem**が**同期**されますが、同時に、存在する可能性のある**malware**が**証拠を破壊**する機会も与えてしまいます。「電源プラグを抜く」方法では、**一部の情報が失われる可能性**があります（すでにメモリのイメージを取得しているため、失われる情報はそれほど多くありません）が、**malwareが何かをする機会はありません**。したがって、**malware**が存在する可能性を**疑っている**場合は、システム上で**`sync`** **コマンド**を実行してから、電源プラグを抜いてください。

#### ディスクのイメージを取得する

**ケースに関連するものへコンピューターを接続する前に**、情報の変更を避けるため、必ず**read onlyとしてマウントされる**ことを確認する必要があります。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

これ以上データが存在しないディスクイメージのイメージング。
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

Linux には、システムコンポーネントの整合性を確認するためのツールが用意されており、問題のある可能性があるファイルを発見するうえで重要です。<sup>[[1]](#references)</sup>

- **RedHat ベースのシステム**: `rpm -Va` を使用して包括的なチェックを実行します。
- **Debian ベースのシステム**: `dpkg --verify` で初期検証を行い、その後 `debsums | grep -v "OK$"` を実行します（`apt-get install debsums` で `debsums` をインストールしてから実行）。これにより問題を特定できます。

### Malware/Rootkit 検出ツール

Malware の発見に役立つツールについては、以下のページを読んでください。


{{#ref}}
malware-analysis.md
{{#endref}}

## インストール済みプログラムの検索

Debian と RedHat の両方のシステムでインストール済みプログラムを効果的に検索するには、一般的なディレクトリでの手動チェックと併せて、システムログとデータベースを活用します。<sup>[[1]](#references)</sup>

- Debian では、_**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を調査してパッケージのインストールに関する詳細を取得し、`grep` を使用して特定の情報を絞り込みます。
- RedHat ユーザーは、`rpm -qa --root=/mntpath/var/lib/rpm` で RPM データベースを照会し、インストール済みパッケージを一覧表示できます。

これらのパッケージマネージャーを使用せずに手動でインストールされたソフトウェアや、パッケージマネージャーの管理外にあるソフトウェアを見つけるには、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_ などのディレクトリを調査します。ディレクトリの一覧とシステム固有のコマンドを組み合わせて、既知のパッケージに関連付けられていない実行ファイルを特定し、インストール済みプログラムを網羅的に検索します。
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

/tmp/exec から実行された後に削除されたプロセスを想定してください。そこから抽出することが可能です
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## SQLite と FTS5 を使った Syscall Trace Triage

プロセスがまだ実行中であるか、lab で再実行できる場合、**`strace`** を使うと、kernel module や完全な EDR telemetry を必要とせず、迅速な挙動 trace を取得できます。大規模な trace では、raw log を直接読んだり LLM に貼り付けたりせず、**SQLite** database に保存し、必要最小限の subset のみを query してください。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> `strace` を attach するとプロセスの timing が変化し、race condition やその他の fragile な bug に影響する可能性があります。可能な場合は、copy/lab system 上での再現を優先してください。

### Capture

新しいプロセスの場合：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
実行中のプロセスの場合:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
便利なオプション:

- `-ff`: fork/thread を追跡し、プロセスごとの出力を保持
- `-ttt`: タイムラインの相関を容易にする epoch timestamps
- `-yy`: 可能な場合、file descriptor を対応するパスや socket に解決
- `-s 4096`: 長いパスや buffer 引数が切り詰められないようにする

### Normalize

実用的なスキーマでは、システムコールごと、および引数ごとに1行とします:
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
これにより、異種の syscall 行を単一の横長テーブルに無理に平坦化する必要がなくなり、triage 中の join も予測しやすくなります。

### FTS5 でテキスト量の多い引数をインデックス化する

大規模な trace で `LIKE "%...%"` を使って単純に path を探すと、非常に遅くなります。引数テキスト用の FTS5 インデックスを作成し、代わりにそれを検索します。
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
例: すべての行をスキャンせずに `/tmp` 下のファイルアクティビティを復元する:
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

- **PATH hijacking / fake sudo**: `~/.local/bin/` 配下への書き込みと `chmod`/`rename` の動作を検索し、その後の `sudo` のような特権を示唆する名前への `execve` と照合する。
- **TOCTOU on temporary files**: 同じ `/tmp/...` パスについて、`stat`、`access`、`openat`、`rename`、`unlink`、`link`、`symlink`、`execve` を横断して追跡し、check/use の間隙を特定する。
- **Crash root cause**: あるプロセスによる同じ inode/path の書き込みまたは切り詰めと、別のプロセスによるファイルの `mmap` を照合し、その後の signal/exit シーケンスを調べて `SIGBUS` を確認する。
- **Network destination recovery**: `connect`、`sendto`、`sendmsg`、`recvfrom` および socket 関連の引数をフィルタリングし、peer IP とポートを抽出する。

### LLM-assisted trace analysis

LLM に支援させる場合は、**read-only** の SQLite handle を公開し、完全な schema を与える。database を限定的な helper functions の背後に隠すのではなく、raw SQL を発行させるほうがよい。これは通常、join、temporal correlation、FTS lookup でうまく機能する。

実用上のルール:

- たとえば `sqlite3 'file:trace.db?mode=ro'` を使用して、database を read-only に保つ。
- 有効な `JOIN` および `FTS5 MATCH` query の例を model に与える。
- raw の数 GB に及ぶ `strace` log を prompt に貼り付けない。
- 次のような焦点を絞った質問をする:
- "この program が書き込んだ persistent file を一覧表示して。"
- "user-controlled PATH directory 内で executable を作成または置き換えたか？"
- "この trace が SIGBUS で終了する理由を説明して。"

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
#### Hunt: 0anacron と不審な stub を介した Cron/Anacron の悪用
攻撃者は、定期的な実行を確実にするため、各 /etc/cron.*/ ディレクトリに存在する 0anacron stub を編集することがよくあります。<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening のロールバックとバックドアシェル
sshd_config と system account の shell の変更は、アクセスを維持するための post-exploitation でよく行われます。<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2マーカー（Dropbox/Cloudflare Tunnel）
- Dropbox API beaconは通常、HTTPS経由で api.dropboxapi.com または content.dropboxapi.com を使用し、`Authorization: Bearer` tokenを付与します。
- proxy/Zeek/NetFlowで、サーバーから予期しないDropboxへのegressをHuntします。
- Cloudflare Tunnel（`cloudflared`）は、outbound 443経由のbackup C2を提供します。<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

malware が service としてインストールされる可能性のあるパス:

- **/etc/inittab**: rc.sysinit などの初期化スクリプトを呼び出し、さらに startup scripts へ処理を委譲します。
- **/etc/rc.d/** および **/etc/rc.boot/**: service startup 用の scripts を含みます。後者は古い Linux バージョンに存在します。
- **/etc/init.d/**: Debian などの特定の Linux バージョンで、startup scripts の保存に使用されます。
- Linux variant によっては、**/etc/inetd.conf** または **/etc/xinetd/** 経由で service を有効化することもできます。
- **/etc/systemd/system**: system および service manager scripts 用のディレクトリです。
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel で起動すべき service への links を含みます。
- **/usr/local/etc/rc.d/**: custom または third-party service 用です。
- **\~/.config/autostart/**: user-specific な automatic startup applications 用で、user-targeted malware の隠し場所になる可能性があります。
- **/lib/systemd/system/**: インストールされた packages が提供する system-wide default unit files 用です。

#### 調査: systemd timers と transient units

systemd persistence は `.service` files に限定されません。`.timer` units、user-level units、および runtime に作成された **transient units** を調査してください。
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
Transient units は `/run/systemd/transient/` が**非永続的**であるため、見落としやすいものです。live image を収集する場合は、シャットダウン前に取得してください。

### Kernel Modules

Linux kernel modules は、rootkit コンポーネントとして malware によって利用されることが多く、システム起動時にロードされます。これらのモジュールにとって重要なディレクトリとファイルは次のとおりです。

- **/lib/modules/$(uname -r)**: 実行中の kernel version 用のモジュールを保持します。
- **/etc/modprobe.d**: モジュールのロードを制御する configuration files が含まれます。
- **/etc/modprobe** および **/etc/modprobe.conf**: global module settings 用のファイルです。

### Other Autostart Locations

Linux では、user login 時にプログラムを自動実行するさまざまなファイルが使用されており、malware が潜んでいる可能性があります。

- **/etc/profile.d/**\*、**/etc/profile**、および **/etc/bash.bashrc**: あらゆる user の login 時に実行されます。
- **\~/.bashrc**、**\~/.bash_profile**、**\~/.profile**、および **\~/.config/autostart**: user ごとの login 時に実行されるファイルです。
- **/etc/rc.local**: すべての system services の起動後に実行され、multiuser environment への移行の終了を示します。

## Examine Logs

Linux systems は、さまざまな log files を通じて user activities と system events を記録します。これらの logs は、unauthorized access、malware infections、その他の security incidents を特定するうえで重要です。<sup>[[2]](#references)</sup> 主な log files は次のとおりです。

- **/var/log/syslog** (Debian) または **/var/log/messages** (RedHat): system-wide messages と activities を記録します。
- **/var/log/auth.log** (Debian) または **/var/log/secure** (RedHat): authentication attempts、successful and failed logins を記録します。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使用して、関連する authentication events を抽出します。
- **/var/log/boot.log**: system startup messages が含まれます。
- **/var/log/maillog** または **/var/log/mail.log**: email server activities を記録し、email-related services の追跡に役立ちます。
- **/var/log/kern.log**: errors や warnings を含む kernel messages を保存します。
- **/var/log/dmesg**: device driver messages を保持します。
- **/var/log/faillog**: failed login attempts を記録し、security breach investigations に役立ちます。
- **/var/log/cron**: cron job executions を記録します。
- **/var/log/daemon.log**: background service activities を追跡します。
- **/var/log/btmp**: failed login attempts を記録します。
- **/var/log/httpd/**: Apache HTTPD の error and access logs が含まれます。
- **/var/log/mysqld.log** または **/var/log/mysql.log**: MySQL database activities を記録します。
- **/var/log/xferlog**: FTP file transfers を記録します。
- **/var/log/**: 予期しない logs がないか、必ず確認してください。

> [!TIP]
> Linux system logs と audit subsystems は、intrusion または malware incident の際に無効化または削除されている可能性があります。Linux systems の logs には一般に、malicious activities に関する最も有用な情報が含まれているため、intruders は日常的にこれらを削除します。そのため、利用可能な log files を調査する際は、削除または tampering の兆候である可能性がある、欠落や順序が不自然な entries がないか確認することが重要です。

### Journald triage (`journalctl`)

現代の Linux hosts では、**systemd journal** は通常、**service execution**、**auth events**、**package operations**、**kernel/user-space messages** に関する最も価値の高い source です。live response 中は、**persistent** journal (`/var/log/journal/`) と **runtime** journal (`/run/log/journal/`) の両方を保持するようにしてください。攻撃者による短時間の activity は、後者にしか存在しない可能性があるためです。<sup>[[5]](#references)</sup>
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
トリアージに役立つ journal フィールドには、`_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID`、`MESSAGE` があります。journald が永続ストレージなしで構成されている場合は、`/run/log/journal/` 配下に最近のデータしかないことを想定してください。

### Audit framework のトリアージ（`auditd`）

`auditd` が有効な場合、ファイル変更、コマンド実行、ログインアクティビティ、パッケージインストールについて**プロセスの帰属を特定**する必要があるときは、常に `auditd` を優先してください。<sup>[[6]](#references)</sup>
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
ルールがキーを使ってデプロイされていた場合は、生ログをgrepするのではなく、そこからpivotする：
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

また、`last -Faiwx` command はユーザーの login 一覧を提供します。不明な login や予期しない login がないか確認してください。

追加の privileges を付与できるファイルを確認します。

- 予期しない user privileges が付与されていないか、`/etc/sudoers` を確認します。
- 予期しない user privileges が付与されていないか、`/etc/sudoers.d/` を確認します。
- `/etc/groups` を調べ、通常とは異なる group memberships や permissions を特定します。
- `/etc/passwd` を調べ、通常とは異なる group memberships や permissions を特定します。

一部の apps は独自の logs も生成します。

- **SSH**: 不正な remote connections がないか、_\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を調べます。
- **Gnome Desktop**: Gnome applications 経由で最近アクセスされた files を確認するため、_\~/.recently-used.xbel_ を調べます。
- **Firefox/Chrome**: 不審な activities がないか、_\~/.mozilla/firefox_ または _\~/.config/google-chrome_ の browser history と downloads を確認します。
- **VIM**: アクセスした file paths や search history などの usage details を確認するため、_\~/.viminfo_ を調べます。
- **Open Office**: compromised files を示す可能性がある、最近の document access を確認します。
- **FTP/SFTP**: unauthorized な file transfers がないか、_\~/.ftp_history_ または _\~/.sftp_history_ の logs を確認します。
- **MySQL**: 実行された MySQL queries を確認するため、_\~/.mysql_history_ を調査します。これにより、unauthorized な database activities が明らかになる可能性があります。
- **Less**: 表示された files や実行された commands などの usage history を確認するため、_\~/.lesshst_ を分析します。
- **Git**: repositories への変更を確認するため、_\~/.gitconfig_ と project の _.git/logs_ を調べます。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) は、pure Python 3 で書かれた小規模な software であり、Linux log files（distro に応じて `/var/log/syslog*` または `/var/log/messages*`）を解析して、USB event history tables を構築します。

**使用されたすべての USB を把握する**ことは有用です。また、"violation events"（その list に含まれていない USB の使用）を特定するために、authorized な USB の list があるとさらに便利です。

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
github内にさらに多くの例と情報があります: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオンアクティビティを確認する

既知の不正イベントの前後に作成または使用された、通常とは異なる名前やアカウントがないか、_**/etc/passwd**_、_**/etc/shadow**_、および **security logs** を調査します。また、sudo brute-force attacks の可能性も確認します。\
さらに、ユーザーに予期しない権限が付与されていないか、_**/etc/sudoers**_ や _**/etc/groups**_ などのファイルを確認します。\
最後に、**パスワードが設定されていない**、または**容易に推測できる**パスワードを持つアカウントを探します。<sup>[[1]](#references)</sup>

## File System を調査する

### Malware Investigation における File System Structures の分析

Malware incidents を調査する際、file system の構造は重要な情報源であり、イベントの順序と malware の内容の両方を明らかにします。しかし、malware authors は、file timestamps の変更やデータ保存に file system を使用しないなど、この分析を妨げる techniques を開発しています。<sup>[[1]](#references)</sup>

これらの anti-forensic methods に対抗するには、以下が重要です。

- **Autopsy** などの tools を使用してイベント timeline を可視化したり、**Sleuth Kit** の `mactime` で詳細な timeline data を取得したりして、**徹底的な timeline analysis を実施する**。
- 攻撃者が使用する shell や PHP scripts が含まれている可能性があるため、system の $PATH 内にある**予期しない scripts を調査する**。
- 通常、`/dev` には special files が含まれていますが、malware 関連の files が存在する可能性もあるため、**`/dev` にある非典型的な files を調査する**。
- 悪意のある content を隠している可能性があるため、".. "（dot dot space）や "..^G"（dot dot control-G）のような名前を持つ**hidden files や directories を検索する**。
- `find / -user root -perm -04000 -print` コマンドを使用して **setuid root files を特定する**。これは elevated permissions を持つ files を検出するもので、攻撃者に悪用される可能性があります。
- 大量の file deletions を発見するため、inode tables の**deletion timestamps を確認する**。これは rootkits や trojans の存在を示している可能性があります。
- 1つの悪意のある file を特定した後、その近くにある**連続した inodes を調査する**。それらは同時に配置された可能性があります。
- 最近 modified された files がないか、common binary directories（_/bin_、_/sbin_）を**確認する**。これらは malware によって変更された可能性があります。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker** は **time** を **modify** して **files appear** **legitimate** に見せることができますが、**inode** を **modify** することはできません。同じフォルダ内の他のファイルと**同じ time** に作成・変更されたことを示す **file** があり、**inode** が**予想外に大きい**場合、そのファイルの **timestamps** は **modified** されています。

### Inode-focused quick triage

anti-forensics を疑う場合は、早い段階で次の inode-focused checks を実行します。
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
疑わしい inode が EXT filesystem の image/device 上にある場合は、inode metadata を直接調査します。
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
Useful fields:
- **Links**: `0` の場合、現在その inode を参照しているディレクトリエントリはありません。
- **dtime**: inode の unlink 時に設定される削除タイムスタンプです。
- **ctime/mtime**: メタデータやコンテンツの変更をインシデントのタイムラインと関連付けるのに役立ちます。

### Capabilities、xattrs、preload-based userland rootkits

Modern Linux の persistence では、明らかな **setuid** バイナリを避け、代わりに **file capabilities**、**extended attributes**、および dynamic loader を悪用することがよくあります。
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
特に、`/tmp`、`/dev/shm`、`/var/tmp`、または `/usr/local/lib` 配下の通常とは異なる場所など、**writable** なパスから参照される libraries に注意してください。また、通常の package ownership の対象外にある capability-bearing binaries を確認し、package verification の結果（`rpm -Va`、`dpkg --verify`、`debsums`）と照合してください。

## 異なる filesystem version の files を比較する

### Filesystem Version Comparison の概要

filesystem version を比較して変更点を特定するには、簡略化した `git diff` コマンドを使用します:<sup>[[3]](#references)</sup>

- **新しい files を見つけるには**、2つの directories を比較します:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **変更されたコンテンツ**については、特定の行を無視して変更点を一覧表示します：
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
- `T`: Type changes（例：ファイルからシンボリックリンクへの変更）
- `U`: マージされていないファイル
- `X`: 不明なファイル
- `B`: 壊れたファイル

## References

- [1] [Linuxシステム向けMalware Forensics Field Guide: Digital Forensics Field Guides – Chapter 3](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux Logsの解説](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff Documentation – --diff-filterオプション](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – persistenceのためのPatching: DripDropper Linux malwareがcloud内を移動する方法](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux JournalsのForensic Analysis](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - システムのAuditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [PikeにSay hi!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)
{{#include ../../banners/hacktricks-training.md}}
