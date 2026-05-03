# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 初期情報収集

### 基本情報

まず最初に、**既知の正常なバイナリとライブラリ**を入れた**USB**を用意することをおすすめします（Ubuntu を入手して、_ /bin_、_ /sbin_、_ /lib,_、_ /lib64_ の各フォルダをコピーすればよいです）。その後、USB をマウントし、環境変数を変更してそれらのバイナリを使うようにします:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムを良質で既知のバイナリを使うように設定したら、**いくつかの基本情報を抽出**し始められます:
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

基本情報を取得する際は、次のような不自然な点を確認すべきです:

- **Root processes** は通常、低いPIDで動作するので、PIDが大きい root process を見つけたら疑うべきです
- `/etc/passwd` 内で、shell のないユーザーの **registered logins** を確認する
- shell のないユーザーについて、`/etc/shadow` 内の **password hashes** を確認する

### Memory Dump

実行中システムの memory を取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) を使うのがおすすめです。\
**compile** するには、被害マシンが使用しているのと**同じ kernel** を使う必要があります。

> [!TIP]
> **LiME やその他のものを被害マシンにインストールしてはいけない**ことを覚えておいてください。多くの変更が加わってしまいます

そのため、同じバージョンの Ubuntu があるなら、`apt-get install lime-forensics-dkms` を使えます\
それ以外の場合は、github から [**LiME**](https://github.com/504ensicsLabs/LiME) をダウンロードし、正しい kernel headers で compile する必要があります。被害マシンの**正確な kernel headers** を入手するには、`/lib/modules/<kernel version>` ディレクトリを自分のマシンに**コピー**し、それを使って LiME を**compile** します:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME は 3 つの **formats** をサポートします:

- Raw (すべてのセグメントを連結したもの)
- Padded (raw と同じだが、右側のビットがゼロ埋めされる)
- Lime (メタデータ付きの推奨 format)

LiME は、システム上に保存する代わりに、`path=tcp:4444` のようにして **ネットワーク経由で dump を送信する** こともできます

### Disk Imaging

#### Shutting down

まず最初に、**システムをシャットダウンする** 必要があります。これは常に可能とは限りません。というのも、システムが会社として停止できない production server の場合があるからです。\
システムを停止する方法は **2 つ** あり、**通常の shutdown** と、**"plug the plug" shutdown** です。前者では **processes** は通常どおり終了し、**filesystem** も **同期** されますが、**malware** が証拠を**破壊する**可能性も残ります。`pull the plug` 方式では、**ある程度の情報損失** が起こるかもしれません（memory の image はすでに取得しているので、失われる情報は多くありません）が、**malware に何かをする機会は与えません**。したがって、**malware** がいると**疑う**場合は、システム上で **`sync`** **command** を実行してから、プラグを抜いてください。

#### Taking an image of the disk

注意すべき重要な点として、**ケースに関連するものへ自分の computer を接続する前に**、情報を変更しないように、それが **read only** で **mount** されることを必ず確認する必要があります。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前分析

それ以上のデータを追加せずにディスクイメージを作成する。
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
## known Malware を探す

### 変更されたシステムファイル

Linux には、システムコンポーネントの整合性を確認するためのツールがあり、問題のある可能性のあるファイルを見つけるのに重要です。

- **RedHat-based systems**: 包括的なチェックには `rpm -Va` を使用します。
- **Debian-based systems**: まず `dpkg --verify` で検証し、その後 `debsums | grep -v "OK$"`（`apt-get install debsums` で `debsums` をインストールした後）を使って問題を特定します。

### Malware/Rootkit Detectors

以下のページを読んで、malware を見つけるのに役立つツールを学んでください:


{{#ref}}
malware-analysis.md
{{#endref}}

## インストール済みプログラムを探す

Debian と RedHat の両方でインストール済みプログラムを効果的に探すには、一般的なディレクトリの手動確認に加えて、システムログとデータベースを活用することを検討してください。

- Debian では、_**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を確認してパッケージのインストール詳細を取得し、`grep` で特定の情報を絞り込みます。
- RedHat ユーザーは `rpm -qa --root=/mntpath/var/lib/rpm` で RPM データベースを照会し、インストール済みパッケージを一覧表示できます。

パッケージマネージャー経由ではなく手動で、またはそれ以外の方法でインストールされたソフトウェアを見つけるには、_**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、および _**`/sbin`**_ のようなディレクトリを調べます。ディレクトリ一覧とシステム固有のコマンドを組み合わせて、既知のパッケージに関連付けられていない実行ファイルを特定し、インストール済みプログラム全体の調査を強化します。
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

/tmp/exec から実行された後に削除されたプロセスを想像してください。それを抽出することは可能です
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Syscall Trace Triage with SQLite and FTS5

プロセスがまだ実行中、または lab で再実行できる場合、**`strace`** は kernel modules や完全な EDR telemetry を必要とせずに、素早い behavioral trace を取得できます。大きな trace では、raw log を直接読んだり LLM に貼り付けたりせず、**SQLite** database に保存して、必要な最小限の subset だけを query してください。

> [!WARNING]
> `strace` を attach すると process timing が変わり、race conditions や他の fragile bugs に影響する可能性があります。可能なら copy/lab system で再現することを優先してください。

### Capture

新しい process については:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
ライブプロセスの場合:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
役立つオプション:

- `-ff`: forks/threads を追跡し、プロセスごとの出力を保持する
- `-ttt`: タイムライン相関を সহজにする epoch timestamp
- `-yy`: 可能な場合は file descriptor を backing path/socket に解決する
- `-s 4096`: 長い path と buffer 引数が切り捨てられるのを防ぐ

### Normalize

実用的な schema は、syscall ごとに1行、argument ごとに1行:
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
これは、異なる種類の syscall 行を 1 つの横長テーブルに無理にフラット化しようとするのを避け、トリアージ中の join を予測可能に保ちます。

### 文字量の多い引数は FTS5 でインデックス化する

`LIKE "%...%"` を使った素朴なパス探索は、大きな trace では非常に遅くなります。代わりに、引数テキスト用の FTS5 インデックスを作成して検索します:
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
例: `/tmp` 配下のファイル活動を、すべての行をスキャンせずに復元する:
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### 高シグナル調査

- **PATH hijacking / fake sudo**: `~/.local/bin/` 配下の書き込みと `chmod`/`rename` の動作を調べ、その後に `sudo` のような特権っぽい名前への `execve` を相関させる。
- **TOCTOU on temporary files**: 同じ `/tmp/...` パスについて `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, `execve` をまたいで追跡し、check/use のギャップを特定する。
- **Crash root cause**: あるファイルの `mmap` と、別プロセスによる同じ inode/path への書き込みまたは truncation を相関させ、その後の signal/exit シーケンスで `SIGBUS` を確認する。
- **Network destination recovery**: `connect`, `sendto`, `sendmsg`, `recvfrom` と socket 関連の引数を絞り込み、peer の IP と port を抽出する。

### LLM-assisted trace analysis

LLM に補助させたい場合は、**read-only** の SQLite handle を公開し、完全な schema を渡す。ラッパー関数で database を狭く隠すより、raw SQL を直接実行させるほうがよい。これにより、JOIN、時間相関、FTS lookup がうまくいくことが多い。

実用ルール:

- database は read-only に保つ。例えば `sqlite3 'file:trace.db?mode=ro'` を使う。
- 有効な `JOIN` と `FTS5 MATCH` query の例をモデルに示す。
- 生の multi-GB の `strace` log を prompt に貼らない。
- 次のように焦点を絞った質問をする:
- "この program によって書き込まれた persistent files を列挙して。"
- "user-controlled PATH directories に executables を作成または置き換えたか?"
- "この trace が SIGBUS で終わる理由を説明して。"

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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
攻撃者は、定期的な実行を確実にするために、各 /etc/cron.*/ ディレクトリにある 0anacron スタブを編集することがよくあります。
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config とシステムアカウントのシェル変更は、アクセスを維持するための post‑exploitation でよく行われます。
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API のビーコンは通常、HTTPS 経由で api.dropboxapi.com または content.dropboxapi.com を使用し、Authorization: Bearer トークンを伴います。
- proxy/Zeek/NetFlow で、サーバーからの予期しない Dropbox への egress をハントします。
- Cloudflare Tunnel (`cloudflared`) は、outbound 443 経由でバックアップ C2 を提供します。
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

マルウェアがサービスとして設置される可能性のあるパス:

- **/etc/inittab**: rc.sysinit のような初期化スクリプトを呼び出し、さらに startup scripts へとつなぐ。
- **/etc/rc.d/** および **/etc/rc.boot/**: サービス起動用のスクリプトを含む。後者は古い Linux バージョンで見られる。
- **/etc/init.d/**: Debian など特定の Linux バージョンで startup scripts を保存するために使われる。
- サービスは Linux の種類に応じて **/etc/inetd.conf** または **/etc/xinetd/** 経由でも有効化されることがある。
- **/etc/systemd/system**: system と service manager のスクリプト用ディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel で起動すべきサービスへのリンクを含む。
- **/usr/local/etc/rc.d/**: カスタムまたはサードパーティ製のサービス向け。
- **\~/.config/autostart/**: ユーザー固有の自動起動アプリケーション向けで、ユーザーを狙った malware の隠し場所になりうる。
- **/lib/systemd/system/**: インストール済みパッケージが提供する system-wide のデフォルト unit files。

#### Hunt: systemd timers and transient units

Systemd persistence は `.service` files に限られない。`.timer` units、user-level units、そして実行時に作成される **transient units** を調査する。
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
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: 実行中のkernel version用のmodulesを保持する。
- **/etc/modprobe.d**: module loadingを制御する設定ファイルを含む。
- **/etc/modprobe** and **/etc/modprobe.conf**: global module settings用のファイル。

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: 任意のuser login時に実行される。
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: login時に実行されるユーザー固有のファイル。
- **/etc/rc.local**: すべてのsystem services起動後に実行され、multiuser environmentへの移行の終わりを示す。

## ログの確認

Linux systemsは、さまざまなlog fileを通じてuser activitiesとsystem eventsを追跡する。これらのlogsは、unauthorized access、malware infections、その他のsecurity incidentsを特定するうえで重要である。主なlog filesは以下のとおり:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): system-wide messagesとactivitiesを記録する。
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): authentication attempts、成功および失敗したloginを記録する。
- `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` を使って、関連するauthentication eventsを絞り込む。
- **/var/log/boot.log**: system startup messagesを含む。
- **/var/log/maillog** or **/var/log/mail.log**: email server activitiesを記録し、email-related servicesの追跡に役立つ。
- **/var/log/kern.log**: errorsやwarningsを含むkernel messagesを保存する。
- **/var/log/dmesg**: device driver messagesを保持する。
- **/var/log/faillog**: failed login attemptsを記録し、security breach investigationsを支援する。
- **/var/log/cron**: cron job executionsを記録する。
- **/var/log/daemon.log**: background service activitiesを追跡する。
- **/var/log/btmp**: failed login attemptsを記録する。
- **/var/log/httpd/**: Apache HTTPD error logsとaccess logsを含む。
- **/var/log/mysqld.log** or **/var/log/mysql.log**: MySQL database activitiesを記録する。
- **/var/log/xferlog**: FTP file transfersを記録する。
- **/var/log/**: ここにあるunexpected logsを常に確認する。

> [!TIP]
> Linux system logsとaudit subsystemsは、intrusionやmalware incidentの際に無効化または削除されることがある。Linux systems上のlogsには通常、悪意ある活動に関する非常に有用な情報が含まれているため、intrudersはそれらを routine に削除する。したがって、利用可能なlog filesを調べる際は、削除や改ざんを示す可能性のある、欠落や順序が前後したエントリに注意して見ることが重要である。

### Journald triage (`journalctl`)

Modern Linux hostsでは、**systemd journal**は通常、**service execution**、**auth events**、**package operations**、および**kernel/user-space messages**にとって最も価値の高い情報源である。live responseでは、**persistent** journal (`/var/log/journal/`) と **runtime** journal (`/run/log/journal/`) の両方を保全するように試みるべきである。短時間だけ存在するattacker activityは後者にしか残らない場合がある。
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
トリアージに役立つ journal のフィールドには `_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID`、および `MESSAGE` が含まれます。`journald` が永続ストレージなしで設定されていた場合、`/run/log/journal/` 配下には最近のデータのみがあると考えてください。

### Audit framework triage (`auditd`)

`auditd` が有効なら、ファイル変更、コマンド実行、ログイン活動、またはパッケージインストールに対する **process attribution** が必要なときは、常にそれを優先してください。
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
キー付きでルールが展開されている場合は、生のログをgrepする代わりにそこからpivotしてください:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux は各ユーザーごとにコマンド履歴を保持します**。保存先は次のとおりです:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

また、`last -Faiwx` コマンドはユーザーのログイン一覧を提供します。未知の、または予期しないログインがないか確認してください。

追加の rprivileges を付与しうるファイルを確認します:

- `/etc/sudoers` を見直し、付与された可能性のある想定外のユーザー権限がないか確認する。
- `/etc/sudoers.d/` を見直し、付与された可能性のある想定外のユーザー権限がないか確認する。
- `/etc/groups` を調べ、異常なグループ所属や権限がないか特定する。
- `/etc/passwd` を調べ、異常なグループ所属や権限がないか特定する。

一部のアプリも独自のログを生成します:

- **SSH**: 不正なリモート接続がないか _\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を確認する。
- **Gnome Desktop**: Gnome アプリケーション経由で最近アクセスされたファイルを _\~/.recently-used.xbel_ で確認する。
- **Firefox/Chrome**: ブラウザの履歴とダウンロードを _\~/.mozilla/firefox_ または _\~/.config/google-chrome_ で確認し、不審な活動がないか調べる。
- **VIM**: アクセスしたファイルパスや検索履歴などの使用詳細を _\~/.viminfo_ で確認する。
- **Open Office**: 侵害されたファイルを示す可能性のある最近の文書アクセスを確認する。
- **FTP/SFTP**: 不正な可能性があるファイル転送について、_~/.ftp_history_ または _\~/.sftp_history_ のログを確認する。
- **MySQL**: 実行された MySQL クエリについて _\~/.mysql_history_ を調査し、不正なデータベース活動を示していないか確認する。
- **Less**: 表示したファイルや実行したコマンドを含む使用履歴を _\~/.lesshst_ で分析する。
- **Git**: リポジトリへの変更について _\~/.gitconfig_ とプロジェクトの _.git/logs_ を確認する。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) は、Linux のログファイル（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析して USB イベント履歴テーブルを構築する、純粋な Python 3 で書かれた小さなソフトウェアです。

**使用されたすべての USB を把握しておく**ことは有益であり、許可された USB の一覧があれば、その一覧に含まれない USB の使用、つまり「violation events」を見つけるうえでさらに役立ちます。

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
github 内のより多くの例と情報: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオン活動を確認する

_**/etc/passwd**_、_**/etc/shadow**_、および **security logs** を調べ、既知の不正アクセス事象の直前または近接して作成・使用された不審な名前やアカウントがないか確認します。加えて、sudo のブルートフォース攻撃の可能性も確認します。\
さらに、_**/etc/sudoers**_ や _**/etc/groups**_ のようなファイルを確認し、ユーザーに対して予期しない権限が付与されていないか調べます。\
最後に、**パスワードなし**、または**容易に推測できる**パスワードを持つアカウントを探します。

## ファイルシステムを調べる

### マルウェア調査におけるファイルシステム構造の分析

マルウェア事案を調査する際、ファイルシステムの構造は重要な情報源であり、事象の時系列とマルウェアの内容の両方を明らかにします。しかし、マルウェア作者は、ファイルタイムスタンプの改ざんや、データ保存にファイルシステムを使わないなど、こうした分析を妨げる手法を発展させています。

これらの anti-forensic 手法に対抗するには、以下が重要です。

- **Autopsy** のようなツールで事象のタイムラインを可視化する、または **Sleuth Kit** の `mactime` で詳細なタイムラインデータを得るなど、**徹底したタイムライン分析を行う**。
- 攻撃者が使った可能性のある shell や PHP スクリプトを含むかもしれない、システムの $PATH 内の**予期しないスクリプトを調査する**。
- 伝統的には special files を含むが、マルウェア関連ファイルを置かれている可能性もあるため、**`/dev` 内の異常なファイルを調べる**。
- ".. "（dot dot space）や "..^G"（dot dot control-G）のような名前の**隠しファイルやディレクトリを探す**。これは悪意あるコンテンツを隠している可能性がある。
- 次のコマンドを使って **setuid root files を特定する**: `find / -user root -perm -04000 -print` これは、攻撃者に悪用されうる高権限のファイルを見つけます。
- inode テーブルの**削除タイムスタンプを確認する**。大量削除が見つかれば、rootkits や trojans の存在を示している可能性があります。
- 1つ見つけたあと、近くにある悪意あるファイルの可能性があるものを探すために、**連続する inode を調べる**。まとめて配置されていることがあるためです。
- 最近変更されたファイルとして、**一般的な binary ディレクトリ**（_/bin_、_/sbin_）を**確認する**。マルウェアによって改ざんされている可能性があります。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker** は **time** を **modify** して **files appear** を **legitimate** に見せかけることはできますが、**inode** を **modify** することはできません。ある **file** が、同じフォルダ内の他のファイルと同じ **time** に作成・修正されたことを示しているのに、**inode** が **unexpectedly bigger** であれば、その **file** の **timestamps were modified** されています。

### Inode-focused quick triage

anti-forensics が疑われる場合は、早い段階で次の inode-focused チェックを実行してください:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
EXT ファイルシステムのイメージ/デバイス上に疑わしい inode がある場合は、inode メタデータを直接調べます:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
有用なフィールド:
- **Links**: `0` の場合、現在その inode を参照しているディレクトリエントリはありません。
- **dtime**: inode が unlink されたときに設定される削除タイムスタンプ。
- **ctime/mtime**: メタデータ/コンテンツの変更をインシデントのタイムラインと照合するのに役立ちます。

### Capabilities, xattrs, and preload-based userland rootkits

現代の Linux の永続化は、明白な **setuid** バイナリを避け、代わりに **file capabilities**、**extended attributes**、および dynamic loader を悪用することが多いです。
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
**書き込み可能な**パス、たとえば `/tmp`、`/dev/shm`、`/var/tmp`、または `/usr/local/lib` 配下の不自然な場所から参照されるライブラリには特に注意してください。また、通常のパッケージ所有範囲外にある capability-bearing binaries も確認し、それらをパッケージ検証結果（`rpm -Va`、`dpkg --verify`、`debsums`）と照合してください。

## 異なる filesystem バージョンのファイルを比較する

### Filesystem Version 比較の概要

filesystem のバージョンを比較して変更点を特定するには、簡略化した `git diff` コマンドを使います:

- **新しいファイルを見つけるには**、2 つのディレクトリを比較します:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **変更されたコンテンツについては、特定の行を無視しながら変更点を सूचीする:**
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **削除されたファイルを検出するには**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) は、追加 (`A`)、削除 (`D`)、または変更 (`M`) されたファイルなど、特定の変更に絞り込むのに役立ちます。
- `A`: 追加されたファイル
- `C`: コピーされたファイル
- `D`: 削除されたファイル
- `M`: 変更されたファイル
- `R`: 名前変更されたファイル
- `T`: Type changes (e.g., file to symlink)
- `U`: 未マージのファイル
- `X`: 不明なファイル
- `B`: Broken files

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
