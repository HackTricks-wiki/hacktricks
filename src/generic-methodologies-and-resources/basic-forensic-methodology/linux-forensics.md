# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 初期情報収集

### 基本情報

まず、**信頼できる既知の binaries と libraries** を入れた **USB** を用意しておくことをおすすめします（ubuntu を入手して、_ /bin_、_ /sbin_、_ /lib,_、_ /lib64_ のフォルダをコピーするだけでよいです）。その後、USB をマウントして、env variables を修正し、それらの binaries を使うようにします:
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
システムを良好で既知の binaries を使うように設定したら、**いくつかの基本情報の抽出**を始められます:
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
#### 不審な情報

基本情報を取得する際は、次のような怪しい点を確認してください:

- **Rootプロセス**は通常、低いPIDで実行されるため、PIDが大きいrootプロセスを見つけたら疑うべきです
- `/etc/passwd` 内で、shell を持たないユーザーの **登録済みログイン** を確認する
- shell を持たないユーザーについて、`/etc/shadow` 内の **password hashes** を確認する

### Memory Dump

実行中のシステムのメモリを取得するには、[**LiME**](https://github.com/504ensicsLabs/LiME) の使用が推奨されます。\
**コンパイル**するには、被害マシンが使用しているのと**同じ kernel** を使う必要があります。

> [!TIP]
> **LiME やその他のものを被害マシンにインストールしてはいけない**ことを忘れないでください。システムにさまざまな変更を加えてしまうからです

したがって、同じバージョンの Ubuntu があれば `apt-get install lime-forensics-dkms` を使えます\
それ以外の場合は、github から [**LiME**](https://github.com/504ensicsLabs/LiME) をダウンロードし、正しい kernel headers でコンパイルする必要があります。被害マシンの**正確な kernel headers** を入手するには、単に `/lib/modules/<kernel version>` ディレクトリを自分のマシンに**コピー**し、それを使って LiME を**コンパイル**します:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME は 3 つの **formats** をサポートしています:

- Raw (すべての segment を連結したもの)
- Padded (raw と同じだが、右側の bit が zeroes)
- Lime (metadata 付きの推奨 format)

LiME は、システムに保存する代わりに `path=tcp:4444` のような方法で **dump を network 経由で送信** するためにも使えます。

### Disk Imaging

#### Shutting down

まず最初に、**システムを shut down** する必要があります。これは常に可能とは限りません。場合によっては、会社が shut down できない production server であることもあります。\
**system** を shut down する方法は **2 つ** あります。**normal shutdown** と **"plug the plug" shutdown** です。前者では、**processes** は通常どおり終了し、**filesystem** も **synchronized** されますが、**malware** が **evidence** を破壊する可能性も許してしまいます。 "pull the plug" 方式では、**some information loss** が起こる可能性があります（memory の image はすでに取得済みなので、失われる情報はそれほど多くありません）が、**malware** に何かをされる機会は与えません。したがって、**malware** がいると**疑う**なら、システム上で **`sync`** **command** を実行してから pull the plug してください。

#### Taking an image of the disk

**case** に関係するものへ **computer** を接続する前に、それが **read only** として **mounted** され、いかなる情報も変更しないことを必ず確認する必要がある、という点に注意することが重要です。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### ディスクイメージの事前解析

これ以上データを増やさずにディスクイメージを作成する。
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
## 既知のMalwareを検索する

### 変更されたシステムファイル

Linuxは、システムコンポーネントの整合性を確認するためのツールを提供しており、問題のある可能性があるファイルを見つけるうえで重要です。

- **RedHat系システム**: 包括的なチェックには `rpm -Va` を使用します。
- **Debian系システム**: まず `dpkg --verify` で検証し、その後 `debsums | grep -v "OK$"`（`apt-get install debsums` で `debsums` をインストールした後）を使って問題を特定します。

### Malware/Rootkit Detectors

以下のページを読んで、malwareの検出に役立つツールについて学んでください:


{{#ref}}
malware-analysis.md
{{#endref}}

## インストール済みプログラムを検索する

DebianとRedHatの両方のシステムでインストール済みプログラムを効率的に検索するには、一般的なディレクトリの手動確認に加えて、システムログとデータベースを活用することを検討してください。

- Debianでは、パッケージのインストール詳細を取得するために _**`/var/lib/dpkg/status`**_ と _**`/var/log/dpkg.log`**_ を確認し、`grep` を使って特定の情報を絞り込みます。
- RedHatユーザーは `rpm -qa --root=/mntpath/var/lib/rpm` でRPMデータベースを問い合わせ、インストール済みパッケージを一覧表示できます。

パッケージマネージャー経由ではなく手動で、または別の方法でインストールされたソフトウェアを見つけるには、 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_、_**`/sbin`**_ などのディレクトリを調べてください。ディレクトリ一覧表示とシステム固有のコマンドを組み合わせることで、既知のパッケージに関連付けられていない実行ファイルを特定し、インストール済みプログラム全体の検索を強化できます。
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

/tmp/exec から実行されたプロセスがその後削除されたと想像してください。それを抽出することは可能です
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## Autostart の場所を確認する

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
攻撃者は、定期的な実行を確実にするために、各 /etc/cron.*/ ディレクトリに存在する 0anacron stub を編集することがよくあります。
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
sshd_config と system account の shells への変更は、アクセスを維持するための post‑exploitation 後によく行われます。
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beaconは通常、HTTPS上で Authorization: Bearer tokens を使って api.dropboxapi.com または content.dropboxapi.com を使用する。
- proxy/Zeek/NetFlow で、servers からの予期しない Dropbox egress を hunt する。
- Cloudflare Tunnel (`cloudflared`) は outbound 443 経由で backup C2 を提供する。
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

マルウェアがサービスとしてインストールされる可能性があるパス:

- **/etc/inittab**: rc.sysinit のような初期化スクリプトを呼び出し、さらに startup scripts へと誘導する。
- **/etc/rc.d/** および **/etc/rc.boot/**: サービス起動用のスクリプトを含む。後者は古い Linux バージョンで見られる。
- **/etc/init.d/**: Debian のような特定の Linux バージョンで startup scripts を保存するために使われる。
- サービスは、Linux の種類に応じて **/etc/inetd.conf** または **/etc/xinetd/** 経由でも有効化される場合がある。
- **/etc/systemd/system**: system と service manager のスクリプト用ディレクトリ。
- **/etc/systemd/system/multi-user.target.wants/**: multi-user runlevel で起動されるべきサービスへのリンクを含む。
- **/usr/local/etc/rc.d/**: カスタムまたは third-party services 用。
- **\~/.config/autostart/**: ユーザー固有の automatic startup applications 用で、ユーザーを狙った malware の隠し場所になり得る。
- **/lib/systemd/system/**: インストール済みパッケージが提供する system-wide default unit files。

#### Hunt: systemd timers and transient units

Systemd の persistence は `.service` ファイルに限定されない。`.timer` units、user-level units、そして実行時に作成される **transient units** を調査する。
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

- **/lib/modules/$(uname -r)**: 実行中の kernel version 用の modules を保持する。
- **/etc/modprobe.d**: module loading を制御する設定ファイルを含む。
- **/etc/modprobe** and **/etc/modprobe.conf**: グローバルな module settings 用のファイル。

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: どの user login でも実行される。
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: ログイン時に実行される user-specific files。
- **/etc/rc.local**: すべての system services が開始された後に実行され、multiuser environment への移行の終了を示す。

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): system-wide messages and activities を記録する。
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): authentication attempts、成功・失敗した logins を記録する。
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: system startup messages を含む。
- **/var/log/maillog** or **/var/log/mail.log**: email server activities のログ。email-related services の追跡に有用。
- **/var/log/kern.log**: errors and warnings を含む kernel messages を保存する。
- **/var/log/dmesg**: device driver messages を保持する。
- **/var/log/faillog**: failed login attempts を記録し、security breach investigations に役立つ。
- **/var/log/cron**: cron job executions を記録する。
- **/var/log/daemon.log**: background service activities を追跡する。
- **/var/log/btmp**: failed login attempts を記録する。
- **/var/log/httpd/**: Apache HTTPD error and access logs を含む。
- **/var/log/mysqld.log** or **/var/log/mysql.log**: MySQL database activities を記録する。
- **/var/log/xferlog**: FTP file transfers を記録する。
- **/var/log/**: 常に unexpected logs がないか確認する。

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

On modern Linux hosts, the **systemd journal** is usually the highest-value source for **service execution**, **auth events**, **package operations**, and **kernel/user-space messages**. During live response, try to preserve both the **persistent** journal (`/var/log/journal/`) and the **runtime** journal (`/run/log/journal/`) because short-lived attacker activity may only exist in the latter.
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
トリアージに役立つ journal のフィールドには、`_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID`、および `MESSAGE` が含まれます。`journald` が永続ストレージなしで設定されていた場合は、`/run/log/journal/` 配下に最近のデータしかないと考えてください。

### Audit framework のトリアージ (`auditd`)

`auditd` が有効な場合、ファイル変更、コマンド実行、ログイン活動、またはパッケージインストールに対する**process attribution**が必要なときは、常にそれを優先してください。
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
キー付きでルールが展開されている場合は、raw logs を grep する代わりに、それらを起点に pivot してください:
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux maintains a command history for each user**, stored in:

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

さらに、`last -Faiwx` コマンドはユーザーログインの一覧を提供します。未知または予期しないログインがないか確認してください。

追加のrprivilegesを与える可能性のあるファイルを確認します:

- `/etc/sudoers` を確認し、付与された可能性のある予期しないユーザー権限を探す。
- `/etc/sudoers.d/` を確認し、付与された可能性のある予期しないユーザー権限を探す。
- `/etc/groups` を調べ、異常なグループ所属や権限を特定する。
- `/etc/passwd` を調べ、異常なグループ所属や権限を特定する。

一部の apps も独自のログを生成します:

- **SSH**: _\~/.ssh/authorized_keys_ と _\~/.ssh/known_hosts_ を調べ、未承認のリモート接続がないか確認する。
- **Gnome Desktop**: _\~/.recently-used.xbel_ を調べ、Gnome applications 経由で最近アクセスされたファイルを確認する。
- **Firefox/Chrome**: _\~/.mozilla/firefox_ または _\~/.config/google-chrome_ の browser history と downloads を確認し、疑わしい活動がないか調べる。
- **VIM**: _\~/.viminfo_ を確認し、アクセスしたファイルパスや search history などの使用詳細を確認する。
- **Open Office**: 最近開いた document access を確認し、compromised files の可能性がないか調べる。
- **FTP/SFTP**: _\~/.ftp_history_ または _\~/.sftp_history_ の logs を確認し、未承認の可能性がある file transfers を調べる。
- **MySQL**: _\~/.mysql_history_ を調査し、実行された MySQL queries を確認する。未承認の database activities が明らかになる可能性がある。
- **Less**: _\~/.lesshst_ を分析し、表示した files や実行した commands を含む usage history を確認する。
- **Git**: _\~/.gitconfig_ と project _.git/logs_ を調べ、repositories への変更を確認する。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) は純粋な Python 3 で書かれた小さな software で、Linux の log files（ディストリビューションに応じて `/var/log/syslog*` または `/var/log/messages*`）を解析し、USB event history tables を構築します。

**使用されたすべての USB を把握する**ことは重要であり、許可された USB 一覧があれば、その一覧に含まれていない USB の使用、つまり "violation events" を見つけるうえでさらに有用です。

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
GitHub内の追加の例と情報: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## ユーザーアカウントとログオン活動の確認

_**/etc/passwd**_、_**/etc/shadow**_、および **security logs** を調べ、既知の不正イベントの直前または直後に作成・使用された、不審な名前やアカウントがないか確認する。また、可能な sudo の brute-force attack も確認する。\
さらに、_**/etc/sudoers**_ や _**/etc/groups**_ などのファイルを調べ、ユーザーに与えられた予期しない権限がないか確認する。\
最後に、**パスワードなし**、または**容易に推測できる**パスワードを持つアカウントを探す。

## ファイルシステムの調査

### Malware Investigation におけるファイルシステム構造の分析

malware incident を調査する際、ファイルシステムの構造は重要な情報源であり、事象の時系列と malware の内容の両方を明らかにする。しかし、malware 作成者は、ファイルタイムスタンプの改変や、データ保存にファイルシステムを使わないなどして、この分析を妨げる手法を開発している。

これらの anti-forensic 手法に対抗するには、以下が重要である:

- **Autopsy** のようなツールでイベントの時系列を可視化して**詳細なタイムライン分析**を行う、または **Sleuth Kit** の `mactime` で詳細なタイムラインデータを確認する。
- システムの $PATH 内にある**予期しないスクリプト**を調査する。攻撃者が使った shell や PHP のスクリプトが含まれている可能性がある。
- **/dev の通常とは異なるファイル**を調べる。通常は special files を含むが、malware 関連のファイルが置かれている場合がある。
- ".. "（dot dot space）や "..^G"（dot dot control-G）のような名前の**隠しファイルやディレクトリ**を検索する。悪意あるコンテンツを隠している可能性がある。
- `find / -user root -perm -04000 -print` というコマンドを使って**setuid root ファイル**を特定する。これは権限昇格されたファイルを見つけるもので、攻撃者に悪用される可能性がある。
- inode table の**削除タイムスタンプ**を確認し、大量のファイル削除を見つける。rootkit や trojan の存在を示している可能性がある。
- 1つ見つけた後は、近くにある悪意あるファイルを探すために**連続する inode**を調べる。まとめて配置されている可能性がある。
- 主要な binary ディレクトリ（_/bin_、_/sbin_）で**最近変更されたファイル**を確認する。malware によって改変されている可能性がある。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> **attacker** は **time** を **modify** して **files appear** を **legitimate** に見せかけることができるが、**inode** は **modify** できない。ある **file** が、同じフォルダ内の他のファイルと **same time** に作成・変更されたと示しているのに、**inode** が **unexpectedly bigger** なら、その **file** の **timestamps were modified** ということだ。

### Inode-focused quick triage

**anti-forensics** が疑われる場合は、これらの inode-focused checks を早い段階で実行する:
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
EXT filesystem イメージ/デバイス上に suspicious inode がある場合は、inode メタデータを直接確認します:
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
有用なフィールド:
- **Links**: `0` の場合、現在その inode を参照しているディレクトリエントリはありません。
- **dtime**: inode が unlink されたときに設定される削除タイムスタンプ。
- **ctime/mtime**: メタデータ/コンテンツの変更をインシデントのタイムラインと照合するのに役立ちます。

### Capabilities, xattrs, and preload-based userland rootkits

現代の Linux の永続化は、目立つ `setuid` バイナリを避け、代わりに **file capabilities**、**extended attributes**、および dynamic loader を悪用することがよくあります。
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
**書き込み可能**なパス、たとえば `/tmp`、`/dev/shm`、`/var/tmp`、または `/usr/local/lib` 配下の不自然な場所から参照されるライブラリには特に注意してください。また、通常のパッケージ所有範囲外にある capability を持つバイナリも確認し、パッケージ検証結果（`rpm -Va`、`dpkg --verify`、`debsums`）と照合してください。

## 異なるファイルシステムバージョンのファイルを比較する

### ファイルシステムバージョン比較の要約

ファイルシステムのバージョンを比較して変更点を特定するには、簡略化した `git diff` コマンドを使います:

- **新しいファイルを見つけるには**、2つのディレクトリを比較します:
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **修正されたコンテンツについては**, 特定の行を無視しながら変更点を一覧表示する:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **削除されたファイルを検出するには**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) は、追加された (`A`)、削除された (`D`)、または変更された (`M`) ファイルなど、特定の変更に絞り込むのに役立つ。
- `A`: 追加されたファイル
- `C`: コピーされたファイル
- `D`: 削除されたファイル
- `M`: 変更されたファイル
- `R`: 名前変更されたファイル
- `T`: Type 変更（例: file から symlink へ）
- `U`: 未マージのファイル
- `X`: 不明なファイル
- `B`: 壊れたファイル

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
