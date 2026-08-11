# Filesystem、Inode、リカバリ

Filesystem abuse は、見えている path と、その背後にある object の関係を混乱させることが中心となる場合が多くあります。

Disk image には別の filesystem が隠れていることがあります。<sup>[[1]](#references)</sup> Writable mount は privileged job によって消費される可能性があります。

Hardlink によって、同じ inode を別の名前から公開できる場合があります。<sup>[[3]](#references)</sup> Deleted file も、open file descriptor 経由で引き続き読み取れる場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

このページでは、特定の lab や target ではなく、technique に焦点を当てます。

## Disk Image と Loop Mount

通常の file には完全な filesystem を含められるため、disk image を mount すると、2つ目の filesystem tree を公開できます。<sup>[[1]](#references)</sup>

Backup image、コピーされた block device、VM artifact、または名前を変更した blob には、外部からは有用に見えなくても、credentials、scripts、SSH keys、configuration files、または flags が含まれている可能性があります。

`file` で候補を分類し、`blkid` で認識可能な filesystem metadata を調べ、`strings -a` で file 全体から printable sequence をスキャンして、可能性のある image を特定します。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
マウントが許可されている場合は、`ro` を指定した loop mount を使用してイメージを読み取り専用でアタッチします。以下の `find` コマンドでは、調査する深さとファイルタイプを制限しています。<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
マウントを利用できず、イメージが ext2/ext3/ext4 の場合は、`debugfs` を使用してメタデータを直接調査します。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
この手法は、一見普通のファイルを2つ目のファイルシステムツリーに変えるため有用です。<sup>[[1]](#references)</sup> これは隠されたデータを復元する手段として扱い、それ自体を権限昇格とみなさないでください。

## Writable Mount Abuse

書き込み可能な mount は、より高い権限を持つコンテキストが後からその内部の何かを信頼すると危険になります。重要なのは「ここに書き込めるか」だけではなく、「後から誰がここから読み取り、実行し、import し、またはロードするのか」という点です。

`findmnt` を使用して、マウントされたファイルシステムとそのオプションを確認します。<sup>[[9]](#references)</sup>

文書化されている `find` の permission、type、filesystem-boundary predicates を使って、書き込み可能な mount と疑わしい consumer を見つけ、その後、recursive `grep` で関連しそうな consumer の設定を検索します。<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
一般的な悪用パターン:

- cron job または systemd service が、mount 上の writable script を実行する。<sup>[[13]](#references)[[14]](#references)</sup>
- privileged service が、mount から plugins、config、templates、または helper binaries を読み込む。
- mount に SUID files が含まれており、変更、置換、または path manipulation が可能である。
- container または chroot が、restricted environment から writable な host-backed path を公開する。Mount namespaces は個別の mount hierarchies を提供する一方、`chroot()` は pathname resolution の変更のみを行い、完全な sandbox ではない。<sup>[[15]](#references)[[16]](#references)</sup>

同じ `find` predicates を使用した一般的な検証パターン。<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
認可済みのラボで影響を実証する場合は、payloadを観測可能かつ最小限に保ちます。たとえば、`id`の出力を一時ファイルに書き込みます。<sup>[[23]](#references)</sup> 中核となる技術は、信頼された書き込み可能な場所を介した遅延実行です。

## Inodes と Path Confusion

inodeはファイルシステムオブジェクトであり、pathはそれを指す単なる名前です。デバイスとinodeのメタデータにより、ファイルシステム間でオブジェクトを区別できます。また、link countによって複数のハードリンクを確認できます。<sup>[[3]](#references)</sup> プロセスがファイルを開いたままの場合、削除されたpathnameが必ずしもデータの消失を意味するとは限りません。<sup>[[5]](#references)</sup>

以下の`find`述語は、inodeの同一性、link count、デバイス境界、タイムスタンプを比較します。<sup>[[4]](#references)</sup>

`ls -i`と`stat`のメタデータ形式を使用して、inodeとデバイスによってファイルを比較します。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
`find -samefile`で同じinodeに対応するすべての可視パス名を検索します。<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
メタデータしかない場合は、`find -inum` で inode 番号を直接検索します。<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
この technique は、ファイルが予期しない名前で現れる場合、アプリケーションがあるパスを検証しながら別のパスを使用する場合、または特権ラッパーが別の場所からも到達可能な inode とやり取りする場合に有用です。

## Hardlink Abuse

Hardlink は、同じ inode に対して複数の名前を作成します。symlink のようにターゲットパスを指すのではなく、同じファイルオブジェクトに対する同等の名前です。<sup>[[3]](#references)</sup>

`find` の権限およびリンク数の predicate を使用して、複数の hardlink を持つ SUID ファイルを見つけます。<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
`stat` と `find -samefile` を使用して、1つの不審なファイルを調査します。<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
なぜ重要か:

- 機密ファイルが、あまり obvious ではないパスから到達可能な場合がある。
- SUID wrapper が、privileged には見えない名前の背後に隠されている場合がある。
- 1つの pathname を削除する cleanup では、別の hardlink が残る可能性がある。

Linux の `fs.protected_hardlinks` sysctl は、権限境界を越えた hardlink の作成を制限できます。<sup>[[7]](#references)</sup> 既存の hardlink も確認する価値があります。

## Open FD 経由の削除済みファイルの復元

プロセスがファイルを open したままの場合、その最後の pathname を unlink しても、最後の descriptor が close されるまでファイルは存続します。Linux では、これらの descriptor が `/proc/<pid>/fd/` 配下に公開されています。<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` の descriptor を一覧表示し、open-file の出力を filter することで、削除済みの open file を見つけられます。<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
これらのリンク経由での復元は、`/proc/<pid>/fd` の逆参照が ptrace のアクセスチェックとファイル権限の対象となるため、権限に依存します。<sup>[[6]](#references)</sup>

許可されている場合、`readlink` はディスクリプタのターゲットを表示し、`cp` はその内容をコピーします。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
これは、削除されたログ、一時的な secrets、削除されたバイナリ、ローテーションされたファイル、または実行後に削除されたスクリプトを復旧するための実践的な手法です。

## debugfs を使った ext の復旧

ext2/ext3/ext4 filesystem では、`debugfs` を使用して inode metadata を検査し、block device または image から inode の内容をダンプできます。`-w` を指定しない場合、filesystem は read-only で開かれます。<sup>[[2]](#references)</sup> 可能な限り、コピーまたは read-only image 上で作業してください。

directory listing、inode status、inode-to-path checks 用の `debugfs` requests を使用して、entries を一覧表示し、inodes を検査します。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
既知の inode を `debugfs dump` コマンドでダンプし、復元した出力を `file` で分類します。<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
これは復旧を保証するものではありません。filesystemの状態、ブロックが再利用されたかどうか、metadataがまだ存在しているかどうかに依存します。ext3/ext4では、`debugfs`のマニュアルに、解放されたinodeのデータブロックが利用できなくなっているため、deleted-inode recoveryに失敗する可能性があると記載されています。<sup>[[2]](#references)</sup> この手法は、通常のpath traversalに依存せず、inode-levelの状態を検査できるため、依然として有用です。

## Inode Exhaustion and Ordering

Inode exhaustionは、空きディスク容量が残っていても、filesystemのfile nodeが枯渇したときに発生します。<sup>[[8]](#references)[[17]](#references)</sup> 通常はreliability failureを引き起こしますが、incident responseやlab triage中の奇妙な挙動を説明できる場合もあります。

ブロック使用量ではなくinode情報を報告するには、`df -i`を使用します。<sup>[[8]](#references)</sup>

`df`と、directory parentの数を数える`find`を使って、inode pressureを確認します。<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode番号とタイムスタンプは、単純なラボ環境でアクティビティを再構築する際にも役立ちます。

以下の`find`フォーマットディレクティブで、これらのフィールドを確認できます。<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
順序は手掛かりとして扱い、証拠とはみなさないでください。コピー操作、archive の展開、filesystem の種類、restore、同時書き込みは、いずれも allocation パターンを変化させる可能性があります。

## Defensive Notes

- 分析中は、未知のイメージを read-only で mount してください。<sup>[[1]](#references)</sup>
- privileged な scripts、service units、plugins、helper paths は、user-writable な mounts の外部に配置してください。
- 運用上適切な場合は、`nosuid`、`nodev`、`noexec` を使用してください。これらのオプションは、mount 上での set-ID/capability の実行、device の解釈、または binary の直接実行を無効にします。<sup>[[1]](#references)</sup> ただし、これらを完全な boundary とみなさないでください。
- `/proc/<pid>/fd` への access を制限してください。これらの links の dereference は ptrace access checks と file permissions によって制御されます。<sup>[[6]](#references)</sup> 可能な限り、より広範な process metadata と user 間の inspection も制限してください。
- writable な mount points、privileged files への予期しない hardlinks、削除済みだが open のままになっている sensitive files を monitor してください。

## References

- [1] [mount(8) — Linux manual page](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux manual page](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux manual page](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux manual page](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux manual page](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux manual page](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [Documentation for /proc/sys/fs/ — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux manual page](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux manual page](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux manual page](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux manual page](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux manual page](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux manual page](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux manual page](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux manual page](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux manual page](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux manual page](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux manual page](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux manual page](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux manual page](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux manual page](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux manual page](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
