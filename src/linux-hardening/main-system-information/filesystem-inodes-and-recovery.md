# ファイルシステム、inode、リカバリ

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse is often about confusing the relationship between a visible path and the object behind it.

ディスクイメージには別のファイルシステムが隠れている場合があります。<sup>[[1]](#references)</sup> 書き込み可能なマウントは、特権ジョブによって消費される可能性があります。

Hardlink によって、別の名前から同じ inode にアクセスできる場合があります。<sup>[[3]](#references)</sup> 削除されたファイルも、開いているファイルディスクリプタを通じて読み取り可能な場合があります。<sup>[[5]](#references)[[6]](#references)</sup>

このページでは、特定のラボやターゲットではなく、technique に焦点を当てます。

## ディスクイメージと Loop Mount

通常のファイルには完全なファイルシステムを格納できるため、ディスクイメージを mount すると、2つ目のファイルシステムツリーを公開できます。<sup>[[1]](#references)</sup>

そのため、バックアップイメージ、コピーされたブロックデバイス、VM アーティファクト、または名前を変更された blob には、外部からは有用に見えなくても、credential、script、SSH key、configuration file、flag などが含まれている可能性があります。

`file` を使用して候補を分類し、`blkid` で認識されたファイルシステム metadata を調べ、`strings -a` でファイル全体をスキャンして printable sequence を探すことで、可能性の高いイメージを特定します。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
マウントが許可されている場合は、`ro` を指定した loop mount を使用してイメージを読み取り専用でアタッチします。以下の `find` コマンドでは、検査する深さとファイルタイプを制限しています。<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
mountが利用できず、イメージがext2/ext3/ext4の場合は、<code>debugfs</code>を使用してメタデータを直接調査します。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
この technique は、通常のファイルに見えるものを、2つ目の filesystem tree に変えるため有用です。<sup>[[1]](#references)</sup> これは隠しデータを復元する方法として扱い、それ自体を privilege escalation として扱わないでください。

## Writable Mount Abuse

より privileged な context が後からその中の何かを信頼すると、writable mount は危険になります。重要なのは「ここに書き込めるか」だけではなく、「後から誰がここから読み取り、実行し、import し、または load するのか」です。

`findmnt` を使用して、マウントされた filesystem とそのオプションを調査します。<sup>[[9]](#references)</sup>

文書化されている `find` の permission、type、filesystem-boundary predicate を使って writable mount と疑わしい consumer を見つけ、その後、recursive `grep` で関連しそうな consumer の configuration を検索します。<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
一般的な悪用パターン:

- cron job または systemd service が、mount 内から書き込み可能な script を実行する。<sup>[[13]](#references)[[14]](#references)</sup>
- 特権 service が、mount から plugin、config、template、または helper binary を読み込む。
- mount に SUID file が含まれており、変更、置換、または path manipulation が可能である。
- container または chroot が、制限された環境から書き込み可能な、host-backed path を公開する。Mount namespace は個別の mount hierarchy を提供する一方、`chroot()` は pathname resolution の変更のみを行い、完全な sandbox ではない。<sup>[[15]](#references)[[16]](#references)</sup>

同じ `find` predicates を使用した一般的な検証パターン。<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
認可されたラボで impact を証明する際は、payload を観測可能かつ最小限に保ちます。例えば、`id` の出力を一時ファイルに書き込みます。<sup>[[23]](#references)</sup> 核となる technique は、信頼できる書き込み可能な場所を介した遅延実行です。

## Inodes と Path Confusion

inode はファイルシステムオブジェクトであり、path はそこを指す名前にすぎません。デバイスと inode のメタデータにより、ファイルシステムをまたいでオブジェクトを区別できます。また、link count により複数のハードリンクを確認できます。<sup>[[3]](#references)</sup> プロセスがファイルを開いたままの場合、削除された pathname が必ずしもデータの消失を意味するとは限りません。<sup>[[5]](#references)</sup>

以下の `find` predicates は、inode の同一性、link count、デバイス境界、タイムスタンプを比較します。<sup>[[4]](#references)</sup>

`ls -i` と `stat` のメタデータ形式を使用して、inode とデバイスによりファイルを比較します。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
`find -samefile` を使って、同じ inode に対応するすべての可視パス名を検索します。<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
メタデータしかない場合は、`find -inum` を使って inode 番号で直接検索します。<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
この technique は、ファイルが予期しない名前で表示される場合、アプリケーションがあるパスを検証する一方で別のパスを使用する場合、または特権ラッパーが別の場所からも到達可能な inode とやり取りする場合に役立ちます。

## Hardlink Abuse

ハードリンクは、同じ inode に対して複数の名前を作成します。symlink のようにターゲットパスを指すのではなく、同じファイルオブジェクトに対する同等の名前です。<sup>[[3]](#references)</sup>

`find` の permission および link-count predicates を使用して、複数のハードリンクを持つ SUID ファイルを見つけます。<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
`stat` と `find -samefile` を使って、疑わしいファイルを1つ調査します。<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
重要である理由:

- 機密ファイルが、より分かりにくいパスから到達可能になっている場合がある。
- SUID wrapper が、特権を持つようには見えない名前の背後に隠されている場合がある。
- 1つの pathname を削除する cleanup では、別の hardlink が残る場合がある。

Linux の `fs.protected_hardlinks` sysctl は、権限境界をまたぐ hardlink の作成を制限できる。<sup>[[7]](#references)</sup> 既存の hardlink も確認する価値がある。

## Open FDs を介した削除済みファイルの復元

プロセスがファイルを開いたままにしている場合、その最後の pathname を unlink しても、最後の descriptor が閉じられるまでファイルは存続する。Linux はそれらの descriptor を `/proc/<pid>/fd/` 配下に公開している。<sup>[[5]](#references)[[6]](#references)</sup>

`/proc` の descriptor を一覧表示し、open-file の出力をフィルタリングすることで、削除済みの open file を見つけられる。<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
これらのリンクを介した復元は権限に依存します。これは、`/proc/<pid>/fd` の逆参照が ptrace のアクセスチェックとファイル権限の対象となるためです。<sup>[[6]](#references)</sup>

許可されている場合、`readlink` はディスクリプタの対象を表示し、`cp` はその内容をコピーします。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
これは、削除されたログ、一時的な secret、削除されたバイナリ、ローテーションされたファイル、または実行後に削除されたスクリプトを復旧するための実践的な technique です。

## debugfs による ext ファイルシステムの復旧

ext2/ext3/ext4 ファイルシステムでは、`debugfs` を使用して inode metadata を検査し、ブロックデバイスまたはイメージから inode の内容をダンプできます。`-w` を指定しない場合、ファイルシステムは read-only で開かれます。<sup>[[2]](#references)</sup> 可能な限り、コピーまたは read-only イメージ上で作業してください。

ディレクトリ一覧、inode の status、inode からパスへのチェック用の `debugfs` request を使用して、エントリを一覧表示し、inode を検査します。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
既知の inode を `debugfs dump` コマンドでダンプし、復元された出力を `file` で分類します。<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
これは復旧を保証するものではありません。ファイルシステムの状態、ブロックが再利用されたかどうか、メタデータがまだ存在するかどうかに依存します。ext3/ext4 では、`debugfs` のマニュアルに、解放された inode のデータブロックが利用できなくなっているため、削除された inode の復旧に失敗する可能性があると記載されています。<sup>[[2]](#references)</sup> この technique は、通常の path traversal に依存せず、inode レベルの状態を検査できるため、依然として有用です。

## inode の枯渇と順序付け

inode の枯渇は、空きディスク容量が残っていても、ファイルノードがファイルシステム内で不足した場合に発生します。<sup>[[8]](#references)[[17]](#references)</sup> 通常は信頼性に関する障害を引き起こしますが、インシデント対応やラボでの triage 中に発生する奇妙な挙動を説明できる場合もあります。

ブロック使用量ではなく inode 情報を報告するには、`df -i` を使用します。<sup>[[8]](#references)</sup>

`df` と、ディレクトリの親を `find` でカウントする方法を使用して、inode の逼迫状況を確認します。<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode番号とtimestampは、単純なlab環境での活動の再構築にも役立ちます。

以下の`find`のformat directivesにより、これらのフィールドを確認できます。<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
順序は手がかりとして扱い、証拠とはみなさないでください。コピー操作、archive の展開、filesystem の種類、restore、同時書き込みによって、allocation パターンはすべて変化する可能性があります。

## Defensive Notes

- 分析中は、不明な image を read-only で mount してください。<sup>[[1]](#references)</sup>
- privileged script、service unit、plugin、helper path は、user-writable mount の外部に配置してください。
- 運用上適切な場合は `nosuid`、`nodev`、`noexec` を使用してください。これらのオプションは、mount 上での set-ID/capability 実行、device の解釈、または binary の直接実行を無効にします。<sup>[[1]](#references)</sup> これらを完全な境界として扱わないでください。
- `/proc/<pid>/fd` へのアクセスを制限してください。これらの link の dereference は ptrace access check と file permission によって制御されます。<sup>[[6]](#references)</sup> 可能な限り、より広範な process metadata と user をまたいだ inspection も制限してください。
- writable mount point、privileged file への予期しない hardlink、deleted-but-open の sensitive file を monitor してください。

## References

- [1] [mount(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [/proc/sys/fs/ のドキュメント — The Linux Kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux マニュアルページ](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
