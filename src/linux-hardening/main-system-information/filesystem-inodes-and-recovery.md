# ファイルシステム、inode、リカバリ

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse is often about confusing the relationship between a visible path and the object behind it. Disk images may hide another filesystem, writable mounts may be consumed by privileged jobs, hardlinks may expose the same inode through a different name, and deleted files may still be readable through an open file descriptor.

This page focuses on the technique, not on one specific lab or target.

## ディスクイメージとLoop Mount

A regular file can contain a complete filesystem. Backup images, copied block devices, VM artifacts, or renamed blobs can therefore contain credentials, scripts, SSH keys, configuration files, or flags even when they do not look useful from the outside.

Identify likely images:
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
マウントが許可されている場合は、未知のイメージをまず読み取り専用でマウントします:
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
マウントが利用できない場合は、ファイルシステムのメタデータを直接調査します：
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
この technique が有用なのは、通常のファイルに見えるものを、2つ目の filesystem tree に変えるためです。これは hidden data を復元する方法として扱い、単独で privilege escalation になるものとは考えないでください。

## Writable Mount Abuse

writable mount は、より privileged な context がその内部にあるものを後から信頼すると危険になります。重要なのは「ここに write できるか」だけではなく、「後から誰がここから read、execute、import、または load するのか」です。

writable mount と疑わしい consumer を見つけます：
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
一般的な悪用パターン:

- 特権 cron または systemd unit が、mount 内の書き込み可能な script を実行する。
- 特権 service が、mount から plugin、config、template、または helper binary を読み込む。
- mount に SUID file が含まれており、変更、置換、または path manipulation が可能である。
- container または chroot が、制限された環境から書き込み可能な host-backed path を公開している。

一般的な検証パターン:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
認証済みのラボで影響を実証する場合は、ペイロードを観測可能かつ最小限に保ちます。例えば、`id` の出力を一時ファイルに書き込みます。中核となる technique は、信頼された書き込み可能な場所を介した遅延実行です。

## Inode と Path の混同

inode は filesystem オブジェクトであり、path はそれを指す名前にすぎません。これは、異なる 2 つの path が同じ inode を指す場合があり、削除された pathname が必ずしもデータの消失を意味しないため重要です。

inode と device でファイルを比較します：
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
同じ inode のすべての可視パス名を見つける：
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
メタデータしかない場合は、inode番号で直接検索します：
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
この手法は、ファイルが予期しない名前で表示される場合、アプリケーションがあるパスを検証して別のパスを使用する場合、または privileged wrapper が別の場所からも到達可能な inode とやり取りする場合に有用です。

## Hardlink Abuse

Hardlink は、同じ inode に対して複数の名前を作成します。symlink のように対象パスを指すのではなく、同じファイルオブジェクトに対する同等の名前です。

複数の hardlink を持つ SUID ファイルを検索します：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
不審なファイルを1つ調査する：
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
なぜ重要か：

- 機密ファイルが、あまり目立たない別のパスから到達可能な場合がある。
- SUID wrapper が、privileged に見えない名前の背後に隠されている場合がある。
- ある pathname を削除する cleanup でも、別の hardlink が残っている場合がある。

Modern kernels と mount options は、この種の abuse を減らすため hardlink の作成を制限できるが、既存の hardlink も引き続き確認する価値がある。

## 開いている FD を介した削除済みファイルの復元

process が file を open したままにしている場合、pathname が削除された後でも file data が利用可能な状態で残ることがある。Linux は、これらの open descriptors を `/proc/<pid>/fd/` 配下に公開している。

削除済みの open files を検索する：
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
権限が許可している場合はデータを復元する：
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
これは、削除されたログ、一時的なsecret、削除されたバイナリ、ローテーションされたファイル、または実行後に削除されたスクリプトを復元するための実践的なtechniqueです。

## debugfsによるextファイルシステムの復元

extファイルシステムでは、`debugfs`を使用してinodeのメタデータを調査し、場合によってはファイルシステムイメージからファイルの内容をdumpできます。可能な限り、コピーまたはread-onlyイメージ上で作業してください。

エントリを一覧表示し、inodeを調査します：
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
既知の inode をダンプする：
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
これは復旧を保証するものではありません。ファイルシステムの状態、ブロックが再利用されたかどうか、メタデータがまだ存在しているかどうかに左右されます。それでもこの手法には価値があります。通常のパス traversing に依存せず、inode レベルの状態を検査できるためです。

## Inode の枯渇と順序

Inode の枯渇は、空きディスク容量が残っていても、ファイルシステムのファイルオブジェクトが不足したときに発生します。通常は信頼性の問題を引き起こしますが、インシデント対応やラボでのトリアージ中に奇妙な動作を説明する手がかりにもなります。

inode の逼迫状況を確認します：
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode番号とタイムスタンプは、単純なラボ環境でアクティビティを再構築する際にも役立ちます。
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
順序は手掛かりとして扱い、証拠とはみなさないでください。コピー操作、アーカイブの展開、filesystem の種類、復元、同時書き込みは、いずれも allocation パターンを変える可能性があります。

## 防御に関する注意事項

- 分析中は、未知のイメージを read-only でマウントする。
- privileged なスクリプト、service unit、plugin、helper path は、user-writable な mount の外部に配置する。
- 運用上適切な場合は `nosuid`、`nodev`、`noexec` を使用する。ただし、これらを完全な境界とみなしてはならない。
- 可能な限り、`/proc/<pid>/fd`、process metadata、cross-user process inspection へのアクセスを制限する。
- writable な mount point、privileged file への予期しない hardlink、削除済みだが open 中の機密ファイルを監視する。
{{#include ../../banners/hacktricks-training.md}}
