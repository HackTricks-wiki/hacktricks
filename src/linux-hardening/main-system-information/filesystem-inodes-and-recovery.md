# ファイルシステム、inode、リカバリ

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse is often about confusing the relationship between a visible path and the object behind it. Disk images may hide another filesystem, writable mounts may be consumed by privileged jobs, hardlinks may expose the same inode through a different name, and deleted files may still be readable through an open file descriptor.

このページでは、特定の lab や target ではなく、technique に焦点を当てます。

## Disk Images and Loop Mounts

通常のファイルに完全な filesystem を含めることができます。そのため、backup image、コピーされた block device、VM artifact、または名前を変更した blob には、外部からは有用に見えなくても、credentials、scripts、SSH keys、configuration files、flags などが含まれている可能性があります。

可能性のある image を特定します:
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
マウントが利用できない場合は、ファイルシステムのメタデータを直接調査します:
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
この technique は、通常のファイルに見えるものを、2つ目の filesystem tree に変えるため有用です。これは hidden data を復元する方法として扱い、それ自体を privilege escalation として扱わないでください。

## Writable Mount Abuse

Writable mount は、より privileged な context が後からその内部の何かを信頼すると危険になります。重要なのは「ここに write できるか」だけではなく、「後から誰がここから read、execute、import、または load するか」です。

Writable mount と suspicious consumer を見つけます：
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
一般的な悪用パターン:

- 権限のある cron または systemd unit が、mount 内の書き込み可能な script を実行する。
- 権限のある service が、mount 内から plugin、config、template、または helper binary を読み込む。
- mount に SUID file が含まれており、変更、置換、または path manipulation が可能である。
- container または chroot が、制限された環境から書き込み可能な host-backed path を公開している。

Generic validation pattern:
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
認可された lab で impact を証明する場合は、payload を観測可能かつ最小限に保ちます。たとえば、`id` の出力を一時ファイルに書き込みます。中核となる technique は、trusted writable location を介した遅延実行です。

## Inodes と Path Confusion

inode は filesystem object であり、path はそれを指す単なる名前です。これは、異なる 2 つの path が同じ inode を指すことがあり、削除された pathname が必ずしもデータの消失を意味しないため重要です。

inode と device でファイルを比較します。
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
同じ inode に対応する、表示可能なすべてのパス名を見つける:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
メタデータしかない場合は、inode番号で直接検索します：
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
この technique は、ファイルが予期しない名前で存在する場合、application がある path を検証する一方で別の path を使用する場合、または privileged wrapper が別の場所からも到達可能な inode とやり取りする場合に役立ちます。

## Hardlink Abuse

Hardlinks は、同じ inode に対して複数の名前を作成します。symlinks のように対象の path を指すのではなく、同じ file object に対する等価な名前です。

複数の hardlinks を持つ SUID files を探します：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
疑わしいファイルを1つ検査する：
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
なぜ重要か：

- 機密ファイルが、あまり目立たない別のパスから到達可能な場合がある。
- SUID wrapper が、特権を持つようには見えない名前の背後に隠されている場合がある。
- 1つの pathname を削除する cleanup では、別の hardlink が残る可能性がある。

Modern kernels と mount options は、この種の悪用を減らすために hardlink の作成を制限できますが、既存の hardlink も引き続き確認する価値があります。

## Open FD 経由で削除済みファイルを復元する

process がファイルを open したままにしている場合、pathname が削除された後でもファイルデータを利用できることがあります。Linux は、これらの open descriptor を `/proc/<pid>/fd/` 配下に公開しています。

削除済みの open file を見つける：
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
権限が許す場合はデータを復元する：
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
これは、削除されたログ、一時的なsecret、ドロップされたバイナリ、ローテーションされたファイル、または実行後に削除されたscriptを復元するための実践的なtechniqueです。

## ext Recovery With debugfs

ext filesystemでは、`debugfs`を使用してinode metadataを調査し、filesystem imageからファイルの内容をdumpできる場合があります。可能な限り、コピーまたはread-only image上で作業してください。

entriesを一覧表示し、inodeを調査します：
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
既知の inode を dump:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
これは復旧が保証されるものではありません。ファイルシステムの状態、ブロックが再利用されたかどうか、メタデータがまだ存在するかどうかに左右されます。この technique は、通常のパス traversal に依存せず inode レベルの状態を調査できるため、依然として有用です。

## inode の枯渇と順序

inode の枯渇は、空きディスク容量が残っていても、ファイルシステムのファイルオブジェクトが不足したときに発生します。通常は信頼性の問題を引き起こしますが、incident response や lab triage 中の不可解な挙動を説明する手がかりにもなります。

inode の逼迫状況を確認します。
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode番号とタイムスタンプは、単純なラボ環境でのアクティビティの再構築にも役立ちます：
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
順序は手がかりとして扱い、証拠とはみなさないでください。コピー操作、アーカイブの展開、filesystem の種類、restore、同時書き込みによって、allocation パターンはすべて変化する可能性があります。

## 防御に関する注意事項

- 分析中は、不明なイメージを read-only でマウントする。
- 特権スクリプト、service unit、plugin、helper path は、ユーザーが書き込み可能な mount の外部に配置する。
- 運用上適切な場合は `nosuid`、`nodev`、`noexec` を使用する。ただし、これらを完全な境界として扱わない。
- 可能な限り、`/proc/<pid>/fd`、process metadata、ユーザーをまたいだ process inspection へのアクセスを制限する。
- 書き込み可能な mount point、特権ファイルへの予期しない hardlink、削除済みだが open 状態の機密ファイルを監視する。

{{#include ../../banners/hacktricks-training.md}}
