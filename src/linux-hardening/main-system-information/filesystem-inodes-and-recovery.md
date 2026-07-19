# ファイルシステム、inode、リカバリ

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse は、可視パスと、その背後にあるオブジェクトとの関係を混乱させることが目的になる場合が多くあります。Disk image には別の filesystem が隠されていることがあり、書き込み可能な mount は privileged job によって消費される可能性があります。また、hardlink によって同じ inode を別の名前で公開でき、削除されたファイルも、開かれた file descriptor 経由で読み取り可能な場合があります。

このページでは、特定の lab や target ではなく、technique に焦点を当てます。

## Disk Image と Loop Mount

通常のファイルに、完全な filesystem を含めることができます。そのため、backup image、コピーされた block device、VM artifact、名前を変更した blob には、外部からは有用に見えなくても、credential、script、SSH key、configuration file、または flag が含まれている可能性があります。

可能性の高い image を特定します：
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
マウントが許可されている場合は、まず不明なイメージを読み取り専用でマウントします：
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
この technique が有用なのは、通常のファイルに見えるものを、2つ目の filesystem tree に変えるためです。これを、hidden data を復元する方法として扱ってください。単独で privilege escalation になるわけではありません。

## Writable Mount Abuse

writable mount は、より高い privilege を持つ context が、その中にある何かを後から信頼すると危険になります。重要なのは「ここに write できるか」だけではなく、「後から誰がここから read、execute、import、または load するのか」という点です。

writable mount と疑わしい consumer を見つけます：
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
一般的な悪用パターン：

- 特権 cron または systemd unit が、mount 内の書き込み可能な script を実行する。
- 特権 service が、mount 内の plugin、config、template、または helper binary を読み込む。
- mount に SUID file が含まれており、変更、置換、または path manipulation が可能である。
- container または chroot が、制限された環境から書き込み可能な host-backed path を公開している。

一般的な検証パターン：
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
認証済みのラボで影響を実証する場合は、ペイロードを観測可能かつ最小限に保ってください。たとえば、`id` の出力を一時ファイルに書き込みます。核心となる technique は、信頼された書き込み可能な場所を介した遅延実行です。

## Inode とパスの混同

inode は filesystem オブジェクトであり、パスはそれを指す単なる名前です。これは、異なる2つのパスが同じ inode を指す場合があり、削除されたパス名が必ずしもデータの消失を意味しないため重要です。

inode とデバイスでファイルを比較します：
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
同じ inode に対応するすべての可視パス名を見つける:
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
メタデータしかない場合は、inode番号で直接検索する：
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
この technique は、ファイルが予期しない名前で存在する場合、アプリケーションがあるパスを検証して別のパスを使用する場合、または privileged wrapper が別の場所からも到達可能な inode とやり取りする場合に役立ちます。

## Hardlink Abuse

Hardlink は、同じ inode に対して複数の名前を作成します。symlink のように対象パスを指すのではなく、同じファイルオブジェクトに対する同等の名前です。

複数の hardlink を持つ SUID ファイルを検索します：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
疑わしいファイルを1つ調査する：
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
重要である理由：

- 機密ファイルが、あまり目立たない別のパスから到達可能な場合がある。
- SUID wrapper が、特権を持つようには見えない名前の背後に隠されている場合がある。
- 1つのパス名を削除するクリーンアップでは、別の hardlink が残っている可能性がある。

Modern kernels と mount options は、この種の悪用を減らすために hardlink の作成を制限できますが、既存の hardlink は引き続き確認する価値があります。

## Open FDs を介した削除済みファイルの復元

プロセスがファイルを open したままにしている場合、パス名が削除された後でもファイルデータを利用できることがあります。Linux は、これらの open descriptor を `/proc/<pid>/fd/` 配下に公開しています。

削除済みの open file を検索する：
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
これは、削除されたログ、一時的な秘密情報、ドロップされたバイナリ、ローテーションされたファイル、または実行後に削除されたスクリプトを復元するための実践的な手法です。

## debugfsによるextリカバリ

extファイルシステムでは、`debugfs`を使用してinodeメタデータを調査し、場合によってはファイルシステムイメージからファイルの内容をダンプできます。可能な限り、コピーまたは読み取り専用イメージ上で作業してください。

エントリを一覧表示し、inodeを調査します：
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
既知の inode をダンプする:
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
これは復旧が保証されるものではありません。ファイルシステムの状態、ブロックが再利用されたかどうか、メタデータがまだ存在しているかどうかに左右されます。それでも、この手法には価値があります。通常のパス走査に依存せず、inode レベルの状態を調査できるためです。

## Inode Exhaustion と Ordering

Inode Exhaustion は、空きディスク容量が残っていても、ファイルシステムがファイルオブジェクトを使い果たしたときに発生します。通常は信頼性に関する障害を引き起こしますが、インシデント対応やラボでのトリアージ中に発生する奇妙な挙動の説明にも役立ちます。

inode の逼迫状況を確認します:
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode番号とタイムスタンプは、単純なラボ環境でのアクティビティの再構成にも役立ちます：
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
順序は手がかりとして扱い、証拠とはみなさないでください。コピー操作、アーカイブの展開、ファイルシステムの種類、リストア、同時書き込みによって、割り当てパターンはすべて変化する可能性があります。

## Defensive Notes

- 分析中は、不明なイメージを読み取り専用でマウントする。
- 特権スクリプト、サービスユニット、プラグイン、ヘルパーのパスを、ユーザーが書き込み可能なマウントポイントの外部に配置する。
- 運用上適切な場合は `nosuid`、`nodev`、`noexec` を使用する。ただし、これらを完全な境界とみなさない。
- 可能な限り、`/proc/<pid>/fd`、プロセスメタデータ、ユーザーをまたいだプロセス検査へのアクセスを制限する。
- 書き込み可能なマウントポイント、特権ファイルへの予期しないハードリンク、削除済みだがオープン中の機密ファイルを監視する。
