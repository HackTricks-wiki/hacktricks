# Seccomp

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## 基本情報

**Seccomp** は、Secure Computing mode の略で、**Linuxカーネルのセキュリティ機能**であり、システムコールをフィルタリングするように設計されています。プロセスをシステムコールの限られたセット（`exit()`、`sigreturn()`、`read()`、および既に開かれたファイルディスクリプタ用の`write()`）に制限します。プロセスが他の何かを呼び出そうとすると、カーネルによって SIGKILL または SIGSYS を使用して終了させられます。このメカニズムはリソースを仮想化するのではなく、プロセスをそれらから分離します。

Seccomp をアクティブ化する方法には、`prctl(2)` システムコールを使用して `PR_SET_SECCOMP` を介して行う方法と、Linuxカーネル3.17以降では `seccomp(2)` システムコールを使用する方法があります。`/proc/self/seccomp` に書き込むことで Seccomp を有効にする古い方法は、`prctl()` に代わって非推奨となっています。

拡張機能である **seccomp-bpf** は、Berkeley Packet Filter（BPF）ルールを使用してカスタマイズ可能なポリシーでシステムコールをフィルタリングする機能を追加します。この拡張機能は、OpenSSH、vsftpd、Chrome OS および Linux 上の Chrome/Chromium ブラウザなどのソフトウェアによって活用され、柔軟で効率的なシスコールフィルタリングを提供し、Linux でサポートされなくなった systrace に代わるものとなっています。

### **オリジナル/厳格モード**

このモードでは、Seccomp は既に開かれたファイルディスクリプタに対して `exit()`、`sigreturn()`、`read()`、`write()` のシスコールのみを許可します。他のシスコールが行われた場合、プロセスは SIGKILL を使用して終了されます。

{% code title="seccomp_strict.c" %}
```c
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>

//From https://sysdig.com/blog/selinux-seccomp-falco-technical-discussion/
//gcc seccomp_strict.c -o seccomp_strict

int main(int argc, char **argv)
{
int output = open("output.txt", O_WRONLY);
const char *val = "test";

//enables strict seccomp mode
printf("Calling prctl() to set seccomp strict mode...\n");
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);

//This is allowed as the file was already opened
printf("Writing to an already open file...\n");
write(output, val, strlen(val)+1);

//This isn't allowed
printf("Trying to open file for reading...\n");
int input = open("output.txt", O_RDONLY);

printf("You will not see this message--the process will be killed first\n");
}
```
### Seccomp-bpf

このモードは、Berkeley Packet Filter ルールを使用して実装された設定可能なポリシーを使用してシステムコールをフィルタリングすることを可能にします。
```c
#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

//https://security.stackexchange.com/questions/168452/how-is-sandboxing-implemented/175373
//gcc seccomp_bpf.c -o seccomp_bpf -lseccomp

void main(void) {
/* initialize the libseccomp context */
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

/* allow exiting */
printf("Adding rule : Allow exit_group\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);

/* allow getting the current pid */
//printf("Adding rule : Allow getpid\n");
//seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0);

printf("Adding rule : Deny getpid\n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
/* allow changing data segment size, as required by glibc */
printf("Adding rule : Allow brk\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);

/* allow writing up to 512 bytes to fd 1 */
printf("Adding rule : Allow write upto 512 bytes to FD 1\n");
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));

/* if writing to any other fd, return -EBADF */
printf("Adding rule : Deny write to any FD except 1 \n");
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));

/* load and enforce the filters */
printf("Load rules and enforce \n");
seccomp_load(ctx);
seccomp_release(ctx);
//Get the getpid is denied, a weird number will be returned like
//this process is -9
printf("this process is %d\n", getpid());
}
```
## DockerにおけるSeccomp

**Seccomp-bpf**は、**Docker**によってサポートされており、コンテナからの**syscalls**を制限することで効果的に表面積を減らすことができます。**デフォルトでブロックされているsyscalls**は[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)で見つけることができ、**デフォルトのseccompプロファイル**はこちらにあります[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)。\
異なるseccompポリシーを使用してdockerコンテナを実行することができます:
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
たとえば、`uname`のような**syscall**の実行を**禁止**したい場合は、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) からデフォルトプロファイルをダウンロードし、単純に**リストから`uname`の文字列を削除**すればよいです。\
**あるバイナリがdockerコンテナ内で動作しないように**するには、straceを使用してバイナリが使用している**syscall**をリストアップし、それらを禁止することができます。\
次の例では、`uname`の**syscalls**が発見されます：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
**Dockerを単にアプリケーションを起動するために使用している場合**、**`strace`**でそれを**プロファイリング**し、必要な**システムコールのみを許可**できます。
{% endhint %}

### Seccompポリシーの例

[こちらの例](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)からの例を示します。

Seccomp機能を説明するために、以下のように「chmod」システムコールを無効にするSeccompプロファイルを作成します。
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
上記のプロファイルでは、デフォルトアクションを「allow」に設定し、「chmod」を無効にするブラックリストを作成しました。より安全にするために、デフォルトアクションを「drop」に設定し、システムコールを選択的に有効にするホワイトリストを作成することができます。\
以下の出力は、seccompプロファイルで無効になっているため、「chmod」呼び出しがエラーを返すことを示しています。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下は、プロファイルを表示する「docker inspect」の出力を示しています：
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Dockerで無効にする

フラグを使用してコンテナを起動します：**`--security-opt seccomp=unconfined`**

Kubernetes 1.19では、**すべてのPodに対してseccompがデフォルトで有効**になっています。ただし、Podに適用されるデフォルトのseccompプロファイルは、コンテナランタイム（例：Docker、containerd）によって**提供される** "**RuntimeDefault**"プロファイルです。 "RuntimeDefault"プロファイルは、ほとんどのシステムコールを許可し、コンテナにとって危険または一般的に必要とされないいくつかのシステムコールをブロックします。
