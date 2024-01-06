<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# 基本情報

**Seccomp**（セキュアコンピューティングモードの略）は、要約すると、**システムコールフィルター**として機能するLinuxカーネルの機能です。
Seccompには2つのモードがあります。

**seccomp**は**Linux** **カーネル**のコンピュータセキュリティ機能です。seccompを使用すると、プロセスは"セキュア"な状態に一方向の遷移を行い、**既に開かれた**ファイルディスクリプタに対して`exit()`、`sigreturn()`、`read()`、`write()`以外の**システムコールを行うことができなくなります**。他のシステムコールを試みた場合、**カーネル**はSIGKILLまたはSIGSYSで**プロセスを終了**します。この意味で、システムのリソースを仮想化するのではなく、プロセスを完全に隔離します。

seccompモードは、`PR_SET_SECCOMP`引数を使用して`prctl(2)`システムコールを介して**有効にされます**、または（Linuxカーネル3.17以降）`seccomp(2)`システムコールを介して有効にされます。seccompモードは以前は`/proc/self/seccomp`というファイルに書き込むことで有効にされていましたが、`prctl()`を優先するためにこの方法は削除されました。一部のカーネルバージョンでは、電源オン以降の経過プロセッササイクル数を返すx86命令`RDTSC`が無効になります。これは高精度タイミングに使用されます。

**seccomp-bpf**は、Berkeley Packet Filterルールを使用して実装された設定可能なポリシーを使用してシステムコールをフィルタリングすることを可能にするseccompの拡張です。これは、Chrome OSとLinuxのGoogle Chrome/Chromiumウェブブラウザだけでなく、OpenSSHやvsftpdによって使用されています。（この点で、seccomp-bpfは古いsystraceと同様の機能を達成しますが、より柔軟性があり、パフォーマンスが高いです。Linuxではもはやサポートされていないようです。）

## **オリジナル/ストリクトモード**

このモードでは、**Seccomp**はシステムコール`exit()`、`sigreturn()`、`read()`、`write()`のみを既に開かれたファイルディスクリプタに対して許可します。他のシステムコールが行われた場合、プロセスはSIGKILLを使用して終了されます。

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
{% endcode %}

## Seccomp-bpf

このモードでは、Berkeley Packet Filterルールを使用して実装された設定可能なポリシーを使用してシステムコールのフィルタリングが可能です。

{% code title="seccomp_bpf.c" %}
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
{% endcode %}

# Docker内のSeccomp

**Seccomp-bpf**は、コンテナからの**syscalls**を効果的に制限し、攻撃対象領域を減少させるために**Docker**によってサポートされています。**デフォルトでブロックされているsyscalls**は[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)で確認でき、**デフォルトのseccompプロファイル**はこちらで見つけることができます[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)。\
異なる**seccomp**ポリシーを使用してdockerコンテナを実行するには：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
例えば、あるコンテナが`uname`のような**syscall**を実行するのを**禁止**したい場合は、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json) からデフォルトプロファイルをダウンロードし、リストから`uname`文字列を**削除する**だけです。\
あるバイナリが**dockerコンテナ内で動作しないことを確認したい**場合は、straceを使用してバイナリが使用しているsyscallsをリストアップし、それらを禁止することができます。\
次の例では、`uname`の**syscalls**が発見されます：
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
**アプリケーションを起動するためだけにDockerを使用している場合**、**`strace`** でプロファイリングし、必要なシステムコールのみを許可することができます。
{% endhint %}

## Dockerで無効にする

フラグを使用してコンテナを起動します: **`--security-opt seccomp=unconfined`**


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **HackTricks**のGitHubリポジトリ[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
