<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


# 基本情報

**Seccomp**またはセキュアコンピューティングモードは、要約すると、**シスコールフィルタ**として機能するLinuxカーネルの機能です。\
Seccompには2つのモードがあります。

**seccomp**（セキュアコンピューティングモードの略）は、**Linuxカーネル**のコンピュータセキュリティ機能です。seccompを使用すると、プロセスは「セキュア」な状態に一方向で移行し、**既に開かれている**ファイルディスクリプタに対して`exit()`、`sigreturn()`、`read()`、`write()`以外の**システムコールを行うことはできません**。他のシステムコールを試みると、**カーネル**はSIGKILLまたはSIGSYSで**プロセスを終了**します。この意味では、システムのリソースを仮想化するのではなく、プロセスをそれらから完全に分離します。

seccompモードは、`prctl(2)`システムコールを使用して`PR_SET_SECCOMP`引数を介して有効にされます。または（Linuxカーネル3.17以降）`seccomp(2)`システムコールを介して有効にされます。seccompモードは、一部のカーネルバージョンでは、高精度タイミングに使用される、電源オンからの経過したプロセッササイクル数を返す`RDTSC` x86命令を無効にします。

**seccomp-bpf**は、Berkeley Packet Filterルールを使用して実装された設定可能なポリシーを使用してシステムコールをフィルタリングするseccompの拡張機能です。これは、OpenSSHやvsftpd、Chrome OSおよびLinux上のGoogle Chrome/Chromiumウェブブラウザなどで使用されています。（この点で、seccomp-bpfは、Linuxではもはやサポートされていないようですが、より柔軟性と高いパフォーマンスを持つ古いsystraceと同様の機能を実現します。）

## **オリジナル/厳格モード**

このモードでは、**Seccompは`exit()`、`sigreturn()`、`read()`、`write()`のシスコールのみを許可**します。他のシスコールが行われると、プロセスはSIGKILLを使用して終了します。

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
## Seccomp-bpf

このモードでは、Berkeley Packet Filter ルールを使用して設定可能なポリシーを実装することで、システムコールのフィルタリングが可能です。

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

# DockerにおけるSeccomp

**Seccomp-bpf**は、**Docker**でサポートされており、コンテナからの**syscalls**を制限することで、効果的に表面積を減らすことができます。デフォルトで**ブロックされるsyscalls**は、[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)で見つけることができ、デフォルトのseccompプロファイルは[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)で見つけることができます。\
異なるseccompポリシーを持つdockerコンテナを実行するには、次のコマンドを使用します：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
たとえば、`uname`のような特定のシステムコールを実行できないようにする場合、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)からデフォルトのプロファイルをダウンロードし、リストから`uname`の文字列を削除するだけです。\
あるバイナリがDockerコンテナ内で動作しないようにするには、straceを使用してバイナリが使用しているシステムコールをリストアップし、それらを禁止します。\
次の例では、`uname`のシステムコールが発見されます。
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
**アプリケーションを起動するためにDockerを使用している場合**は、**`strace`**を使用してそれを**プロファイル**し、必要なシスコールのみを**許可**することができます。
{% endhint %}

## Dockerで無効にする

フラグ**`--security-opt seccomp=unconfined`**を使用してコンテナを起動します。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
