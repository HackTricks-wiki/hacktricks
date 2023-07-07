# Seccomp

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* あなたは**サイバーセキュリティ会社**で働いていますか？ HackTricksであなたの**会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、HackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有する**ために、[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。

</details>

## 基本情報

**Seccomp**またはSecure Computingモードは、Linuxカーネルの**シスコールフィルタ**として機能する機能です。\
Seccompには2つのモードがあります。

**seccomp**（セキュアコンピューティングモードの略）は、Linuxカーネルのコンピュータセキュリティ機能です。seccompは、プロセスが「セキュア」な状態に一方向で移行し、**既に開かれている**ファイルディスクリプタに対して`exit()`、`sigreturn()`、`read()`、`write()`以外のシステムコールを行うことができなくなります。他のシステムコールを試みると、カーネルはSIGKILLまたはSIGSYSでプロセスを**終了**します。この意味では、システムのリソースを仮想化するのではなく、プロセスをそれらから完全に分離します。

seccompモードは、`prctl(2)`システムコールを使用して`PR_SET_SECCOMP`引数を介して有効にされます。または（Linuxカーネル3.17以降）`seccomp(2)`システムコールを介して有効にされます。seccompモードは、一部のカーネルバージョンでは、高精度タイミングに使用される、電源オンからの経過したプロセッササイクル数を返す`RDTSC` x86命令を無効にします。

**seccomp-bpf**は、Berkeley Packet Filterルールを使用して実装された設定可能なポリシーを使用してシステムコールをフィルタリングするseccompの拡張機能です。これは、OpenSSHやvsftpd、およびChrome OSおよびLinux上のGoogle Chrome/Chromiumウェブブラウザに使用されます。（この点で、seccomp-bpfは、Linuxではもはやサポートされていないようですが、より柔軟性と高いパフォーマンスを持つ古いsystraceと同様の機能を実現します。）

### **オリジナル/厳格モード**

このモードでは、Seccompは`exit()`、`sigreturn()`、`read()`、`write()`のシスコールのみを許可します。他のシスコールが行われると、プロセスはSIGKILLを使用して終了します。

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

## DockerにおけるSeccomp

**Seccomp-bpf**は、**Docker**でサポートされており、コンテナからの**syscalls**を制限することで、効果的に表面積を減らすことができます。デフォルトで**ブロックされるsyscalls**は[https://docs.docker.com/engine/security/seccomp/](https://docs.docker.com/engine/security/seccomp/)で見つけることができ、デフォルトのseccompプロファイルは[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)で見つけることができます。\
異なるseccompポリシーでdockerコンテナを実行するには、以下のコマンドを使用します：
```bash
docker run --rm \
-it \
--security-opt seccomp=/path/to/seccomp/profile.json \
hello-world
```
たとえば、`uname`のような特定の**システムコール**を実行するコンテナを**禁止**したい場合は、[https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)からデフォルトのプロファイルをダウンロードし、リストから`uname`の文字列を**削除**するだけです。\
あるバイナリがDockerコンテナ内で動作しないようにするには、straceを使用してバイナリが使用しているシステムコールをリストアップし、それらを禁止します。\
以下の例では、`uname`のシステムコールが発見されます。
```bash
docker run -it --security-opt seccomp=default.json modified-ubuntu strace uname
```
{% hint style="info" %}
アプリケーションを起動するためにDockerを使用している場合、**`strace`**を使用してアプリケーションを**プロファイル**し、必要なシステムコールのみを許可することができます。
{% endhint %}

### サンプルのSeccompポリシー

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
上記のプロファイルでは、デフォルトのアクションを「許可」に設定し、「chmod」を無効にするためのブラックリストを作成しました。より安全にするために、デフォルトのアクションをドロップに設定し、システムコールを選択的に有効にするためのホワイトリストを作成することができます。\
以下の出力は、seccompプロファイルで無効にされているため、「chmod」呼び出しがエラーを返すことを示しています。
```bash
$ docker run --rm -it --security-opt seccomp:/home/smakam14/seccomp/profile.json busybox chmod 400 /etc/hosts
chmod: /etc/hosts: Operation not permitted
```
以下の出力は、プロファイルを表示する「docker inspect」の結果を示しています：
```json
"SecurityOpt": [
"seccomp:{\"defaultAction\":\"SCMP_ACT_ALLOW\",\"syscalls\":[{\"name\":\"chmod\",\"action\":\"SCMP_ACT_ERRNO\"}]}"
],
```
### Dockerで無効にする

フラグ**`--security-opt seccomp=unconfined`**を使用してコンテナを起動します。

Kubernetes 1.19以降、**すべてのPodに対してseccompがデフォルトで有効**になっています。ただし、Podに適用されるデフォルトのseccompプロファイルは、コンテナランタイム（例：Docker、containerd）によって提供される「RuntimeDefault」プロファイルです。この「RuntimeDefault」プロファイルは、ほとんどのシステムコールを許可し、コンテナにとって危険または一般的に必要ではないとされるいくつかのシステムコールをブロックします。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか？または、**HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **および** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
