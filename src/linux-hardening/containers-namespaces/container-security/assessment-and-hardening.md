# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## 概要

優れた container assessment では、2つの並行した問いに答えられる必要があります。第一に、現在の workload から attacker は何ができるのか。第二に、それを可能にした operator の選択は何か。Enumeration tools は前者の問いに役立ち、hardening guidance は後者に役立ちます。両方を同じページにまとめることで、このセクションは単なる escape tricks のカタログではなく、現場で参照しやすい資料になります。

modern environments で実務上重要な更新点は、古い container writeups の多くが、暗黙のうちに **rootful runtime**、**user namespace isolation なし**、そして多くの場合 **cgroup v1** を前提としていることです。これらの前提は、もはや安全ではありません。古い escape primitives に時間をかける前に、まず workload が rootless または userns-remapped か、host が cgroup v2 を使用しているか、そして Kubernetes または runtime が default seccomp および AppArmor profiles を適用しているかを確認してください。これらの詳細によって、有名な breakout が依然として適用可能かどうかが決まることがよくあります。

## Enumeration Tools

container environment を迅速に把握するために、現在も多くの tools が役立ちます。

- `linpeas` は、多数の container indicators、mounted sockets、capability sets、危険な filesystems、および breakout hints を特定できます。
- `CDK` は特に container environments に焦点を当てており、enumeration に加えて自動化された escape checks も含んでいます。
- `amicontained` は軽量で、container restrictions、capabilities、namespace exposure、および想定される breakout classes の特定に役立ちます。
- `deepce` も container に特化した enumerator で、breakout を重視した checks を備えています。
- `grype` は、runtime escape analysis だけでなく image-package vulnerability review も assessment に含める場合に役立ちます。
- `Tracee` は static posture だけではなく **runtime evidence** が必要な場合に役立ちます。特に、不審な process execution、file access、および container-aware event collection に有用です。
- `Inspektor Gadget` は Kubernetes および Linux-host investigations で、pods、containers、namespaces、その他の higher-level concepts に関連付けられた eBPF-backed visibility が必要な場合に役立ちます。

これらの tools の価値は、確実性ではなく speed と coverage にあります。これらは全体的な posture を迅速に明らかにするのに役立ちますが、興味深い findings については、実際の runtime、namespace、capability、および mount model に照らして、なお手動で解釈する必要があります。

## Hardening Priorities

最も重要な hardening principles は、platform によって実装が異なるとはいえ、概念的には単純です。privileged containers を避けてください。mounted runtime sockets を避けてください。非常に具体的な理由がない限り、containers に writable host paths を与えないでください。可能な場合は user namespaces または rootless execution を使用してください。すべての capabilities を drop し、workload が本当に必要とするものだけを追加してください。application compatibility の問題を解決するために seccomp、AppArmor、および SELinux を無効化するのではなく、有効なまま維持してください。compromised container が host に対して容易に denial of service を実行できないように、resources を制限してください。

image と build の hygiene は、runtime posture と同じくらい重要です。minimal images を使用し、頻繁に rebuild し、scan を実施し、実用的な場合は provenance を要求し、secrets を layers に保存しないでください。non-root として実行される、小さな image と限定的な syscall および capability surface を持つ container は、debugging tools があらかじめインストールされた大規模な convenience image を、host と同等の root として実行する場合よりも、はるかに防御しやすくなります。

Kubernetes では、現在の hardening baselines は、依然として多くの operators が想定しているよりも厳格です。組み込みの **Pod Security Standards** では、`restricted` を「current best practice」profile として扱っています。`allowPrivilegeEscalation` は `false` にすべきであり、workloads は non-root として実行し、seccomp は `RuntimeDefault` または `Localhost` に明示的に設定し、capability sets は積極的に drop すべきです。assessment 中にこれが重要なのは、`warn` または `audit` labels のみを使用している cluster が、書面上は hardened に見えても、実際には risky pods の admission を許可している可能性があるためです。<sup>[[1]](#references)</sup>

## Modern Triage Questions

escape-specific pages に進む前に、次の簡単な質問に答えてください。

1. workload は **rootful**、**rootless**、それとも **userns-remapped** ですか？
2. node は **cgroup v1** と **cgroup v2** のどちらを使用していますか？
3. **seccomp** と **AppArmor/SELinux** は明示的に設定されていますか。それとも、利用可能な場合に単に継承されるだけですか？
4. Kubernetes では、namespace は実際に `baseline` または `restricted` を **enforcing** していますか。それとも warning/auditing のみですか？

Useful checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
ここで注目すべき点:

- `/proc/self/uid_map` に、container root が **high host UID range** にマッピングされていることが示されている場合、container 内の root はもはや host-root と同等ではないため、古い host-root writeup の多くは関連性が低くなります。
- `/sys/fs/cgroup` が `cgroup2fs` の場合、`release_agent` abuse などの古い **cgroup v1** 固有の writeup を最初に疑うべきではありません。
- seccomp と AppArmor が暗黙的に継承されているだけの場合、portability は defenders が想定するより弱い可能性があります。Kubernetes では、node の defaults に黙って依存するよりも、`RuntimeDefault` を明示的に設定する方が強固なことがよくあります。
- `supplementalGroupsPolicy` が `Strict` に設定されている場合、pod は image 内の `/etc/group` から追加の group membership を暗黙的に継承しないようにする必要があります。これにより、group ベースの volume および file access の挙動が予測しやすくなります。
- `pod-security.kubernetes.io/enforce=restricted` などの namespace label は、直接確認する価値があります。`warn` と `audit` は有用ですが、risk のある pod の作成を阻止するものではありません。

## Runtime Baseline Triage

runtime baseline は、container が通常の隔離された workload に見えるのか、それとも host に影響を及ぼす control plane foothold のように見えるのかを素早く判断するための確認です。次に読むべき項目、つまり runtime socket abuse、host mount、namespace、cgroup、capability、または image-secret review の優先順位を決めるのに十分な情報を収集します。

workload 内から実行できる有用なチェック:
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
解釈:

- `memory.max` / `pids.max` が欠落している、または無制限である場合、完全な escape がなくても blast radius の制御が弱いことを示します。
- `NoNewPrivs: 0` の root shell、広範な capabilities、permissive な seccomp の組み合わせは、限定的な non-root workload よりもはるかに興味深い対象です。
- Runtime sockets と書き込み可能な host mounts は、すでに management または filesystem の control path を露出しているため、通常は kernel exploits よりも優先度が高くなります。
- Shared PID、network、IPC、または cgroup namespaces は、それだけで常に完全な escape になるわけではありませんが、次のステップを見つけやすくします。

## Resource-Exhaustion Examples

Resource controls は華やかなものではありませんが、compromise の blast radius を制限するため、container security の一部です。memory、CPU、または PID limits がなければ、単純な shell だけで host または隣接する workloads の性能を低下させるのに十分な場合があります。

Host に影響を与えるテストの例:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
これらの例が有用なのは、危険な container の結果が必ずしも完全な「escape」になるわけではないことを示しているためです。弱い cgroup の制限でも、code execution を実際の運用上の影響に変える可能性があります。

Kubernetes-backed 環境では、DoS を理論上の問題として扱う前に、resource control がそもそも存在するかどうかも確認してください：
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker中心の環境では、`docker-bench-security` は、広く認知されたベンチマークのガイダンスに照らして一般的な設定上の問題をチェックするため、host側のaudit baselineとして引き続き有用です:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
この tool は threat modeling の代替にはなりませんが、時間の経過とともに蓄積する、注意不足な daemon、mount、network、runtime のデフォルト設定を見つけるうえでは依然として有用です。

Kubernetes や runtime の比重が大きい環境では、static checks と runtime visibility を組み合わせてください。

- `Tracee` は container-aware な runtime detection や、侵害された workload が実際に何に触れたのかを確認する必要がある場合の迅速な forensics に有用です。
- `Inspektor Gadget` は、assessment で kernel-level telemetry を pods、containers、DNS activity、file execution、network behavior に対応付ける必要がある場合に有用です。

## Checks

assessment 中に first-pass で実行するコマンドとして、以下を使用してください。
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
ここで注目すべき点:

- 広範な capabilities を持ち、`Seccomp: 0` である root プロセスには、直ちに注意を払うべきです。
- **1:1 UID map** も持つ root プロセスは、適切に分離された user namespace 内の「root」よりもはるかに興味深い対象です。
- `cgroup2fs` は通常、古い **cgroup v1** の escape chain の多くが最適な出発点ではないことを意味します。一方、`memory.max` または `pids.max` が存在しない場合は、blast radius の制御が弱いことを示します。
- 不審な mount や runtime socket は、kernel exploit よりも速く impact に到達できることがよくあります。
- 弱い runtime posture と弱い resource limits の組み合わせは、単一の孤立した設定ミスではなく、全般的に permissive な container environment であることを示す場合が多くあります。

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
