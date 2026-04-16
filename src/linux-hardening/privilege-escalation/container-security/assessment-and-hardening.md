# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## Overview

優れた container assessment は、2つの並行した問いに答えるべきです。1つ目は、現在の workload から attacker は何ができるか。2つ目は、それを可能にした operator の選択は何か。Enumeration tools は1つ目の問いを助け、hardening guidance は2つ目を助けます。両方を1ページにまとめることで、単なる escape tricks のカタログではなく、現場向けの参照資料としてこのセクションがより有用になります。

現代の環境における実用的な更新点として、多くの古い container の記述は、ひそかに **rootful runtime**、**no user namespace isolation**、そしてしばしば **cgroup v1** を前提にしています。これらの前提はもはや安全ではありません。古い escape primitives に時間をかける前に、まず workload が rootless か userns-remapped か、host が cgroup v2 を使っているか、そして Kubernetes または runtime がデフォルトの seccomp と AppArmor profiles を適用しているかを確認してください。これらの詳細が、有名な breakout が今でも当てはまるかどうかを左右することがよくあります。

## Enumeration Tools

container 環境を素早く把握するのに役立つ tool はいくつかあります。

- `linpeas` は、多くの container indicators、mounted sockets、capability sets、dangerous filesystems、そして breakout のヒントを特定できます。
- `CDK` は container 環境に特化しており、enumeration に加えていくつかの自動 escape checks を含みます。
- `amicontained` は軽量で、container 制限、capabilities、namespace exposure、そして起こりそうな breakout classes の特定に役立ちます。
- `deepce` も container 向けの enumerator で、breakout 指向の checks を備えています。
- `grype` は、評価対象が runtime escape analysis だけでなく image-package vulnerability review を含む場合に役立ちます。
- `Tracee` は、静的な姿勢だけでなく **runtime evidence** が必要なとき、特に不審な process execution、file access、container-aware な event collection に役立ちます。
- `Inspektor Gadget` は、Kubernetes と Linux-host の調査で、pods、containers、namespaces、その他のより高レベルな概念に結びついた eBPF ベースの可視化が必要なときに役立ちます。

これらの tool の価値は、正確性ではなく速度と網羅性にあります。大まかな姿勢を素早く明らかにするのに役立ちますが、興味深い findings は、実際の runtime、namespace、capability、mount model と照らして手動で解釈する必要があります。

## Hardening Priorities

最も重要な hardening の原則は、platform ごとに実装は異なっても、概念的には単純です。privileged containers を避けること。mounted runtime sockets を避けること。明確な理由がない限り、containers に writable な host paths を与えないこと。可能なら user namespaces または rootless execution を使うこと。すべての capabilities を削除し、workload が本当に必要とするものだけを追加すること。互換性問題を修正するために seccomp、AppArmor、SELinux を無効化するのではなく、有効に保つこと。compromise された container が host に対して容易に service denial を起こせないよう、resources を制限すること。

image と build の hygiene も、runtime posture と同じくらい重要です。最小限の images を使い、頻繁に rebuild し、scan し、可能な範囲で provenance を要求し、secrets を layers に残さないこと。non-root で動作し、image が小さく、syscall と capability の surface が狭い container は、debugging tools があらかじめ入った host-equivalent root で動作する大きな convenience image よりもはるかに防御しやすいです。

Kubernetes では、現在の hardening baselines は、多くの operator が今も想定しているものより意見が強くなっています。組み込みの **Pod Security Standards** では、`restricted` を「current best practice」profile として扱います。`allowPrivilegeEscalation` は `false` であるべきで、workloads は non-root で実行し、seccomp は `RuntimeDefault` または `Localhost` に明示的に設定し、capability sets は積極的に削除すべきです。assessment の際にこれが重要なのは、`warn` または `audit` ラベルだけを使っている cluster は、見た目には hardened に見えても、実際には risky な pods を許可している可能性があるからです。

## Modern Triage Questions

escape-specific なページに入る前に、次の簡単な質問に答えてください。

1. workload は **rootful**、**rootless**、それとも **userns-remapped** か？
2. node は **cgroup v1** か **cgroup v2** か？
3. **seccomp** と **AppArmor/SELinux** は明示的に設定されているか、それとも利用可能な場合に継承されているだけか？
4. Kubernetes では、namespace は実際に `baseline` または `restricted` を **enforcing** しているか、それとも warning/auditing だけか？

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
ここで興味深いのは次の点です:

- `/proc/self/uid_map` がコンテナの root を **高い host UID 範囲** にマップしている場合、古い host-root 系の writeup の多くはあまり重要ではなくなります。なぜなら、コンテナ内の root はもはや host-root と同等ではないからです。
- `/sys/fs/cgroup` が `cgroup2fs` であれば、`release_agent` 悪用のような古い **cgroup v1** 専用の writeup は、もはや最初に疑うべきものではありません。
- seccomp と AppArmor が暗黙的に継承されるだけなら、移植性は防御側が期待するより弱い場合があります。Kubernetes では、`RuntimeDefault` を明示的に設定する方が、ノードのデフォルトに黙って依存するよりも強いことが多いです。
- `supplementalGroupsPolicy` が `Strict` に設定されている場合、pod は image 内の `/etc/group` から余分な group membership を黙って継承しないようにすべきです。これにより、group ベースの volume および file access の挙動がより予測しやすくなります。
- `pod-security.kubernetes.io/enforce=restricted` のような namespace labels は、直接確認する価値があります。`warn` と `audit` は有用ですが、危険な pod の作成を止めるものではありません。

## Resource-Exhaustion Examples

resource controls は華やかではありませんが、container security の一部です。なぜなら、compromise の blast radius を制限するからです。memory、CPU、PID の制限がなければ、単純な shell だけで host や隣接する workload を劣化させるのに十分な場合があります。

ホストへ影響するテストの例:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
これらの例は有用です。なぜなら、危険な container の結果がすべてきれいな「escape」ではないことを示しているからです。弱い cgroup 制限でも、code execution を実際の operational impact に変えられます。

Kubernetes-backed 環境では、DoS を理論上のものとして扱う前に、そもそも resource controls が存在するかどうかも確認してください:
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

Docker中心の環境では、`docker-bench-security` は引き続き有用なホスト側の監査ベースラインです。これは、広く認知されたベンチマーク指針に照らして一般的な設定不備を確認するためです:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
このツールは threat modeling の代替ではありませんが、時間とともに蓄積される不注意な daemon、mount、network、runtime のデフォルト設定を見つけるうえでは依然として有用です。

Kubernetes と runtime-heavy な環境では、静的チェックと runtime の可視性を組み合わせます。

- `Tracee` は、container-aware な runtime detection と、侵害された workload が実際に何に触れたのかを確認する必要があるときの迅速な forensics に役立ちます。
- `Inspektor Gadget` は、評価で kernel-level telemetry を pods、containers、DNS activity、file execution、または network behavior にマッピングして把握する必要がある場合に役立ちます。

## Checks

assessment 中の簡易な first-pass コマンドとして、以下を使用します:
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

- 広範な capabilities と `Seccomp: 0` を持つ root process は、直ちに注意が必要です。
- さらに **1:1 UID map** を持つ root process は、適切に分離された user namespace 内の「root」よりもはるかに重要です。
- `cgroup2fs` は通常、古い **cgroup v1** の escape chain の多くが最善の出発点ではないことを意味しますが、`memory.max` や `pids.max` が欠けている場合は、依然として弱い blast-radius 制御を示します。
- 疑わしい mounts と runtime sockets は、kernel exploit よりも早く影響に到達できることがよくあります。
- 弱い runtime posture と弱い resource limits の組み合わせは、通常、単独の isolated なミスというより、全体として permissive な container environment を示します。

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
