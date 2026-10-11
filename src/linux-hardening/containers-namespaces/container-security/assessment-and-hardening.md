# 評価とハードニング

{{#include ../../../banners/hacktricks-training.md}}

## 概要

適切なコンテナ評価では、2つの問いに並行して答える必要があります。1つ目は、現在のワークロードから攻撃者が何をできるか。2つ目は、それを可能にした運用者の選択は何か、です。列挙ツールは1つ目の問いに役立ち、ハードニングの指針は2つ目の問いに役立ちます。この2つを同じページにまとめることで、単なるescape手法の一覧ではなく、現場で使えるリファレンスになります。

現代の環境向けに更新するうえで実践的なのは、古いコンテナ関連の記事の多くが暗黙のうちに**rootful runtime**、**user namespace isolationなし**、そして多くの場合**cgroup v1**を前提としている点です。もはや、これらの前提は安全ではありません。古いescape手法に時間をかける前に、まずワークロードがrootlessかuserns-remappedか、ホストがcgroup v2を使用しているか、KubernetesまたはruntimeがデフォルトのseccompプロファイルとAppArmorプロファイルを適用しているかを確認してください。こうした詳細によって、有名なbreakout手法が今も有効かどうかが決まることがよくあります。

## 列挙ツール

コンテナ環境をすばやく特徴づけるうえで、今でも役立つツールがいくつかあります。

- `linpeas` は、多くのコンテナ関連の指標、マウントされたsocket、capabilityセット、危険なfilesystem、breakoutの手がかりを特定できます。
- `CDK` はコンテナ環境に特化しており、列挙機能に加えて、自動化されたescapeチェックも備えています。
- `amicontained` は軽量で、コンテナの制限、capability、namespaceの露出、発生しそうなbreakoutの種類を特定するのに役立ちます。
- `deepce` は、breakoutを重視したチェックを備える、コンテナに特化した別の列挙ツールです。
- `grype` は、runtime escape分析だけでなく、イメージ内パッケージの脆弱性レビューも評価に含める場合に役立ちます。
- `Tracee` は、静的な設定状況だけでなく**runtimeの証拠**が必要な場合に役立ちます。特に、不審なプロセス実行、ファイルアクセス、コンテナを考慮したイベント収集に有用です。
- `Inspektor Gadget` は、pod、コンテナ、namespaceなどのより上位の概念にひも付いた、eBPFベースの可視性が必要なKubernetesおよびLinuxホストの調査に役立ちます。

これらのツールの価値は、確実性ではなく速度と網羅性にあります。大まかな状況をすばやく把握できますが、興味深い検出結果は、実際のruntime、namespace、capability、mountのモデルに照らして、引き続き手動で解釈する必要があります。

## ハードニングの優先事項

最も重要なハードニングの原則は、プラットフォームによって実装は異なるものの、概念的には単純です。privilegedコンテナを避けてください。runtime socketをマウントしないでください。特別な理由がない限り、コンテナに書き込み可能なホストパスを与えないでください。可能な場合はuser namespaceまたはrootless実行を使用してください。すべてのcapabilityを削除し、ワークロードに本当に必要なものだけを追加してください。アプリケーションの互換性問題を解決するために無効化するのではなく、seccomp、AppArmor、SELinuxを有効に保ってください。侵害されたコンテナがホストのサービスを容易に妨害できないよう、リソースを制限してください。

イメージとビルドの衛生管理も、runtimeの設定と同じくらい重要です。最小限のイメージを使用し、頻繁に再ビルドしてスキャンし、可能な場合はprovenanceを必須にし、secretをレイヤーに残さないでください。非rootで動作し、イメージが小さく、syscallとcapabilityの範囲が狭いコンテナは、ホストと同等のroot権限でデバッグツールがあらかじめインストールされた大きな便利イメージよりも、はるかに防御しやすくなります。

Kubernetesの現在のハードニングベースラインは、多くの運用者がいまだに想定しているよりも厳格です。組み込みの**Pod Security Standards**では、`restricted`が「現在のベストプラクティス」プロファイルとして扱われます。`allowPrivilegeEscalation`は`false`にし、ワークロードは非rootで実行し、seccompは`RuntimeDefault`または`Localhost`に明示的に設定し、capabilityセットは積極的に削除する必要があります。評価において重要なのは、クラスターが`warn`または`audit`ラベルだけを使用している場合、書面上はハードニングされているように見えても、実際にはリスクの高いpodを許可している可能性がある点です。<sup>[[1]](#references)</sup>

Podにservice-account tokenがマウントされている場合は、権限を**対象namespaceごとに**評価してください。あるnamespace内のPodを列挙するルールがあっても、別のnamespaceでの権限が示されるわけではありません。別のPodにマウントされたtokenは、異なる権限を持つ可能性があります。実際に評価対象となるidentityを使って、`kubectl auth can-i list pods -n <target-namespace>`と`kubectl auth can-i list secrets -n <target-namespace>`を実行してください。Secretのlistが許可されている場合は重大な手がかりになります。listの応答にはSecretの内容が含まれ得ますが、それだけではprivileged tokenの存在を証明できません。ホストへのアクセスにはさらに、利用可能なワークロード作成権限、提案された`hostPath` mountの許可、そして意図したファイル操作を可能にするnode/podのsecurity contextが必要です。Kubernetesの[認可チェック](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)と[RBACの権限昇格に関するガイダンス](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)を参照してください。

## 現代のトリアージで確認すること

escapeに特化したページを読み込む前に、次の簡単な質問に答えてください。

1. ワークロードは**rootful**、**rootless**、**userns-remapped**のどれですか？
2. nodeは**cgroup v1**と**cgroup v2**のどちらを使用していますか？
3. **seccomp**と**AppArmor/SELinux**は明示的に設定されていますか。それとも利用可能な場合に継承されるだけですか？
4. Kubernetesでは、namespaceで`baseline`または`restricted`が実際に**enforcing**されていますか。それともwarning/auditのみですか？

確認に役立つコマンド：

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

- `/proc/self/uid_map` でコンテナの root が **ホスト上の高い UID 範囲**にマッピングされている場合、コンテナ内の root はもはやホストの root と同等ではないため、古いホスト root に関する writeup の多くは関連性が低くなります。
- `/sys/fs/cgroup` が `cgroup2fs` の場合、`release_agent` の悪用など、古い **cgroup v1** 固有の writeup を最初に疑うべきではありません。
- seccomp と AppArmor が暗黙的にのみ継承されている場合、移植性は防御側が想定するより低い可能性があります。Kubernetes では、ノードのデフォルト設定に暗黙的に依存するよりも、`RuntimeDefault` を明示的に設定するほうが堅牢なことがよくあります。
- `supplementalGroupsPolicy` が `Strict` に設定されている場合、pod はイメージ内の `/etc/group` から追加のグループメンバーシップを暗黙的に継承しないはずです。これにより、グループベースのボリュームやファイルへのアクセス動作がより予測しやすくなります。
- `pod-security.kubernetes.io/enforce=restricted` のような Namespace ラベルは、直接確認する価値があります。`warn` と `audit` も有用ですが、リスクのある pod の作成を阻止するものではありません。

## ランタイムのベースライン・トリアージ

ランタイムのベースライン確認は、コンテナが一般的な隔離ワークロードに見えるのか、ホストに影響を及ぼす制御プレーンの足掛かりに見えるのかを素早く把握するためのものです。次に読むべきページの優先順位を決めるのに十分な情報、つまりランタイムソケットの悪用、ホストマウント、Namespace、cgroup、capability、イメージ内のシークレットの確認に関する情報を収集します。

ワークロード内から実行する有用な確認項目:

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

- `memory.max` / `pids.max` が未設定または無制限の場合、明確な escape がなくても blast radius の制御が弱いことを示します。
- `NoNewPrivs: 0`、広範な capabilities、制限の緩い seccomp を備えた root shell は、制限された non-root workload よりもはるかに注目すべきです。
- Runtime socket と書き込み可能なホストマウントは、すでに管理またはファイルシステムへの制御経路を露出しているため、通常は kernel exploit より優先度が高くなります。
- PID、network、IPC、または cgroup namespace の共有だけで常に完全な escape が実現するわけではありませんが、次の手がかりを見つけやすくなります。

## リソース枯渇の例

リソース制御は華やかなものではありませんが、侵害の blast radius を制限するため、container security の一部です。メモリ、CPU、または PID の制限がなければ、単純な shell だけでホストや隣接する workload のパフォーマンスを低下させる可能性があります。

ホストに影響を与えるテストの例:

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

これらの例は、危険なコンテナの影響がすべて明確な「escape」とは限らないことを示しているため、有用です。cgroup の制限が弱い場合でも、コード実行が実際の運用上の影響につながる可能性があります。

Kubernetes を基盤とする環境では、DoS を理論上の脅威と見なす前に、リソース制御がそもそも存在するかどうかも確認してください。

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## Hardening Tooling

Docker中心の環境では、`docker-bench-security` は広く認知されたベンチマークのガイダンスに照らして一般的な設定上の問題をチェックするため、ホスト側の監査ベースラインとして引き続き有用です。設定ベンチマークでは、インストール済みのランタイムが新たに公表された脆弱性の影響を受けるかどうかは検出できないため、ランタイムに関するアドバイザリは別途確認してください。 <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

このツールは脅威モデリングの代わりにはなりませんが、時間とともに蓄積する、注意不足による daemon、mount、network、runtime のデフォルト設定を見つけるうえでは依然として有用です。

Kubernetes や runtime を多用する環境では、静的チェックと runtime の可視性を組み合わせてください。

- `Tracee` は、コンテナを考慮した runtime 検知や、侵害された workload が実際に何に触れたかを確認する必要がある場合の迅速なフォレンジックに役立ちます。
- `Inspektor Gadget` は、kernel レベルのテレメトリを pod、container、DNS アクティビティ、ファイル実行、network の挙動に対応付ける必要がある評価に役立ちます。

## チェック

評価の初期段階で、手早く確認するために以下のコマンドを使います。

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

- 広範な capabilities を持ち、`Seccomp: 0` の root プロセスは、すぐに注意を払う必要があります。
- **1:1 UID map** も持つ root プロセスは、適切に隔離された user namespace 内の「root」よりもはるかに注目に値します。
- `cgroup2fs` の場合、古い **cgroup v1** の多くの escape chain は最初に調べる対象として最適ではないことが多い一方、`memory.max` や `pids.max` がない場合は、blast radius を抑える制御が弱いことを示しています。
- 不審なマウントや runtime socket は、多くの場合、kernel exploit よりも迅速に影響を及ぼす経路になります。
- runtime のセキュリティ態勢が弱く、resource limit も弱い場合は、単独のミスではなく、全般的に制限の緩い container 環境であることを示す場合がよくあります。

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker セキュリティアドバイザリ: runc、BuildKit、Moby における複数の脆弱性](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
