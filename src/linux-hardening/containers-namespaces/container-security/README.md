# Container Security

## コンテナとは実際には何か

コンテナを実用的に定義するなら、次のようになります。コンテナとは、制御されたファイルシステム、制御されたカーネルリソースのセット、制限された権限モデルが見えるように、特定の OCI スタイルの設定で起動された **通常の Linux プロセスツリー** です。プロセスは自分が PID 1 であると認識し、自身のネットワークスタックを持っていると認識し、自身のホスト名や IPC リソースを所有していると認識し、独自の user namespace 内では root として実行される場合さえあります。しかし内部的には、カーネルが他のプロセスと同様にスケジュールするホストプロセスにすぎません。

このため、コンテナセキュリティとは実際には、その錯覚がどのように構築され、どのように破綻するかを研究する分野です。mount namespace が弱い場合、プロセスからホストのファイルシステムが見える可能性があります。user namespace が存在しないか無効化されている場合、コンテナ内の root がホスト上の root に近すぎる形でマッピングされる可能性があります。seccomp が unconfined で capability set が広すぎる場合、本来到達できないはずの syscall や特権的なカーネル機能にプロセスがアクセスできる可能性があります。runtime socket がコンテナ内に mount されている場合、コンテナは kernel breakout を必要としない可能性があります。runtime により、より強力な sibling container を起動したり、ホストの root filesystem を直接 mount したりできるためです。

## コンテナと Virtual Machine の違い

VM は通常、独自のカーネルとハードウェア抽象化境界を持ちます。つまり、guest kernel がクラッシュ、panic、または exploit されても、それだけでホストカーネルを直接制御できることにはなりません。コンテナでは、workload は別のカーネルを取得しません。代わりに、ホストが使用する同じカーネルを、慎重にフィルタリングされ namespace 化された形で参照します。その結果、コンテナは通常、より軽量で、起動が速く、1 台のマシン上に高密度で配置しやすく、短期間の application deployment に適しています。その代償として、分離境界はホストと runtime の正しい設定に、より直接的に依存します。

これは、コンテナが「insecure」で VM が「secure」だという意味ではありません。security model が異なるという意味です。rootless execution、user namespaces、default seccomp、strict capability set、host namespace sharing なし、強力な SELinux または AppArmor enforcement を備えた適切に設定されたコンテナスタックは、非常に堅牢になり得ます。反対に、`--privileged`、host PID/network sharing、内部に mount された Docker socket、`/` の writable bind mount を使って起動されたコンテナは、安全に分離された application sandbox よりも、実質的には host root access に近いものです。この違いは、有効化または無効化されたレイヤーによって生じます。

また、現実の環境で目にする機会が増えているため、読者が理解しておくべき中間領域もあります。**Sandboxed container runtimes** である **gVisor** や **Kata Containers** は、従来の `runc` コンテナよりも境界を意図的に強化します。gVisor は workload と多数のホストカーネルインターフェースの間に userspace kernel layer を配置し、Kata は workload を lightweight virtual machine 内で起動します。これらは依然としてコンテナエコシステムや orchestration workflow を通じて使用されますが、security properties は通常の OCI runtimes とは異なります。そのため、すべてが同じように動作するかのように「normal Docker containers」と一括りにしてはいけません。

## Container Stack: 1 つではなく複数のレイヤー

「このコンテナは insecure だ」と言われたとき、続けて尋ねるべき有用な質問は、**どのレイヤーが insecure にしたのか** です。コンテナ化された workload は通常、複数のコンポーネントが連携した結果です。

最上位には、OCI image と metadata を作成する BuildKit、Buildah、Kaniko などの **image build layer** が存在することが多くあります。low-level runtime の上には、Docker Engine、Podman、containerd、CRI-O、Incus、systemd-nspawn などの **engine or manager** が存在する場合があります。cluster 環境では、workload configuration を通じて要求された security posture を決定する Kubernetes などの **orchestrator** も存在する可能性があります。最終的に、namespaces、cgroups、seccomp、MAC policy を実際に enforcement するのは **kernel** です。

この layered model は、defaults を理解するうえで重要です。制限は Kubernetes によって要求され、containerd または CRI-O によって CRI 経由で変換され、runtime wrapper によって OCI spec に変換され、その後で `runc`、`crun`、`runsc`、または別の runtime が workload に対してカーネルを通じて enforcement する場合があります。環境ごとに defaults が異なる場合、その理由は多くの場合、これらのレイヤーのいずれかが最終設定を変更したためです。そのため、同じ mechanism が Docker や Podman では CLI flag として、Kubernetes では Pod または `securityContext` field として、low-level runtime stack では workload 用に生成された OCI configuration として現れることがあります。このため、このセクションの CLI example は、すべての tool がサポートする universal flag ではなく、**一般的なコンテナ概念を表す runtime-specific syntax** として読む必要があります。

## コンテナの実際のセキュリティ境界

実際には、コンテナセキュリティは単一の完全な control ではなく、**重なり合う controls** によって成立します。Namespaces は可視性を分離します。cgroups はリソース使用量を管理および制限します。Capabilities は、特権を持っているように見えるプロセスが実際に実行できる操作を減らします。seccomp は危険な syscalls がカーネルに到達する前にブロックします。AppArmor と SELinux は、通常の DAC checks の上に Mandatory Access Control を追加します。`no_new_privs`、masked procfs paths、read-only system paths は、一般的な privilege abuse や proc/sys abuse の chain を難しくします。mount、socket、label、namespace join の作成方法を決定するため、runtime 自体も重要です。

そのため、多くの container security documentation は繰り返しが多いように見えます。同じ escape chain が、しばしば複数の mechanism に同時に依存するためです。たとえば writable host bind mount は危険ですが、コンテナがホスト上で real root として実行され、`CAP_SYS_ADMIN` を持ち、seccomp による制限を受けず、SELinux や AppArmor による制限もなければ、危険性はさらに大きくなります。同様に、host PID sharing は重大な exposure ですが、`CAP_SYS_PTRACE`、弱い procfs protections、または `nsenter` のような namespace-entry tools と組み合わされると、attacker にとって劇的に有用になります。したがって、この topic を適切に documentation する方法は、各ページで同じ attack を繰り返すことではなく、各レイヤーが最終的な境界に何をもたらすかを説明することです。

## このセクションの読み方

このセクションは、最も一般的な概念から最も具体的な概念へ進むように構成されています。

まず runtime と ecosystem の概要から始めます。

{{#ref}}
runtimes-and-engines.md
{{#endref}}

次に、attacker が kernel escape さえ必要とするかどうかを頻繁に左右する control planes と supply-chain surfaces を確認します。

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

続いて protection model に進みます。

{{#ref}}
protections/
{{#endref}}

Namespace pages では、カーネルの isolation primitives を個別に説明します。

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths、read-only system paths に関する pages では、通常 namespaces の上に layered される mechanisms を説明します。

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 最初の Enumeration で持つべき視点

コンテナ化された target を assessment する場合、有名な escape PoC にすぐ飛びつくよりも、少数の正確な technical questions を尋ねるほうがはるかに有用です。まず **stack** を特定します。Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、またはより specialized なもののいずれかです。次に **runtime** を特定します。`runc`、`crun`、`runsc`、`kata-runtime`、または別の OCI-compatible implementation です。その後、環境が **rootful または rootless** か、**user namespaces** が active か、**host namespaces** が shared されているか、どの **capabilities** が残っているか、**seccomp** が enabled か、**MAC policy** が実際に enforcing されているか、**dangerous mounts または sockets** が存在するか、プロセスが container runtime API と interact できるかを確認します。

これらの回答からは、base image の name よりも、実際の security posture についてはるかに多くのことが分かります。多くの assessment では、最終的なコンテナ設定を理解するだけで、application file を 1 つも読む前に、起こり得る breakout family を予測できます。

## Coverage

このセクションでは、従来の Docker-focused material を container-oriented organization の下で扱います。runtime と daemon exposure、authorization plugins、image trust と build secrets、sensitive host mounts、distroless workloads、privileged containers、そして通常 container execution の周囲に layered される kernel protections が対象です。

{{#include ../../../banners/hacktricks-training.md}}
