# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Container とは実際には何か

Container を実用的に定義するなら、Container とは、制御された filesystem、制御された kernel resource の集合、制限された privilege model が見えるように、特定の OCI-style configuration の下で起動された **通常の Linux process tree** です。その process は、自分が PID 1 であると認識し、自分専用の network stack があると認識し、自分専用の hostname と IPC resource を所有していると認識し、独自の user namespace 内では root として実行されることさえあります。しかし内部的には、kernel が他の process と同様に scheduling する host process にすぎません。

これが、container security とは実際には、その illusion がどのように構築され、どのように破綻するかを研究するものだという理由です。mount namespace が弱ければ、process は host filesystem を見られる可能性があります。user namespace が存在しないか無効化されていれば、container 内の root は host 上の root に近く map される可能性があります。seccomp が unconfined で capability set が広すぎれば、process は本来到達できないはずの syscall や privileged kernel feature に到達できる可能性があります。runtime socket が container 内に mount されていれば、container は kernel breakout を必要としない場合があります。runtime に、より強力な sibling container の起動や host root filesystem の直接 mount を依頼できるからです。

## Container と Virtual Machine の違い

VM には通常、独自の kernel と hardware abstraction boundary があります。つまり guest kernel が crash、panic、または exploit されても、それだけで host kernel を直接制御できることにはなりません。Container では workload に個別の kernel が与えられることはありません。代わりに、host が使用するものと同じ kernel に対して、慎重に filter され、namespace 化された view が与えられます。その結果、container は通常、より軽量で、起動が速く、1 台の machine に高密度で配置しやすく、短期間の application deployment に適しています。代償として、isolation boundary は host と runtime の正しい configuration により直接的に依存します。

これは、container が「insecure」で VM が「secure」だという意味ではありません。security model が異なるという意味です。rootless execution、user namespace、default seccomp、strict capability set、host namespace sharing の無効化、強力な SELinux または AppArmor enforcement を備えた適切な container stack は、非常に堅牢です。反対に、`--privileged`、host PID/network sharing、内部に mount された Docker socket、`/` の writable bind mount を指定して起動された container は、安全に隔離された application sandbox というより、実質的に host root access に近いものです。その違いは、有効化または無効化された layer によって生じます。

また、読者が理解しておくべき中間的な領域もあります。これは実際の環境でますます頻繁に登場しているものです。**Sandboxed container runtime** である **gVisor** や **Kata Containers** は、従来の `runc` container よりも boundary を意図的に強化します。gVisor は workload と多くの host kernel interface の間に userspace kernel layer を配置し、Kata は workload を lightweight virtual machine 内で起動します。これらは依然として container ecosystem や orchestration workflow を通じて使用されますが、その security property は plain OCI runtime とは異なります。すべてが同じように動作するかのように、「通常の Docker container」と同じグループとして考えるべきではありません。

## Container Stack: 1 つではなく複数の Layer

「この container は insecure だ」と言われたとき、役立つ追加質問は **どの layer が insecure にしたのか** です。Containerized workload は通常、複数の component が連携した結果です。

最上位には、OCI image と metadata を作成する BuildKit、Buildah、Kaniko などの **image build layer** が存在することがよくあります。低レベル runtime の上には、Docker Engine、Podman、containerd、CRI-O、Incus、systemd-nspawn などの **engine または manager** が存在する場合があります。Cluster environment では、workload configuration を通じて要求された security posture を Kubernetes などの **orchestrator** が決定することもあります。最終的に namespace、cgroup、seccomp、MAC policy を実際に enforcement するのは **kernel** です。

この layered model は、default を理解するうえで重要です。Restriction は Kubernetes によって要求され、containerd または CRI-O によって CRI 経由で変換され、runtime wrapper によって OCI spec に変換され、その後に `runc`、`crun`、`runsc`、または別の runtime が kernel に対して enforcement する場合があります。環境によって default が異なる場合、その理由は多くの場合、これらの layer のいずれかが最終 configuration を変更したためです。そのため、同じ mechanism が Docker や Podman では CLI flag として、Kubernetes では Pod または `securityContext` field として、低レベル runtime stack では workload 用に生成された OCI configuration として現れることがあります。したがって、この section の CLI example は、すべての tool がサポートする universal flag ではなく、**一般的な container concept に対する runtime-specific syntax** として読むべきです。

## 実際の Container Security Boundary

実際には、container security は単一の完全な control ではなく、**重なり合う control** によって成り立っています。Namespace は visibility を隔離します。cgroup は resource usage を管理および制限します。Capability は、privileged に見える process が実際に実行できる操作を削減します。seccomp は危険な syscall が kernel に到達する前に block します。AppArmor と SELinux は、通常の DAC check に加えて Mandatory Access Control を提供します。`no_new_privs`、masked procfs path、read-only system path により、一般的な privilege abuse や proc/sys abuse の chain はより困難になります。Mount、socket、label、namespace join の作成方法を決めるため、runtime 自体も重要です。

そのため、多くの container security documentation は反復的に見えます。同じ escape chain が、しばしば複数の mechanism に同時に依存するからです。たとえば writable host bind mount は危険ですが、container が host 上で real root として実行され、`CAP_SYS_ADMIN` を持ち、seccomp による制限がなく、SELinux や AppArmor による制限もなければ、はるかに危険になります。同様に、host PID sharing は重大な exposure ですが、`CAP_SYS_PTRACE`、弱い procfs protection、または `nsenter` のような namespace-entry tool と組み合わされると、attacker にとって劇的に有用になります。したがって、この topic を document する正しい方法は、すべての page で同じ attack を繰り返すことではなく、各 layer が最終的な boundary に何を提供するかを説明することです。

## この Section の読み方

この section は、最も一般的な concept から最も具体的な concept へ進むように構成されています。

まず runtime と ecosystem の概要を確認します。

{{#ref}}
runtimes-and-engines.md
{{#endref}}

次に、attacker が kernel escape を必要とするかどうかを頻繁に左右する control plane と supply-chain surface を確認します。

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

Namespace page では、kernel isolation primitive を個別に説明します。

{{#ref}}
protections/namespaces/
{{#endref}}

cgroup、capability、seccomp、AppArmor、SELinux、`no_new_privs`、masked path、read-only system path に関する page では、通常 namespace の上に layer として追加される mechanism を説明します。

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

## 最初の Enumeration に適した考え方

Containerized target を assessment する場合、有名な escape PoC にすぐ飛びつくよりも、少数の正確な technical question を確認する方がはるかに有用です。まず **stack** を特定します。Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、またはより specialized なものかを確認します。次に **runtime** を特定します。`runc`、`crun`、`runsc`、`kata-runtime`、または別の OCI-compatible implementation かを確認します。その後、環境が **rootful か rootless か**、**user namespace** が active か、**host namespace** が共有されているか、残っている **capability** は何か、**seccomp** が有効か、**MAC policy** が実際に enforcement しているか、**dangerous mount または socket** が存在するか、process が container runtime API と interaction できるかを確認します。

これらの回答は、base image name よりも実際の security posture についてはるかに多くの情報を与えます。多くの assessment では、最終的な container configuration を理解するだけで、application file を 1 つ読む前に、起こり得る breakout family を予測できます。

## Coverage

この section では、従来の Docker-focused material を container-oriented な構成の下で扱います。runtime と daemon exposure、authorization plugin、image trust と build secret、sensitive host mount、distroless workload、privileged container、そして container execution の周囲に通常 layer として追加される kernel protection を対象とします。

{{#include ../../../banners/hacktricks-training.md}}
