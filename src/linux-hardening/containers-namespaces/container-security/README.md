# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

container を実用的に定義するなら、container とは、制御された filesystem、制御された kernel resource の集合、制限された privilege model が見えるように、特定の OCI-style configuration の下で起動された **通常の Linux process tree** です。process は自分が PID 1 だと思い、自分専用の network stack を持っていると思い、自分専用の hostname や IPC resource を所有していると思うことがあります。また、自分専用の user namespace 内で root として実行されることさえあります。しかし内部では、kernel が他の process と同じようにスケジュールする host process に過ぎません。

これが、container security が実際には、その錯覚がどのように構築され、どのように破綻するかを研究するものだという理由です。mount namespace が弱ければ、process は host filesystem を見られる可能性があります。user namespace が存在しないか無効化されていれば、container 内の root は host 上の root に近くマッピングされる可能性があります。seccomp が unconfined で capability set が広すぎれば、process は、本来到達できないはずの syscall や privileged kernel feature に到達できる可能性があります。runtime socket が container 内に mount されていれば、container は kernel breakout を必要としない可能性があります。runtime に依頼して、より強力な sibling container を起動したり、host root filesystem を直接 mount したりできるためです。

## How Containers Differ From Virtual Machines

VM は通常、独自の kernel と hardware abstraction boundary を備えています。つまり、guest kernel が crash、panic、または exploit されたとしても、それだけで host kernel の直接制御を意味するわけではありません。container では、workload に別の kernel は提供されません。その代わり、host が使用するものと同じ kernel に対する、慎重に filter され namespace 化された view が提供されます。その結果、container は通常、より軽量で、起動が速く、1 台の machine 上に高密度で配置しやすく、短期間の application deployment に適しています。その代償として、isolation boundary は正しい host と runtime configuration により直接的に依存します。

これは、container が "insecure" で VM が "secure" だという意味ではありません。security model が異なるという意味です。rootless execution、user namespace、default seccomp、strict capability set、host namespace sharing の禁止、強力な SELinux または AppArmor enforcement を備えた適切な container stack は、非常に堅牢になり得ます。逆に、`--privileged`、host PID/network sharing、container 内に mount された Docker socket、`/` の writable bind mount を使って起動された container は、安全に隔離された application sandbox というより、実質的に host root access に近いものです。その違いは、有効化または無効化された layer によって生じます。

また、読者が理解しておくべき中間的な領域もあります。これは実環境でますます頻繁に登場しているためです。**Sandboxed container runtimes** である **gVisor** と **Kata Containers** は、classic な `runc` container よりも boundary を意図的に強化します。gVisor は workload と多くの host kernel interface の間に userspace kernel layer を配置し、Kata は workload を lightweight virtual machine 内で起動します。これらも container ecosystem や orchestration workflow を通じて利用されますが、その security property は plain OCI runtime とは異なります。そのため、すべてが同じように動作するかのように「通常の Docker containers」と同じグループとして考えるべきではありません。

## The Container Stack: Several Layers, Not One

「この container は insecure だ」と言われたとき、役に立つ follow-up question は、**どの layer が insecure にしたのか**です。containerized workload は通常、複数の component が連携した結果です。

最上位には、OCI image と metadata を作成する BuildKit、Buildah、Kaniko などの **image build layer** が存在することがよくあります。low-level runtime の上には、Docker Engine、Podman、containerd、CRI-O、Incus、systemd-nspawn などの **engine または manager** が存在する場合があります。cluster environment では、workload configuration を通じて要求された security posture を決定する Kubernetes などの **orchestrator** も存在することがあります。最終的に namespace、cgroup、seccomp、MAC policy を実際に enforcement するのは **kernel** です。

この layered model は default を理解するうえで重要です。restriction は Kubernetes によって要求され、containerd または CRI-O によって CRI 経由で変換され、runtime wrapper によって OCI spec に変換され、その後になって初めて、`runc`、`crun`、`runsc`、または別の runtime が workload に対して kernel へ enforcement します。environment ごとに default が異なる場合、多くはこれらの layer のいずれかが最終 configuration を変更したことが原因です。そのため、同じ mechanism が Docker や Podman では CLI flag として、Kubernetes では Pod または `securityContext` field として、low-level runtime stack では workload 用に生成された OCI configuration として現れることがあります。したがって、この section の CLI example は、すべての tool が対応する universal flag ではなく、**一般的な container concept に対する runtime-specific syntax** として読むべきです。

## The Real Container Security Boundary

実際には、container security は単一の完璧な control ではなく、**重なり合う control** によって成立します。namespace は visibility を隔離します。cgroup は resource usage を管理および制限します。capability は、privileged に見える process が実際に実行できることを減らします。seccomp は危険な syscall が kernel に到達する前に block します。AppArmor と SELinux は、通常の DAC check の上に Mandatory Access Control を追加します。`no_new_privs`、masked procfs path、read-only system path は、一般的な privilege abuse や proc/sys abuse の chain を困難にします。runtime 自体も重要です。mount、socket、label、namespace join の作成方法を決定するためです。

このため、多くの container security documentation は繰り返しが多いように見えます。同じ escape chain が、一度に複数の mechanism に依存することがよくあるためです。たとえば、writable な host bind mount は危険ですが、container がさらに host 上で実際の root として実行され、`CAP_SYS_ADMIN` を持ち、seccomp による制限を受けず、SELinux または AppArmor による制限も受けていなければ、はるかに危険になります。同様に、host PID sharing は深刻な exposure ですが、`CAP_SYS_PTRACE`、弱い procfs protection、または `nsenter` のような namespace-entry tool と組み合わされると、attacker にとって劇的に有用になります。したがって、この topic を document する正しい方法は、すべての page で同じ attack を繰り返すことではなく、各 layer が最終的な boundary に何を提供するかを説明することです。

## How To Read This Section

この section は、最も一般的な concept から最も具体的な concept へ進むように構成されています。

まず runtime と ecosystem の概要を確認します。

{{#ref}}
runtimes-and-engines.md
{{#endref}}

次に、attacker が kernel escape を必要とするかどうかを頻繁に決定する control plane と supply-chain surface を確認します。

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

続いて protection model に移ります。

{{#ref}}
protections/
{{#endref}}

namespace page では、kernel isolation primitive を個別に説明します。

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

## A Good First Enumeration Mindset

containerized target を assess する場合、有名な escape PoC にすぐ飛びつくよりも、少数の正確な technical question を尋ねるほうがはるかに有用です。まず **stack** を特定します。Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、またはより specialized なもののいずれかです。次に **runtime** を特定します。`runc`、`crun`、`runsc`、`kata-runtime`、または別の OCI-compatible implementation です。その後、environment が **rootful または rootless** か、**user namespace** が active か、**host namespace** が shared されているか、どの **capability** が残っているか、**seccomp** が enabled か、**MAC policy** が実際に enforcing されているか、**dangerous mount または socket** が存在するか、process が container runtime API と interact できるかを確認します。

これらの回答は、base image name よりも実際の security posture についてはるかに多くの情報を示します。多くの assessment では、最終的な container configuration を理解するだけで、単一の application file を読む前に、発生し得る breakout family を予測できます。

## Coverage

この section では、container-oriented organization の下に再構成した、従来の Docker-focused material を扱います。runtime と daemon exposure、authorization plugin、image trust と build secret、sensitive host mount、distroless workload、privileged container、および container execution の周囲に通常 layer として追加される kernel protection が含まれます。

{{#include ../../../banners/hacktricks-training.md}}
