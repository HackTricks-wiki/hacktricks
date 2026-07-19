# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## コンテナとは実際には何か

コンテナを実用的に定義するなら、コンテナとは、特定の OCI スタイルの設定で起動された **通常の Linux プロセスツリー** であり、制御されたファイルシステム、制御されたカーネルリソースの集合、制限された権限モデルを認識するものです。プロセスは自分自身を PID 1 だと思うこともあれば、独自の network stack を持っている、自身の hostname と IPC リソースを所有していると思うこともあります。また、自身の user namespace 内で root として実行されることさえあります。しかし実際には、カーネルが他のプロセスと同じようにスケジュールする host process です。

このため、container security とは本質的に、この錯覚がどのように構築され、どのように破綻するかを研究することです。mount namespace が弱ければ、プロセスは host filesystem を認識できる可能性があります。user namespace が存在しない、または無効化されている場合、コンテナ内の root は host 上の root に近くマッピングされる可能性があります。seccomp が unconfined で capability set が広すぎる場合、プロセスは本来到達できないはずの syscall や privileged kernel feature にアクセスできる可能性があります。runtime socket がコンテナ内に mount されている場合、コンテナは kernel breakout を必要としないことがあります。runtime に、より強力な sibling container の起動や host root filesystem の直接 mount を依頼できるためです。

## コンテナと Virtual Machine の違い

VM は通常、自身の kernel と hardware abstraction boundary を備えています。つまり、guest kernel が crash、panic、または exploit されたとしても、それだけで host kernel の直接的な制御につながるわけではありません。コンテナでは、workload に独立した kernel は与えられません。その代わり、host が使用する同じ kernel に対して、慎重に filter され、namespace 化された view が与えられます。その結果、コンテナは通常、より軽量で、起動が速く、1 台のマシンに高密度で配置しやすく、短期間の application deployment に適しています。その代償として、isolation boundary は host と runtime の正しい設定に、より直接的に依存します。

これは、コンテナが "insecure" で VM が "secure" だという意味ではありません。security model が異なるという意味です。rootless execution、user namespaces、default seccomp、strict capability set、host namespace sharing の無効化、強力な SELinux または AppArmor enforcement を備えた適切な container stack は、非常に堅牢になり得ます。反対に、`--privileged`、host PID/network sharing、内部に mount された Docker socket、`/` の writable bind mount を使って起動されたコンテナは、安全に隔離された application sandbox というより、実質的に host root access に近いものです。この違いは、有効化または無効化された layer によって生じます。

また、読者が理解しておくべき中間領域もあります。実際の環境で登場する機会が増えているためです。**Sandboxed container runtime** である **gVisor** や **Kata Containers** は、従来の `runc` container よりも boundary を意図的に強化します。gVisor は workload と多くの host kernel interface の間に userspace kernel layer を配置し、Kata は workload を軽量な virtual machine 内で起動します。これらも container ecosystem や orchestration workflow を通じて使用されますが、security property は通常の OCI runtime とは異なります。そのため、すべてが同じように動作すると考えて、"normal Docker containers" と同じグループにまとめてはいけません。

## Container Stack: 1 つではなく複数の Layer

「このコンテナは insecure だ」と言われたとき、次に尋ねるべき有用な質問は、**どの layer が insecure にしたのか** です。containerized workload は通常、複数の component が連携した結果です。

最上位には、OCI image と metadata を作成する BuildKit、Buildah、Kaniko などの **image build layer** が存在することがよくあります。low-level runtime の上には、Docker Engine、Podman、containerd、CRI-O、Incus、systemd-nspawn などの **engine または manager** が存在する場合があります。cluster environment では、workload configuration を通じて要求された security posture を決定する Kubernetes などの **orchestrator** も存在します。最終的に、namespaces、cgroups、seccomp、MAC policy を実際に enforcement するのは **kernel** です。

この layered model は、default を理解するうえで重要です。restriction は Kubernetes によって要求され、containerd または CRI-O によって CRI 経由で変換され、runtime wrapper によって OCI spec に変換され、その後に `runc`、`crun`、`runsc`、または別の runtime が kernel に対して enforcement することがあります。環境によって default が異なる場合、その理由は多くの場合、これらの layer のいずれかが最終 configuration を変更したためです。したがって、同じ mechanism が Docker や Podman では CLI flag、Kubernetes では Pod または `securityContext` field、low-level runtime stack では workload 用に生成された OCI configuration として現れることがあります。このため、この section の CLI example は、すべての tool が対応する universal flag ではなく、**一般的な container concept を runtime ごとの syntax で表したもの** として読んでください。

## 実際の Container Security Boundary

実際には、container security は 1 つの完全な control ではなく、**重なり合う control** によって成立します。Namespaces は visibility を隔離します。cgroups は resource usage を管理・制限します。Capabilities は、privileged に見えるプロセスが実際に実行できる操作を減らします。seccomp は危険な syscall が kernel に到達する前に block します。AppArmor と SELinux は、通常の DAC check の上に Mandatory Access Control を追加します。`no_new_privs`、masked procfs path、read-only system path は、一般的な privilege abuse や proc/sys abuse の chain をより困難にします。runtime 自体も重要です。mount、socket、label、namespace join がどのように作成されるかを runtime が決定するためです。

このため、多くの container security documentation は繰り返しが多いように見えます。同じ escape chain が、複数の mechanism に同時に依存することがよくあるからです。たとえば、writable host bind mount は危険ですが、コンテナが host 上の実際の root として実行され、`CAP_SYS_ADMIN` を持ち、seccomp による制限がなく、SELinux または AppArmor による制限もなければ、危険性はさらに大きくなります。同様に、host PID sharing は深刻な exposure ですが、`CAP_SYS_PTRACE`、弱い procfs protection、または `nsenter` などの namespace-entry tool と組み合わさると、attacker にとってはるかに有用になります。したがって、この topic を document する適切な方法は、すべての page で同じ attack を繰り返すことではなく、各 layer が最終的な boundary に何をもたらすかを説明することです。

## この Section の読み方

この section は、最も一般的な concept から最も具体的な concept へ進むように構成されています。

まず runtime と ecosystem の overview から始めます。

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

その後、protection model に進みます。

{{#ref}}
protections/
{{#endref}}

namespace page では、kernel isolation primitive を個別に説明します。

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked path、read-only system path に関する page では、namespaces の上に通常 layer される mechanism を説明します。

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

containerized target を assess するときは、有名な escape PoC にすぐ飛びつくよりも、少数の正確な technical question を尋ねるほうがはるかに有用です。まず **stack** を特定します。Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、またはより specialized なものです。次に **runtime** を特定します。`runc`、`crun`、`runsc`、`kata-runtime`、または別の OCI-compatible implementation です。その後、環境が **rootful か rootless か**、**user namespaces** が active か、**host namespaces** が shared か、どの **capabilities** が残っているか、**seccomp** が enabled か、**MAC policy** が実際に enforcing されているか、**dangerous mounts または sockets** が存在するか、プロセスが container runtime API とやり取りできるかを確認します。

これらの回答は、base image の name よりも、実際の security posture についてはるかに多くの情報を与えます。多くの assessment では、最終的な container configuration を理解するだけで、application file を 1 つ読む前に、発生し得る breakout family を予測できます。

## Coverage

この section では、従来の Docker-focused material を container-oriented な構成で扱います。対象は、runtime と daemon exposure、authorization plugin、image trust と build secret、sensitive host mount、distroless workload、privileged container、そして container execution の周囲に通常 layer される kernel protection です。
{{#include ../../../banners/hacktricks-training.md}}
