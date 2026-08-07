# Container Runtimes, Engines, Builders, And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security における最大の混乱要因の1つは、まったく異なる複数のコンポーネントが、同じ1つの言葉にまとめられてしまうことです。"Docker" は、image format、CLI、daemon、build system、runtime stack、あるいは単に containers 全般の概念を指している場合があります。Security work では、この曖昧さが問題になります。なぜなら、異なるレイヤーがそれぞれ異なる保護を担っているからです。悪意のある bind mount による breakout は、low-level runtime の bug による breakout とは異なり、どちらも Kubernetes における cluster policy のミスとは異なります。

このページでは、ecosystem を役割ごとに分けます。これにより、このセクションの後半で、保護や weakness が実際にどこに存在するのかを正確に説明できます。

## OCI As The Common Language

Modern Linux container stacks は、OCI specifications を共通の言語として使用するため、相互運用できることがよくあります。**OCI Image Specification** は、images と layers の表現方法を定義します。**OCI Runtime Specification** は、namespaces、mounts、cgroups、security settings などを含め、runtime が process を起動する方法を定義します。**OCI Distribution Specification** は、registries が content を公開する方法を標準化します。

これは、ある tool で build した container image を別の tool で実行できることが多い理由や、複数の engines が同じ low-level runtime を共有できる理由を説明します。また、異なる products 間で security behavior が似て見える理由も説明します。多くの products が同じ OCI runtime configuration を構築し、それを同じ少数の runtimes に渡しているためです。

## Low-Level OCI Runtimes

Low-level runtime は、kernel boundary に最も近い component です。実際に namespaces を作成し、cgroup settings を書き込み、capabilities と seccomp filters を適用し、最後に container process を `execve()` する部分です。mechanical な意味で "container isolation" について議論するとき、明示的にそう呼ばなくても、通常はこの layer を指しています。

### `runc`

`runc` は reference OCI runtime であり、現在も最もよく知られている implementation です。Docker、containerd、そして多くの Kubernetes deployments の下で広く使用されています。多くの public research や exploitation material が `runc`-style environments を対象にしているのは、単にそれらが一般的であり、`runc` が多くの人が Linux container を思い浮かべるときの baseline を定義しているためです。したがって、`runc` を理解することは、classic container isolation の mental model を構築するうえで非常に役立ちます。

### `crun`

`crun` は別の OCI runtime であり、C で記述され、modern Podman environments で広く使用されています。優れた cgroup v2 support、強力な rootless ergonomics、低い overhead が評価されることが多い runtime です。Security の観点で重要なのは、別の language で書かれていることではなく、同じ役割を担っていることです。つまり、OCI configuration を kernel 上で動作する process tree に変換する component です。rootless Podman workflow がより安全に感じられることが多いのは、`crun` が魔法のようにすべてを修正するからではなく、その周辺の stack 全体が user namespaces と least privilege をより強く重視する傾向があるためです。

### `runsc` From gVisor

`runsc` は gVisor が使用する runtime です。ここでは boundary の意味が大きく変わります。通常の方法でほとんどの syscalls を host kernel に直接渡すのではなく、gVisor は userspace kernel layer を挿入し、Linux interface の大部分を emulate または mediate します。その結果は、いくつかの追加 flags を付けた通常の `runc` container ではありません。host-kernel attack surface を減らすことを目的とした、異なる sandbox design です。Compatibility と performance の tradeoffs もこの design の一部であるため、`runsc` を使用する environments は、通常の OCI runtime environments とは別に記録すべきです。

### `kata-runtime`

Kata Containers は、workload を lightweight virtual machine 内で起動することで boundary をさらに広げます。管理上は依然として container deployment のように見え、orchestration layers もそのように扱う場合があります。しかし基盤となる isolation boundary は、classic host-kernel-shared container よりも virtualization に近いものです。そのため、container-centric workflows を放棄せずに、より強力な tenant isolation を実現したい場合に Kata は有用です。

## Engines And Container Managers

Low-level runtime が kernel と直接通信する component であるなら、engine または manager は通常、users と operators が操作する component です。image pulls、metadata、logs、networks、volumes、lifecycle operations、API exposure を処理します。この layer は非常に重要です。現実の compromise の多くはここで発生するためです。low-level runtime 自体が完全に正常であっても、runtime socket や daemon API への access は host compromise と同等になり得ます。

### Docker Engine

Docker Engine は developers にとって最も認識しやすい container platform であり、container に関する vocabulary が Docker を中心とした形になった理由の1つです。一般的な経路は `docker` CLI から `dockerd` へ進み、`dockerd` が `containerd` や OCI runtime などの lower-level components を調整します。歴史的に、Docker deployments は **rootful** であることが多く、そのため Docker socket への access は非常に強力な primitive でした。これが、実用的な privilege-escalation material の多くが `docker.sock` に注目する理由です。process が `dockerd` に対して privileged container の作成、host paths の mount、host namespaces への join を要求できるなら、kernel exploit はまったく必要ない可能性があります。

### Podman

Podman は、より daemonless な model を中心に設計されました。運用上、これは container が、長時間稼働する privileged daemon を通じてではなく、standard Linux mechanisms で管理される単なる processes であるという考えを強化します。Podman は、classic Docker deployments よりもはるかに強力な **rootless** story も備えています。これは Podman が自動的に safe になるという意味ではありませんが、特に user namespaces、SELinux、`crun` と組み合わせた場合、default risk profile を大きく変えます。

### containerd

containerd は、多くの modern stacks における core runtime management component です。Docker の下で使用され、dominant な Kubernetes runtime backends の1つでもあります。強力な APIs を公開し、images と snapshots を管理し、最終的な process creation を low-level runtime に委譲します。containerd に関する security discussions では、containerd socket または `ctr`/`nerdctl` functionality への access は、interface や workflow がそれほど "developer friendly" に感じられなくても、Docker の API への access と同じくらい危険になり得ることを強調すべきです。

### CRI-O

CRI-O は Docker Engine よりも対象を絞った component です。general-purpose developer platform ではなく、Kubernetes Container Runtime Interface を適切に実装することを中心に構築されています。そのため、Kubernetes distributions や OpenShift のような SELinux-heavy ecosystems で特によく使用されます。Security の観点では、この狭い scope は有用です。conceptual clutter が減るためです。CRI-O はまさに "Kubernetes のために containers を実行する" layer の一部であり、everything-platform ではありません。

### Incus, LXD, And LXC

Incus/LXD/LXC systems は、Docker-style application containers とは分けて考える価値があります。これらは **system containers** として使用されることが多いためです。通常、system container は、より完全な userspace、long-running services、豊富な device exposure、より広範な host integration を備えた lightweight machine に近いものとして期待されます。Isolation mechanisms は依然として kernel primitives ですが、operational expectations は異なります。その結果、ここでの misconfigurations は、"bad app-container defaults" というより、lightweight virtualization や host delegation におけるミスのように見えることがよくあります。

### systemd-nspawn

systemd-nspawn は systemd-native であり、testing、debugging、OS-like environments の実行に非常に役立つため、興味深い位置を占めています。dominant な cloud-native production runtime ではありませんが、labs や distro-oriented environments で十分頻繁に登場するため、言及する価値があります。Security analysis において、これは "container" という概念が複数の ecosystems と operational styles にまたがっていることを改めて示します。

### Apptainer / Singularity

Apptainer（旧称 Singularity）は research および HPC environments で一般的です。その trust assumptions、user workflow、execution model は、Docker/Kubernetes-centric stacks とは重要な点で異なります。特にこれらの environments では、users に広範な privileged container-management powers を与えずに、packaged workloads を実行できるようにすることが重視されます。reviewer がすべての container environments を基本的に "server 上の Docker" だと想定すると、これらの deployments を大きく誤解することになります。

## Build-Time Tooling

Security discussions の多くは run time についてのみ扱います。しかし build-time tooling も重要です。image contents、build secrets exposure、そしてどの程度の trusted context が最終 artifact に埋め込まれるかを決定するためです。

**BuildKit** と `docker buildx` は modern build backends であり、caching、secret mounting、SSH forwarding、multi-platform builds などの features をサポートします。これらは便利な features ですが、security の観点では、secrets が image layers に leak したり、広すぎる build context によって本来含めるべきでない files が露出したりする場所も生み出します。**Buildah** は OCI-native ecosystems、特に Podman 周辺で同様の役割を担います。一方、**Kaniko** は privileged Docker daemon を build pipeline に与えたくない CI environments でよく使用されます。

重要な lesson は、image creation と image execution は異なる phases ですが、weak build pipeline は container が launch されるずっと前から、weak runtime posture を作り出す可能性があるということです。

## Orchestration Is Another Layer, Not The Runtime

Kubernetes を runtime 自体と同一視すべきではありません。Kubernetes は orchestrator です。Pods を schedule し、desired state を保存し、workload configuration を通じて security policy を表現します。その後 kubelet が containerd や CRI-O などの CRI implementation と通信し、それらが `runc`、`crun`、`runsc`、`kata-runtime` などの low-level runtime を呼び出します。

この分離は重要です。多くの人が、実際には node runtime によって enforce されている protection を "Kubernetes" のものだと誤って atribbute したり、Pod spec に由来する behavior を "containerd defaults" のせいにしたりするためです。実際の最終的な security posture は composition です。orchestrator が何かを要求し、runtime stack がそれを変換し、最後に kernel がそれを enforce します。

## Why Runtime Identification Matters During Assessment

engine と runtime を早期に特定すると、その後の多くの observations を解釈しやすくなります。rootless Podman container であれば、user namespaces が関係している可能性が高いと考えられます。workload に Docker socket が mount されていれば、API-driven privilege escalation が現実的な path であることを示します。CRI-O/OpenShift node であれば、SELinux labels と restricted workload policy をすぐに意識すべきです。gVisor または Kata environment であれば、classic `runc` breakout PoC が同じように動作すると想定することに慎重になるべきです。

そのため、container assessment の最初の steps の1つは、常に次の2つの簡単な questions に答えることであるべきです。**どの component が container を管理しているのか**、そして **どの runtime が実際に process を launch したのか**。これらの answers が明確になれば、残りの environment は通常、はるかに容易に推論できます。

## Runtime Vulnerabilities

すべての container escape が operator misconfiguration によって発生するわけではありません。runtime 自体が vulnerable component である場合もあります。これは、workload が注意深く見える configuration で実行されていても、low-level runtime flaw を通じて exposed になる可能性があるため重要です。

典型的な example は、`runc` に存在した **CVE-2019-5736** です。malicious container が host の `runc` binary を overwrite し、その後の `docker exec` または同様の runtime invocation が attacker-controlled code を trigger するのを待つことが可能でした。この exploit path は、単純な bind-mount や capability のミスとは大きく異なります。exec handling 中に runtime が container process space に再侵入する方法を abuse するためです。<sup>[[1]](#references)</sup>

red-team の観点から見た minimal reproduction workflow は次のとおりです。
```bash
go build main.go
./main
```
次に、host から:
```bash
docker exec -it <container-name> /bin/sh
```
重要な教訓は、過去の exploit 実装の正確な内容ではありません。評価上の意味は、runtime のバージョンに脆弱性がある場合、目に見える container の設定が明らかに弱く見えなくても、通常の in-container code execution だけで host を compromise できる可能性があるということです。

`runc` の `CVE-2024-21626`、BuildKit の mount race、containerd の parsing bug など、最近の runtime CVE は同じ点を裏付けています。runtime のバージョンと patch level は、単なる保守上の細部ではなく、security boundary の一部です。

## References

- [1] [runC を介した Docker からの脱出 – CVE-2019-5736 の解説](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
