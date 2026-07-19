# Container Runtimes、Engines、Builders、そして Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security における最大の混乱要因の一つは、まったく異なる複数のコンポーネントが、同じ一つの言葉にまとめられてしまうことです。"Docker" は、image format、CLI、daemon、build system、runtime stack、あるいは単に containers 全般の概念を指している場合があります。Security の作業では、この曖昧さが問題になります。異なるレイヤーが異なる保護を担っているからです。不適切な bind mount による breakout は、low-level runtime の bug による breakout とは異なり、どちらも Kubernetes における cluster policy のミスとは別のものです。

このページでは、ecosystem を役割ごとに分けます。これにより、このセクションの以降の説明で、保護や弱点が実際にどこに存在するのかを正確に扱えるようにします。

## 共通言語としての OCI

Modern Linux container stack は、OCI specifications のセットを使用して相互運用することがよくあります。**OCI Image Specification** は、images と layers の表現方法を定義します。**OCI Runtime Specification** は、namespaces、mounts、cgroups、security settings などを含め、runtime が process を起動する方法を定義します。**OCI Distribution Specification** は、registries が content を公開する方法を標準化します。

これは、ある tool で build した container image を別の tool で実行できることが多い理由や、複数の engines が同じ low-level runtime を共有できる理由を説明します。また、異なる products 間で security behavior が似て見える理由も説明します。多くの products は同じ OCI runtime configuration を構築し、それを同じ少数の runtimes に渡しているためです。

## Low-Level OCI Runtimes

low-level runtime は kernel boundary に最も近いコンポーネントです。実際に namespaces を作成し、cgroup settings を書き込み、capabilities と seccomp filters を適用し、最終的に container process を `execve()` する部分です。mechanical なレベルで "container isolation" について話すとき、明示的にそう述べていなくても、通常はこの layer を指しています。

### `runc`

`runc` は reference OCI runtime であり、現在も最もよく知られた implementation です。Docker、containerd、多くの Kubernetes deployments で広く使用されています。多くの public research と exploitation material が `runc`-style environments を対象にしているのは、単純にそれらが普及していることと、`runc` が多くの人が Linux container を想像するときの baseline を定義しているためです。したがって、`runc` を理解することは、classic container isolation の mental model を得るうえで非常に有用です。

### `crun`

`crun` は別の OCI runtime で、C で書かれており、modern Podman environments で広く使用されています。優れた cgroup v2 support、強力な rootless ergonomics、低い overhead で評価されることがよくあります。Security の観点で重要なのは、別の language で書かれていることではなく、同じ役割を担っていることです。つまり、OCI configuration を kernel 上で動作する process tree に変換するコンポーネントです。rootless Podman workflow がより安全に感じられることが多いのは、`crun` がすべてを魔法のように修正するからではありません。その周辺の stack 全体が user namespaces と least privilege をより重視する傾向にあるためです。

### gVisor の `runsc`

`runsc` は gVisor が使用する runtime です。ここでは boundary の意味が大きく変わります。通常の方法で大部分の syscalls を host kernel に直接渡す代わりに、gVisor は userspace kernel layer を挿入し、Linux interface の大部分を emulate または mediate します。その結果は、いくつかの flags を追加した通常の `runc` container ではありません。host-kernel attack surface を減らすことを目的とした、異なる sandbox design です。Compatibility と performance の tradeoffs はこの design の一部であるため、`runsc` を使用する environments は、通常の OCI runtime environments とは異なるものとして document する必要があります。

### `kata-runtime`

Kata Containers は、workload を lightweight virtual machine 内で起動することで boundary をさらに拡張します。管理上は通常の container deployment に見え、orchestration layers もそのように扱う場合があります。しかし基盤となる isolation boundary は、classic host-kernel-shared container よりも virtualization に近いものです。そのため Kata は、container-centric workflow を捨てずに、より強力な tenant isolation を求める場合に有用です。

## Engines と Container Managers

low-level runtime が kernel と直接通信するコンポーネントであるなら、engine または manager は、通常 users と operators が操作するコンポーネントです。image pulls、metadata、logs、networks、volumes、lifecycle operations、API exposure を処理します。この layer は非常に重要です。実際の compromise の多くはここで発生するためです。low-level runtime 自体が完全に正常でも、runtime socket や daemon API への access は host compromise と同等になり得ます。

### Docker Engine

Docker Engine は developers にとって最も認識されている container platform であり、container vocabulary が Docker 中心になった理由の一つです。典型的な path は `docker` CLI から `dockerd` へ進み、`dockerd` が `containerd` や OCI runtime などの lower-level components を調整します。Historically、Docker deployments は **rootful** であることが多く、そのため Docker socket への access は非常に強力な primitive でした。これが、実用的な privilege-escalation material の多くが `docker.sock` に注目する理由です。process が `dockerd` に対して privileged container の作成、host paths の mount、host namespaces への join を要求できるなら、kernel exploit はまったく必要ない場合があります。

### Podman

Podman は、より daemonless な model を中心に設計されました。Operationally、これは containers が一つの長期間稼働する privileged daemon ではなく、standard Linux mechanisms を通じて管理される単なる processes であるという考えを強めます。Podman は、初めて学んだ classic Docker deployments よりも、はるかに強力な **rootless** story も備えています。これは Podman が自動的に safe になるという意味ではありません。しかし、特に user namespaces、SELinux、`crun` と組み合わせた場合、default の risk profile を大きく変えます。

### containerd

containerd は、多くの modern stacks における core runtime management component です。Docker の下で使用され、dominant な Kubernetes runtime backends の一つでもあります。強力な APIs を公開し、images と snapshots を管理し、最終的な process creation を low-level runtime に委譲します。containerd に関する security discussions では、containerd socket や `ctr`/`nerdctl` functionality への access が、Docker API への access と同じくらい危険になり得ることを強調すべきです。interface や workflow がそれほど "developer friendly" に見えなくても同様です。

### CRI-O

CRI-O は Docker Engine よりも対象が限定されています。general-purpose developer platform ではなく、Kubernetes Container Runtime Interface を適切に実装することを中心に構築されています。そのため、Kubernetes distributions や OpenShift のような SELinux-heavy ecosystems で特に一般的です。Security の観点では、この限定された scope が有用です。概念上の clutter が減るからです。CRI-O はまさに "run containers for Kubernetes" layer の一部であり、everything-platform ではありません。

### Incus、LXD、LXC

Incus/LXD/LXC systems は、Docker-style application containers とは分けて考える価値があります。これらは **system containers** として使用されることが多いためです。system container は通常、より完全な userspace、long-running services、豊富な device exposure、より広範な host integration を備えた lightweight machine のように動作することが期待されます。Isolation mechanisms は依然として kernel primitives ですが、operational expectations は異なります。その結果、ここでの misconfigurations は "bad app-container defaults" というより、lightweight virtualization や host delegation におけるミスに近い形になることがよくあります。

### systemd-nspawn

systemd-nspawn は systemd-native であり、testing、debugging、OS-like environments の実行に非常に便利なため、興味深い位置を占めています。dominant な cloud-native production runtime ではありませんが、labs や distro-oriented environments に十分な頻度で登場するため、言及する価値があります。Security analysis において、これは "container" という概念が複数の ecosystems と operational styles にまたがっていることを再認識させる存在です。

### Apptainer / Singularity

Apptainer（旧称 Singularity）は、research と HPC environments で一般的です。その trust assumptions、user workflow、execution model は、Docker/Kubernetes-centric stacks とは重要な点で異なります。特にこれらの environments では、users に広範な privileged container-management powers を与えることなく、packaged workloads を実行させることが重視されます。reviewer がすべての container environments を基本的に "server 上の Docker" だと想定すると、これらの deployments を大きく誤解することになります。

## Build-Time Tooling

多くの security discussions は run time のみを扱います。しかし build-time tooling も重要です。image contents、build secrets exposure、最終 artifact にどれだけ trusted context が埋め込まれるかを決定するためです。

**BuildKit** と `docker buildx` は、caching、secret mounting、SSH forwarding、multi-platform builds などの features をサポートする modern build backends です。これらは便利な features ですが、Security の観点では、secrets が image layers に leak したり、過度に広い build context により本来含めるべきでない files が露出したりする場所も作り出します。**Buildah** は OCI-native ecosystems、特に Podman 周辺で同様の役割を果たします。一方、**Kaniko** は build pipeline に privileged Docker daemon を与えたくない CI environments でよく使用されます。

重要な lesson は、image creation と image execution は異なる phases だということです。しかし、弱い build pipeline は、container が launch されるはるか前から weak runtime posture を作り出す可能性があります。

## Orchestration は Runtime とは別の Layer

Kubernetes を runtime 自体と同一視すべきではありません。Kubernetes は orchestrator です。Pods を schedule し、desired state を保存し、workload configuration を通じて security policy を表現します。その後 kubelet が containerd や CRI-O などの CRI implementation と通信し、それらが `runc`、`crun`、`runsc`、`kata-runtime` などの low-level runtime を呼び出します。

この分離は重要です。多くの人は、実際には node runtime によって enforce されている protection を "Kubernetes" に帰属させたり、Pod spec に由来する behavior を "containerd defaults" のせいにしたりするからです。実際の最終的な security posture は composition です。orchestrator が何かを要求し、runtime stack がそれを変換し、kernel が最終的に enforce します。

## Assessment 中に Runtime Identification が重要な理由

engine と runtime を早い段階で特定できれば、その後の多くの observations を解釈しやすくなります。rootless Podman container なら、user namespaces が関係している可能性が高いことを示します。workload に mount された Docker socket は、API-driven privilege escalation が現実的な path であることを示します。CRI-O/OpenShift node では、直ちに SELinux labels と restricted workload policy を考えるべきです。gVisor や Kata environment では、classic `runc` breakout PoC が同じように動作すると想定することに慎重になるべきです。

そのため、container assessment の最初の steps の一つでは、常に次の二つの簡単な questions に答えるべきです。**どの component が container を管理しているか**、そして **どの runtime が実際に process を launch したか**。これらの answers が明確になれば、残りの environment は通常、はるかに容易に理解できます。

## Runtime Vulnerabilities

すべての container escape が operator misconfiguration によって発生するわけではありません。runtime 自体が vulnerable component である場合もあります。これは、workload が慎重に見える configuration で実行されていても、low-level runtime flaw を通じて exposed になる可能性があることを意味します。

Classic な example は `runc` の **CVE-2019-5736** です。malicious container が host の `runc` binary を overwrite し、その後の `docker exec` や同様の runtime invocation が attacker-controlled code を trigger するまで待機できました。この exploit path は、単純な bind-mount や capability mistake とは大きく異なります。exec handling 中に runtime が container process space に再び入る方法を abuse するためです。

red-team perspective における minimal reproduction workflow は次のとおりです。
```bash
go build main.go
./main
```
次に、host から:
```bash
docker exec -it <container-name> /bin/sh
```
重要な教訓は、正確な過去の exploit 実装ではなく、評価上の意味にあります。runtime のバージョンに脆弱性がある場合、目に見える container の設定が明らかに弱そうに見えなくても、通常の container 内での code execution だけで host を compromise するのに十分な可能性があります。

`runc` の `CVE-2024-21626`、BuildKit の mount race、containerd の parsing bug など、最近の runtime CVE は同じ点を裏付けています。runtime のバージョンと patch level は、単なる保守上の細部ではなく、security boundary の一部です。
{{#include ../../../banners/hacktricks-training.md}}
