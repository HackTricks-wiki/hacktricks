# Container Runtimes、Engines、Builders、そして Sandboxes

Container security における最大の混乱要因の1つは、まったく異なる複数のコンポーネントが、同じ1つの言葉にまとめられてしまうことです。"Docker" は、image format、CLI、daemon、build system、runtime stack、あるいは単に container 全般の概念を指している場合があります。Security work では、この曖昧さが問題になります。異なるレイヤーが異なる保護を担っているためです。bad bind mount が原因の breakout は、low-level runtime の bug が原因の breakout と同じではなく、どちらも Kubernetes における cluster policy のミスとは異なります。

このページでは ecosystem を役割ごとに分離し、この section の以降の内容で、保護や weakness が実際にどこに存在するのかを正確に説明できるようにします。

## OCI As The Common Language

Modern Linux container stacks は、複数の OCI specifications に対応しているため、相互運用できることが多くなっています。**OCI Image Specification** は、image と layer の表現方法を定義します。**OCI Runtime Specification** は、namespace、mount、cgroup、security settings などを含め、runtime が process を起動する方法を定義します。**OCI Distribution Specification** は、registry が content を公開する方法を標準化します。

これは、ある tool で build した container image を別の tool で実行できることが多い理由や、複数の engine が同じ low-level runtime を共有できる理由を説明します。また、異なる product 間で security behavior が似て見える理由も説明します。多くの product が同じ OCI runtime configuration を構築し、それを同じ少数の runtime に渡しているためです。

## Low-Level OCI Runtimes

low-level runtime は、kernel boundary に最も近い component です。実際に namespace を作成し、cgroup settings を書き込み、capability と seccomp filter を適用し、最後に container process を `execve()` する部分です。mechanical なレベルで "container isolation" について議論するとき、明示されていなくても、通常はこの layer を指しています。

### `runc`

`runc` は reference OCI runtime であり、現在も最もよく知られた実装です。Docker、containerd、多くの Kubernetes deployment で幅広く使用されています。多くの public research と exploitation material が `runc`-style environment を対象にしているのは、単純にそれらが普及していることと、`runc` が多くの人が Linux container を思い浮かべるときの baseline を定義しているためです。そのため、`runc` を理解すると、classic container isolation について強い mental model を得られます。

### `crun`

`crun` は別の OCI runtime で、C で記述され、modern Podman environment で広く使用されています。優れた cgroup v2 support、強力な rootless ergonomics、低い overhead が評価されることが多い runtime です。security の観点で重要なのは、別の language で書かれていることではなく、同じ役割を担っていることです。つまり、OCI configuration を kernel 下で動作する process tree に変換する component です。rootless Podman workflow がより安全に感じられることが多いのは、`crun` がすべてを魔法のように修正するからではなく、その周辺の stack 全体が user namespace と least privilege をより重視する傾向にあるためです。

### `runsc` From gVisor

`runsc` は gVisor が使用する runtime です。ここでは boundary の意味が大きく変わります。通常の方法でほとんどの syscall を host kernel に直接渡すのではなく、gVisor は userspace kernel layer を挿入し、Linux interface の大部分を emulate または mediate します。その結果は、いくつかの flag を追加した通常の `runc` container ではありません。host-kernel attack surface を減らすことを目的とした、異なる sandbox design です。compatibility と performance の trade-off もこの design の一部であるため、`runsc` を使用する environment は、通常の OCI runtime environment とは別に記録すべきです。

### `kata-runtime`

Kata Containers は、workload を lightweight virtual machine 内で起動することにより、boundary をさらに拡張します。管理上は container deployment のように見え、orchestration layer もそのように扱う場合があります。しかし、基盤となる isolation boundary は、classic な host-kernel-shared container よりも virtualization に近いものです。そのため、container-centric workflow を放棄せずに、より強い tenant isolation が必要な場合に Kata が役立ちます。

## Engines And Container Managers

low-level runtime が kernel と直接通信する component だとすれば、engine または manager は、通常 users と operators が操作する component です。image pull、metadata、log、network、volume、lifecycle operation、API exposure を処理します。この layer は非常に重要です。現実の compromise の多くがここで発生するためです。low-level runtime 自体が完全に正常でも、runtime socket または daemon API への access は host compromise と同等になり得ます。

### Docker Engine

Docker Engine は developers にとって最も認識されやすい container platform であり、container vocabulary が Docker 中心になった理由の1つでもあります。典型的な path は `docker` CLI から `dockerd` へ進み、`dockerd` が `containerd` や OCI runtime などの lower-level component を調整します。歴史的に Docker deployment は **rootful** であることが多く、そのため Docker socket への access は非常に強力な primitive でした。これが、実用的な privilege-escalation material の多くが `docker.sock` に焦点を当てる理由です。process が `dockerd` に対して privileged container の作成、host path の mount、host namespace への join を要求できるなら、kernel exploit はまったく必要ない可能性があります。

### Podman

Podman は、より daemonless な model を中心に設計されました。運用面では、container が1つの long-lived privileged daemon ではなく、標準的な Linux mechanism を通じて管理される単なる process であるという考えを強化します。Podman は、従来の Docker deployment よりもはるかに強力な **rootless** story も備えています。これは Podman が自動的に安全であることを意味しませんが、特に user namespace、SELinux、`crun` と組み合わせた場合、default の risk profile を大きく変えます。

### containerd

containerd は、多くの modern stack における core runtime management component です。Docker の下で使用されるほか、主要な Kubernetes runtime backend の1つでもあります。強力な API を公開し、image と snapshot を管理し、最終的な process creation を low-level runtime に委譲します。containerd に関する security discussion では、containerd socket や `ctr`/`nerdctl` の functionality への access は、interface と workflow がそれほど "developer friendly" に感じられなくても、Docker API への access と同じくらい危険になり得ることを強調すべきです。

### CRI-O

CRI-O は Docker Engine よりも用途が限定されています。general-purpose developer platform ではなく、Kubernetes Container Runtime Interface を適切に実装することを中心に構築されています。そのため、Kubernetes distribution や OpenShift のような SELinux-heavy ecosystem で特によく使用されます。security の観点では、この限定された scope が有用です。概念上の clutter が減るためです。CRI-O は、あくまで "Kubernetes のために container を実行する" layer の一部であり、everything-platform ではありません。

### Incus, LXD, And LXC

Incus/LXD/LXC system は、Docker-style application container とは分けて考える価値があります。これらは **system container** として使用されることが多いためです。system container は通常、より完全な userspace、long-running service、豊富な device exposure、より広範な host integration を備えた lightweight machine に近い動作を期待されます。isolation mechanism は依然として kernel primitive ですが、運用上の前提が異なります。その結果、ここでの misconfiguration は "bad app-container default" というより、lightweight virtualization や host delegation におけるミスに近い形で現れることが多くなります。

### systemd-nspawn

systemd-nspawn は systemd-native であり、testing、debugging、OS-like environment の実行に非常に有用であるため、興味深い位置を占めています。cloud-native production runtime の主流ではありませんが、lab や distro-oriented environment で十分頻繁に登場するため、言及する価値があります。security analysis において、これは "container" という概念が複数の ecosystem と運用 style にまたがっていることを再認識させる存在です。

### Apptainer / Singularity

Apptainer（旧称 Singularity）は research と HPC environment で一般的です。その trust assumption、user workflow、execution model は、Docker/Kubernetes-centric stack とは重要な点で異なります。特にこれらの environment では、ユーザーに広範な privileged container-management power を与えずに packaged workload を実行させることが重視されます。すべての container environment が基本的に "server 上の Docker" だと考える reviewer は、これらの deployment を大きく誤って理解することになります。

## Build-Time Tooling

多くの security discussion は run time だけを扱います。しかし build-time tooling も重要です。image の内容、build secrets の exposure、最終 artifact にどれだけの trusted context が組み込まれるかを決定するためです。

**BuildKit** と `docker buildx` は、caching、secret mounting、SSH forwarding、multi-platform build などの feature をサポートする modern build backend です。これらは便利な feature ですが、security の観点では、secret が image layer に leak したり、広すぎる build context により、本来含めるべきでない file が露出したりする場所も作り出します。**Buildah** は OCI-native ecosystem、特に Podman 周辺で同様の役割を果たします。一方、**Kaniko** は privileged Docker daemon を build pipeline に与えたくない CI environment でよく使用されます。

重要な lesson は、image creation と image execution は異なる phase だということです。しかし weak build pipeline は、container が起動されるずっと前から weak runtime posture を作り出す可能性があります。

## Orchestration Is Another Layer, Not The Runtime

Kubernetes を runtime 自体と同一視すべきではありません。Kubernetes は orchestrator です。Pod を schedule し、desired state を保存し、workload configuration を通じて security policy を表現します。kubelet はその後、containerd や CRI-O などの CRI implementation と通信し、それらが `runc`、`crun`、`runsc`、`kata-runtime` などの low-level runtime を呼び出します。

この分離は重要です。多くの人が、実際には node runtime によって enforcement されている protection を "Kubernetes" によるものだと誤って atribuite したり、Pod spec に由来する behavior を "containerd default" のせいにしたりするためです。実際の最終的な security posture は composition です。orchestrator が何かを要求し、runtime stack がそれを変換し、最後に kernel が enforcement します。

## Why Runtime Identification Matters During Assessment

engine と runtime を早期に特定すると、後続の多くの observation を解釈しやすくなります。rootless Podman container なら、user namespace が関係している可能性が高いと判断できます。workload に Docker socket が mount されていれば、API-driven privilege escalation が現実的な path だと考えられます。CRI-O/OpenShift node では、SELinux label と restricted workload policy をすぐに意識すべきです。gVisor または Kata environment では、classic な `runc` breakout PoC が同じように動作すると仮定しないよう注意すべきです。

そのため、container assessment の最初の steps の1つは、常に次の2つの簡単な質問に答えることです。**container を管理している component は何か**、そして **process を実際に起動した runtime は何か**。これらの答えが明確になれば、environment の残りの部分も通常ははるかに容易に推論できます。

## Runtime Vulnerabilities

すべての container escape が operator misconfiguration によって発生するわけではありません。runtime 自体が vulnerable component である場合もあります。これは、注意深く見える configuration で workload が実行されていても、low-level runtime flaw を通じて expose される可能性があることを意味します。

classic な例は `runc` の **CVE-2019-5736** です。malicious container が host の `runc` binary を overwrite し、その後の `docker exec` または類似した runtime invocation が attacker-controlled code を trigger するまで待機できました。この exploit path は、単純な bind-mount や capability のミスとは大きく異なります。exec handling 中に runtime が container process space に再入する仕組みを悪用するためです。<sup>[[1]](#references)</sup>

red-team perspective から見た minimal reproduction workflow は次のとおりです。
```bash
go build main.go
./main
```
その後、hostから:
```bash
docker exec -it <container-name> /bin/sh
```
重要な教訓は、過去の exploit の正確な実装ではなく、評価上の意味にあります。runtime のバージョンに脆弱性がある場合、目に見える container 設定が明らかに弱く見えなくても、通常の in-container code execution だけで host を compromise するのに十分な可能性があります。

`runc` の `CVE-2024-21626`、BuildKit の mount race、containerd の parsing bug など、最近の runtime CVE は同じ点を強調しています。runtime のバージョンと patch level は、単なる保守上の細部ではなく、security boundary の一部です。

## References

- [1] [runC を介した Docker からの脱出 – CVE-2019-5736 の解説](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
