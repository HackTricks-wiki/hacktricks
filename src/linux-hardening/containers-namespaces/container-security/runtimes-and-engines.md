# Container Runtimes、Engines、Builders、And Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container securityにおける最大の混乱要因の1つは、まったく異なる複数のコンポーネントが同じ1つの言葉にまとめられてしまうことです。「Docker」は、image format、CLI、daemon、build system、runtime stack、あるいは単にcontainers全般の概念を指す場合があります。Security workでは、この曖昧さが問題になります。異なるlayerが異なるprotectionを担っているためです。悪いbind mountが原因のbreakoutは、low-level runtimeのbugが原因のbreakoutとは異なり、どちらもKubernetesにおけるcluster policyのミスとは別物です。

このページでは、ecosystemをroleごとに分け、protectionやweaknessが実際にどこに存在するのかを、このセクションの後半で正確に説明できるようにします。

## OCIを共通言語として

Modern Linux container stackは、OCI specificationsの一連の仕様に対応しているため、相互運用できることがよくあります。**OCI Image Specification**は、imagesとlayersの表現方法を定義します。**OCI Runtime Specification**は、namespaces、mounts、cgroups、security settingsを含め、runtimeがprocessを起動する方法を定義します。**OCI Distribution Specification**は、registriesがcontentを公開する方法を標準化します。

これは、あるtoolでbuildしたcontainer imageを別のtoolで実行できることが多い理由や、複数のenginesが同じlow-level runtimeを共有できる理由を説明します。また、多くの製品が同じOCI runtime configurationを構築し、同じ少数のruntimesに渡しているため、異なる製品間でsecurity behaviorが似て見える理由も説明できます。

## Low-Level OCI Runtimes

low-level runtimeは、kernel boundaryに最も近いcomponentです。実際にnamespacesを作成し、cgroup settingsを書き込み、capabilitiesとseccomp filtersを適用し、最後にcontainer processを`execve()`する部分です。mechanicalな意味で「container isolation」について議論するとき、明示的にそう言わなくても、通常はこのlayerを指しています。

### `runc`

`runc`はreference OCI runtimeであり、現在も最もよく知られたimplementationです。Docker、containerd、多くのKubernetes deploymentsで広く使用されています。`runc`形式のenvironmentを対象とするpublic researchやexploitation materialが多いのは、単純に普及していること、そしてLinux containerを思い浮かべたときに多くの人が想定するbaselineを`runc`が定義しているためです。したがって、`runc`を理解することは、classic container isolationについて強固なmental modelを得ることにつながります。

### `crun`

`crun`は別のOCI runtimeで、Cで記述され、modern Podman environmentsで広く使用されています。優れたcgroup v2 support、強力なrootless ergonomics、低いoverheadで評価されることが多いruntimeです。Securityの観点で重要なのは、別のlanguageで書かれていることではなく、同じroleを担っていることです。つまり、OCI configurationをkernel上で動作するprocess treeに変換するcomponentです。rootless Podman workflowがより安全に感じられる場合、それは`crun`が魔法のようにすべてを修正するからではなく、その周辺のstackがuser namespacesとleast privilegeをより強く重視する傾向にあるためです。

### gVisorの`runsc`

`runsc`はgVisorが使用するruntimeです。ここではboundaryの意味が大きく変わります。通常の方法でほとんどのsyscallsをhost kernelへ直接渡す代わりに、gVisorはuserspace kernel layerを挿入し、Linux interfaceの大部分をemulateまたはmediateします。その結果は、いくつかの追加flagsを付けた通常の`runc` containerではなく、host-kernel attack surfaceを減らすことを目的とした別のsandbox designになります。Compatibilityとperformanceのtradeoffsはこのdesignの一部であるため、`runsc`を使用するenvironmentは、通常のOCI runtime environmentとは異なるものとしてdocumentすべきです。

### `kata-runtime`

Kata Containersは、workloadをlightweight virtual machine内で起動することでboundaryをさらに広げます。管理上はcontainer deploymentのように見え、orchestration layersもそのように扱う場合がありますが、基盤となるisolation boundaryはclassicなhost-kernel-shared containerよりもvirtualizationに近いものです。そのためKataは、container-centric workflowを捨てずに、より強いtenant isolationが必要な場合に有用です。

## Engines And Container Managers

low-level runtimeがkernelと直接通信するcomponentであるのに対し、engineまたはmanagerは、通常ユーザーやoperatorsが操作するcomponentです。image pulls、metadata、logs、networks、volumes、lifecycle operations、API exposureを処理します。このlayerは非常に重要です。実際のcompromiseの多くはここで発生するためです。low-level runtime自体が完全に正常でも、runtime socketやdaemon APIへのaccessはhost compromiseと同等になり得ます。

### Docker Engine

Docker Engineはdevelopersにとって最も認識しやすいcontainer platformであり、container vocabularyがDocker中心になった理由の1つです。一般的な経路は`docker` CLIから`dockerd`へ進み、`dockerd`が`containerd`やOCI runtimeなどのlower-level componentsを調整します。Historically、Docker deploymentsは**rootful**であることが多く、そのためDocker socketへのaccessは非常に強力なprimitiveでした。これが、実用的なprivilege-escalation materialの多くが`docker.sock`に注目する理由です。processが`dockerd`に対してprivileged containerの作成、host pathsのmount、host namespacesへの参加を要求できるなら、kernel exploitはまったく必要ない可能性があります。

### Podman

Podmanは、よりdaemonlessなmodelを中心に設計されました。Operationally、これはcontainersが、長期間稼働するprivileged daemonを介するのではなく、standard Linux mechanismsによって管理される単なるprocessであるという考えを強めます。またPodmanには、最初に学んだclassic Docker deploymentsよりもはるかに強力な**rootless**の仕組みがあります。これによってPodmanが自動的に安全になるわけではありませんが、特にuser namespaces、SELinux、`crun`と組み合わせた場合、defaultのrisk profileは大きく変わります。

### containerd

containerdは、多くのmodern stackにおけるcore runtime management componentです。Dockerの下で使用されるほか、主要なKubernetes runtime backendsの1つでもあります。強力なAPIsを公開し、imagesとsnapshotsを管理し、最終的なprocess creationをlow-level runtimeへ委譲します。containerdに関するsecurity discussionsでは、containerd socketへのaccessや`ctr`/`nerdctl` functionalityへのaccessが、interfaceやworkflowがDockerのAPIほど「developer friendly」に感じられなくても、DockerのAPIへのaccessと同じくらい危険になり得ることを強調すべきです。

### CRI-O

CRI-OはDocker Engineよりもfocusedです。general-purpose developer platformではなく、Kubernetes Container Runtime Interfaceを適切に実装することを中心に構築されています。そのため、Kubernetes distributionsやOpenShiftのようなSELinux-heavy ecosystemsで特によく使用されます。Securityの観点では、この狭いscopeが有用です。conceptual clutterを減らせるためです。CRI-Oはまさに「Kubernetes用にcontainersを実行する」layerの一部であり、everything-platformではありません。

### Incus、LXD、And LXC

Incus/LXD/LXC systemsは、Docker-style application containersとは分けて考える価値があります。これらはしばしば**system containers**として使用されるためです。system containerは通常、より完全なuserspace、long-running services、より豊富なdevice exposure、より広範なhost integrationを備えたlightweight machineに近い動作を期待されます。Isolation mechanismsは依然としてkernel primitivesですが、operational expectationsは異なります。その結果、ここでのmisconfigurationsは「bad app-container defaults」というより、lightweight virtualizationやhost delegationにおけるミスに近い形で現れることが多くなります。

### systemd-nspawn

systemd-nspawnはsystemd-nativeであり、testing、debugging、OS-like environmentsの実行に非常に有用なため、興味深い位置を占めています。dominantなcloud-native production runtimeではありませんが、labsやdistro-oriented environmentsで十分頻繁に登場するため、言及する価値があります。Security analysisにおいて、これは「container」という概念が複数のecosystemsとoperational stylesにまたがっていることを改めて示します。

### Apptainer / Singularity

Apptainer（旧称Singularity）はresearchやHPC environmentsで一般的です。そのtrust assumptions、user workflow、execution modelは、Docker/Kubernetes-centric stacksとは重要な点で異なります。特にこれらのenvironmentでは、usersに広範なprivileged container-management powersを与えずに、packaged workloadsを実行させることが重視される場合があります。reviewerがすべてのcontainer environmentを基本的に「server上のDocker」だと想定すると、これらのdeploymentsを大きく誤解することになります。

## Build-Time Tooling

多くのsecurity discussionsはrun timeについてのみ扱います。しかしbuild-time toolingも重要です。image contents、build secrets exposure、trusted contextが最終artifactにどの程度埋め込まれるかを決定するためです。

**BuildKit**と`docker buildx`は、caching、secret mounting、SSH forwarding、multi-platform buildsなどのfeaturesをサポートするmodern build backendsです。これらは便利なfeaturesですが、securityの観点では、secretsがimage layersにleakする場所や、広すぎるbuild contextによって本来含めるべきでないfilesが露出する場所も生み出します。**Buildah**はOCI-native ecosystems、特にPodman周辺で同様のroleを担います。一方、**Kaniko**は、build pipelineにprivileged Docker daemonを与えたくないCI environmentsでよく使用されます。

重要なlessonは、image creationとimage executionは異なるphasesだということです。しかし、弱いbuild pipelineは、containerが起動されるずっと前から弱いruntime postureを作り出す可能性があります。

## Orchestration Is Another Layer, Not The Runtime

Kubernetesをruntimeそのものと同一視すべきではありません。Kubernetesはorchestratorです。Podsをscheduleし、desired stateを保存し、workload configurationを通じてsecurity policyを表現します。その後kubeletがcontainerdやCRI-OなどのCRI implementationと通信し、それらがさらに`runc`、`crun`、`runsc`、`kata-runtime`などのlow-level runtimeを呼び出します。

この分離は重要です。多くの人が、実際にはnode runtimeによってenforceされているprotectionを「Kubernetes」に誤って帰属させたり、Pod specに由来するbehaviorを「containerd defaults」のせいにしたりするためです。実際のsecurity postureはcompositionです。orchestratorが何かを要求し、runtime stackがそれを変換し、最終的にkernelがenforceします。

## Why Runtime Identification Matters During Assessment

早い段階でengineとruntimeを特定すれば、その後の多くのobservationsを容易に解釈できます。rootless Podman containerからは、user namespacesが関係している可能性が高いと考えられます。workloadにmountされたDocker socketからは、API-driven privilege escalationが現実的なpathだと推測できます。CRI-O/OpenShift nodeでは、SELinux labelsとrestricted workload policyをすぐに検討すべきです。gVisorやKata environmentでは、classicな`runc` breakout PoCが同じように動作すると想定することに慎重になるべきです。

そのため、container assessmentの最初のstepsの1つとして、常に2つの簡単な質問に答えるべきです。**containerを管理しているcomponentはどれか**、そして**実際にprocessを起動したruntimeはどれか**。これらの答えが明確になれば、残りのenvironmentは通常、はるかに容易にreasoningできるようになります。

## Runtime Vulnerabilities

すべてのcontainer escapeがoperator misconfigurationによって発生するわけではありません。runtime自体がvulnerable componentである場合もあります。これは、workloadが慎重に見えるconfigurationで実行されていても、low-level runtime flawを通じてexposedになる可能性があるため重要です。

classicな例は、`runc`における**CVE-2019-5736**です。malicious containerがhostの`runc` binaryをoverwriteし、その後の`docker exec`や同様のruntime invocationがattacker-controlled codeをtriggerするまで待機できました。このexploit pathは、runtimeがexec handling中にcontainer process spaceへ再侵入する方法を悪用するため、単純なbind-mountやcapability mistakeとは大きく異なります。<sup>[[1]](#references)</sup>

red-teamの観点から見たminimal reproduction workflowは、次のとおりです。
```bash
go build main.go
./main
```
次に、host から:
```bash
docker exec -it <container-name> /bin/sh
```
重要なのは、過去の exploit の正確な実装ではなく、評価上の意味です。ランタイムのバージョンに脆弱性がある場合、目に見えるコンテナ設定が明らかに弱く見えなくても、通常の in-container code execution だけでホストを compromise するのに十分な可能性があります。

`runc` の `CVE-2024-21626`、BuildKit の mount race、containerd の parsing bug など、最近のランタイム CVE は同じ点を強調しています。ランタイムのバージョンとパッチレベルは、単なる保守上の細部ではなく、security boundary の一部です。

## References

- [1] [runC 経由で Docker から脱出する – CVE-2019-5736 の解説](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
