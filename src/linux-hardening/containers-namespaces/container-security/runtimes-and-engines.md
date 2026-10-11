# コンテナ Runtime、Engine、Builder、Sandbox

{{#include ../../../banners/hacktricks-training.md}}

コンテナセキュリティで大きな混乱を招く原因の一つは、まったく異なる複数のコンポーネントが、しばしば同じ言葉でひとまとめにされることです。「Docker」は、イメージ形式、CLI、daemon、build system、runtime stack、あるいは単にコンテナ全般を指す場合があります。セキュリティの作業では、この曖昧さが問題になります。レイヤーごとに担う保護が異なるためです。不適切な bind mount による脱出は、低レベル runtime の脆弱性による脱出とは異なり、どちらも Kubernetes の cluster policy の設定ミスとは別物です。

このページでは、エコシステムを役割ごとに分け、以降のセクションで保護や弱点が実際にどこにあるのかを正確に説明できるようにします。

## 共通言語としての OCI

現代の Linux コンテナ stack は、OCI 仕様群に準拠しているため、相互運用できることがよくあります。**OCI Image Specification** は、イメージと layer の表現方法を定めています。**OCI Runtime Specification** は、namespace、mount、cgroup、セキュリティ設定などを含め、runtime がプロセスを起動する方法を定めています。**OCI Distribution Specification** は、registry がコンテンツを公開する方法を標準化しています。

このことから、あるツールで作成したコンテナイメージを別のツールで実行できることが多い理由や、複数の engine が同じ低レベル runtime を共有できる理由がわかります。また、異なる製品間でセキュリティ動作が似ていることがある理由も説明できます。多くの製品は、同じ OCI runtime 設定を構築し、限られた種類の runtime に渡しているからです。

## 低レベル OCI Runtime

低レベル runtime は、kernel 境界に最も近いコンポーネントです。実際に namespace を作成し、cgroup 設定を書き込み、capability と seccomp filter を適用し、最後にコンテナプロセスを `execve()` する部分です。機構としての「コンテナ分離」について人々が話すとき、明示していなくても、通常はこのレイヤーを指しています。

### `runc`

`runc` は OCI の reference runtime であり、今も最もよく知られた実装です。Docker、containerd、および多くの Kubernetes 環境で広く使われています。`runc` 形式の環境を対象にした公開研究や exploit 情報が多いのは、単に普及しているからだけでなく、多くの人が Linux コンテナを想像するときの基準を `runc` が定めているからです。そのため、`runc` を理解すると、従来型のコンテナ分離について強固なメンタルモデルを得られます。

### `crun`

`crun` は C で書かれた別の OCI runtime で、現代の Podman 環境で広く使われています。cgroup v2 のサポート、rootless の使いやすさ、オーバーヘッドの低さが評価されることがよくあります。セキュリティの観点で重要なのは、異なる言語で書かれていることではなく、同じ役割を担う点です。つまり、OCI 設定を kernel 配下で動作するプロセスツリーに変換するコンポーネントです。rootless Podman の workflow がより安全に感じられることが多いのは、`crun` がすべてを魔法のように解決するからではなく、その周辺の stack 全体が user namespace と最小権限をより重視する傾向があるからです。

### gVisor の `runsc`

`runsc` は gVisor が使用する runtime です。ここでは境界の意味が大きく変わります。通常の方法で大部分の syscall を host kernel に直接渡す代わりに、gVisor は userspace kernel layer を挿入し、Linux interface の大部分をエミュレートまたは仲介します。その結果は、いくつかの flag を追加した通常の `runc` コンテナではありません。host kernel の攻撃対象領域を減らすことを目的とした、別種の sandbox 設計です。互換性とパフォーマンスのトレードオフも設計の一部であるため、`runsc` を使う環境は、通常の OCI runtime 環境とは分けて記録する必要があります。

### `kata-runtime`

Kata Containers は、軽量 virtual machine 内で workload を起動することで、さらに境界を広げます。管理上はコンテナ deployment のように見え、orchestration layer もコンテナとして扱う場合がありますが、基盤となる分離境界は従来型の host kernel 共有コンテナというより仮想化に近いものです。そのため Kata は、コンテナ中心の workflow を捨てずに、より強い tenant 分離が必要な場合に有用です。

## Engine とコンテナ Manager

低レベル runtime が kernel と直接やり取りするコンポーネントなら、engine または manager は、ユーザーや運用担当者が通常操作するコンポーネントです。イメージの pull、metadata、log、network、volume、lifecycle 操作、API 公開を処理します。このレイヤーは非常に重要です。実際の侵害の多くはここで発生するためです。runtime socket や daemon API へのアクセスは、低レベル runtime 自体に問題がなくても、host の侵害と同等になり得ます。

### Docker Engine

Docker Engine は、開発者にとって最もよく知られたコンテナ platform であり、コンテナに関する語彙が Docker を中心に形作られた理由の一つでもあります。一般的な経路は `docker` CLI から `dockerd` へ、そこから `containerd` や OCI runtime などの低レベルコンポーネントへと進みます。歴史的に、Docker deployment は**rootful**であることが多く、そのため Docker socket へのアクセスは非常に強力な権限でした。実用的な権限昇格の解説で `docker.sock` が頻繁に取り上げられるのはこのためです。プロセスが `dockerd` に、privileged container の作成、host path の mount、host namespace への参加を要求できるなら、kernel exploit は必要ない場合があります。

release 番号は、dot を除去するのではなく、major、minor、patch の各要素で比較してください。たとえば、minor がゼロ埋めされていても、`18.09.1` は `18.09.2` と `18.09.4` のどちらよりも古いバージョンです。Docker の[18.09 release notes](https://docs.docker.com/engine/release-notes/18.09/)には、CVE-2019-5736 に対する同梱 `runc` の修正が 18.09.2 に、CVE-2019-13139 に対する build-reference の修正が 18.09.4 に含まれると記載されています。これらはバージョンを調査する手掛かりであり、exploit が実際に到達可能である証明ではありません。同じ release notes には、daemon、client、runtime は別々に package 化されているという注意もあります。そのため、daemon のバージョンに加えて、インストール済み runtime と vendor の backport も確認してください。また、build-reference の問題には、影響を受ける build workflow と攻撃者が制御する入力へのアクセスも必要です。

### Podman

Podman は、より daemonless なモデルを前提に設計されています。運用面では、コンテナは長期間動作する特権 daemon ではなく、標準的な Linux の仕組みで管理される単なるプロセスだという考え方を後押しします。また、Podman は、多くの人が最初に学んだ従来型 Docker deployment と比べ、**rootless** のサポートがはるかに充実しています。Podman が自動的に安全になるわけではありませんが、特に user namespace、SELinux、`crun` と組み合わせた場合、デフォルトのリスクプロファイルは大きく変わります。

### containerd

containerd は、多くの現代的な stack で中核となる runtime 管理コンポーネントです。Docker の下で使われるほか、Kubernetes の主要な runtime backend の一つでもあります。強力な API を公開し、イメージと snapshot を管理し、最終的なプロセス作成を低レベル runtime に委ねます。containerd に関するセキュリティの議論では、containerd socket や `ctr`/`nerdctl` の機能へのアクセスが、Docker API へのアクセスと同じくらい危険になり得ることを強調してください。interface や workflow がそれほど「開発者向け」に見えなくても同じです。

### CRI-O

CRI-O は Docker Engine よりも用途が絞られています。汎用の開発者向け platform ではなく、Kubernetes Container Runtime Interface を適切に実装することを目的として構築されています。そのため、Kubernetes distribution や OpenShift などの SELinux を重視する ecosystem で特によく使われています。セキュリティの観点では、この用途の絞り込みが役立ちます。概念上の混乱が減り、CRI-O が「Kubernetes 用にコンテナを実行する」レイヤーの一部であることが明確になるからです。

Kubernetes node が CRI-O を使用している場合は、namespace で Pod を作成できる現在の identity かどうかに加えて、**node で稼働中の CRI-O release**を確認してください。[CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7)では、細工された Pod sysctl 値によって host kernel parameter が変更され、影響を受ける release で host-root 実行に至る可能性がありました。upstream advisory には、修正済み release と回避策が記載されています。ローカルでの `crio --version` では、Minikube などの node container 内部にある runtime を見落とす場合があります。読み取り可能な Minikube 起動 log はバージョンを推測する手掛かりにはなりますが、過去の情報であり、稼働中の runtime やその patch 状態を証明するものではありません。これが到達可能な権限昇格経路だと判断する前に、実際の node runtime、Pod 作成の認可、admission rule、関連する seccomp と user namespace の境界を確認してください。

ローカルで `pinns` を直接調べる方法もあります。[調査者によると、問題のある helper の実行に Kubernetes は不要です](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/)。現在の account が root 所有の setuid `pinns` を実行できるか、その権限移行が NoNewPrivs または `nosuid` mount によって阻止されるか、インストール済みの**helper build**に修正が含まれているかを確認してください。[upstream advisory](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7)には修正済み release のバージョンが記載されていますが、daemon に表示されるバージョンだけでは、どの helper binary がインストールされているかは証明できません。また、distribution の backport によって影響の有無が変わる可能性があります。setuid file はあくまで候補にすぎません。日常的な調査の際に実行することなく、helper の出所、設定、host の sysctl 動作を検証してください。

### Incus、LXD、LXC

Incus/LXD/LXC の system は、**system container**として使われることが多いため、Docker 型の application container と分けて考える価値があります。system container は通常、より完全な userspace、長期間稼働する service、豊富な device 公開、より広範な host 連携を備えた、軽量な machine に近いものとして期待されます。分離には引き続き kernel の primitive が使われますが、運用上の想定は異なります。そのため、ここでの設定ミスは「app container のデフォルト設定の不備」というより、軽量仮想化や host の権限委譲の誤りとして現れることがよくあります。

### systemd-nspawn

systemd-nspawn は systemd に組み込まれており、テスト、debug、OS のような環境の実行に便利なため、興味深い位置を占めています。cloud-native の本番 runtime として主流ではありませんが、lab や distro 中心の環境では十分に見かけるため、触れておく価値があります。セキュリティ分析において、これは「コンテナ」という概念が複数の ecosystem と運用形態にまたがることを改めて示す例です。

### Apptainer / Singularity

Apptainer（旧 Singularity）は、研究や HPC 環境で一般的です。信頼モデル、ユーザー workflow、実行モデルは、Docker/Kubernetes 中心の stack と重要な点で異なります。特に、ユーザーに広範な特権コンテナ管理権限を与えずに、package 化された workload を実行できるようにすることが重視される環境が多くあります。すべてのコンテナ環境が基本的に「server 上の Docker」だと考えると、こうした deployment を大きく誤解することになります。

## Build 時の Tooling

セキュリティの議論では実行時だけが取り上げられることが多いものの、build 時の tooling も重要です。イメージの内容、build secret の漏洩、信頼された context が最終 artifact にどれだけ含まれるかを左右するためです。

**BuildKit** と `docker buildx` は、cache、secret の mount、SSH forwarding、multi-platform build などの機能をサポートする現代的な build backend です。これらは便利な機能ですが、セキュリティの観点では、secret が image layer に leak したり、広すぎる build context によって本来含めるべきでない file が露出したりする箇所にもなります。**Buildah** は OCI native な ecosystem、特に Podman の周辺で同様の役割を果たします。一方、**Kaniko** は、build pipeline に特権 Docker daemon を与えたくない CI 環境でよく使われます。

重要なのは、イメージの作成と実行は別々の段階だということです。しかし、弱い build pipeline は、コンテナが起動されるずっと前に、実行時のセキュリティ態勢を弱める可能性があります。

## Orchestration は Runtime とは別のレイヤー

Kubernetes を runtime 自体と同一視してはいけません。Kubernetes は orchestrator です。Pod をスケジュールし、desired state を保存し、workload 設定を通じてセキュリティ policy を表現します。kubelet はその後、containerd や CRI-O などの CRI 実装と通信し、さらにその実装が `runc`、`crun`、`runsc`、`kata-runtime` などの低レベル runtime を呼び出します。

この区別は重要です。多くの人は、実際には node runtime が適用している保護を誤って「Kubernetes の保護」と説明したり、Pod spec に起因する動作を「containerd のデフォルト設定」のせいにしたりします。実際のセキュリティ態勢は複数要素の組み合わせです。orchestrator が要求を出し、runtime stack がそれを変換し、最後に kernel が適用します。

## Assessment 中に Runtime を特定する理由

早い段階で engine と runtime を特定すれば、後から得られる多くの所見を解釈しやすくなります。rootless Podman container であれば、user namespace が関係している可能性が高いと考えられます。workload に Docker socket が mount されていれば、API を利用した権限昇格が現実的な経路になります。CRI-O/OpenShift node では、SELinux label と制限付き workload policy をすぐに考慮すべきです。gVisor や Kata の環境では、従来型の `runc` breakout PoC が同じように動作すると思い込まないよう、より慎重になる必要があります。

そのため、コンテナ assessment の最初の手順では、次の2つの簡単な質問に必ず答えるべきです。**どのコンポーネントがコンテナを管理しているか**、そして**どの runtime が実際にプロセスを起動したか**。答えが明確になれば、通常、環境の残りの部分もはるかに理解しやすくなります。

## Runtime の脆弱性

コンテナ escape の原因がすべて、運用担当者の設定ミスとは限りません。runtime 自体が脆弱なコンポーネントである場合もあります。注意深く設定されているように見える workload でも、低レベル runtime の欠陥を通じて影響を受ける可能性があるため、これは重要です。

典型例は `runc` の **CVE-2019-5736** です。悪意のあるコンテナが host の `runc` binary を上書きし、その後の `docker exec` などの runtime 呼び出しを待って、攻撃者が制御する code を実行させる可能性がありました。この exploit 経路は、単純な bind-mount や capability の設定ミスとは大きく異なります。exec 処理中に runtime がコンテナのプロセス空間へ再び入る方法を悪用するためです。<sup>[[1]](#references)</sup>

red-team の観点からの最小限の再現 workflow は次のとおりです。

```bash
go build main.go
./main
```

次に、ホスト側から:

```bash
docker exec -it <container-name> /bin/sh
```

重要なのは、過去のexploitの実装そのものではなく、評価上の示唆です。runtimeのバージョンに脆弱性がある場合、見た目上のコンテナ設定に明らかな弱点がなくても、コンテナ内で通常のコード実行ができるだけでホストを侵害できる可能性があります。

`runc`の`CVE-2024-21626`、BuildKitのmount race、containerdのparsing bugなど、近年のruntime CVEも同じ点を示しています。runtimeのバージョンとpatch levelは、単なる保守上の細事ではなく、セキュリティ境界の一部です。

## References

- [1] [runC経由でDockerから脱出する — CVE-2019-5736の解説](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
