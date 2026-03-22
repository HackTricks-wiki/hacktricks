# コンテナセキュリティ

{{#include ../../../banners/hacktricks-training.md}}

## コンテナが実際に何であるか

実務的な定義としては、コンテナとは特定の OCI-style 設定の下で起動され、制御されたファイルシステム、制御されたカーネルリソース、および制限された特権モデルを「見る」ようにされた**通常の Linux プロセスツリー**です。プロセスは自分が PID 1 だと信じるかもしれませんし、自前の network stack を持っていると信じるかもしれませんし、自分の hostname や IPC リソースを所有していると信じるかもしれませんし、user namespace 内で root として実行されることさえあります。しかし内部では、それでもカーネルが他のプロセスと同様にスケジュールするホスト上のプロセスに過ぎません。

だからこそコンテナセキュリティは、その「幻影」がどのように構築され、どのように破綻するかの研究なのです。mount namespace が弱ければプロセスはホストのファイルシステムを見てしまいます。user namespace がないか無効化されていれば、コンテナ内の root はホスト上の root とあまりに近くマップされる可能性があります。seccomp が制限されておらず、capability セットが広すぎれば、プロセスは到達すべきでなかった syscalls や特権的なカーネル機能にアクセスできます。runtime socket がコンテナ内にマウントされていれば、コンテナはカーネル脱出を必要とせず、単に runtime により強力な兄弟コンテナを起動させたりホストのルートファイルシステムを直接マウントさせたりできます。

## コンテナと仮想マシンの違い

VM は通常、自分用のカーネルとハードウェア抽象化境界を持ちます。つまり、ゲストカーネルがクラッシュ、panic、またはエクスプロイトされても、必ずしもホストカーネルの直接制御を意味しません。一方コンテナでは、ワークロードに別個のカーネルは与えられません。代わりにホストが使用する同じカーネルの、慎重にフィルタリングされ namespaced 化されたビューが与えられます。そのため、コンテナは一般に軽量で起動が速く、マシン上に密に詰めやすく、一時的なアプリケーション展開に向いています。代償は、隔離境界がホストとランタイムの正しい設定にずっと直接依存することです。

これはコンテナが「insecure」で VM が「secure」である、という意味ではありません。セキュリティモデルが異なる、ということです。rootless 実行、user namespaces、デフォルト seccomp、厳格な capability セット、ホスト namespace 共有なし、強力な SELinux や AppArmor の強制などを備えた適切に設定されたコンテナスタックは非常に堅牢になり得ます。逆に `--privileged`、ホスト PID/ネットワーク共有、Docker socket を内部にマウント、`/` の書き込み可能な bind mount で開始されたコンテナは、安全に隔離されたアプリケーションサンドボックスというよりもホスト root アクセスに機能的に非常に近くなります。差は有効化または無効化されたレイヤーから生じます。

実運用環境では読者が理解すべき中間の立ち位置も増えています。gVisor や Kata Containers といった **sandboxed container runtimes** は意図的に古典的な `runc` コンテナ以上に境界を強化します。gVisor はワークロードと多くのホストカーネルインターフェースの間に userspace カーネル層を置き、Kata はワークロードを軽量な仮想マシン内で起動します。これらはコンテナエコシステムとオーケストレーションワークフローを通じて使われ続けますが、そのセキュリティ特性はプレーンな OCI ランタイムとは異なり、「普通の Docker コンテナ」と同じように一括りに扱うべきではありません。

## コンテナスタック：単一ではなく複数のレイヤー

「このコンテナは insecure だ」と言われたときに有益な追跡質問は：**どのレイヤーがそれを insecure にしたのか？** です。コンテナ化されたワークロードは通常いくつかのコンポーネントが協調して動作した結果です。

最上位には BuildKit、Buildah、Kaniko のような **image build layer** があり、OCI イメージとメタデータを作成します。低レベルの runtime の上には Docker Engine、Podman、containerd、CRI-O、Incus、または systemd-nspawn といった **engine or manager** があるかもしれません。クラスタ環境では Kubernetes のような **orchestrator** が workload の設定を通じて要求されるセキュリティ姿勢を決定することもあります。最後に、namespaces、cgroups、seccomp、MAC ポリシーを実際に強制するのは **kernel** です。

このレイヤモデルはデフォルトを理解する上で重要です。制限は Kubernetes により要求され、CRI を通じて containerd や CRI-O に翻訳され、runtime wrapper により OCI spec に変換され、そして初めて `runc`、`crun`、`runsc` などのランタイムによってカーネルに対して強制されることがあります。環境間でデフォルトが異なるのは、しばしばこれらいずれかのレイヤが最終構成を変更したためです。同じメカニズムは Docker や Podman では CLI フラグとして、Kubernetes では Pod や `securityContext` フィールドとして、低レベルのランタイムスタックではワークロードのために生成された OCI 設定として現れます。したがってこのセクションの CLI 例は、すべてのツールでサポートされる普遍的なフラグではなく、一般的なコンテナ概念に対する **runtime-specific syntax** として読むべきです。

## 実際のコンテナセキュリティ境界

実務では、コンテナセキュリティは単一の完璧な制御から来るのではなく、**重なり合う制御** から来ます。Namespaces は可視性を隔離します。cgroups はリソース使用を統制・制限します。Capabilities は特権に見えるプロセスが実際に何をできるかを減らします。seccomp は危険な syscalls をカーネルに到達する前にブロックします。AppArmor と SELinux は通常の DAC チェックの上に Mandatory Access Control を追加します。`no_new_privs`、マスクされた procfs パス、および読み取り専用のシステムパスは一般的な特権昇格や proc/sys の悪用チェーンを難しくします。runtime 自体も重要で、どのように mounts、sockets、labels、namespace joins が作成されるかを決定します。

このため多くのコンテナセキュリティ文書が反復的に見えるのです。同じ脱出チェーンはしばしば複数のメカニズムに同時に依存します。例えば、書き込み可能なホスト bind mount はまず問題ですが、それがさらにコンテナがホスト上で実際の root として動いていて、`CAP_SYS_ADMIN` を持ち、seccomp によって制限されておらず、SELinux や AppArmor によって制限されていない場合は遥かに悪化します。同様にホスト PID 共有は深刻な露出ですが、`CAP_SYS_PTRACE`、弱い procfs 保護、または `nsenter` のような namespace-entry ツールと組み合わされると攻撃者にとって劇的に有用になります。したがって正しい説明の方法は同じ攻撃を何度も繰り返すことではなく、各レイヤが最終的な境界に何を寄与しているかを説明することです。

## このセクションの読み方

セクションは最も一般的な概念から最も具体的なものへと構成されています。

まず runtime とエコシステムの概要から始めてください：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

次に、攻撃者がそもそもカーネル脱出を必要とするかどうかを頻繁に決める control planes と supply-chain の表面を確認してください：

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

それから保護モデルに進んでください：

{{#ref}}
protections/
{{#endref}}

namespace のページはカーネルの隔離プリミティブを個別に説明します：

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths、読み取り専用システムパスに関するページは、通常 namespaces の上に重ねられるメカニズムを説明します：

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

## 最初に取るべき良い列挙の心構え

コンテナ化対象を評価する際には、有名な脱出 PoC にすぐ飛びつくよりも、少数の正確な技術的質問をする方がずっと有益です。まず **stack** を特定してください：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、またはそれ以外の特殊なものか。次に **runtime** を特定します：`runc`、`crun`、`runsc`、`kata-runtime`、または他の OCI-compatible 実装。そして環境が **rootful or rootless** か、**user namespaces** が有効か、どの **host namespaces** が共有されているか、どんな **capabilities** が残っているか、**seccomp** が有効か、**MAC policy** が実際に強制されているか、**dangerous mounts or sockets** が存在するか、プロセスがコンテナ runtime API とやり取りできるかを確認してください。

これらの答えは、ベースイメージ名よりも実際のセキュリティ姿勢についてはるかに多くを教えてくれます。多くの評価では、最終的なコンテナ構成を理解するだけで、アプリケーションファイルを一つも読まずに予想される脱出ファミリを推測できます。

## 対象範囲

このセクションはコンテナ指向の構成下で旧来の Docker 中心の資料を扱います：runtime と daemon の露出、authorization plugins、image trust と build secrets、センシティブなホストマウント、distroless ワークロード、privileged containers、および通常コンテナ実行の周りに重ねられるカーネル保護。
{{#include ../../../banners/hacktricks-training.md}}
