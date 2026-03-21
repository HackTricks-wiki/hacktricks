# コンテナ セキュリティ

{{#include ../../../banners/hacktricks-training.md}}

## コンテナとは何か

実用的にコンテナを定義するならば次のようになります：コンテナとは、特定のOCI-styleの設定の下で起動され、制御されたファイルシステム、制御されたカーネル資源の集合、そして制限された権限モデルを見ている**通常のLinuxプロセスツリー**です。プロセスは自分がPID 1だと信じるかもしれませんし、自分専用のネットワークスタックやホスト名、IPC資源を持っていると考えるかもしれませんし、ユーザーネームスペース内でrootとして動作することさえあります。しかし裏側では、それでもカーネルが他のプロセスと同様にスケジュールするホスト上のプロセスに過ぎません。

だからこそコンテナセキュリティは、その「幻影」がどのように構築されているか、そしてそれがどのように破綻するかを研究する領域なのです。mount namespace が弱ければ、プロセスはホストのファイルシステムを見てしまうかもしれません。user namespace が存在しないか無効化されていれば、コンテナ内の root はホストの root と過度に近いマッピングになり得ます。seccomp が未設定で capability のセットが広すぎれば、プロセスはアクセスすべきでなかった syscalls や特権的なカーネル機能に届いてしまうかもしれません。runtime ソケットがコンテナ内にマウントされていれば、コンテナはカーネルブレイクアウトを起こす必要すらなく、単に runtime にもっと強力な兄弟コンテナを起動させたりホストのルートファイルシステムを直接マウントさせたりできます。

## コンテナと仮想マシンの違い

VM は通常独自のカーネルとハードウェア抽象境界を持ちます。つまりゲストのカーネルがクラッシュ、パニック、あるいはエクスプロイトされても、それだけでホストのカーネルを直接制御できることを意味しません。コンテナではワークロードは別のカーネルを得るわけではなく、ホストが使う同じカーネルに対してフィルタリングされ、名前空間化されたビューを与えられます。その結果、コンテナは通常より軽量で起動が速く、マシン上に高密度で詰めやすく、短命のアプリケーション配備に向いています。その代償は、隔離境界がホストとランタイムの正しい設定により直接依存する点です。

これはコンテナが「不安全」で仮想マシンが「安全」という意味ではありません。セキュリティモデルが異なる、ということです。rootless 実行、user namespaces、デフォルトの seccomp、厳格な capability セット、ホストの namespace 共有なし、強力な SELinux や AppArmor の強制がある適切に構成されたコンテナスタックは非常に堅牢になり得ます。逆に、`--privileged` で起動され、host PID/network を共有し、Docker ソケットがマウントされ、`/` を書き込み可能な bind mount で与えられたコンテナは、安全に隔離されたアプリケーションサンドボックスというよりもホスト root アクセスに機能的に非常に近いものです。違いは有効化または無効化されたレイヤーから生じます。

また現実の環境でますます目にする中間的な選択肢も理解しておくべきです。**gVisor** や **Kata Containers** のような**サンドボックス化されたコンテナランタイム**は、古典的な `runc` コンテナを超えて境界を強化することを意図しています。gVisor はワークロードと多くのホストカーネルインターフェイスの間にユーザースペースカーネル層を置き、Kata はワークロードを軽量な仮想マシン内で起動します。これらはコンテナエコシステムやオーケストレーションワークフローを通じて使われますが、セキュリティ特性は通常の OCI ランタイムとは異なり、すべてが「通常の Docker コンテナ」と同じ振る舞いをするかのように一括りに考えるべきではありません。

## コンテナスタック：単一ではなく複数のレイヤー

誰かが「このコンテナは安全でない」と言ったときに有用な追問は：**どのレイヤーがそれを不安全にしたのか？**です。コンテナ化されたワークロードは通常、複数のコンポーネントが連携してできています。

最上位には BuildKit、Buildah、Kaniko のような **image build layer** があり、OCI イメージとメタデータを作成します。低レイヤの runtime の上には Docker Engine、Podman、containerd、CRI-O、Incus、systemd-nspawn のような **engine or manager** があることもあります。クラスタ環境では、Kubernetes のような **orchestrator** がワークロードの構成を通じて要求されるセキュリティ姿勢を決めることもあります。最後に、名前空間、cgroups、seccomp、MAC ポリシーを実際に強制するのは **カーネル** です。

このレイヤードモデルはデフォルトを理解する上で重要です。制約は Kubernetes によって要求され、CRI を介して containerd や CRI-O に翻訳され、ランタイムラッパーによって OCI spec に変換され、そして `runc`、`crun`、`runsc`、あるいは別のランタイムによってカーネルに対して強制される、という流れがよくあります。環境間でデフォルトが異なるのは、多くの場合これらのレイヤーのどれかが最終的な設定を変えたためです。同じメカニズムは Docker や Podman では CLI フラグとして、Kubernetes では Pod や `securityContext` フィールドとして、低レベルのランタイムスタックではワークロード用に生成された OCI 設定として現れることがあります。したがってこの節の CLI 例は、すべてのツールで共通のフラグとして理解するのではなく、一般的なコンテナ概念に対する**ランタイム固有の構文**として読むべきです。

## 実際のコンテナセキュリティ境界

実務では、コンテナセキュリティは単一の完璧な制御から生じるのではなく、**重なり合う制御**から生じます。Namespaces は可視性を隔離します。cgroups はリソース使用を管理・制限します。Capabilities は特権に見えるプロセスが実際に何をできるかを減らします。seccomp は危険な syscall をカーネルに到達する前にブロックします。AppArmor や SELinux は通常の DAC チェックに上乗せして Mandatory Access Control を追加します。`no_new_privs`、mask された procfs パス、読み取り専用のシステムパスは一般的な権限昇格や proc/sys の悪用チェーンを難しくします。さらにランタイム自体も重要で、どのようにマウント、ソケット、ラベル、namespace の参加が作成されるかを決めます。

だから多くのコンテナセキュリティ文書が冗長に見えるのです。同じ脱出チェーンが複数のメカニズムに同時に依存することが多いからです。例えば書き込み可能なホスト bind mount は悪いことですが、コンテナがホスト上で実際の root で動作し、`CAP_SYS_ADMIN` を持ち、seccomp による拘束がなく、SELinux や AppArmor による制限がない場合、その危険性はさらに増大します。同様に host PID の共有は重大な露出ですが、`CAP_SYS_PTRACE`、弱い procfs 保護、`nsenter` のような namespace エントリーツールと組み合わさると攻撃者にとって劇的に有用になります。従ってこのトピックを文書化する正しい方法は、各ページで同じ攻撃を繰り返すのではなく、最終的な境界に対して各レイヤーが何を寄与しているかを説明することです。

## このセクションの読み方

このセクションは最も一般的な概念から最も具体的なものへと構成されています。

まず runtime とエコシステムの概観から始めてください：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

次に、攻撃者がそもそもカーネルエスケープを必要とするかどうかを頻繁に決めるコントロールプレーンやサプライチェーンの表面を確認します：

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

そして保護モデルに進んでください：

{{#ref}}
protections/
{{#endref}}

namespace に関するページはカーネルの隔離プリミティブを個別に説明します：

{{#ref}}
protections/namespaces/
{{#endref}}

cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths、および読み取り専用システムパスに関するページは、通常 namespace の上に重ねられるメカニズムを説明します：

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

## 最初の有用な列挙マインドセット

コンテナ化されたターゲットを評価するときは、有名な脱出 PoC にすぐ飛びつくよりも、少数の正確な技術的質問をする方がずっと有用です。まず **スタック** を特定します：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer、あるいはもっと特殊なものか。次に **runtime** を特定します：`runc`、`crun`、`runsc`、`kata-runtime`、あるいは別の OCI 互換実装。さらに、その環境が rootful か rootless か、user namespaces が有効か、どの host namespaces が共有されているか、残っている capabilities は何か、seccomp が有効か、MAC ポリシーが実際に強制されているか、危険なマウントやソケットが存在するか、プロセスがコンテナ runtime API と対話できるかを確認します。

これらの答えは、ベースイメージ名が何であるかよりも実際のセキュリティ姿勢についてはるかに多くを教えてくれます。多くの評価において、最終的なコンテナ設定を理解するだけで、アプリケーションファイルを一つも読まずにどの脱出ファミリーが起こり得るかを予測できます。

## カバレッジ

このセクションはコンテナ指向の構成に下された古い Docker 中心の資料をカバーします：runtime と daemon の露出、authorization plugins、image 信頼と build secrets、敏感なホストマウント、distroless ワークロード、privileged containers、そしてコンテナ実行の周りに通常レイヤーされるカーネル保護などです。
