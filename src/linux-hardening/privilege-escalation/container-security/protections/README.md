# コンテナ保護の概要

{{#include ../../../../banners/hacktricks-training.md}}

コンテナのハードニングで最も重要な考え方は、'container security' という単一の制御は存在しない、ということです。人々が container isolation と呼ぶものは、実際には複数の Linux セキュリティおよびリソース管理機構が協調して働いた結果です。文書がそれらのうちの一つだけを説明すると、読者はその有効性を過大評価しがちです。逆に、相互作用を説明せずにすべてを列挙すると、名前のカタログは得られても実際のモデルは得られません。このセクションはその両方の誤りを避けようとします。

モデルの中心にあるのは **namespaces** で、ワークロードが見えるものを分離します。namespaces はプロセスに対してファイルシステムのマウント、PIDs、ネットワーク、IPC オブジェクト、ホスト名、ユーザー/グループのマッピング、cgroup パス、いくつかのクロックなどの私的または部分的に私的なビューを与えます。しかし namespaces だけでプロセスに何が許可されるかが決まるわけではありません。ここで次の層が関与します。

**cgroups** はリソース使用を管理します。mount や PID namespaces と同じ意味での主たる分離境界ではありませんが、メモリ、CPU、PIDs、I/O、デバイスアクセスを制限するため運用上重要です。また、歴史的に writable cgroup 機能を悪用する breakout techniques があり、特に cgroup v1 環境でセキュリティ上の関連がありました。

**Capabilities** はかつての全能な root モデルをより小さな権限単位に分割します。これはコンテナで重要です。なぜなら多くのワークロードがコンテナ内でまだ UID 0 として実行されているからです。したがって問題は単に「プロセスは root か？」ではなく、「どの capabilities が、どの namespaces の内部で、どの seccomp や MAC 制限のもとで残っているか？」ということになります。だからこそ、あるコンテナ内の root プロセスは比較的制約されている一方で、別のコンテナ内の root プロセスは実際にはホストの root とほとんど区別がつかない場合があるのです。

**seccomp** は syscall をフィルタリングし、ワークロードに露出するカーネルの攻撃面を縮小します。これは `unshare`, `mount`, `keyctl` のような明らかに危険な呼び出しや、breakout chains で使われる他の syscall をブロックする仕組みであることが多いです。プロセスが本来なら操作を許す capability を持っていても、seccomp はカーネルが完全に処理する前に syscall 経路をブロックする可能性があります。

**AppArmor** と **SELinux** は通常のファイルシステムや権限チェックの上に Mandatory Access Control を追加します。これらは特に重要で、コンテナが本来より多くの capabilities を持っている場合でも意味を持ち続けます。ワークロードは理論上はある操作を試みる権限を持っていても、ラベルやプロファイルが該当するパス、オブジェクト、操作へのアクセスを禁止しているため実行できないことがあります。

最後に、注目されにくいが実際の攻撃で頻繁に重要となる追加のハードニング層があります: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, および慎重な runtime defaults。これらの仕組みは特に、攻撃者がコード実行をより広い権限獲得に変えようとする際の妥協の「最後の一歩」を止めることが多いです。

このフォルダの残りの部分では、これら各機構について、カーネルプリミティブが実際に何を行うか、ローカルでどう観察するか、一般的なランタイムがどう使っているか、オペレーターが誤って弱めてしまう典型例を含めて、詳しく説明します。

## 続きを読む

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
