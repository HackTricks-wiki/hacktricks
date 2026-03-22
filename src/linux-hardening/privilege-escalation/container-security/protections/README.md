# Container 保護の概要

{{#include ../../../../banners/hacktricks-training.md}}

container のハードニングで最も重要な考え方は、「container security」と呼ばれる単一の制御は存在しないということです。人々が container isolation と呼ぶものは、実際にはいくつかの Linux セキュリティおよびリソース管理メカニズムが連携して働いた結果です。ドキュメントがそれらのうちの一つだけを説明していると、読者はその強度を過大評価しがちです。すべてを列挙してそれらの相互作用を説明していなければ、読者は名前のカタログを手に入れるだけで実際のモデルを得られません。本セクションではその両方の誤りを避けることを目指しています。

モデルの中心には **namespaces** があり、workload が見られるものを分離します。namespaces はプロセスに対してファイルシステムのマウント、PIDs、ネットワーキング、IPC オブジェクト、ホスト名、ユーザ/グループのマッピング、cgroup パス、および一部のクロックに対するプライベートまたは部分的にプライベートなビューを与えます。しかし namespaces だけでプロセスが何を許可されているかが決まるわけではありません。そこで次の層が登場します。

**cgroups** はリソース使用を統制します。mount や PID namespaces と同じ意味での分離境界では主にありませんが、メモリ、CPU、PIDs、I/O、およびデバイスアクセスを制限するため運用上は重要です。また、歴史的に breakout 手法が writable cgroup 機能を悪用したため（特に cgroup v1 環境で）、セキュリティ上の関連性もあります。

**Capabilities** は旧来の全能な root モデルをより小さな特権単位に分割します。多くの workload が依然として container 内で UID 0 として実行されているため、これは container にとって基本的な考え方です。したがって問題は単に「プロセスは root か？」ということではなく、「どの capabilities が、どの namespaces 内で、どの seccomp および MAC 制限のもとで残っているのか？」という点です。このため、ある container 内の root プロセスは比較的制約されている一方で、別の container の root プロセスは実際にはホスト root とほとんど区別がつかない場合があります。

**seccomp** は syscall をフィルタリングし、workload にさらされるカーネルの攻撃面を減らします。これはしばしば `unshare`、`mount`、`keyctl` のような明らかに危険な呼び出しや、breakout チェーンで使用されるその他の syscalls をブロックするメカニズムです。プロセスが本来その操作を許す capability を持っていても、seccomp はカーネルがそれを完全に処理する前に syscall 経路をブロックすることがあります。

**AppArmor** と **SELinux** は通常のファイルシステムと特権チェックの上に Mandatory Access Control を追加します。これらは特に重要で、container が本来より多くの capabilities を持っている場合でも影響を与え続けます。workload は理論上その操作を試みる特権を持っていても、ラベルやプロファイルが該当するパス、オブジェクト、または操作へのアクセスを禁止しているため実行を阻止されることがあります。

最後に、あまり注目されないが実際の攻撃でしばしば重要になる追加のハードニング層があります: `no_new_privs`、masked procfs paths、read-only system paths、read-only root filesystems、そして慎重な runtime defaults。これらのメカニズムは、特に攻撃者がコード実行をより広い権限獲得に転換しようとする際に、侵害の「最後の一里」を止めることがよくあります。

このフォルダの残りでは、これらの各メカニズムをより詳しく説明します。カーネルのプリミティブが実際に何をするのか、ローカルでどう観察するか、一般的な runtimes がどう使うか、そしてオペレータが誤ってどのように弱めてしまうかを含みます。

## 次に読む

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

多くの実際の escape は、ホストのどのコンテンツが workload にマウントされているかにも依存するため、コアな保護を読んだ後は次を続けて読むと有用です:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
