# CGroups

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

**Linux Control Groups**、または**cgroups**は、CPU、メモリ、ディスクI/Oなどのシステムリソースをプロセスグループ間で割り当て、制限し、優先順位を付けることを可能にするLinuxカーネルの機能です。これは、リソース制限、ワークロードの分離、異なるプロセスグループ間のリソース優先順位付けなどの目的に役立つ、プロセスコレクションのリソース使用を**管理および分離する**ためのメカニズムを提供します。

**cgroupsには2つのバージョン**があります：バージョン1とバージョン2。両方はシステム上で同時に使用できます。主な違いは、**cgroupsバージョン2**が**階層的なツリー状の構造**を導入し、プロセスグループ間でのリソース配分をより微妙かつ詳細に行えるようにしていることです。さらに、バージョン2は、以下のようなさまざまな強化をもたらします。

新しい階層的な組織に加えて、cgroupsバージョン2は**新しいリソースコントローラーのサポート**、レガシーアプリケーションへのより良いサポート、パフォーマンスの向上など、**いくつかの他の変更と改善**も導入しました。

全体として、cgroups **バージョン2はバージョン1よりも多くの機能と優れたパフォーマンスを提供**しますが、後者は古いシステムとの互換性が懸念される特定のシナリオではまだ使用される可能性があります。

任意のプロセスのv1およびv2 cgroupsをリストするには、そのcgroupファイルを/proc/\<pid>で確認します。次のコマンドを使用して、シェルのcgroupsを確認することから始めることができます：
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
- **数字 2–12**: cgroups v1、各行は異なる cgroup を表します。これらのコントローラーは、数字の隣に指定されています。
- **数字 1**: これも cgroups v1 ですが、管理目的のみに使用され（例: systemd によって設定）、コントローラーはありません。
- **数字 0**: cgroups v2 を表します。コントローラーはリストされておらず、この行は cgroups v2 のみを実行しているシステムで独占的です。
- **名前は階層的**で、ファイルパスに似ており、異なる cgroup 間の構造と関係を示しています。
- **/user.slice や /system.slice** のような名前は cgroup の分類を指定し、user.slice は通常 systemd によって管理されるログインセッション用、system.slice はシステムサービス用です。

### cgroups の表示

ファイルシステムは通常、**cgroups** へのアクセスに利用され、カーネルとのインタラクションに伝統的に使用される Unix システムコールインターフェースとは異なります。シェルの cgroup 構成を調査するには、**/proc/self/cgroup** ファイルを確認し、シェルの cgroup を明らかにします。その後、**/sys/fs/cgroup**（または **`/sys/fs/cgroup/unified`**）ディレクトリに移動し、cgroup の名前を共有するディレクトリを見つけることで、cgroup に関連するさまざまな設定やリソース使用情報を観察できます。

![Cgroup Filesystem](<../../../images/image (1128).png>)

cgroups の主要なインターフェースファイルは **cgroup** で始まります。**cgroup.procs** ファイルは、cat などの標準コマンドで表示でき、cgroup 内のプロセスをリストします。別のファイル **cgroup.threads** にはスレッド情報が含まれています。

![Cgroup Procs](<../../../images/image (281).png>)

シェルを管理する cgroups は通常、メモリ使用量とプロセス数を制御する 2 つのコントローラーを含みます。コントローラーと対話するには、コントローラーのプレフィックスを持つファイルを参照する必要があります。たとえば、**pids.current** を参照して cgroup 内のスレッド数を確認します。

![Cgroup Memory](<../../../images/image (677).png>)

値に **max** が示されている場合、cgroup に特定の制限がないことを示唆しています。ただし、cgroups の階層的な性質により、ディレクトリ階層の下位レベルの cgroup によって制限が課される可能性があります。

### cgroups の操作と作成

プロセスは **`cgroup.procs` ファイルにそのプロセス ID (PID) を書き込むことによって cgroups に割り当てられます**。これには root 権限が必要です。たとえば、プロセスを追加するには:
```bash
echo [pid] > cgroup.procs
```
同様に、**cgroup属性を変更すること、例えばPID制限を設定すること**は、関連するファイルに希望の値を書き込むことで行われます。cgroupの最大3,000 PIDを設定するには:
```bash
echo 3000 > pids.max
```
**新しいcgroupsの作成**は、cgroup階層内に新しいサブディレクトリを作成することを含み、これによりカーネルは必要なインターフェースファイルを自動的に生成します。アクティブなプロセスのないcgroupsは`rmdir`で削除できますが、いくつかの制約に注意してください：

- **プロセスはリーフcgroupsにのみ配置できます**（つまり、階層内で最もネストされたもの）。
- **cgroupは親に存在しないコントローラーを持つことはできません**。
- **子cgroupsのコントローラーは`cgroup.subtree_control`ファイルで明示的に宣言する必要があります**。たとえば、子cgroupでCPUとPIDコントローラーを有効にするには：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**ルートcgroup**はこれらのルールの例外であり、プロセスを直接配置することを許可します。これを使用して、systemd管理からプロセスを削除することができます。

**cgroup内のCPU使用量の監視**は、`cpu.stat`ファイルを通じて可能で、消費された総CPU時間を表示し、サービスのサブプロセス全体の使用状況を追跡するのに役立ちます：

<figure><img src="../../../images/image (908).png" alt=""><figcaption><p>cpu.statファイルに表示されるCPU使用統計</p></figcaption></figure>

## 参考文献

- **書籍: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**

{{#include ../../../banners/hacktricks-training.md}}
