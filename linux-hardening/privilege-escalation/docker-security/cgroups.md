# CGroups

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **と** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出する**

</details>

## 基本情報

**Linux Control Groups**、または **cgroups** は、Linuxカーネルの機能であり、CPU、メモリ、およびディスクI/Oなどのシステムリソースの割り当て、制限、および優先順位付けをプロセスグループ間で可能にします。これらは、プロセスコレクションのリソース使用量を**管理および分離**するメカニズムを提供し、リソース制限、ワークロードの分離、および異なるプロセスグループ間でのリソースの優先順位付けなどの目的に役立ちます。

**cgroupsには2つのバージョン**があります: バージョン1とバージョン2。両方をシステムで同時に使用できます。主な違いは、**cgroupsバージョン2**が**階層的なツリー構造**を導入し、プロセスグループ間でより微妙で詳細なリソース分配を可能にすることです。さらに、バージョン2には次のようなさまざまな改善点があります:

新しい階層的な組織に加えて、cgroupsバージョン2は、**新しいリソースコントローラ**のサポート、レガシーアプリケーションのより良いサポート、およびパフォーマンスの向上など、**その他の変更と改善**を導入しました。

全体として、cgroups **バージョン2は、バージョン1よりも多くの機能と優れたパフォーマンス**を提供しますが、後者は、古いシステムとの互換性が懸念される場合には引き続き使用される可能性があります。

任意のプロセスのv1およびv2 cgroupsをリストするには、そのプロセスのcgroupファイルを /proc/\<pid> で見ることができます。次のコマンドでシェルのcgroupsを確認できます:
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
- **Numbers 2–12**: cgroups v1、各行が異なるcgroupを表す。これらのコントローラは数字の隣に指定される。
- **Number 1**: cgroups v1でもありますが、管理目的のみ（例：systemdによって設定される）で、コントローラがありません。
- **Number 0**: cgroups v2を表します。コントローラはリストされず、この行はcgroups v2のみを実行しているシステムにのみ存在します。
- **名前は階層的**で、ファイルパスを模しており、異なるcgroup間の構造と関係を示しています。
- **/user.sliceや/system.slice**のような名前は、cgroupの分類を指定し、通常はsystemdによって管理されるログインセッション用のuser.sliceと、システムサービス用のsystem.sliceを示します。

### cgroupsの表示

通常、Unixシステムコールインターフェイスではなく、**cgroups**にアクセスするためにファイルシステムが使用されます。シェルのcgroup構成を調査するには、**/proc/self/cgroup**ファイルを調べる必要があります。これにより、シェルのcgroupが明らかになります。次に、**/sys/fs/cgroup**（または**`/sys/fs/cgroup/unified`**）ディレクトリに移動し、cgroupの名前を共有するディレクトリを見つけることで、cgroupに関連するさまざまな設定やリソース使用情報を観察できます。

![Cgroup Filesystem](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

cgroupsの主要なインターフェースファイルは**cgroup**で始まります。**cgroup.procs**ファイルは、catなどの標準コマンドで表示でき、cgroup内のプロセスがリストされます。別のファイルである**cgroup.threads**にはスレッド情報が含まれています。

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

シェルを管理するcgroupsには通常、メモリ使用量とプロセス数を規制する2つのコントローラが含まれています。コントローラとやり取りするには、コントローラの接頭辞を持つファイルを参照する必要があります。例えば、**pids.current**は、cgroup内のスレッド数を確認するために参照されます。

![Cgroup Memory](../../../.gitbook/assets/image%20(3)%20(5).png)

値に**max**が表示されている場合、その値はcgroupに特定の制限がないことを示します。ただし、cgroupsの階層構造のため、制限はディレクトリ階層の下位レベルのcgroupによって課せられる可能性があります。


### cgroupsの操作と作成

プロセスは、**そのプロセスID（PID）を`cgroup.procs`ファイルに書き込むこと**でcgroupsに割り当てられます。これにはroot権限が必要です。たとえば、プロセスを追加するには：
```bash
echo [pid] > cgroup.procs
```
同様に、**PID制限の設定など、cgroup属性の変更**は、関連するファイルに希望する値を書き込むことで行われます。cgroupに最大3,000個のPIDを設定するには：
```bash
echo 3000 > pids.max
```
**新しいcgroupsを作成する**には、cgroup階層内に新しいサブディレクトリを作成する必要があります。これにより、カーネルが必要なインターフェースファイルを自動的に生成します。`rmdir`を使用してプロセスがアクティブでないcgroupsを削除できますが、次の制約に注意してください：

- **プロセスは、葉cgroupsにのみ配置できます**（つまり、階層内で最も入れ子になっているもの）。
- **親に存在しないコントローラを持つcgroupは存在できません**。
- **子cgroupsのコントローラは、`cgroup.subtree_control`ファイルで明示的に宣言する必要があります**。たとえば、子cgroupでCPUおよびPIDコントローラを有効にするには：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**ルートcgroup**はこれらのルールの例外であり、直接プロセス配置を許可します。これは、プロセスをsystemdの管理から削除するために使用できます。

cgroup内での**CPU使用率の監視**は、`cpu.stat`ファイルを介して可能であり、消費された合計CPU時間を表示し、サービスのサブプロセス間での使用状況を追跡するのに役立ちます：

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>cpu.statファイルに表示されるCPU使用率統計</figcaption></figure>

## 参考文献
* **書籍: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**
