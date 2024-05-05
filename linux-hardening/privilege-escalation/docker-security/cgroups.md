# CGroups

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**または **HackTricks をPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)をフォローする。
* **ハッキングトリックを共有するために、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **のGitHubリポジトリに提出してください。**

</details>

## 基本情報

**Linux Control Groups**、または **cgroups** は、Linuxカーネルの機能であり、CPU、メモリ、およびディスクI/Oなどのシステムリソースの割り当て、制限、および優先順位付けをプロセスグループ間で可能にするものです。これらは、プロセスコレクションのリソース使用量を**管理および分離**するメカニズムを提供し、リソース制限、ワークロードの分離、および異なるプロセスグループ間でのリソースの優先順位付けなどの目的に役立ちます。

**cgroupsには2つのバージョン**があります：バージョン1とバージョン2。両方をシステムで同時に使用できます。主な違いは、**cgroupsバージョン2**が**階層的なツリー構造**を導入し、プロセスグループ間でより微妙で詳細なリソース分配を可能にする点です。さらに、バージョン2には、次のようなさまざまな改善点が含まれます：

新しい階層的な組織に加えて、cgroupsバージョン2には、**新しいリソースコントローラ**のサポート、レガシーアプリケーションのサポート向上、およびパフォーマンスの向上など、**その他の変更と改善**が導入されました。

全体として、cgroups **バージョン2は、バージョン1よりも多くの機能と優れたパフォーマンス**を提供しますが、後者は、古いシステムとの互換性が懸念される場合には引き続き使用される可能性があります。

任意のプロセスのv1およびv2 cgroupsをリストするには、そのcgroupファイルを /proc/\<pid> で見ることで行うことができます。次のコマンドで、シェルのcgroupsを確認できます：
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
### cgroupsの表示

ファイルシステムは通常、**cgroups**にアクセスするために使用され、従来はカーネルとのやり取りに使用されていたUnixシステムコールインターフェースから逸脱しています。シェルのcgroup構成を調査するには、**/proc/self/cgroup**ファイルを調べる必要があります。これにより、シェルのcgroupが明らかになります。次に、**/sys/fs/cgroup**（または**`/sys/fs/cgroup/unified`**）ディレクトリに移動し、cgroupの名前を共有するディレクトリを見つけることで、cgroupに関連するさまざまな設定やリソース使用情報を観察できます。

![Cgroup Filesystem](<../../../.gitbook/assets/image (1128).png>)

cgroupsの主要なインターフェースファイルは**cgroup**で接頭辞が付けられています。標準のcatなどのコマンドで表示できる**cgroup.procs**ファイルには、cgroup内のプロセスがリストされています。別のファイルである**cgroup.threads**にはスレッド情報が含まれています。

![Cgroup Procs](<../../../.gitbook/assets/image (281).png>)

シェルを管理するcgroupsには通常、メモリ使用量とプロセス数を規制する2つのコントローラが含まれています。コントローラとやり取りするには、コントローラの接頭辞を持つファイルを参照する必要があります。たとえば、**pids.current**は、cgroup内のスレッド数を確認するために参照されます。

![Cgroup Memory](<../../../.gitbook/assets/image (677).png>)

値に**max**が示されている場合、そのcgroupに特定の制限がないことを示します。ただし、cgroupsの階層構造のため、ディレクトリ階層の下位レベルのcgroupによって制限が課される場合があります。

### cgroupsの操作と作成

プロセスは、**そのプロセスのプロセスID（PID）を`cgroup.procs`ファイルに書き込むこと**でcgroupsに割り当てられます。これにはroot権限が必要です。たとえば、プロセスを追加するには：
```bash
echo [pid] > cgroup.procs
```
同様に、**PID制限を設定するなど、cgroup属性を変更**するには、関連するファイルに希望する値を書き込むことで行われます。cgroupに最大3,000個のPIDを設定するには：
```bash
echo 3000 > pids.max
```
**新しいcgroupsを作成する**には、cgroup階層内で新しいサブディレクトリを作成する必要があります。これにより、カーネルが自動的に必要なインターフェースファイルを生成します。アクティブなプロセスがないcgroupsは`rmdir`で削除できますが、次の制約に注意してください：

- **プロセスはリーフcgroupsにのみ配置できます**（つまり、階層内で最も入れ子になっているもの）。
- **親に存在しないコントローラを持つcgroupはできません**。
- **子cgroupsのコントローラは、`cgroup.subtree_control`ファイルで明示的に宣言する必要があります**。たとえば、子cgroupでCPUおよびPIDコントローラを有効にするには：
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
**ルートcgroup**はこれらのルールの例外であり、直接プロセス配置を許可します。これを使用して、プロセスをsystemdの管理から削除することができます。

cgroup内での**CPU使用率の監視**は、`cpu.stat`ファイルを介して可能であり、消費された合計CPU時間を表示し、サービスのサブプロセス全体での使用状況を追跡するのに役立ちます:

<figure><img src="../../../.gitbook/assets/image (908).png" alt=""><figcaption><p>cpu.statファイルに表示されるCPU使用率統計</p></figcaption></figure>

## 参考文献

* **書籍: How Linux Works, 3rd Edition: What Every Superuser Should Know By Brian Ward**
