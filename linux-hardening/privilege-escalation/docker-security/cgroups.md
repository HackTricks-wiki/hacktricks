# CGroups

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 基本情報

**Linuxコントロールグループ**、またはcgroupsは、プロセスの集合に対して**システムリソース**を**制限**、管理、優先順位付けすることを可能にするLinuxカーネルの機能です。Cgroupsは、システム内のプロセスグループのリソース使用量（CPU、メモリ、ディスクI/O、ネットワークなど）を**管理し分離する**方法を提供します。これは、特定のプロセスグループに利用可能なリソースを制限したり、特定の種類のワークロードを他から分離したり、異なるプロセスグループ間でシステムリソースの使用を優先順位付けするなど、多くの目的に役立ちます。

cgroupsには**バージョン1と2**があり、両方が現在使用されており、システム上で同時に設定することができます。cgroupsバージョン1と**バージョン2**の間の最も**顕著な違い**は、後者がcgroupsの新しい階層的な組織を導入したことであり、グループを親子関係を持つ**ツリー構造**で配置することができます。これにより、異なるプロセスグループ間でリソースの割り当てをより柔軟かつ細かく制御することが可能になります。

新しい階層的な組織に加えて、cgroupsバージョン2は**新しいリソースコントローラー**のサポート、レガシーアプリケーションのより良いサポート、パフォーマンスの向上など、**いくつかの他の変更と改善**も導入しました。

全体として、cgroupsの**バージョン2はバージョン1よりも多くの機能と優れたパフォーマンスを提供します**が、古いシステムとの互換性が懸念される特定のシナリオでは、バージョン1が引き続き使用される場合があります。

/proc/\<pid>のcgroupファイルを見ることで、任意のプロセスのv1とv2のcgroupsをリストすることができます。次のコマンドでシェルのcgroupsを見てみることから始めることができます：
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
システムによっては**出力がかなり短い**場合がありますが、これはおそらく**cgroups v2のみを持っている**ことを意味します。ここにある各行の出力は数字で始まり、異なるcgroupです。それを読むためのポインターは以下の通りです：

* **数字の2～12はcgroups v1用です**。それらの**コントローラー**は数字の隣にリストされています。
* **数字の1**も**バージョン1用**ですが、コントローラーはありません。このcgroupは**管理目的**のみのものです（この場合、systemdが設定しました）。
* 最後の行、**数字の0**は、**cgroups v2用**です。ここにはコントローラーが表示されていません。cgroups v1を持たないシステムでは、これが唯一の出力行になります。
* **名前は階層的で、ファイルパスの一部のように見えます**。この例では、いくつかのcgroupsが/user.sliceと名付けられ、他は/user.slice/user-1000.slice/session-2.scopeと名付けられているのがわかります。
* /testcgroupという名前は、cgroups v1では、プロセスのcgroupsが完全に独立していることを示すために作成されました。
* user.sliceの下にある**名前にsessionが含まれているもの**は、systemdによって割り当てられたログインセッションです。シェルのcgroupsを見ているときにそれらを見るでしょう。**システムサービス**の**cgroups**は**system.sliceの下にあります**。

### cgroupsの表示

Cgroupsは通常、**ファイルシステムを通じてアクセスされます**。これは、カーネルと対話するための従来のUnixシステムコールインターフェースとは対照的です。\
シェルのcgroup設定を探るには、`/proc/self/cgroup`ファイルを見てシェルのcgroupを見つけ、次に`/sys/fs/cgroup`（または`/sys/fs/cgroup/unified`）ディレクトリに移動し、**cgroupと同じ名前のディレクトリ**を探します。このディレクトリに移動して周りを見ることで、cgroupの**さまざまな設定とリソース使用情報**を見ることができます。

<figure><img src="../../../.gitbook/assets/image (10) (2) (2).png" alt=""><figcaption></figcaption></figure>

ここにある多くのファイルの中で、**主要なcgroupインターフェースファイルは`cgroup`で始まります**。`cgroup.procs`（catを使っても構いません）から始めてください。これはcgroup内のプロセスをリストします。同様のファイルである`cgroup.threads`にはスレッドも含まれています。

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

シェルに使用されるほとんどのcgroupsには、これらの二つのコントローラーがあり、**使用されるメモリの量**と**cgroup内のプロセスの総数**を制御できます。コントローラーと対話するには、**コントローラーのプレフィックスに一致するファイル**を探します。例えば、cgroup内で実行中のスレッドの数を見たい場合は、pids.currentを参照してください：

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

**maxという値は、このcgroupに特定の制限がないことを意味します**が、cgroupsは階層的であるため、サブディレクトリチェーンを下ったcgroupがそれを制限する可能性があります。

### cgroupsの操作と作成

プロセスをcgroupに入れるには、**rootとしてその`cgroup.procs`ファイルにPIDを書き込みます**：
```shell-session
# echo pid > cgroup.procs
```
```markdown
これがcgroupsの変更がどのように機能するかの一例です。例えば、**cgroupの最大PID数を制限したい**場合（例えば、3,000 PIDsに）、以下のように行います：
```
```shell-session
# echo 3000 > pids.max
```
**cgroupsの作成はもっと複雑です**。技術的には、cgroupツリーのどこかにサブディレクトリを作成するのと同じくらい簡単です。そうすると、カーネルが自動的にインターフェースファイルを作成します。プロセスがないcgroupは、インターフェースファイルが存在してもrmdirでcgroupを削除できます。しかし、cgroupsを取り巻く規則には注意が必要です。これには以下のようなものがあります：

* **プロセスは外側のレベル（「葉」）のcgroupsにのみ配置できます**。例えば、/my-cgroupと/my-cgroup/my-subgroupというcgroupsがある場合、/my-cgroupにはプロセスを配置できませんが、/my-cgroup/my-subgroupは大丈夫です。（例外は、cgroupsにコントローラーがない場合ですが、詳しくは触れません。）
* cgroupは、**親cgroupにないコントローラーを持つことはできません**。
* 子cgroupsには明示的に**コントローラーを指定する必要があります**。これは`cgroup.subtree_control`ファイルを通じて行います。例えば、子cgroupにcpuとpidsコントローラーを持たせたい場合、このファイルに+cpu +pidsと書き込みます。

これらの規則の例外は、階層の最下部にある**ルートcgroup**です。このcgroupには**プロセスを配置できます**。これを行いたい理由の一つは、プロセスをsystemdの制御から切り離すことです。

コントローラーが有効になっていなくても、cgroupのcpu.statファイルを見ることでCPU使用状況を確認できます：

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

これはcgroupの全生涯にわたる累積CPU使用量であるため、多くのサブプロセスを生成して最終的に終了するサービスがプロセッサ時間をどのように消費しているかを確認できます。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* **HackTricks**の[**githubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
