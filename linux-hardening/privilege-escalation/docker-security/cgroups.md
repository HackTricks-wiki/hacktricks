# CGroups

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

**Linuxコントロールグループ**、またはcgroupsは、Linuxカーネルの機能であり、**システムリソース**を制限、監視、優先順位付けするためのものです。cgroupsは、システム内のプロセスグループのリソース使用量（CPU、メモリ、ディスクI/O、ネットワークなど）を**管理および分離**する方法を提供します。これは、特定のプロセスグループに利用可能なリソースを制限したり、特定のワークロードを他のワークロードから分離したり、異なるプロセスグループ間でシステムリソースの使用を優先するために役立ちます。

cgroupsには、バージョン1と2の**2つのバージョン**があり、現在のところ両方が使用され、システム上で同時に設定できます。cgroupsバージョン1とバージョン2の**最も重要な違い**は、後者がcgroupsの新しい階層的な組織を導入したことです。これにより、グループを親子関係を持つ**ツリー構造**で配置することができます。これにより、異なるプロセスグループ間でリソースの割り当てをより柔軟かつ細かく制御することができます。

階層的な組織の導入に加えて、cgroupsバージョン2では、**その他の変更と改善**もいくつか導入されました。これには、新しいリソースコントローラのサポート、レガシーアプリケーションのサポートの向上、パフォーマンスの改善などが含まれます。

全体的に、cgroupsバージョン2はバージョン1よりも多機能でパフォーマンスも優れていますが、互換性のある古いシステムとの互換性が問題となる場合には、バージョン1が使用される場合もあります。

任意のプロセスのv1およびv2 cgroupsをリストするには、/proc/\<pid>のcgroupファイルを参照することで行うことができます。次のコマンドでシェルのcgroupsを確認できます。
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
システム上の出力がかなり短くなっている場合は心配しないでください。これはおそらくcgroups v2のみを持っていることを意味します。ここでの各行は数字で始まり、異なるcgroupです。以下は読み方のポイントです：

- 数字2から12はcgroups v1用です。それらのコントローラは数字の隣にリストされています。
- 数字1もバージョン1用ですが、コントローラはありません。このcgroupは管理目的のみです（この場合、systemdが設定しました）。
- 最後の行、数字0はcgroups v2用です。ここではコントローラは表示されません。cgroups v1を持たないシステムでは、これが唯一の出力行になります。
- 名前は階層的で、ファイルパスの一部のように見えます。この例では、いくつかのcgroupの名前は/user.sliceで、他のものは/user.slice/user-1000.slice/session-2.scopeです。
- /testcgroupという名前は、cgroups v1ではプロセスのcgroupsが完全に独立していることを示すために作成されました。
- sessionを含むuser.sliceの名前は、systemdによって割り当てられたログインセッションです。シェルのcgroupsを見ているときにそれらを見ることができます。システムサービスのcgroupsはsystem.sliceの下にあります。

### cgroupsの表示

通常、cgroupsは**ファイルシステムを介してアクセス**されます。これは、カーネルとの対話のための従来のUnixシステムコールインターフェースとは対照的です。\
シェルのcgroupのセットアップを探索するには、`/proc/self/cgroup`ファイルを見て、シェルのcgroupを見つけ、次に`/sys/fs/cgroup`（または`/sys/fs/cgroup/unified`）ディレクトリに移動し、cgroupと同じ名前のディレクトリを探します。このディレクトリに移動して周りを見ることで、cgroupのさまざまな設定とリソース使用情報を確認できます。

<figure><img src="../../../.gitbook/assets/image (10) (2).png" alt=""><figcaption></figcaption></figure>

ここにある多くのファイルの中で、**主要なcgroupインターフェースファイルは`cgroup`で始まります**。まず、`cgroup.procs`（catを使用しても問題ありません）を見て、cgroup内のプロセスのリストを確認します。同様のファイルである`cgroup.threads`にはスレッドも含まれます。

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

シェルに使用されるほとんどのcgroupには、これら2つのコントローラがあります。これらのコントローラは、使用するメモリの量とcgroup内のプロセスの総数を制御できます。コントローラと対応するファイルを操作するには、コントローラの接頭辞に一致するファイルを探します。たとえば、cgroup内で実行されているスレッドの数を確認したい場合は、pids.currentを参照します。

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

**maxの値は、このcgroupに特定の制限がないことを意味します**が、cgroupsは階層的であるため、サブディレクトリチェーンの下のcgroupが制限する可能性があります。

### cgroupsの操作と作成

プロセスをcgroupに入れるには、そのPIDをrootとして`cgroup.procs`ファイルに書き込みます：
```shell-session
# echo pid > cgroup.procs
```
これはcgroupsの変更方法です。例えば、cgroupの最大PID数を制限したい場合（例えば、3,000 PIDに制限する場合）、以下のように行います：
```shell-session
# echo 3000 > pids.max
```
**cgroupsの作成は少しトリッキーです**。技術的には、cgroupツリーのどこかにサブディレクトリを作成するだけで簡単です。そうすると、カーネルは自動的にインターフェースファイルを作成します。プロセスがない場合、インターフェースファイルが存在していてもrmdirでcgroupを削除することができます。cgroupsに関するルールがあるため、トラブルになることがあります。これには次のものが含まれます：

* プロセスは、**外部レベル（"leaf"）のcgroupにのみ配置できます**。たとえば、/my-cgroupと/my-cgroup/my-subgroupという名前のcgroupがある場合、プロセスを/my-cgroupに配置することはできませんが、/my-cgroup/my-subgroupには配置できます。（例外は、cgroupにコントローラがない場合ですが、詳しくは掘り下げません。）
* cgroupは、**親のcgroupに存在しないコントローラを持つことはできません**。
* 子のcgroupには、**明示的にコントローラを指定する必要があります**。これは、`cgroup.subtree_control`ファイルを介して行います。たとえば、子のcgroupにcpuとpidsコントローラを持たせたい場合は、このファイルに+cpu +pidsと書き込みます。

これらのルールの例外は、階層の一番下にある**ルートcgroup**です。このcgroupにプロセスを配置することができます。これを行う理由の1つは、プロセスをsystemdの制御から切り離すためです。

コントローラが有効になっていなくても、cgroupのCPU使用率はcpu.statファイルを見ることで確認できます：

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

これは、cgroupの生涯にわたる累積CPU使用率なので、多くのサブプロセスを生成して最終的に終了させるサービスがどれだけのプロセッサ時間を消費するかを確認できます。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見してください。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出してください。**

</details>
