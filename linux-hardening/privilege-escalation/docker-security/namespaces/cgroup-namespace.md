# CGroup Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

cgroup namespaceは、Linuxカーネルの機能で、名前空間内で実行されているプロセスのcgroup階層の**分離を提供します**。cgroups（**control groups**の略）は、プロセスを階層的なグループに編成し、CPU、メモリ、I/Oなどの**システムリソースの制限を管理および強制する**ためのカーネル機能です。

cgroup namespaceは、以前に議論した他の名前空間タイプ（PID、マウント、ネットワークなど）とは別の名前空間タイプではありませんが、名前空間の分離の概念に関連しています。**cgroup namespaceはcgroup階層のビューを仮想化します**。つまり、cgroup namespace内で実行されているプロセスは、ホストまたは他の名前空間で実行されているプロセスとは異なる階層のビューを持ちます。

### 動作方法:

1. 新しいcgroup namespaceが作成されると、**作成プロセスのcgroupに基づいたcgroup階層のビューから始まります**。これは、新しいcgroup namespaceで実行されているプロセスは、作成プロセスのcgroupを根とするcgroupサブツリーに限定されたcgroup階層のサブセットのみを見ることを意味します。
2. cgroup namespace内のプロセスは、**自分たちのcgroupを階層のルートとして見ます**。つまり、名前空間内のプロセスの視点からは、自分たちのcgroupがルートとして現れ、自分たちのサブツリー外のcgroupを見たりアクセスしたりすることはできません。
3. cgroup namespaceはリソースの分離を直接提供するものではありません。**それらはcgroup階層ビューの分離のみを提供します**。**リソースの制御と分離は、依然としてcgroup**サブシステム（例：cpu、メモリなど）自体によって強制されます。

CGroupsについての詳細はこちらをご覧ください:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して `/proc` ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

上記の行を `-f` なしで実行すると、そのエラーが発生します。\
エラーは新しい名前空間で PID 1 のプロセスが終了することによって引き起こされます。

bashが実行を開始した後、bashはいくつかの新しいサブプロセスをフォークして何かを行います。`unshare` を `-f` なしで実行すると、bashは現在の "unshare" プロセスと同じ pid を持つことになります。現在の "unshare" プロセスは unshare システムコールを呼び出し、新しい pid 名前空間を作成しますが、現在の "unshare" プロセスは新しい pid 名前空間には含まれません。これは Linux カーネルの望ましい動作です：プロセス A が新しい名前空間を作成すると、プロセス A 自体は新しい名前空間には入れられず、プロセス A のサブプロセスのみが新しい名前空間に入れられます。したがって、次のように実行すると：
```
unshare -p /bin/bash
```
unshareプロセスは`/bin/bash`を実行し、`/bin/bash`はいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しいネームスペースのPID 1になり、サブプロセスはその仕事を完了した後に終了します。そのため、新しいネームスペースのPID 1が終了します。

PID 1プロセスには特別な機能があります：それはすべての孤児プロセスの親プロセスになるべきです。ルートネームスペースのPID 1プロセスが終了すると、カーネルはパニックになります。サブネームスペースのPID 1プロセスが終了すると、Linuxカーネルは`disable_pid_allocation`関数を呼び出し、そのネームスペースで`PIDNS_HASH_ADDING`フラグをクリーンします。Linuxカーネルが新しいプロセスを作成するとき、カーネルは`alloc_pid`関数を呼び出してネームスペース内でPIDを割り当てますが、`PIDNS_HASH_ADDING`フラグが設定されていない場合、`alloc_pid`関数は-ENOMEMエラーを返します。そのため、「Cannot allocate memory」というエラーが発生します。

この問題は`-f`オプションを使用して解決できます：
```
unshare -fp /bin/bash
```
</details>

#### Docker

`unshare` を `-f` オプションで実行すると、新しい pid ネームスペースを作成した後に新しいプロセスをフォークします。そして新しいプロセスで `/bin/bash` を実行します。新しいプロセスは新しい pid ネームスペースの pid 1 になります。その後、bash はいくつかのサブプロセスをフォークして作業を行います。bash 自体が新しい pid ネームスペースの pid 1 であるため、そのサブプロセスは問題なく終了できます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory) からコピーしました
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどのネームスペースにあるかを確認する
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### CGroup 名前空間をすべて見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### CGroup 名前空間に入る
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
他のプロセスのネームスペースに**入るにはrootである必要があります**。また、(`/proc/self/ns/cgroup`のような)それを指すディスクリプタ**なしに**他のネームスペースに**入ることはできません**。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
