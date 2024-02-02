# IPC Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

IPC（Inter-Process Communication）ネームスペースは、Linuxカーネルの機能で、メッセージキュー、共有メモリセグメント、セマフォなどのSystem V IPCオブジェクトの**分離**を提供します。この分離により、**異なるIPCネームスペースのプロセスは、お互いのIPCオブジェクトに直接アクセスしたり、変更したりすることができなくなり**、プロセスグループ間のセキュリティとプライバシーの追加層を提供します。

### 動作方法:

1. 新しいIPCネームスペースが作成されると、**完全に分離されたSystem V IPCオブジェクトのセット**から始まります。これは、新しいIPCネームスペースで実行されているプロセスは、デフォルトでは他のネームスペースやホストシステムのIPCオブジェクトにアクセスしたり干渉したりできないことを意味します。
2. ネームスペース内で作成されたIPCオブジェクトは、そのネームスペース内のプロセスにのみ見え、**アクセス可能です**。各IPCオブジェクトは、そのネームスペース内で一意のキーによって識別されます。キーは異なるネームスペースで同一である可能性がありますが、オブジェクト自体は分離されており、ネームスペースを越えてアクセスすることはできません。
3. プロセスは、`setns()`システムコールを使用してネームスペース間を移動したり、`CLONE_NEWIPC`フラグを使用して`unshare()`または`clone()`システムコールで新しいネームスペースを作成したりできます。プロセスが新しいネームスペースに移動するか、新しいものを作成すると、そのネームスペースに関連付けられたIPCオブジェクトを使用し始めます。

## 実験室:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して新しい `/proc` ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間が**その名前空間に特有のプロセス情報の正確で隔離されたビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

前述の行を `-f` なしで実行すると、そのエラーが発生します。\
このエラーは、新しい名前空間で PID 1 のプロセスが終了することによって引き起こされます。

bashが実行を開始した後、bashはいくつかの新しいサブプロセスをフォークして何かを行います。`unshare` を `-f` なしで実行すると、bashは現在の "unshare" プロセスと同じ pid を持つことになります。現在の "unshare" プロセスは unshare システムコールを呼び出し、新しい pid 名前空間を作成しますが、現在の "unshare" プロセスは新しい pid 名前空間には含まれません。これは Linux カーネルの望ましい動作です：プロセス A が新しい名前空間を作成すると、プロセス A 自体は新しい名前空間には入れられず、プロセス A のサブプロセスのみが新しい名前空間に入れられます。したがって、次のように実行するとき：
```
unshare -p /bin/bash
```
unshareプロセスは`/bin/bash`を実行し、`/bin/bash`はいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しいネームスペースのPID 1になり、サブプロセスはその仕事を完了した後に終了します。したがって、新しいネームスペースのPID 1が終了します。

PID 1プロセスには特別な機能があります：それはすべての孤児プロセスの親プロセスになるべきです。ルートネームスペースのPID 1プロセスが終了すると、カーネルはパニックになります。サブネームスペースのPID 1プロセスが終了すると、Linuxカーネルは`disable_pid_allocation`関数を呼び出し、そのネームスペースで`PIDNS_HASH_ADDING`フラグをクリーンします。Linuxカーネルが新しいプロセスを作成するとき、カーネルは`alloc_pid`関数を呼び出してネームスペース内でPIDを割り当てますが、`PIDNS_HASH_ADDING`フラグが設定されていない場合、`alloc_pid`関数は-ENOMEMエラーを返します。それが「Cannot allocate memory」エラーの原因です。

この問題は'-f'オプションを使用して解決できます：
```
unshare -fp /bin/bash
```
</details>

#### Docker

Dockerを使用すると、IPCネームスペースを簡単に扱うことができます。Dockerコンテナはデフォルトで独自のIPCネームスペースを持っています。これにより、ホストOSとは独立したプロセス間通信が可能になります。しかし、`--ipc`フラグを使用することで、コンテナがホストのIPCネームスペースまたは他のコンテナのIPCネームスペースを使用するように設定することもできます。

コンテナがホストのIPCネームスペースを共有する場合、プロセス間通信に関連する脆弱性がホストに影響を与える可能性があります。また、悪意のあるコンテナが他のコンテナのIPCリソースにアクセスし、情報漏洩を引き起こすリスクもあります。

DockerコンテナでのIPCネームスペースの使用を適切に管理することは、システムのセキュリティを強化する上で重要です。
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどのネームスペースにあるかを確認する
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### すべてのIPCネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### IPCネームスペース内に入る
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指すディスクリプタ（`/proc/self/ns/net`のような）**がなければ**、他のネームスペースに**入ることはできません**。

### IPCオブジェクトの作成
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
