# IPC Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

IPC（Inter-Process Communication）ネームスペースは、Linuxカーネルの機能で、メッセージキュー、共有メモリセグメント、セマフォなどのSystem V IPCオブジェクトの**分離**を提供します。この分離により、**異なるIPCネームスペースのプロセスは、互いのIPCオブジェクトに直接アクセスしたり、変更したりすることができません**。これにより、プロセスグループ間のセキュリティとプライバシーの追加層が提供されます。

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
`/proc` ファイルシステムの新しいインスタンスをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間が**その名前空間に特有のプロセス情報の正確で隔離されたビューを持つ**ことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しい PID (プロセス ID) 名前空間を扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです:

1. **問題の説明**:
- Linuxカーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤立したプロセスを引き継ぐ特別な役割を持っているため、Linuxカーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:
- 新しい名前空間での PID 1 の終了は、`PIDNS_HASH_ADDING` フラグのクリーニングにつながります。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることができず、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` と `-f` オプションを使用することで解決できます。このオプションは、新しい PID 名前空間を作成した後に `unshare` が新しいプロセスをフォークするようにします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。`/bin/bash` とその子プロセスは、この新しい名前空間内で安全に保持され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく操作できるようになります。

</details>

#### Docker
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
また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指し示すディスクリプタ（`/proc/self/ns/net`のような）**がなければ**、他のネームスペースに**入ることはできません**。

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
# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキング</strong>をゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
