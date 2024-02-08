# IPC Namespace

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するために、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 基本情報

IPC（Inter-Process Communication）名前空間は、Linuxカーネルの機能であり、メッセージキュー、共有メモリセグメント、セマフォなどのSystem V IPCオブジェクトを**隔離**する機能を提供します。この隔離により、**異なるIPC名前空間内のプロセスはお互いのIPCオブジェクトに直接アクセスしたり変更したりすることができません**。これにより、プロセスグループ間にセキュリティとプライバシーの追加のレイヤーが提供されます。

### 動作方法：

1. 新しいIPC名前空間が作成されると、**完全に隔離されたSystem V IPCオブジェクトのセット**で開始されます。これは、新しいIPC名前空間で実行されるプロセスが、デフォルトで他の名前空間やホストシステムのIPCオブジェクトにアクセスしたり干渉したりすることができないことを意味します。
2. 名前空間内で作成されたIPCオブジェクトは、**その名前空間内のプロセスだけが見え、アクセスできます**。各IPCオブジェクトは、その名前空間内で一意のキーで識別されます。キーは異なる名前空間で同一である場合がありますが、オブジェクト自体は隔離され、名前空間を超えてアクセスすることはできません。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを`CLONE_NEWIPC`フラグとともに使用して新しい名前空間を作成したりすることができます。プロセスが新しい名前空間に移動したり、新しい名前空間を作成したりすると、その名前空間に関連付けられたIPCオブジェクトを使用し始めます。

## Lab:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
マウントオプション`--mount-proc`を使用して新しい`/proc`ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に概説されています:

1. **問題の説明**:
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1が、その名前空間内でPIDの割り当てを無効にします。

2. **結果**:
- 新しい名前空間内のPID 1の終了により、`PIDNS_HASH_ADDING`フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てられなくなり、「Cannot allocate memory」エラーが発生します。

3. **解決策**:
- `unshare`に`-f`オプションを使用することで問題を解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間でPID 1になります。その後、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作するようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;あなたのプロセスがどの名前空間にあるかを確認します
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### すべてのIPC名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### IPCネームスペースに入る

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
### IPCオブジェクトの作成

別のプロセスの名前空間に入ることは、ルート権限でのみ可能です。また、他の名前空間に入るには、それを指すディスクリプタ（例：`/proc/self/ns/net`）がないとできません。
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
## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)



<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
