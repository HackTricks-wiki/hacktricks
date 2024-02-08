# UTS Namespace

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをご覧ください
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 基本情報

UTS（UNIX Time-Sharing System）名前空間は、Linuxカーネルの機能であり、**2つのシステム識別子**、つまり**ホスト名**と**NIS**（Network Information Service）ドメイン名を**分離**します。この分離により、各UTS名前空間は**独自のホスト名とNISドメイン名**を持つことができ、特に各コンテナが独自のホスト名を持つ別々のシステムとして表示されるコンテナ化シナリオで便利です。

### 動作方法：

1. 新しいUTS名前空間が作成されると、**親名前空間からホスト名とNISドメイン名のコピー**で開始されます。つまり、作成時に新しい名前空間は**親と同じ識別子を共有**します。ただし、名前空間内でホスト名またはNISドメイン名を変更しても、他の名前空間には影響しません。
2. UTS名前空間内のプロセスは、それぞれ`sethostname()`および`setdomainname()`システムコールを使用して、**ホスト名とNISドメイン名を変更**できます。これらの変更は名前空間内でのみ有効であり、他の名前空間やホストシステムには影響しません。
3. プロセスは`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを`CLONE_NEWUTS`フラグとともに使用して新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたホスト名とNISドメイン名が使用されます。

## Lab:

### 異なる名前空間を作成

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
マウントパラメータ`--mount-proc`を使用して新しい`/proc`ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に対して正確で隔離されたビューを持つことが保証されます。

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に示されています:

1. **問題の説明**:
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1により、その名前空間のクリーンアップがトリガーされます。その後、Linuxカーネルはその名前空間でのPID割り当てを無効にします。

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
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### すべてのUTSネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTSネームスペース内に入る

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと**、**他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に入るには、それを指す**記述子**（例：`/proc/self/ns/uts`）がないと**入ることができません**。

### ホスト名の変更
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com) を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)** に参加するか、[telegramグループ](https://t.me/peass) に参加するか、**Twitter** 🐦 で私をフォローする **@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **ハッキングテクニックを共有するために、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>
