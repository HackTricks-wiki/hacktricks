# CGroup Namespace

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングトリックを共有するには、PRを** [**HackTricks**](https://github.com/carlospolop/hacktricks) **および** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **githubリポジトリに提出してください。**

</details>

## 基本情報

CGroup Namespaceは、**名前空間内で実行されるプロセスのためのcgroup階層の分離**を提供するLinuxカーネル機能です。**コントロールグループ**の略であるCgroupsは、プロセスを階層的グループに整理して、CPU、メモリ、I/Oなどの**システムリソースに制限を設ける**ためのカーネル機能です。

Cgroup名前空間は、PID、マウント、ネットワークなど他の名前空間タイプとは異なる独立した名前空間タイプではありませんが、名前空間分離の概念に関連しています。**Cgroup名前空間はcgroup階層のビューを仮想化**し、その結果、cgroup名前空間内で実行されるプロセスは、ホストまたは他の名前空間で実行されるプロセスと比較して、階層の異なるビューを持ちます。

### 動作方法：

1. 新しいcgroup名前空間が作成されると、**作成プロセスのcgroupに基づいたcgroup階層のビューで開始**されます。これは、新しいcgroup名前空間で実行されるプロセスが、作成プロセスのcgroupを根とするcgroupサブツリーに制限されたcgroup階層のサブセットのみを見ることを意味します。
2. cgroup名前空間内のプロセスは、**自分自身のcgroupを階層のルートとして見る**ことになります。つまり、名前空間内のプロセスの視点からは、自分自身のcgroupがルートとして表示され、自分自身のサブツリーの外側のcgroupを見たりアクセスしたりすることはできません。
3. Cgroup名前空間はリソースの分離を直接提供しません。**リソースの制御と分離は、cgroup**サブシステム（例：CPU、メモリなど）自体によって依然として強制されます。

CGroupsに関する詳細情報は次を参照してください：

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Lab:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して `/proc` ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に対して正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`unshare` を `-f` オプションなしで実行すると、Linux が新しい PID (プロセス ID) 名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に示されています:

1. **問題の説明**:
- Linux カーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスだけが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` が `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つ PID 1 により、その名前空間のクリーンアップがトリガーされます。その後、Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:
- 新しい名前空間内の PID 1 の終了により、`PIDNS_HASH_ADDING` フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てられなくなり、"Cannot allocate memory" エラーが発生します。

3. **解決策**:
- `unshare` に `-f` オプションを使用することで問題を解決できます。このオプションにより、`unshare` は新しい PID 名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。その後、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;あなたのプロセスがどの名前空間にあるかを確認します
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### すべてのCGroup名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### CGroupネームスペースに入る

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に**ディスクリプタ**が指すことなしには**入ることができません**（例：`/proc/self/ns/cgroup`）。

## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、**ハッキングトリックを共有**してください。

</details>
