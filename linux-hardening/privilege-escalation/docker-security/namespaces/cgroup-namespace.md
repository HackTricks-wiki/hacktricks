# CGroup Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 基本情報

cgroup namespaceは、Linuxカーネルの機能であり、名前空間内で実行されているプロセスのcgroup階層の**分離を提供します**。cgroups（**control groups**の略）は、CPU、メモリ、I/Oなどのシステムリソースに**制限を管理および適用する**ために、プロセスを階層的なグループに編成するカーネル機能です。

cgroup namespaceは、以前に議論した他の名前空間タイプ（PID、マウント、ネットワークなど）とは別の名前空間タイプではありませんが、名前空間の分離の概念に関連しています。**cgroup namespaceはcgroup階層のビューを仮想化します**。そのため、cgroup namespace内で実行されているプロセスは、ホストまたは他の名前空間で実行されているプロセスとは異なる階層のビューを持ちます。

### 動作方法:

1. 新しいcgroup namespaceが作成されると、**作成プロセスのcgroupに基づいたcgroup階層のビューから始まります**。これは、新しいcgroup namespaceで実行されているプロセスは、作成プロセスのcgroupを根とするcgroupサブツリーに限定されたcgroup階層のサブセットのみを見ることを意味します。
2. cgroup namespace内のプロセスは、**自分たちのcgroupを階層のルートとして見ます**。つまり、名前空間内のプロセスの視点からは、自分たちのcgroupがルートとして現れ、自分たちのサブツリー外のcgroupを見たりアクセスしたりすることはできません。
3. cgroup namespaceはリソースの分離を直接提供するものではありません。**それらはcgroup階層ビューの分離のみを提供します**。**リソースの制御と分離は、依然としてcgroup**サブシステム（例：cpu、メモリなど）自体によって強制されます。

CGroupsについての詳細はこちらをチェックしてください:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して新しい `/proc` ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しい PID (プロセス ID) 名前空間を扱う方法によりエラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可します。しかし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤立したプロセスを引き受ける特別な役割を持っているため、Linuxカーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:
- 新しい名前空間での PID 1 の終了は `PIDNS_HASH_ADDING` フラグのクリーニングにつながります。これにより `alloc_pid` 関数が新しいプロセスを作成する際に新しい PID を割り当てることができず、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は `unshare` に `-f` オプションを使用することで解決できます。このオプションは `unshare` が新しい PID 名前空間を作成した後に新しいプロセスをフォークするようにします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく操作できるようになります。

</details>

#### Docker
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
```
また、**rootである場合に限り、他のプロセスのネームスペースに入ることができます**。そして、(`/proc/self/ns/cgroup`のような)それを指すディスクリプタ**なしに**他のネームスペースに**入ることはできません**。
```

# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
