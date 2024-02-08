# PIDネームスペース

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でAWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)**。**
- **ハッキングトリックを共有するには、[**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 基本情報

PID（プロセス識別子）ネームスペースは、Linuxカーネルの機能であり、一群のプロセスが他のネームスペースのPIDとは独立した一意のPIDセットを持つことを可能にすることで、プロセスの分離を提供します。これは、プロセスの分離がセキュリティとリソース管理に不可欠なコンテナ化に特に役立ちます。

新しいPIDネームスペースが作成されると、そのネームスペース内の最初のプロセスにはPID 1が割り当てられます。このプロセスは新しいネームスペースの「init」プロセスとなり、そのネームスペース内の他のプロセスを管理する責任があります。ネームスペース内で作成される各後続プロセスは、そのネームスペース内で一意のPIDを持ち、これらのPIDは他のネームスペースのPIDとは独立しています。

PIDネームスペース内のプロセスの視点からは、同じネームスペース内の他のプロセスしか見ることができません。他のネームスペース内のプロセスには気づかず、従来のプロセス管理ツール（例：`kill`、`wait`など）を使用してそれらとやり取りすることはできません。これにより、プロセスが互いに干渉するのを防ぐ一定の分離レベルが提供されます。

### 動作原理：

1. 新しいプロセスが作成されると（たとえば、`clone()`システムコールを使用して）、そのプロセスは新しいまたは既存のPIDネームスペースに割り当てることができます。**新しいネームスペースが作成されると、そのプロセスはそのネームスペースの「init」プロセスとなります**。
2. **カーネル**は、新しいネームスペース内のPIDと親ネームスペース（つまり、新しいネームスペースが作成されたネームスペース）内の対応するPIDとの**マッピングを維持**します。このマッピングにより、異なるネームスペース内のプロセス間でシグナルを送信する必要がある場合など、**カーネルがPIDを変換できるようになります**。
3. **PIDネームスペース内のプロセスは、同じネームスペース内の他のプロセスしか見ることができず、それらとやり取りすることができます**。他のネームスペース内のプロセスには気づかず、そのPIDはネームスペース内で一意です。
4. **PIDネームスペースが破棄されると**（たとえば、ネームスペースの「init」プロセスが終了すると）、**そのネームスペース内のすべてのプロセスが終了**します。これにより、ネームスペースに関連するすべてのリソースが適切にクリーンアップされます。

## Lab:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に概説されています:

1. **問題の説明**:
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1により、名前空間のクリーンアップがトリガーされます。その後、Linuxカーネルはその名前空間でのPID割り当てを無効にします。

2. **結果**:
- 新しい名前空間内のPID 1の終了により、`PIDNS_HASH_ADDING`フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てられなくなり、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- `unshare`に`-f`オプションを使用することで問題を解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間でPID 1になります。その後、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作するようになります。

</details>

`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報の正確で隔離されたビューを持つことが保証されます。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;あなたのプロセスがどの名前空間にあるかを確認します
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### すべてのPIDネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

ルートユーザーは初期（デフォルト）のPIDネームスペースからすべてのプロセスを見ることができます。新しいPIDネームスペース内のプロセスも見ることができるため、すべてのPIDネームスペースを見ることができます。

### PIDネームスペースに入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
PIDネームスペースからデフォルトのネームスペースに入ると、すべてのプロセスを見ることができます。そして、そのPIDネームスペースからのプロセスは、PIDネームスペース上の新しいbashを見ることができます。

また、**rootユーザーでないと**、**他のプロセスのPIDネームスペースに入ることはできません**。そして、（`/proc/self/ns/pid`のような）それを指す記述子なしには、**他のネームスペースに入ることはできません**。

## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>でゼロからヒーローまでAWSハッキングを学びましょう！</summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で私を**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、あなたのハッキングトリックを共有してください。

</details>
