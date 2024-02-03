# PID Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 基本情報

PID（プロセスID）ネームスペースは、Linuxカーネルの機能であり、プロセスの分離を実現することにより、プロセスグループが独自の一意のPIDセットを持つことができ、他のネームスペースのPIDとは別になります。これは、セキュリティとリソース管理に不可欠なプロセスの分離が必要なコンテナ化において特に有用です。

新しいPIDネームスペースが作成されると、そのネームスペース内の最初のプロセスにPID 1が割り当てられます。このプロセスは新しいネームスペースの「init」プロセスとなり、ネームスペース内の他のプロセスを管理する責任を負います。その後、ネームスペース内で作成される各プロセスは、そのネームスペース内で一意のPIDを持ち、これらのPIDは他のネームスペースのPIDとは独立しています。

PIDネームスペース内のプロセスの視点からは、同じネームスペース内の他のプロセスのみを見ることができます。他のネームスペースのプロセスを認識しておらず、従来のプロセス管理ツール（例：`kill`、`wait`など）を使用してそれらと対話することはできません。これにより、プロセスが互いに干渉するのを防ぐための分離レベルが提供されます。

### 仕組み:

1. 新しいプロセスが作成されるとき（例えば、`clone()`システムコールを使用して）、プロセスは新しいまたは既存のPIDネームスペースに割り当てることができます。**新しいネームスペースが作成されると、プロセスはそのネームスペースの「init」プロセスになります**。
2. **カーネル**は、新しいネームスペースのPIDと親ネームスペース（つまり、新しいネームスペースが作成されたネームスペース）の対応するPIDとの間の**マッピングを維持します**。このマッピングにより、異なるネームスペースのプロセス間でシグナルを送信するなど、必要に応じてPIDを変換することが**カーネルに可能になります**。
3. **PIDネームスペース内のプロセスは、同じネームスペース内の他のプロセスのみを見て対話することができます**。彼らは他のネームスペースのプロセスを認識しておらず、彼らのPIDは自分たちのネームスペース内でユニークです。
4. **PIDネームスペースが破壊されるとき**（例えば、ネームスペースの「init」プロセスが終了したとき）、**そのネームスペース内のすべてのプロセスが終了します**。これにより、ネームスペースに関連するすべてのリソースが適切にクリーンアップされることが保証されます。

## ラボ:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare`が`-f`オプションなしで実行されると、Linuxが新しいPID（プロセスID）ネームスペースを扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、プロセスが`unshare`システムコールを使用して新しいネームスペースを作成することを許可しています。しかし、新しいPIDネームスペースの作成を開始するプロセス（"unshare"プロセスと呼ばれる）は、新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`は`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPIDネームスペースにあります。
- 新しいネームスペースでの`/bin/bash`の最初の子プロセスがPID 1になります。このプロセスが終了すると、他のプロセスがない場合、ネームスペースのクリーンアップがトリガーされます。なぜなら、PID 1には孤立したプロセスを引き継ぐ特別な役割があるからです。LinuxカーネルはそのネームスペースでのPID割り当てを無効にします。

2. **結果**:
- 新しいネームスペースでのPID 1の終了は、`PIDNS_HASH_ADDING`フラグのクリーニングにつながります。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てることができず、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare`と一緒に`-f`オプションを使用することで解決できます。このオプションは、新しいPIDネームスペースを作成した後に`unshare`が新しいプロセスをフォークするようにします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しいネームスペースでPID 1になります。`/bin/bash`とその子プロセスは、この新しいネームスペース内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPIDネームスペースが正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく操作できるようになります。

</details>

`--mount-proc`パラメータを使用して新しい`/proc`ファイルシステムのインスタンスをマウントすることで、新しいマウントネームスペースが**そのネームスペースに特有のプロセス情報の正確で隔離されたビューを持つ**ことを保証します。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどのネームスペースにあるか確認する
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

初期（デフォルト）のPIDネームスペースのrootユーザーは、新しいPIDネームスペース内のプロセスも含め、すべてのプロセスを見ることができます。そのため、すべてのPIDネームスペースを確認できます。

### PIDネームスペース内に入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
デフォルトの名前空間からPID名前空間に入ると、すべてのプロセスが見えるままです。また、そのPID nsのプロセスは、PID ns上の新しいbashを見ることができます。

また、**rootである場合に限り、他のプロセスのPID名前空間に** **入ることができます**。そして、(`/proc/self/ns/pid`のような)それを指すディスクリプタ**なしに**他の名前空間に**入ることはできません**。

# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>!</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの**会社を広告したい、または**HackTricksをPDFでダウンロード**したい場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
