# PID Namespace

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

他のHackTricksをサポートする方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 基本情報

PID (Process IDentifier) ネームスペースは、Linuxカーネルの機能で、プロセスの分離を実現するために、一群のプロセスが他のネームスペースのPIDとは別の一意のPIDセットを持つことを可能にします。これは、セキュリティとリソース管理に不可欠なプロセスの分離が特に重要なコンテナ化において有用です。

新しいPIDネームスペースが作成されると、そのネームスペース内の最初のプロセスにPID 1が割り当てられます。このプロセスは新しいネームスペースの「init」プロセスとなり、ネームスペース内の他のプロセスを管理する責任を負います。その後、ネームスペース内で作成される各プロセスは、そのネームスペース内で一意のPIDを持ち、これらのPIDは他のネームスペースのPIDとは独立しています。

PIDネームスペース内のプロセスの視点からは、同じネームスペース内の他のプロセスのみを見ることができます。他のネームスペースのプロセスを認識しておらず、従来のプロセス管理ツール（例：`kill`、`wait`など）を使用してそれらと対話することはできません。これにより、プロセスが互いに干渉するのを防ぐための分離レベルが提供されます。

### 仕組み:

1. 新しいプロセスが作成されるとき（例えば、`clone()`システムコールを使用する場合）、プロセスは新しいまたは既存のPIDネームスペースに割り当てることができます。**新しいネームスペースが作成されると、プロセスはそのネームスペースの「init」プロセスになります**。
2. **カーネル**は、新しいネームスペースのPIDと親ネームスペース（つまり、新しいネームスペースが作成されたネームスペース）の対応するPIDとの間の**マッピングを維持します**。このマッピングにより、異なるネームスペースのプロセス間でシグナルを送信するなど、必要に応じてPIDを変換することが**可能になります**。
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

`-f` なしで前の行を実行すると、そのエラーが発生します。\
このエラーは、新しいネームスペースで PID 1 のプロセスが終了するために発生します。

bashが実行を開始すると、bashはいくつかの新しいサブプロセスをフォークして何かを行います。`unshare` を `-f` なしで実行すると、bashは現在の "unshare" プロセスと同じ pid を持つことになります。現在の "unshare" プロセスは unshare システムコールを呼び出し、新しい pid ネームスペースを作成しますが、現在の "unshare" プロセスは新しい pid ネームスペースには含まれません。これは Linux カーネルの望ましい動作です：プロセス A が新しいネームスペースを作成すると、プロセス A 自体は新しいネームスペースには入れられず、プロセス A のサブプロセスのみが新しいネームスペースに入れられます。したがって、次のように実行すると：

</details>
```
unshare -p /bin/bash
```
```markdown
unshareプロセスは`/bin/bash`を実行し、`/bin/bash`はいくつかのサブプロセスをフォークします。bashの最初のサブプロセスが新しいネームスペースのPID 1になり、サブプロセスはその仕事を完了した後に終了します。そのため、新しいネームスペースのPID 1が終了します。

PID 1プロセスには特別な機能があります：それはすべての孤児プロセスの親プロセスになるべきです。ルートネームスペースのPID 1プロセスが終了すると、カーネルはパニックになります。サブネームスペースのPID 1プロセスが終了すると、Linuxカーネルは`disable_pid_allocation`関数を呼び出し、そのネームスペースでPIDNS_HASH_ADDINGフラグをクリーンします。Linuxカーネルが新しいプロセスを作成するとき、カーネルは`alloc_pid`関数を呼び出してネームスペース内でPIDを割り当てますが、PIDNS_HASH_ADDINGフラグが設定されていない場合、`alloc_pid`関数は-ENOMEMエラーを返します。そのため、「Cannot allocate memory」というエラーが発生します。

この問題は'-f'オプションを使用して解決できます：
```
```
unshare -fp /bin/bash
```
`unshare`を`-f`オプションと共に実行すると、新しいpidネームスペースを作成した後に新しいプロセスをフォークします。そして、新しいプロセスで`/bin/bash`を実行します。新しいプロセスは新しいpidネームスペースのpid 1になります。その後、bashはいくつかのサブプロセスをフォークして作業を行います。bash自体が新しいpidネームスペースのpid 1であるため、そのサブプロセスは問題なく終了できます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory) からの転載

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

初期（デフォルト）のPIDネームスペースのrootユーザーは、新しいPIDネームスペース内のプロセスも含め、すべてのプロセスを確認できるため、すべてのPIDネームスペースを見ることができます。

### PIDネームスペース内に入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
```markdown
デフォルトの名前空間からPID名前空間に入ると、すべてのプロセスが見える状態が続きます。また、そのPID nsのプロセスは、PID ns上の新しいbashを見ることができます。

また、**rootである場合に限り、他のプロセスのPID名前空間に** **入ることができます**。そして、(`/proc/self/ns/pid`のような)それを指す**ディスクリプタ** **なしに** 他の名前空間に**入ることはできません**。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
```
