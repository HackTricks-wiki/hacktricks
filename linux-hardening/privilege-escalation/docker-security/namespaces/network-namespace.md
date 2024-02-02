# ネットワークネームスペース

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

ネットワークネームスペースは、ネットワークスタックの隔離を提供するLinuxカーネルの機能であり、**各ネットワークネームスペースが独自の独立したネットワーク構成を持つことができます**。インターフェース、IPアドレス、ルーティングテーブル、ファイアウォールルールが独立しています。この隔離は、コンテナ化などのさまざまなシナリオで役立ちます。ここでは、各コンテナが他のコンテナやホストシステムとは独立したネットワーク構成を持つべきです。

### 動作原理:

1. 新しいネットワークネームスペースが作成されると、ループバックインターフェース(lo)を除いて**ネットワークインターフェースがない完全に隔離されたネットワークスタック**から始まります。これは、新しいネットワークネームスペースで実行されているプロセスが、デフォルトでは他のネームスペースやホストシステムのプロセスと通信できないことを意味します。
2. **仮想ネットワークインターフェース**（例えばvethペア）は作成され、ネットワークネームスペース間で移動することができます。これにより、ネームスペース間またはネームスペースとホストシステム間のネットワーク接続を確立することができます。例えば、vethペアの一方の端をコンテナのネットワークネームスペースに配置し、他方の端をホストネームスペースの**ブリッジ**または別のネットワークインターフェースに接続することで、コンテナにネットワーク接続を提供できます。
3. ネームスペース内のネットワークインターフェースは、他のネームスペースとは独立して、**独自のIPアドレス、ルーティングテーブル、ファイアウォールルール**を持つことができます。これにより、異なるネットワークネームスペースのプロセスは異なるネットワーク構成を持ち、別々のネットワークシステムで実行されているかのように操作することができます。
4. プロセスは`setns()`システムコールを使用してネームスペース間を移動するか、`CLONE_NEWNET`フラグを使用して`unshare()`または`clone()`システムコールで新しいネームスペースを作成することができます。プロセスが新しいネームスペースに移動するか、新しいものを作成すると、そのネームスペースに関連付けられたネットワーク構成とインターフェースを使用し始めます。

## 実験室:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`--mount-proc` パラメータを使用して新しい `/proc` ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間が**その名前空間に特有のプロセス情報の正確で隔離されたビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

上記の行を `-f` なしで実行すると、そのエラーが発生します。\
このエラーは、新しい名前空間で PID 1 のプロセスが終了することによって引き起こされます。

bashが実行を開始した後、bashはいくつかの新しいサブプロセスをフォークして何かを行います。`unshare` を `-f` なしで実行すると、bashは現在の "unshare" プロセスと同じ pid を持つことになります。現在の "unshare" プロセスは unshare システムコールを呼び出し、新しい pid 名前空間を作成しますが、現在の "unshare" プロセスは新しい pid 名前空間には含まれません。これは Linux カーネルの望ましい動作です：プロセス A が新しい名前空間を作成すると、プロセス A 自体は新しい名前空間には入れられず、プロセス A のサブプロセスのみが新しい名前空間に入れられます。したがって、次のように実行するとき：
```
unshare -p /bin/bash
```
unshareプロセスは`/bin/bash`を実行し、`/bin/bash`はいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しいネームスペースのPID 1になり、サブプロセスはその仕事を完了した後に終了します。そのため、新しいネームスペースのPID 1が終了します。

PID 1プロセスには特別な機能があります：それはすべての孤立したプロセスの親プロセスになるべきです。ルートネームスペースのPID 1プロセスが終了すると、カーネルはパニックになります。サブネームスペースのPID 1プロセスが終了すると、Linuxカーネルは`disable_pid_allocation`関数を呼び出し、そのネームスペースで`PIDNS_HASH_ADDING`フラグをクリーンします。Linuxカーネルが新しいプロセスを作成するとき、カーネルは`alloc_pid`関数を呼び出してネームスペース内でPIDを割り当てますが、`PIDNS_HASH_ADDING`フラグが設定されていない場合、`alloc_pid`関数は-ENOMEMエラーを返します。これが「Cannot allocate memory」エラーの原因です。

この問題は`-f`オプションを使用して解決できます：
```
unshare -fp /bin/bash
```
```
`unshare` を `-f` オプションで実行すると、新しい pid ネームスペースを作成した後に新しいプロセスをフォークします。そして新しいプロセスで `/bin/bash` を実行します。新しいプロセスは新しい pid ネームスペースの pid 1 になります。その後、bash はいくつかのジョブを行うためにいくつかのサブプロセスをフォークします。bash 自体が新しい pid ネームスペースの pid 1 であるため、そのサブプロセスは問題なく終了できます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory) からコピーされました

</details>

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### プロセスがどのネームスペースにあるかを確認する
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### すべてのネットワーク名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### ネットワーク名前空間に入る
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
```
また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指すディスクリプタ（`/proc/self/ns/net`のような）**がなければ**、他のネームスペースに**入ることは** **できません**。

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキングをゼロからヒーローまで学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
```
