# ネットワークネームスペース

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 基本情報

ネットワークネームスペースは、ネットワークスタックの隔離を提供するLinuxカーネルの機能であり、**各ネットワークネームスペースが独自の独立したネットワーク構成を持つことができます**。インターフェース、IPアドレス、ルーティングテーブル、ファイアウォールルールが含まれます。この隔離は、コンテナ化などのさまざまなシナリオで役立ちます。ここでは、各コンテナが他のコンテナやホストシステムとは独立したネットワーク構成を持つべきです。

### 動作原理:

1. 新しいネットワークネームスペースが作成されると、ループバックインターフェース(lo)を除いて、**完全に隔離されたネットワークスタック**が始まります。つまり、新しいネットワークネームスペースで実行されているプロセスは、デフォルトでは他のネームスペースやホストシステムのプロセスと通信できません。
2. **仮想ネットワークインターフェース**（例えばvethペア）は作成され、ネットワークネームスペース間で移動することができます。これにより、ネームスペース間、またはネームスペースとホストシステム間のネットワーク接続を確立することができます。例えば、vethペアの一方の端をコンテナのネットワークネームスペースに配置し、他方の端をホストネームスペースの**ブリッジ**または別のネットワークインターフェースに接続することで、コンテナにネットワーク接続を提供できます。
3. ネームスペース内のネットワークインターフェースは、他のネームスペースとは独立して、**独自のIPアドレス、ルーティングテーブル、ファイアウォールルール**を持つことができます。これにより、異なるネットワークネームスペースのプロセスは、異なるネットワーク構成を持ち、別々のネットワークシステムで実行されているかのように操作することができます。
4. プロセスは、`setns()`システムコールを使用してネームスペース間を移動したり、`CLONE_NEWNET`フラグを使用して`unshare()`または`clone()`システムコールで新しいネームスペースを作成することができます。プロセスが新しいネームスペースに移動するか、新しいものを作成すると、そのネームスペースに関連付けられたネットワーク構成とインターフェースを使用し始めます。

## 実験室:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`/proc` ファイルシステムの新しいインスタンスをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しい PID (プロセス ID) 名前空間を扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、プロセスが `unshare` システムコールを使用して新しい名前空間を作成することを許可しています。しかし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1 は孤立したプロセスを引き取る特別な役割を持っているため、Linuxカーネルはその名前空間での PID 割り当てを無効にします。

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
また、**rootである場合に限り、他のプロセスのネームスペースに入ることができます**。そして、それを指すディスクリプタ（`/proc/self/ns/net`のような）が**なければ**、他のネームスペースに**入ることはできません**。

# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
```
