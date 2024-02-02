# マウント名前空間

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

## 基本情報

マウント名前空間は、プロセスグループが見るファイルシステムのマウントポイントの隔離を提供するLinuxカーネルの機能です。各マウント名前空間は、独自のファイルシステムマウントポイントのセットを持ち、**一つの名前空間でのマウントポイントの変更は他の名前空間に影響しません**。これは、異なるマウント名前空間で実行されているプロセスが、ファイルシステム階層の異なるビューを持つことができることを意味します。

マウント名前空間は、各コンテナが独自のファイルシステムと設定を持ち、他のコンテナやホストシステムから隔離されるべきであるコンテナ化に特に有用です。

### 動作方法:

1. 新しいマウント名前空間が作成されると、**親名前空間のマウントポイントのコピーで初期化されます**。これは、作成時に新しい名前空間が親と同じファイルシステムのビューを共有することを意味します。しかし、名前空間内のマウントポイントに後続する変更は、親や他の名前空間には影響しません。
2. プロセスがその名前空間内のマウントポイントを変更すると、例えばファイルシステムのマウントやアンマウントを行うと、**その変更はその名前空間に局所的です** 他の名前空間には影響しません。これにより、各名前空間は独立したファイルシステム階層を持つことができます。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動するか、`CLONE_NEWNS`フラグを使用して`unshare()`または`clone()`システムコールで新しい名前空間を作成することができます。プロセスが新しい名前空間に移動するか、新しいものを作成すると、その名前空間に関連付けられたマウントポイントを使用し始めます。
4. **ファイルディスクリプタとinodeは名前空間を越えて共有されます**。つまり、ある名前空間のプロセスがファイルを指すオープンファイルディスクリプタを持っている場合、**そのファイルディスクリプタを別の名前空間のプロセスに渡すことができ**、**両方のプロセスが同じファイルにアクセスします**。ただし、マウントポイントの違いにより、ファイルのパスは両方の名前空間で同じではない可能性があります。

## ラボ:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して新しい `/proc` ファイルシステムのインスタンスをマウントすることにより、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

前述の行を `-f` なしで実行すると、そのエラーが発生します。\
このエラーは、新しい名前空間で PID 1 のプロセスが終了することによって引き起こされます。

bashが実行を開始した後、bashはいくつかの新しいサブプロセスをフォークして何かを行います。`unshare` を `-f` なしで実行すると、bashは現在の "unshare" プロセスと同じ pid を持つことになります。現在の "unshare" プロセスは unshare システムコールを呼び出し、新しい pid 名前空間を作成しますが、現在の "unshare" プロセスは新しい pid 名前空間には含まれません。これは Linux カーネルの望ましい動作です：プロセス A が新しい名前空間を作成すると、プロセス A 自体は新しい名前空間には入れられず、プロセス A のサブプロセスのみが新しい名前空間に入れられます。したがって、次のように実行するとき：
```
unshare -p /bin/bash
```
unshareプロセスは/bin/bashを実行し、/bin/bashはいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しいネームスペースのPID 1になり、サブプロセスはその仕事を完了した後に終了します。したがって、新しいネームスペースのPID 1が終了します。

PID 1プロセスには特別な機能があります：それはすべての孤児プロセスの親プロセスになるべきです。ルートネームスペースのPID 1プロセスが終了すると、カーネルはパニックになります。サブネームスペースのPID 1プロセスが終了すると、Linuxカーネルはdisable_pid_allocation関数を呼び出し、そのネームスペースでPIDNS_HASH_ADDINGフラグをクリーンします。Linuxカーネルが新しいプロセスを作成するとき、カーネルはalloc_pid関数を呼び出してネームスペース内でPIDを割り当てますが、PIDNS_HASH_ADDINGフラグが設定されていない場合、alloc_pid関数は-ENOMEMエラーを返します。そのため、「Cannot allocate memory」エラーが発生します。

この問題は'-f'オプションを使用して解決できます：
```
unshare -fp /bin/bash
```
```markdown
`unshare`を`-f`オプションで実行すると、新しいpidネームスペースを作成した後に新しいプロセスをフォークします。そして、新しいプロセスで`/bin/bash`を実行します。新しいプロセスは新しいpidネームスペースのpid 1になります。その後、bashはいくつかのジョブを行うためにいくつかのサブプロセスをフォークします。bash自体が新しいpidネームスペースのpid 1であるため、そのサブプロセスは問題なく終了できます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory) からコピーされました

</details>

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどのネームスペースにあるかを確認する
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### すべてのマウント名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### マウント名前空間に入る
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指すディスクリプタ（`/proc/self/ns/mnt`のような）が**なければ**、他のネームスペースに**入ることはできません**。

新しいマウントはそのネームスペース内でのみアクセス可能なので、ネームスペースにはそれからのみアクセス可能な機密情報が含まれている可能性があります。

### 何かをマウントする
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
