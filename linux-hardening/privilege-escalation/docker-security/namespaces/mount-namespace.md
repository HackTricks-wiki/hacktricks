# マウント名前空間

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 基本情報

マウント名前空間は、プロセスグループが見るファイルシステムのマウントポイントの隔離を提供するLinuxカーネルの機能です。各マウント名前空間は、独自のファイルシステムマウントポイントのセットを持ち、**一つの名前空間でのマウントポイントの変更は他の名前空間に影響しません**。これは、異なるマウント名前空間で実行されているプロセスが、ファイルシステム階層の異なるビューを持つことができることを意味します。

マウント名前空間は、各コンテナが独自のファイルシステムと設定を持ち、他のコンテナやホストシステムから隔離されるべきであるコンテナ化に特に有用です。

### 動作方法:

1. 新しいマウント名前空間が作成されると、**親名前空間のマウントポイントのコピーで初期化されます**。つまり、作成時に新しい名前空間は親と同じファイルシステムのビューを共有します。しかし、その後の名前空間内のマウントポイントの変更は、親や他の名前空間には影響しません。
2. プロセスがその名前空間内でマウントポイントを変更すると、例えばファイルシステムのマウントやアンマウントを行うと、**その変更はその名前空間に局所的です** 他の名前空間には影響しません。これにより、各名前空間は独立したファイルシステム階層を持つことができます。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`CLONE_NEWNS`フラグを使用して`unshare()`や`clone()`システムコールで新しい名前空間を作成することができます。プロセスが新しい名前空間に移動するか、新しいものを作成すると、その名前空間に関連付けられたマウントポイントを使用し始めます。
4. **ファイルディスクリプタとinodeは名前空間間で共有されます**。つまり、ある名前空間のプロセスがファイルを指すオープンファイルディスクリプタを持っている場合、**そのファイルディスクリプタを別の名前空間のプロセスに渡すことができ**、**両方のプロセスが同じファイルにアクセスします**。ただし、マウントポイントの違いにより、ファイルのパスは両方の名前空間で同じではない可能性があります。

## 実験室:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
新しい `/proc` ファイルシステムのインスタンスをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間が**その名前空間に特有のプロセス情報の正確で隔離されたビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可します。しかし、新しいPID名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスがPID 1になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。PID 1は孤立したプロセスを引き取る特別な役割を持っているため、Linuxカーネルはその名前空間でのPID割り当てを無効にします。

2. **結果**:
- 新しい名前空間でのPID 1の終了は、`PIDNS_HASH_ADDING` フラグのクリーニングにつながります。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しいPIDを割り当てることができず、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` と `-f` オプションを使用することで解決できます。このオプションは、新しいPID名前空間を作成した後に `unshare` が新しいプロセスをフォークするようにします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間でPID 1になります。`/bin/bash` とその子プロセスは、この新しい名前空間内で安全に保持され、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく操作できるようになります。

</details>

#### Docker
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
### マウントする

また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指し示すディスクリプタ（`/proc/self/ns/mnt`のような）**なしに** 他のネームスペースに**入ることはできません**。

新しいマウントはそのネームスペース内でのみアクセス可能なので、ネームスペースにはそれからのみアクセス可能な機密情報が含まれている可能性があります。
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
# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)で<strong>AWSハッキング</strong>をゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**してください。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有**してください。

</details>
