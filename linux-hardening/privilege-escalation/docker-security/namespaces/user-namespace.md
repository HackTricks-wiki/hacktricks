# ユーザーネームスペース

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>

## 基本情報

ユーザーネームスペースは、**ユーザーとグループIDのマッピングの分離を提供する**Linuxカーネルの機能であり、各ユーザーネームスペースが**独自のユーザーとグループIDのセット**を持つことができます。この分離により、異なるユーザーネームスペースで実行されるプロセスは、数値上で同じユーザーとグループIDを共有していても、**異なる権限と所有権を持つ**ことができます。

ユーザーネームスペースは、コンテナ化に特に有用であり、各コンテナが独立したユーザーとグループIDのセットを持つべきであり、コンテナとホストシステム間のセキュリティと分離を向上させることができます。

### 動作方法:

1. 新しいユーザーネームスペースが作成されると、**ユーザーとグループIDのマッピングの空のセットから始まります**。これは、新しいユーザーネームスペースで実行されるプロセスは、**当初はネームスペースの外での権限がない**ことを意味します。
2. 新しいネームスペース内のユーザーとグループIDと親（またはホスト）ネームスペース内のIDとの間にIDマッピングを確立することができます。これにより、**新しいネームスペース内のプロセスが、親ネームスペース内のユーザーとグループIDに対応する権限と所有権を持つことができます**。ただし、IDマッピングは特定の範囲やIDのサブセットに制限することができ、新しいネームスペース内のプロセスに付与される権限を細かく制御することができます。
3. ユーザーネームスペース内では、**プロセスはネームスペース内の操作に対して完全なroot権限（UID 0）を持つことができます**が、ネームスペースの外では限定された権限を持ちます。これにより、**コンテナが自身のネームスペース内でroot権限に似た機能を持ちながら、ホストシステム上で完全なroot権限を持たないようにすることができます**。
4. プロセスは、`setns()`システムコールを使用してネームスペース間を移動したり、`CLONE_NEWUSER`フラグを使用して`unshare()`または`clone()`システムコールで新しいネームスペースを作成することができます。プロセスが新しいネームスペースに移動するか、新しいものを作成すると、そのネームスペースに関連付けられたユーザーとグループIDのマッピングを使用し始めます。

## ラボ:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
`/proc` ファイルシステムの新しいインスタンスをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しい PID (プロセス ID) 名前空間を扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可しています。しかし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。なぜなら、PID 1 には孤立したプロセスを引き継ぐ特別な役割があるからです。その後、Linuxカーネルはその名前空間での PID 割り当てを無効にします。

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
```
ユーザー名前空間を使用するには、Dockerデーモンを **`--userns-remap=default`** で起動する必要があります(ubuntu 14.04では、`/etc/default/docker` を変更してから `sudo service docker restart` を実行します)

### &#x20;プロセスがどの名前空間にあるか確認する
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
コンテナからユーザーマップを確認する方法は以下の通りです:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
ホストからは以下の通りです:
```bash
cat /proc/<pid>/uid_map
```
### すべてのユーザー名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### ユーザー名前空間に入る
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
また、**rootである場合に限り、他のプロセスのネームスペースに** **入ることができます**。そして、それを指し示すディスクリプタ（`/proc/self/ns/user`のような）が**なければ**、他のネームスペースに**入ることはできません**。

### 新しいユーザーネームスペースを作成する（マッピング付き）

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### 権限の回復

ユーザー名前空間の場合、**新しいユーザー名前空間が作成されると、その名前空間に入るプロセスは、その名前空間内で完全な権限セットを付与されます**。これらの権限により、プロセスは**ファイルシステムのマウント**、デバイスの作成、ファイルの所有権の変更などの特権操作を実行できますが、**自分のユーザー名前空間のコンテキスト内でのみ**可能です。

例えば、ユーザー名前空間内で`CAP_SYS_ADMIN`権限を持っている場合、通常この権限が必要とされるファイルシステムのマウントなどの操作を実行できますが、自分のユーザー名前空間のコンテキスト内でのみです。この権限で実行する操作は、ホストシステムや他の名前空間には影響を与えません。

{% hint style="warning" %}
したがって、新しいプロセスが新しいユーザー名前空間内で実行されると**すべての権限が戻る**（CapEff: 000001ffffffffff）としても、実際には**名前空間に関連する権限のみ**（例えばマウント）を使用でき、すべての権限を使用できるわけではありません。したがって、これだけではDockerコンテナからの脱出には十分ではありません。
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
# 参照
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください。**

</details>
