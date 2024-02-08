# ユーザー名前空間

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法:

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**または[telegramグループ](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)を**フォロー**する
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください**

</details>

## 基本情報

ユーザー名前空間は、Linuxカーネルの機能であり、**ユーザーとグループIDのマッピングを分離**し、各ユーザー名前空間が**独自のユーザーとグループIDセット**を持つことを可能にする。この分離により、異なるユーザー名前空間で実行されるプロセスは、数値的に同じユーザーとグループIDを共有していても、**異なる特権と所有権**を持つことができる。

ユーザー名前空間は、コンテナ化において特に有用であり、各コンテナが独自のユーザーとグループIDセットを持ち、コンテナとホストシステムの間のセキュリティと分離が向上する。

### 動作方法:

1. 新しいユーザー名前空間が作成されると、**空のユーザーとグループIDマッピングセット**で開始される。これは、新しいユーザー名前空間で実行されるプロセスは、**初めは名前空間外で特権を持たない**ことを意味する。
2. IDマッピングは、新しい名前空間内のユーザーとグループIDと親（またはホスト）名前空間内のそれらとの間に確立される。これにより、新しい名前空間内のプロセスが、親名前空間内のユーザーとグループIDに対応する特権と所有権を持つことができる。ただし、IDマッピングは特定の範囲やIDのサブセットに制限することができ、新しい名前空間内のプロセスに付与される特権を細かく制御することができる。
3. ユーザー名前空間内では、**プロセスは名前空間内の操作に対して完全なルート特権（UID 0）を持つ**ことができ、名前空間外では制限された特権を持つ。これにより、**コンテナはホストシステムで完全なルート特権を持たずに、独自の名前空間内でルートのような機能を実行**することができる。
4. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを`CLONE_NEWUSER`フラグとともに使用して新しい名前空間を作成したりすることができる。プロセスが新しい名前空間に移動したり作成したりすると、その名前空間に関連付けられたユーザーとグループIDマッピングが使用される。

## Lab:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に概説されています:

1. **問題の説明**:
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1が名前空間のクリーンアップをトリガーします。その後、Linuxカーネルはその名前空間でのPID割り当てを無効にします。

2. **結果**:
- 新しい名前空間内のPID 1の終了により、`PIDNS_HASH_ADDING`フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てられなくなり、「Cannot allocate memory」エラーが発生します。

3. **解決策**:
- `unshare`に`-f`オプションを使用することで問題を解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間でPID 1になります。その後、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作するようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dockerコンテナからユーザーマップを確認することができます：
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
または、ホストから次のようにします：
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
### ユーザー名前空間に入る

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと**、**他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に入るには（`/proc/self/ns/user`のような）**それを指すディスクリプタ**が必要です。

### 新しいユーザー名前空間を作成する（マッピング付き）

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

ユーザー名前空間の場合、**新しいユーザー名前空間が作成されると、その名前空間内で入るプロセスには完全なセットの権限が付与されます**。これらの権限により、プロセスは特権操作（ファイルシステムのマウント、デバイスの作成、ファイルの所有権の変更など）を実行できますが、**そのユーザー名前空間のコンテキスト内でのみ**です。

たとえば、ユーザー名前空間内で`CAP_SYS_ADMIN`権限を持っている場合、通常この権限が必要な操作（ファイルシステムのマウントなど）を実行できますが、ユーザー名前空間のコンテキスト内でのみです。この権限を使用して行う操作は、ホストシステムや他の名前空間には影響しません。

{% hint style="warning" %}
したがって、新しいプロセスを新しいユーザー名前空間内に取得しても、**すべての権限が戻ってくる**（CapEff: 000001ffffffffff）が、実際には**名前空間に関連する権限のみ**（たとえばマウント）を使用できます。したがって、これだけではDockerコンテナから脱出するのには十分ではありません。
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
## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>でAWSハッキングをゼロからヒーローまで学ぶ！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい**、または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>
