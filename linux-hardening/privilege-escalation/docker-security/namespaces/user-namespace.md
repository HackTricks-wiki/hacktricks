# ユーザーネームスペース

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

ユーザーネームスペースは、Linuxカーネルの機能であり、**ユーザーとグループIDのマッピングの分離**を提供します。これにより、各ユーザーネームスペースは、**独自のユーザーとグループIDのセット**を持つことができます。この分離により、同じユーザーとグループIDを共有していても、異なるユーザーネームスペースで実行されるプロセスは、**異なる特権と所有権**を持つことができます。

ユーザーネームスペースは、特にコンテナ化において有用です。各コンテナは、独自のユーザーとグループIDの独立したセットを持つことができるため、コンテナとホストシステムの間のセキュリティと分離が向上します。

### 動作原理：

1. 新しいユーザーネームスペースが作成されると、**空のユーザーとグループIDのマッピングセット**で開始されます。これは、新しいユーザーネームスペースで実行されるプロセスが、**ネームスペースの外部に特権を持たない**ことを意味します。
2. IDマッピングは、新しいネームスペース内のユーザーとグループIDと、親（またはホスト）ネームスペース内のIDとの間で確立することができます。これにより、新しいネームスペース内のプロセスが、親ネームスペース内のユーザーとグループIDに対応する特権と所有権を持つことができます。ただし、IDマッピングは特定の範囲やIDのサブセットに制限することもできるため、新しいネームスペース内のプロセスに付与される特権を細かく制御することができます。
3. ユーザーネームスペース内では、**プロセスはネームスペース内の操作に対して完全なルート特権（UID 0）を持つ**一方で、ネームスペースの外部では制限された特権を持ちます。これにより、**コンテナはホストシステム上で完全なルート特権を持たずに、独自のネームスペース内でルートのような機能を実行**することができます。
4. プロセスは、`setns()`システムコールを使用してネームスペース間を移動したり、`unshare()`または`clone()`システムコールを使用して新しいネームスペースを作成したりすることができます。プロセスが新しいネームスペースに移動したり作成したりすると、そのネームスペースに関連付けられたユーザーとグループIDのマッピングを使用し始めます。

## ラボ：

### 異なるネームスペースの作成

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報の正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー：bash: fork: Cannot allocate memory</summary>

`-f`を指定せずに前の行を実行すると、このエラーが発生します。\
このエラーは、新しい名前空間でPID 1プロセスが終了することによって引き起こされます。

bashが実行されると、bashはいくつかの新しいサブプロセスをフォークして何かを行います。-fを指定せずにunshareを実行すると、bashは現在の「unshare」プロセスと同じPIDを持ちます。現在の「unshare」プロセスはunshareシステムコールを呼び出し、新しいPID名前空間を作成しますが、現在の「unshare」プロセス自体は新しいPID名前空間にありません。これはLinuxカーネルの望ましい動作です：プロセスAが新しい名前空間を作成すると、プロセスA自体は新しい名前空間に配置されず、プロセスAのサブプロセスのみが新しい名前空間に配置されます。したがって、次のコマンドを実行すると：
```
unshare -p /bin/bash
```
unshareプロセスは/bin/bashを実行し、/bin/bashはいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しい名前空間のPID 1になり、ジョブが完了するとサブプロセスは終了します。したがって、新しい名前空間のPID 1が終了します。

PID 1プロセスには特別な機能があります。孤児プロセスの親プロセスになる必要があります。ルート名前空間のPID 1プロセスが終了すると、カーネルはパニックになります。サブ名前空間のPID 1プロセスが終了すると、Linuxカーネルはdisable\_pid\_allocation関数を呼び出し、その名前空間のPIDNS\_HASH\_ADDINGフラグをクリアします。Linuxカーネルが新しいプロセスを作成するとき、カーネルはalloc\_pid関数を呼び出して名前空間内でPIDを割り当てます。PIDNS\_HASH\_ADDINGフラグが設定されていない場合、alloc\_pid関数は-ENOMEMエラーを返します。これが「Cannot allocate memory」エラーが発生する理由です。

この問題は、'-f'オプションを使用することで解決できます：
```
unshare -fp /bin/bash
```
もし`-f`オプションを使ってunshareを実行すると、unshareは新しいpid namespaceを作成した後に新しいプロセスをフォークします。そして新しいプロセスで`/bin/bash`を実行します。新しいプロセスは新しいpid namespaceのpid 1となります。その後、bashはいくつかのサブプロセスをフォークしてジョブを実行します。bash自体が新しいpid namespaceのpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
ユーザー名前空間を使用するには、Dockerデーモンを**`--userns-remap=default`**オプションで起動する必要があります（Ubuntu 14.04では、`/etc/default/docker`を変更してから`sudo service docker restart`を実行することで行えます）。

### &#x20;プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
Dockerコンテナからユーザーマップを確認することができます。以下のコマンドを使用します。
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
または、ホストから次のコマンドを実行します：
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
{% code %}

### ユーザー名前空間に入る

{% endcode %}
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
また、rootユーザーでない限り、他のプロセスの名前空間には入ることができません。また、`/proc/self/ns/user`のようなディスクリプタがない場合、他の名前空間に入ることはできません。

### 新しいユーザー名前空間の作成（マッピング付き）

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

ユーザー名前空間の場合、**新しいユーザー名前空間が作成されると、その名前空間に入るプロセスには完全なセットの権限が付与されます**。これらの権限により、プロセスは特権操作（ファイルシステムのマウント、デバイスの作成、ファイルの所有権の変更など）を実行できますが、**ユーザー名前空間のコンテキスト内でのみ**です。

例えば、ユーザー名前空間内で`CAP_SYS_ADMIN`の権限を持っている場合、通常この権限が必要な操作（ファイルシステムのマウントなど）をユーザー名前空間のコンテキスト内で実行できます。この権限を使用して行う操作は、ホストシステムや他の名前空間には影響を与えません。

{% hint style="warning" %}
したがって、新しいプロセスを新しいユーザー名前空間内に取得しても、**すべての権限が復元されるわけではありません**（CapEff: 000001ffffffffff）。実際には、**名前空間に関連する権限のみを使用できます**（例えば、マウント）。そのため、これだけではDockerコンテナからの脱出には十分ではありません。
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
