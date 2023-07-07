# IPC ネームスペース

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PR を** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

IPC (Inter-Process Communication) ネームスペースは、Linux カーネルの機能であり、メッセージキュー、共有メモリセグメント、セマフォなどの System V IPC オブジェクトを**分離**します。この分離により、**異なる IPC ネームスペースのプロセスは、直接に他のネームスペースの IPC オブジェクトにアクセスしたり変更したりすることができません**。これにより、プロセスグループ間のセキュリティとプライバシーの追加のレイヤーが提供されます。

### 動作原理:

1. 新しい IPC ネームスペースが作成されると、**完全に分離された System V IPC オブジェクトのセット**で開始されます。これは、新しい IPC ネームスペースで実行されるプロセスが、デフォルトでは他のネームスペースやホストシステムの IPC オブジェクトにアクセスしたり干渉したりすることができないことを意味します。
2. ネームスペース内で作成された IPC オブジェクトは、**そのネームスペース内のプロセスのみが見え、アクセスできます**。各 IPC オブジェクトは、ネームスペース内で一意のキーによって識別されます。キーは異なるネームスペースで同じである場合がありますが、オブジェクト自体は分離され、ネームスペース間でアクセスすることはできません。
3. プロセスは、`setns()` システムコールを使用してネームスペース間を移動したり、`unshare()` または `clone()` システムコールを使用して `CLONE_NEWIPC` フラグとともに新しいネームスペースを作成したりすることができます。プロセスが新しいネームスペースに移動したり作成したりすると、そのネームスペースに関連付けられた IPC オブジェクトを使用し始めます。

## ラボ:

### 異なるネームスペースの作成

#### CLI
```bash
sudo unshare -i [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報の正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー：bash: fork: Cannot allocate memory</summary>

`-f`を指定せずに前の行を実行すると、このエラーが発生します。\
このエラーは、新しい名前空間でPID 1のプロセスが終了することによって引き起こされます。

bashが実行されると、bashはいくつかの新しいサブプロセスをフォークして何かを行います。-fを指定せずにunshareを実行すると、bashのPIDは現在の「unshare」プロセスと同じになります。現在の「unshare」プロセスはunshareシステムコールを呼び出し、新しいPID名前空間を作成しますが、現在の「unshare」プロセス自体は新しいPID名前空間にありません。これはLinuxカーネルの望ましい動作です：プロセスAが新しい名前空間を作成すると、プロセスA自体は新しい名前空間に配置されず、プロセスAのサブプロセスのみが新しい名前空間に配置されます。したがって、次のコマンドを実行すると：
```
unshare -p /bin/bash
```
unshareプロセスは/bin/bashを実行し、/bin/bashはいくつかのサブプロセスをフォークします。bashの最初のサブプロセスは新しい名前空間のPID 1になり、ジョブが完了するとサブプロセスは終了します。したがって、新しい名前空間のPID 1が終了します。

PID 1プロセスには特別な機能があります。孤児プロセスの親プロセスになる必要があります。ルート名前空間のPID 1プロセスが終了すると、カーネルはパニックになります。サブ名前空間のPID 1プロセスが終了すると、Linuxカーネルはdisable\_pid\_allocation関数を呼び出し、その名前空間のPIDNS\_HASH\_ADDINGフラグをクリアします。Linuxカーネルが新しいプロセスを作成するとき、カーネルはalloc\_pid関数を呼び出して名前空間内でPIDを割り当てます。PIDNS\_HASH\_ADDINGフラグが設定されていない場合、alloc\_pid関数は-ENOMEMエラーを返します。これが「Cannot allocate memory」エラーが発生する理由です。

この問題は、'-f'オプションを使用することで解決できます：
```
unshare -fp /bin/bash
```
もし'unshare'を'-f'オプションと共に実行すると、'unshare'は新しいpid名前空間を作成した後に新しいプロセスをフォークします。そして、新しいプロセスで'/bin/bash'を実行します。新しいプロセスは新しいpid名前空間のpid 1となります。その後、bashはいくつかのサブプロセスをフォークしてジョブを実行します。bash自体が新しいpid名前空間のpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the `lsns` command. This command lists all the namespaces on the system along with the processes associated with each namespace.

名前空間がどこにあるかを確認するには、`lsns`コマンドを使用します。このコマンドは、システム上のすべての名前空間とそれに関連するプロセスを一覧表示します。

```bash
$ lsns
```

The output will show the different namespaces and their associated processes. Look for the process ID (PID) of your process in the output to determine which namespace it belongs to.

出力には、異なる名前空間とそれに関連するプロセスが表示されます。自分のプロセスのプロセスID（PID）を出力から探し、それがどの名前空間に属しているかを確認します。
```bash
ls -l /proc/self/ns/ipc
lrwxrwxrwx 1 root root 0 Apr  4 20:37 /proc/self/ns/ipc -> 'ipc:[4026531839]'
```
### すべてのIPCネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name ipc -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name ipc -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### IPC ネームスペースに入る

{% endcode %}
```bash
nsenter -i TARGET_PID --pid /bin/bash
```
また、rootユーザーでない限り、他のプロセスの名前空間には入ることができません。また、`/proc/self/ns/net`のようなディスクリプタがない場合、他の名前空間に入ることはできません。

### IPCオブジェクトの作成
```bash
# Container
sudo unshare -i /bin/bash
ipcmk -M 100
Shared memory id: 0
ipcs -m

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status
0x2fba9021 0          root       644        100        0

# From the host
ipcs -m # Nothing is seen
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、私たちの独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクション
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で私を**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するために、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
