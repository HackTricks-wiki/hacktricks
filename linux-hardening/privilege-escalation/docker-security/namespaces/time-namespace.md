# タイムネームスペース

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

タイムネームスペースは、ネームスペースごとのシステムのモノトニックおよび起動時のクロックへのオフセットを可能にします。タイムネームスペースは、コンテナ内で日付/時刻を変更したり、チェックポイント/スナップショットからの復元後にコンテナ内のクロックを調整するために使用されるLinuxコンテナに適しています。

## ラボ：

### 異なるネームスペースの作成

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報の正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー：bash: fork: Cannot allocate memory</summary>

`-f`を指定せずに前の行を実行すると、このエラーが発生します。\
このエラーは、新しい名前空間でPID 1プロセスが終了することによって引き起こされます。

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
もし'unshare'を'-f'オプションと共に実行すると、'unshare'は新しいpid名前空間を作成した後に新しいプロセスをフォークします。そして、新しいプロセスで'/bin/bash'を実行します。新しいプロセスは新しいpid名前空間のpid 1となります。その後、bashはいくつかのジョブを実行するためにいくつかのサブプロセスをフォークします。bash自体が新しいpid名前空間のpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the `lsns` command. This command displays information about the namespaces on the system.

名前空間にあるプロセスを確認するには、`lsns`コマンドを使用します。このコマンドは、システム上の名前空間に関する情報を表示します。

```bash
$ lsns
```

This command will list all the namespaces along with their type, ID, and the number of processes in each namespace. The namespace type can be identified by the prefix in the ID. For example, `m` represents the mount namespace, `u` represents the user namespace, and `i` represents the IPC namespace.

このコマンドは、すべての名前空間とそのタイプ、ID、および各名前空間内のプロセス数を一覧表示します。名前空間のタイプは、IDの接頭辞で識別できます。たとえば、`m`はマウント名前空間を表し、`u`はユーザ名前空間を表し、`i`はIPC名前空間を表します。

To filter the output and display only the namespaces associated with your process, you can use the `ps` command along with the process ID (`PID`) of your process.

出力をフィルタリングして、自分のプロセスに関連する名前空間のみを表示するには、`ps`コマンドを使用し、自分のプロセスのプロセスID（`PID`）を指定します。

```bash
$ ps -o pid,user,ns
```

This command will display the PID, user, and namespace information for all processes. You can identify the namespaces associated with your process by matching the PID with your process's PID.

このコマンドは、すべてのプロセスのPID、ユーザ、および名前空間情報を表示します。自分のプロセスに関連する名前空間は、PIDを自分のプロセスのPIDと一致させることで特定できます。
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### すべてのタイムネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### タイムネームスペースに入る

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
また、**rootユーザーでなければ他のプロセスの名前空間に入ることはできません**。また、他の名前空間に入るためには（`/proc/self/ns/net`のような）ディスクリプタが必要です。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
