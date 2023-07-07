# PID ネームスペース

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PR を** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

PID（プロセス ID）ネームスペースは、Linux カーネルの機能であり、一連のプロセスが他のネームスペースとは異なる一意の PID セットを持つことでプロセスの分離を提供します。これは特にコンテナ化において重要なセキュリティとリソース管理のためにプロセスの分離が必要な場合に役立ちます。

新しい PID ネームスペースが作成されると、そのネームスペース内の最初のプロセスには PID 1 が割り当てられます。このプロセスは新しいネームスペースの "init" プロセスとなり、ネームスペース内の他のプロセスを管理する責任を持ちます。ネームスペース内で作成される各プロセスは、そのネームスペース内で一意の PID を持ち、これらの PID は他のネームスペースの PID とは独立しています。

PID ネームスペース内のプロセスの視点からは、同じネームスペース内の他のプロセスしか見ることができません。他のネームスペースのプロセスには気付かず、従来のプロセス管理ツール（`kill`、`wait` など）を使用してそれらと対話することはできません。これにより、プロセス同士の干渉を防ぐ一定の分離レベルが提供されます。

### 動作原理:

1. 新しいプロセスが作成されると（たとえば、`clone()` システムコールを使用して）、そのプロセスは新しいまたは既存の PID ネームスペースに割り当てることができます。**新しいネームスペースが作成される場合、そのプロセスはそのネームスペースの "init" プロセスとなります**。
2. **カーネル**は、新しいネームスペースの PID と親ネームスペース（新しいネームスペースが作成されたネームスペース）の対応する PID との間の**マッピングを維持**します。このマッピングにより、カーネルは必要に応じて PID を変換できます。たとえば、異なるネームスペースのプロセス間でシグナルを送信する場合などです。
3. **PID ネームスペース内のプロセスは、同じネームスペース内の他のプロセスしか見ることができず、対話することができます**。他のネームスペースのプロセスには気付かず、それらの PID はネームスペース内で一意です。
4. **PID ネームスペースが破棄されると**（たとえば、ネームスペースの "init" プロセスが終了すると）、**そのネームスペース内のすべてのプロセスが終了**します。これにより、ネームスペースに関連するすべてのリソースが適切にクリーンアップされます。

## ラボ:

### 異なるネームスペースの作成

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>エラー：bash: fork: メモリを割り当てることができません</summary>

前の行を`-f`なしで実行すると、このエラーが発生します。\
このエラーは、新しい名前空間でPID 1プロセスが終了することによって引き起こされます。

bashが実行されると、いくつかの新しいサブプロセスをフォークして何かを実行します。`-f`なしでunshareを実行すると、bashのPIDは現在の「unshare」プロセスと同じになります。現在の「unshare」プロセスはunshareシステムコールを呼び出し、新しいPID名前空間を作成しますが、現在の「unshare」プロセスは新しいPID名前空間にありません。これはLinuxカーネルの望ましい動作です：プロセスAが新しい名前空間を作成すると、プロセスA自体は新しい名前空間に配置されず、プロセスAのサブプロセスのみが新しい名前空間に配置されます。したがって、次のコマンドを実行すると：
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

`--mount-proc`パラメータを使用して新しい`/proc`ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間はその名前空間固有のプロセス情報の正確で隔離されたビューを持つことが保証されます。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the `lsns` command. This command displays information about the namespaces on the system, including the PID (Process ID) namespace.

```bash
$ lsns -p <PID>
```

Replace `<PID>` with the process ID of the process you want to check. This will show you the namespace(s) that the process is associated with.

You can also use the `readlink` command to check the symbolic link of the `/proc/<PID>/ns/pid` file, which represents the PID namespace of a process.

```bash
$ readlink /proc/<PID>/ns/pid
```

Again, replace `<PID>` with the process ID you want to check. The output will be the path to the PID namespace file, indicating the namespace the process belongs to.
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### すべてのPID名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

初期（デフォルト）のPID名前空間からのrootユーザーは、新しいPID名前空間にあるプロセスを含めてすべてのプロセスを見ることができるため、すべてのPID名前空間を見ることができます。

### PID名前空間に入る
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
デフォルトの名前空間からPID名前空間に入ると、すべてのプロセスを見ることができます。そして、そのPID名前空間のプロセスは、PID名前空間上の新しいbashを見ることができます。

また、**rootでなければ他のプロセスのPID名前空間に入ることはできません**。そして、**`/proc/self/ns/pid`**のようなディスクリプタが指す名前空間にディスクリプタなしで入ることはできません。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
