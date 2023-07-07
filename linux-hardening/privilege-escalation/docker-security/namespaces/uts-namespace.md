# UTS ネームスペース

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricks で会社を宣伝**したいですか？または、**PEASS の最新バージョンにアクセスしたり、HackTricks を PDF でダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式の PEASS & HackTricks スワッグ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discord グループ**](https://discord.gg/hRep4RUj7f)または[**telegram グループ**](https://t.me/peass)に**参加**するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks リポジトリ**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud リポジトリ**](https://github.com/carlospolop/hacktricks-cloud) **に PR を提出**してください。

</details>

## 基本情報

UTS (UNIX Time-Sharing System) ネームスペースは、Linux カーネルの機能であり、**ホスト名**と**NIS** (Network Information Service) ドメイン名の**2つのシステム識別子を分離**します。この分離により、各 UTS ネームスペースは、独自のホスト名と NIS ドメイン名を持つことができます。これは、各コンテナが独立したシステムとして表示される必要があるコンテナ化シナリオで特に有用です。

### 動作原理:

1. 新しい UTS ネームスペースが作成されると、**親ネームスペースからホスト名と NIS ドメイン名のコピー**で開始されます。つまり、作成時に新しいネームスペースは親と同じ識別子を**共有**します。ただし、ネームスペース内でホスト名または NIS ドメイン名を変更すると、他のネームスペースには影響しません。
2. UTS ネームスペース内のプロセスは、`sethostname()` および `setdomainname()` システムコールを使用して、ホスト名と NIS ドメイン名を**変更**することができます。これらの変更はネームスペース内にローカルであり、他のネームスペースやホストシステムには影響しません。
3. プロセスは、`setns()` システムコールを使用してネームスペース間を移動したり、`unshare()` または `clone()` システムコールを使用して新しいネームスペースを作成したりすることができます。プロセスが新しいネームスペースに移動するか作成すると、そのネームスペースに関連付けられたホスト名と NIS ドメイン名が使用されるようになります。

## ラボ:

### 異なるネームスペースの作成

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
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
もし'unshare'を'-f'オプションと共に実行すると、'unshare'は新しいpid名前空間を作成した後に新しいプロセスをフォークします。そして、新しいプロセスで'/bin/bash'を実行します。新しいプロセスは新しいpid名前空間のpid 1となります。その後、bashはいくつかのサブプロセスをフォークしてジョブを実行します。bash自体が新しいpid名前空間のpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the following command:

プロセスがどの名前空間にあるかを確認するには、次のコマンドを使用します。

```bash
$ cat /proc/$$/ns/uts
```

This command will display the UTS namespace of your process. The output will be a file descriptor, which represents the namespace.

このコマンドは、プロセスのUTS名前空間を表示します。出力は、名前空間を表すファイルディスクリプタです。
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### すべてのUTS名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### UTS ネームスペースに入る

{% endcode %}
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
また、rootユーザーでない限り、他のプロセスの名前空間には入ることができません。また、`/proc/self/ns/uts`のようなディスクリプタがない場合、他の名前空間に入ることはできません。

### ホスト名の変更
```bash
unshare -u /bin/bash
hostname newhostname # Hostname won't be changed inside the host UTS ns
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
