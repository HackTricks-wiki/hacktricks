# ネットワークの名前空間

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

ネットワークの名前空間は、Linuxカーネルの機能であり、ネットワークスタックの分離を提供します。これにより、**各ネットワークの名前空間は独立したネットワーク構成**、インターフェース、IPアドレス、ルーティングテーブル、およびファイアウォールルールを持つことができます。この分離は、コンテナ化などのさまざまなシナリオで有用であり、各コンテナは他のコンテナやホストシステムとは独立したネットワーク構成を持つ必要があります。

### 動作原理：

1. 新しいネットワークの名前空間が作成されると、**完全に分離されたネットワークスタック**が開始されます。ループバックインターフェース（lo）以外には**ネットワークインターフェースが存在しない**ことを意味します。これにより、新しいネットワークの名前空間で実行されているプロセスは、デフォルトでは他の名前空間やホストシステムのプロセスと通信することはできません。
2. vethペアなどの**仮想ネットワークインターフェース**は、ネットワークの名前空間間または名前空間とホストシステム間のネットワーク接続を確立するために作成および移動できます。たとえば、vethペアの一方のエンドをコンテナのネットワークの名前空間に配置し、もう一方のエンドをホストの名前空間の**ブリッジ**または他のネットワークインターフェースに接続することで、コンテナにネットワーク接続を提供できます。
3. 名前空間内のネットワークインターフェースは、他の名前空間とは独立して、**独自のIPアドレス、ルーティングテーブル、およびファイアウォールルール**を持つことができます。これにより、異なるネットワークの名前空間内のプロセスは、異なるネットワーク構成を持ち、別々のネットワークシステム上で実行されているかのように動作することができます。
4. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを使用して`CLONE_NEWNET`フラグとともに新しい名前空間を作成したりすることができます。プロセスが新しい名前空間に移動するか、新しい名前空間を作成すると、その名前空間に関連付けられたネットワーク構成とインターフェースを使用し始めます。

## ラボ：

### 異なる名前空間の作成

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
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
もし'unshare'を'-f'オプションと共に実行すると、'unshare'は新しいpid名前空間を作成した後に新しいプロセスをフォークします。そして、新しいプロセスで'/bin/bash'を実行します。新しいプロセスは新しいpid名前空間のpid 1となります。その後、bashはいくつかのサブプロセスをフォークしてジョブを実行します。bash自体が新しいpid名前空間のpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the following command:

プロセスがどの名前空間にあるかを確認するには、次のコマンドを使用します。

```bash
$ ls -l /proc/$$/ns/net
```

This command will display the network namespace associated with your process. The `$$` represents the process ID of the current shell.

このコマンドは、プロセスに関連付けられたネットワーク名前空間を表示します。`$$`は現在のシェルのプロセスIDを表します。
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
{% code %}

### ネットワーク名前空間に入る

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
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
