# CGroup Namespace

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* サイバーセキュリティ会社で働いていますか？ HackTricksであなたの会社を宣伝したいですか？または、最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロードしたりしたいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォローしてください。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

CGroup Namespaceは、**名前空間内で実行されるプロセスのcgroup階層を分離する**Linuxカーネルの機能です。**制御グループ**（control groups）の略であるcgroupsは、CPU、メモリ、I/Oなどのシステムリソースに対する制限を管理および強制するためのカーネル機能です。

CGroup Namespaceは、PID、マウント、ネットワークなどの他の名前空間とは異なる独立した名前空間タイプではありませんが、名前空間の分離の概念に関連しています。**CGroup Namespaceはcgroup階層のビューを仮想化**し、そのため、CGroup Namespace内で実行されるプロセスは、ホストや他の名前空間で実行されるプロセスと比較して、階層の異なるビューを持ちます。

### 動作原理：

1. 新しいCGroup Namespaceが作成されると、**作成プロセスのcgroupに基づいてcgroup階層のビューが開始されます**。これは、CGroup Namespace内で実行されるプロセスが、作成プロセスのcgroupをルートとするcgroupのサブツリーに制限されたビューしか見ることができないことを意味します。
2. CGroup Namespace内のプロセスは、**自分自身のcgroupを階層のルートとして見る**ことができます。つまり、名前空間内のプロセスの視点からは、自分自身のcgroupがルートとして表示され、自分自身のサブツリー以外のcgroupを見ることやアクセスすることはできません。
3. CGroup Namespaceはリソースの直接的な分離を提供しません。**リソースの制御と分離は、cgroupのサブシステム（例：CPU、メモリなど）によって依然として強制されます**。

CGroupsの詳細については、次を参照してください：

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## ラボ：

### 異なる名前空間の作成

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
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
もし`-f`オプションを使ってunshareを実行すると、unshareは新しいpid namespaceを作成した後に新しいプロセスをフォークします。そして、新しいプロセスで`/bin/bash`を実行します。新しいプロセスは新しいpid namespaceのpid 1となります。その後、bashはいくつかのサブプロセスをフォークしてジョブを実行します。bash自体が新しいpid namespaceのpid 1であるため、そのサブプロセスは問題なく終了することができます。

[https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)から転載

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the following command:

プロセスがどの名前空間にあるかを確認するには、次のコマンドを使用します。

```bash
cat /proc/$$/cgroup
```

This command will display the control groups associated with your process, including the cgroup namespace. The output will show the path to the cgroup namespace file, which will indicate the namespace your process is in.

このコマンドは、プロセスに関連するコントロールグループを表示し、cgroup名前空間も含まれます。出力には、cgroup名前空間ファイルへのパスが表示され、プロセスがどの名前空間にあるかを示します。
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### すべてのCGroupの名前空間を見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% code %}

### CGroup ネームスペースに入る

{% endcode %}
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
また、**rootユーザーでなければ他のプロセスの名前空間に入ることはできません**。また、**`/proc/self/ns/cgroup`**のようなディスクリプタがない場合、他の名前空間に**入ることはできません**。

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
