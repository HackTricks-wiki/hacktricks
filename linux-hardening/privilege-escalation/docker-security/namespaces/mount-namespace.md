# マウント名前空間

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

マウント名前空間は、Linuxカーネルの機能であり、一連のプロセスが見るファイルシステムマウントポイントを分離します。各マウント名前空間には独自のファイルシステムマウントポイントがあり、**1つの名前空間でのマウントポイントの変更は他の名前空間に影響を与えません**。これは、異なるマウント名前空間で実行されるプロセスがファイルシステムの階層に異なるビューを持つことを意味します。

マウント名前空間は、コンテナ化に特に有用であり、各コンテナが他のコンテナやホストシステムから分離された独自のファイルシステムと設定を持つ必要がある場合に使用されます。

### 動作原理：

1. 新しいマウント名前空間が作成されると、それは**親名前空間のマウントポイントのコピー**で初期化されます。つまり、作成時に新しい名前空間は親と同じファイルシステムのビューを共有します。ただし、名前空間内のマウントポイントに対する後続の変更は親や他の名前空間に影響を与えません。
2. プロセスが名前空間内のマウントポイントを変更する場合（ファイルシステムのマウントやアンマウントなど）、**変更はその名前空間にローカル**であり、他の名前空間には影響を与えません。これにより、各名前空間が独立したファイルシステムの階層を持つことができます。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`clone()`システムコールを使用して新しい名前空間を作成したりすることができます（`CLONE_NEWNS`フラグを使用）。プロセスが新しい名前空間に移動するか作成すると、その名前空間に関連付けられたマウントポイントを使用し始めます。
4. **ファイルディスクリプタとinodeは名前空間間で共有**されるため、1つの名前空間のプロセスがファイルを指すオープンされたファイルディスクリプタを持っている場合、そのファイルディスクリプタを別の名前空間のプロセスに**渡すことができ**、**両方のプロセスが同じファイルにアクセス**できます。ただし、マウントポイントの違いにより、両方の名前空間でのファイルのパスが同じであるとは限りません。

## ラボ：

### 異なる名前空間の作成

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して、新しい`/proc`ファイルシステムのインスタンスをマウントすることで、新しいマウント名前空間には、その名前空間固有のプロセス情報の正確で分離されたビューが確保されます。

<details>

<summary>エラー：bash: fork: Cannot allocate memory</summary>

`-f`を指定せずに前の行を実行すると、このエラーが発生します。\
このエラーは、新しい名前空間でPID 1プロセスが終了することによって引き起こされます。

bashが実行されると、いくつかの新しいサブプロセスをフォークして何かを実行します。-fを指定せずにunshareを実行すると、bashのPIDは現在の「unshare」プロセスと同じになります。現在の「unshare」プロセスはunshareシステムコールを呼び出し、新しいPID名前空間を作成しますが、現在の「unshare」プロセス自体は新しいPID名前空間に存在しません。これはLinuxカーネルの望ましい動作です：プロセスAが新しい名前空間を作成すると、プロセスA自体は新しい名前空間に配置されず、プロセスAのサブプロセスのみが新しい名前空間に配置されます。したがって、次のコマンドを実行すると：
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
### &#x20;自分のプロセスがどの名前空間にあるかを確認する

To check which namespace your process is in, you can use the `lsns` command. This command lists all the namespaces on the system along with the processes associated with each namespace.

名前空間がどこにあるかを確認するには、`lsns`コマンドを使用します。このコマンドは、システム上のすべての名前空間と、それぞれの名前空間に関連付けられたプロセスを一覧表示します。

```bash
lsns
```

The output will show the different namespaces and their associated processes. Look for the process ID (PID) of your process in the `NSPID` column to determine which namespace it belongs to.

出力には、異なる名前空間とそれに関連するプロセスが表示されます。自分のプロセスのプロセスID（PID）を`NSPID`列で探し、それがどの名前空間に属しているかを確認します。
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
{% code %}

### マウント名前空間に入る

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
また、rootユーザーでない限り、他のプロセスの名前空間には入ることができません。また、`/proc/self/ns/mnt`のようなディスクリプタがない場合、他の名前空間に入ることはできません。

新しいマウントは名前空間内でのみアクセス可能なため、名前空間にはその名前空間からのみアクセス可能な機密情報が含まれている可能性があります。

### 何かをマウントする
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
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
