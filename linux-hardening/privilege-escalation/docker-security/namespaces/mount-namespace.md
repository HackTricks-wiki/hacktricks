# マウント名前空間

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**！</summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする：[**@carlospolopm**](https://twitter.com/carlospolopm)。
- **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>

## 基本情報

マウント名前空間は、Linuxカーネルの機能であり、一群のプロセスが見るファイルシステムマウントポイントを分離する機能を提供します。各マウント名前空間には独自のファイルシステムマウントポイントがあり、**1つの名前空間内でのマウントポイントの変更は他の名前空間に影響を与えません**。これにより、異なるマウント名前空間で実行されるプロセスは、ファイルシステム階層の異なるビューを持つことができます。

マウント名前空間は、コンテナ化において特に有用であり、各コンテナが他のコンテナやホストシステムから分離された独自のファイルシステムと構成を持つべきです。

### 動作方法：

1. 新しいマウント名前空間が作成されると、**親名前空間からマウントポイントのコピーが初期化**されます。これは、作成時に新しい名前空間が親と同じファイルシステムビューを共有していることを意味します。ただし、名前空間内のマウントポイントに対する後続の変更は、親または他の名前空間に影響を与えません。
2. プロセスが名前空間内のマウントポイントを変更すると（ファイルシステムをマウントまたはアンマウントするなど）、**その名前空間内での変更はローカル**であり、他の名前空間に影響を与えません。これにより、各名前空間が独自のファイルシステム階層を持つことができます。
3. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`CLONE_NEWNS`フラグを使用して`clone()`システムコールを使用して新しい名前空間を作成したりすることができます。プロセスが新しい名前空間に移動したり作成したりすると、その名前空間に関連付けられたマウントポイントを使用し始めます。
4. **ファイルディスクリプタとinodeは名前空間間で共有**されるため、1つの名前空間のプロセスがファイルを指すオープンファイルディスクリプタを持っている場合、そのファイルディスクリプタを別の名前空間のプロセスに**渡す**ことができ、**両方のプロセスが同じファイルにアクセス**できます。ただし、マウントポイントの違いにより、両方の名前空間でのファイルのパスが同じでない場合があります。 

## Lab:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`unshare`を`-f`オプションなしで実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に示されています：

1. **問題の説明**：
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1により、その名前空間のクリーンアップがトリガーされます。その後、Linuxカーネルはその名前空間でのPID割り当てを無効にします。

2. **結果**：
- 新しい名前空間内のPID 1の終了により、`PIDNS_HASH_ADDING`フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てられなくなり、「Cannot allocate memory」エラーが発生します。

3. **解決策**：
- `unshare`に`-f`オプションを使用することで問題を解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間でPID 1になります。その後、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作するようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;あなたのプロセスがどの名前空間にあるかを確認します
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
### マウント名前空間に入る

{% endcode %}
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に**ディスクリプタ**（`/proc/self/ns/mnt`のような）を指すことなしに**入ることはできません**。

新しいマウントは名前空間内でのみアクセス可能なため、名前空間には名前空間からのみアクセス可能な機密情報が含まれている可能性があります。

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
## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を**フォロー**する。
* **HackTricks** と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに PR を提出して、あなたのハッキングテクニックを共有してください。

</details>
