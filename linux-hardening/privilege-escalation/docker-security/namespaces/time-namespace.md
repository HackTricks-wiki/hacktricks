# Time Namespace

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>

## 基本情報

Time Namespaceは、システムのモノトニッククロックとブートタイムクロックに対して、名前空間ごとのオフセットを可能にします。Time Namespaceは、コンテナ内で日付/時刻を変更したり、チェックポイント/スナップショットからの復元後にコンテナ内のクロックを調整するために、Linuxコンテナの使用に適しています。

## ラボ:

### 異なるNamespaceを作成する

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
`/proc` ファイルシステムの新しいインスタンスをマウントすることで、`--mount-proc` パラメータを使用すると、新しいマウント名前空間がその名前空間に特有の**正確で隔離されたプロセス情報のビューを持つことを保証します**。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` を `-f` オプションなしで実行すると、Linuxが新しい PID (プロセス ID) 名前空間を扱う方法により、エラーが発生します。重要な詳細と解決策は以下の通りです：

1. **問題の説明**:
- Linuxカーネルは、プロセスが `unshare` システムコールを使用して新しい名前空間を作成することを許可しています。しかし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間での `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他のプロセスがない場合、名前空間のクリーンアップがトリガーされます。なぜなら、PID 1 は孤立したプロセスを引き継ぐ特別な役割を持っているからです。その後、Linuxカーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:
- 新しい名前空間での PID 1 の終了は、`PIDNS_HASH_ADDING` フラグのクリーニングにつながります。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることができず、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` と `-f` オプションを使用することで解決できます。このオプションは、新しい PID 名前空間を作成した後に `unshare` が新しいプロセスをフォークするようにします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。その後、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく操作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどのネームスペースにあるかを確認する
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### すべてのTimeネームスペースを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
{% endcode %}

### Time ネームスペースに入る
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
```markdown
また、**rootでなければ他のプロセスのネームスペースに** **入ることはできません**。そして、それを指すディスクリプタ（`/proc/self/ns/net`のような）**なしに**他のネームスペースに**入ることは** **できません**。

# 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で私を**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有してください**。

</details>
```
