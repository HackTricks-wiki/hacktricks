# ネットワーク名前空間

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong>で**ゼロからヒーローまでAWSハッキングを学ぶ**</summary>

HackTricksをサポートする他の方法:

- **HackTricksで企業を宣伝**したい場合や**HackTricksをPDFでダウンロード**したい場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に参加するか、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)をフォローする
- **ハッキングトリックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。

</details>

## 基本情報

ネットワーク名前空間は、Linuxカーネルの機能であり、**各ネットワーク名前空間が独自のネットワーク構成**、インターフェース、IPアドレス、ルーティングテーブル、およびファイアウォールルールを持つようにする分離を提供します。この分離は、コンテナ化などのさまざまなシナリオで有用であり、各コンテナが他のコンテナやホストシステムとは独立したネットワーク構成を持つ必要がある場合に役立ちます。

### 動作方法:

1. 新しいネットワーク名前空間が作成されると、**完全に分離されたネットワークスタック**が開始され、ループバックインターフェース（lo）を除く**ネットワークインターフェースが存在しない**状態となります。これにより、新しいネットワーク名前空間で実行されるプロセスは、デフォルトでは他の名前空間やホストシステムのプロセスと通信できません。
2. vethペアなどの**仮想ネットワークインターフェース**を作成し、ネットワーク名前空間間や名前空間とホストシステム間のネットワーク接続を確立できます。たとえば、vethペアの一方の端をコンテナのネットワーク名前空間に配置し、他方の端を**ブリッジ**またはホスト名前空間の別のネットワークインターフェースに接続して、コンテナにネットワーク接続を提供できます。
3. 名前空間内のネットワークインターフェースは、他の名前空間とは独立して、**独自のIPアドレス、ルーティングテーブル、およびファイアウォールルール**を持つことができます。これにより、異なるネットワーク名前空間のプロセスは、異なるネットワーク構成を持ち、別々のネットワークシステム上で実行されているかのように動作できます。
4. プロセスは、`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`または`CLONE_NEWNET`フラグを使用して`clone()`システムコールを使用して新しい名前空間を作成したりすることができます。プロセスが新しい名前空間に移動したり、新しい名前空間を作成したりすると、その名前空間に関連付けられたネットワーク構成とインターフェースを使用し始めます。

## Lab:

### 異なる名前空間を作成する

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
`--mount-proc`パラメータを使用して`/proc`ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`-f`オプションなしで`unshare`を実行すると、Linuxが新しいPID（プロセスID）名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に示されています:

1. **問題の説明**:
- Linuxカーネルは、`unshare`システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しいPID名前空間の作成を開始するプロセス（「unshare」プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%`を実行すると、`/bin/bash`が`unshare`と同じプロセスで開始されます。その結果、`/bin/bash`とその子プロセスは元のPID名前空間にあります。
- 新しい名前空間内の`/bin/bash`の最初の子プロセスはPID 1になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つPID 1により、その名前空間のクリーンアップがトリガーされます。その後、Linuxカーネルはその名前空間でPIDの割り当てを無効にします。

2. **結果**:
- 新しい名前空間内のPID 1の終了により、`PIDNS_HASH_ADDING`フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に`alloc_pid`関数が新しいPIDを割り当てられなくなり、「Cannot allocate memory」エラーが発生します。

3. **解決策**:
- `unshare`に`-f`オプションを使用することで問題を解決できます。このオプションにより、`unshare`は新しいPID名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%`を実行すると、`unshare`コマンド自体が新しい名前空間でPID 1になります。その後、`/bin/bash`とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1の早期終了を防ぎ、通常のPID割り当てを可能にします。

`unshare`が`-f`フラグで実行されることを確認することで、新しいPID名前空間が正しく維持され、`/bin/bash`とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作するようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### &#x20;あなたのプロセスがどのネームスペースにあるかを確認します
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
### ネットワーク名前空間に入る

{% endcode %}
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に**ディスクリプタ**（`/proc/self/ns/net`のような）を指すことなしに**入ることはできません**。

## 参考文献
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>を通じてゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォロー**する。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出して、**あなたのハッキングテクニックを共有**してください。

</details>
