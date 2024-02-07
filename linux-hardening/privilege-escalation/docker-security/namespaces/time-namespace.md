# タイムネームスペース

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) をフォローする**
* **ハッキングテクニックを共有するには、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出してください。

</details>

## 基本情報

Linux のタイムネームスペースは、システムの単調増加時計と起動時刻クロックに対するネームスペースごとのオフセットを可能にします。Linux コンテナでは、コンテナ内の日付/時刻を変更し、チェックポイントやスナップショットから復元した後にクロックを調整するために一般的に使用されます。

## Lab:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -T [--mount-proc] /bin/bash
```
`--mount-proc` パラメータを使用して `/proc` ファイルシステムの新しいインスタンスをマウントすることで、新しいマウント名前空間がその名前空間固有のプロセス情報に正確で隔離されたビューを持つことが保証されます。

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`-f` オプションを指定せずに `unshare` を実行すると、Linux が新しい PID (プロセス ID) 名前空間を処理する方法によりエラーが発生します。主要な詳細と解決策は以下に示されています:

1. **問題の説明**:
- Linux カーネルは、`unshare` システムコールを使用してプロセスが新しい名前空間を作成することを許可します。ただし、新しい PID 名前空間の作成を開始するプロセス（"unshare" プロセスと呼ばれる）は、新しい名前空間に入りません。その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`/bin/bash` が `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID 名前空間にあります。
- 新しい名前空間内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他のプロセスがいない場合、孤児プロセスを引き取る特別な役割を持つ PID 1 により、その名前空間のクリーンアップがトリガーされます。その後、Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:
- 新しい名前空間内の PID 1 の終了により、`PIDNS_HASH_ADDING` フラグのクリーニングが行われます。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てられなくなり、"Cannot allocate memory" エラーが発生します。

3. **解決策**:
- `unshare` に `-f` オプションを使用することで問題を解決できます。このオプションにより、`unshare` は新しい PID 名前空間を作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。その後、`/bin/bash` とその子プロセスはこの新しい名前空間内に安全に含まれ、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを確認することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;あなたのプロセスがどの名前空間にあるかを確認します
```bash
ls -l /proc/self/ns/time
lrwxrwxrwx 1 root root 0 Apr  4 21:16 /proc/self/ns/time -> 'time:[4026531834]'
```
### すべてのTime namespacesを見つける

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name time -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name time -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 時間ネームスペースに入る

{% endcode %}
```bash
nsenter -T TARGET_PID --pid /bin/bash
```
また、**rootユーザーでないと他のプロセスの名前空間に入ることはできません**。そして、他の名前空間に**ディスクリプタ**が指すことなしに**入ることはできません**（例：`/proc/self/ns/net`）。
