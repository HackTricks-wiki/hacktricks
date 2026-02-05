# UTS 名前空間

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

UTS（UNIX Time-Sharing System）名前空間は、Linuxカーネルの機能で、**2つのシステム識別子の分離**を提供します: **ホスト名** と **NIS** (Network Information Service) のドメイン名。 この分離により、各UTS名前空間は**それぞれ独立したホスト名とNISドメイン名**を持つことができ、特に各コンテナが独立したシステムとして振る舞うことが望まれるコンテナ化の状況で有用です。

### 仕組み:

1. 新しいUTS名前空間が作成されると、親名前空間からの**ホスト名とNISドメイン名のコピー**で開始されます。つまり、作成時点では新しい名前空間は**親と同じ識別子を共有します**。ただし、その名前空間内でホスト名やNISドメイン名に対して行われた以降の変更は他の名前空間には影響しません。
2. UTS名前空間内のプロセスは、`sethostname()` および `setdomainname()` システムコールを使用して、**ホスト名とNISドメイン名を変更することができます**。これらの変更はその名前空間にローカルなものであり、他の名前空間やホストシステムには影響しません。
3. プロセスは `setns()` システムコールを使って名前空間間を移動したり、`unshare()` や `clone()` システムコール（`CLONE_NEWUTS` フラグ付き）を使って新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか作成すると、その名前空間に関連付けられたホスト名とNISドメイン名を使い始めます。

## ラボ:

### 異なる名前空間の作成

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **その namespace 固有のプロセス情報を正確かつ隔離された形で参照できる**.

<details>

<summary>エラー: bash: fork: Cannot allocate memory</summary>

`unshare` を `-f` オプションなしで実行すると、Linux が新しい PID (Process ID) namespace を扱う方法に起因するエラーが発生します。主なポイントと解決策を以下に示します:

1. **問題の説明**:

- Linux カーネルは `unshare` システムコールでプロセスが新しい namespace を作成することを許可します。ただし、新しい PID namespace の作成を開始したプロセス（"unshare" プロセスと呼ぶ）は新しい namespace に入らず、その子プロセスだけが入ります。
- %unshare -p /bin/bash% を実行すると、`/bin/bash` は `unshare` と同じプロセスで開始されます。その結果、`/bin/bash` とその子プロセスは元の PID namespace に属することになります。
- 新しい namespace 内での `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、PID 1 は孤児プロセスの引き受け等の特別な役割を持つため、他にプロセスがなければ namespace のクリーンアップが発生します。すると Linux カーネルはその namespace での PID 割り当てを無効にします。

2. **結果**:

- 新しい namespace で PID 1 が終了すると `PIDNS_HASH_ADDING` フラグのクリーンアップが行われます。その結果、プロセス作成時に `alloc_pid` が新しい PID を割り当てられなくなり、"Cannot allocate memory" エラーが発生します。

3. **解決策**:
- この問題は `unshare` に `-f` オプションを付けることで解決できます。このオプションは新しい PID namespace を作成した後に `unshare` をフォークさせます。
- %unshare -fp /bin/bash% を実行すると、`unshare` コマンド自体が新しい namespace で PID 1 になります。これにより `/bin/bash` とその子プロセスは新しい namespace 内に安全に収まり、PID 1 の早期終了を防いで通常の PID 割り当てが可能になります。

`unshare` を `-f` フラグ付きで実行することで、新しい PID namespace は正しく維持され、`/bin/bash` とそのサブプロセスはメモリ割り当てエラーに遭遇することなく動作できます。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどの namespace にいるか確認する
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### すべての UTS namespaces を見つける
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### UTS namespace に入る
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## ホストの UTS 共有の悪用

`--uts=host` でコンテナを起動すると、分離された UTS 名前空間を取得する代わりにホストの UTS 名前空間に参加します。`--cap-add SYS_ADMIN` のような capabilities があると、コンテナ内のコードは `sethostname()`/`setdomainname()` を使ってホストの hostname/NIS name を変更できます：
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
ホスト名を変更すると、ログやアラートを改ざんしたり、クラスタの検出を混乱させたり、ホスト名を固定している TLS/SSH 設定を破損させる可能性があります。

### ホストと UTS を共有しているコンテナを検出する
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
