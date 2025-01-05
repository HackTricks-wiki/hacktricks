# マウントネームスペース

{{#include ../../../../banners/hacktricks-training.md}}

## 基本情報

マウントネームスペースは、プロセスのグループが見るファイルシステムのマウントポイントの隔離を提供するLinuxカーネルの機能です。各マウントネームスペースは独自のファイルシステムマウントポイントのセットを持ち、**あるネームスペースのマウントポイントへの変更は他のネームスペースに影響を与えません**。これは、異なるマウントネームスペースで実行されているプロセスがファイルシステム階層の異なるビューを持つことができることを意味します。

マウントネームスペースは特にコンテナ化において便利であり、各コンテナは他のコンテナやホストシステムから隔離された独自のファイルシステムと設定を持つべきです。

### 仕組み:

1. 新しいマウントネームスペースが作成されると、**親ネームスペースからのマウントポイントのコピーで初期化されます**。これは、作成時に新しいネームスペースが親と同じファイルシステムのビューを共有することを意味します。しかし、その後のネームスペース内のマウントポイントへの変更は、親や他のネームスペースに影響を与えません。
2. プロセスがそのネームスペース内のマウントポイントを変更すると、例えばファイルシステムをマウントまたはアンマウントする場合、**変更はそのネームスペースにローカルであり**、他のネームスペースには影響を与えません。これにより、各ネームスペースは独自の独立したファイルシステム階層を持つことができます。
3. プロセスは`setns()`システムコールを使用してネームスペース間を移動することができ、`unshare()`または`clone()`システムコールを`CLONE_NEWNS`フラグと共に使用して新しいネームスペースを作成することができます。プロセスが新しいネームスペースに移動するか、新しいネームスペースを作成すると、そのネームスペースに関連付けられたマウントポイントを使用し始めます。
4. **ファイルディスクリプタとinodeはネームスペース間で共有されます**。つまり、あるネームスペースのプロセスがファイルを指すオープンファイルディスクリプタを持っている場合、その**ファイルディスクリプタを他のネームスペースのプロセスに渡すことができ**、**両方のプロセスが同じファイルにアクセスします**。ただし、マウントポイントの違いにより、ファイルのパスは両方のネームスペースで同じではない場合があります。

## ラボ:

### 異なるネームスペースを作成する

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
新しいインスタンスの `/proc` ファイルシステムを `--mount-proc` パラメータを使用してマウントすることで、新しいマウントネームスペースがそのネームスペースに特有のプロセス情報の**正確で孤立したビュー**を持つことを保証します。

<details>

<summary>エラー: bash: fork: メモリを割り当てることができません</summary>

`unshare` が `-f` オプションなしで実行されると、Linux が新しい PID (プロセス ID) ネームスペースを処理する方法のためにエラーが発生します。重要な詳細と解決策は以下に示されています。

1. **問題の説明**:

- Linux カーネルは、プロセスが `unshare` システムコールを使用して新しいネームスペースを作成することを許可します。しかし、新しい PID ネームスペースの作成を開始するプロセス（「unshare」プロセスと呼ばれる）は新しいネームスペースに入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると、`unshare` と同じプロセスで `/bin/bash` が開始されます。その結果、`/bin/bash` とその子プロセスは元の PID ネームスペースに存在します。
- 新しいネームスペース内の `/bin/bash` の最初の子プロセスは PID 1 になります。このプロセスが終了すると、他にプロセスがない場合、PID 1 が孤児プロセスを引き取る特別な役割を持っているため、ネームスペースのクリーンアップがトリガーされます。Linux カーネルはそのネームスペース内での PID 割り当てを無効にします。

2. **結果**:

- 新しいネームスペース内での PID 1 の終了は、`PIDNS_HASH_ADDING` フラグのクリーンアップを引き起こします。これにより、新しいプロセスを作成する際に `alloc_pid` 関数が新しい PID を割り当てることに失敗し、「メモリを割り当てることができません」というエラーが発生します。

3. **解決策**:
- この問題は、`unshare` に `-f` オプションを使用することで解決できます。このオプションにより、`unshare` は新しい PID ネームスペースを作成した後に新しいプロセスをフォークします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しいネームスペース内で PID 1 になります。これにより、`/bin/bash` とその子プロセスはこの新しいネームスペース内に安全に収容され、PID 1 の早期終了を防ぎ、通常の PID 割り当てを可能にします。

`unshare` が `-f` フラグで実行されることを保証することで、新しい PID ネームスペースが正しく維持され、`/bin/bash` とそのサブプロセスがメモリ割り当てエラーに遭遇することなく動作できるようになります。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどの名前空間にあるかを確認する
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### すべてのマウントネームスペースを見つける
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### マウントネームスペースに入る
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
また、**ルートでなければ他のプロセスの名前空間に入ることはできません**。そして、**ディスクリプタ**がそれを指していない限り（例えば `/proc/self/ns/mnt`）、他の名前空間に**入ることはできません**。

新しいマウントは名前空間内でのみアクセス可能であるため、名前空間にはそれからのみアクセス可能な機密情報が含まれている可能性があります。

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

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## 参考文献

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
