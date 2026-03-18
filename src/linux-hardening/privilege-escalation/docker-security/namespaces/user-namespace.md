# ユーザー名前空間

{{#include ../../../../banners/hacktricks-training.md}}

{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 参考資料

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)



## 基本情報

ユーザー名前空間は、Linux カーネルの機能で、**ユーザーおよびグループIDのマッピングを分離（隔離）**し、各ユーザー名前空間が**独自のユーザーおよびグループIDのセット**を持つことを可能にします。この分離により、異なるユーザー名前空間で動作するプロセスは、数値的に同じユーザーおよびグループIDを共有していても、**異なる特権や所有権**を持つことができます。

ユーザー名前空間はコンテナ化で特に有用であり、各コンテナが独立したユーザーおよびグループIDのセットを持つことを可能にして、コンテナ間およびホストシステムとの間でより良いセキュリティと隔離を実現します。

### 仕組み:

1. 新しいユーザー名前空間が作成されると、それは**ユーザーおよびグループIDのマッピングが空の状態から始まります**。これは、新しいユーザー名前空間内で動作するプロセスは**当初は名前空間の外部での特権を持たない**ことを意味します。
2. 新しい名前空間内のユーザーおよびグループIDと、親（またはホスト）名前空間内のIDとの間でIDマッピングを確立できます。これにより、**新しい名前空間内のプロセスが親名前空間のユーザーおよびグループIDに対応する権限や所有権を持つことができます**。ただし、IDマッピングは特定の範囲やIDのサブセットに制限できるため、新しい名前空間内のプロセスに付与される特権を細かく制御できます。
3. ユーザー名前空間内では、**プロセスは名前空間内部での操作に対して完全なroot特権（UID 0）を持つことができます**が、名前空間の外部では制限された特権しか持ちません。これにより、**コンテナはホスト上で完全なroot特権を持つことなく、自分の名前空間内ではrootに近い能力で実行できます**。
4. プロセスは`setns()`システムコールを使用して名前空間間を移動したり、`unshare()`や`clone()`システムコールと`CLONE_NEWUSER`フラグを使って新しい名前空間を作成したりできます。プロセスが新しい名前空間に移動するか、名前空間を作成すると、その名前空間に関連付けられたユーザーおよびグループIDマッピングの使用を開始します。

## ラボ:

### 異なる名前空間を作成

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **その名前空間固有のプロセス情報を正確かつ分離された形で参照できる**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **問題の説明**:

- Linux カーネルは `unshare` システムコールを使ってプロセスが新しい名前空間を作成することを許可します。ただし、新しい PID 名前空間の作成を開始したプロセス（「unshare」プロセスと呼ぶ）は新しい名前空間に入らず、その子プロセスのみが入ります。
- `%unshare -p /bin/bash%` を実行すると `/bin/bash` は `unshare` と同じプロセスとして起動します。したがって `/bin/bash` とその子プロセスは元の PID 名前空間にいます。
- 新しい名前空間内で `/bin/bash` の最初の子プロセスが PID 1 になります。このプロセスが終了すると、他にプロセスがなければ名前空間のクリーンアップが行われます。PID 1 は孤児プロセスの引受けという特別な役割を持つためです。その後、Linux カーネルはその名前空間での PID 割り当てを無効にします。

2. **結果**:

- 新しい名前空間で PID 1 が終了すると `PIDNS_HASH_ADDING` フラグがクリアされます。その結果、`alloc_pid` 関数が新しいプロセス作成時に PID を割り当てられず、"Cannot allocate memory" エラーが発生します。

3. **解決策**:
- `unshare` に `-f` オプションを付けることで問題を解決できます。このオプションは新しい PID 名前空間を作成した後に `unshare` が新しいプロセスを fork するようにします。
- `%unshare -fp /bin/bash%` を実行すると、`unshare` コマンド自体が新しい名前空間で PID 1 になります。これにより `/bin/bash` とその子プロセスはその新しい名前空間に安全に収容され、PID 1 の早期終了が防がれ通常の PID 割り当てが可能になります。

`unshare` を `-f` フラグ付きで実行することで、新しい PID 名前空間が正しく維持され、`/bin/bash` とそのサブプロセスはメモリ割り当てエラーに遭遇することなく動作できます。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
user namespaceを使用するには、Dockerデーモンを**`--userns-remap=default`**付きで起動する必要があります（ubuntu 14.04では、`/etc/default/docker` を編集し、`sudo service docker restart` を実行することで設定できます）

### 自分のプロセスがどの namespace にいるか確認する
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
docker コンテナから user map を確認できます:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
またはホストからは次のコマンドで:
```bash
cat /proc/<pid>/uid_map
```
### すべてのユーザー名前空間を見つける
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### User namespace に入る
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
また、**rootである場合に限り別のプロセス namespace に入ることができます**。そして、他の namespace に**入る**にはそれを指す**descriptor**（例: `/proc/self/ns/user`）がないと**できません**。

### 新しい User namespace (with mappings) を作成する
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```

```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### 非特権 UID/GID マッピングルール

`uid_map`/`gid_map` に書き込むプロセスが親ユーザー名前空間で **CAP_SETUID/CAP_SETGID を持っていない** 場合、kernel はより厳しいルールを適用します: 呼び出し元の実効 UID/GID に対しては **単一のマッピング** しか許可されず、`gid_map` については **まず `setgroups(2)` を無効化する必要があり**、そのために `/proc/<pid>/setgroups` に `deny` と書き込まなければなりません。
```bash
# Check whether setgroups is allowed in this user namespace
cat /proc/self/setgroups   # allow|deny

# For unprivileged gid_map writes, disable setgroups first
echo deny > /proc/self/setgroups
```
### ID-mapped Mounts (MOUNT_ATTR_IDMAP)

ID-mapped mountsは、マウントにuser namespaceのマッピングを付与することで、そのマウント経由でアクセスした際にファイル所有権がリマップされます。これはcontainer runtimes（特にrootless）で、ユーザー namespace のUID/GID変換を維持しつつ、再帰的な`chown`なしでホストのパスを共有するためによく使われます。

攻撃的な観点では、**もしmount namespaceを作成し、user namespace内で`CAP_SYS_ADMIN`を保持でき、かつファイルシステムがID-mapped mountsをサポートしている**なら、bind mountsの所有権のビューをリマップできます。これはディスク上の所有権を変更するものではありませんが、通常は書き込み不可のファイルでも、そのnamespace内ではマップされたUID/GIDの所有に見せかけることが可能です。

### 権限の回復

user namespaceの場合、**新しいuser namespaceが作成され、そのnamespaceに入るプロセスにはそのnamespace内でのフルセットのcapabilitiesが付与されます**。これらのcapabilitiesにより、プロセスはファイルシステムのマウント、デバイスの作成、ファイルの所有権変更などの特権操作を実行できますが、**それらはあくまで自身のuser namespaceのコンテキスト内に限定されます**。

例えば、user namespace内で`CAP_SYS_ADMIN` capabilityを持っている場合、このcapabilityを通常必要とする操作（例: ファイルシステムのマウント）を実行できますが、それはあくまで自身のuser namespaceのコンテキスト内に限られます。これらの操作はホストシステムや他のnamespacesには影響を与えません。

> [!WARNING]
> したがって、新しいUser namespace内にプロセスを入れることで**すべてのcapabilitiesが戻される** (CapEff: 000001ffffffffff) としても、実際に使用できるのは**namespaceに関連するものだけ**（例えばmount）であり、すべてのcapabilityが使えるわけではありません。したがって、これだけではDockerコンテナからの脱出には十分ではありません。
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
```
{{#ref}}
../docker-breakout-privilege-escalation/README.md
{{#endref}}


## 参考文献

- [https://man7.org/linux/man-pages/man7/user_namespaces.7.html](https://man7.org/linux/man-pages/man7/user_namespaces.7.html)
- [https://man7.org/linux/man-pages/man2/mount_setattr.2.html](https://man7.org/linux/man-pages/man2/mount_setattr.2.html)

{{#include ../../../../banners/hacktricks-training.md}}
