# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

UTS (UNIX Time-Sharing System) namespace は、Linux カーネルの機能で、**2つのシステム識別子の分離**、つまり **hostname** と **NIS (Network Information Service)** ドメイン名を提供します。この分離により、各 UTS namespace は**独立した hostname と NIS ドメイン名を持つ**ことができ、各コンテナが独立したシステムとして自身の hostname を持つように見せる必要があるコンテナ化の状況で特に有用です。

### How it works:

1. 新しい UTS namespace が作成されるとき、親 namespace から **hostname と NIS ドメイン名のコピーを受け継ぎます**。つまり、作成時点では新しい namespace は親と**同じ識別子を共有します**。ただし、その後に namespace 内で行われた hostname や NIS ドメイン名の変更は他の namespace に影響を与えません。
2. UTS namespace 内のプロセスは、`sethostname()` および `setdomainname()` システムコールを使用して **hostname と NIS ドメイン名を変更することができます**。これらの変更はその namespace にローカルであり、他の namespace やホストシステムには影響しません。
3. プロセスは `setns()` システムコールを使用して namespace 間を移動したり、`unshare()` や `clone()` システムコールを `CLONE_NEWUTS` フラグ付きで呼び出して新しい namespace を作成したりできます。プロセスが新しい namespace に移動するか作成すると、その namespace に紐づいた hostname と NIS ドメイン名を使用し始めます。

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
By mounting a new instance of the `/proc` filesystem if you use the param `--mount-proc`, you ensure that the new mount namespace has an **accurate and isolated view of the process information specific to that namespace**.

<details>

<summary>Error: bash: fork: Cannot allocate memory</summary>

When `unshare` is executed without the `-f` option, an error is encountered due to the way Linux handles new PID (Process ID) namespaces. The key details and the solution are outlined below:

1. **Problem Explanation**:

- The Linux kernel allows a process to create new namespaces using the `unshare` system call. However, the process that initiates the creation of a new PID namespace (referred to as the "unshare" process) does not enter the new namespace; only its child processes do.
- Running `%unshare -p /bin/bash%` starts `/bin/bash` in the same process as `unshare`. Consequently, `/bin/bash` and its child processes are in the original PID namespace.
- The first child process of `/bin/bash` in the new namespace becomes PID 1. When this process exits, it triggers the cleanup of the namespace if there are no other processes, as PID 1 has the special role of adopting orphan processes. The Linux kernel will then disable PID allocation in that namespace.

2. **Consequence**:

- The exit of PID 1 in a new namespace leads to the cleaning of the `PIDNS_HASH_ADDING` flag. This results in the `alloc_pid` function failing to allocate a new PID when creating a new process, producing the "Cannot allocate memory" error.

3. **Solution**:
- The issue can be resolved by using the `-f` option with `unshare`. This option makes `unshare` fork a new process after creating the new PID namespace.
- Executing `%unshare -fp /bin/bash%` ensures that the `unshare` command itself becomes PID 1 in the new namespace. `/bin/bash` and its child processes are then safely contained within this new namespace, preventing the premature exit of PID 1 and allowing normal PID allocation.

By ensuring that `unshare` runs with the `-f` flag, the new PID namespace is correctly maintained, allowing `/bin/bash` and its sub-processes to operate without encountering the memory allocation error.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### プロセスがどの namespace に属しているかを確認する
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
### UTS namespace の中に入る
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
## ホスト UTS 共有の悪用

コンテナが `--uts=host` で起動されると、隔離された UTS 名前空間が与えられるのではなく、ホストの UTS 名前空間に参加します。`--cap-add SYS_ADMIN` のような capabilities を持つと、コンテナ内のコードは `sethostname()`/`setdomainname()` を使ってホストの hostname/NIS 名を変更できます:
```bash
docker run --rm -it --uts=host --cap-add SYS_ADMIN alpine sh -c "hostname hacked-host && exec sh"
# Hostname on the host will immediately change to "hacked-host"
```
ホスト名を変更すると、ログやアラートを改ざんしたり、クラスタ検出を混乱させたり、ホスト名を固定している TLS/SSH の設定を破損させる可能性があります。

### ホストと UTS を共有しているコンテナを検出する
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
# Shows "host" when the container uses the host UTS namespace
```
{{#include ../../../../banners/hacktricks-training.md}}
