<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい** 場合は [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)、当社の独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) コレクションを発見する
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) に参加するか、[**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする。
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する。

</details>


# Sudo/Admin グループ

## **PE - 方法1**

**時々**、**デフォルトで \(またはあるソフトウェアが必要とするために\)** **/etc/sudoers** ファイルの中にこれらの行のいくつかが見つかることがあります:
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに属するユーザーはsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには単に実行するだけです**:
```text
sudo su
```
## PE - 方法2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します：
```bash
find / -perm -4000 2>/dev/null
```
もしバイナリpkexecがSUIDバイナリであり、sudoまたはadminに所属している場合、pkexecを使用してsudoとしてバイナリを実行できる可能性があります。
次の内容を確認してください：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
以下では、どのグループが**pkexec**を実行することが許可されており、そして**デフォルトで**いくつかのLinuxには**sudo**や**admin**のグループが登録されていることがあります。

**rootになるためには、次のコマンドを実行します**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
**Translation:**
もし**pkexec**を実行しようとして、この**エラー**が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないわけではなく、GUIなしで接続されていないため**です。この問題には回避策があります: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**異なる2つのsshセッション**が必要です:

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

# Wheel Group

**時々**、**デフォルトで**、**/etc/sudoers**ファイルの中にこの行が見つかることがあります：
```text
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに属するユーザーはsudoとして何でも実行できる**ことを意味します。

この場合、**rootになるには単に実行するだけです**:
```text
sudo su
```
# シャドウグループ

**group shadow**のユーザーは**/etc/shadow**ファイルを**読む**ことができます。
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
## ディスクグループ

この権限は、マシン内のすべてのデータにアクセスできるため、ほぼ**rootアクセスに等しい**です。

ファイル：`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
debugfsを使用して**ファイルを書き込む**こともできます。たとえば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、**rootが所有するファイルを書き込もうとする**と（例：`/etc/shadow`や`/etc/passwd`）、**Permission denied**エラーが発生します。

# Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、以下のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiがマシンの端末に物理的にログイン**していることを意味します。

**videoグループ**は、画面出力を表示する権限を持っています。基本的に、画面を観察することができます。これを行うためには、画面上の現在のイメージを生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**ルートグループ**

デフォルトでは、**ルートグループのメンバー**は、特権を昇格させるのに使用できる**一部のサービス**構成ファイルや**ライブラリ**ファイル、または**その他の興味深いもの**を変更できる可能性があります...

**ルートメンバーが変更できるファイルを確認**します:
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker Group

ホストマシンのルートファイルシステムをインスタンスのボリュームにマウントできるため、インスタンスが起動するとすぐにそのボリュームに `chroot` をロードします。これにより、実質的にマシンで root 権限を取得できます。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd Group

[lxc - 特権昇格](lxd-privilege-escalation.md)



<details>

<summary><strong>ゼロからヒーローまでのAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks で企業を宣伝したい** または **HackTricks をPDFでダウンロードしたい場合は** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop) をチェックしてください！
* [**公式PEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f) または [**telegramグループ**](https://t.me/peass) に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live) をフォローする**
* **ハッキングトリックを共有するために** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のGitHubリポジトリにPRを提出する

</details>
