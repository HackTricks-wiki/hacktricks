# Dockerソケットの悪用による権限昇格

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>

Dockerソケットに**アクセスできる**場合があり、それを使用して**権限を昇格**したいと思うことがあります。いくつかのアクションは非常に怪しいかもしれませんので、避けたいと思うかもしれません。ここでは、権限を昇格するために役立つさまざまなフラグを見つけることができます：

### マウントを介して

rootとして実行されているコンテナ内で**ファイルシステム**の異なる部分を**マウント**し、それらに**アクセス**することができます。\
また、コンテナ内で権限を昇格するためにマウントを**悪用**することもできます。

* **`-v /:/host`** -> ホストファイルシステムをコンテナにマウントして、**ホストファイルシステムを読む**ことができます。
* コンテナにいながら**ホストにいるように感じたい**場合は、以下のようなフラグを使用して他の防御メカニズムを無効にすることができます：
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> これは前述の方法と似ていますが、ここでは**デバイスディスクをマウント**しています。その後、コンテナ内で`mount /dev/sda1 /mnt`を実行し、`/mnt`で**ホストファイルシステムにアクセス**できます。
* マウントする`</dev/sda1>`デバイスを見つけるためにホストで`fdisk -l`を実行します。
* **`-v /tmp:/host`** -> 何らかの理由でホストのディレクトリを**マウントすることしかできない**場合、それをマウントして、マウントされたディレクトリに**suidを持つ`/bin/bash`**を作成し、ホストから実行して**rootに昇格**します。

{% hint style="info" %}
`/tmp`フォルダをマウントできないかもしれませんが、**異なる書き込み可能なフォルダ**をマウントできることに注意してください。書き込み可能なディレクトリを見つけるには、`find / -writable -type d 2>/dev/null`を使用します。

**すべてのディレクトリがsuidビットをサポートしているわけではないことに注意してください！** suidビットをサポートするディレクトリを確認するには、`mount | grep -v "nosuid"`を実行します。例えば通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs`はsuidビットをサポートしていません。

また、**`/etc`**や他の**設定ファイルを含むフォルダ**を**マウントできる**場合、dockerコンテナ内でrootとしてそれらを変更し、ホストで**悪用して権限を昇格**することができます（例えば`/etc/shadow`を変更することによって）
{% endhint %}

### コンテナからの脱出

* **`--privileged`** -> このフラグを使用すると、[コンテナからすべての隔離を取り除く](docker-privileged.md#what-affects)ことができます。rootとして[特権コンテナから脱出する](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)テクニックを確認してください。
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [機能を悪用して権限を昇格する](../linux-capabilities.md)ために、**その機能をコンテナに付与**し、エクスプロイトが機能するのを防ぐ可能性のある他の保護方法を無効にします。

### Curl

このページでは、dockerフラグを使用して権限を昇格する方法について議論しました。curlコマンドを使用してこれらの方法を悪用する方法については、以下のページで見つけることができます：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><strong>htARTE (HackTricks AWS Red Team Expert)でAWSハッキングをゼロからヒーローまで学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有する。

</details>
