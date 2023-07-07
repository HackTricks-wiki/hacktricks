# Dockerソケットの悪用による特権エスカレーション

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけて、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションを発見しましょう。

- [**公式のPEASS＆HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**をフォロー**してください。

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>

特権エスカレーションを行いたい場合に、**Dockerソケットにアクセス**できる場合があります。いくつかのアクションは非常に怪しいかもしれず、それらを避けたい場合、特権エスカレーションに役立つさまざまなフラグを見つけることができます。

### マウントを介して

ルートとして実行されているコンテナ内で、**ファイルシステム**の異なる部分を**マウント**して**アクセス**することができます。\
また、**マウントを悪用して特権エスカレーション**することもできます。

* **`-v /:/host`** -> ホストのファイルシステムをコンテナにマウントして、**ホストのファイルシステムを読み取る**ことができます。
* ホストのように**感じる**が、コンテナ内にいる場合には、次のようなフラグを使用して他の防御メカニズムを無効にすることができます：
* `--privileged`
* `--cap-add=ALL`
* `--security-opt apparmor=unconfined`
* `--security-opt seccomp=unconfined`
* `-security-opt label:disable`
* `--pid=host`
* `--userns=host`
* `--uts=host`
* `--cgroupns=host`
* \*\*`--device=/dev/sda1 --cap-add=SYS_ADMIN --security-opt apparmor=unconfined` \*\* -> これは前の方法と似ていますが、ここでは**デバイスディスクをマウント**しています。その後、コンテナ内で `mount /dev/sda1 /mnt` を実行し、`/mnt` で**ホストのファイルシステムにアクセス**できます。
* ホストで `fdisk -l` を実行して、マウントするための `</dev/sda1>` デバイスを見つけます。
* **`-v /tmp:/host`** -> 何らかの理由でホストから**特定のディレクトリのみをマウント**でき、ホスト内でアクセスできる場合は、マウントしてマウントされたディレクトリに **suid** を持つ **`/bin/bash`** を作成し、ホストから実行して特権をエスカレーションさせることができます。

{% hint style="info" %}
おそらく `/tmp` フォルダをマウントすることはできないかもしれませんが、**別の書き込み可能なフォルダ**をマウントすることができます。次のコマンドを使用して書き込み可能なディレクトリを見つけることができます：`find / -writable -type d 2>/dev/null`

**Linuxマシンのすべてのディレクトリがsuidビットをサポートするわけではありません！** suidビットをサポートするディレクトリを確認するには、`mount | grep -v "nosuid"` を実行します。通常、`/dev/shm`、`/run`、`/proc`、`/sys/fs/cgroup`、`/var/lib/lxcfs`はsuidビットをサポートしていません。

また、**`/etc`** または他の構成ファイルを含むフォルダを**マウント**できる場合は、ルートとしてDockerコンテナからそれらを変更して、ホストで**悪用**して特権をエスカレーションさせることができます（たとえば、`/etc/shadow` を変更することができます）。
{% endhint %}

### コンテナからの脱出

* **`--privileged`** -> このフラグを使用すると、コンテナから[すべての分離が削除](docker-privileged.md#what-affects)されます。[特権コンテナからルートとして脱出する](docker-breakout-privilege-escalation/#automatic-enumeration-and-escape)ためのテクニックを確認してください。
* **`--cap-add=<CAPABILITY/ALL> [--security-opt apparmor=unconfined] [--security-opt seccomp=unconfined] [-security-opt label:disable]`** -> [機能を悪用して特権をエスカレーション](../linux-capabilities.md)するために、その機能をコンテナに付与し、エクスプロイトが機能しない可能性のある他の保護方法を無効にします。

### Curl

このページでは、Dockerフラグを使用して特権をエスカレーションする方法について説明しましたが、これらの方法を**curlコマンドを使用して悪用**する方法については、次のページで見つけることができます：

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**した
- **[💬](https://emojipedia.org/speech-balloon/)Discordグループ**に参加するか、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter**で私をフォローする[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください**。

</details>
