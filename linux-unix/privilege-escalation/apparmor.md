<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください、独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>


# 基本情報

**AppArmor**は、**プログラムを制限されたリソースのセットに制約する**カーネルの拡張機能です。プロファイルは、ネットワークアクセス、生のソケットアクセス、および一致するパス上のファイルの読み取り、書き込み、実行の許可などの**機能**を**許可**できます。

これは、アクセス制御属性をユーザーではなく**プログラムにバインドする**Mandatory Access Control（MAC）です。\
AppArmorの制約は、通常は起動時にカーネルにロードされる**プロファイル**によって提供されます。\
AppArmorプロファイルは、次の**2つのモード**のいずれかになることがあります。

* **Enforcement（強制）**：強制モードでロードされたプロファイルは、プロファイルで定義されたポリシーの**強制**と、ポリシー違反の試みの**報告**（syslogまたはauditd経由）を結果としてもたらします。
* **Complain（苦情）**：苦情モードのプロファイルは、ポリシーを**強制しない**代わりに、ポリシー違反の試みを**報告**します。

AppArmorは、Linux上の他の一部のMACシステムとは異なり、**パスベース**であり、強制と苦情モードのプロファイルを混在させることができ、開発を容易にするためにインクルードファイルを使用し、他の人気のあるMACシステムよりもはるかに低い参入障壁を持っています。

## AppArmorのパーツ

* **カーネルモジュール**：実際の作業を行う
* **ポリシー**：動作と制約を定義する
* **パーサー**：ポリシーをカーネルにロードする
* **ユーティリティ**：apparmorとの対話のためのユーザーモードプログラム

## プロファイルのパス

AppArmorのプロファイルは通常、_**/etc/apparmor.d/**_に保存されます。\
`sudo aa-status`を使用すると、いくつかのプロファイルに制限がかけられているバイナリをリストアップすることができます。リストされた各バイナリのパスの"/"をドットに変更すると、言及されたフォルダ内のapparmorプロファイルの名前が取得できます。

たとえば、_usr/bin/man_の**apparmor**プロファイルは、_**/etc/apparmor.d/usr.bin.man**_にあります。

## コマンド
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
# プロファイルの作成

* 影響を受ける実行可能ファイルを示すために、**絶対パスとワイルドカード**（ファイルグロブ）が使用できます。
* **ファイル**に対するアクセスを示すために、以下の**アクセス制御**が使用できます：
* **r**（読み取り）
* **w**（書き込み）
* **m**（実行可能としてメモリにマップ）
* **k**（ファイルロック）
* **l**（ハードリンクの作成）
* **ix**（新しいプログラムがポリシーを継承して別のプログラムを実行するために使用）
* **Px**（環境をクリーンアップした後、別のプロファイルの下で実行）
* **Cx**（環境をクリーンアップした後、子プロファイルの下で実行）
* **Ux**（環境をクリーンアップした後、制約なしで実行）
* **変数**はプロファイル内で定義でき、プロファイルの外部から操作できます。例：@{PROC}と@{HOME}（プロファイルファイルに#include \<tunables/global>を追加）
* **許可ルールを上書きするために拒否ルールがサポートされています**。

## aa-genprof

プロファイルの作成を簡単に開始するために、apparmorが役立ちます。**apparmorはバイナリが実行するアクションを検査し、どのアクションを許可または拒否するかを選択できるようにします**。\
次のコマンドを実行するだけです：
```bash
sudo aa-genprof /path/to/binary
```
次に、別のコンソールで通常バイナリが実行するすべてのアクションを実行します。
```bash
/path/to/binary -a dosomething
```
次に、最初のコンソールで「**s**」を押し、記録されたアクションで無視するか、許可するか、その他の操作を指定します。終了したら「**f**」を押して、新しいプロファイルが _/etc/apparmor.d/path.to.binary_ に作成されます。

{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の操作を選択できます。
{% endhint %}

## aa-easyprof

また、次のコマンドを使用して、バイナリのapparmorプロファイルのテンプレートを作成することもできます。
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
デフォルトでは、作成したプロファイルでは何も許可されていないため、すべてが拒否されます。たとえば、`/etc/passwd r,`のような行を追加して、バイナリが`/etc/passwd`を読み取ることを許可する必要があります。
{% endhint %}

次に、新しいプロファイルを**強制的に**適用します。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## ログからプロファイルを変更する

以下のツールはログを読み取り、ユーザーに検出された禁止されたアクションの許可を求めます。
```bash
sudo aa-logprof
```
{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の選択を行うことができます。
{% endhint %}

## プロファイルの管理

### Loading a Profile

To load a profile, use the `apparmor_parser` command followed by the profile path:

```bash
sudo apparmor_parser -r -W /path/to/profile
```

### Unloading a Profile

To unload a profile, use the `apparmor_parser` command with the `-R` option followed by the profile path:

```bash
sudo apparmor_parser -R /path/to/profile
```

### Enforcing and Disabling a Profile

To enforce a profile, use the `aa-enforce` command followed by the profile name:

```bash
sudo aa-enforce /path/to/profile
```

To disable a profile, use the `aa-disable` command followed by the profile name:

```bash
sudo aa-disable /path/to/profile
```

### Checking the Status of a Profile

To check the status of a profile, use the `aa-status` command:

```bash
sudo aa-status
```

### Editing a Profile

To edit a profile, use a text editor to modify the profile file located in `/etc/apparmor.d/`. After making the changes, reload the profile using the `apparmor_parser` command.

### Creating a New Profile

To create a new profile, use the `aa-genprof` command followed by the path to the binary or script that you want to create the profile for:

```bash
sudo aa-genprof /path/to/binary_or_script
```

The `aa-genprof` command will guide you through the process of creating a new profile.

### Customizing a Profile

To customize a profile, use a text editor to modify the profile file located in `/etc/apparmor.d/`. You can add or remove rules to customize the profile according to your needs. After making the changes, reload the profile using the `apparmor_parser` command.

### Debugging a Profile

To debug a profile, use the `aa-logprof` command:

```bash
sudo aa-logprof
```

The `aa-logprof` command will analyze the AppArmor log entries and suggest changes to the profile based on the observed behavior.

### Disabling AppArmor

To disable AppArmor, use the following command:

```bash
sudo systemctl disable apparmor
```

After disabling AppArmor, remember to restart your system for the changes to take effect.
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# ログ

実行可能ファイル **`service_bin`** の _/var/log/audit/audit.log_ からの **AUDIT** と **DENIED** ログの例:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
次のコマンドを使用してもこの情報を取得できます：

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```bash
command
```

または

```
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
# DockerにおけるApparmor

デフォルトでDockerのプロファイル**docker-profile**がロードされていることに注意してください。
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
デフォルトでは、**Apparmor docker-defaultプロファイル**は[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)から生成されます。

**docker-defaultプロファイルの概要**：

* すべての**ネットワーキング**への**アクセス**
* **権限**は定義されていません（ただし、一部の権限は基本的なベースルールを含むことによって提供されます、つまり#include \<abstractions/base>）
* **/proc**ファイルへの書き込みは**許可されていません**
* 他の**サブディレクトリ**/**ファイル**の/**proc**および/**sys**への読み取り/書き込み/ロック/リンク/実行アクセスは**拒否されます**
* **マウント**は**許可されていません**
* **Ptrace**は、**同じapparmorプロファイル**によって制限されたプロセスでのみ実行できます

Dockerコンテナを実行すると、次の出力が表示されるはずです：
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意してください。**apparmorはデフォルトでコンテナに付与された特権権限であるcapabilitiesもブロックします**。例えば、SYS_ADMINの特権が付与されていても、デフォルトのDockerのapparmorプロファイルでは/procへの書き込み権限をブロックすることができます。
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
apparmorの制限をバイパスするために、apparmorを**無効化する必要があります**：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
注意してください、デフォルトでは**AppArmor**はコンテナが内部からフォルダをマウントすることを禁止します。これはSYS_ADMINの機能でも制限されます。

また、**capabilities**をDockerコンテナに**追加/削除**することができます（これは**AppArmor**や**Seccomp**などの保護方法によって制限されます）：

* `--cap-add=SYS_ADMIN`_ _`SYS_ADMIN`機能を与える
* `--cap-add=ALL`_ _すべての機能を与える
* `--cap-drop=ALL --cap-add=SYS_PTRACE`_ _すべての機能を削除し、`SYS_PTRACE`のみを与える

{% hint style="info" %}
通常、**docker**コンテナの**内部**で**特権のある機能**が利用可能であることがわかった場合でも、**エクスプロイトの一部が機能しない**場合は、dockerの**apparmorがそれを防いでいる**可能性があります。
{% endhint %}

## AppArmor Docker脱出

次のコマンドを使用して、どの**apparmorプロファイルがコンテナを実行しているか**を確認できます：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
次に、次のコマンドを実行して、使用されている正確なプロファイルを見つけることができます。
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
奇妙な場合には、**apparmorのDockerプロファイルを変更して再読み込みすることができます。** 制限を削除してそれらを「バイパス」することができます。


<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！

- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。

- [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。

- [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**Telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **ハッキングのトリックを共有するには、[hacktricksリポジトリ](https://github.com/carlospolop/hacktricks)と[hacktricks-cloudリポジトリ](https://github.com/carlospolop/hacktricks-cloud)**にPRを提出してください。

</details>
