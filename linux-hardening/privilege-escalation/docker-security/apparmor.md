# AppArmor

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricks swag**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

## 基本情報

**AppArmor**は、**プログラム**を**制限されたリソース**の**限られたセット**に制約するためのカーネルの拡張機能です。プロファイルは、ネットワークアクセス、生のソケットアクセス、および一致するパス上のファイルの読み取り、書き込み、実行の許可などの**機能**を**許可**できます。

これは、アクセス制御属性をユーザーではなく**プログラムにバインドする**Mandatory Access Control（MAC）です。\
AppArmorの制約は、通常は起動時にカーネルにロードされる**プロファイル**によって提供されます。\
AppArmorプロファイルは、次の**2つのモード**のいずれかになることができます。

* **Enforcement（強制）**：強制モードでロードされたプロファイルは、プロファイルで定義されたポリシーの**強制**と、ポリシー違反の試みの**報告**（syslogまたはauditd経由）の結果となります。
* **Complain（苦情）**：苦情モードのプロファイルは、ポリシーを**強制しない**代わりに、ポリシー違反の試みを**報告**します。

AppArmorは、Linux上の他の一部のMACシステムとは異なり、**パスベース**であり、強制モードと苦情モードのプロファイルを混在させることができ、開発を容易にするためにインクルードファイルを使用し、他の人気のあるMACシステムよりもはるかに低い参入障壁を持っています。

### AppArmorのパーツ

* **カーネルモジュール**：実際の作業を行う
* **ポリシー**：動作と制約を定義する
* **パーサー**：ポリシーをカーネルにロードする
* **ユーティリティ**：apparmorとの対話のためのユーザーモードプログラム

### プロファイルのパス

AppArmorのプロファイルは通常、_**/etc/apparmor.d/**_に保存されます。\
`sudo aa-status`を使用すると、いくつかのプロファイルに制限されているバイナリをリストすることができます。リストされた各バイナリのパスの"/"をドットに変更すると、言及されたフォルダ内のapparmorプロファイルの名前が取得できます。

たとえば、_usr/bin/man_の**apparmor**プロファイルは、_**/etc/apparmor.d/usr.bin.man**_にあります。

### コマンド
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## プロファイルの作成

* 影響を受ける実行可能ファイルを示すために、**絶対パスとワイルドカード**が使用できます（ファイルグロブを使用）。
* **ファイル**に対するアクセスを示すために、次の**アクセス制御**を使用できます：
* **r**（読み取り）
* **w**（書き込み）
* **m**（実行可能としてメモリにマップ）
* **k**（ファイルロック）
* **l**（ハードリンクの作成）
* **ix**（新しいプログラムを実行し、ポリシーを継承するために別のプログラムを実行）
* **Px**（環境をクリーンアップした後、別のプロファイルで実行）
* **Cx**（環境をクリーンアップした後、子プロファイルで実行）
* **Ux**（環境をクリーンアップした後、制約なしで実行）
* **プロファイル内で変数**を定義し、プロファイルの外部から操作することができます。例：@{PROC}と@{HOME}（プロファイルファイルに#include \<tunables/global>を追加）
* **許可ルールを上書きするために拒否ルールがサポートされています**。

### aa-genprof

プロファイルの作成を簡単に開始するために、apparmorが役立ちます。**apparmorはバイナリによって実行されるアクションを検査し、どのアクションを許可または拒否するかを選択できるようにします**。\
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

### aa-easyprof

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
デフォルトでは、作成されたプロファイルでは何も許可されていないため、すべてが拒否されます。たとえば、`/etc/passwd r,`のような行を追加して、バイナリが`/etc/passwd`を読み取ることを許可する必要があります。
{% endhint %}

次に、新しいプロファイルを**強制的に**適用できます。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### ログからプロファイルを変更する

以下のツールはログを読み取り、ユーザーに検出された禁止されたアクションの許可を求めます。
```bash
sudo aa-logprof
```
{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の選択を行うことができます。
{% endhint %}

### プロファイルの管理

#### Loading a Profile

To load a profile, use the `apparmor_parser` command followed by the profile file path:

```bash
sudo apparmor_parser -r -W /path/to/profile
```

The `-r` flag reloads the profile, and the `-W` flag enforces the profile. This ensures that the profile is loaded and enforced immediately.

#### Unloading a Profile

To unload a profile, use the `apparmor_parser` command followed by the profile name:

```bash
sudo apparmor_parser -R /path/to/profile
```

The `-R` flag removes the profile from the system.

#### Checking the Status of a Profile

To check the status of a profile, use the `apparmor_status` command:

```bash
sudo apparmor_status
```

This command will display a list of all active profiles and their status.

### Creating a Profile

To create a new profile, follow these steps:

1. Identify the application or process for which you want to create a profile.
2. Use the `aa-genprof` command to generate a profile template:

   ```bash
   sudo aa-genprof /path/to/application
   ```

   This command will start the profiling process and prompt you to perform various actions with the application.
3. Perform the actions you want to allow or deny for the application.
4. Once you have finished profiling the application, press `Ctrl+C` to exit the profiling process.
5. Use the `aa-logprof` command to review and adjust the generated profile:

   ```bash
   sudo aa-logprof
   ```

   This command will display a list of actions performed during the profiling process and allow you to customize the profile.
6. Review the generated profile and make any necessary adjustments.
7. Save the profile and load it using the `apparmor_parser` command as described earlier.

### Modifying a Profile

To modify an existing profile, follow these steps:

1. Locate the profile file you want to modify.
2. Edit the profile file using a text editor.
3. Make the necessary changes to the profile.
4. Save the modified profile.
5. Load the modified profile using the `apparmor_parser` command as described earlier.

### Conclusion

AppArmor provides a powerful mechanism for managing and enforcing security profiles for applications and processes. By understanding how to load, unload, create, and modify profiles, you can enhance the security of your system and protect against unauthorized access and privilege escalation.
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## ログ

実行可能ファイル **`service_bin`** の _/var/log/audit/audit.log_ からの **AUDIT** と **DENIED** ログの例:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
次のコマンドを使用して、この情報を取得することもできます。

```bash
command_here
```

または、次の方法でも情報を取得できます。

```bash
another_command_here
```

この情報を取得するための他の方法もあります。以下のコマンドを使用してください。

```bash
more_commands_here
```

この情報を取得するためのさらなる方法もあります。以下のコマンドを使用してください。

```bash
even_more_commands_here
```

これらの方法を使用して、必要な情報を取得できます。
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
## DockerにおけるApparmor

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
注意してください。デフォルトでは、**apparmorはコンテナに付与された特権の権限さえもブロックします**。たとえば、SYS\_ADMINの特権が付与されている場合でも、デフォルトのDocker apparmorプロファイルでは/proc内への書き込み権限を拒否します。
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
apparmorの制限をバイパスするために、**apparmorを無効にする**必要があります。
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
注意してください、デフォルトでは**AppArmor**はコンテナがSYS\_ADMINの機能を持っていても、内部からフォルダをマウントすることを禁止します。

また、**AppArmor**や**Seccomp**のような保護方法によって制限されますが、dockerコンテナに**capabilities**を追加/削除することもできます。

* `--cap-add=SYS_ADMIN` で`SYS_ADMIN` capを与える
* `--cap-add=ALL` ですべてのcapを与える
* `--cap-drop=ALL --cap-add=SYS_PTRACE` ですべてのcapを削除し、`SYS_PTRACE`のみを与える

{% hint style="info" %}
通常、dockerコンテナの中で特権のあるcapabilityが利用可能であることがわかった場合でも、エクスプロイトの一部が機能しない場合は、dockerのapparmorがそれを防いでいる可能性があります。
{% endhint %}

### 例

([**ここ**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))からの例です。

AppArmorの機能を説明するために、以下の行が追加された新しいDockerプロファイル「mydocker」を作成しました。
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
プロファイルをアクティブにするには、以下の手順を実行する必要があります：
```
sudo apparmor_parser -r -W mydocker
```
プロファイルをリストするには、以下のコマンドを実行します。以下のコマンドは、私の新しいAppArmorプロファイルをリストしています。

```bash
$ sudo apparmor_status
```

または

```bash
$ sudo aa-status
```

これにより、現在のAppArmorプロファイルの一覧が表示されます。
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
以下のように、AppArmorプロファイルが「/etc/」への書き込みアクセスを防いでいるため、「/etc/」を変更しようとするとエラーが発生します。
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

コンテナで実行されている**AppArmorプロファイルを見つける**には、次のコマンドを使用します：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
次に、以下のコマンドを実行して、使用されている正確なプロファイルを見つけることができます。
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmorはパスベースです**。つまり、ディレクトリ内のファイル（例：`/proc`）を**保護**している場合でも、コンテナの実行方法を**設定**できれば、ホストのprocディレクトリを**`/host/proc`**にマウントすることができ、AppArmorの保護対象外になります。

### AppArmor Shebang Bypass

[**このバグ**](https://bugs.launchpad.net/apparmor/+bug/1911431)では、特定のリソースでperlの実行を防いでいる場合でも、シェルスクリプトを作成し、最初の行に**`#!/usr/bin/perl`**を指定し、ファイルを直接実行すると、任意のコマンドを実行できます。例：
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**最新バージョンのPEASSを入手したり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
