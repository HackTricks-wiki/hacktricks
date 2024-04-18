# AppArmor

<details>

<summary><strong>ゼロからヒーローまでAWSハッキングを学ぶ</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE（HackTricks AWS Red Team Expert）</strong></a><strong>！</strong></summary>

HackTricksをサポートする他の方法：

- **HackTricksで企業を宣伝したい**または**HackTricksをPDFでダウンロードしたい**場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
- [**公式PEASS＆HackTricksスワッグ**](https://peass.creator-spring.com)を入手する
- [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションを見つける
- **💬 [Discordグループ](https://discord.gg/hRep4RUj7f)**に参加するか、[telegramグループ](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)をフォローする
- **HackTricks**および**HackTricks Cloud**のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する

</details>

### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**盗難マルウェア**によって**侵害**されていないかをチェックする**無料**機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

---

## 基本情報

AppArmorは、**プログラムごとのプロファイルを介してプログラムが利用できるリソースを制限するように設計されたカーネルの拡張機能**であり、アクセス制御属性をユーザーではなくプログラムに直接結びつけることで、強制アクセス制御（MAC）を効果的に実装しています。このシステムは、**プロファイルをカーネルにロード**して動作し、これらのプロファイルは、ネットワーク接続、生のソケットアクセス、ファイルアクセス権限など、プログラムがアクセスできるリソースを指示します。

AppArmorプロファイルには、次の2つの動作モードがあります：

- **強制モード**：このモードは、プロファイルで定義されたポリシーを積極的に強制し、これらのポリシーに違反するアクションをブロックし、syslogやauditdなどのシステムを介してこれらを侵害しようとする試みを記録します。
- **クレームモード**：強制モードとは異なり、クレームモードはプロファイルのポリシーに違反するアクションをブロックしません。代わりに、これらの試みをポリシー違反として記録しますが、制限を強制しません。

### AppArmorの構成要素

- **カーネルモジュール**：ポリシーの強制を担当します。
- **ポリシー**：プログラムの動作とリソースアクセスのルールと制限を指定します。
- **パーサー**：ポリシーをカーネルにロードして強制または報告します。
- **ユーティリティ**：これらは、AppArmorとのやり取りと管理のためのインターフェースを提供するユーザーモードプログラムです。

### プロファイルのパス

AppArmorプロファイルは通常、_**/etc/apparmor.d/**_に保存されます。\
`sudo aa-status`を使用すると、いくつかのプロファイルに制限がかけられているバイナリをリストアップできます。リストされた各バイナリのパスのスラッシュ"/"をドットに変更すると、言及されたフォルダ内のapparmorプロファイルの名前が取得できます。

たとえば、_**/usr/bin/man**_の**apparmor**プロファイルは、_**/etc/apparmor.d/usr.bin.man**_にあります。

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

- 影響を受ける実行可能ファイルを示すために、**絶対パスとワイルドカード**が許可されています（ファイルグロブを使用するため）。
- **ファイル**に対するバイナリのアクセスを示すために、以下の**アクセス制御**を使用できます：
  - **r**（読み取り）
  - **w**（書き込み）
  - **m**（実行可能としてメモリマップ）
  - **k**（ファイルロック）
  - **l**（ハードリンクの作成）
  - **ix**（新しいプログラムがポリシーを継承して別のプログラムを実行する）
  - **Px**（環境をクリーンアップした後、別のプロファイルで実行）
  - **Cx**（環境をクリーンアップした後、子プロファイルで実行）
  - **Ux**（環境をクリーンアップした後、無制限に実行）
- **プロファイル内で変数**を定義し、プロファイル外から操作することができます。例：@{PROC} および @{HOME}（プロファイルファイルに #include \<tunables/global> を追加します）
- **許可ルールを上書きするために拒否ルールがサポート**されています。

### aa-genprof

簡単にプロファイルを作成するために、apparmor が役立ちます。**バイナリによって実行されるアクションを apparmor に検査させ、その後、許可または拒否するアクションを決定できます**。\
次のコマンドを実行するだけです：
```bash
sudo aa-genprof /path/to/binary
```
その後、別のコンソールで通常バイナリが実行するすべてのアクションを実行します：
```bash
/path/to/binary -a dosomething
```
### aa-easyprof

また、バイナリのAppArmorプロファイルのテンプレートを作成することもできます。
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
デフォルトでは、作成したプロファイルでは何も許可されていないため、すべてが拒否されます。たとえば、バイナリが `/etc/passwd` を読むことを許可するために `/etc/passwd r,` のような行を追加する必要があります。
{% endhint %}

新しいプロファイルを**強制**することができます。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### ログからプロファイルを修正する

次のツールはログを読み取り、ユーザーに検出された禁止されたアクションのうち許可するものがあるかどうかを尋ねます：
```bash
sudo aa-logprof
```
{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の選択を行うことができます
{% endhint %}

### プロファイルの管理
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## ログ

実行可能ファイル **`service_bin`** の _/var/log/audit/audit.log_ からの **AUDIT** と **DENIED** ログの例：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
以下の方法でもこの情報を取得できます：
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
## DockerのApparmor

デフォルトでDockerのプロファイル**docker-profile**がロードされていることに注意してください：
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

**docker-defaultプロファイルの概要**:

- すべての**ネットワーキング**への**アクセス**
- **権限**は定義されていません（ただし、一部の権限は基本的なベースルールを含むことによって提供されます、つまり#include \<abstractions/base>）
- 任意の**/proc**ファイルへの**書き込み**は**許可されていません**
- 他の/**proc**および/**sys**の**サブディレクトリ**/**ファイル**への読み取り/書き込み/ロック/リンク/実行アクセスは**拒否されます**
- **マウント**は**許可されていません**
- **Ptrace**は、**同じapparmorプロファイル**によって制限されたプロセスでのみ実行できます

Dockerコンテナを**実行**すると、次の出力が表示されるはずです:
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意してください。デフォルトでは、**apparmorはコンテナに付与された権限でさえもブロック**します。たとえば、**SYS_ADMIN権限が付与**されていても、デフォルトではdockerのapparmorプロファイルがこのアクセスを拒否するため、**/proc内に書き込む権限をブロック**することができます。
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Apparmorの制限をバイパスするために、**Apparmorを無効にする**必要があります。
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
デフォルトでは、**AppArmor** はコンテナがSYS_ADMIN機能を持っていても、内部からフォルダをマウントすることを**禁止します**。

dockerコンテナに**capabilities**を**追加/削除**できることに注意してください（これは**AppArmor**や**Seccomp**などの保護方法によって引き続き制限されます）:

- `--cap-add=SYS_ADMIN` は `SYS_ADMIN` 機能を付与します
- `--cap-add=ALL` はすべての機能を付与します
- `--cap-drop=ALL --cap-add=SYS_PTRACE` はすべての機能を削除し、`SYS_PTRACE` のみを付与します

{% hint style="info" %}
通常、**docker**コンテナ内で**特権機能**が利用可能であることがわかった場合でも、**exploit**の一部が機能しない場合は、docker **apparmor がそれを防いでいる**可能性があります。
{% endhint %}

### 例

（[**こちら**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)の例から）

AppArmorの機能を説明するために、新しいDockerプロファイル "mydocker" を作成し、次の行を追加しました：
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
プロファイルをアクティブにするには、以下の手順を実行する必要があります:
```
sudo apparmor_parser -r -W mydocker
```
プロファイルをリストするには、以下のコマンドを使用します。以下のコマンドは、私の新しいAppArmorプロファイルをリストしています。
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

コンテナで実行されている**apparmorプロファイルを見つける**には、次のコマンドを使用できます：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
その後、次の行を実行して、**使用されている正確なプロファイルを見つける**ことができます：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmorはパスベース**であり、これは、たとえ**`/proc`**のようなディレクトリ内のファイルを**保護**していても、コンテナの実行方法を**構成**できる場合、ホストのprocディレクトリを**`/host/proc`**にマウントすることができ、それによりAppArmorによる保護が**解除**されます。

### AppArmor Shebang Bypass

[**このバグ**](https://bugs.launchpad.net/apparmor/+bug/1911431)では、**特定のリソースでperlの実行を防いでいる場合でも**、最初の行に**`#!/usr/bin/perl`**を指定したシェルスクリプトを作成し、そのファイルを直接**実行**すると、任意のコマンドを実行できることが示されています。例：
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
### [WhiteIntel](https://whiteintel.io)

<figure><img src="/.gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io)は、**ダークウェブ**を活用した検索エンジンで、企業やその顧客が**スティーラーマルウェア**によって**侵害**されているかどうかをチェックする**無料**の機能を提供しています。

WhiteIntelの主な目標は、情報窃取マルウェアによるアカウント乗っ取りやランサムウェア攻撃と戦うことです。

彼らのウェブサイトをチェックして、**無料**でエンジンを試すことができます：

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>**htARTE (HackTricks AWS Red Team Expert)**を使って、ゼロからヒーローまでAWSハッキングを学ぶ</strong></summary>

HackTricksをサポートする他の方法：

* **HackTricksで企業を宣伝したり、HackTricksをPDFでダウンロードしたり**する場合は、[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS＆HackTricksスウォッグ**](https://peass.creator-spring.com)を手に入れる
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションを見つける
* **💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)で**フォロー**してください。
* **HackTricks**と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks)のGitHubリポジトリにPRを提出して、あなたのハッキングテクニックを共有してください。

</details>
