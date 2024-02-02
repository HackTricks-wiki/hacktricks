# AppArmor

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をご覧ください！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見する、私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクション
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**telegramグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォロー**してください。
* **HackTricks**の[**GitHubリポジトリ**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングテクニックを共有してください。

</details>

## 基本情報

**AppArmor**は、**プログラム**を**限定された**一連の**リソース**に制限するカーネル拡張機能であり、**プログラムごとのプロファイル**を使用します。プロファイルは、ネットワークアクセス、生のソケットアクセス、および一致するパス上のファイルの読み取り、書き込み、または実行の許可などの**機能**を**許可**することができます。

これは、**アクセス制御**属性をユーザーではなく**プログラムに結び付ける**強制アクセス制御または**MAC**です。\
AppArmorの制限は、通常はブート時にカーネルにロードされる**プロファイル**を介して提供されます。\
AppArmorプロファイルは**2つのモード**のいずれかになります：

* **Enforcement（強制）**: 強制モードでロードされたプロファイルは、プロファイルに定義されたポリシーの**強制**およびポリシー違反試行の**報告**（syslogまたはauditd経由）をもたらします。
* **Complain（苦情）**: 苦情モードのプロファイルはポリシーを強制しませんが、代わりにポリシー**違反**試行を**報告**します。

AppArmorは、他のいくつかのLinux上のMACシステムとは異なります：それは**パスベース**であり、強制と苦情モードのプロファイルを混在させることができ、開発を容易にするためのインクルードファイルを使用し、他の人気のあるMACシステムよりもはるかに低い参入障壁を持っています。

### AppArmorの構成要素

* **カーネルモジュール**: 実際の作業を行います
* **ポリシー**: 振る舞いと制限を定義します
* **パーサー**: カーネルにポリシーをロードします
* **ユーティリティ**: apparmorと対話するユーザーモードプログラム

### プロファイルのパス

Apparmorプロファイルは通常、_**/etc/apparmor.d/**_に保存されます。\
`sudo aa-status`を使用すると、プロファイルによって制限されているバイナリをリストすることができます。リストされた各バイナリのパスの文字"/"をドットに変更すると、言及されたフォルダ内のapparmorプロファイルの名前が得られます。

例えば、_/usr/bin/man_の**apparmor**プロファイルは_/etc/apparmor.d/usr.bin.man_に位置しています。

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

* 実行可能ファイルを指定するために、**絶対パスとワイルドカード**が許可されています（ファイルのグロビングを指定するため）。
* バイナリが**ファイル**に対して持つアクセスを示すために、以下の**アクセスコントロール**が使用できます：
* **r**（読み取り）
* **w**（書き込み）
* **m**（実行可能としてメモリマップ）
* **k**（ファイルロック）
* **l**（ハードリンクの作成）
* **ix**（別のプログラムを実行し、新しいプログラムがポリシーを継承する）
* **Px**（環境をクリーニングした後、別のプロファイルで実行）
* **Cx**（環境をクリーニングした後、子プロファイルで実行）
* **Ux**（環境をクリーニングした後、制限なしで実行）
* **変数**はプロファイル内で定義でき、プロファイルの外から操作できます。例：@{PROC} と @{HOME}（プロファイルファイルに #include \<tunables/global> を追加）
* **許可ルールを上書きする拒否ルールがサポートされています**。

### aa-genprof

簡単にプロファイル作成を始めるために、apparmorが助けになります。**apparmorがバイナリによって実行されたアクションを検査し、どのアクションを許可または拒否するかを決定することを可能にします**。\
実行するだけです：
```bash
sudo aa-genprof /path/to/binary
```
次に、別のコンソールでバイナリが通常実行するすべてのアクションを実行します：
```bash
/path/to/binary -a dosomething
```
最初のコンソールで「**s**」を押し、記録されたアクションで無視するか、許可するか、その他の操作を指示します。終了したら「**f**」を押すと、新しいプロファイルが _/etc/apparmor.d/path.to.binary_ に作成されます。

{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の操作を選択できます。
{% endhint %}

### aa-easyprof

バイナリのapparmorプロファイルのテンプレートも以下のように作成できます：
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
デフォルトでは作成されたプロファイルでは何も許可されていないため、全てが拒否されます。たとえば、バイナリが`/etc/passwd`を読み取ることを許可するには、`/etc/passwd r,`のような行を追加する必要があります。
{% endhint %}

その後、新しいプロファイルを**強制**することができます。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### ログからプロファイルを変更する

次のツールはログを読み取り、検出された禁止されているアクションを許可するかどうかユーザーに尋ねます：
```bash
sudo aa-logprof
```
{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他を選択できます
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
```markdown
情報は以下の使用でも取得できます:
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
## DockerにおけるApparmor

デフォルトで**docker-profile**がどのようにDockerによってロードされるかに注目してください：
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
デフォルトでは、**Apparmor docker-default プロファイル**は[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)から生成されます。

**docker-default プロファイルの概要**：

* すべての**ネットワーキング**への**アクセス**
* **権限**は定義されていません（ただし、基本的な基本ルールを含むことにより、いくつかの権限が付与されます。例：#include \<abstractions/base>）
* 任意の**/proc**ファイルへの**書き込み**は**許可されていません**
* /**proc** および /**sys** の他の**サブディレクトリ**/**ファイル**は、読み取り/書き込み/ロック/リンク/実行アクセスが**拒否**されます
* **マウント**は**許可されていません**
* **Ptrace**は、**同じapparmorプロファイル**によって制限されているプロセスでのみ実行できます

**dockerコンテナを実行**すると、次の出力が表示されるはずです：
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意: **apparmorは、デフォルトでコンテナに付与された機能権限もブロックします**。例えば、**SYS\_ADMIN機能が付与されていても、/proc内への書き込み権限をブロックすることができます**。なぜなら、デフォルトのdocker apparmorプロファイルはこのアクセスを拒否するからです:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
**AppArmorを無効にする**必要があります。それによって制限を回避できます：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
デフォルトでは、**AppArmor** は **SYS\_ADMIN** 権限があっても、コンテナが内部からフォルダをマウントすることを**禁止**します。

Docker コンテナに **capabilities** を **追加/削除** することができます（これは **AppArmor** や **Seccomp** などの保護方法によって依然として制限されます）：

* `--cap-add=SYS_ADMIN` は `SYS_ADMIN` 権限を与えます
* `--cap-add=ALL` はすべての権限を与えます
* `--cap-drop=ALL --cap-add=SYS_PTRACE` はすべての権限を削除し、`SYS_PTRACE` のみを与えます

{% hint style="info" %}
通常、Docker コンテナ**内部**で**特権権限**が利用可能であることが**分かった**場合でも、**エクスプロイトの一部が機能しない**ことがあります。これは、Docker **AppArmor がそれを防いでいる**可能性が高いです。
{% endhint %}

### 例

（[**こちら**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)からの例）

AppArmor の機能を示すために、「mydocker」という新しい Docker プロファイルを作成し、以下の行を追加しました：
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
プロファイルを有効にするには、次の操作を行う必要があります：
```
sudo apparmor_parser -r -W mydocker
```
プロファイルを一覧表示するには、以下のコマンドを実行します。以下のコマンドは、私の新しいAppArmorプロファイルをリストしています。
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
以下に示すように、「/etc/」を変更しようとすると、AppArmorプロファイルが「/etc」への書き込みアクセスを防いでいるため、エラーが発生します。
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

コンテナが実行している**apparmorプロファイル**を見つける方法は以下の通りです：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
その後、以下の行を実行して**使用されている正確なプロファイルを見つけます**：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
奇妙なケースでは、**AppArmorのDockerプロファイルを変更して再読み込みすることができます。** 制限を取り除き、それらを「バイパス」することができます。

### AppArmor Docker バイパス2

**AppArmorはパスベースです**。これは、**`/proc`** のようなディレクトリ内のファイルを**保護**しているかもしれませんが、コンテナの実行方法を**設定**できる場合、ホストのprocディレクトリを **`/host/proc`** に**マウント**すると、それはもはやAppArmorによって**保護されなくなります**。

### AppArmor Shebang バイパス

[**このバグ**](https://bugs.launchpad.net/apparmor/+bug/1911431)では、**特定のリソースでperlを実行することを防いでいる場合でも**、最初の行に**`#!/usr/bin/perl`** を**指定**したシェルスクリプトを作成し、ファイルを**直接実行**すると、何でも実行できる例が見られます。例：
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

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい**、または**HackTricksをPDFでダウンロードしたい**場合は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加する**か、[**テレグラムグループ**](https://t.me/peass)に参加する、または**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks) および [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) githubリポジトリにPRを提出して、あなたのハッキングのコツを**共有する**。

</details>
