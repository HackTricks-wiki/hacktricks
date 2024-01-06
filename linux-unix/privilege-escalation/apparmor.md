<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**や**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手する
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックする
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加する**か、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローする**。
* [**HackTricks**](https://github.com/carlospolop/hacktricks)と[**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud)のgithubリポジトリにPRを提出して、あなたのハッキングテクニックを共有する。

</details>


# 基本情報

**AppArmor**は、**プログラム**を**限定された**リソースセットに制限するためのカーネル拡張であり、**プログラムごとのプロファイル**を使用します。プロファイルは、ネットワークアクセス、生のソケットアクセス、および一致するパス上のファイルの読み取り、書き込み、実行の許可などの**機能**を**許可**することができます。

これは、**アクセス制御**属性をユーザーではなく**プログラムに結び付ける**Mandatory Access Controlまたは**MAC**です。\
AppArmorの制限は、通常はブート時にカーネルにロードされる**プロファイル**を介して提供されます。\
AppArmorプロファイルは**2つのモード**のいずれかになります：

* **Enforcement**: 実施モードでロードされたプロファイルは、プロファイルに定義されたポリシーの**実施**およびポリシー違反の試みの**報告**（syslogまたはauditd経由）をもたらします。
* **Complain**: コンプレインモードのプロファイルはポリシーを実施せず、代わりにポリシー違反の試みを**報告**します。

AppArmorは、他のいくつかのLinux上のMACシステムとは異なります：それは**パスベース**であり、実施とコンプレインモードのプロファイルを混在させることができ、開発を容易にするためのインクルードファイルを使用し、他の人気のあるMACシステムよりもはるかに低い参入障壁を持っています。

## AppArmorの構成要素

* **カーネルモジュール**: 実際の作業を行います
* **ポリシー**: 振る舞いと制限を定義します
* **パーサー**: カーネルにポリシーをロードします
* **ユーティリティ**: apparmorと対話するユーザーモードのプログラム

## プロファイルのパス

Apparmorプロファイルは通常 _**/etc/apparmor.d/**_ に保存されます。\
`sudo aa-status` を使用すると、いくつかのプロファイルによって制限されているバイナリをリストすることができます。リストされた各バイナリのパスの文字 "/" をドットに変更すると、前述のフォルダ内のapparmorプロファイルの名前が得られます。

例えば、_/usr/bin/man_ の **apparmor** プロファイルは _/etc/apparmor.d/usr.bin.man_ に位置しています。

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

* 影響を受ける実行可能ファイルを指定するために、**絶対パスとワイルドカード**が許可されています（ファイルのグロビング用）。
* バイナリが**ファイル**に対して持つアクセスを示すために、以下の**アクセス制御**が使用できます：
* **r**（読み取り）
* **w**（書き込み）
* **m**（実行可能としてメモリマップ）
* **k**（ファイルロック）
* **l**（ハードリンクの作成）
* **ix**（別のプログラムを実行し、新しいプログラムがポリシーを継承）
* **Px**（環境をクリアした後、別のプロファイルで実行）
* **Cx**（環境をクリアした後、子プロファイルで実行）
* **Ux**（環境をクリアした後、制限なしで実行）
* **変数**はプロファイル内で定義でき、プロファイルの外から操作できます。例：@{PROC} と @{HOME}（プロファイルファイルに #include \<tunables/global> を追加）
* **許可ルールを上書きする拒否ルールがサポートされています**。

## aa-genprof

AppArmorを使用すると、簡単にプロファイルの作成を開始できます。実行可能ファイルによって実行されるアクションを**AppArmorが検査し、どのアクションを許可または拒否するかを決定できます**。\
実行するだけです：
```bash
sudo aa-genprof /path/to/binary
```
次に、別のコンソールでバイナリが通常実行するすべてのアクションを実行します:
```bash
/path/to/binary -a dosomething
```
最初のコンソールで「**s**」を押し、記録されたアクションで無視するか、許可するか、その他の操作を指示します。終了したら「**f**」を押して、新しいプロファイルが _/etc/apparmor.d/path.to.binary_ に作成されます。

{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他の操作を選択できます。
{% endhint %}

## aa-easyprof

また、以下のコマンドでバイナリのAppArmorプロファイルのテンプレートを作成することもできます：
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
デフォルトでは作成されたプロファイルでは何も許可されていないため、全てが拒否されます。たとえば、バイナリが `/etc/passwd` を読み取ることを許可するには、`/etc/passwd r,` のような行を追加する必要があります。
{% endhint %}

その後、新しいプロファイルを**適用**することができます。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
## ログからプロファイルを変更する

以下のツールはログを読み込み、検出された禁止されたアクションを許可するかどうかユーザーに尋ねます：
```bash
sudo aa-logprof
```
{% hint style="info" %}
矢印キーを使用して、許可/拒否/その他を選択できます
{% endhint %}

## プロファイルの管理
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
# ログ

実行可能ファイル **`service_bin`** の _/var/log/audit/audit.log_ からの **AUDIT** と **DENIED** ログの例：
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
```
あなたはこの情報を以下の使用でも取得できます:
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
# DockerのApparmor

デフォルトで**docker-profile**のプロファイルがどのようにDockerによってロードされるかに注目してください：
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
デフォルトでは、**Apparmor docker-default profile** は [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor) から生成されます。

**docker-default profile の概要**:

* すべての**ネットワーキング**への**アクセス**
* **No capability** が定義されています (ただし、基本的な基本ルールを含むことでいくつかの機能が提供されます。例: #include \<abstractions/base> )
* 任意の **/proc** ファイルへの**書き込み**は**許可されていません**
* /**proc** および /**sys** の他の**サブディレクトリ**/**ファイル**は、読み取り/書き込み/ロック/リンク/実行アクセスが**拒否**されます
* **マウント**は**許可されていません**
* **Ptrace** は、**同じapparmorプロファイル**によって制限されているプロセスでのみ実行できます

**dockerコンテナを実行**すると、以下の出力が表示されるはずです：
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意: **apparmorは、デフォルトでコンテナに付与されたcapabilities権限さえもブロックします**。例えば、SYS_ADMIN capabilityが付与されていても、デフォルトのdocker apparmorプロファイルはこのアクセスを拒否するため、**/proc内への書き込み権限をブロックすることができます**：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
**AppArmorを無効にする**必要があります。これにより、その制限を回避できます：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
デフォルトでは、**AppArmor** は **SYS_ADMIN** 権限があっても、コンテナ内部からフォルダをマウントすることを**禁止します**。

Dockerコンテナに **capabilities** を **追加/削除** することができますが、これは **AppArmor** や **Seccomp** などの保護方法によって制限されます：

* `--cap-add=SYS_ADMIN` は `SYS_ADMIN` 権限を**与えます**
* `--cap-add=ALL` はすべての権限を**与えます**
* `--cap-drop=ALL --cap-add=SYS_PTRACE` はすべての権限を削除し、`SYS_PTRACE` のみを**与えます**

{% hint style="info" %}
通常、**docker** コンテナ**内部**で**特権権限**が利用可能であることが**分かった**にも関わらず、**エクスプロイトの一部が機能しない**場合、それは docker **apparmor が防止している**ためです。
{% endhint %}

## AppArmor Docker 脱出

コンテナが実行している **apparmor プロファイル** を以下の方法で確認できます：
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
次に、以下の行を実行して**使用されている正確なプロファイルを見つけます**：
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
```markdown
変わったケースとして、**AppArmorのDockerプロファイルを変更して、再読み込みすることができます。** 制限を取り除き、それらを「バイパス」することができます。

<details>

<summary><strong>AWSハッキングをゼロからヒーローまで学ぶには</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>をチェック！</strong></summary>

HackTricksをサポートする他の方法:

* **HackTricksにあなたの会社を広告したい場合**、または**HackTricksをPDFでダウンロードしたい場合**は、[**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見し、独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションをチェックしてください
* 💬 [**Discordグループ**](https://discord.gg/hRep4RUj7f)に**参加するか**、[**テレグラムグループ**](https://t.me/peass)に参加するか、**Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)を**フォローしてください。**
* **あなたのハッキングのコツを、** [**HackTricks**](https://github.com/carlospolop/hacktricks) と [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) のgithubリポジトリにPRを提出することで共有してください。

</details>
```
