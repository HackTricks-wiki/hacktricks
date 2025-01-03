# AppArmor

{{#include ../../../banners/hacktricks-training.md}}

## 基本情報

AppArmorは、**プログラムごとのプロファイルを通じてプログラムに利用可能なリソースを制限するために設計されたカーネル拡張**であり、ユーザーではなくプログラムに直接アクセス制御属性を結びつけることによって、必須アクセス制御（MAC）を効果的に実装します。このシステムは、**プロファイルをカーネルにロードすることによって動作**し、通常はブート時に行われ、これらのプロファイルはプログラムがアクセスできるリソース（ネットワーク接続、生ソケットアクセス、ファイル権限など）を決定します。

AppArmorプロファイルには2つの運用モードがあります：

- **強制モード**：このモードは、プロファイル内で定義されたポリシーを積極的に強制し、これらのポリシーに違反するアクションをブロックし、syslogやauditdなどのシステムを通じて違反の試みをログに記録します。
- **コンプライアンスモード**：強制モードとは異なり、コンプライアンスモードはプロファイルのポリシーに反するアクションをブロックしません。代わりに、制限を強制することなく、これらの試みをポリシー違反としてログに記録します。

### AppArmorのコンポーネント

- **カーネルモジュール**：ポリシーの強制を担当します。
- **ポリシー**：プログラムの動作とリソースアクセスのルールと制限を指定します。
- **パーサー**：ポリシーをカーネルにロードして強制または報告します。
- **ユーティリティ**：AppArmorとのインターフェースを提供し、管理するためのユーザーモードプログラムです。

### プロファイルパス

AppArmorプロファイルは通常、_**/etc/apparmor.d/**_に保存されます。\
`sudo aa-status`を使用すると、いくつかのプロファイルによって制限されているバイナリをリストできます。リストされた各バイナリのパスの「/」をドットに変更すると、指定されたフォルダー内のAppArmorプロファイルの名前が得られます。

例えば、**apparmor**プロファイルは_/usr/bin/man_に対しては、_/etc/apparmor.d/usr.bin.man_にあります。

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

- 影響を受ける実行可能ファイルを示すために、**絶対パスとワイルドカード**がファイルを指定するために許可されています。
- バイナリが**ファイル**に対して持つアクセスを示すために、以下の**アクセス制御**を使用できます：
- **r** (読み取り)
- **w** (書き込み)
- **m** (実行可能なメモリマップ)
- **k** (ファイルロック)
- **l** (ハードリンクの作成)
- **ix** (新しいプログラムがポリシーを継承して別のプログラムを実行するため)
- **Px** (環境をクリーンにした後、別のプロファイルの下で実行)
- **Cx** (環境をクリーンにした後、子プロファイルの下で実行)
- **Ux** (環境をクリーンにした後、制限なしで実行)
- **変数**はプロファイル内で定義でき、プロファイルの外部から操作できます。例えば： @{PROC} と @{HOME} （プロファイルファイルに #include \<tunables/global> を追加）
- **許可ルールを上書きするための拒否ルールがサポートされています**。

### aa-genprof

プロファイルの作成を簡単に始めるために、apparmorが役立ちます。**apparmorがバイナリによって実行されるアクションを検査し、許可または拒否したいアクションを決定できるようにすることが可能です**。\
実行する必要があるのは次のコマンドです：
```bash
sudo aa-genprof /path/to/binary
```
その後、別のコンソールでバイナリが通常実行するすべてのアクションを実行します：
```bash
/path/to/binary -a dosomething
```
次に、最初のコンソールで "**s**" を押し、記録されたアクションで無視、許可、またはその他を選択します。終了したら "**f**" を押すと、新しいプロファイルが _/etc/apparmor.d/path.to.binary_ に作成されます。

> [!NOTE]
> 矢印キーを使用して、許可/拒否/その他を選択できます。

### aa-easyprof

バイナリの apparmor プロファイルのテンプレートを作成することもできます:
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
> [!NOTE]
> デフォルトでは、作成されたプロファイルでは何も許可されていないため、すべてが拒否されます。たとえば、バイナリが`/etc/passwd`を読み取ることを許可するには、`/etc/passwd r,`のような行を追加する必要があります。

その後、新しいプロファイルを**強制**することができます。
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### ログからのプロファイルの変更

次のツールはログを読み取り、ユーザーに検出された禁止されたアクションのいくつかを許可するかどうかを尋ねます:
```bash
sudo aa-logprof
```
> [!NOTE]
> 矢印キーを使用して、許可/拒否/その他の選択を行うことができます。

### プロファイルの管理
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## ログ

Example of **AUDIT** and **DENIED** logs from _/var/log/audit/audit.log_ of the executable **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
この情報は次の方法でも取得できます：
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

デフォルトで**docker-profile**のプロファイルがロードされることに注意してください:
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
デフォルトでは、**Apparmor docker-default profile**は[https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)から生成されます。

**docker-default profileの概要**:

- **すべてのネットワーキング**への**アクセス**
- **能力**は定義されていません（ただし、いくつかの能力は基本的なベースルールを含むことから来ます。つまり、#include \<abstractions/base>）
- **/proc**ファイルへの**書き込み**は**許可されていません**
- **/proc**および**/sys**の他の**サブディレクトリ**/**ファイル**への読み取り/書き込み/ロック/リンク/実行アクセスは**拒否**されます
- **マウント**は**許可されていません**
- **Ptrace**は、**同じapparmor profile**によって制限されたプロセスでのみ実行できます

**dockerコンテナを実行すると**、次の出力が表示されるはずです:
```bash
1 processes are in enforce mode.
docker-default (825)
```
注意してください、**apparmorはデフォルトでコンテナに付与された能力の特権をブロックします**。例えば、**SYS_ADMIN能力が付与されていても/proc内への書き込み権限をブロックすることができます**。なぜなら、デフォルトのdocker apparmorプロファイルはこのアクセスを拒否するからです：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
あなたはその制限を回避するために**apparmorを無効にする**必要があります：
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
デフォルトでは、**AppArmor**は**コンテナが内部から**フォルダーをマウントすることを**禁止します**。SYS_ADMIN権限があってもです。

**capabilities**をdockerコンテナに**追加/削除**することができます（これは**AppArmor**や**Seccomp**のような保護方法によって制限されます）：

- `--cap-add=SYS_ADMIN` `SYS_ADMIN`権限を付与
- `--cap-add=ALL` すべての権限を付与
- `--cap-drop=ALL --cap-add=SYS_PTRACE` すべての権限を削除し、`SYS_PTRACE`のみを付与

> [!NOTE]
> 通常、**docker**コンテナの**内部**で**特権権限**が利用可能であることを**発見**したが、**エクスプロイトの一部が機能していない**場合、これはdockerの**apparmorがそれを防いでいる**ためです。

### 例

（[**こちら**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)からの例）

AppArmorの機能を示すために、次の行を追加した新しいDockerプロファイル「mydocker」を作成しました：
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
プロファイルを有効にするには、次の手順を実行する必要があります：
```
sudo apparmor_parser -r -W mydocker
```
プロファイルをリストするには、次のコマンドを実行できます。以下のコマンドは、私の新しいAppArmorプロファイルをリストしています。
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
以下のように、AppArmorプロファイルが「/etc」への書き込みアクセスを防いでいるため、「/etc/」を変更しようとするとエラーが発生します。
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

どの **apparmor プロファイルがコンテナを実行しているか** を見つけるには、次のコマンドを使用します:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
次に、以下の行を実行して**使用されている正確なプロファイルを見つける**ことができます:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
奇妙な場合には、**apparmor docker プロファイルを変更して再読み込みすることができます。** 制限を削除し、「バイパス」することができます。

### AppArmor Docker バイパス2

**AppArmorはパスベースです。** これは、**`/proc`**のようなディレクトリ内のファイルを**保護**している場合でも、**コンテナの実行方法を構成できる**なら、ホストのプロクスディレクトリを**`/host/proc`**に**マウント**することができ、AppArmorによって**保護されなくなる**ことを意味します。

### AppArmor シェバング バイパス

[**このバグ**](https://bugs.launchpad.net/apparmor/+bug/1911431)では、**特定のリソースでperlの実行を防いでいる場合でも、**最初の行に**`#!/usr/bin/perl`**を指定したシェルスクリプトを作成し、**ファイルを直接実行**することで、任意のものを実行できる例を見ることができます。例えば：
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{{#include ../../../banners/hacktricks-training.md}}
