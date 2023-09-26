# macOSの自動起動場所

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業**で働いていますか？ **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を見つけてください。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>

以下は、ユーザーの操作なしにバイナリが**実行**される可能性のあるシステム上の場所です。

### Launchd

**`launchd`**は、OX Sカーネルによって起動時に最初に実行され、シャットダウン時に最後に終了する**プロセス**です。常に**PID 1**を持つべきです。このプロセスは、以下の場所にある**ASEP** **plists**で指定された設定を**読み取り、実行**します。

* `/Library/LaunchAgents`：管理者によってインストールされたユーザーごとのエージェント
* `/Library/LaunchDaemons`：管理者によってインストールされたシステム全体のデーモン
* `/System/Library/LaunchAgents`：Appleが提供するユーザーごとのエージェント
* `/System/Library/LaunchDaemons`：Appleが提供するシステム全体のデーモン

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents`と`/Users/$USER/Library/LaunchDemons`にあるplistsが**ログインしたユーザーの権限**で開始されます。

**エージェントとデーモンの主な違いは、エージェントはユーザーがログインすると読み込まれ、デーモンはシステムの起動時に読み込まれる**ことです（sshなどのサービスは、ユーザーがシステムにアクセスする前に実行する必要があるため）。また、エージェントはGUIを使用する場合がありますが、デーモンはバックグラウンドで実行する必要があります。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>/Users/username/malware</string>
</array>
<key>RunAtLoad</key><true/> <!--Execute at system startup-->
<key>StartInterval</key>
<integer>800</integer> <!--Execute each 800s-->
<key>KeepAlive</key>
<dict>
<key>SuccessfulExit</key></false> <!--Re-execute if exit unsuccessful-->
<!--If previous is true, then re-execute in successful exit-->
</dict>
</dict>
</plist>
```
ユーザーがログインする前に**エージェントを実行する必要がある**場合があります。これらは**PreLoginAgents**と呼ばれます。たとえば、これはログイン時に支援技術を提供するために役立ちます。これらは`/Library/LaunchAgents`にも見つけることができます（[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)に例があります）。

\{% hint style="info" %\} 新しいデーモンまたはエージェントの設定ファイルは、**次回の再起動後または** `launchctl load <target.plist>`を使用して**ロードされます**。また、拡張子なしで`.plist`ファイルをロードすることも可能です。`launchctl -F <file>`（ただし、これらのplistファイルは自動的に再起動後にロードされません）。
`launchctl unload <target.plist>`を使用して**アンロード**することも可能です（それによって指定されたプロセスは終了します）。

**エージェント**または**デーモン**が**実行されるのを妨げる**（オーバーライドなど）**何もないこと**を**確認する**には、次のコマンドを実行します：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist` \{% endhint %\}

現在のユーザーによってロードされているすべてのエージェントとデーモンをリストアップします：
```bash
launchctl list
```
### Cron

以下のコマンドで、**現在のユーザー**のcronジョブをリストします。
```bash
crontab -l
```
ユーザーのすべてのcronジョブは、**`/usr/lib/cron/tabs/`**と**`/var/at/tabs/`**（root権限が必要）にあります。

MacOSでは、**特定の頻度**でスクリプトを実行するいくつかのフォルダが次の場所にあります：
```bash
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
以下では、通常のcronジョブ、あまり使用されないatジョブ、および一時ファイルのクリーニングに主に使用される定期ジョブが見つかります。たとえば、デイリーの定期ジョブは次のように実行できます：`periodic daily`。

定期スクリプト（`/etc/periodic`）は、`/System/Library/LaunchDaemons/com.apple.periodic*`に設定されたランチデーモンのために実行されます。スクリプトが特権を昇格させるために`/etc/periodic/`に保存されている場合、それはファイルの所有者として実行されることに注意してください。
```bash
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist
```
### kext

スタートアップアイテムとしてKEXTをインストールするためには、次のいずれかの場所に**インストールする必要があります**：

* `/System/Library/Extensions`
* OS Xオペレーティングシステムに組み込まれたKEXTファイル。
* `/Library/Extensions`
* サードパーティのソフトウェアによってインストールされたKEXTファイル

現在ロードされているkextファイルをリストするには、次のコマンドを使用します：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
詳細については、[**カーネル拡張に関するこのセクション**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers)を参照してください。

### **ログイン項目**

システム環境設定 -> ユーザーとグループ -> **ログイン項目**では、**ユーザーがログインするときに実行される項目**を見つけることができます。\
これらをリストアップしたり、コマンドラインから追加や削除することが可能です。
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
これらのアイテムは、ファイル/Users/\<username>/Library/Application Support/com.apple.backgroundtaskmanagementagentに保存されます。

### ログインアイテムとしてのZIP

**ZIP**ファイルを**ログインアイテム**として保存すると、**`Archive Utility`**がそれを開きます。たとえば、ZIPが**`~/Library`**に保存され、バックドアを含む**`LaunchAgents/file.plist`**フォルダが含まれている場合、そのフォルダが作成され（デフォルトでは作成されません）、plistが追加されます。したがって、次回ユーザーがログインすると、plistで指定された**バックドアが実行されます**。

別のオプションは、ユーザーのホームディレクトリに**`.bash_profile`**と**`.zshenv`**ファイルを作成することです。したがって、LaunchAgentsフォルダが既に存在する場合でも、このテクニックは機能します。

### At

「Atタスク」は、特定の時間にタスクをスケジュールするために使用されます。\
これらのタスクはcronと異なり、**一度だけ実行された後に削除される**タスクです。ただし、システムの再起動後も残るため、潜在的な脅威として排除することはできません。

**デフォルトでは**無効化されていますが、**root**ユーザーはこれらを**有効化**することができます。
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これにより、13:37にファイルが作成されます。
```bash
echo hello > /tmp/hello | at 1337
```
### ログイン/ログアウトフック

これらは非推奨ですが、ユーザーがログインする際にコマンドを実行するために使用することができます。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
```
この設定は`/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`に保存されています。
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
削除するには：
```bash
defaults delete com.apple.loginwindow LoginHook
```
前の例では、**LoginHook**を作成して削除しましたが、**LogoutHook**を作成することも可能です。

ルートユーザーの場合、**`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**に保存されます。

### アプリケーションの設定

**`~/Library/Preferences`**には、アプリケーションのユーザーの設定が保存されます。これらの設定の中には、**他のアプリケーション/スクリプトを実行する**ための構成が含まれているものもあります。

例えば、Terminalは起動時にコマンドを実行することができます:

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、ファイル**`~/Library/Preferences/com.apple.Terminal.plist`**に以下のように反映されます:
```bash
[...]
"Window Settings" => {
"Basic" => {
"CommandString" => "touch /tmp/terminal_pwn"
"Font" => {length = 267, bytes = 0x62706c69 73743030 d4010203 04050607 ... 00000000 000000cf }
"FontAntialias" => 1
"FontWidthSpacing" => 1.004032258064516
"name" => "Basic"
"ProfileCurrentVersion" => 2.07
"RunCommandAsShell" => 0
"type" => "Window Settings"
}
[...]
```
### Emond

Appleは**emond**というログ記録メカニズムを導入しました。これは完全に開発されなかったようで、Appleが他のメカニズムに移行したため、開発が**放棄**された可能性もありますが、まだ**利用可能**です。

このあまり知られていないサービスは、Macの管理者には**あまり役に立たないかもしれません**が、脅威の存在としては、macOSの管理者がおそらく**調査しないであろう永続性のメカニズム**として使用する理由が非常に優れています。emondの悪用を検出することは難しくありません。なぜなら、サービスのSystem LaunchDaemonはスクリプトを実行する場所を**1か所だけ**探すからです：
```bash
ls -l /private/var/db/emondClients
```
{% hint style="danger" %}
**あまり使用されていないため、そのフォルダ内のすべてのものは疑わしいものと見なすべきです**
{% endhint %}

### スタートアップアイテム

{% hint style="danger" %}
**これは非推奨ですので、以下のディレクトリには何も見つかるべきではありません。**
{% endhint %}

**StartupItem**は、次の2つのフォルダのいずれかに**配置**される**ディレクトリ**です。`/Library/StartupItems/`または`/System/Library/StartupItems/`

これらの2つの場所のいずれかに新しいディレクトリを配置した後、そのディレクトリ内に**2つのアイテム**をさらに配置する必要があります。これらの2つのアイテムは、**rcスクリプト**といくつかの設定を保持する**plist**です。このplistは「**StartupParameters.plist**」と呼ばれる必要があります。

{% tabs %}
{% tab title="StartupParameters.plist" %}
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>Description</key>
<string>This is a description of this service</string>
<key>OrderPreference</key>
<string>None</string> <!--Other req services to execute before this -->
<key>Provides</key>
<array>
<string>superservicename</string> <!--Name of the services provided by this file -->
</array>
</dict>
</plist>
```
{% tab title="superservicename" %}スーパーサービス名
```bash
#!/bin/sh
. /etc/rc.common

StartService(){
touch /tmp/superservicestarted
}

StopService(){
rm /tmp/superservicestarted
}

RestartService(){
echo "Restarting"
}

RunService "$1"
```
{% endtab %}
{% endtabs %}

### /etc/rc.common

{% hint style="danger" %}
**これは最新のMacOSバージョンでは機能しません**
{% endhint %}

ここには**起動時に実行されるコマンドを配置することもできます。**通常のrc.commonスクリプトの例：
```bash
#
# Common setup for startup scripts.
#
# Copyright 1998-2002 Apple Computer, Inc.
#

######################
# Configure the shell #
######################

#
# Be strict
#
#set -e
set -u

#
# Set command search path
#
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec:/System/Library/CoreServices; export PATH

#
# Set the terminal mode
#
#if [ -x /usr/bin/tset ] && [ -f /usr/share/misc/termcap ]; then
#    TERM=$(tset - -Q); export TERM
#fi

###################
# Useful functions #
###################

#
# Determine if the network is up by looking for any non-loopback
# internet network interfaces.
#
CheckForNetwork()
{
local test

if [ -z "${NETWORKUP:=}" ]; then
test=$(ifconfig -a inet 2>/dev/null | sed -n -e '/127.0.0.1/d' -e '/0.0.0.0/d' -e '/inet/p' | wc -l)
if [ "${test}" -gt 0 ]; then
NETWORKUP="-YES-"
else
NETWORKUP="-NO-"
fi
fi
}

alias ConsoleMessage=echo

#
# Process management
#
GetPID ()
{
local program="$1"
local pidfile="${PIDFILE:=/var/run/${program}.pid}"
local     pid=""

if [ -f "${pidfile}" ]; then
pid=$(head -1 "${pidfile}")
if ! kill -0 "${pid}" 2> /dev/null; then
echo "Bad pid file $pidfile; deleting."
pid=""
rm -f "${pidfile}"
fi
fi

if [ -n "${pid}" ]; then
echo "${pid}"
return 0
else
return 1
fi
}

#
# Generic action handler
#
RunService ()
{
case $1 in
start  ) StartService   ;;
stop   ) StopService    ;;
restart) RestartService ;;
*      ) echo "$0: unknown argument: $1";;
esac
}
```
### プロファイル

設定プロファイルは、ユーザーに特定のブラウザの設定、DNSプロキシの設定、またはVPNの設定を使用させることができます。その他にも、悪用される可能性のある多くのペイロードが存在します。

次のコマンドを実行して、それらを列挙することができます。
```bash
ls -Rl /Library/Managed\ Preferences/
```
### その他の持続性の技術とツール

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ企業で働いていますか？** **HackTricksで会社を宣伝**したいですか？または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロード**したいですか？[**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見しましょう。独占的な[**NFT**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS＆HackTricksのグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* [**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)または[**telegramグループ**](https://t.me/peass)に**参加**するか、**Twitter**で**フォロー**してください[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**。**
* **ハッキングのトリックを共有するには、PRを** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **と** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud) **に提出してください。**

</details>
