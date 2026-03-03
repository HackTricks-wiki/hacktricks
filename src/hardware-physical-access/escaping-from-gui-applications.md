# 从 KIOSKs 逃逸

{{#include ../banners/hacktricks-training.md}}

---

## 检查物理设备

| Component    | Action                                                             |
| ------------ | ------------------------------------------------------------------ |
| Power button | 关闭并重新开机可能会显示开始屏幕                                   |
| Power cable  | 检查在短暂断电后设备是否会重启                                      |
| USB ports    | 连接物理键盘以使用更多快捷键                                         |
| Ethernet     | 网络扫描或嗅探可能允许进一步利用                                     |

## 检查 GUI 应用内的可能操作

**Common Dialogs** 是指那些 **保存文件**、**打开文件**、选择字体、颜色等选项……它们中的大多数会**提供完整的 Explorer 功能**。这意味着如果你能访问这些选项，就能够使用 Explorer 的功能：

- Close/Close as
- Open/Open with
- Print
- Export/Import
- Search
- Scan

你应该检查是否可以：

- 修改或创建新文件
- 创建符号链接
- 访问受限区域
- 执行其他应用

### 命令执行

也许 **using a `Open with`** option\*\* 你可以打开/执行某种 shell。

#### Windows

例如 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 在这里可以找到更多可用于执行命令（并执行意外操作）的二进制文件: [https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ 更多信息见: [https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### 绕过路径限制

- **Environment variables**: 有很多环境变量指向某些路径
- **Other protocols**: _about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**: CTRL+N (open new session), CTRL+R (Execute Commands), CTRL+SHIFT+ESC (Task Manager), Windows+E (open explorer), CTRL-B, CTRL-I (Favourites), CTRL-H (History), CTRL-L, CTRL-O (File/Open Dialog), CTRL-P (Print Dialog), CTRL-S (Save As)
- Hidden Administrative menu: CTRL-ALT-F8, CTRL-ESC-F9
- **Shell URIs**: _shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**: 用于连接共享文件夹的路径。你应该尝试连接本地机器的 C$（"\\\127.0.0.1\c$\Windows\System32"）
- **More UNC paths:**

| UNC                       | UNC            | UNC                  |
| ------------------------- | -------------- | -------------------- |
| %ALLUSERSPROFILE%         | %APPDATA%      | %CommonProgramFiles% |
| %COMMONPROGRAMFILES(x86)% | %COMPUTERNAME% | %COMSPEC%            |
| %HOMEDRIVE%               | %HOMEPATH%     | %LOCALAPPDATA%       |
| %LOGONSERVER%             | %PATH%         | %PATHEXT%            |
| %ProgramData%             | %ProgramFiles% | %ProgramFiles(x86)%  |
| %PROMPT%                  | %PSModulePath% | %Public%             |
| %SYSTEMDRIVE%             | %SYSTEMROOT%   | %TEMP%               |
| %TMP%                     | %USERDOMAIN%   | %USERNAME%           |
| %USERPROFILE%             | %WINDIR%       |                      |

### 受限桌面逃逸（Citrix/RDS/VDI）

- **Dialog-box pivoting**: 将 *Open/Save/Print-to-file* 对话框作为精简版 Explorer 使用。尝试在文件名字段中输入 `*.*` / `*.exe`，右键单击文件夹选择 **Open in new window**，并使用 **Properties → Open file location** 来扩展导航。
- **Create execution paths from dialogs**: 创建新文件并重命名为 `.CMD` 或 `.BAT`，或创建指向 `%WINDIR%\System32`（或指向特定二进制文件如 `%WINDIR%\System32\cmd.exe`）的快捷方式。
- **Shell launch pivots**: 如果可以浏览到 `cmd.exe`，尝试将任意文件**拖放**到其上以启动提示符。如果可以打开任务管理器（`CTRL+SHIFT+ESC`），使用 **Run new task**。
- **Task Scheduler bypass**: 如果交互式 shell 被阻止但允许调度，创建一个运行 `cmd.exe` 的任务（GUI `taskschd.msc` 或 `schtasks.exe`）。
- **Weak allowlists**: 如果执行被 **filename/extension** 限制，通过把你的有效载荷重命名为允许的名称来绕过。如果被 **directory** 限制，将有效载荷复制到允许的程序文件夹并在那里运行。
- **Find writable staging paths**: 从 `%TEMP%` 开始，并使用 Sysinternals AccessChk 列举可写文件夹。
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **下一步**：如果你获得了 shell，请转向 Windows LPE 检查表：
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### 下载所需二进制文件

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### 从浏览器访问文件系统

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

### 快捷键

- Sticky Keys – 按 SHIFT 5 次
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – 按住 NUMLOCK 5 秒
- Filter Keys – 按住右侧 SHIFT 12 秒
- WINDOWS+F1 – Windows 搜索
- WINDOWS+D – 显示桌面
- WINDOWS+E – 启动 Windows Explorer
- WINDOWS+R – 运行
- WINDOWS+U – 辅助功能中心
- WINDOWS+F – 搜索
- SHIFT+F10 – 上下文菜单
- CTRL+SHIFT+ESC – 任务管理器
- CTRL+ALT+DEL – 新版本 Windows 的启动画面
- F1 – 帮助 F3 – 搜索
- F6 – 地址栏
- F11 – 在 Internet Explorer 中切换全屏
- CTRL+H – Internet Explorer 历史记录
- CTRL+T – Internet Explorer 新标签
- CTRL+N – Internet Explorer 新页面
- CTRL+O – 打开文件
- CTRL+S – 保存 CTRL+N – 新建 RDP / Citrix

### 滑动手势

- 从左向右滑动以查看所有打开的窗口，最小化 KIOSK 应用并直接访问整个操作系统；
- 从右向左滑动以打开操作中心，最小化 KIOSK 应用并直接访问整个操作系统；
- 从顶部边缘向内滑动以在全屏模式下显示应用的标题栏；
- 从底部向上滑动以在全屏应用中显示任务栏。

### Internet Explorer 技巧

#### 'Image Toolbar'

这是在点击图片时出现在左上角的工具栏。你可以执行 Save、Print、Mailto、在 Explorer 中打开 "My Pictures" 等操作。Kiosk 需要使用 Internet Explorer。

#### Shell 协议

输入以下 URL 可获取 Explorer 视图：

- `shell:Administrative Tools`
- `shell:DocumentsLibrary`
- `shell:Libraries`
- `shell:UserProfiles`
- `shell:Personal`
- `shell:SearchHomeFolder`
- `shell:NetworkPlacesFolder`
- `shell:SendTo`
- `shell:UserProfiles`
- `shell:Common Administrative Tools`
- `shell:MyComputerFolder`
- `shell:InternetFolder`
- `Shell:Profile`
- `Shell:ProgramFiles`
- `Shell:System`
- `Shell:ControlPanelFolder`
- `Shell:Windows`
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> 控制面板
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> 我的电脑
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> 我的网络位置
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### 显示文件扩展名

有关更多信息，请查看此页面： [https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

## 浏览器技巧

备用 iKat 版本：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

使用 JavaScript 创建通用对话框并访问文件资源管理器： `document.write('<input/type=file>')`\
来源: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### 手势与按键

- 用四指（或五指）向上滑 / 双击 Home 按钮：查看多任务视图并切换应用
- 用四指或五指向任一方向滑动：切换到下一/上一个应用
- 用五指捏合屏幕 / 触按 Home 按钮 / 以快速动作从屏幕底部向上用一指滑动：回到主屏幕
- 用一指从屏幕底部缓慢向上滑动约 1-2 英寸：显示 Dock
- 用一指从显示屏顶部向下滑动：查看通知
- 用一指从屏幕右上角向下滑动：查看 iPad Pro 的控制中心
- 用一指从屏幕左侧向内滑动 1-2 英寸：查看今日视图
- 从屏幕中央快速向左或向右用一指滑动：切换到下一/上一个应用
- 按住并按住 iPad 右上角的开/关/睡眠按钮：将 “滑动以关机” 滑块全部滑到右侧以关机
- 同时按住 iPad 右上角的开/关/睡眠按钮和 Home 按钮几秒钟：强制关机
- 快速同时按下 iPad 右上角的开/关/睡眠按钮和 Home 按钮：截屏（会在左下角弹出）。如果你长按这两个按钮几秒，会执行强制关机。

### 快捷键

你需要一个 iPad 键盘或 USB 键盘适配器。这里只列出可能帮助退出应用的快捷键。

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | 左箭头       |
| →   | 右箭头       |
| ↑   | 上箭头       |
| ↓   | 下箭头       |

#### 系统快捷键

这些快捷键用于视觉设置和声音设置，取决于 iPad 的使用情况。

| Shortcut | Action                                                                 |
| -------- | ---------------------------------------------------------------------- |
| F1       | 降低屏幕亮度                                                             |
| F2       | 增加屏幕亮度                                                             |
| F7       | 返回上一曲                                                               |
| F8       | 播放/暂停                                                               |
| F9       | 跳到下一曲                                                               |
| F10      | 静音                                                                     |
| F11      | 减小音量                                                                 |
| F12      | 增大音量                                                                 |
| ⌘ Space  | 显示可用语言列表；要选择其中一种，再次按空格键。                        |

#### iPad 导航

| Shortcut                                           | Action                                                      |
| -------------------------------------------------- | ----------------------------------------------------------- |
| ⌘H                                                 | 返回主屏幕                                                   |
| ⌘⇧H (Command-Shift-H)                              | 返回主屏幕                                                   |
| ⌘ (Space)                                          | 打开 Spotlight                                               |
| ⌘⇥ (Command-Tab)                                   | 列出最近使用的十个应用                                        |
| ⌘\~                                                | 切换到上一个应用                                               |
| ⌘⇧3 (Command-Shift-3)                              | 截屏（会在左下角悬浮，可保存或处理）                           |
| ⌘⇧4                                                | 截屏并在编辑器中打开                                           |
| Press and hold ⌘                                   | 列出该应用可用的快捷键                                         |
| ⌘⌥D (Command-Option/Alt-D)                         | 显示 Dock                                                    |
| ^⌥H (Control-Option-H)                             | Home 键                                                      |
| ^⌥H H (Control-Option-H-H)                         | 显示多任务栏                                                  |
| ^⌥I (Control-Option-i)                             | 项目选择器                                                    |
| Escape                                             | 返回按钮                                                      |
| → (Right arrow)                                    | 下一个项目                                                    |
| ← (Left arrow)                                     | 上一个项目                                                    |
| ↑↓ (Up arrow, Down arrow)                          | 同时点击所选项目                                               |
| ⌥ ↓ (Option-Down arrow)                            | 向下滚动                                                      |
| ⌥↑ (Option-Up arrow)                               | 向上滚动                                                      |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 向左或向右滚动                                                |
| ^⌥S (Control-Option-S)                             | 打开或关闭 VoiceOver 语音                                      |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 切换到上一个应用                                               |
| ⌘⇥ (Command-Tab)                                   | 切换回原始应用                                                |
| ←+→, then Option + ← or Option+→                   | 在 Dock 中导航                                                 |

#### Safari 快捷键

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 打开地址栏                                       |
| ⌘T                      | 打开新标签                                       |
| ⌘W                      | 关闭当前标签                                     |
| ⌘R                      | 刷新当前标签                                     |
| ⌘.                      | 停止加载当前标签                                  |
| ^⇥                      | 切换到下一个标签                                   |
| ^⇧⇥ (Control-Shift-Tab) | 切换到上一个标签                                   |
| ⌘L                      | 选中地址/输入字段以便修改                          |
| ⌘⇧T (Command-Shift-T)   | 打开上一次关闭的标签（可多次使用）                 |
| ⌘\[                     | 在浏览历史中后退一页                                |
| ⌘]                      | 在浏览历史中前进一页                                |
| ⌘⇧R                     | 启用阅读模式                                       |

#### Mail 快捷键

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 打开地址栏                    |
| ⌘T                         | 打开新标签                    |
| ⌘W                         | 关闭当前标签                  |
| ⌘R                         | 刷新当前标签                  |
| ⌘.                         | 停止加载当前标签               |
| ⌘⌥F (Command-Option/Alt-F) | 在邮箱中搜索                  |

## 参考资料

- [https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../banners/hacktricks-training.md}}
