# 从 KIOSKs 中逃逸

{{#include ../banners/hacktricks-training.md}}

---

## 检查物理设备

| 组件         | 操作                                                               |
| ------------ | ------------------------------------------------------------------ |
| 电源按钮     | 关闭并重新打开设备可能会显示启动屏幕                               |
| 电源线       | 检查短暂断电时设备是否会重新启动                                   |
| USB 端口     | 连接物理键盘以使用更多快捷键                                      |
| Ethernet     | Network scan 或 sniffing 可能会启用进一步的 exploitation           |

## 检查 GUI 应用程序中的可能操作

**Common Dialogs** 是指**保存文件**、**打开文件**、选择字体、颜色等选项。它们中的大多数都会**提供完整的 Explorer 功能**。这意味着，如果你可以访问以下选项，就能够访问 Explorer 功能：

- 关闭/另存为
- 打开/打开方式
- 打印
- 导出/导入
- 搜索
- 扫描

你应该检查是否可以：

- 修改或创建新文件
- 创建 symbolic links
- 访问受限区域
- 执行其他应用程序

### Command Execution

也许通过 **`Open with`** 选项\*\*可以打开/执行某种 shell。

#### Windows

例如 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 在此查找更多可用于执行命令（并执行意外操作）的 binaries：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

#### \*NIX \_\_

_bash, sh, zsh..._ 更多内容见：[https://gtfobins.github.io/](https://gtfobins.github.io)

## Windows

### 绕过路径限制

- **Environment variables**：有许多 environment variables 指向某个路径
- **其他 protocols**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **Symbolic links**
- **Shortcuts**：CTRL+N（打开新会话）、CTRL+R（Execute Commands）、CTRL+SHIFT+ESC（Task Manager）、Windows+E（打开 Explorer）、CTRL-B、CTRL-I（Favourites）、CTRL-H（History）、CTRL-L、CTRL-O（File/Open Dialog）、CTRL-P（Print Dialog）、CTRL-S（Save As）
- 隐藏的 Administrative menu：CTRL-ALT-F8、CTRL-ESC-F9
- **Shell URIs**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC paths**：用于连接共享文件夹的路径。你应该尝试连接本地机器的 C$（"\\\127.0.0.1\c$\Windows\System32"）
- **更多 UNC paths：**

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

- **Dialog-box pivoting**：将 *Open/Save/Print-to-file* 对话框作为精简版 Explorer 使用。在文件名字段中尝试 `*.*` / `*.exe`，右键单击文件夹选择 **Open in new window**，并使用 **Properties → Open file location** 扩展导航范围。<sup>[[1]](#references)</sup>
- **从对话框创建 execution paths**：创建新文件并将其重命名为 `.CMD` 或 `.BAT`，或者创建一个指向 `%WINDIR%\System32`（或特定 binary，如 `%WINDIR%\System32\cmd.exe`）的 shortcut。
- **Shell launch pivots**：如果可以浏览到 `cmd.exe`，尝试将任意文件**拖放**到其上以启动 prompt。如果可以访问 Task Manager（`CTRL+SHIFT+ESC`），则使用 **Run new task**。
- **Task Scheduler bypass**：如果 interactive shells 被阻止但允许 scheduling，则创建一个运行 `cmd.exe` 的 task（GUI `taskschd.msc` 或 `schtasks.exe`）。
- **Weak allowlists**：如果通过**文件名/扩展名**允许执行，则将 payload 重命名为允许的名称。如果通过**目录**允许执行，则将 payload 复制到允许的 program folder 中并在那里运行。
- **查找可写入的 staging paths**：从 `%TEMP%` 开始，并使用 Sysinternals AccessChk 枚举可写入的文件夹。
```cmd
echo %TEMP%
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\
```
- **下一步**：如果你获得了 shell，请转向 Windows LPE checklist：
{{#ref}}
../windows-hardening/checklist-windows-privilege-escalation.md
{{#endref}}

### 下载你的 Binaries

Console: [https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
Explorer: [https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
Registry editor: [https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

### 从浏览器访问文件系统

| PATH                | PATH              | PATH               | PATH               |
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
- Filter Keys – 按住右 SHIFT 12 秒
- WINDOWS+F1 – Windows Search
- WINDOWS+D – 显示桌面
- WINDOWS+E – 启动 Windows Explorer
- WINDOWS+R – Run
- WINDOWS+U – Ease of Access Centre
- WINDOWS+F – Search
- SHIFT+F10 – Context Menu
- CTRL+SHIFT+ESC – Task Manager
- CTRL+ALT+DEL – 较新 Windows 版本中的启动画面
- F1 – Help F3 – Search
- F6 – Address Bar
- F11 – 在 Internet Explorer 中切换全屏
- CTRL+H – Internet Explorer History
- CTRL+T – Internet Explorer – New Tab
- CTRL+N – Internet Explorer – New Page
- CTRL+O – Open File
- CTRL+S – Save CTRL+N – New RDP / Citrix

### 滑动手势

- 从左侧向右滑动，以查看所有已打开的 Windows，同时最小化 KIOSK app 并直接访问整个 OS；
- 从右侧向左滑动，以打开 Action Center，同时最小化 KIOSK app 并直接访问整个 OS；
- 从顶部边缘向下滑动，使以全屏模式打开的 app 显示标题栏；
- 从底部向上滑动，在全屏 app 中显示任务栏。

### Internet Explorer 技巧

#### “Image Toolbar”

这是点击图像后出现在其左上方的工具栏。你可以 Save、Print、Mailto，或在 Explorer 中打开 “My Pictures”。Kiosk 必须使用 Internet Explorer。

#### Shell Protocol

输入以下 URLs 以获得 Explorer 视图：

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
- `shell:::{21EC2020-3AEA-1069-A2DD-08002B30309D}` --> Control Panel
- `shell:::{20D04FE0-3AEA-1069-A2D8-08002B30309D}` --> My Computer
- `shell:::{{208D2C60-3AEA-1069-A2D7-08002B30309D}}` --> My Network Places
- `shell:::{871C5380-42A0-1069-A2EA-08002B30309D}` --> Internet Explorer

### 显示文件扩展名

查看此页面以了解更多信息：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)<sup>[[7]](#references)</sup>

## 浏览器技巧

Backup iKat versions:

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)

使用 JavaScript 创建 common dialog 并访问 file explorer：`document.write('<input/type=file>')`<sup>[[2]](#references)</sup>\
Source: https://medium.com/@Rend\_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

## iPad

### 手势和按钮

- 用四（或五）根手指向上滑动 / 双击 Home button：查看 multitask view 并切换 App
- 用四或五根手指向左或向右滑动：切换到下一个/上一个 App
- 用五根手指捏合屏幕 / 触摸 Home button / 用 1 根手指从屏幕底部快速向上滑动：访问 Home
- 用 1 根手指从屏幕底部向上滑动 1-2 英寸（缓慢）：显示 dock
- 用 1 根手指从显示屏顶部向下滑动：查看 notifications
- 用 1 根手指从屏幕右上角向下滑动：查看 iPad Pro 的 control centre
- 用 1 根手指从屏幕左侧向右滑动 1-2 英寸：查看 Today view
- 用 1 根手指从屏幕中央快速向右或向左滑动：切换到下一个/上一个 App
- 按住 iPad 右上角的 On/**Off**/Sleep button + 将 Slide to **power off** 滑块一直向右移动：关机
- 按住 iPad 右上角的 On/**Off**/Sleep button 和 Home button 几秒：强制硬关机
- 快速按下 iPad 右上角的 On/**Off**/Sleep button 和 Home button：截取屏幕截图，截图会出现在显示屏左下角。需要同时短暂按下两个按钮；如果按住几秒，则会执行硬关机。<sup>[[3]](#references)</sup>

### 快捷键

你应当准备一个 iPad keyboard 或 USB keyboard adaptor。这里只列出可能有助于逃离 app 的快捷键。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

| Key | Name         |
| --- | ------------ |
| ⌘   | Command      |
| ⌥   | Option (Alt) |
| ⇧   | Shift        |
| ↩   | Return       |
| ⇥   | Tab          |
| ^   | Control      |
| ←   | Left Arrow   |
| →   | Right Arrow  |
| ↑   | Up Arrow     |
| ↓   | Down Arrow   |

#### 系统快捷键

这些快捷键用于视觉设置和声音设置，具体取决于 iPad 的使用方式。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 调暗屏幕                                                                    |
| F2       | 调亮屏幕                                                                |
| F7       | 上一首歌曲                                                                  |
| F8       | 播放/暂停                                                                     |
| F9       | 跳过歌曲                                                                      |
| F10      | 静音                                                                           |
| F11      | 降低音量                                                                |
| F12      | 增大音量                                                                |
| ⌘ Space  | 显示可用语言列表；再次点击空格键以选择语言。 |

#### iPad 导航

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | 转到 Home                                              |
| ⌘⇧H (Command-Shift-H)                              | 转到 Home                                              |
| ⌘ (Space)                                          | 打开 Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | 列出最近使用的十个 app                                 |
| ⌘\~                                                | 转到上一个 App                                       |
| ⌘⇧3 (Command-Shift-3)                              | 截图（悬浮在左下角，可保存或操作） |
| ⌘⇧4                                                | 截图并在 editor 中打开                    |
| 按住 ⌘                                   | 列出该 App 可用的快捷键                 |
| ⌘⌥D (Command-Option/Alt-D)                         | 调出 dock                                      |
| ^⌥H (Control-Option-H)                             | Home button                                             |
| ^⌥H H (Control-Option-H-H)                         | 显示 multitask bar                                      |
| ^⌥I (Control-Option-i)                             | Item chooser                                            |
| Escape                                             | Back button                                             |
| → (Right arrow)                                    | 下一个项目                                               |
| ← (Left arrow)                                     | 上一个项目                                           |
| ↑↓ (Up arrow, Down arrow)                          | 同时点击选中的项目                        |
| ⌥ ↓ (Option-Down arrow)                            | 向下滚动                                             |
| ⌥↑ (Option-Up arrow)                               | 向上滚动                                               |
| ⌥← or ⌥→ (Option-Left arrow or Option-Right arrow) | 向左或向右滚动                                    |
| ^⌥S (Control-Option-S)                             | 开启或关闭 VoiceOver speech                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 切换到上一个 app                              |
| ⌘⇥ (Command-Tab)                                   | 切换回原始 app                         |
| ←+→, then Option + ← or Option+→                   | 在 Dock 中导航                                   |

#### Safari 快捷键

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 打开 Location                                    |
| ⌘T                      | 打开新标签页                                   |
| ⌘W                      | 关闭当前标签页                            |
| ⌘R                      | 刷新当前标签页                          |
| ⌘.                      | 停止加载当前标签页                     |
| ^⇥                      | 切换到下一个标签页                           |
| ^⇧⇥ (Control-Shift-Tab) | 移动到上一个标签页                         |
| ⌘L                      | 选择文本输入/URL 字段进行修改     |
| ⌘⇧T (Command-Shift-T)   | 打开最近关闭的标签页（可多次使用） |
| ⌘\[                     | 在浏览历史中后退一页      |
| ⌘]                      | 在浏览历史中前进一页   |
| ⌘⇧R                     | 激活 Reader Mode                             |

#### Mail 快捷键

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 打开 Location                |
| ⌘T                         | 打开新标签页               |
| ⌘W                         | 关闭当前标签页               |
| ⌘R                         | 刷新当前标签页               |
| ⌘.                         | 停止加载当前标签页 |
| ⌘⌥F (Command-Option/Alt-F) | 在 mailbox 中搜索       |

## References

- [1] [Breaking Out of Citrix and other Restricted Desktop Environments](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [2] [Give me a browser, I'll give you a shell](https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0)
- [3] [6 only-for-iPad gestures you need to know](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [4] [iPad shortcuts guide](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [5] [Best iPad Keyboard Shortcuts](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [6] [iPad Keyboard Shortcuts](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)
- [7] [howtohaven.com - Show File Extensions In Windows Explorer](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

{{#include ../banners/hacktricks-training.md}}
