{{#include ../../banners/hacktricks-training.md}}

# 检查 GUI 应用程序内可能的操作

**常见对话框**是指**保存文件**、**打开文件**、选择字体、颜色等选项。大多数情况下，它们将**提供完整的资源管理器功能**。这意味着如果您可以访问这些选项，您将能够访问资源管理器的功能：

- 关闭/另存为
- 打开/使用其他程序打开
- 打印
- 导出/导入
- 搜索
- 扫描

您应该检查是否可以：

- 修改或创建新文件
- 创建符号链接
- 访问受限区域
- 执行其他应用程序

## 命令执行

也许**使用 `Open with` 选项**，您可以打开/执行某种 shell。

### Windows

例如 _cmd.exe, command.com, Powershell/Powershell ISE, mmc.exe, at.exe, taskschd.msc..._ 在这里找到更多可以用来执行命令（并执行意外操作）的二进制文件：[https://lolbas-project.github.io/](https://lolbas-project.github.io)

### \*NIX \_\_

_bash, sh, zsh..._ 更多信息请见：[https://gtfobins.github.io/](https://gtfobins.github.io)

# Windows

## 绕过路径限制

- **环境变量**：有很多环境变量指向某个路径
- **其他协议**：_about:, data:, ftp:, file:, mailto:, news:, res:, telnet:, view-source:_
- **符号链接**
- **快捷方式**：CTRL+N（打开新会话），CTRL+R（执行命令），CTRL+SHIFT+ESC（任务管理器），Windows+E（打开资源管理器），CTRL-B，CTRL-I（收藏夹），CTRL-H（历史记录），CTRL-L，CTRL-O（文件/打开对话框），CTRL-P（打印对话框），CTRL-S（另存为）
- 隐藏的管理菜单：CTRL-ALT-F8，CTRL-ESC-F9
- **Shell URIs**：_shell:Administrative Tools, shell:DocumentsLibrary, shell:Librariesshell:UserProfiles, shell:Personal, shell:SearchHomeFolder, shell:Systemshell:NetworkPlacesFolder, shell:SendTo, shell:UsersProfiles, shell:Common Administrative Tools, shell:MyComputerFolder, shell:InternetFolder_
- **UNC 路径**：连接到共享文件夹的路径。您应该尝试连接到本地计算机的 C$（"\\\127.0.0.1\c$\Windows\System32"）
- **更多 UNC 路径：**

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

## 下载您的二进制文件

控制台：[https://sourceforge.net/projects/console/](https://sourceforge.net/projects/console/)\
资源管理器：[https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/](https://sourceforge.net/projects/explorerplus/files/Explorer%2B%2B/)\
注册表编辑器：[https://sourceforge.net/projects/uberregedit/](https://sourceforge.net/projects/uberregedit/)

## 从浏览器访问文件系统

| PATH                | PATH              | PATH               | PATH                |
| ------------------- | ----------------- | ------------------ | ------------------- |
| File:/C:/windows    | File:/C:/windows/ | File:/C:/windows\\ | File:/C:\windows    |
| File:/C:\windows\\  | File:/C:\windows/ | File://C:/windows  | File://C:/windows/  |
| File://C:/windows\\ | File://C:\windows | File://C:\windows/ | File://C:\windows\\ |
| C:/windows          | C:/windows/       | C:/windows\\       | C:\windows          |
| C:\windows\\        | C:\windows/       | %WINDIR%           | %TMP%               |
| %TEMP%              | %SYSTEMDRIVE%     | %SYSTEMROOT%       | %APPDATA%           |
| %HOMEDRIVE%         | %HOMESHARE        |                    | <p><br></p>         |

## 快捷键

- Sticky Keys – 按 SHIFT 5 次
- Mouse Keys – SHIFT+ALT+NUMLOCK
- High Contrast – SHIFT+ALT+PRINTSCN
- Toggle Keys – 按住 NUMLOCK 5 秒
- Filter Keys – 按住右 SHIFT 12 秒
- WINDOWS+F1 – Windows 搜索
- WINDOWS+D – 显示桌面
- WINDOWS+E – 启动 Windows 资源管理器
- WINDOWS+R – 运行
- WINDOWS+U – 辅助功能中心
- WINDOWS+F – 搜索
- SHIFT+F10 – 上下文菜单
- CTRL+SHIFT+ESC – 任务管理器
- CTRL+ALT+DEL – 在较新版本的 Windows 上显示启动画面
- F1 – 帮助 F3 – 搜索
- F6 – 地址栏
- F11 – 在 Internet Explorer 中切换全屏
- CTRL+H – Internet Explorer 历史记录
- CTRL+T – Internet Explorer – 新标签
- CTRL+N – Internet Explorer – 新页面
- CTRL+O – 打开文件
- CTRL+S – 保存 CTRL+N – 新 RDP / Citrix

## 滑动操作

- 从左侧向右滑动以查看所有打开的窗口，最小化 KIOSK 应用程序并直接访问整个操作系统；
- 从右侧向左滑动以打开操作中心，最小化 KIOSK 应用程序并直接访问整个操作系统；
- 从顶部边缘向下滑动以使全屏模式下的应用程序的标题栏可见；
- 从底部向上滑动以在全屏应用程序中显示任务栏。

## Internet Explorer 技巧

### '图像工具栏'

这是一个在单击图像时出现在左上角的工具栏。您将能够保存、打印、发送邮件、在资源管理器中打开“我的图片”。Kiosk 需要使用 Internet Explorer。

### Shell 协议

输入这些 URL 以获取资源管理器视图：

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

## 显示文件扩展名

请查看此页面以获取更多信息：[https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml](https://www.howtohaven.com/system/show-file-extensions-in-windows-explorer.shtml)

# 浏览器技巧

备份 iKat 版本：

[http://swin.es/k/](http://swin.es/k/)\
[http://www.ikat.kronicd.net/](http://www.ikat.kronicd.net)\

使用 JavaScript 创建一个通用对话框并访问文件资源管理器：`document.write('<input/type=file>')`
来源：https://medium.com/@Rend_/give-me-a-browser-ill-give-you-a-shell-de19811defa0

# iPad

## 手势和按钮

- 用四个（或五个）手指向上滑动 / 双击主屏幕按钮：查看多任务视图并更改应用程序

- 用四个或五个手指向一个方向滑动：以更改到下一个/上一个应用程序

- 用五个手指捏合屏幕 / 按下主屏幕按钮 / 用一根手指快速从屏幕底部向上滑动：访问主屏幕

- 用一根手指从屏幕底部滑动 1-2 英寸（慢）：停靠栏将出现

- 用一根手指从显示器顶部向下滑动：查看通知

- 用一根手指从屏幕右上角向下滑动：查看 iPad Pro 的控制中心

- 用一根手指从屏幕左侧滑动 1-2 英寸：查看今日视图

- 用一根手指快速从屏幕中心向右或向左滑动：更改到下一个/上一个应用程序

- 按住右上角的开/关/睡眠按钮 + 将滑块移动到右侧以**关闭电源**：关闭电源

- 按住右上角的开/关/睡眠按钮和主屏幕按钮几秒钟：强制硬关机

- 快速按右上角的开/关/睡眠按钮和主屏幕按钮：截屏，截屏将弹出在显示器的左下角。两者同时按下非常短暂，如果按住几秒钟将执行硬关机。

## 快捷键

您应该有一个 iPad 键盘或 USB 键盘适配器。这里只显示可能帮助您逃离应用程序的快捷键。

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

### 系统快捷键

这些快捷键用于视觉设置和声音设置，具体取决于 iPad 的使用。

| Shortcut | Action                                                                         |
| -------- | ------------------------------------------------------------------------------ |
| F1       | 调暗屏幕                                                                    |
| F2       | 提亮屏幕                                                                |
| F7       | 返回一首歌曲                                                                  |
| F8       | 播放/暂停                                                                     |
| F9       | 跳过歌曲                                                                      |
| F10      | 静音                                                                           |
| F11      | 降低音量                                                                |
| F12      | 增加音量                                                                |
| ⌘ Space  | 显示可用语言列表；要选择一种，请再次按空格键。 |

### iPad 导航

| Shortcut                                           | Action                                                  |
| -------------------------------------------------- | ------------------------------------------------------- |
| ⌘H                                                 | 返回主屏幕                                              |
| ⌘⇧H (Command-Shift-H)                              | 返回主屏幕                                              |
| ⌘ (Space)                                          | 打开 Spotlight                                          |
| ⌘⇥ (Command-Tab)                                   | 列出最近使用的十个应用程序                                 |
| ⌘\~                                                | 返回上一个应用程序                                       |
| ⌘⇧3 (Command-Shift-3)                              | 截屏（悬停在左下角以保存或操作） |
| ⌘⇧4                                                | 截屏并在编辑器中打开                    |
| 按住 ⌘                                           | 列出可用于该应用程序的快捷键                 |
| ⌘⌥D (Command-Option/Alt-D)                         | 显示停靠栏                                      |
| ^⌥H (Control-Option-H)                             | 主屏幕按钮                                             |
| ^⌥H H (Control-Option-H-H)                         | 显示多任务栏                                      |
| ^⌥I (Control-Option-i)                             | 项目选择器                                            |
| Escape                                             | 返回按钮                                             |
| → (右箭头)                                    | 下一个项目                                               |
| ← (左箭头)                                     | 上一个项目                                           |
| ↑↓ (上箭头, 下箭头)                          | 同时点击选定的项目                        |
| ⌥ ↓ (Option-Down arrow)                            | 向下滚动                                             |
| ⌥↑ (Option-Up arrow)                               | 向上滚动                                               |
| ⌥← 或 ⌥→ (Option-Left arrow 或 Option-Right arrow) | 向左或向右滚动                                    |
| ^⌥S (Control-Option-S)                             | 开启或关闭 VoiceOver 语音                         |
| ⌘⇧⇥ (Command-Shift-Tab)                            | 切换到上一个应用程序                              |
| ⌘⇥ (Command-Tab)                                   | 切换回原始应用程序                         |
| ←+→，然后 Option + ← 或 Option+→                   | 在停靠栏中导航                                   |

### Safari 快捷键

| Shortcut                | Action                                           |
| ----------------------- | ------------------------------------------------ |
| ⌘L (Command-L)          | 打开位置                                    |
| ⌘T                      | 打开新标签                                   |
| ⌘W                      | 关闭当前标签                            |
| ⌘R                      | 刷新当前标签                          |
| ⌘.                      | 停止加载当前标签                     |
| ^⇥                      | 切换到下一个标签                           |
| ^⇧⇥ (Control-Shift-Tab) | 移动到上一个标签                         |
| ⌘L                      | 选择文本输入/URL 字段以进行修改     |
| ⌘⇧T (Command-Shift-T)   | 打开最后关闭的标签（可以多次使用） |
| ⌘\[                     | 在浏览历史中返回一页      |
| ⌘]                      | 在浏览历史中前进一页   |
| ⌘⇧R                     | 激活阅读模式                             |

### 邮件快捷键

| Shortcut                   | Action                       |
| -------------------------- | ---------------------------- |
| ⌘L                         | 打开位置                |
| ⌘T                         | 打开新标签               |
| ⌘W                         | 关闭当前标签        |
| ⌘R                         | 刷新当前标签      |
| ⌘.                         | 停止加载当前标签 |
| ⌘⌥F (Command-Option/Alt-F) | 在您的邮箱中搜索       |

# 参考文献

- [https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html](https://www.macworld.com/article/2975857/6-only-for-ipad-gestures-you-need-to-know.html)
- [https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html](https://www.tomsguide.com/us/ipad-shortcuts,news-18205.html)
- [https://thesweetsetup.com/best-ipad-keyboard-shortcuts/](https://thesweetsetup.com/best-ipad-keyboard-shortcuts/)
- [http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html](http://www.iphonehacks.com/2018/03/ipad-keyboard-shortcuts.html)

{{#include ../../banners/hacktricks-training.md}}
