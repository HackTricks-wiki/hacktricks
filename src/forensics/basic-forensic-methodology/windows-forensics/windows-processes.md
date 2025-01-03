{{#include ../../../banners/hacktricks-training.md}}

## smss.exe

**会话管理器**。\
会话 0 启动 **csrss.exe** 和 **wininit.exe** (**操作系统** **服务**)，而会话 1 启动 **csrss.exe** 和 **winlogon.exe** (**用户** **会话**)。然而，您应该在进程树中只看到该 **二进制文件** 的 **一个进程**，且没有子进程。

此外，除了 0 和 1 的会话可能意味着正在发生 RDP 会话。

## csrss.exe

**客户端/服务器运行子系统进程**。\
它管理 **进程** 和 **线程**，使 **Windows** **API** 可供其他进程使用，并且还 **映射驱动器字母**，创建 **临时文件**，并处理 **关机** **过程**。

在会话 0 中有一个 **正在运行的进程，另一个在会话 1 中**（因此在进程树中有 **2 个进程**）。每个新会话会创建一个新的进程。

## winlogon.exe

**Windows 登录进程**。\
它负责用户 **登录**/**注销**。它启动 **logonui.exe** 以请求用户名和密码，然后调用 **lsass.exe** 进行验证。

然后它启动 **userinit.exe**，该程序在 **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** 中指定，键为 **Userinit**。

此外，之前的注册表应在 **Shell 键** 中有 **explorer.exe**，否则可能会被滥用作为 **恶意软件持久性方法**。

## wininit.exe

**Windows 初始化进程**。 \
它在会话 0 中启动 **services.exe**、**lsass.exe** 和 **lsm.exe**。应该只有 1 个进程。

## userinit.exe

**Userinit 登录应用程序**。\
加载 **HKCU 中的 ntduser.dat**，初始化 **用户** **环境**，并运行 **登录** **脚本** 和 **GPO**。

它启动 **explorer.exe**。

## lsm.exe

**本地会话管理器**。\
它与 smss.exe 一起工作以操纵用户会话：登录/注销、启动 shell、锁定/解锁桌面等。

在 W7 之后，lsm.exe 被转变为服务 (lsm.dll)。

在 W7 中应该只有 1 个进程，并且其中一个是运行 DLL 的服务。

## services.exe

**服务控制管理器**。\
它 **加载** 配置为 **自动启动** 的 **服务** 和 **驱动程序**。

它是 **svchost.exe**、**dllhost.exe**、**taskhost.exe**、**spoolsv.exe** 等的父进程。

服务在 `HKLM\SYSTEM\CurrentControlSet\Services` 中定义，该进程在内存中维护一个服务信息的数据库，可以通过 sc.exe 查询。

注意 **某些** **服务** 将在 **自己的进程中运行**，而其他服务将 **共享一个 svchost.exe 进程**。

应该只有 1 个进程。

## lsass.exe

**本地安全授权子系统**。\
它负责用户 **身份验证** 并创建 **安全** **令牌**。它使用位于 `HKLM\System\CurrentControlSet\Control\Lsa` 的身份验证包。

它写入 **安全** **事件** **日志**，并且应该只有 1 个进程。

请记住，该进程是高度攻击的目标，用于提取密码。

## svchost.exe

**通用服务主机进程**。\
它在一个共享进程中托管多个 DLL 服务。

通常，您会发现 **svchost.exe** 是使用 `-k` 标志启动的。这将查询注册表 **HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**，其中将有一个带有 -k 中提到的参数的键，该键将包含在同一进程中启动的服务。

例如：`-k UnistackSvcGroup` 将启动：`PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

如果 **标志 `-s`** 也与参数一起使用，则 svchost 被要求 **仅启动指定的服务**。

将会有多个 `svchost.exe` 进程。如果其中任何一个 **没有使用 `-k` 标志**，那么这非常可疑。如果您发现 **services.exe 不是父进程**，那也是非常可疑的。

## taskhost.exe

该进程充当从 DLL 运行的进程的主机。它还加载从 DLL 运行的服务。

在 W8 中称为 taskhostex.exe，在 W10 中称为 taskhostw.exe。

## explorer.exe

这是负责 **用户桌面** 和通过文件扩展名启动文件的进程。

**每个登录用户应该只生成 1 个** 进程。

这是从 **userinit.exe** 运行的，应该被终止，因此 **该进程不应有父进程**。

# 捕获恶意进程

- 它是否从预期路径运行？（没有 Windows 二进制文件从临时位置运行）
- 它是否与奇怪的 IP 通信？
- 检查数字签名（Microsoft 伪造物应已签名）
- 拼写是否正确？
- 是否在预期的 SID 下运行？
- 父进程是否是预期的进程（如果有的话）？
- 子进程是否是预期的进程？（没有 cmd.exe、wscript.exe、powershell.exe..？）

{{#include ../../../banners/hacktricks-training.md}}
