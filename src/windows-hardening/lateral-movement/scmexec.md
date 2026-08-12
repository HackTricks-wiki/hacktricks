# SCMExec

{{#include ../../banners/hacktricks-training.md}}

## How It Works

The Service Control Manager Remote Protocol (SCMR) is an RPC-based protocol for configuring and controlling Windows services on a remote computer. With sufficient permissions, an operator can create or reconfigure a service whose binary path contains a command and then start that service to execute the command remotely.<sup>[[1]](#references)</sup>

If no service account is specified, `CreateService` uses `LocalSystem`, which has extensive local privileges. This explains the high impact of successful SCM execution. It does not inherently disable UAC or Microsoft Defender: the caller still needs remote SCM rights, and endpoint controls can inspect or block the service or payload.<sup>[[3]](#references)</sup><sup>[[4]](#references)</sup>

## Tools

**SharpMove** supports authenticated remote execution through SCM and several other Windows mechanisms. The following example selects its SCM action, creates a service named `WindowsDebug`, and points it at a payload already present on the remote host.<sup>[[2]](#references)</sup>

```powershell
SharpMove.exe action=scm computername=remote.host.local command="C:\windows\temp\payload.exe" servicename=WindowsDebug amsi=true
```

## References

- [1] [Microsoft Open Specifications - Service Control Manager Remote Protocol overview](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/d5bd5712-fa64-44bf-9433-3651f6a5ce97)
- [2] [GitHub - SharpMove](https://github.com/0xthirteen/SharpMove)
- [3] [Microsoft Learn - LocalSystem account](https://learn.microsoft.com/en-us/windows/win32/services/localsystem-account)
- [4] [Microsoft Learn - `CreateService` function](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea)

{{#include ../../banners/hacktricks-training.md}}
