# PsExec/Winexec/ScExec/SMBExec

{{#include ../../banners/hacktricks-training.md}}

## How do they work

The process is outlined in the steps below, illustrating how service binaries are manipulated to achieve remote execution on a target machine via SMB:

1. **Copying of a service binary to the ADMIN$ share over SMB** is performed.
2. **Creation of a service on the remote machine** is done by pointing to the binary.
3. The service is **started remotely**.
4. Upon exit, the service is **stopped, and the binary is deleted**.

### **Process of Manually Executing PsExec**

Assuming there is an executable payload (created with msfvenom and obfuscated using Veil to evade antivirus detection), named 'met8888.exe', representing a meterpreter reverse_http payload, the following steps are taken:

- **Copying the binary**: The executable is copied to the ADMIN$ share from a command prompt, though it may be placed anywhere on the filesystem to remain concealed.
    - Instead of copying the binary it's also possible to use a LOLBAS binary like `powershell.exe` or `cmd.exe` to execute commands directly from the arguments. E.g. `sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"`
- **Creating a service**: Utilizing the Windows `sc` command, which allows for querying, creating, and deleting Windows services remotely, a service named "meterpreter" is created to point to the uploaded binary.
- **Starting the service**: The final step involves starting the service, which will likely result in a "time-out" error due to the binary not being a genuine service binary and failing to return the expected response code. This error is inconsequential as the primary goal is the binary's execution.

Observation of the Metasploit listener will reveal that the session has been initiated successfully.

[Learn more about the `sc` command](https://technet.microsoft.com/en-us/library/bb490995.aspx).

Find moe detailed steps in: [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

- You could also use the **Windows Sysinternals binary PsExec.exe**:

![](<../../images/image (928).png>)

Or access it via webddav:

```bash
\\live.sysinternals.com\tools\PsExec64.exe -accepteula
```

- You could also use [**SharpLateral**](https://github.com/mertdas/SharpLateral):

```bash
SharpLateral.exe redexec HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe.exe malware.exe ServiceName
```

- You could also use [**SharpMove**](https://github.com/0xthirteen/SharpMove):

```bash
SharpMove.exe action=modsvc computername=remote.host.local command="C:\windows\temp\payload.exe" amsi=true servicename=TestService
SharpMove.exe action=startservice computername=remote.host.local servicename=TestService
```

- You could also use **Impacket's `psexec` and `smbexec.py`**.


{{#include ../../banners/hacktricks-training.md}}

