# SmbExec/ScExec

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

## How it Works

**Smbexec** is a tool used for remote command execution on Windows systems, similar to **Psexec**, but it avoids placing any malicious files on the target system.

### Key Points about **SMBExec**

- It operates by creating a temporary service (for example, "BTOBTO") on the target machine to execute commands via cmd.exe (%COMSPEC%), without dropping any binaries.
- Despite its stealthy approach, it does generate event logs for each command executed, offering a form of non-interactive "shell".
- The command to connect using **Smbexec** looks like this:

```bash
smbexec.py WORKGROUP/genericuser:genericpassword@10.10.10.10
```

### Executing Commands Without Binaries

- **Smbexec** enables direct command execution through service binPaths, eliminating the need for physical binaries on the target.
- This method is useful for executing one-time commands on a Windows target. For instance, pairing it with Metasploit's `web_delivery` module allows for the execution of a PowerShell-targeted reverse Meterpreter payload.
- By creating a remote service on the attacker's machine with binPath set to run the provided command through cmd.exe, it's possible to execute the payload successfully, achieving callback and payload execution with the Metasploit listener, even if service response errors occur.

### Commands Example

Creating and starting the service can be accomplished with the following commands:

```bash
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```

FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## References

- [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<figure><img src="/images/pentest-tools.svg" alt=""><figcaption></figcaption></figure>

**Get a hacker's perspective on your web apps, network, and cloud**

**Find and report critical, exploitable vulnerabilities with real business impact.** Use our 20+ custom tools to map the attack surface, find security issues that let you escalate privileges, and use automated exploits to collect essential evidence, turning your hard work into persuasive reports.

{% embed url="https://pentest-tools.com/?utm_term=jul2024&utm_medium=link&utm_source=hacktricks&utm_campaign=spons" %}

{{#include ../../banners/hacktricks-training.md}}

