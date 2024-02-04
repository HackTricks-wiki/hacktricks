# SmbExec/ScExec

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## How it Works

**Smbexec** operates in a manner similar to **Psexec**, targeting **cmd.exe** or **powershell.exe** on the victim's system for backdoor execution, avoiding the use of malicious executables.

## **SMBExec**

```bash
smbexec.py WORKGROUP/username:password@10.10.10.10
```

Smbexec's functionality involves creating a temporary service (e.g., "BTOBTO") on the target machine to execute commands without dropping a binary. This service, constructed to run a command via cmd.exe's path (%COMSPEC%), redirects output to a temporary file and deletes itself post-execution. The method is stealthy but generates event logs for each command, offering a non-interactive "shell" by repeating this process for every command issued from the attacker's side.

## Executing Commands Without Binaries

This approach allows for direct command execution via service binPaths, eliminating the need for binaries. It's particularly useful for one-off command execution on a Windows target. For example, using Metasploit's `web_delivery` module with a PowerShell-targeted reverse Meterpreter payload can establish a listener that provides the necessary execution command. Creating and starting a remote service on the attacker's Windows machine with the binPath set to execute this command via cmd.exe allows for the payload's execution, despite potential service response errors, achieving callback and payload execution on the Metasploit listener's side.

### Commands Example

Creating and starting the service can be accomplished with the following commands:

```cmd
sc create [ServiceName] binPath= "cmd.exe /c [PayloadCommand]"
sc start [ServiceName]
```

FOr further details check [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)


# References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
