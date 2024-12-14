# Kerberos Double Hop Problem

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

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

The Kerberos "Double Hop" problem appears when an attacker attempts to use **Kerberos authentication across two** **hops**, for example using **PowerShell**/**WinRM**.

When an **authentication** occurs through **Kerberos**, **credentials** **aren't** cached in **memory.** Therefore, if you run mimikatz you **won't find credentials** of the user in the machine even if he is running processes.

This is because when connecting with Kerberos these are the steps:

1. User1 provides credentials and **domain controller** returns a Kerberos **TGT** to the User1.
2. User1 uses **TGT** to request a **service ticket** to **connect** to Server1.
3. User1 **connects** to **Server1** and provides **service ticket**.
4. **Server1** **doesn't** have **credentials** of User1 cached or the **TGT** of User1. Therefore, when User1 from Server1 tries to login to a second server, he is **not able to authenticate**.

### Unconstrained Delegation

If **unconstrained delegation** is enabled in the PC, this won't happen as the **Server** will **get** a **TGT** of each user accessing it. Moreover, if unconstrained delegation is used you probably can **compromise the Domain Controller** from it.\
[**More info in the unconstrained delegation page**](unconstrained-delegation.md).

### CredSSP

Another way to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) is **Credential Security Support Provider**. From Microsoft:

> CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.

It is highly recommended that **CredSSP** be disabled on production systems, sensitive networks, and similar environments due to security concerns. To determine whether **CredSSP** is enabled, the `Get-WSManCredSSP` command can be run. This command allows for the **checking of CredSSP status** and can even be executed remotely, provided **WinRM** is enabled.

```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```

## Workarounds

### Invoke Command

To address the double hop issue, a method involving a nested `Invoke-Command` is presented. This does not solve the problem directly but offers a workaround without needing special configurations. The approach allows executing a command (`hostname`) on a secondary server through a PowerShell command executed from an initial attacking machine or through a previously established PS-Session with the first server. Here's how it's done:

```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```

Alternatively, establishing a PS-Session with the first server and running the `Invoke-Command` using `$cred` is suggested for centralizing tasks.

### Register PSSession Configuration

A solution to bypass the double hop problem involves using `Register-PSSessionConfiguration` with `Enter-PSSession`. This method requires a different approach than `evil-winrm` and allows for a session that does not suffer from the double hop limitation. 

```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```

### PortForwarding

For local administrators on an intermediary target, port forwarding allows requests to be sent to a final server. Using `netsh`, a rule can be added for port forwarding, alongside a Windows firewall rule to allow the forwarded port. 

```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```

#### winrs.exe

`winrs.exe` can be used for forwarding WinRM requests, potentially as a less detectable option if PowerShell monitoring is a concern. The command below demonstrates its use:

```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```

### OpenSSH

Installing OpenSSH on the first server enables a workaround for the double-hop issue, particularly useful for jump box scenarios. This method requires CLI installation and setup of OpenSSH for Windows. When configured for Password Authentication, this allows the intermediary server to obtain a TGT on behalf of the user.

#### OpenSSH Installation Steps

1. Download and move the latest OpenSSH release zip to the target server.
2. Unzip and run the `Install-sshd.ps1` script.
3. Add a firewall rule to open port 22 and verify SSH services are running.

To resolve `Connection reset` errors, permissions might need to be updated to allow everyone read and execute access on the OpenSSH directory.

```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```

## References

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

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

