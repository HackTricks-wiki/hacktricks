# Kerberos Double Hop Problem

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>

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

Another suggested option to **sysadmins** to avoid this problem which is [**notably insecure**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) \*\*\*\* is **Credential Security Support Provider**. Enabling CredSSP has been a solution mentioned on various forums throughout the years. From Microsoft:

_“CredSSP authentication delegates the user credentials from the local computer to a remote computer. This practice increases the security risk of the remote operation. If the remote computer is compromised, when credentials are passed to it, the credentials can be used to control the network session.”_

If you find **CredSSP enabled** on production systems, sensitive networks, etc it’s recommended they be disabled. A quick way to **check CredSSP status** is by running `Get-WSManCredSSP`. Which can be executed remotely if WinRM is enabled.

```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```

## Workarounds

### Invoke Command <a href="#invoke-command" id="invoke-command"></a>

This method is sort of _“working with”_ the double hop issue, not necessarily solving it. It doesn’t rely on any configurations, and you can simply run it from your attacking box. It’s basically a **nested `Invoke-Command`**.

This’ll **run** **`hostname`** on the **second server:**

```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```

You could also have a **PS-Session** established with the **first server** and simply **run** the **`Invoke-Command`** with `$cred` from there instead of nesting it. Although, running it from your attacking box centralizes tasking:

```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```

### Register PSSession Configuration

If instead of using **`evil-winrm`** you can use **`Enter-PSSession`** cmdlet you can then use **`Register-PSSessionConfiguration`** and reconnect to bypass the double hop problem:

```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```

### PortForwarding <a href="#portproxy" id="portproxy"></a>

Since we have Local Administrator on the intermediate target **bizintel: 10.35.8.17**, you can add a port forwarding rule to send your requests to the final/third server **secdev: 10.35.8.23**.

Can quickly use **netsh** to rip out a one-liner and add the rule.

```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```

So **the first server** is listening on port 5446 and will forward requests hitting 5446 off to **the second server** port 5985 (aka WinRM).

Then punch a hole in the Windows firewall, which can also be done with a swift netsh one-liner.

```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```

Now establish the session, which will forward us to **the first server**.

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

**Portforwarding WinRM** requests also seems to work when using **`winrs.exe`**. This may be a better options if you’re aware PowerShell is being monitored. The below command brings back “**secdev**” as the result of `hostname`.

```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```

Like `Invoke-Command`, this can be easily scripted so the attacker can simply issue system commands as an argument. A generic batch script example _winrm.bat_:

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

This method requires [installing OpenSSH](https://github.com/PowerShell/Win32-OpenSSH/wiki/Install-Win32-OpenSSH) on the first server box. Installing OpenSSH for Windows can be done **completely via CLI** and doesn’t take much time at all - plus it doesn’t flag as malware!

Of course in certain circumstances it may not be feasible, too cumbersome or may be a general OpSec risk.

This method may be especially useful on a jump box setup - with access to an otherwise inaccessible network. Once the SSH connection is established, the user/attacker can fire-off as many `New-PSSession`’s as needed against the segmented network without blasting into the double-hop issue.

When configured to use **Password Authentication** in OpenSSH (not keys or Kerberos), the **logon type is 8** aka _Network Clear text logon_. This doesn’t mean your password is sent in the clear - it is in fact encrypted by SSH. Upon arrival it’s unencrypted into clear text via its [authentication package](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN) for your session to further request juicy TGT’s!

This allows the intermediary server to request & obtain a TGT on your behalf to store locally on the intermediary server. Your session can then use this TGT to authenticate(PS remote) to additional servers.

#### OpenSSH Install Scenario

Download the latest [OpenSSH Release zip from github](https://github.com/PowerShell/Win32-OpenSSH/releases) onto you attacking box and move it over (or download it directly onto the jump box).

Uncompress the zip to where you’d like. Then, run the install script - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

Lastly, just add a firewall rule to **open port 22**. Verify the SSH services are installed, and start them. Both of these services will need to be running for SSH to work.

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

If you receive a `Connection reset` error, update permissions to allow **Everyone: Read & Execute** on the root OpenSSH directory.

```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```

## References

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Do you work in a **cybersecurity company**? Do you want to see your **company advertised in HackTricks**? or do you want to have access to the **latest version of the PEASS or download HackTricks in PDF**? Check the [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Discover [**The PEASS Family**](https://opensea.io/collection/the-peass-family), our collection of exclusive [**NFTs**](https://opensea.io/collection/the-peass-family)
* Get the [**official PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Join the** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** me on **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Share your hacking tricks by submitting PRs to the** [**hacktricks repo**](https://github.com/carlospolop/hacktricks) **and** [**hacktricks-cloud repo**](https://github.com/carlospolop/hacktricks-cloud).

</details>
