# Kerberos Double Hop Problem

{{#include ../../banners/hacktricks-training.md}}


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

```bash
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```

### Remote Credential Guard (RCG)

**Remote Credential Guard** keeps the user's TGT on the originating workstation while still allowing the RDP session to request new Kerberos service tickets on the next hop. Enable **Computer Configuration > Administrative Templates > System > Credentials Delegation > Restrict delegation of credentials to remote servers** and select **Require Remote Credential Guard**, then connect with `mstsc.exe /remoteGuard /v:server1` instead of falling back to CredSSP.

Microsoft broke RCG for multi-hop access on Windows 11 22H2+ until the **April 2024 cumulative updates** (KB5036896/KB5036899/KB5036894). Patch the client and intermediary server or the second hop will still fail. Quick hotfix check:

```powershell
("KB5036896","KB5036899","KB5036894") | ForEach-Object {
    Get-HotFix -Id $_ -ErrorAction SilentlyContinue
}
```

With those builds installed, the RDP hop can satisfy downstream Kerberos challenges without exposing reusable secrets on the first server.

## Workarounds

### Invoke Command

To address the double hop issue, a method involving a nested `Invoke-Command` is presented. This does not solve the problem directly but offers a workaround without needing special configurations. The approach allows executing a command (`hostname`) on a secondary server through a PowerShell command executed from an initial attacking machine or through a previously established PS-Session with the first server. Here's how it's done:

```bash
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```

Alternatively, establishing a PS-Session with the first server and running the `Invoke-Command` using `$cred` is suggested for centralizing tasks.

### Register PSSession Configuration

A solution to bypass the double hop problem involves using `Register-PSSessionConfiguration` with `Enter-PSSession`. This method requires a different approach than `evil-winrm` and allows for a session that does not suffer from the double hop limitation.

```bash
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName TARGET_PC -Credential domain_name\username
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

### LSA Whisperer CacheLogon (Advanced)

**LSA Whisperer** (2024) exposes the `msv1_0!CacheLogon` package call so you can seed an existing *network logon* with a known NT hash instead of creating a fresh session with `LogonUser`. By injecting the hash into the logon session that WinRM/PowerShell already opened on hop #1, that host can authenticate to hop #2 without storing explicit credentials or generating extra 4624 events.

1. Get code execution inside LSASS (either disable/abuse PPL or run on a lab VM you control).
2. Enumerate logon sessions (e.g. `lsa.exe sessions`) and capture the LUID corresponding to your remoting context.
3. Pre-compute the NT hash and feed it to `CacheLogon`, then clear it when done.

```powershell
lsa.exe cachelogon --session 0x3e4 --domain ta --username redsuit --nthash a7c5480e8c1ef0ffec54e99275e6e0f7
lsa.exe cacheclear --session 0x3e4
```

After the cache seed, rerun `Invoke-Command`/`New-PSSession` from hop #1: LSASS will reuse the injected hash to satisfy Kerberos/NTLM challenges for the second hop, neatly bypassing the double hop constraint. The trade-off is heavier telemetry (code execution in LSASS) so keep it for high-friction environments where CredSSP/RCG are disallowed.

## References

- [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
- [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
- [https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey_babkins_blog/another-solution-to-multi-hop-powershell-remoting)
- [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)
- [https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92](https://support.microsoft.com/en-au/topic/april-9-2024-kb5036896-os-build-17763-5696-efb580f1-2ce4-4695-b76c-d2068a00fb92)
- [https://specterops.io/blog/2024/04/17/lsa-whisperer/](https://specterops.io/blog/2024/04/17/lsa-whisperer/)


{{#include ../../banners/hacktricks-training.md}}
