# Abusing Tokens

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Belki zaten sahip olduğunuz token'ları kötüye kullanarak ayrıcalıkları yükseltebilirsiniz**

### SeImpersonatePrivilege

This is privilege that is held by any process allows the impersonation (but not creation) of any token, given that a handle to it can be obtained. A privileged token can be acquired from a Windows service (DCOM) by inducing it to perform NTLM authentication against an exploit, subsequently enabling the execution of a process with SYSTEM privileges. This vulnerability can be exploited using various tools, such as [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (which requires winrm to be disabled), [SweetPotato](https://github.com/CCob/SweetPotato), and [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).


{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

It is very similar to **SeImpersonatePrivilege**, it will use the **same method** to get a privileged token.\
Then, this privilege allows **to assign a primary token** to a new/suspended process. With the privileged impersonation token you can derivate a primary token (DuplicateTokenEx).\
With the token, you can create a **new process** with 'CreateProcessAsUser' or create a process suspended and **set the token** (in general, you cannot modify the primary token of a running process).

### SeTcbPrivilege

If you have enabled this token you can use **KERB_S4U_LOGON** to get an **impersonation token** for any other user without knowing the credentials, **add an arbitrary group** (admins) to the token, set the **integrity level** of the token to "**medium**", and assign this token to the **current thread** (SetThreadToken).

### SeBackupPrivilege

The system is caused to **grant all read access** control to any file (limited to read operations) by this privilege. It is utilized for **reading the password hashes of local Administrator** accounts from the registry, following which, tools like "**psexec**" or "**wmiexec**" can be used with the hash (Pass-the-Hash technique). However, this technique fails under two conditions: when the Local Administrator account is disabled, or when a policy is in place that removes administrative rights from Local Administrators connecting remotely.\
You can **abuse this privilege** with:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Permission for **write access** to any system file, irrespective of the file's Access Control List (ACL), is provided by this privilege. It opens up numerous possibilities for escalation, including the ability to **modify services**, perform DLL Hijacking, and set **debuggers** via Image File Execution Options among various other techniques.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege is a powerful permission, especially useful when a user possesses the ability to impersonate tokens, but also in the absence of SeImpersonatePrivilege. This capability hinges on the ability to impersonate a token that represents the same user and whose integrity level does not exceed that of the current process.

**Key Points:**

- **Impersonation without SeImpersonatePrivilege:** It's possible to leverage SeCreateTokenPrivilege for EoP by impersonating tokens under specific conditions.
- **Conditions for Token Impersonation:** Successful impersonation requires the target token to belong to the same user and have an integrity level that is less or equal to the integrity level of the process attempting impersonation.
- **Creation and Modification of Impersonation Tokens:** Users can create an impersonation token and enhance it by adding a privileged group's SID (Security Identifier).

### SeLoadDriverPrivilege

This privilege allows to **load and unload device drivers** with the creation of a registry entry with specific values for `ImagePath` and `Type`. Since direct write access to `HKLM` (HKEY_LOCAL_MACHINE) is restricted, `HKCU` (HKEY_CURRENT_USER) must be utilized instead. However, to make `HKCU` recognizable to the kernel for driver configuration, a specific path must be followed.

This path is `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, where `<RID>` is the Relative Identifier of the current user. Inside `HKCU`, this entire path must be created, and two values need to be set:

- `ImagePath`, which is the path to the binary to be executed
- `Type`, with a value of `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Steps to Follow:**

1. Access `HKCU` instead of `HKLM` due to restricted write access.
2. Create the path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` within `HKCU`, where `<RID>` represents the current user's Relative Identifier.
3. Set the `ImagePath` to the binary's execution path.
4. Assign the `Type` as `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Bu ayrıcalığı kötüye kullanmanın daha fazla yolu: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege**'e benzer. Temel işlevi, bir sürecin **bir nesnenin sahipliğini üstlenmesine** izin vererek, WRITE_OWNER erişim haklarını sağlayıp açıkça tanımlanmış discretionary erişim gerekliliğini atlamaktır. İşlem, yazma amaçlı hedef kayıt anahtarının sahipliğini önce ele geçirip, ardından yazma işlemlerine izin vermek için DACL'i değiştirmeyi içerir.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege

Bu ayrıcalık **debug other processes** yapmaya izin verir; belleği okumak ve yazmak da dahil. Bu ayrıcalıkla, çoğu antivirüs ve host intrusion prevention çözümlerini atlatabilecek çeşitli bellek enjeksiyon stratejileri uygulanabilir.

#### Dump memory

You could use [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) from the [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) to **capture the memory of a process**. Specifically, this can apply to the **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process, which is responsible for storing user credentials once a user has successfully logged into a system.

You can then load this dump in mimikatz to obtain passwords:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Bir `NT SYSTEM` shell elde etmek istiyorsanız şunları kullanabilirsiniz:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Bu hak (Perform volume maintenance tasks), NTFS ACL'lerini atlayan doğrudan disk I/O için ham volume cihaz tutucularını (ör. \\.\C:) açmaya izin verir. Bununla, alttaki blokları okuyarak volum üzerindeki herhangi bir dosyanın baytlarını kopyalayabilirsiniz; bu da hassas materyallerin rastgele okunmasını mümkün kılar (ör. makine özel anahtarları %ProgramData%\Microsoft\Crypto\, registry hives, SAM/NTDS via VSS). CA sunucularında özellikle etkili olup, CA özel anahtarının dışarı çıkarılması Golden Certificate oluşturarak herhangi bir varlığı taklit etmeye izin verir.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Ayrıcalıkları kontrol et
```
whoami /priv
```
The **tokens that appear as Disabled** etkinleştirilebilir; aslında _Enabled_ ve _Disabled_ tokens'ları istismar edebilirsiniz.

### Tüm tokens'ları etkinleştir

Eğer bazı tokens devre dışıysa, tümünü etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) betiğini kullanabilirsiniz:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Veya bu [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) içindeki **script** gömülü.

## Tablo

Tam token ayrıcalıkları cheatsheet'i: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), aşağıdaki özet yalnızca ayrıcalığı kullanarak yönetici oturumu elde etmenin veya hassas dosyaları okumanın doğrudan yollarını listeleyecektir.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Yönetici**_ | 3. taraf araç          | _"Bir kullanıcının token'larla kimlik taklidi yapmasına ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçları kullanarak NT system'e privesc yapmasına izin verirdi"_                                                                                                                                                                      | Teşekkürler [Aurélien Chalot](https://twitter.com/Defte_) güncelleme için. Bunu yakında daha tarif-eğilimli bir şekilde yeniden ifade etmeye çalışacağım.                                                                                                                                                                      |
| **`SeBackup`**             | **Tehdit**  | _**Yerleşik komutlar**_ | Hassas dosyaları `robocopy /b` ile okuma                                                                                                                                                                                                                                                                                                           | <p>- %WINDIR%\MEMORY.DMP dosyasını okuyabiliyorsanız daha ilginç olabilir<br><br>- <code>SeBackupPrivilege</code> (ve robocopy) açık dosyalar söz konusu olduğunda yardımcı olmaz.<br><br>- Robocopy'nin /b parametresi ile çalışması için hem SeBackup hem de SeRestore gereklidir.</p>                                                                      |
| **`SeCreateToken`**        | _**Yönetici**_ | 3. taraf araç          | `NtCreateToken` ile yerel yönetici haklarını içeren keyfi bir token oluşturma.                                                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Yönetici**_ | **PowerShell**          | `lsass.exe` token'ını çoğaltma.                                                                                                                                                                                                                                                                                                                    | Script şu adreste bulunabilir: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                  |
| **`SeLoadDriver`**         | _**Yönetici**_ | 3. taraf araç          | <p>1. <code>szkg64.sys</code> gibi hatalı bir kernel driver'ı yükleme<br>2. Sürücü açığını istismar etme<br><br>Alternatif olarak, ayrıcalık güvenlikle ilgili driver'ların <code>ftlMC</code> yerleşik komutuyla unload edilmesinde kullanılabilir. Örn: <code>fltMC sysmondrv</code></p>                                           | <p>1. <code>szkg64</code> açığı <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> olarak listelenmiştir<br>2. <code>szkg64</code> <a href="https://www.greyhathacker.net/?p=1025">exploit code</a> Parvez Anwar tarafından oluşturulmuştur</p> |
| **`SeRestore`**            | _**Yönetici**_ | **PowerShell**          | <p>1. SeRestore ayrıcalığı etkinken PowerShell/ISE başlatın.<br>2. Ayrıcalığı <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile etkinleştirin.<br>3. utilman.exe dosyasının adını utilman.old yapın<br>4. cmd.exe dosyasının adını utilman.exe yapın<br>5. Konsolu kilitleyin ve Win+U tuşuna basın</p> | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde saklanan servis ikili dosyalarını değiştirmeye dayanır</p>                                                                                                                       |
| **`SeTakeOwnership`**      | _**Yönetici**_ | _**Yerleşik komutlar**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasının adını utilman.exe yapın<br>4. Konsolu kilitleyin ve Win+U tuşuna basın</p>                                                                                                                   | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde saklanan servis ikili dosyalarını değiştirmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Yönetici**_ | 3. taraf araç          | <p>Token'ları manipüle ederek yerel yönetici haklarını dahil etme. SeImpersonate gerektirebilir.</p><p>Doğrulanacak.</p>                                                                                                                                                                                                                            |                                                                                                                                                                                                                                                                                                                                |

## Referans

- Windows tokenlerini tanımlayan bu tabloya bakın: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- Token'larla privesc hakkında [**bu makaleye**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) göz atın.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
