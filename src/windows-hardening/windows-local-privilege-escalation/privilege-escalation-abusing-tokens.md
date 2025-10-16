# Token'leri Kötüye Kullanma

{{#include ../../banners/hacktricks-training.md}}

## Tokens

If you **don't know what are Windows Access Tokens** read this page before continuing:


{{#ref}}
access-tokens.md
{{#endref}}

**Zaten sahip olduğunuz token'leri kötüye kullanarak yetkileri yükseltebilirsiniz**

### SeImpersonatePrivilege

Bu, herhangi bir süreç tarafından sahip olunan ve bir handle elde edilebildiği takdirde herhangi bir token'ın impersonation'ına (ama oluşturulmasına değil) izin veren bir ayrıcalıktır. Ayrıcalıklı bir token, bir Windows servisini (DCOM) zorlayarak onun bir exploit'e karşı NTLM authentication yapmasını sağlayıp elde edilebilir; bu da SYSTEM ayrıcalıklarına sahip bir süreç çalıştırmayı mümkün kılar. Bu zafiyet [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (winrm'in devre dışı bırakılmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi çeşitli araçlarla istismar edilebilir.

{{#ref}}
roguepotato-and-printspoofer.md
{{#endref}}


{{#ref}}
juicypotato.md
{{#endref}}

### SeAssignPrimaryPrivilege

Bu, **SeImpersonatePrivilege** ile çok benzerdir; ayrıcalıklı bir token almak için **aynı yöntemi** kullanır. Sonrasında, bu ayrıcalık yeni/askıya alınmış bir sürece **primary token atamaya** izin verir. Ayrıcalıklı impersonation token'ı ile bir primary token türetebilirsiniz (DuplicateTokenEx). Bu token ile 'CreateProcessAsUser' kullanarak **yeni bir süreç** oluşturabilir veya bir süreci askıda oluşturup **token'i ayarlayabilirsiniz** (genelde, çalışan bir sürecin primary token'ını değiştiremezsiniz).

### SeTcbPrivilege

Bu ayrıcalık etkinse, kimlik bilgilerini bilmeden herhangi bir kullanıcı için **KERB_S4U_LOGON** kullanarak bir **impersonation token** alabilir, token'a **istediğiniz bir grup** (admins) ekleyebilir, token'ın **integrity level**'ını "**medium**" olarak ayarlayabilir ve bu token'ı **mevcut thread'e** atayabilirsiniz (SetThreadToken).

### SeBackupPrivilege

Bu ayrıcalık, herhangi bir dosyaya (yalnızca okuma işlemleriyle sınırlı olmak üzere) **tüm okuma erişimini** sağlamasına yol açar. Kayıt defterinden yerel Administrator hesaplarının parola hash'lerini okumak için kullanılır; ardından hash ile **psexec** veya **wmiexec** gibi araçlar (Pass-the-Hash technique) kullanılabilir. Ancak bu teknik iki durumda başarısız olur: Local Administrator hesabı devre dışı bırakıldığında veya uzaktan bağlanan Local Administrator'ların yönetici haklarını kaldıran bir politika mevcutsa.\
Bu ayrıcalığı şu yollarla **kötüye kullanabilirsiniz**:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- following **IppSec** in [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)
- Or as explained in the **escalating privileges with Backup Operators** section of:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu ayrıcalık, bir dosyanın Access Control List (ACL) ne olursa olsun herhangi bir sistem dosyasına **yazma erişimi** sağlar. Bu, **servisleri değiştirme**, DLL Hijacking gerçekleştirme ve Image File Execution Options aracılığıyla **debugger** ayarlama gibi çeşitli yükseltme (escalation) imkânları açar.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir kullanıcının token'ları impersonate edebilme yeteneğine sahip olduğu durumlarda güçlü bir izindir, ancak SeImpersonatePrivilege yokken de faydalıdır. Bu yetenek, aynı kullanıcıyı temsil eden ve integrity level'ı mevcut sürecininkini aşmayan bir token'ı impersonate etme yeteneğine dayanır.

Key Points:

- **SeImpersonatePrivilege olmadan Impersonation:** Belirli koşullar altında token'ları impersonate ederek SeCreateTokenPrivilege'i EoP için kullanmak mümkündür.
- **Token Impersonation için Koşullar:** Başarılı impersonation, hedef token'ın aynı kullanıcıya ait olmasını ve impersonation yapmaya çalışan sürecin integrity level'ından daha düşük veya eşit bir integrity level'a sahip olmasını gerektirir.
- **Impersonation Token'larının Oluşturulması ve Değiştirilmesi:** Kullanıcılar bir impersonation token'ı oluşturabilir ve ona ayrıcalıklı bir grubun SID (Security Identifier)'ini ekleyerek yetkilerini artırabilirler.

### SeLoadDriverPrivilege

Bu ayrıcalık, `ImagePath` ve `Type` için belirli değerler içeren bir kayıt girdisi oluşturarak aygıt sürücülerini yüklemeye ve kaldırmaya izin verir. `HKLM` (HKEY_LOCAL_MACHINE)'e doğrudan yazma erişimi kısıtlı olduğundan, `HKCU` (HKEY_CURRENT_USER) kullanılmalıdır. Ancak kernel'in sürücü yapılandırması için `HKCU`'yu tanımasını sağlamak üzere belirli bir yol izlenmelidir.

Bu yol `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`'dır; burada `<RID>` mevcut kullanıcının Relative Identifier'ıdır. `HKCU` içinde bu tüm yol oluşturulmalı ve iki değer ayarlanmalıdır:

- `ImagePath`, çalıştırılacak ikili dosyanın yolu
- `Type`, değeri `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak ayarlayın.

Steps to Follow:

1. Yazma erişimi kısıtlı olduğundan `HKCU`'ya erişin, `HKLM` yerine.
2. `HKCU` içinde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun; burada `<RID>` mevcut kullanıcının Relative Identifier'ını temsil eder.
3. `ImagePath`'i ikili dosyanın çalıştırma yoluna ayarlayın.
4. `Type`'ı `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak atayın.
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
Bu ayrıcalığın kötüye kullanılmasıyla ilgili daha fazla yol için: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** ile benzerdir. Temel işlevi, bir işlemin bir nesnenin **sahipliğini üstlenmesine izin vermek** olup, WRITE_OWNER erişim haklarının verilmesi yoluyla explicit discretionary access gereksinimini atlar. Süreç, öncelikle yazma amacıyla hedef registry key'in sahipliğini almak, ardından yazma işlemlerini etkinleştirmek için DACL'i değiştirmekten oluşur.
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

Bu ayrıcalık, diğer süreçleri **debug other processes** yapmaya ve bellek üzerinde okuma/yazma yapmaya izin verir. Bu ayrıcalıkla, çoğu antivirus ve host intrusion prevention solutions'ı atlatabilecek çeşitli memory injection stratejileri uygulanabilir.

#### Bellek dökümü

Bu amaçla [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)'ı [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içinden kullanarak **bir sürecin belleğini yakalayabilirsiniz**. Özellikle bu, **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** süreci için geçerlidir; bu süreç, bir kullanıcı sisteme başarıyla giriş yaptıktan sonra kullanıcı kimlik bilgilerini saklamaktan sorumludur.

Bu dökümü daha sonra mimikatz'e yükleyip parolaları elde edebilirsiniz:
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

Bu hak (Perform volume maintenance tasks), NTFS ACL'lerini atlayan doğrudan disk I/O için ham hacim aygıt tutamaçlarını (ör. \\.\C:) açmaya izin verir. Bununla, alt blokları okuyarak hacimdeki herhangi bir dosyanın baytlarını kopyalayabilir; bu da hassas içeriklerin rastgele okunmasına olanak sağlar (ör. makine private key'leri %ProgramData%\Microsoft\Crypto\, kayıt defteri hive'ları, SAM/NTDS (VSS üzerinden)). Bu durum, CA sunucularında özellikle etkildir; CA private key'in exfiltrating edilmesi herhangi bir principal'ı taklit etmek için bir Golden Certificate oluşturulmasını mümkün kılar.

See detailed techniques and mitigations:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Ayrıcalıkları Kontrol Et
```
whoami /priv
```
**Disabled olarak görünen token'lar** etkinleştirilebilir; aslında _Enabled_ ve _Disabled_ token'ları suistimal edebilirsiniz.

### Tüm token'ları etkinleştir

Eğer token'lar devre dışıysa, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script'ini kullanabilirsiniz:
```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Veya bu [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) içindeki gömülü **script**.

## Table

Full token privileges cheatsheet at [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), özet aşağıda sadece ayrıcalığı kötüye kullanarak yönetici oturumu elde etmenin veya hassas dosyaları okumanın doğrudan yollarını listeleyecektir.

| Privilege                  | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                                     | Remarks                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Yönetici**_ | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                                      | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tehdit**  | _**Built-in commands**_ | `robocopy /b` ile hassas dosyaları okuyun.                                                                                                                                                                                                                                                                                                       | <p>- %WINDIR%\MEMORY.DMP dosyasını okuyabiliyorsanız daha ilginç olabilir<br><br>- <code>SeBackupPrivilege</code> (ve robocopy) açık dosyalar söz konusu olduğunda yardımcı olmaz.<br><br>- Robocopy'nin /b parametresi ile çalışması için hem SeBackup hem de SeRestore gereklidir.</p>                                                                      |
| **`SeCreateToken`**        | _**Yönetici**_ | 3rd party tool          | `NtCreateToken` ile yerel yönetici hakları dahil olmak üzere keyfi token oluşturun.                                                                                                                                                                                                                                                               |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Yönetici**_ | **PowerShell**          | `lsass.exe` token'ını çoğaltın.                                                                                                                                                                                                                                                                                                                  | Script şu adreste bulunabilir: [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                 |
| **`SeLoadDriver`**         | _**Yönetici**_ | 3rd party tool          | <p>1. <code>szkg64.sys</code> gibi hatalı bir kernel sürücüsünü yükleyin<br>2. Sürücü açığını istismar edin<br><br>Alternatif olarak, ayrıcalık <code>ftlMC</code> yerleşik komutuyla güvenlikle ilgili sürücüleri unloaded etmek için kullanılabilir. örn.: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. <code>szkg64</code> açığı <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a> olarak listelenmiştir<br>2. <code>szkg64</code> için <a href="https://www.greyhathacker.net/?p=1025">exploit kodu</a> <a href="https://twitter.com/parvezghh">Parvez Anwar</a> tarafından oluşturulmuştur</p> |
| **`SeRestore`**            | _**Yönetici**_ | **PowerShell**          | <p>1. SeRestore ayrıcalığı etkinken PowerShell/ISE başlatın.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile ayrıcalığı etkinleştirin.<br>3. utilman.exe dosyasının adını utilman.old olarak değiştirin<br>4. cmd.exe dosyasının adını utilman.exe olarak değiştirin<br>5. Konsolu kilitleyip Win+U tuşuna basın</p> | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde saklanan servis ikili dosyalarının değiştirilmesine dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Yönetici**_ | _**Built-in commands**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasının adını utilman.exe olarak değiştirin<br>4. Konsolu kilitleyip Win+U tuşuna basın</p>                                                                                                                                       | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı ayrıcalığı kullanarak "Program Files" içinde saklanan servis ikili dosyalarının değiştirilmesine dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Yönetici**_ | 3rd party tool          | <p>Token'ları yerel yönetici hakları içerecek şekilde manipüle edin. SeImpersonate gerektirebilir.</p><p>Doğrulanacak.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## Reference

- Windows token'larını tanımlayan bu tabloya göz atın: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
- token'larla privesc hakkında [**bu makaleye**](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt) göz atın.
- Microsoft – Perform volume maintenance tasks (SeManageVolumePrivilege): https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks
- 0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate): https://0xdf.gitlab.io/2025/10/04/htb-certificate.html

{{#include ../../banners/hacktricks-training.md}}
